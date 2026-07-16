"""Flutter Engine version detection from libflutter.so.

Strategy overview
-----------------
All strategies run in *priority order* until both ``version_string`` and
``engine_hash`` are resolved.  Results from lower-priority strategies are
used to fill in fields that higher-priority ones could not supply.

1. **ELF section scan** (via LIEF)
   Searches the named sections that carry Flutter's embedded string table:
   ``.rodata``, ``.data.rel.ro``, ``.dynstr``, and — per the user request —
   ``.text``.  Looks for:

   * ``Flutter/<semver>`` → ``version_string``
   * ``engine_revision\\x00<hash>`` or a standalone 40-hex string near
     ``flutter_assets`` / ``engine_revision`` → ``engine_hash``

2. **Raw byte scan** (pure Python, no LIEF sections required)
   Falls back to a sliding-window scan over the entire file when LIEF cannot
   surface named sections (heavily stripped or packed binaries).  Uses the
   same patterns but applies them to the raw bytes.

3. **GNU Build-ID lookup**
   Extracts the ELF ``.note.gnu.build-id`` note and cross-references it
   against ``data/version_map.yaml``.  Used to promote ``version_string``
   when neither the string scan nor the raw scan found one.

All three strategies share extracted artifacts: the Build-ID is always
extracted regardless of which version strategy succeeds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import lief  # type: ignore[import-untyped]
import yaml

from fluttersec.utils.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

_VERSION_MAP_PATH = Path(__file__).parent.parent / "data" / "version_map.yaml"

# ELF sections to inspect (in scan order — most likely first).
# .text is included per the implementation brief; it carries the string table
# for stripped builds where .rodata is absent.
_SCAN_SECTIONS: tuple[str, ...] = (
    ".rodata",
    ".data.rel.ro",
    ".dynstr",
    ".text",
    ".data",
    ".rodata.str1.1",   # common alternate name in newer LLVM builds
    ".rodata.str1.8",
)

# ---------------------------------------------------------------------------
# Compiled regular expressions
# ---------------------------------------------------------------------------

# "Flutter/3.22.0"  or  "Flutter/3.22.0.pre.1"
_VERSION_RE: re.Pattern[bytes] = re.compile(
    rb"Flutter/(\d+\.\d+\.\d+(?:[.\-]\w+)*)"
)

# 40 contiguous lowercase hex characters, *not* surrounded by more hex chars.
# This is the canonical form of a Git SHA-1 engine revision hash.
_HEX40_RE: re.Pattern[bytes] = re.compile(
    rb"(?<![0-9a-f])([0-9a-f]{40})(?![0-9a-f])"
)

# "engine_revision" as a null-terminated C string, followed within 128 bytes
# by the 40-hex hash (also null-terminated or space-delimited).
_ENGINE_REVISION_ANCHORED_RE: re.Pattern[bytes] = re.compile(
    rb"engine_revision[\x00\s]?[^\x00]{0,128}?([0-9a-f]{40})",
    re.DOTALL,
)

# Alternate anchor: "revision" key in a JSON-style or key=value payload
_REVISION_KV_RE: re.Pattern[bytes] = re.compile(
    rb'"revision"\s*:\s*"([0-9a-f]{40})"'
)

# "flutter_assets" string — used as a proximity anchor for hash hunting
_FLUTTER_ASSETS_ANCHOR: bytes = b"flutter_assets"
_HASH_PROXIMITY_WINDOW: int = 2048  # bytes on each side of anchor to search


# ---------------------------------------------------------------------------
# Data transfer object
# ---------------------------------------------------------------------------

@dataclass
class EngineVersion:
    """All version-related metadata extracted from ``libflutter.so``.

    Attributes:
        version_string: Human-readable semver (e.g. ``"3.22.0"``), or ``None``
            when no ``Flutter/<version>`` marker was found.
        build_id: Lowercase hex GNU Build-ID extracted from ELF notes, or
            ``None`` when the binary has no Build-ID note.
        engine_hash: The 40-character lowercase hex Git SHA-1 engine revision
            hash, or ``None`` when not found.
        detection_method: Primary strategy that produced ``version_string``:
            ``"section_scan"``, ``"raw_scan"``, ``"build_id"``, or
            ``"unknown"``.
        sections_found: Names of ELF sections that were successfully read
            during detection (empty on fully stripped binaries).
    """

    version_string: str | None
    build_id: str | None
    engine_hash: str | None
    detection_method: str
    sections_found: list[str]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class VersionDetector:
    """Detect the Flutter Engine version and revision hash inside ``libflutter.so``.

    Uses LIEF to load the ELF binary and surface named sections, then applies
    a cascade of regex strategies to extract the version string and 40-character
    engine revision hash.  Falls back to raw byte scanning for stripped
    production binaries where section headers have been removed.

    Example::

        detector = VersionDetector()
        ev = detector.detect(Path("arm64-v8a/libflutter.so"))
        print(ev.version_string)   # "3.22.0"
        print(ev.engine_hash)      # "9e8b56b6a82dfba7c7e64fd5efad37da9c4e9c8a"
        print(ev.detection_method) # "section_scan"
    """

    def __init__(self) -> None:
        self._version_map: dict[str, str] = self._load_version_map()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, lib_path: Path) -> EngineVersion:
        """Detect the Flutter Engine version from *lib_path*.

        All three strategies run on every call; results are merged so that
        a later strategy can fill in fields the earlier one missed (e.g. the
        hash found by raw scan and the version string found via Build-ID).

        Args:
            lib_path: Path to the ``libflutter.so`` ELF binary.

        Returns:
            :class:`EngineVersion` populated with the best available data.

        Raises:
            FileNotFoundError: If *lib_path* does not exist on disk.
        """
        if not lib_path.exists():
            raise FileNotFoundError(f"Library not found: {lib_path}")

        log.info("Detecting Flutter Engine version from: %s", lib_path)

        # ── Phase 1: load LIEF binary ──────────────────────────────────────
        binary = self._load_binary(lib_path)

        # ── Phase 2: Build-ID (always extracted; used for lookup later) ───
        build_id = self._extract_build_id(binary)
        if build_id:
            log.debug("GNU Build-ID: %s", build_id)

        # ── Phase 3: ELF section scan ─────────────────────────────────────
        version, engine_hash, sections_found = self._section_scan(binary, lib_path)
        if version:
            log.info("Version via section_scan: %s  hash=%s", version, engine_hash)
            return EngineVersion(
                version_string=version,
                build_id=build_id,
                engine_hash=engine_hash,
                detection_method="section_scan",
                sections_found=sections_found,
            )

        # ── Phase 4: Raw byte scan (stripped binary fallback) ─────────────
        raw_version, raw_hash = self._raw_scan(lib_path)
        engine_hash = engine_hash or raw_hash  # keep hash from section scan if available
        if raw_version:
            log.info("Version via raw_scan: %s  hash=%s", raw_version, engine_hash)
            return EngineVersion(
                version_string=raw_version,
                build_id=build_id,
                engine_hash=engine_hash,
                detection_method="raw_scan",
                sections_found=sections_found,
            )

        # Also use raw hash if section scan didn't find one
        engine_hash = engine_hash or raw_hash

        # ── Phase 5: Build-ID lookup ───────────────────────────────────────
        if build_id and build_id in self._version_map:
            mapped = self._version_map[build_id]
            log.info("Version via build_id lookup: %s", mapped)
            return EngineVersion(
                version_string=mapped,
                build_id=build_id,
                engine_hash=engine_hash,
                detection_method="build_id",
                sections_found=sections_found,
            )

        log.warning(
            "Flutter Engine version could not be determined for: %s", lib_path.name
        )
        return EngineVersion(
            version_string=None,
            build_id=build_id,
            engine_hash=engine_hash,
            detection_method="unknown",
            sections_found=sections_found,
        )

    # ------------------------------------------------------------------
    # Strategy 1: LIEF section scan
    # ------------------------------------------------------------------

    @staticmethod
    def _load_binary(lib_path: Path) -> lief.ELF.Binary | None:
        """Parse *lib_path* with LIEF, returning ``None`` on failure.

        Args:
            lib_path: Path to the ELF binary.

        Returns:
            Parsed :class:`lief.ELF.Binary`, or ``None`` if LIEF cannot parse
            the file (e.g. packed, truncated, or non-ELF input).
        """
        try:
            binary = lief.parse(str(lib_path))
            if not isinstance(binary, lief.ELF.Binary):
                log.debug("LIEF did not return an ELF binary for %s", lib_path.name)
                return None
            return binary
        except Exception as exc:
            log.debug("LIEF parse failed for %s: %s", lib_path.name, exc)
            return None

    @staticmethod
    def _section_scan(
        binary: lief.ELF.Binary | None,
        lib_path: Path,
    ) -> tuple[str | None, str | None, list[str]]:
        """Scan named ELF sections for Flutter version and engine revision hash.

        Iterates over :data:`_SCAN_SECTIONS` (which includes ``.text``) in
        order and applies four patterns per section:

        1. ``Flutter/<semver>`` → ``version_string``
        2. ``engine_revision`` anchor + 40-hex → ``engine_hash``
        3. ``"revision": "<hash>"`` JSON fragment → ``engine_hash``
        4. Proximity scan: 40-hex within ``±HASH_PROXIMITY_WINDOW`` bytes of
           ``flutter_assets`` → ``engine_hash``

        Args:
            binary: Parsed LIEF ELF binary, or ``None`` (section scan is
                skipped and empty results are returned).
            lib_path: Original library path (used in log messages only).

        Returns:
            Tuple of ``(version_string, engine_hash, sections_found)`` where
            *sections_found* lists the section names that were read.
        """
        version: str | None = None
        engine_hash: str | None = None
        sections_found: list[str] = []

        if binary is None:
            return version, engine_hash, sections_found

        # Build a fast lookup: name → section
        section_map: dict[str, lief.ELF.Section] = {
            s.name: s for s in binary.sections if s.name
        }

        for sec_name in _SCAN_SECTIONS:
            section = section_map.get(sec_name)
            if section is None:
                continue

            # Materialise section content — LIEF returns a memoryview-like
            # object; bytes() is the safest cross-version conversion.
            try:
                content: bytes = bytes(section.content)
            except Exception as exc:
                log.debug("Could not read section %s: %s", sec_name, exc)
                continue

            if not content:
                continue

            sections_found.append(sec_name)
            log.debug("Scanning section %-20s (%d bytes)", sec_name, len(content))

            # ── version_string ─────────────────────────────────────────────
            if version is None:
                m = _VERSION_RE.search(content)
                if m:
                    version = m.group(1).decode("ascii", errors="ignore")
                    log.debug("  flutter version: %s (in %s)", version, sec_name)

            # ── engine_hash — multiple patterns tried in order ─────────────
            if engine_hash is None:
                engine_hash = _extract_hash_from_content(content, sec_name)

            if version and engine_hash:
                break  # both found — stop scanning

        return version, engine_hash, sections_found

    # ------------------------------------------------------------------
    # Strategy 2: Raw byte scan (stripped binary fallback)
    # ------------------------------------------------------------------

    @staticmethod
    def _raw_scan(lib_path: Path) -> tuple[str | None, str | None]:
        """Scan the entire raw file for Flutter version and hash markers.

        This strategy does *not* use LIEF or any ELF structure awareness — it
        treats the file as a flat byte array.  This makes it effective against
        stripped binaries where LIEF finds no sections.

        The scan is intentionally conservative: it only extracts a 40-hex
        string if it is adjacent to a known anchor (``flutter_assets`` or
        ``engine_revision``) to avoid false positives from random data that
        happens to look like a hex string.

        Args:
            lib_path: Path to the ELF (or any) binary file.

        Returns:
            Tuple of ``(version_string, engine_hash)``, either may be ``None``.
        """
        version: str | None = None
        engine_hash: str | None = None

        try:
            data: bytes = lib_path.read_bytes()
        except OSError as exc:
            log.debug("Raw scan: could not read %s: %s", lib_path.name, exc)
            return None, None

        # ── version string ─────────────────────────────────────────────────
        m = _VERSION_RE.search(data)
        if m:
            version = m.group(1).decode("ascii", errors="ignore")
            log.debug("Raw scan: flutter version: %s", version)

        # ── engine hash — anchored patterns ────────────────────────────────
        # Pattern A: engine_revision anchor
        hm = _ENGINE_REVISION_ANCHORED_RE.search(data)
        if hm:
            engine_hash = hm.group(1).decode("ascii", errors="ignore")
            log.debug("Raw scan: engine_hash (engine_revision anchor): %s", engine_hash)

        # Pattern B: JSON "revision" key
        if engine_hash is None:
            jm = _REVISION_KV_RE.search(data)
            if jm:
                engine_hash = jm.group(1).decode("ascii", errors="ignore")
                log.debug("Raw scan: engine_hash (JSON revision key): %s", engine_hash)

        # Pattern C: proximity to flutter_assets
        if engine_hash is None:
            engine_hash = _hash_near_anchor(data, _FLUTTER_ASSETS_ANCHOR)
            if engine_hash:
                log.debug("Raw scan: engine_hash (flutter_assets proximity): %s", engine_hash)

        return version, engine_hash

    # ------------------------------------------------------------------
    # Strategy 3: GNU Build-ID extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_build_id(
        binary: lief.ELF.Binary | None,
    ) -> str | None:
        """Extract the GNU Build-ID from ELF notes.

        The Build-ID is stored as raw bytes in an ELF ``PT_NOTE`` segment
        (note name ``"GNU"``, note type ``NT_GNU_BUILD_ID = 3``).  LIEF
        exposes this via ``binary.notes``.

        Args:
            binary: Parsed LIEF ELF binary, or ``None``.

        Returns:
            Lowercase hex string of the Build-ID, or ``None`` if absent or
            if *binary* is ``None``.
        """
        if binary is None:
            return None
        try:
            for note in binary.notes:
                # LIEF ≥ 0.14 uses NoteType / Note.TYPE enum variants.
                # We test both the enum attribute name and the raw integer
                # value (3 == NT_GNU_BUILD_ID) for maximum compatibility.
                note_type = note.type
                is_build_id = False

                # Enum comparison (LIEF ≥ 0.14)
                try:
                    is_build_id = (
                        note_type == lief.ELF.Note.TYPE.GNU_BUILD_ID
                        or int(note_type) == 3
                    )
                except Exception:
                    # Fallback: compare integer value directly
                    try:
                        is_build_id = int(note_type) == 3
                    except Exception:
                        pass

                if is_build_id:
                    desc = bytes(note.description)
                    if desc:
                        return desc.hex()
        except Exception as exc:
            log.debug("Build-ID extraction failed: %s", exc)
        return None

    # ------------------------------------------------------------------
    # YAML version map
    # ------------------------------------------------------------------

    @staticmethod
    def _load_version_map() -> dict[str, str]:
        """Load the Build-ID → version string lookup table from YAML.

        Returns:
            Dict mapping lowercase Build-ID hex strings to Flutter version
            strings.  Empty dict if the file does not exist.
        """
        if not _VERSION_MAP_PATH.exists():
            log.debug("version_map.yaml not found at %s", _VERSION_MAP_PATH)
            return {}
        try:
            with _VERSION_MAP_PATH.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            return {k.strip(): str(v) for k, v in data.items() if isinstance(k, str)}
        except Exception as exc:
            log.warning("Failed to load version_map.yaml: %s", exc)
            return {}


# ---------------------------------------------------------------------------
# Private helpers (module-level for testability)
# ---------------------------------------------------------------------------

def _extract_hash_from_content(content: bytes, section_name: str) -> str | None:
    """Extract a 40-char engine revision hash from *content* using multiple patterns.

    Tries, in order:

    1. ``engine_revision`` anchor regex
    2. JSON ``"revision": "<hash>"`` fragment
    3. 40-hex proximity to ``flutter_assets`` within ``±HASH_PROXIMITY_WINDOW``
    4. First standalone 40-hex string in the content (last resort, most
       likely to produce a false positive — only used in ``.rodata`` /
       ``.data.rel.ro`` where random 40-hex strings are uncommon)

    Args:
        content: Raw bytes of the section to scan.
        section_name: Name of the section (used for logging only).

    Returns:
        Matched 40-character lowercase hex string, or ``None``.
    """
    # Pattern 1: engine_revision anchor
    m = _ENGINE_REVISION_ANCHORED_RE.search(content)
    if m:
        h = m.group(1).decode("ascii", errors="ignore")
        log.debug("  engine_hash (engine_revision anchor) in %s: %s", section_name, h)
        return h

    # Pattern 2: JSON "revision" key
    m2 = _REVISION_KV_RE.search(content)
    if m2:
        h = m2.group(1).decode("ascii", errors="ignore")
        log.debug("  engine_hash (JSON revision key) in %s: %s", section_name, h)
        return h

    # Pattern 3: proximity to flutter_assets
    h = _hash_near_anchor(content, _FLUTTER_ASSETS_ANCHOR)
    if h:
        log.debug("  engine_hash (flutter_assets proximity) in %s: %s", section_name, h)
        return h

    # Pattern 4: last-resort standalone 40-hex (only safe in non-.text sections)
    if section_name not in (".text",):
        m4 = _HEX40_RE.search(content)
        if m4:
            h = m4.group(1).decode("ascii", errors="ignore")
            log.debug("  engine_hash (standalone hex40) in %s: %s", section_name, h)
            return h

    return None


def _hash_near_anchor(data: bytes, anchor: bytes, window: int = _HASH_PROXIMITY_WINDOW) -> str | None:
    """Search for a 40-char hex string within *±window* bytes of *anchor*.

    Args:
        data: Byte buffer to search.
        anchor: Anchor byte sequence to locate.
        window: Number of bytes to scan on each side of the anchor.

    Returns:
        First 40-character lowercase hex string found in the window, or
        ``None`` if the anchor is absent or no hash is found nearby.
    """
    total = len(data)
    for am in re.finditer(re.escape(anchor), data):
        start = max(0, am.start() - window)
        end = min(total, am.end() + window)
        region = data[start:end]
        hm = _HEX40_RE.search(region)
        if hm:
            return hm.group(1).decode("ascii", errors="ignore")
    return None
