"""Binary analysis module — locates SSL pinning offsets in libflutter.so.

Detection strategy cascade
--------------------------
All three strategies are attempted in order.  Results are de-duplicated by
virtual address and merged into a single sorted list.

1. **Symbol scan** — Searches the ELF symbol table (via LIEF) for well-known
   BoringSSL / Flutter SSL function names.  Exact, zero false-positives, but
   only works on *unstripped* production builds.

2. **Pattern scan** — Slides ARM64/ARM32/x86_64 byte-sequence patterns over
   the ``.text`` segment using Python :mod:`re` with ``??`` wildcard support.
   Patterns are loaded from ``data/patterns.yaml`` and filtered by architecture
   and Flutter version prefix before scanning.

3. **Version-map lookup** — If both the above strategies find nothing, the
   detected engine hash / Build-ID is cross-referenced against the
   ``offsets`` block inside ``data/version_map.yaml``, which carries
   pre-computed ``{symbol, virtual_address, file_offset}`` tuples that were
   extracted from official Flutter release binaries.

Custom exceptions
-----------------
:class:`OffsetNotFoundError` is raised (by callers that require at least one
result) when all three strategies come up empty.
:class:`BinaryParseError` wraps LIEF failures on corrupted inputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import lief  # type: ignore[import-untyped]
import yaml

from fluttersec.core.version_detector import EngineVersion
from fluttersec.utils.logger import get_logger

log = get_logger(__name__)

_PATTERNS_PATH = Path(__file__).parent.parent / "data" / "patterns.yaml"
_VERSION_MAP_PATH = Path(__file__).parent.parent / "data" / "version_map.yaml"

# Well-known BoringSSL / Flutter SSL symbol names to hunt for in the symbol table.
_SSL_SYMBOLS: tuple[str, ...] = (
    "ssl_verify_peer_cert",
    "SSL_CTX_set_custom_verify",
    "SSL_CTX_set_verify",
    "ssl_client_hello_cb",
    "x509_verify_cert_error_string",
    "ssl_crypto_x509_session_verify_cert_chain",
    "boringssl_self_test",
    "ssl_verify_cert_chain",
    "tls1_handshake_digest",
)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class BinaryParseError(Exception):
    """Raised when LIEF cannot parse the provided ELF binary.

    This guards against corrupted, packed, or non-ELF inputs that would
    otherwise cause LIEF to return ``None`` or raise internally.

    Args:
        lib_path: Path to the binary that failed to parse.
        detail: Human-readable reason from LIEF (if available).
    """

    def __init__(self, lib_path: Path, detail: str = "") -> None:
        self.lib_path = lib_path
        super().__init__(
            f"LIEF failed to parse '{lib_path.name}'"
            + (f": {detail}" if detail else "")
        )


class OffsetNotFoundError(Exception):
    """Raised when no SSL pinning offset can be located by any strategy.

    Attributes:
        lib_path: Library that was analyzed.
        engine_version: Engine version metadata used during analysis.
        strategies_tried: List of strategy names that were attempted.
    """

    def __init__(
        self,
        lib_path: Path,
        engine_version: EngineVersion,
        strategies_tried: list[str],
    ) -> None:
        self.lib_path = lib_path
        self.engine_version = engine_version
        self.strategies_tried = strategies_tried
        tried = ", ".join(strategies_tried) if strategies_tried else "none"
        super().__init__(
            f"No SSL pinning offset found in '{lib_path.name}' "
            f"after trying: {tried}. "
            "Add a pattern entry to data/patterns.yaml or an offset entry "
            "to data/version_map.yaml for this engine version."
        )


# ---------------------------------------------------------------------------
# Data transfer objects
# ---------------------------------------------------------------------------

@dataclass
class SslOffset:
    """A located SSL pinning hook point within libflutter.so.

    Attributes:
        symbol: Name or description of the target function.
        virtual_address: ELF virtual address of the function entry point.
        file_offset: Raw byte offset from the start of the file.
        method: Detection method — ``"symbol"``, ``"pattern"``, or
            ``"version_map"``.
        arch: ABI/architecture of the binary (e.g. ``"arm64-v8a"``).
    """

    symbol: str
    virtual_address: int
    file_offset: int
    method: str
    arch: str


@dataclass
class AnalysisResult:
    """Full output of a :class:`BinaryAnalyzer` run.

    Attributes:
        offsets: Sorted list of located :class:`SslOffset` instances.
        strategies_used: Names of strategies that produced at least one result.
        arch: Architecture of the analyzed binary.
    """

    offsets: list[SslOffset]
    strategies_used: list[str]
    arch: str


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class BinaryAnalyzer:
    """Locate SSL pinning–related offsets within ``libflutter.so``.

    The analyzer can be used in two ways:

    **Standalone (stateless) mode** — call :meth:`find_ssl_offsets` directly::

        analyzer = BinaryAnalyzer()
        offsets = analyzer.find_ssl_offsets(lib_path, engine_version)

    **Bound mode** — instantiate with the target binary and engine version for
    a more ergonomic API::

        analyzer = BinaryAnalyzer(lib_path, engine_version)
        result = analyzer.analyze()

    Both modes run the same three-strategy cascade.
    """

    def __init__(
        self,
        lib_path: Path | None = None,
        engine_version: EngineVersion | None = None,
    ) -> None:
        """Initialise the analyzer, optionally binding it to a specific target.

        Args:
            lib_path: Path to the ``libflutter.so`` to analyze.  When supplied,
                :meth:`analyze` can be called without arguments.
            engine_version: Detected engine version metadata.  Required for
                version-specific pattern filtering and version-map lookup.
        """
        self._lib_path: Path | None = lib_path
        self._engine_version: EngineVersion | None = engine_version
        self._patterns: list[dict[str, str]] = self._load_patterns()
        self._version_map_offsets: dict[str, list[dict]] = self._load_version_map_offsets()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        lib_path: Path | None = None,
        engine_version: EngineVersion | None = None,
        arch: str | None = None,
        raise_on_empty: bool = False,
    ) -> AnalysisResult:
        """Run the full three-strategy cascade and return an :class:`AnalysisResult`.

        Args:
            lib_path: Override for the bound ``lib_path``; required if no
                path was supplied at construction time.
            engine_version: Override for the bound ``engine_version``.
            arch: ABI string for pattern filtering.  Inferred from the parent
                directory name if ``None``.
            raise_on_empty: If ``True``, raises :class:`OffsetNotFoundError`
                when no offsets are found.

        Returns:
            :class:`AnalysisResult` with all located offsets and strategy metadata.

        Raises:
            ValueError: If no ``lib_path`` is available (neither bound nor passed).
            BinaryParseError: If LIEF cannot parse the ELF binary.
            OffsetNotFoundError: If ``raise_on_empty=True`` and no offsets found.
        """
        effective_path = lib_path or self._lib_path
        if effective_path is None:
            raise ValueError(
                "lib_path must be supplied either at construction or at call time."
            )
        effective_ev = engine_version or self._engine_version
        if effective_ev is None:
            from fluttersec.core.version_detector import EngineVersion
            effective_ev = EngineVersion(
                version_string=None,
                build_id=None,
                engine_hash=None,
                detection_method="unknown",
                sections_found=[],
            )

        offsets = self.find_ssl_offsets(effective_path, effective_ev, arch=arch)

        strategies_used: list[str] = list({o.method for o in offsets})

        if raise_on_empty and not offsets:
            tried = ["symbol", "pattern", "version_map"]
            raise OffsetNotFoundError(effective_path, effective_ev, tried)

        return AnalysisResult(
            offsets=offsets,
            strategies_used=strategies_used,
            arch=arch or effective_path.parent.name,
        )

    def find_ssl_offsets(
        self,
        lib_path: Path,
        engine_version: EngineVersion,
        arch: str | None = None,
    ) -> list[SslOffset]:
        """Locate SSL pinning offsets using all three strategies.

        This is the primary workhorse method.  All strategies run and their
        results are de-duplicated by virtual address and sorted ascending.

        Args:
            lib_path: Path to ``libflutter.so``.
            engine_version: Detected engine version (used for pattern filtering
                and version-map lookup).
            arch: ABI string.  Inferred from parent directory name when ``None``.

        Returns:
            Sorted list of unique :class:`SslOffset` instances.

        Raises:
            BinaryParseError: If LIEF cannot parse *lib_path*.
            FileNotFoundError: If *lib_path* does not exist.
        """
        if not lib_path.exists():
            raise FileNotFoundError(f"Library not found: {lib_path}")

        if arch is None:
            arch = lib_path.parent.name  # e.g. "arm64-v8a"

        log.info("Analyzing binary for SSL offsets (arch=%s): %s", arch, lib_path)

        binary = self._parse_binary(lib_path)

        seen_vas: set[int] = set()
        results: list[SslOffset] = []
        strategies_tried: list[str] = []

        # ── Strategy 1: Symbol scan ────────────────────────────────────────
        strategies_tried.append("symbol")
        for offset in self._symbol_scan(binary, arch):
            if offset.virtual_address not in seen_vas:
                results.append(offset)
                seen_vas.add(offset.virtual_address)

        # ── Strategy 2: Pattern scan ───────────────────────────────────────
        strategies_tried.append("pattern")
        for offset in self._pattern_scan(binary, arch, engine_version):
            if offset.virtual_address not in seen_vas:
                results.append(offset)
                seen_vas.add(offset.virtual_address)

        # ── Strategy 3: Version-map offset lookup ──────────────────────────
        strategies_tried.append("version_map")
        if not results:
            # Only run the fallback if the two scanning strategies found nothing.
            # This avoids inflating results with potentially stale static data.
            for offset in self._version_map_lookup(engine_version, arch):
                if offset.virtual_address not in seen_vas:
                    results.append(offset)
                    seen_vas.add(offset.virtual_address)

        results.sort(key=lambda o: o.virtual_address)
        log.info(
            "SSL offsets found: %d (strategies: %s)",
            len(results),
            ", ".join(strategies_tried),
        )
        return results

    # ------------------------------------------------------------------
    # Strategy 1 — symbol table scan
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_binary(lib_path: Path) -> lief.ELF.Binary:
        """Parse *lib_path* with LIEF, raising :class:`BinaryParseError` on failure.

        Args:
            lib_path: Path to the ELF binary.

        Returns:
            Parsed :class:`lief.ELF.Binary`.

        Raises:
            BinaryParseError: If LIEF returns ``None`` or raises.
        """
        try:
            binary = lief.parse(str(lib_path))
        except Exception as exc:
            raise BinaryParseError(lib_path, str(exc)) from exc
        if binary is None or not isinstance(binary, lief.ELF.Binary):
            raise BinaryParseError(lib_path, "LIEF returned None or non-ELF object")
        return binary

    @staticmethod
    def _symbol_scan(binary: lief.ELF.Binary, arch: str) -> list[SslOffset]:
        """Search the ELF symbol table for known SSL function names.

        Compatible with LIEF ≥ 0.13 and ≥ 0.14 (unified ``.symbols`` API).

        Args:
            binary: Parsed LIEF ELF binary.
            arch: ABI string to embed in result metadata.

        Returns:
            List of :class:`SslOffset` for each matched symbol with non-zero VA.
        """
        offsets: list[SslOffset] = []

        # LIEF ≥ 0.14 unified the symbol table under `.symbols`.
        try:
            all_symbols = list(binary.symbols)
        except AttributeError:
            all_symbols = list(binary.dynamic_symbols) + list(
                getattr(binary, "static_symbols", [])
            )

        for sym in all_symbols:
            name: str = sym.name
            if not name:
                continue
            for target in _SSL_SYMBOLS:
                if target in name:
                    va: int = sym.value
                    if va == 0:
                        continue
                    file_off = BinaryAnalyzer._va_to_file_offset(binary, va)
                    offsets.append(
                        SslOffset(
                            symbol=name,
                            virtual_address=va,
                            file_offset=file_off,
                            method="symbol",
                            arch=arch,
                        )
                    )
                    log.debug("Symbol match: %s @ VA=0x%x  file_off=0x%x", name, va, file_off)
                    break  # avoid double-matching the same symbol against multiple targets

        return offsets

    # ------------------------------------------------------------------
    # Strategy 2 — byte-pattern scan
    # ------------------------------------------------------------------

    def _pattern_scan(
        self,
        binary: lief.ELF.Binary,
        arch: str,
        engine_version: EngineVersion,
    ) -> list[SslOffset]:
        """Scan the ``.text`` section for known SSL-bypass byte patterns.

        Patterns are filtered by architecture and (optionally) Flutter version
        prefix before scanning.  Each ``??`` token in the pattern string becomes
        a regex ``.`` that matches exactly one byte.

        Args:
            binary: Parsed LIEF ELF binary.
            arch: ABI string for filtering and result metadata.
            engine_version: Used for version-specific pattern filtering.

        Returns:
            List of :class:`SslOffset` for each pattern match found.
        """
        offsets: list[SslOffset] = []

        text_section = binary.get_section(".text")
        if text_section is None:
            log.warning("No .text section in binary — skipping pattern scan.")
            return offsets

        section_content: bytes = bytes(text_section.content)
        if not section_content:
            log.warning(".text section is empty — skipping pattern scan.")
            return offsets

        section_va: int = text_section.virtual_address
        log.debug(
            "Pattern scan: .text  VA=0x%x  size=%d bytes  patterns=%d",
            section_va,
            len(section_content),
            len(self._patterns),
        )

        for pat_entry in self._patterns:
            pat_arch: str = pat_entry.get("arch", "*")
            if pat_arch != "*" and pat_arch != arch:
                continue

            pat_version: str = pat_entry.get("version", "*")
            if (
                pat_version != "*"
                and engine_version.version_string is not None
                and not engine_version.version_string.startswith(pat_version)
            ):
                continue

            symbol: str = pat_entry.get("symbol", "unknown_ssl_fn")
            pattern_hex: str = pat_entry.get("pattern", "")
            compiled = self._compile_pattern(pattern_hex)
            if compiled is None:
                continue

            for match in compiled.finditer(section_content):
                rel_offset = match.start()
                va = section_va + rel_offset
                file_off = self._va_to_file_offset(binary, va)
                offsets.append(
                    SslOffset(
                        symbol=symbol,
                        virtual_address=va,
                        file_offset=file_off,
                        method="pattern",
                        arch=arch,
                    )
                )
                log.debug(
                    "Pattern match: %-50s  VA=0x%x  file_off=0x%x  (arch=%s)",
                    symbol,
                    va,
                    file_off,
                    arch,
                )

        return offsets

    @staticmethod
    def _compile_pattern(pattern_hex: str) -> re.Pattern[bytes] | None:
        """Convert a hex-string pattern (with ``??`` wildcards) to a regex.

        Each space-separated token is either a two-digit hex byte or the
        wildcard ``"??"`` which matches any single byte.

        Args:
            pattern_hex: Space-separated hex token string, e.g.
                ``"FD 7B ?? A9 FD 03 00 91"``.

        Returns:
            Compiled :class:`re.Pattern[bytes]`, or ``None`` if the input is
            empty, malformed, or contains an invalid token.

        Example::

            pat = BinaryAnalyzer._compile_pattern("55 8B ?? C3")
            assert pat.search(b"\\x55\\x8b\\x42\\xc3") is not None
        """
        if not pattern_hex or not pattern_hex.strip():
            return None

        parts: list[bytes] = []
        for token in pattern_hex.strip().split():
            if token == "??":
                parts.append(b".")           # regex dot — matches any one byte
            else:
                try:
                    byte_val = bytes.fromhex(token)
                    parts.append(re.escape(byte_val))
                except ValueError:
                    log.warning("Invalid pattern token %r — skipping entire pattern.", token)
                    return None

        try:
            return re.compile(b"".join(parts), re.DOTALL)
        except re.error as exc:
            log.warning("Pattern compile error: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Strategy 3 — version-map offset lookup
    # ------------------------------------------------------------------

    def _version_map_lookup(
        self,
        engine_version: EngineVersion,
        arch: str,
    ) -> list[SslOffset]:
        """Look up pre-computed SSL offsets from the version-map YAML.

        The lookup key is the engine's 40-character hash (``engine_hash``),
        falling back to the GNU Build-ID (``build_id``) if the hash is absent.

        The ``offsets`` block of ``data/version_map.yaml`` has the structure::

            offsets:
              "<40-char-hash>":
                - symbol: ssl_verify_peer_cert
                  arch: arm64-v8a
                  virtual_address: 0x512ab80
                  file_offset: 0x112ab80

        Args:
            engine_version: Engine version object supplying the lookup key.
            arch: ABI string for filtering and result metadata.

        Returns:
            List of :class:`SslOffset` from the map entry, or empty list if
            no matching entry is found.
        """
        lookup_key = engine_version.engine_hash or engine_version.build_id
        if not lookup_key:
            log.debug("Version-map lookup skipped: no engine hash or Build-ID available.")
            return []

        entries = self._version_map_offsets.get(lookup_key, [])
        if not entries:
            log.debug("Version-map lookup: no entry for key=%s", lookup_key[:12] + "…")
            return []

        offsets: list[SslOffset] = []
        for entry in entries:
            entry_arch = entry.get("arch", "*")
            if entry_arch != "*" and entry_arch != arch:
                continue
            symbol = entry.get("symbol", "unknown_ssl_fn")
            va = int(entry.get("virtual_address", 0))
            file_off = int(entry.get("file_offset", 0))
            if va == 0 and file_off == 0:
                continue
            offsets.append(
                SslOffset(
                    symbol=symbol,
                    virtual_address=va,
                    file_offset=file_off,
                    method="version_map",
                    arch=arch,
                )
            )
            log.debug(
                "Version-map hit: %-50s  VA=0x%x  file_off=0x%x", symbol, va, file_off
            )

        if offsets:
            log.info(
                "Version-map lookup returned %d offset(s) for key %s…",
                len(offsets),
                lookup_key[:12],
            )
        return offsets

    # ------------------------------------------------------------------
    # YAML loaders
    # ------------------------------------------------------------------

    @staticmethod
    def _load_patterns() -> list[dict[str, str]]:
        """Load SSL pinning byte patterns from ``data/patterns.yaml``.

        Returns:
            List of pattern entry dicts.  Empty list if file is missing or
            malformed.
        """
        if not _PATTERNS_PATH.exists():
            log.warning("patterns.yaml not found at %s", _PATTERNS_PATH)
            return []
        try:
            with _PATTERNS_PATH.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            return list(data.get("patterns", []))
        except Exception as exc:
            log.warning("Failed to load patterns.yaml: %s", exc)
            return []

    @staticmethod
    def _load_version_map_offsets() -> dict[str, list[dict]]:
        """Load pre-computed SSL offsets from the ``offsets`` block of version_map.yaml.

        The ``offsets`` block maps engine-hash strings to lists of offset dicts.
        This is separate from the top-level Build-ID → version-string entries.

        Returns:
            Dict mapping engine hash strings to lists of offset entry dicts.
        """
        if not _VERSION_MAP_PATH.exists():
            log.debug("version_map.yaml not found at %s", _VERSION_MAP_PATH)
            return {}
        try:
            with _VERSION_MAP_PATH.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            raw = data.get("offsets", {}) or {}
            return {str(k): list(v) for k, v in raw.items() if isinstance(v, list)}
        except Exception as exc:
            log.warning("Failed to load version_map.yaml offsets block: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # VA → file offset helper
    # ------------------------------------------------------------------

    @staticmethod
    def _va_to_file_offset(binary: lief.ELF.Binary, va: int) -> int:
        """Convert an ELF virtual address to its raw file byte offset.

        Iterates over all loadable (``PT_LOAD``) segments to find the one
        that contains *va* and computes the file offset as::

            file_offset = segment.file_offset + (va - segment.virtual_address)

        Args:
            binary: Parsed LIEF ELF binary.
            va: Virtual address to convert.

        Returns:
            File offset in bytes from the start of the file.  Returns ``0``
            if *va* does not fall within any loadable segment (e.g. for purely
            virtual addresses or stripped binaries with no segment headers).
        """
        for seg in binary.segments:
            seg_va: int = seg.virtual_address
            seg_size: int = seg.virtual_size or seg.file_size
            if seg_va <= va < seg_va + seg_size:
                return seg.file_offset + (va - seg_va)
        return 0
