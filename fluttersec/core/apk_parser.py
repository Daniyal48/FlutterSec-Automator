"""APK parsing module — extracts libflutter.so from a Flutter APK.

This module is the primary entry-point for APK ingestion.  It combines:

* **Manifest parsing** via :mod:`androguard` (with a raw ZIP-comment fallback)
  to surface the package name, version name, and version code.
* **Multi-ABI extraction** of ``libflutter.so`` via :mod:`zipfile`, written to
  a caller-supplied workspace directory in streaming chunks.
* **Security hardening** against malformed archives (zip-slip, compressed-size
  overflow, path traversal) so that untrusted APKs cannot escape the workspace.
* **Custom exception hierarchy** so callers can handle each failure mode
  independently without stringly-typed ``ValueError`` catches.
"""

from __future__ import annotations

import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from fluttersec.utils.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# ABI directories searched inside an APK, in descending preference order.
# arm64-v8a is tried first because it is the primary production target for
# modern Flutter apps; the remaining ABIs are fallbacks.
_ABI_PRIORITY: tuple[str, ...] = (
    "arm64-v8a",
    "armeabi-v7a",
    "x86_64",
    "x86",
)

_LIBFLUTTER_NAME: str = "libflutter.so"

# Streaming chunk size for extraction (256 KiB)
_CHUNK_SIZE: int = 256 * 1024

# Maximum uncompressed size we allow for libflutter.so (512 MiB).
# Real-world libraries are 5–30 MiB; this cap guards against zip-bomb entries.
_MAX_LIB_BYTES: int = 512 * 1024 * 1024


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class ApkParseError(Exception):
    """Base class for all APK parsing failures."""


class ApkNotFoundError(ApkParseError, FileNotFoundError):
    """Raised when the supplied APK path does not exist on disk.

    Inherits from :class:`FileNotFoundError` so existing ``except
    FileNotFoundError`` handlers continue to work.
    """


class InvalidApkError(ApkParseError):
    """Raised when the file is not a valid ZIP / APK archive."""


class LibflutterNotFoundError(ApkParseError):
    """Raised when no ``libflutter.so`` can be found in any supported ABI.

    This typically indicates the application is *not* a Flutter app, or was
    built exclusively for an ABI not yet listed in :data:`_ABI_PRIORITY`.
    """


class ZipSlipError(ApkParseError):
    """Raised when a ZIP entry path would escape the destination directory.

    Zip-slip attacks embed ``../`` components in entry names to write files
    outside the intended extraction root.  We abort immediately on detection.
    """


class LibflutterTooLargeError(ApkParseError):
    """Raised when a ``libflutter.so`` entry exceeds :data:`_MAX_LIB_BYTES`.

    Guards against decompression bombs embedded in malformed APKs.
    """


# ---------------------------------------------------------------------------
# Data transfer objects
# ---------------------------------------------------------------------------

@dataclass
class ManifestInfo:
    """Parsed metadata from AndroidManifest.xml.

    Attributes:
        package_name: Reverse-DNS application identifier (e.g. ``com.example.app``).
        version_name: Human-readable version string (e.g. ``"1.4.2"``).
        version_code: Monotonically increasing integer build number.
        source: Which strategy produced this metadata —
            ``"androguard"``, ``"zip_comment"``, or ``"fallback"``.
    """

    package_name: str
    version_name: str
    version_code: int
    source: str


@dataclass
class ApkInfo:
    """All information extracted from a parsed Flutter APK.

    Attributes:
        manifest: Parsed :class:`ManifestInfo` from AndroidManifest.xml.
        package_name: Shortcut to ``manifest.package_name``.
        version_name: Shortcut to ``manifest.version_name``.
        version_code: Shortcut to ``manifest.version_code``.
        abis: ABI architectures for which ``libflutter.so`` was found,
            ordered by discovery (i.e. by :data:`_ABI_PRIORITY`).
        libflutter_paths: Mapping of ABI name → local :class:`Path` of the
            extracted ``libflutter.so`` in the workspace.
    """

    manifest: ManifestInfo
    abis: list[str]
    libflutter_paths: dict[str, Path] = field(default_factory=dict)

    # Convenience shortcut properties so callers don't always drill into .manifest
    @property
    def package_name(self) -> str:
        """Application package identifier."""
        return self.manifest.package_name

    @property
    def version_name(self) -> str:
        """Human-readable version string."""
        return self.manifest.version_name

    @property
    def version_code(self) -> int:
        """Integer build number."""
        return self.manifest.version_code

    @property
    def primary_lib(self) -> Path:
        """Path to the highest-priority (arm64-v8a) extracted ``libflutter.so``.

        Raises:
            LibflutterNotFoundError: If no library was extracted (should not
                happen after a successful :meth:`ApkParser.parse` call).
        """
        for abi in _ABI_PRIORITY:
            if abi in self.libflutter_paths:
                return self.libflutter_paths[abi]
        raise LibflutterNotFoundError(
            "primary_lib called but libflutter_paths is empty."
        )


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class ApkParser:
    """Parse a Flutter APK and extract its native ``libflutter.so`` library.

    The parser performs the following steps in order:

    1. Validate the APK path and open it as a ZIP archive.
    2. Parse AndroidManifest.xml via :mod:`androguard`, with two fallbacks.
    3. Scan the ZIP entry list for ``lib/<abi>/libflutter.so`` in ABI-priority
       order, extract each one to the workspace directory in streaming chunks,
       and guard against zip-slip and decompression-bomb attacks.
    4. Raise :class:`LibflutterNotFoundError` if none were found.

    Example::

        import tempfile
        from pathlib import Path
        from fluttersec.core.apk_parser import ApkParser

        with tempfile.TemporaryDirectory(prefix="fluttersec_") as tmp:
            workspace = Path(tmp)
            parser = ApkParser()
            info = parser.parse(Path("target.apk"), workspace)
            print(info.package_name)           # com.example.myapp
            print(info.primary_lib)            # /tmp/fluttersec_.../arm64-v8a/libflutter.so
    """

    def parse(
        self,
        apk_path: Path,
        workspace: Path | None = None,
    ) -> ApkInfo:
        """Parse *apk_path* and extract all available ``libflutter.so`` variants.

        Args:
            apk_path: Path to the target ``.apk`` file.  Must exist and be a
                valid ZIP/APK archive.
            workspace: Directory to extract native libraries into.  A
                subdirectory named after each ABI is created inside it.
                When ``None``, a new :func:`tempfile.mkdtemp` directory is
                created automatically — the caller is then responsible for
                cleaning it up.

        Returns:
            Fully populated :class:`ApkInfo` dataclass.

        Raises:
            ApkNotFoundError: If *apk_path* does not exist.
            InvalidApkError: If the file is not a valid ZIP/APK archive.
            LibflutterNotFoundError: If no ``libflutter.so`` is present in any
                supported ABI directory.
            ZipSlipError: If an entry name would escape the workspace root.
            LibflutterTooLargeError: If any ``libflutter.so`` entry exceeds
                :data:`_MAX_LIB_BYTES` uncompressed.
        """
        apk_path = apk_path.resolve()
        self._validate_apk_path(apk_path)

        if workspace is None:
            workspace = Path(tempfile.mkdtemp(prefix="fluttersec_apk_"))
            log.debug("Auto-created workspace: %s", workspace)
        workspace.mkdir(parents=True, exist_ok=True)
        workspace = workspace.resolve()

        log.info("Parsing APK: %s", apk_path.name)

        try:
            zf = zipfile.ZipFile(apk_path, "r")  # noqa: SIM115 — kept open across two operations
        except zipfile.BadZipFile as exc:
            raise InvalidApkError(
                f"'{apk_path.name}' is not a valid ZIP/APK archive: {exc}"
            ) from exc
        except OSError as exc:
            raise InvalidApkError(
                f"Cannot open '{apk_path.name}': {exc}"
            ) from exc

        with zf:
            manifest = self._parse_manifest(apk_path, zf)
            libflutter_paths, abis_found = self._extract_libs(zf, workspace, apk_path)

        if not libflutter_paths:
            searched = [f"lib/{a}/{_LIBFLUTTER_NAME}" for a in _ABI_PRIORITY]
            raise LibflutterNotFoundError(
                f"No '{_LIBFLUTTER_NAME}' found in any of the following ZIP entries "
                f"inside '{apk_path.name}':\n  " + "\n  ".join(searched) + "\n"
                "This may not be a Flutter application, or it targets an unsupported ABI."
            )

        log.info(
            "Parsing complete — package=%s  version=%s  abis=%s",
            manifest.package_name,
            manifest.version_name,
            abis_found,
        )

        return ApkInfo(
            manifest=manifest,
            abis=abis_found,
            libflutter_paths=libflutter_paths,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_apk_path(apk_path: Path) -> None:
        """Raise :class:`ApkNotFoundError` if *apk_path* does not exist."""
        if not apk_path.exists():
            raise ApkNotFoundError(f"APK not found: {apk_path}")
        if not apk_path.is_file():
            raise ApkNotFoundError(f"APK path is not a file: {apk_path}")

    @staticmethod
    def _parse_manifest(
        apk_path: Path,
        zf: zipfile.ZipFile,
    ) -> ManifestInfo:
        """Extract package metadata from AndroidManifest.xml.

        Three strategies are attempted in order:

        1. **androguard** — full binary XML decoder; returns accurate data.
        2. **ZIP comment** — some build tools embed ``pkg=..;ver=..`` in the
           archive comment; used as a lightweight fallback.
        3. **Hardcoded fallback** — returns ``"unknown.package"`` / ``"0.0.0"``
           so parsing continues even for stripped APKs.

        Args:
            apk_path: Path to the APK (forwarded to androguard).
            zf: Already-opened :class:`zipfile.ZipFile` (used for ZIP comment).

        Returns:
            :class:`ManifestInfo` with ``source`` indicating which strategy succeeded.
        """
        # ── Strategy 1: androguard ────────────────────────────────────────────
        try:
            from androguard.core.apk import APK  # type: ignore[import-untyped]

            apk_obj = APK(str(apk_path))
            pkg = (apk_obj.get_package() or "").strip() or "unknown.package"
            ver_name = (apk_obj.get_androidversion_name() or "").strip() or "0.0.0"
            ver_code_raw = apk_obj.get_androidversion_code()
            ver_code = int(ver_code_raw) if ver_code_raw is not None else 0

            log.debug(
                "Manifest via androguard: pkg=%s ver=%s code=%d", pkg, ver_name, ver_code
            )
            return ManifestInfo(
                package_name=pkg,
                version_name=ver_name,
                version_code=ver_code,
                source="androguard",
            )
        except ImportError:
            log.debug("androguard not installed — skipping strategy 1.")
        except Exception as exc:
            log.warning("androguard manifest parse failed: %s", exc)

        # ── Strategy 2: ZIP archive comment ──────────────────────────────────
        try:
            comment = zf.comment.decode("utf-8", errors="ignore").strip()
            if comment:
                pkg = _extract_kv(comment, "pkg") or "unknown.package"
                ver_name = _extract_kv(comment, "ver") or "0.0.0"
                ver_code_str = _extract_kv(comment, "code") or "0"
                ver_code = int(ver_code_str) if ver_code_str.isdigit() else 0
                log.debug(
                    "Manifest via ZIP comment: pkg=%s ver=%s code=%d",
                    pkg,
                    ver_name,
                    ver_code,
                )
                return ManifestInfo(
                    package_name=pkg,
                    version_name=ver_name,
                    version_code=ver_code,
                    source="zip_comment",
                )
        except Exception as exc:
            log.debug("ZIP comment parse failed: %s", exc)

        # ── Strategy 3: fallback ──────────────────────────────────────────────
        log.warning(
            "All manifest parse strategies failed for '%s' — using placeholder values.",
            apk_path.name,
        )
        return ManifestInfo(
            package_name="unknown.package",
            version_name="0.0.0",
            version_code=0,
            source="fallback",
        )

    @staticmethod
    def _extract_libs(
        zf: zipfile.ZipFile,
        workspace: Path,
        apk_path: Path,
    ) -> tuple[dict[str, Path], list[str]]:
        """Extract ``libflutter.so`` for every available ABI into *workspace*.

        Args:
            zf: Opened APK archive.
            workspace: Resolved root directory for extraction.
            apk_path: Original APK path (used in error messages only).

        Returns:
            Tuple of ``(libflutter_paths, abis_found)`` where
            *libflutter_paths* maps ABI → extracted :class:`Path` and
            *abis_found* preserves discovery order.

        Raises:
            ZipSlipError: If an entry name would escape *workspace*.
            LibflutterTooLargeError: If an entry exceeds :data:`_MAX_LIB_BYTES`.
            InvalidApkError: If a ZIP entry cannot be read (e.g. bad CRC).
        """
        zip_entries: set[str] = set(zf.namelist())
        libflutter_paths: dict[str, Path] = {}
        abis_found: list[str] = []

        for abi in _ABI_PRIORITY:
            entry_name = f"lib/{abi}/{_LIBFLUTTER_NAME}"
            if entry_name not in zip_entries:
                continue

            # ── Zip-slip guard ────────────────────────────────────────────
            dest_dir = workspace / abi
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir / _LIBFLUTTER_NAME
            _assert_safe_path(dest_path, workspace)

            # ── Size guard ────────────────────────────────────────────────
            info: zipfile.ZipInfo = zf.getinfo(entry_name)
            if info.file_size > _MAX_LIB_BYTES:
                raise LibflutterTooLargeError(
                    f"'{entry_name}' reports an uncompressed size of "
                    f"{info.file_size:,} bytes (>{_MAX_LIB_BYTES:,} limit). "
                    "Possible decompression bomb in APK."
                )

            # ── Streaming extraction ──────────────────────────────────────
            try:
                with zf.open(entry_name) as src, dest_path.open("wb") as dst:
                    bytes_written = 0
                    while True:
                        chunk = src.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        bytes_written += len(chunk)
                        if bytes_written > _MAX_LIB_BYTES:
                            dest_path.unlink(missing_ok=True)
                            raise LibflutterTooLargeError(
                                f"'{entry_name}' expanded beyond {_MAX_LIB_BYTES:,} "
                                "bytes during streaming extraction. Aborting."
                            )
                        dst.write(chunk)
            except (zipfile.BadZipFile, OSError) as exc:
                raise InvalidApkError(
                    f"Failed to read '{entry_name}' from '{apk_path.name}': {exc}"
                ) from exc

            actual_size = dest_path.stat().st_size
            log.debug(
                "Extracted %-20s → %s  (%d bytes)", entry_name, dest_path, actual_size
            )
            libflutter_paths[abi] = dest_path
            abis_found.append(abi)

        return libflutter_paths, abis_found


# ---------------------------------------------------------------------------
# Private utilities
# ---------------------------------------------------------------------------

def _assert_safe_path(candidate: Path, root: Path) -> None:
    """Raise :class:`ZipSlipError` if *candidate* is outside *root*.

    Both paths must already be resolved (absolute, symlinks expanded).

    Args:
        candidate: Resolved destination path to validate.
        root: Resolved workspace root.

    Raises:
        ZipSlipError: If *candidate* does not share *root* as a prefix.
    """
    try:
        candidate.relative_to(root)
    except ValueError:
        raise ZipSlipError(
            f"Zip-slip attempt detected: entry would escape workspace.\n"
            f"  Destination : {candidate}\n"
            f"  Workspace   : {root}"
        )


def _extract_kv(text: str, key: str) -> str | None:
    """Extract a value from a ``key=value`` pair in *text*.

    Handles semicolons or newlines as pair separators.

    Args:
        text: Raw string to search (e.g. ZIP archive comment).
        key: Key name to look for.

    Returns:
        The value string, or ``None`` if the key is absent.
    """
    import re
    m = re.search(rf"(?:^|[;\n])\s*{re.escape(key)}\s*=\s*([^\s;]+)", text)
    return m.group(1).strip() if m else None
