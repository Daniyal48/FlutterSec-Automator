"""APK extraction module — unzip a Flutter APK and surface libflutter.so.

This module is intentionally narrow: it extracts *only* the arm64-v8a
``libflutter.so`` from an APK into a caller-managed temporary directory.
For multi-ABI extraction see :mod:`fluttersec.core.apk_parser`.
"""

from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

from fluttersec.utils.logger import get_logger

log = get_logger(__name__)

# APK zip entry path for the arm64-v8a Flutter library
_ARM64_LIBFLUTTER_ENTRY: str = "lib/arm64-v8a/libflutter.so"


def extract_libflutter(
    apk_path: Path,
    dest_dir: Path | None = None,
) -> Path:
    """Unzip *apk_path* and extract ``lib/arm64-v8a/libflutter.so``.

    If *dest_dir* is ``None`` a new temporary directory is created with
    :func:`tempfile.mkdtemp` and ownership is transferred to the caller —
    remember to clean it up when done.

    Args:
        apk_path: Absolute path to the Flutter ``.apk`` file.
        dest_dir: Directory to write the extracted library into.  A unique
            sub-directory named ``arm64-v8a`` will be created inside it.
            When ``None`` a system temporary directory is used.

    Returns:
        :class:`Path` pointing to the extracted ``libflutter.so`` on disk.

    Raises:
        FileNotFoundError: If *apk_path* does not exist.
        ValueError: If the APK does not contain
            ``lib/arm64-v8a/libflutter.so`` — likely not a Flutter APK, or
            only bundles a different ABI.
        zipfile.BadZipFile: If *apk_path* is not a valid ZIP/APK archive.

    Example::

        lib_path = extract_libflutter(Path("com.example.apk"))
        print(lib_path)  # /tmp/fluttersec_xxx/arm64-v8a/libflutter.so
    """
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    log.info("Opening APK archive: %s", apk_path)

    with zipfile.ZipFile(apk_path, "r") as zf:
        entries = zf.namelist()

        if _ARM64_LIBFLUTTER_ENTRY not in entries:
            raise ValueError(
                f"Entry '{_ARM64_LIBFLUTTER_ENTRY}' not found in {apk_path.name}. "
                "Ensure the APK is a Flutter build targeting arm64-v8a."
            )

        # Resolve / create destination
        if dest_dir is None:
            dest_dir = Path(tempfile.mkdtemp(prefix="fluttersec_extract_"))
            log.debug("Created temporary extraction directory: %s", dest_dir)

        out_dir = dest_dir / "arm64-v8a"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "libflutter.so"

        log.info("Extracting %s → %s", _ARM64_LIBFLUTTER_ENTRY, out_path)
        with zf.open(_ARM64_LIBFLUTTER_ENTRY) as src, out_path.open("wb") as dst:
            dst.write(src.read())

    log.info(
        "Extracted libflutter.so (%d bytes)", out_path.stat().st_size
    )
    return out_path
