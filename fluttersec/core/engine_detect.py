"""Flutter Engine version-hash detection via raw binary scanning.

The Flutter Engine embeds a 40-character lowercase hex SHA-1 commit hash
(the *engine revision*) in ``libflutter.so`` at build time.  This hash is
always located in close proximity to the ``flutter_assets`` string inside
the binary's read-only data region.

This module performs a **pure Python, dependency-free** scan — no LIEF
required — so it works as a fast, first-pass detector before heavier
analysis with :mod:`fluttersec.core.version_detector`.

Typical embedded layout (simplified)::

    ...flutter_assets\x00<padding>...<40-hex-hash>\x00...

The scanner reads the raw file bytes, locates every ``flutter_assets``
occurrence, then searches a configurable window around each hit for the
40-char hex pattern.
"""

from __future__ import annotations

import re
from pathlib import Path

from fluttersec.utils.logger import get_logger

log = get_logger(__name__)

# Compiled pattern: exactly 40 contiguous lowercase hex characters bounded by
# a non-hex byte on each side (or start/end of buffer).
_HEX40_RE: re.Pattern[bytes] = re.compile(
    rb"(?<![0-9a-f])([0-9a-f]{40})(?![0-9a-f])"
)

# Anchor string that Flutter always embeds near the engine revision hash.
_ANCHOR: bytes = b"flutter_assets"

# Number of bytes to scan on either side of each anchor hit.
_WINDOW_BYTES: int = 2048


def detect_engine_hash(
    lib_path: Path,
    window: int = _WINDOW_BYTES,
) -> str | None:
    """Scan *lib_path* for the Flutter Engine revision hash.

    The function reads the raw bytes of ``libflutter.so``, locates every
    occurrence of ``flutter_assets``, and searches within *±window* bytes
    of each hit for a 40-character lowercase hex string.  The first such
    string found is returned.

    Args:
        lib_path: Path to ``libflutter.so`` (or any Flutter ELF binary).
        window: Byte radius around each ``flutter_assets`` anchor to search.
            Defaults to 2048.  Increase if your binary has unusual padding.

    Returns:
        The 40-character engine revision hash string if found, otherwise
        ``None``.

    Raises:
        FileNotFoundError: If *lib_path* does not exist.
        OSError: If the file cannot be read.

    Example::

        h = detect_engine_hash(Path("libflutter.so"))
        # '9e8b56b6a82dfba7c7e64fd5efad37da9c4e9c8a'
    """
    if not lib_path.exists():
        raise FileNotFoundError(f"Library not found: {lib_path}")

    log.info("Scanning for engine hash: %s", lib_path)
    data: bytes = lib_path.read_bytes()
    total = len(data)

    anchor_positions = [m.start() for m in re.finditer(re.escape(_ANCHOR), data)]

    if not anchor_positions:
        log.warning(
            "Anchor string %r not found in %s — may not be a Flutter binary.",
            _ANCHOR.decode(),
            lib_path.name,
        )
        return None

    log.debug(
        "Found %d '%s' anchor(s) — scanning ±%d byte windows.",
        len(anchor_positions),
        _ANCHOR.decode(),
        window,
    )

    for anchor_pos in anchor_positions:
        start = max(0, anchor_pos - window)
        end = min(total, anchor_pos + len(_ANCHOR) + window)
        region = data[start:end]

        match = _HEX40_RE.search(region)
        if match:
            hash_str = match.group(1).decode("ascii")
            log.info(
                "Engine hash found near offset 0x%x: %s",
                start + match.start(),
                hash_str,
            )
            return hash_str

    log.warning(
        "No 40-char hex hash found near any '%s' anchor in %s.",
        _ANCHOR.decode(),
        lib_path.name,
    )
    return None


def detect_all_engine_hashes(
    lib_path: Path,
    window: int = _WINDOW_BYTES,
) -> list[str]:
    """Return every unique 40-char hash found near ``flutter_assets`` anchors.

    Useful when a binary contains multiple embedded version markers (e.g.
    fat binaries or specially patched builds).

    Args:
        lib_path: Path to ``libflutter.so``.
        window: Byte radius around each anchor to search.

    Returns:
        Ordered list of unique 40-character hex hash strings, preserving
        discovery order.  Empty list if none are found.

    Raises:
        FileNotFoundError: If *lib_path* does not exist.
    """
    if not lib_path.exists():
        raise FileNotFoundError(f"Library not found: {lib_path}")

    data: bytes = lib_path.read_bytes()
    total = len(data)
    seen: dict[str, None] = {}  # ordered dedup via insertion-ordered dict

    for anchor_match in re.finditer(re.escape(_ANCHOR), data):
        anchor_pos = anchor_match.start()
        start = max(0, anchor_pos - window)
        end = min(total, anchor_pos + len(_ANCHOR) + window)
        region = data[start:end]

        for hex_match in _HEX40_RE.finditer(region):
            h = hex_match.group(1).decode("ascii")
            seen[h] = None  # dedup preserving order

    result = list(seen.keys())
    log.debug("Unique engine hashes found: %d", len(result))
    return result
