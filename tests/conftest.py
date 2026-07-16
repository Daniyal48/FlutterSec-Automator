"""Shared pytest fixtures for FlutterSec-Automator tests."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Workspace fixture
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def tmp_workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Return a session-scoped temporary directory for all test workspaces."""
    return tmp_path_factory.mktemp("fluttersec_test_ws")


# ---------------------------------------------------------------------------
# Synthetic libflutter.so (minimal valid ELF64 stub)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def sample_libflutter_path(tmp_workspace: Path) -> Path:
    """Return a path to a minimal synthetic ELF64 stub.

    The stub is intentionally minimal: it has a valid ELF magic and class
    bytes so that LIEF can open it without crashing.  It does *not* contain
    real sections or symbols — that level of testing requires real Flutter
    release binaries and belongs in integration tests.
    """
    stub_path = tmp_workspace / "arm64-v8a" / "libflutter.so"
    stub_path.parent.mkdir(parents=True, exist_ok=True)

    # Minimal 64-byte ELF64 LE AArch64 shared-object header (zeroed body)
    header = bytearray(64)
    # e_ident
    header[0:4] = b"\x7fELF"   # Magic
    header[4] = 2               # EI_CLASS:   ELFCLASS64
    header[5] = 1               # EI_DATA:    ELFDATA2LSB (little-endian)
    header[6] = 1               # EI_VERSION: EV_CURRENT
    header[7] = 0               # EI_OSABI:   ELFOSABI_NONE
    # e_type: ET_DYN (shared object) = 0x0003
    header[16] = 3
    header[17] = 0
    # e_machine: EM_AARCH64 = 0x00B7
    header[18] = 0xB7
    header[19] = 0x00
    # e_version: EV_CURRENT = 1
    header[20] = 1
    # e_ehsize: 64 bytes
    header[52] = 64

    stub_path.write_bytes(bytes(header))
    return stub_path


# ---------------------------------------------------------------------------
# Synthetic APK fixture
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def sample_apk_path(tmp_workspace: Path, sample_libflutter_path: Path) -> Path:
    """Return a path to a synthetic minimal APK containing libflutter.so.

    The APK is a ZIP archive with the library placed at the standard Flutter
    path ``lib/arm64-v8a/libflutter.so``.
    """
    apk_path = tmp_workspace / "sample.apk"
    with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.write(sample_libflutter_path, arcname="lib/arm64-v8a/libflutter.so")
    return apk_path
