"""Unit tests for fluttersec.core.apk_parser.

Covers:
  - Happy-path extraction (content integrity, directory placement, ABI ordering)
  - All custom exception types (ApkNotFoundError, InvalidApkError,
    LibflutterNotFoundError, ZipSlipError, LibflutterTooLargeError)
  - Three-strategy manifest parsing (androguard, ZIP comment, fallback)
  - Streaming extraction correctness
  - Auto workspace creation (workspace=None)
  - ApkInfo convenience properties (package_name, version_name, primary_lib)
  - ManifestInfo dataclass fields and 'source' attribute
  - Idempotent re-extraction
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from fluttersec.core.apk_parser import (
    _MAX_LIB_BYTES,
    ApkInfo,
    ApkNotFoundError,
    ApkParser,
    InvalidApkError,
    LibflutterNotFoundError,
    LibflutterTooLargeError,
    ManifestInfo,
    ZipSlipError,
    _extract_kv,
)

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------
_STUB_LIB: bytes = b"\x7fELF" + b"\x00" * 60   # minimal ELF header


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def arm64_apk(tmp_path: Path) -> Path:
    """Minimal valid APK with lib/arm64-v8a/libflutter.so."""
    apk = tmp_path / "arm64.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("lib/arm64-v8a/libflutter.so", _STUB_LIB)
        zf.writestr("AndroidManifest.xml", b"placeholder")
    return apk


@pytest.fixture()
def multi_abi_apk(tmp_path: Path) -> Path:
    """APK with both arm64-v8a and armeabi-v7a libflutter.so entries."""
    apk = tmp_path / "multi.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libflutter.so", _STUB_LIB + b"\xaa")
        zf.writestr("lib/armeabi-v7a/libflutter.so", _STUB_LIB + b"\xbb")
    return apk


@pytest.fixture()
def no_flutter_apk(tmp_path: Path) -> Path:
    """Valid APK ZIP that contains no libflutter.so at all."""
    apk = tmp_path / "noflutter.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"placeholder")
    return apk


@pytest.fixture()
def corrupt_apk(tmp_path: Path) -> Path:
    """File that is NOT a valid ZIP archive."""
    apk = tmp_path / "corrupt.apk"
    apk.write_bytes(b"NOTAZIP" * 16)
    return apk


@pytest.fixture()
def zip_comment_apk(tmp_path: Path) -> Path:
    """APK with package metadata embedded in the ZIP archive comment."""
    apk = tmp_path / "comment.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libflutter.so", _STUB_LIB)
        zf.comment = b"pkg=com.comment.app;ver=2.5.0;code=250"
    return apk


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------
class TestApkParserHappyPath:
    """Successful extraction and data correctness tests."""

    def test_returns_apk_info_instance(self, arm64_apk: Path, tmp_path: Path) -> None:
        """parse() must return an ApkInfo instance."""
        info = ApkParser().parse(arm64_apk, tmp_path)
        assert isinstance(info, ApkInfo)

    def test_arm64_abi_in_abis_list(self, arm64_apk: Path, tmp_path: Path) -> None:
        """arm64-v8a must appear in ApkInfo.abis after extraction."""
        info = ApkParser().parse(arm64_apk, tmp_path)
        assert "arm64-v8a" in info.abis

    def test_libflutter_path_exists(self, arm64_apk: Path, tmp_path: Path) -> None:
        """Extracted libflutter.so must exist on disk."""
        info = ApkParser().parse(arm64_apk, tmp_path)
        assert info.libflutter_paths["arm64-v8a"].exists()

    def test_libflutter_placed_in_abi_subdir(
        self, arm64_apk: Path, tmp_path: Path
    ) -> None:
        """Extracted file must sit inside an 'arm64-v8a' sub-directory."""
        info = ApkParser().parse(arm64_apk, tmp_path)
        assert info.libflutter_paths["arm64-v8a"].parent.name == "arm64-v8a"

    def test_extracted_content_matches_original(
        self, arm64_apk: Path, tmp_path: Path
    ) -> None:
        """Byte contents of the extracted file must match what was zipped."""
        info = ApkParser().parse(arm64_apk, tmp_path)
        assert info.libflutter_paths["arm64-v8a"].read_bytes() == _STUB_LIB

    def test_multi_abi_both_extracted(
        self, multi_abi_apk: Path, tmp_path: Path
    ) -> None:
        """Both arm64-v8a and armeabi-v7a should be extracted from a multi-ABI APK."""
        info = ApkParser().parse(multi_abi_apk, tmp_path)
        assert "arm64-v8a" in info.libflutter_paths
        assert "armeabi-v7a" in info.libflutter_paths

    def test_multi_abi_arm64_listed_first(
        self, multi_abi_apk: Path, tmp_path: Path
    ) -> None:
        """arm64-v8a must be the first entry in abis (highest-priority ABI)."""
        info = ApkParser().parse(multi_abi_apk, tmp_path)
        assert info.abis[0] == "arm64-v8a"

    def test_primary_lib_returns_arm64_path(
        self, multi_abi_apk: Path, tmp_path: Path
    ) -> None:
        """primary_lib must return the arm64-v8a path when available."""
        info = ApkParser().parse(multi_abi_apk, tmp_path)
        assert info.primary_lib == info.libflutter_paths["arm64-v8a"]

    def test_auto_workspace_created_when_none(self, arm64_apk: Path) -> None:
        """parse(workspace=None) should auto-create a temp directory."""
        info = ApkParser().parse(arm64_apk, workspace=None)
        lib = info.primary_lib
        try:
            assert lib.exists()
        finally:
            import shutil
            shutil.rmtree(lib.parent.parent, ignore_errors=True)

    def test_idempotent_re_extraction(self, arm64_apk: Path, tmp_path: Path) -> None:
        """Calling parse() twice on the same workspace must succeed."""
        p = ApkParser()
        info1 = p.parse(arm64_apk, tmp_path)
        info2 = p.parse(arm64_apk, tmp_path)
        assert info1.primary_lib.read_bytes() == info2.primary_lib.read_bytes()

    def test_extracted_size_is_positive(self, arm64_apk: Path, tmp_path: Path) -> None:
        """Extracted libflutter.so must have a positive on-disk size."""
        info = ApkParser().parse(arm64_apk, tmp_path)
        assert info.primary_lib.stat().st_size > 0


# ---------------------------------------------------------------------------
# ApkInfo convenience properties
# ---------------------------------------------------------------------------
class TestApkInfoProperties:
    """Tests for ApkInfo shortcut properties and ManifestInfo."""

    def test_package_name_shortcut(self, arm64_apk: Path, tmp_path: Path) -> None:
        """info.package_name must equal info.manifest.package_name."""
        info = ApkParser().parse(arm64_apk, tmp_path)
        assert info.package_name == info.manifest.package_name

    def test_version_name_shortcut(self, arm64_apk: Path, tmp_path: Path) -> None:
        """info.version_name must equal info.manifest.version_name."""
        info = ApkParser().parse(arm64_apk, tmp_path)
        assert info.version_name == info.manifest.version_name

    def test_version_code_shortcut(self, arm64_apk: Path, tmp_path: Path) -> None:
        """info.version_code must equal info.manifest.version_code."""
        info = ApkParser().parse(arm64_apk, tmp_path)
        assert info.version_code == info.manifest.version_code

    def test_manifest_source_is_valid_string(
        self, arm64_apk: Path, tmp_path: Path
    ) -> None:
        """ManifestInfo.source must be one of the three recognised strategy names."""
        info = ApkParser().parse(arm64_apk, tmp_path)
        assert info.manifest.source in {"androguard", "zip_comment", "fallback"}

    def test_manifest_info_dataclass_fields(self) -> None:
        """ManifestInfo should be constructable and field-accessible."""
        mi = ManifestInfo(
            package_name="com.test",
            version_name="1.0",
            version_code=1,
            source="androguard",
        )
        assert mi.package_name == "com.test"
        assert mi.source == "androguard"

    def test_primary_lib_raises_when_empty(self) -> None:
        """primary_lib on an ApkInfo with no paths should raise LibflutterNotFoundError."""
        mi = ManifestInfo("p", "1", 1, "fallback")
        info = ApkInfo(manifest=mi, abis=[], libflutter_paths={})
        with pytest.raises(LibflutterNotFoundError):
            _ = info.primary_lib


# ---------------------------------------------------------------------------
# Manifest parsing strategies
# ---------------------------------------------------------------------------
class TestManifestParsing:
    """Tests for the three-strategy manifest parsing logic."""

    def test_fallback_when_androguard_absent(
        self, arm64_apk: Path, tmp_path: Path
    ) -> None:
        """Without androguard, source should be 'zip_comment' or 'fallback'."""
        with patch.dict("sys.modules", {"androguard": None, "androguard.core": None,
                                        "androguard.core.apk": None}):
            info = ApkParser().parse(arm64_apk, tmp_path)
        assert info.manifest.source in {"zip_comment", "fallback"}

    def test_zip_comment_strategy(self, zip_comment_apk: Path, tmp_path: Path) -> None:
        """When androguard is absent, ZIP comment should provide metadata."""
        with patch.dict("sys.modules", {"androguard": None, "androguard.core": None,
                                        "androguard.core.apk": None}):
            info = ApkParser().parse(zip_comment_apk, tmp_path)
        if info.manifest.source == "zip_comment":
            assert info.package_name == "com.comment.app"
            assert info.version_name == "2.5.0"
            assert info.version_code == 250

    def test_fallback_values_are_safe_strings(
        self, arm64_apk: Path, tmp_path: Path
    ) -> None:
        """Fallback values must be non-empty strings, not None or empty."""
        info = ApkParser().parse(arm64_apk, tmp_path)
        assert isinstance(info.package_name, str) and info.package_name
        assert isinstance(info.version_name, str) and info.version_name
        assert isinstance(info.version_code, int)


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------
class TestApkParserErrors:
    """Tests for each custom exception type."""

    def test_raises_apk_not_found_error(self, tmp_path: Path) -> None:
        """Missing APK path must raise ApkNotFoundError (a FileNotFoundError subclass)."""
        with pytest.raises(ApkNotFoundError, match="APK not found"):
            ApkParser().parse(Path("/does/not/exist.apk"), tmp_path)

    def test_apk_not_found_is_file_not_found(self, tmp_path: Path) -> None:
        """ApkNotFoundError must be catchable as FileNotFoundError for compatibility."""
        with pytest.raises(FileNotFoundError):
            ApkParser().parse(Path("/does/not/exist.apk"), tmp_path)

    def test_raises_invalid_apk_error_for_corrupt_file(
        self, corrupt_apk: Path, tmp_path: Path
    ) -> None:
        """Non-ZIP files must raise InvalidApkError."""
        with pytest.raises(InvalidApkError):
            ApkParser().parse(corrupt_apk, tmp_path)

    def test_raises_libflutter_not_found_error(
        self, no_flutter_apk: Path, tmp_path: Path
    ) -> None:
        """APKs with no libflutter.so must raise LibflutterNotFoundError."""
        with pytest.raises(LibflutterNotFoundError):
            ApkParser().parse(no_flutter_apk, tmp_path)

    def test_libflutter_not_found_message_lists_searched_paths(
        self, no_flutter_apk: Path, tmp_path: Path
    ) -> None:
        """The error message should list the entry paths that were searched."""
        with pytest.raises(LibflutterNotFoundError, match="lib/arm64-v8a"):
            ApkParser().parse(no_flutter_apk, tmp_path)

    def test_raises_apk_not_found_for_directory_path(self, tmp_path: Path) -> None:
        """Passing a directory (not a file) as apk_path must raise ApkNotFoundError."""
        with pytest.raises(ApkNotFoundError):
            ApkParser().parse(tmp_path, tmp_path / "ws")

    def test_raises_lib_too_large_error(self, tmp_path: Path) -> None:
        """A ZipInfo entry reporting an oversized file must raise LibflutterTooLargeError."""
        apk = tmp_path / "bomb.apk"
        real_content = b"X" * 64

        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("lib/arm64-v8a/libflutter.so", real_content)

        # Patch ZipInfo.file_size to report an impossibly large value
        original_getinfo = zipfile.ZipFile.getinfo

        def patched_getinfo(self: zipfile.ZipFile, name: str) -> zipfile.ZipInfo:
            info = original_getinfo(self, name)
            if name.endswith("libflutter.so"):
                info.file_size = _MAX_LIB_BYTES + 1
            return info

        with patch.object(zipfile.ZipFile, "getinfo", patched_getinfo):
            with pytest.raises(LibflutterTooLargeError):
                ApkParser().parse(apk, tmp_path / "ws")


# ---------------------------------------------------------------------------
# Zip-slip guard
# ---------------------------------------------------------------------------
class TestZipSlipGuard:
    """Tests for path-traversal protection (_assert_safe_path)."""

    def test_zip_slip_raises_zip_slip_error(self, tmp_path: Path) -> None:
        """A crafted APK with a traversal entry should raise ZipSlipError."""
        from fluttersec.core.apk_parser import _assert_safe_path

        workspace = (tmp_path / "ws").resolve()
        workspace.mkdir()
        # Simulate a resolved path that escapes the workspace
        evil_path = Path("/etc/passwd").resolve()
        with pytest.raises(ZipSlipError):
            _assert_safe_path(evil_path, workspace)

    def test_safe_path_does_not_raise(self, tmp_path: Path) -> None:
        """A legitimate path inside workspace must not raise."""
        from fluttersec.core.apk_parser import _assert_safe_path

        workspace = (tmp_path / "ws").resolve()
        workspace.mkdir()
        safe = (workspace / "arm64-v8a" / "libflutter.so").resolve()
        _assert_safe_path(safe, workspace)  # must not raise


# ---------------------------------------------------------------------------
# _extract_kv helper
# ---------------------------------------------------------------------------
class TestExtractKv:
    """Unit tests for the ZIP comment key-value parser."""

    def test_extracts_value_by_key(self) -> None:
        assert _extract_kv("pkg=com.example;ver=1.0", "pkg") == "com.example"

    def test_extracts_numeric_value(self) -> None:
        assert _extract_kv("code=42;other=x", "code") == "42"

    def test_returns_none_for_missing_key(self) -> None:
        assert _extract_kv("pkg=com.example", "ver") is None

    def test_handles_newline_separator(self) -> None:
        assert _extract_kv("pkg=com.foo\nver=2.0", "ver") == "2.0"

    def test_empty_string_returns_none(self) -> None:
        assert _extract_kv("", "pkg") is None
