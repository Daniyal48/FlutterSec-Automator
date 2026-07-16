"""Unit tests for fluttersec.core.extractor and fluttersec.core.engine_detect.

All tests are fully self-contained — no real APK or libflutter.so is required.
Synthetic fixtures are constructed in-process using only the standard library.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from fluttersec.core.engine_detect import detect_all_engine_hashes, detect_engine_hash
from fluttersec.core.extractor import extract_libflutter

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------
_FAKE_HASH: str = "a" * 39 + "f"          # 40 lowercase hex chars, valid format
_SECOND_HASH: str = "b" * 39 + "e"        # second unique hash for multi-hash tests
_LIBFLUTTER_CONTENT: bytes = b"\x7fELF" + b"\x00" * 60  # tiny ELF stub payload


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def tmp_apk(tmp_path: Path) -> Path:
    """Return a synthetic APK (ZIP) containing lib/arm64-v8a/libflutter.so."""
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("lib/arm64-v8a/libflutter.so", _LIBFLUTTER_CONTENT)
        zf.writestr("AndroidManifest.xml", b"placeholder")
    return apk


@pytest.fixture()
def apk_without_flutter(tmp_path: Path) -> Path:
    """Return a synthetic APK that has NO libflutter.so entry."""
    apk = tmp_path / "no_flutter.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"placeholder")
    return apk


@pytest.fixture()
def lib_with_hash(tmp_path: Path) -> Path:
    """Return a fake libflutter.so with a 40-char hash near 'flutter_assets'."""
    content = (
        b"\x00" * 128
        + b"flutter_assets"
        + b"\x00" * 16
        + _FAKE_HASH.encode("ascii")
        + b"\x00" * 128
    )
    lib = tmp_path / "libflutter.so"
    lib.write_bytes(content)
    return lib


@pytest.fixture()
def lib_no_anchor(tmp_path: Path) -> Path:
    """Return a fake libflutter.so with NO 'flutter_assets' string."""
    lib = tmp_path / "libflutter_no_anchor.so"
    lib.write_bytes(b"\x00" * 512 + _FAKE_HASH.encode("ascii") + b"\x00" * 64)
    return lib


@pytest.fixture()
def lib_no_hash_near_anchor(tmp_path: Path) -> Path:
    """Return a fake libflutter.so with 'flutter_assets' but no hash within window."""
    # Hash is placed 4096 bytes away from anchor — outside the default 2048 window
    lib = tmp_path / "libflutter_far_hash.so"
    content = (
        b"flutter_assets"
        + b"\x00" * 4096
        + _FAKE_HASH.encode("ascii")
        + b"\x00" * 64
    )
    lib.write_bytes(content)
    return lib


@pytest.fixture()
def lib_with_two_hashes(tmp_path: Path) -> Path:
    """Return a fake libflutter.so with two distinct hashes near two anchors."""
    content = (
        b"flutter_assets" + b"\x00" * 8 + _FAKE_HASH.encode("ascii") + b"\x00" * 256
        + b"flutter_assets" + b"\x00" * 8 + _SECOND_HASH.encode("ascii") + b"\x00" * 64
    )
    lib = tmp_path / "libflutter_two.so"
    lib.write_bytes(content)
    return lib


# ===========================================================================
# Tests: extract_libflutter
# ===========================================================================
class TestExtractLibflutter:
    """Tests for :func:`fluttersec.core.extractor.extract_libflutter`."""

    def test_returns_path_to_libflutter(self, tmp_apk: Path, tmp_path: Path) -> None:
        """Should return a Path whose name is 'libflutter.so'."""
        result = extract_libflutter(tmp_apk, tmp_path)
        assert result.name == "libflutter.so"

    def test_extracted_file_exists(self, tmp_apk: Path, tmp_path: Path) -> None:
        """Extracted file must exist on disk after the call returns."""
        result = extract_libflutter(tmp_apk, tmp_path)
        assert result.exists(), "libflutter.so must be written to disk."

    def test_extracted_file_is_in_arm64_subdir(
        self, tmp_apk: Path, tmp_path: Path
    ) -> None:
        """Extracted file must be placed inside an 'arm64-v8a' sub-directory."""
        result = extract_libflutter(tmp_apk, tmp_path)
        assert result.parent.name == "arm64-v8a"

    def test_extracted_content_matches_original(
        self, tmp_apk: Path, tmp_path: Path
    ) -> None:
        """Extracted bytes must be identical to those stored in the APK."""
        result = extract_libflutter(tmp_apk, tmp_path)
        assert result.read_bytes() == _LIBFLUTTER_CONTENT

    def test_auto_creates_temp_dir_when_dest_is_none(self, tmp_apk: Path) -> None:
        """When dest_dir is None, a temporary directory should be created."""
        result = extract_libflutter(tmp_apk, dest_dir=None)
        try:
            assert result.exists()
            assert result.name == "libflutter.so"
        finally:
            # Clean up the auto-created temp dir
            import shutil
            shutil.rmtree(result.parent.parent, ignore_errors=True)

    def test_raises_file_not_found_for_missing_apk(self, tmp_path: Path) -> None:
        """Must raise FileNotFoundError if the APK path does not exist."""
        with pytest.raises(FileNotFoundError, match="APK not found"):
            extract_libflutter(Path("/nonexistent/path.apk"), tmp_path)

    def test_raises_value_error_when_no_libflutter(
        self, apk_without_flutter: Path, tmp_path: Path
    ) -> None:
        """Must raise ValueError if libflutter.so is absent from the APK."""
        with pytest.raises(ValueError, match="lib/arm64-v8a/libflutter.so"):
            extract_libflutter(apk_without_flutter, tmp_path)

    def test_raises_bad_zip_for_non_zip_file(self, tmp_path: Path) -> None:
        """Must raise BadZipFile for a file that is not a valid ZIP archive."""
        fake = tmp_path / "corrupt.apk"
        fake.write_bytes(b"NOT_A_ZIP_FILE_AT_ALL")
        with pytest.raises(zipfile.BadZipFile):
            extract_libflutter(fake, tmp_path)

    def test_idempotent_second_extraction(self, tmp_apk: Path, tmp_path: Path) -> None:
        """Calling extract_libflutter twice on the same dest_dir must succeed."""
        r1 = extract_libflutter(tmp_apk, tmp_path)
        r2 = extract_libflutter(tmp_apk, tmp_path)
        assert r1 == r2
        assert r2.read_bytes() == _LIBFLUTTER_CONTENT


# ===========================================================================
# Tests: detect_engine_hash
# ===========================================================================
class TestDetectEngineHash:
    """Tests for :func:`fluttersec.core.engine_detect.detect_engine_hash`."""

    def test_returns_hash_string(self, lib_with_hash: Path) -> None:
        """Should return the 40-char hash string when present near anchor."""
        result = detect_engine_hash(lib_with_hash)
        assert result == _FAKE_HASH

    def test_hash_is_40_chars(self, lib_with_hash: Path) -> None:
        """Returned hash must be exactly 40 characters long."""
        result = detect_engine_hash(lib_with_hash)
        assert result is not None
        assert len(result) == 40

    def test_hash_is_lowercase_hex(self, lib_with_hash: Path) -> None:
        """Returned hash must consist solely of lowercase hexadecimal characters."""
        result = detect_engine_hash(lib_with_hash)
        assert result is not None
        assert all(c in "0123456789abcdef" for c in result)

    def test_returns_none_when_no_anchor(self, lib_no_anchor: Path) -> None:
        """Should return None when 'flutter_assets' is absent from the binary."""
        result = detect_engine_hash(lib_no_anchor)
        assert result is None

    def test_returns_none_when_hash_outside_default_window(
        self, lib_no_hash_near_anchor: Path
    ) -> None:
        """Should return None when the hash is beyond the default search window."""
        result = detect_engine_hash(lib_no_hash_near_anchor, window=2048)
        assert result is None

    def test_finds_hash_with_larger_window(
        self, lib_no_hash_near_anchor: Path
    ) -> None:
        """Widening the window should find a hash that was previously out of range."""
        result = detect_engine_hash(lib_no_hash_near_anchor, window=8192)
        assert result == _FAKE_HASH

    def test_raises_file_not_found_for_missing_lib(self, tmp_path: Path) -> None:
        """Must raise FileNotFoundError if lib_path does not exist."""
        with pytest.raises(FileNotFoundError, match="Library not found"):
            detect_engine_hash(Path("/nonexistent/libflutter.so"))

    def test_hash_preceded_by_anchor_in_different_positions(
        self, tmp_path: Path
    ) -> None:
        """Hash should be found regardless of how many padding bytes separate it."""
        for padding in (0, 4, 16, 64, 512):
            lib = tmp_path / f"lib_pad_{padding}.so"
            lib.write_bytes(
                b"flutter_assets"
                + b"\x00" * padding
                + _FAKE_HASH.encode("ascii")
                + b"\x00" * 32
            )
            result = detect_engine_hash(lib)
            assert result == _FAKE_HASH, (
                f"Hash not found with {padding} padding bytes between anchor and hash."
            )


# ===========================================================================
# Tests: detect_all_engine_hashes
# ===========================================================================
class TestDetectAllEngineHashes:
    """Tests for :func:`fluttersec.core.engine_detect.detect_all_engine_hashes`."""

    def test_returns_list(self, lib_with_hash: Path) -> None:
        """Should always return a list."""
        result = detect_all_engine_hashes(lib_with_hash)
        assert isinstance(result, list)

    def test_single_hash_returns_one_element(self, lib_with_hash: Path) -> None:
        """Single-anchor binary should yield a list with exactly one hash."""
        result = detect_all_engine_hashes(lib_with_hash)
        assert result == [_FAKE_HASH]

    def test_two_anchors_returns_two_unique_hashes(
        self, lib_with_two_hashes: Path
    ) -> None:
        """Two distinct anchors with different hashes should yield two results."""
        result = detect_all_engine_hashes(lib_with_two_hashes)
        assert len(result) == 2
        assert _FAKE_HASH in result
        assert _SECOND_HASH in result

    def test_deduplicates_identical_hashes(self, tmp_path: Path) -> None:
        """Same hash appearing near multiple anchors should be deduplicated."""
        content = (
            b"flutter_assets" + b"\x00" * 8 + _FAKE_HASH.encode("ascii") + b"\x00" * 128
            + b"flutter_assets" + b"\x00" * 8 + _FAKE_HASH.encode("ascii") + b"\x00" * 64
        )
        lib = tmp_path / "dup_hash.so"
        lib.write_bytes(content)
        result = detect_all_engine_hashes(lib)
        assert result == [_FAKE_HASH], "Duplicate hash entries must be deduplicated."

    def test_empty_list_when_no_anchor(self, lib_no_anchor: Path) -> None:
        """Should return an empty list when no 'flutter_assets' anchor exists."""
        result = detect_all_engine_hashes(lib_no_anchor)
        assert result == []

    def test_raises_file_not_found_for_missing_lib(self) -> None:
        """Must raise FileNotFoundError if lib_path does not exist."""
        with pytest.raises(FileNotFoundError, match="Library not found"):
            detect_all_engine_hashes(Path("/nonexistent/libflutter.so"))
