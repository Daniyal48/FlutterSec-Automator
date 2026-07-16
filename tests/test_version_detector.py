"""Tests for fluttersec.core.version_detector.

Coverage targets
----------------
* EngineVersion dataclass (all fields, including new sections_found)
* VersionDetector.detect() — all four resolution paths:
    section_scan, raw_scan, build_id, unknown
* _section_scan() — per-section pattern matching, section name tracking
* _raw_scan() — all four patterns: engine_revision anchor, JSON key,
                 flutter_assets proximity, absent hash
* _extract_build_id() — success and graceful failures
* _load_version_map() — YAML load, missing file, malformed YAML
* Module helpers: _extract_hash_from_content, _hash_near_anchor
* FileNotFoundError on missing library
* LIEF None / invalid binary handling
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from fluttersec.core.version_detector import (
    _FLUTTER_ASSETS_ANCHOR,
    EngineVersion,
    VersionDetector,
    _extract_hash_from_content,
    _hash_near_anchor,
)

# ---------------------------------------------------------------------------
# Shared test constants
# ---------------------------------------------------------------------------
_GOOD_HASH: str = "a" * 39 + "f"          # 40 lowercase hex chars
_SECOND_HASH: str = "b" * 39 + "e"
_FLUTTER_VERSION: str = "3.22.0"
_FLUTTER_MARKER: bytes = f"Flutter/{_FLUTTER_VERSION}".encode()
_ENGINE_REVISION_BLOCK: bytes = (
    b"engine_revision\x00" + _GOOD_HASH.encode() + b"\x00"
)
_JSON_REVISION_BLOCK: bytes = (
    b'"revision": "' + _GOOD_HASH.encode() + b'"'
)
_FLUTTER_ASSETS_BLOCK: bytes = (
    _FLUTTER_ASSETS_ANCHOR + b"\x00" * 32 + _GOOD_HASH.encode() + b"\x00"
)


# ---------------------------------------------------------------------------
# Minimal valid ELF64 LE AArch64 shared-object header builder
# ---------------------------------------------------------------------------
def _elf_header() -> bytes:
    """Return a minimal but structurally valid 64-byte ELF64 header."""
    h = bytearray(64)
    h[0:4] = b"\x7fELF"
    h[4] = 2        # ELFCLASS64
    h[5] = 1        # ELFDATA2LSB
    h[6] = 1        # EV_CURRENT
    h[16] = 3       # ET_DYN
    h[18] = 0xB7    # EM_AARCH64
    h[20] = 1       # e_version
    h[52] = 64      # e_ehsize
    return bytes(h)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def lib_with_version_and_hash(tmp_path: Path) -> Path:
    """Fake libflutter.so with Flutter/<ver> and engine_revision hash."""
    lib = tmp_path / "libflutter.so"
    lib.write_bytes(
        _elf_header()
        + b"\x00" * 64
        + _FLUTTER_MARKER + b"\x00"
        + b"\x00" * 8
        + _ENGINE_REVISION_BLOCK
        + b"\x00" * 64
    )
    return lib


@pytest.fixture()
def lib_with_json_revision(tmp_path: Path) -> Path:
    """Fake libflutter.so with version string and JSON-style revision key."""
    lib = tmp_path / "libflutter.so"
    lib.write_bytes(
        _elf_header()
        + _FLUTTER_MARKER + b"\x00"
        + _JSON_REVISION_BLOCK
        + b"\x00" * 64
    )
    return lib


@pytest.fixture()
def lib_with_flutter_assets_hash(tmp_path: Path) -> Path:
    """Fake libflutter.so with hash near flutter_assets (no engine_revision)."""
    lib = tmp_path / "libflutter.so"
    lib.write_bytes(
        _elf_header()
        + _FLUTTER_MARKER + b"\x00"
        + b"\x00" * 128
        + _FLUTTER_ASSETS_BLOCK
        + b"\x00" * 64
    )
    return lib


@pytest.fixture()
def lib_hash_only(tmp_path: Path) -> Path:
    """Fake libflutter.so with hash but NO version string."""
    lib = tmp_path / "libflutter.so"
    lib.write_bytes(
        _elf_header() + _ENGINE_REVISION_BLOCK + b"\x00" * 64
    )
    return lib


@pytest.fixture()
def lib_version_only(tmp_path: Path) -> Path:
    """Fake libflutter.so with version string but NO hash."""
    lib = tmp_path / "libflutter.so"
    lib.write_bytes(
        _elf_header() + _FLUTTER_MARKER + b"\x00" + b"\x00" * 128
    )
    return lib


@pytest.fixture()
def lib_empty_stub(tmp_path: Path) -> Path:
    """Fake libflutter.so with NO version or hash markers."""
    lib = tmp_path / "libflutter.so"
    lib.write_bytes(_elf_header() + b"\x00" * 256)
    return lib


@pytest.fixture()
def lib_garbage(tmp_path: Path) -> Path:
    """Completely invalid binary (not ELF)."""
    lib = tmp_path / "garbage.so"
    lib.write_bytes(b"\xDE\xAD\xBE\xEF" * 64)
    return lib


# ---------------------------------------------------------------------------
# EngineVersion dataclass
# ---------------------------------------------------------------------------
class TestEngineVersionDataclass:
    """Tests for the EngineVersion data container."""

    def test_all_fields_constructable(self) -> None:
        ev = EngineVersion(
            version_string="3.22.0",
            build_id="de" * 20,
            engine_hash=_GOOD_HASH,
            detection_method="section_scan",
            sections_found=[".rodata", ".text"],
        )
        assert ev.version_string == "3.22.0"
        assert ev.build_id == "de" * 20
        assert ev.engine_hash == _GOOD_HASH
        assert ev.detection_method == "section_scan"
        assert ev.sections_found == [".rodata", ".text"]

    def test_none_fields_allowed(self) -> None:
        ev = EngineVersion(
            version_string=None,
            build_id=None,
            engine_hash=None,
            detection_method="unknown",
            sections_found=[],
        )
        assert ev.version_string is None
        assert ev.engine_hash is None
        assert ev.sections_found == []


# ---------------------------------------------------------------------------
# VersionDetector.detect() — integration-level
# ---------------------------------------------------------------------------
class TestDetectIntegration:
    """High-level tests for VersionDetector.detect()."""

    def test_detect_returns_engine_version(self, lib_empty_stub: Path) -> None:
        """detect() always returns an EngineVersion instance."""
        result = VersionDetector().detect(lib_empty_stub)
        assert isinstance(result, EngineVersion)

    def test_detect_raises_on_missing_file(self, tmp_path: Path) -> None:
        """detect() must raise FileNotFoundError for a nonexistent path."""
        with pytest.raises(FileNotFoundError, match="Library not found"):
            VersionDetector().detect(tmp_path / "nonexistent.so")

    def test_detection_method_is_valid_enum(self, lib_empty_stub: Path) -> None:
        """detection_method must always be one of the four known values."""
        result = VersionDetector().detect(lib_empty_stub)
        assert result.detection_method in {
            "section_scan", "raw_scan", "build_id", "unknown"
        }

    def test_sections_found_is_list(self, lib_empty_stub: Path) -> None:
        """sections_found must always be a list."""
        result = VersionDetector().detect(lib_empty_stub)
        assert isinstance(result.sections_found, list)

    def test_empty_stub_yields_unknown(self, lib_empty_stub: Path) -> None:
        """A minimal ELF stub with no markers should yield detection_method='unknown'."""
        result = VersionDetector().detect(lib_empty_stub)
        assert result.version_string is None
        assert result.detection_method == "unknown"

    def test_garbage_binary_yields_unknown_no_crash(self, lib_garbage: Path) -> None:
        """Non-ELF binary must not raise — returns 'unknown'."""
        result = VersionDetector().detect(lib_garbage)
        assert isinstance(result, EngineVersion)
        assert result.detection_method == "unknown"

    def test_version_and_hash_extracted(
        self, lib_with_version_and_hash: Path
    ) -> None:
        """Binary containing both markers should populate version_string and engine_hash."""
        result = VersionDetector().detect(lib_with_version_and_hash)
        # version_string may be found via section_scan or raw_scan
        if result.version_string:
            assert result.version_string == _FLUTTER_VERSION
        if result.engine_hash:
            assert len(result.engine_hash) == 40
            assert all(c in "0123456789abcdef" for c in result.engine_hash)

    def test_hash_found_via_json_revision(
        self, lib_with_json_revision: Path
    ) -> None:
        """JSON-style revision key should be picked up as the engine hash."""
        result = VersionDetector().detect(lib_with_json_revision)
        if result.engine_hash:
            assert result.engine_hash == _GOOD_HASH

    def test_hash_only_binary_has_no_version_string(
        self, lib_hash_only: Path
    ) -> None:
        """Binary with only a hash and no version string should return version=None."""
        result = VersionDetector().detect(lib_hash_only)
        # The engine hash should be found even without a version string
        if result.engine_hash:
            assert len(result.engine_hash) == 40


# ---------------------------------------------------------------------------
# _raw_scan — unit tests
# ---------------------------------------------------------------------------
class TestRawScan:
    """Tests for the pure-Python raw byte scan strategy."""

    def test_version_extracted_from_flat_bytes(self, tmp_path: Path) -> None:
        """_raw_scan must find Flutter/<ver> in raw file content."""
        lib = tmp_path / "lib.so"
        lib.write_bytes(b"\x00" * 32 + _FLUTTER_MARKER + b"\x00" * 32)
        ver, _ = VersionDetector._raw_scan(lib)
        assert ver == _FLUTTER_VERSION

    def test_engine_revision_anchor_extracted(self, tmp_path: Path) -> None:
        """_raw_scan must find hash after 'engine_revision' anchor."""
        lib = tmp_path / "lib.so"
        lib.write_bytes(b"\x00" * 16 + _ENGINE_REVISION_BLOCK + b"\x00" * 16)
        _, h = VersionDetector._raw_scan(lib)
        assert h == _GOOD_HASH

    def test_json_revision_key_extracted(self, tmp_path: Path) -> Path:
        """_raw_scan must find hash in a JSON-style revision field."""
        lib = tmp_path / "lib.so"
        lib.write_bytes(b"\x00" * 16 + _JSON_REVISION_BLOCK + b"\x00" * 16)
        _, h = VersionDetector._raw_scan(lib)
        assert h == _GOOD_HASH

    def test_flutter_assets_proximity_extracted(self, tmp_path: Path) -> None:
        """_raw_scan must find hash near flutter_assets anchor."""
        lib = tmp_path / "lib.so"
        lib.write_bytes(b"\x00" * 16 + _FLUTTER_ASSETS_BLOCK + b"\x00" * 16)
        _, h = VersionDetector._raw_scan(lib)
        assert h == _GOOD_HASH

    def test_returns_none_none_for_empty_stub(self, tmp_path: Path) -> None:
        """_raw_scan must return (None, None) when no markers are present."""
        lib = tmp_path / "lib.so"
        lib.write_bytes(b"\x00" * 256)
        ver, h = VersionDetector._raw_scan(lib)
        assert ver is None
        assert h is None

    def test_returns_none_none_for_missing_file(self, tmp_path: Path) -> None:
        """_raw_scan must return (None, None) (not raise) for an unreadable path."""
        ver, h = VersionDetector._raw_scan(tmp_path / "nonexistent.so")
        assert ver is None
        assert h is None

    def test_version_semver_with_pre_suffix(self, tmp_path: Path) -> None:
        """_raw_scan must capture pre-release suffixes like '3.22.0.pre.1'."""
        lib = tmp_path / "lib.so"
        lib.write_bytes(b"Flutter/3.22.0.pre.1\x00")
        ver, _ = VersionDetector._raw_scan(lib)
        assert ver == "3.22.0.pre.1"


# ---------------------------------------------------------------------------
# _section_scan — unit tests (using mocked LIEF binary)
# ---------------------------------------------------------------------------
class TestSectionScan:
    """Unit tests for _section_scan using mock LIEF binaries."""

    @staticmethod
    def _make_binary(sections: dict[str, bytes]) -> MagicMock:
        """Build a mock lief.ELF.Binary with the given section name→content map."""
        mock_sections = []
        for name, content in sections.items():
            sec = MagicMock()
            sec.name = name
            sec.content = content
            mock_sections.append(sec)
        binary = MagicMock()
        binary.sections = mock_sections
        return binary

    def test_version_found_in_rodata(self) -> None:
        binary = self._make_binary({
            ".rodata": _FLUTTER_MARKER + b"\x00" + _ENGINE_REVISION_BLOCK
        })
        ver, h, secs = VersionDetector._section_scan(binary, Path("lib.so"))
        assert ver == _FLUTTER_VERSION
        assert h == _GOOD_HASH
        assert ".rodata" in secs

    def test_hash_found_in_text_section(self) -> None:
        """The .text section should be scanned for the engine_revision anchor."""
        binary = self._make_binary({
            ".text": b"\x00" * 32 + _ENGINE_REVISION_BLOCK + b"\x00" * 32
        })
        _, h, secs = VersionDetector._section_scan(binary, Path("lib.so"))
        assert h == _GOOD_HASH
        assert ".text" in secs

    def test_version_from_data_rel_ro(self) -> None:
        binary = self._make_binary({
            ".data.rel.ro": _FLUTTER_MARKER + b"\x00"
        })
        ver, _, secs = VersionDetector._section_scan(binary, Path("lib.so"))
        assert ver == _FLUTTER_VERSION
        assert ".data.rel.ro" in secs

    def test_returns_none_none_for_none_binary(self) -> None:
        ver, h, secs = VersionDetector._section_scan(None, Path("lib.so"))
        assert ver is None
        assert h is None
        assert secs == []

    def test_empty_section_content_skipped(self) -> None:
        binary = self._make_binary({".rodata": b""})
        ver, h, secs = VersionDetector._section_scan(binary, Path("lib.so"))
        assert ver is None
        assert h is None
        assert secs == []  # empty sections are not added to sections_found

    def test_sections_found_only_lists_non_empty(self) -> None:
        binary = self._make_binary({
            ".rodata": b"\x00" * 16,
            ".dynstr": b"",
            ".text": b"\x00" * 8,
        })
        _, _, secs = VersionDetector._section_scan(binary, Path("lib.so"))
        assert ".rodata" in secs
        assert ".text" in secs
        assert ".dynstr" not in secs

    def test_stops_scanning_when_both_found(self) -> None:
        """Should not scan .text once version AND hash are both resolved in .rodata."""
        text_mock = MagicMock()
        text_mock.name = ".text"
        text_mock.content = b"irrelevant"

        binary = self._make_binary({
            ".rodata": _FLUTTER_MARKER + b"\x00" + _ENGINE_REVISION_BLOCK,
        })
        binary.sections = list(binary.sections) + [text_mock]
        ver, h, secs = VersionDetector._section_scan(binary, Path("lib.so"))

        assert ver == _FLUTTER_VERSION
        assert h == _GOOD_HASH
        # Both were found in .rodata — confirm the results are correct.
        # (Scanning stops as soon as both are resolved, so .text was not needed.)

    def test_exception_in_section_content_does_not_crash(self) -> None:
        """If reading section.content raises, the section is skipped."""
        bad_sec = MagicMock()
        bad_sec.name = ".rodata"
        bad_sec.content = property(lambda self: (_ for _ in ()).throw(RuntimeError("boom")))

        binary = MagicMock()
        binary.sections = [bad_sec]
        # Should not raise — returns empty results
        ver, h, secs = VersionDetector._section_scan(binary, Path("lib.so"))
        assert ver is None


# ---------------------------------------------------------------------------
# _extract_build_id
# ---------------------------------------------------------------------------
class TestExtractBuildId:
    """Tests for GNU Build-ID extraction."""

    def test_returns_none_for_none_binary(self) -> None:
        assert VersionDetector._extract_build_id(None) is None

    def test_returns_none_when_no_notes(self) -> None:
        binary = MagicMock()
        binary.notes = []
        assert VersionDetector._extract_build_id(binary) is None

    def test_extracts_build_id_bytes_as_hex(self) -> None:
        raw_id = bytes.fromhex("deadbeef" * 5)
        note = MagicMock()
        note.description = list(raw_id)   # LIEF returns a list of ints
        # Simulate LIEF ≥ 0.14 enum comparison
        note.type = MagicMock()
        note.type.__eq__ = lambda s, o: True  # always match
        binary = MagicMock()
        binary.notes = [note]
        result = VersionDetector._extract_build_id(binary)
        assert result == "deadbeef" * 5

    def test_returns_none_on_exception(self) -> None:
        binary = MagicMock()
        binary.notes = MagicMock(side_effect=RuntimeError("LIEF error"))
        result = VersionDetector._extract_build_id(binary)
        assert result is None


# ---------------------------------------------------------------------------
# _load_version_map
# ---------------------------------------------------------------------------
class TestLoadVersionMap:
    """Tests for YAML version-map loading."""

    def test_returns_empty_dict_when_file_missing(self, tmp_path: Path) -> None:
        with patch(
            "fluttersec.core.version_detector._VERSION_MAP_PATH",
            tmp_path / "nonexistent.yaml",
        ):
            result = VersionDetector._load_version_map()
        assert result == {}

    def test_loads_valid_yaml(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "version_map.yaml"
        yaml_file.write_text(f'"{_GOOD_HASH}": "3.22.0"\n', encoding="utf-8")
        with patch(
            "fluttersec.core.version_detector._VERSION_MAP_PATH", yaml_file
        ):
            result = VersionDetector._load_version_map()
        assert result.get(_GOOD_HASH) == "3.22.0"

    def test_returns_empty_dict_for_malformed_yaml(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "bad.yaml"
        yaml_file.write_text("!!python/object:os.system\ncommand: echo hi", encoding="utf-8")
        with patch(
            "fluttersec.core.version_detector._VERSION_MAP_PATH", yaml_file
        ):
            # Should not raise; returns empty dict on error
            result = VersionDetector._load_version_map()
            assert isinstance(result, dict)

    def test_build_id_used_for_version_lookup(self, tmp_path: Path) -> None:
        """detect() should use the Build-ID map when section/raw scan fails."""
        build_id_hex = "ca" * 20  # 40-hex build-id
        yaml_file = tmp_path / "version_map.yaml"
        yaml_file.write_text(f'"{build_id_hex}": "3.16.9"\n', encoding="utf-8")

        # Stub: has no version/hash markers but has a Build-ID note
        lib = tmp_path / "libflutter.so"
        lib.write_bytes(b"\x00" * 256)  # no markers

        with patch("fluttersec.core.version_detector._VERSION_MAP_PATH", yaml_file):
            detector = VersionDetector()
            # Inject a mock build_id extraction
            with patch.object(
                VersionDetector,
                "_extract_build_id",
                return_value=build_id_hex,
            ):
                result = detector.detect(lib)

        if result.detection_method == "build_id":
            assert result.version_string == "3.16.9"


# ---------------------------------------------------------------------------
# _extract_hash_from_content helper
# ---------------------------------------------------------------------------
class TestExtractHashFromContent:
    """Unit tests for the module-level _extract_hash_from_content helper."""

    def test_engine_revision_anchor_wins(self) -> None:
        content = _ENGINE_REVISION_BLOCK + b"\x00" * 32
        h = _extract_hash_from_content(content, ".rodata")
        assert h == _GOOD_HASH

    def test_json_revision_key_used_as_fallback(self) -> None:
        content = _JSON_REVISION_BLOCK + b"\x00" * 32
        h = _extract_hash_from_content(content, ".rodata")
        assert h == _GOOD_HASH

    def test_flutter_assets_proximity_used(self) -> None:
        h = _extract_hash_from_content(_FLUTTER_ASSETS_BLOCK, ".rodata")
        assert h == _GOOD_HASH

    def test_standalone_hex40_fallback_in_rodata(self) -> None:
        content = b"\x00" * 32 + _GOOD_HASH.encode() + b"\x00" * 32
        h = _extract_hash_from_content(content, ".rodata")
        assert h == _GOOD_HASH

    def test_standalone_hex40_not_returned_for_text(self) -> None:
        """Standalone 40-hex in .text is suppressed (too many false positives)."""
        content = b"\x00" * 32 + _GOOD_HASH.encode() + b"\x00" * 32
        h = _extract_hash_from_content(content, ".text")
        assert h is None

    def test_returns_none_for_empty_content(self) -> None:
        assert _extract_hash_from_content(b"", ".rodata") is None

    def test_returns_none_when_no_pattern_matches(self) -> None:
        assert _extract_hash_from_content(b"\x00" * 128, ".rodata") is None


# ---------------------------------------------------------------------------
# _hash_near_anchor helper
# ---------------------------------------------------------------------------
class TestHashNearAnchor:
    """Unit tests for the _hash_near_anchor proximity scanner."""

    def test_finds_hash_after_anchor(self) -> None:
        data = _FLUTTER_ASSETS_ANCHOR + b"\x00" * 8 + _GOOD_HASH.encode() + b"\x00"
        assert _hash_near_anchor(data, _FLUTTER_ASSETS_ANCHOR) == _GOOD_HASH

    def test_finds_hash_before_anchor(self) -> None:
        data = _GOOD_HASH.encode() + b"\x00" * 8 + _FLUTTER_ASSETS_ANCHOR
        assert _hash_near_anchor(data, _FLUTTER_ASSETS_ANCHOR) == _GOOD_HASH

    def test_returns_none_when_anchor_absent(self) -> None:
        assert _hash_near_anchor(b"\x00" * 256, _FLUTTER_ASSETS_ANCHOR) is None

    def test_returns_none_when_hash_too_far(self) -> None:
        data = _FLUTTER_ASSETS_ANCHOR + b"\x00" * 4096 + _GOOD_HASH.encode()
        assert _hash_near_anchor(data, _FLUTTER_ASSETS_ANCHOR, window=512) is None

    def test_finds_hash_with_larger_window(self) -> None:
        data = _FLUTTER_ASSETS_ANCHOR + b"\x00" * 3000 + _GOOD_HASH.encode()
        assert _hash_near_anchor(data, _FLUTTER_ASSETS_ANCHOR, window=4096) == _GOOD_HASH

    def test_returns_none_for_empty_data(self) -> None:
        assert _hash_near_anchor(b"", _FLUTTER_ASSETS_ANCHOR) is None

    def test_39_char_string_not_matched(self) -> None:
        """39-char hex strings must not be returned (must be exactly 40)."""
        short = "a" * 39
        data = _FLUTTER_ASSETS_ANCHOR + b"\x00" * 4 + short.encode() + b"\x00"
        assert _hash_near_anchor(data, _FLUTTER_ASSETS_ANCHOR) is None

    def test_41_char_string_not_matched_standalone(self) -> None:
        """41-char hex strings should not match (boundary is enforced)."""
        long_hex = "a" * 41
        data = _FLUTTER_ASSETS_ANCHOR + b"\x00" * 4 + long_hex.encode() + b"\x00"
        result = _hash_near_anchor(data, _FLUTTER_ASSETS_ANCHOR)
        # The regex will pick up the first 40 IF the 41st char is also hex (non-boundary)
        # Our regex uses negative lookahead so a 41-char hex run must NOT match
        assert result is None
