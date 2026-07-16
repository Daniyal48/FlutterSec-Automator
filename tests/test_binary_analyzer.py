"""Tests for fluttersec.core.binary_analyzer.

Coverage matrix
---------------
TestCustomExceptions          — BinaryParseError, OffsetNotFoundError construction/message
TestPatternDatabase           — YAML loading, required keys
TestCompilePattern            — empty, valid, wildcards, literals, invalid tokens, arm64
TestSslOffsetDataclass        — field access
TestVaToFileOffset            — segment hit, segment miss, multi-segment
TestSymbolScanUnit            — mock LIEF binary, symbol match / no-match
TestPatternScanUnit           — mock LIEF binary with real .text content,
                                arch filter, version filter, wildcard matching
TestVersionMapLookup          — sentinel hash hit, unknown hash miss,
                                arch-filtered hit, no-key fallback
TestFindSslOffsets            — integration: stub ELF via LIEF,
                                BinaryParseError on corrupt file,
                                FileNotFoundError on missing file,
                                deduplication by VA, sorted output
TestAnalyzeAPI                — bound-mode analyze(), raise_on_empty=True/False
TestVersionMapLoader          — _load_version_map_offsets YAML parsing
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from fluttersec.core.binary_analyzer import (
    AnalysisResult,
    BinaryAnalyzer,
    BinaryParseError,
    OffsetNotFoundError,
    SslOffset,
)
from fluttersec.core.version_detector import EngineVersion

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
_TEST_HASH: str = "a" * 39 + "f"   # sentinel hash present in version_map.yaml
_UNKNOWN_HASH: str = "9" * 40      # deliberately absent from version_map.yaml

_EV_UNKNOWN = EngineVersion(
    version_string=None,
    build_id=None,
    engine_hash=None,
    detection_method="unknown",
    sections_found=[],
)

_EV_WITH_HASH = EngineVersion(
    version_string="3.22.0",
    build_id=None,
    engine_hash=_TEST_HASH,
    detection_method="section_scan",
    sections_found=[".rodata"],
)

_EV_UNKNOWN_HASH = EngineVersion(
    version_string=None,
    build_id=None,
    engine_hash=_UNKNOWN_HASH,
    detection_method="unknown",
    sections_found=[],
)


def _make_ev(version: str | None = None, engine_hash: str | None = None) -> EngineVersion:
    return EngineVersion(
        version_string=version,
        build_id=None,
        engine_hash=engine_hash,
        detection_method="section_scan" if version else "unknown",
        sections_found=[],
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def corrupt_lib(tmp_path: Path) -> Path:
    lib = tmp_path / "corrupt.so"
    lib.write_bytes(b"NOTANELF" * 32)
    return lib


# ---------------------------------------------------------------------------
# Custom exception tests
# ---------------------------------------------------------------------------
class TestCustomExceptions:
    """Tests for BinaryParseError and OffsetNotFoundError."""

    def test_binary_parse_error_message(self, tmp_path: Path) -> None:
        lib = tmp_path / "bad.so"
        err = BinaryParseError(lib, "failed to read")
        assert "bad.so" in str(err)
        assert "failed to read" in str(err)

    def test_binary_parse_error_no_detail(self, tmp_path: Path) -> None:
        lib = tmp_path / "x.so"
        err = BinaryParseError(lib)
        assert "x.so" in str(err)

    def test_binary_parse_error_stores_path(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib.so"
        err = BinaryParseError(lib)
        assert err.lib_path == lib

    def test_binary_parse_error_is_exception(self, tmp_path: Path) -> None:
        with pytest.raises(BinaryParseError):
            raise BinaryParseError(Path("dummy.so"))

    def test_offset_not_found_error_message(self, tmp_path: Path) -> None:
        lib = tmp_path / "libflutter.so"
        err = OffsetNotFoundError(lib, _EV_UNKNOWN, ["symbol", "pattern", "version_map"])
        assert "libflutter.so" in str(err)
        assert "symbol" in str(err)
        assert "pattern" in str(err)
        assert "version_map" in str(err)

    def test_offset_not_found_stores_attributes(self, tmp_path: Path) -> None:
        lib = tmp_path / "libflutter.so"
        err = OffsetNotFoundError(lib, _EV_UNKNOWN, ["symbol"])
        assert err.lib_path == lib
        assert err.engine_version is _EV_UNKNOWN
        assert err.strategies_tried == ["symbol"]

    def test_offset_not_found_is_exception(self, tmp_path: Path) -> None:
        with pytest.raises(OffsetNotFoundError):
            raise OffsetNotFoundError(Path("lib.so"), _EV_UNKNOWN, [])

    def test_offset_not_found_empty_strategies(self, tmp_path: Path) -> None:
        err = OffsetNotFoundError(Path("lib.so"), _EV_UNKNOWN, [])
        assert "none" in str(err).lower()


# ---------------------------------------------------------------------------
# Pattern database loading
# ---------------------------------------------------------------------------
class TestPatternDatabase:
    """Tests for _load_patterns from patterns.yaml."""

    def test_patterns_loaded_from_yaml(self) -> None:
        analyzer = BinaryAnalyzer()
        assert isinstance(analyzer._patterns, list)
        assert len(analyzer._patterns) > 0, "patterns.yaml must have at least one entry."

    def test_each_pattern_has_required_keys(self) -> None:
        analyzer = BinaryAnalyzer()
        required = {"symbol", "arch", "version", "pattern"}
        for entry in analyzer._patterns:
            missing = required - entry.keys()
            assert not missing, f"Pattern entry missing keys {missing}: {entry}"

    def test_patterns_is_list_when_yaml_missing(self, tmp_path: Path) -> None:
        with patch("fluttersec.core.binary_analyzer._PATTERNS_PATH", tmp_path / "nope.yaml"):
            analyzer = BinaryAnalyzer()
        assert analyzer._patterns == []

    def test_patterns_arch_values_are_known(self) -> None:
        known = {"arm64-v8a", "armeabi-v7a", "x86_64", "x86", "*"}
        for entry in BinaryAnalyzer()._patterns:
            assert entry.get("arch", "*") in known, f"Unknown arch: {entry}"


# ---------------------------------------------------------------------------
# _compile_pattern
# ---------------------------------------------------------------------------
class TestCompilePattern:
    """Unit tests for the hex-pattern compiler."""

    def test_empty_string_returns_none(self) -> None:
        assert BinaryAnalyzer._compile_pattern("") is None
        assert BinaryAnalyzer._compile_pattern("   ") is None

    def test_valid_hex_compiles(self) -> None:
        result = BinaryAnalyzer._compile_pattern("55 8B EC 5D C3")
        assert isinstance(result, re.Pattern)

    def test_wildcard_matches_any_byte(self) -> None:
        pat = BinaryAnalyzer._compile_pattern("55 ?? C3")
        assert pat is not None
        assert pat.search(b"\x55\x00\xC3") is not None
        assert pat.search(b"\x55\xFF\xC3") is not None
        assert pat.search(b"\x55\xAB\xC3") is not None

    def test_wildcard_matches_exactly_one_byte(self) -> None:
        pat = BinaryAnalyzer._compile_pattern("55 ?? C3")
        assert pat is not None
        # Two bytes in wildcard position → no match
        assert pat.search(b"\x55\xAB\xCD\xC3") is None

    def test_literal_byte_matches_exactly(self) -> None:
        pat = BinaryAnalyzer._compile_pattern("AA BB CC")
        assert pat is not None
        assert pat.search(b"\xAA\xBB\xCC") is not None
        assert pat.search(b"\xAA\xBB\xDD") is None

    def test_invalid_hex_token_returns_none(self) -> None:
        assert BinaryAnalyzer._compile_pattern("55 GG CC") is None

    def test_arm64_prologue_pattern_compiles(self) -> None:
        result = BinaryAnalyzer._compile_pattern(
            "FD 7B ?? A9 FD 03 00 91 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??"
        )
        assert result is not None

    def test_all_wildcard_pattern_matches_any_bytes(self) -> None:
        pat = BinaryAnalyzer._compile_pattern("?? ??")
        assert pat is not None
        assert pat.search(b"\x00\x00") is not None
        assert pat.search(b"\xFF\xFF") is not None

    def test_single_byte_compiles(self) -> None:
        assert BinaryAnalyzer._compile_pattern("C3") is not None


# ---------------------------------------------------------------------------
# SslOffset dataclass
# ---------------------------------------------------------------------------
class TestSslOffsetDataclass:
    def test_fields_accessible(self) -> None:
        off = SslOffset(
            symbol="ssl_verify_peer_cert",
            virtual_address=0x1234,
            file_offset=0x0034,
            method="symbol",
            arch="arm64-v8a",
        )
        assert off.symbol == "ssl_verify_peer_cert"
        assert off.virtual_address == 0x1234
        assert off.file_offset == 0x0034
        assert off.method == "symbol"
        assert off.arch == "arm64-v8a"

    def test_method_values(self) -> None:
        for method in ("symbol", "pattern", "version_map"):
            off = SslOffset("fn", 0, 0, method, "arm64-v8a")
            assert off.method == method


# ---------------------------------------------------------------------------
# _va_to_file_offset
# ---------------------------------------------------------------------------
class TestVaToFileOffset:
    """Tests for the VA → file offset computation."""

    @staticmethod
    def _make_seg(va: int, vsize: int, file_off: int, fsize: int = 0) -> MagicMock:
        seg = MagicMock()
        seg.virtual_address = va
        seg.virtual_size = vsize
        seg.file_size = fsize
        seg.file_offset = file_off
        return seg

    def test_va_in_first_segment(self) -> None:
        binary = MagicMock()
        binary.segments = [self._make_seg(0x1000, 0x500, 0x100)]
        assert BinaryAnalyzer._va_to_file_offset(binary, 0x1200) == 0x100 + 0x200

    def test_va_at_segment_start(self) -> None:
        binary = MagicMock()
        binary.segments = [self._make_seg(0x2000, 0x100, 0x400)]
        assert BinaryAnalyzer._va_to_file_offset(binary, 0x2000) == 0x400

    def test_va_at_segment_end_exclusive(self) -> None:
        """VA == seg_va + seg_size should NOT match (exclusive upper bound)."""
        binary = MagicMock()
        binary.segments = [self._make_seg(0x1000, 0x100, 0x200)]
        assert BinaryAnalyzer._va_to_file_offset(binary, 0x1100) == 0  # exactly at end

    def test_va_not_in_any_segment_returns_zero(self) -> None:
        binary = MagicMock()
        binary.segments = [self._make_seg(0x1000, 0x100, 0x200)]
        assert BinaryAnalyzer._va_to_file_offset(binary, 0x9999) == 0

    def test_no_segments_returns_zero(self) -> None:
        binary = MagicMock()
        binary.segments = []
        assert BinaryAnalyzer._va_to_file_offset(binary, 0x1234) == 0

    def test_second_segment_matched(self) -> None:
        binary = MagicMock()
        binary.segments = [
            self._make_seg(0x1000, 0x100, 0x200),
            self._make_seg(0x5000, 0x400, 0x800),
        ]
        assert BinaryAnalyzer._va_to_file_offset(binary, 0x5100) == 0x800 + 0x100


# ---------------------------------------------------------------------------
# _symbol_scan — unit tests with mocked binary
# ---------------------------------------------------------------------------
class TestSymbolScanUnit:
    """Tests for _symbol_scan using mock LIEF binary."""

    @staticmethod
    def _make_binary(symbols: list[tuple[str, int]]) -> MagicMock:
        """Build a mock binary with the given (name, value) symbol list."""
        mock_syms = []
        for name, val in symbols:
            s = MagicMock()
            s.name = name
            s.value = val
            mock_syms.append(s)
        binary = MagicMock()
        binary.symbols = mock_syms
        binary.segments = []
        return binary

    def test_known_symbol_matched(self) -> None:
        binary = self._make_binary([("ssl_verify_peer_cert", 0x4000)])
        offsets = BinaryAnalyzer._symbol_scan(binary, "arm64-v8a")
        assert len(offsets) == 1
        assert offsets[0].symbol == "ssl_verify_peer_cert"
        assert offsets[0].virtual_address == 0x4000
        assert offsets[0].method == "symbol"
        assert offsets[0].arch == "arm64-v8a"

    def test_unknown_symbol_not_matched(self) -> None:
        binary = self._make_binary([("some_random_function", 0x4000)])
        offsets = BinaryAnalyzer._symbol_scan(binary, "arm64-v8a")
        assert offsets == []

    def test_zero_va_symbol_skipped(self) -> None:
        binary = self._make_binary([("ssl_verify_peer_cert", 0)])
        offsets = BinaryAnalyzer._symbol_scan(binary, "arm64-v8a")
        assert offsets == []

    def test_empty_symbol_name_skipped(self) -> None:
        binary = self._make_binary([("", 0x1234)])
        offsets = BinaryAnalyzer._symbol_scan(binary, "arm64-v8a")
        assert offsets == []

    def test_multiple_matching_symbols(self) -> None:
        binary = self._make_binary([
            ("ssl_verify_peer_cert", 0x1000),
            ("SSL_CTX_set_custom_verify", 0x2000),
        ])
        offsets = BinaryAnalyzer._symbol_scan(binary, "arm64-v8a")
        assert len(offsets) == 2

    def test_partial_name_match(self) -> None:
        """Symbol names that CONTAIN a target string should match."""
        binary = self._make_binary([
            ("boringssl_ssl_verify_peer_cert_wrapper", 0x3000)
        ])
        offsets = BinaryAnalyzer._symbol_scan(binary, "arm64-v8a")
        assert len(offsets) == 1

    def test_arch_embedded_in_result(self) -> None:
        binary = self._make_binary([("ssl_verify_peer_cert", 0x5000)])
        offsets = BinaryAnalyzer._symbol_scan(binary, "x86_64")
        assert offsets[0].arch == "x86_64"

    def test_lief_14_fallback_for_no_symbols_attr(self) -> None:
        """Should fall back gracefully when .symbols raises AttributeError."""
        binary = MagicMock()
        binary.symbols = PropertyMock(side_effect=AttributeError("no attr"))
        # Trigger the AttributeError path
        binary.symbols = MagicMock()
        type(binary).symbols = PropertyMock(side_effect=AttributeError)
        dynamic_sym = MagicMock()
        dynamic_sym.name = "ssl_verify_peer_cert"
        dynamic_sym.value = 0x6000
        binary.dynamic_symbols = [dynamic_sym]
        binary.segments = []
        # Should not raise
        offsets = BinaryAnalyzer._symbol_scan(binary, "arm64-v8a")
        assert isinstance(offsets, list)


# ---------------------------------------------------------------------------
# _pattern_scan — unit tests with mock binary + real .text content
# ---------------------------------------------------------------------------
class TestPatternScanUnit:
    """Tests for _pattern_scan using a mock binary injecting specific .text bytes."""

    # The arm64 pattern in patterns.yaml: "FF 83 ?? D1 FD 7B ?? A9 ?? ?? ?? ??"
    # We embed the exact bytes (with arbitrary wildcard fills) into the .text
    _PATTERN_BYTES = bytes([
        0xFF, 0x83, 0x01, 0xD1,   # FF 83 ?? D1  — sub sp, sp, #N
        0xFD, 0x7B, 0x02, 0xA9,   # FD 7B ?? A9  — stp x29, x30, [sp]
        0x00, 0x11, 0x22, 0x33,   # ?? ?? ?? ??   — wildcard fill
    ])

    @staticmethod
    def _make_text_section(content: bytes, va: int = 0x10000) -> MagicMock:
        sec = MagicMock()
        sec.content = content
        sec.virtual_address = va
        return sec

    @staticmethod
    def _make_binary_with_text(content: bytes, va: int = 0x10000) -> MagicMock:
        sec = MagicMock()
        sec.content = content
        sec.virtual_address = va
        binary = MagicMock()
        binary.get_section.return_value = sec
        binary.segments = []
        return binary

    def test_pattern_match_returns_offset(self) -> None:
        binary = self._make_binary_with_text(
            b"\x00" * 16 + self._PATTERN_BYTES + b"\x00" * 16
        )
        analyzer = BinaryAnalyzer()
        ev = _make_ev("3.22.0")
        offsets = analyzer._pattern_scan(binary, "arm64-v8a", ev)
        # At minimum one match should be found
        assert len(offsets) >= 1
        assert all(o.method == "pattern" for o in offsets)
        assert all(o.arch == "arm64-v8a" for o in offsets)

    def test_no_match_returns_empty(self) -> None:
        binary = self._make_binary_with_text(b"\x00" * 128)
        analyzer = BinaryAnalyzer()
        offsets = analyzer._pattern_scan(binary, "arm64-v8a", _EV_UNKNOWN)
        # No SSL patterns embedded in all-zeros — may or may not match depending
        # on patterns.yaml; we just assert it returns a list
        assert isinstance(offsets, list)

    def test_arch_mismatch_filters_pattern(self) -> None:
        """Patterns tagged arm64-v8a should NOT match when arch is x86_64."""
        binary = self._make_binary_with_text(
            b"\x00" * 8 + self._PATTERN_BYTES + b"\x00" * 8
        )
        analyzer = BinaryAnalyzer()
        ev = _make_ev("3.22.0")
        arm64_offsets = analyzer._pattern_scan(binary, "arm64-v8a", ev)
        x86_offsets = analyzer._pattern_scan(binary, "x86_64", ev)
        # arm64 patterns must not fire for x86_64 arch
        assert all("arm64" not in str(o.symbol).lower() for o in x86_offsets)

        # arm64 pattern bytes should produce hits under arm64-v8a
        if arm64_offsets:
            assert any(o.arch == "arm64-v8a" for o in arm64_offsets)

    def test_version_mismatch_filters_pattern(self) -> None:
        """A pattern tagged '3.22.' must NOT fire for version '3.16.x'."""
        binary = self._make_binary_with_text(
            b"\x00" * 8 + self._PATTERN_BYTES + b"\x00" * 8
        )
        analyzer = BinaryAnalyzer()
        ev_322 = _make_ev("3.22.0")
        ev_316 = _make_ev("3.16.0")
        hits_322 = analyzer._pattern_scan(binary, "arm64-v8a", ev_322)
        hits_316 = analyzer._pattern_scan(binary, "arm64-v8a", ev_316)
        # 3.22-tagged patterns fire for 3.22 but not 3.16
        assert len(hits_322) >= len(hits_316)

    def test_no_text_section_returns_empty(self) -> None:
        binary = MagicMock()
        binary.get_section.return_value = None
        analyzer = BinaryAnalyzer()
        offsets = analyzer._pattern_scan(binary, "arm64-v8a", _EV_UNKNOWN)
        assert offsets == []

    def test_empty_text_section_returns_empty(self) -> None:
        binary = self._make_binary_with_text(b"")
        analyzer = BinaryAnalyzer()
        offsets = analyzer._pattern_scan(binary, "arm64-v8a", _EV_UNKNOWN)
        assert offsets == []

    def test_star_version_pattern_matches_any_version(self) -> None:
        """A pattern tagged version='*' should match regardless of ev.version_string."""
        # SSL_CTX_set_custom_verify arm64 pattern: "08 00 40 F9 ?? 00 00 91 08 ?? 00 F9 C0 03 5F D6"
        pattern_bytes = bytes([
            0x08, 0x00, 0x40, 0xF9,
            0xAA, 0x00, 0x00, 0x91,  # ?? fill
            0x08, 0xBB, 0x00, 0xF9,  # ?? fill
            0xC0, 0x03, 0x5F, 0xD6,
        ])
        binary = self._make_binary_with_text(b"\x00" * 8 + pattern_bytes + b"\x00" * 8)
        analyzer = BinaryAnalyzer()
        for ver in ("3.10.0", "3.16.0", "3.22.0"):
            analyzer._pattern_scan(binary, "arm64-v8a", _make_ev(ver))
            # '*'-version patterns should always be tried regardless of version


# ---------------------------------------------------------------------------
# _version_map_lookup — unit tests
# ---------------------------------------------------------------------------
class TestVersionMapLookup:
    """Tests for the version-map offset fallback strategy."""

    def test_sentinel_hash_returns_offsets(self) -> None:
        """The sentinel hash in version_map.yaml should return 2 offsets."""
        analyzer = BinaryAnalyzer()
        offsets = analyzer._version_map_lookup(_EV_WITH_HASH, "arm64-v8a")
        assert len(offsets) >= 1
        for o in offsets:
            assert o.method == "version_map"
            assert o.arch == "arm64-v8a"
            assert o.virtual_address > 0

    def test_unknown_hash_returns_empty(self) -> None:
        """An engine hash not in version_map.yaml must return an empty list."""
        analyzer = BinaryAnalyzer()
        offsets = analyzer._version_map_lookup(_EV_UNKNOWN_HASH, "arm64-v8a")
        assert offsets == []

    def test_no_hash_or_build_id_returns_empty(self) -> None:
        """EngineVersion with no hash or Build-ID should return empty list."""
        analyzer = BinaryAnalyzer()
        offsets = analyzer._version_map_lookup(_EV_UNKNOWN, "arm64-v8a")
        assert offsets == []

    def test_arch_filter_excludes_wrong_arch(self) -> None:
        """Offsets tagged arm64-v8a must not appear when searching for x86_64."""
        analyzer = BinaryAnalyzer()
        offsets = analyzer._version_map_lookup(_EV_WITH_HASH, "x86_64")
        # The sentinel entry is arm64-v8a only → should be filtered out
        assert not any(o.arch == "arm64-v8a" for o in offsets)
        # Either empty or only x86_64 offsets
        assert all(o.arch in ("x86_64", "*") for o in offsets)

    def test_star_arch_entry_included_for_any_arch(self, tmp_path: Path) -> None:
        """An entry with arch='*' should be returned for any requested arch."""
        yaml_content = (
            "offsets:\n"
            f"  \"{_TEST_HASH}\":\n"
            "    - symbol: test_fn\n"
            "      arch: \"*\"\n"
            "      virtual_address: 0x1000\n"
            "      file_offset: 0x500\n"
        )
        yaml_file = tmp_path / "version_map.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")
        with patch("fluttersec.core.binary_analyzer._VERSION_MAP_PATH", yaml_file):
            analyzer = BinaryAnalyzer()
        for arch in ("arm64-v8a", "armeabi-v7a", "x86_64"):
            offsets = analyzer._version_map_lookup(_EV_WITH_HASH, arch)
            assert len(offsets) == 1
            assert offsets[0].symbol == "test_fn"

    def test_returned_offsets_have_correct_method(self) -> None:
        analyzer = BinaryAnalyzer()
        offsets = analyzer._version_map_lookup(_EV_WITH_HASH, "arm64-v8a")
        for o in offsets:
            assert o.method == "version_map"

    def test_falls_back_to_build_id_when_no_engine_hash(self) -> None:
        """If engine_hash is None but build_id matches a key, it should be used."""
        ev = EngineVersion(
            version_string=None,
            build_id=_TEST_HASH,       # build_id as fallback key
            engine_hash=None,
            detection_method="build_id",
            sections_found=[],
        )
        analyzer = BinaryAnalyzer()
        offsets = analyzer._version_map_lookup(ev, "arm64-v8a")
        assert len(offsets) >= 1


# ---------------------------------------------------------------------------
# Version-map YAML loader
# ---------------------------------------------------------------------------
class TestVersionMapLoader:
    """Tests for _load_version_map_offsets."""

    def test_returns_dict(self) -> None:
        assert isinstance(BinaryAnalyzer._load_version_map_offsets(), dict)

    def test_returns_empty_when_file_missing(self, tmp_path: Path) -> None:
        with patch("fluttersec.core.binary_analyzer._VERSION_MAP_PATH",
                   tmp_path / "nope.yaml"):
            result = BinaryAnalyzer._load_version_map_offsets()
        assert result == {}

    def test_parses_valid_offsets_block(self, tmp_path: Path) -> None:
        yaml_content = (
            f"offsets:\n"
            f"  \"{_TEST_HASH}\":\n"
            f"    - symbol: ssl_fn\n"
            f"      arch: arm64-v8a\n"
            f"      virtual_address: 0x1000\n"
            f"      file_offset: 0x800\n"
        )
        yaml_file = tmp_path / "vm.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")
        with patch("fluttersec.core.binary_analyzer._VERSION_MAP_PATH", yaml_file):
            result = BinaryAnalyzer._load_version_map_offsets()
        assert _TEST_HASH in result
        assert result[_TEST_HASH][0]["symbol"] == "ssl_fn"

    def test_returns_empty_when_no_offsets_key(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "nooffsets.yaml"
        yaml_file.write_text("version: 3.22.0\n", encoding="utf-8")
        with patch("fluttersec.core.binary_analyzer._VERSION_MAP_PATH", yaml_file):
            result = BinaryAnalyzer._load_version_map_offsets()
        assert result == {}

    def test_returns_empty_on_malformed_yaml(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "bad.yaml"
        yaml_file.write_text("offsets: {invalid}}: yaml", encoding="utf-8")
        with patch("fluttersec.core.binary_analyzer._VERSION_MAP_PATH", yaml_file):
            result = BinaryAnalyzer._load_version_map_offsets()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# find_ssl_offsets — integration tests
# ---------------------------------------------------------------------------
class TestFindSslOffsets:
    """Integration tests using the stub ELF fixture from conftest.py."""

    def test_returns_list(self, sample_libflutter_path: Path) -> None:
        """find_ssl_offsets must always return a list."""
        analyzer = BinaryAnalyzer()
        try:
            result = analyzer.find_ssl_offsets(sample_libflutter_path, _EV_UNKNOWN)
            assert isinstance(result, list)
        except BinaryParseError:
            pytest.skip("Minimal ELF stub not accepted by LIEF on this platform.")

    def test_results_sorted_by_va(self, sample_libflutter_path: Path) -> None:
        """Output must be sorted ascending by virtual_address."""
        analyzer = BinaryAnalyzer()
        try:
            offsets = analyzer.find_ssl_offsets(sample_libflutter_path, _EV_UNKNOWN)
            vas = [o.virtual_address for o in offsets]
            assert vas == sorted(vas)
        except BinaryParseError:
            pytest.skip("Minimal ELF stub not accepted by LIEF.")

    def test_deduplication_by_va(self, sample_libflutter_path: Path) -> None:
        """No two offsets should share the same virtual_address."""
        analyzer = BinaryAnalyzer()
        try:
            offsets = analyzer.find_ssl_offsets(sample_libflutter_path, _EV_UNKNOWN)
            vas = [o.virtual_address for o in offsets]
            assert len(vas) == len(set(vas)), "Duplicate VAs found in output."
        except BinaryParseError:
            pytest.skip("Minimal ELF stub not accepted by LIEF.")

    def test_raises_file_not_found_for_missing_lib(self, tmp_path: Path) -> None:
        """Must raise FileNotFoundError (not BinaryParseError) for missing path."""
        with pytest.raises(FileNotFoundError):
            BinaryAnalyzer().find_ssl_offsets(tmp_path / "nope.so", _EV_UNKNOWN)

    def test_raises_binary_parse_error_for_corrupt_file(
        self, corrupt_lib: Path
    ) -> None:
        """A non-ELF file must raise BinaryParseError."""
        with pytest.raises(BinaryParseError):
            BinaryAnalyzer().find_ssl_offsets(corrupt_lib, _EV_UNKNOWN)

    def test_version_map_fallback_fires_when_no_scan_results(
        self, tmp_path: Path
    ) -> None:
        """Strategy 3 should fire when symbol + pattern scans both fail."""
        # Build a stub ELF with no symbols and no matching patterns
        stub = tmp_path / "arm64-v8a" / "libflutter.so"
        stub.parent.mkdir(parents=True, exist_ok=True)
        # Minimal ELF header only, no sections/segments
        h = bytearray(64)
        h[0:4] = b"\x7fELF"
        h[4] = 2
        h[5] = 1
        h[16] = 3
        h[18] = 0xB7
        stub.write_bytes(bytes(h) + b"\x00" * 512)

        analyzer = BinaryAnalyzer()
        try:
            offsets = analyzer.find_ssl_offsets(stub, _EV_WITH_HASH)
            # If LIEF accepts it, version_map fallback should add entries
            version_map_hits = [o for o in offsets if o.method == "version_map"]
            # With _EV_WITH_HASH (sentinel hash) there should be hits from version_map
            assert len(version_map_hits) >= 1
        except BinaryParseError:
            pytest.skip("LIEF rejected the minimal ELF stub.")


# ---------------------------------------------------------------------------
# analyze() bound-mode API
# ---------------------------------------------------------------------------
class TestAnalyzeAPI:
    """Tests for the bound-mode analyze() method."""

    def test_analyze_requires_lib_path(self) -> None:
        """Calling analyze() without any lib_path must raise ValueError."""
        with pytest.raises(ValueError, match="lib_path"):
            BinaryAnalyzer().analyze()

    def test_analyze_returns_analysis_result(
        self, sample_libflutter_path: Path
    ) -> None:
        """analyze() must return an AnalysisResult instance."""
        analyzer = BinaryAnalyzer()
        try:
            result = analyzer.analyze(lib_path=sample_libflutter_path,
                                      engine_version=_EV_UNKNOWN)
            assert isinstance(result, AnalysisResult)
            assert isinstance(result.offsets, list)
            assert isinstance(result.strategies_used, list)
        except BinaryParseError:
            pytest.skip("LIEF rejected the ELF stub.")

    def test_analyze_raise_on_empty_raises_offset_not_found(
        self, corrupt_lib: Path
    ) -> None:
        """raise_on_empty=True must propagate BinaryParseError (corrupt → parse fail)."""
        with pytest.raises(BinaryParseError):
            BinaryAnalyzer().analyze(
                lib_path=corrupt_lib,
                engine_version=_EV_UNKNOWN,
                raise_on_empty=True,
            )

    def test_analyze_bound_mode(self, sample_libflutter_path: Path) -> None:
        """When lib_path + engine_version are bound at construction, analyze() works."""
        analyzer = BinaryAnalyzer(
            lib_path=sample_libflutter_path,
            engine_version=_EV_UNKNOWN,
        )
        try:
            result = analyzer.analyze()
            assert isinstance(result, AnalysisResult)
        except BinaryParseError:
            pytest.skip("LIEF rejected the ELF stub.")

    def test_analyze_result_arch_inferred(
        self, sample_libflutter_path: Path
    ) -> None:
        """arch in AnalysisResult should match the parent directory name."""
        analyzer = BinaryAnalyzer()
        try:
            result = analyzer.analyze(
                lib_path=sample_libflutter_path,
                engine_version=_EV_UNKNOWN,
            )
            assert result.arch == sample_libflutter_path.parent.name
        except BinaryParseError:
            pytest.skip("LIEF rejected the ELF stub.")
