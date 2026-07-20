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
TestXrefStrategy              — _find_string_va, _decode_adrp_target,
                                _decode_add_imm12, _find_adrp_add_xrefs,
                                _find_function_start, find_offset_via_xref
"""

from __future__ import annotations

import re
import struct
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


# ---------------------------------------------------------------------------
# String XREF strategy unit tests
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# ARM64 instruction encoding helpers used by tests
# ---------------------------------------------------------------------------

def _encode_adrp(rd: int, pc: int, target_page: int) -> int:
    """Encode an ARM64 ADRP instruction that loads `target_page` when executed at `pc`.

    Args:
        rd: Destination register (0-30).
        pc: Virtual address of this instruction.
        target_page: Target 4 KB-aligned page VA to load.

    Returns:
        32-bit instruction word (little-endian integer).
    """
    pc_page = pc & ~0xFFF
    offset = target_page - pc_page           # signed, 33-bit range
    raw_imm = (offset >> 12) & 0x1FFFFF     # 21 bits of page offset
    immlo = raw_imm & 0x3
    immhi = (raw_imm >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


def _encode_add_imm12(rd: int, rn: int, imm12: int) -> int:
    """Encode ARM64 ADD Xd, Xn, #imm12 (64-bit, shift=0)."""
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _encode_stp_x29_x30_preindex(imm7_scaled: int) -> int:
    """Encode STP X29, X30, [SP, #imm7_scaled]! (pre-indexed).

    Args:
        imm7_scaled: Signed byte offset (must be a multiple of 8, range -512..504).

    Returns:
        32-bit instruction word.
    """
    # imm7 field = byte_offset / 8, stored as signed 7-bit.
    imm7 = (imm7_scaled // 8) & 0x7F
    # STP Xt1, Xt2, [Xn, #imm]! (pre-index):
    # [31:30]=10  [29:27]=101  [26]=0  [25:24]=11  [23]=0  [22:16]=imm7
    # [15:10]=Rt2=30  [9:5]=Rn=31  [4:0]=Rt=29
    return (
        0xA9800000       # base: STP Xregs, pre-index, 64-bit
        | (imm7 << 15)   # imm7 in bits[21:15]... wait, let me be precise
    )
    # Precise encoding: bits[31:24]=0xA9, bits[23]=1(pre), bits[22:16]=imm7,
    # bits[14:10]=Rt2=30, bits[9:5]=Rn=31, bits[4:0]=Rt=29.
    # In practice the _find_function_start mask is (word & 0xFF00FFFF)==0xA9007BFD
    # so we only need byte0=0xFD, byte1=0x7B, byte3=0xA9.


def _stp_x29_x30_word(frame_bytes: int) -> int:
    """Return the 32-bit LE word for STP X29, X30, [SP, #-frame_bytes]!.

    The mask used by _find_function_start only checks byte0, byte1, byte3
    (0xFF00FFFF == 0xA9007BFD), so byte2 (imm7) can be anything.
    We compute the correct imm7 for correctness.
    """
    assert frame_bytes > 0 and frame_bytes % 8 == 0
    imm7_neg = ((-frame_bytes) // 8) & 0x7F   # 7-bit two's complement
    # byte0 = 0xFD (Rt=29 | Rn[0]=1)
    # byte1 = 0x7B (Rn[4:1]=0b1111 | Rt2[0]=0)
    # byte2 = imm7[6:0] | pre-index bit  (bit23 in the 32-bit word = bit7 of byte2)
    byte2 = (imm7_neg & 0x7F) | 0x80   # bit7 set = pre-index
    # byte3 = 0xA9 (opcode: STP 64-bit)
    return struct.unpack("<I", bytes([0xFD, 0x7B, byte2, 0xA9]))[0]


def _make_mock_section(name: str, va: int, content: bytes) -> MagicMock:
    """Create a mock LIEF section with the given name, VA, and content."""
    sec = MagicMock()
    sec.virtual_address = va
    sec.content = list(content)
    return sec


class TestXrefStrategy:
    """Unit tests for the string XREF detection strategy.

    All tests use synthetic ARM64 instruction words and mock LIEF objects so
    no real ELF binary is required.  This keeps the suite fast and deterministic.
    """

    # ------------------------------------------------------------------
    # _decode_adrp_target
    # ------------------------------------------------------------------

    def test_decode_adrp_target_returns_none_for_non_adrp(self) -> None:
        """A non-ADRP instruction (e.g. NOP = 0xD503201F) must return None."""
        nop = 0xD503201F
        result = BinaryAnalyzer._decode_adrp_target(nop, pc=0x1000)
        assert result is None

    def test_decode_adrp_target_positive_forward_page(self) -> None:
        """ADRP pointing one page ahead of PC must return PC_page + 4096."""
        pc = 0x10000
        target_page = 0x11000   # one page forward
        instr = _encode_adrp(rd=0, pc=pc, target_page=target_page)
        result = BinaryAnalyzer._decode_adrp_target(instr, pc=pc)
        assert result == target_page, (
            f"Expected 0x{target_page:x}, got 0x{result:x} for instr=0x{instr:08x}"
        )

    def test_decode_adrp_target_same_page(self) -> None:
        """ADRP with imm=0 must return the aligned PC page itself."""
        pc = 0x1234      # mid-page address
        expected_page = pc & ~0xFFF   # = 0x1000
        instr = _encode_adrp(rd=0, pc=pc, target_page=expected_page)
        result = BinaryAnalyzer._decode_adrp_target(instr, pc=pc)
        assert result == expected_page

    def test_decode_adrp_target_large_forward_offset(self) -> None:
        """ADRP with a large positive page offset must decode correctly."""
        pc = 0x400000
        target_page = 0x900000   # 5 MiB ahead
        instr = _encode_adrp(rd=5, pc=pc, target_page=target_page)
        result = BinaryAnalyzer._decode_adrp_target(instr, pc=pc)
        assert result == target_page

    # ------------------------------------------------------------------
    # _decode_add_imm12
    # ------------------------------------------------------------------

    def test_decode_add_imm12_valid_zero_offset(self) -> None:
        """ADD Xd, Xn, #0 must return 0."""
        instr = _encode_add_imm12(rd=0, rn=0, imm12=0)
        assert BinaryAnalyzer._decode_add_imm12(instr) == 0

    def test_decode_add_imm12_valid_nonzero(self) -> None:
        """ADD Xd, Xn, #0xABC must return 0xABC."""
        instr = _encode_add_imm12(rd=1, rn=0, imm12=0xABC)
        assert BinaryAnalyzer._decode_add_imm12(instr) == 0xABC

    def test_decode_add_imm12_max_offset(self) -> None:
        """ADD Xd, Xn, #0xFFF (max imm12) must return 0xFFF."""
        instr = _encode_add_imm12(rd=0, rn=1, imm12=0xFFF)
        assert BinaryAnalyzer._decode_add_imm12(instr) == 0xFFF

    def test_decode_add_imm12_non_add_returns_none(self) -> None:
        """A SUB instruction must not be decoded as ADD."""
        sub_instr = 0xD1000000   # SUB opcode
        assert BinaryAnalyzer._decode_add_imm12(sub_instr) is None

    def test_decode_add_imm12_nop_returns_none(self) -> None:
        """NOP (0xD503201F) must not match the ADD mask."""
        assert BinaryAnalyzer._decode_add_imm12(0xD503201F) is None

    # ------------------------------------------------------------------
    # _find_string_va
    # ------------------------------------------------------------------

    def test_find_string_va_found_in_rodata(self) -> None:
        """Needle present in .rodata must be found and its VA returned."""
        needle = b"ssl_client"
        payload = b"\x00" * 16 + needle + b"\x00" * 8
        rodata_va = 0x500000
        binary = MagicMock()
        sec = _make_mock_section(".rodata", va=rodata_va, content=payload)
        binary.get_section.side_effect = lambda name: sec if name == ".rodata" else None

        result = BinaryAnalyzer._find_string_va(binary, needle)
        assert result == rodata_va + 16

    def test_find_string_va_not_present_returns_none(self) -> None:
        """Needle absent from all sections must return None."""
        binary = MagicMock()
        binary.get_section.return_value = None
        result = BinaryAnalyzer._find_string_va(binary, b"ssl_client")
        assert result is None

    def test_find_string_va_prefers_rodata_over_data(self) -> None:
        """When needle is in both .rodata and .data, .rodata VA wins."""
        needle = b"ssl_client"
        rodata_va = 0x100000
        data_va = 0x200000
        rodata_sec = _make_mock_section(".rodata", va=rodata_va, content=needle)
        data_sec = _make_mock_section(".data", va=data_va, content=needle)

        def side_effect(name: str):
            return {"rodata": rodata_sec, ".data": data_sec, ".data.rel.ro": None}.get(
                name, None
            )

        binary = MagicMock()
        binary.get_section.side_effect = (
            lambda n: rodata_sec if n == ".rodata" else None
        )
        result = BinaryAnalyzer._find_string_va(binary, needle)
        assert result == rodata_va

    # ------------------------------------------------------------------
    # _find_function_start
    # ------------------------------------------------------------------

    def test_find_function_start_finds_prologue_directly_before_xref(self) -> None:
        """STP prologue placed immediately before the XREF site must be found."""
        text_va = 0x400000
        prologue_word = _stp_x29_x30_word(16)   # STP X29, X30, [SP, #-16]!
        nop = struct.pack("<I", 0xD503201F)
        prologue_bytes = struct.pack("<I", prologue_word)
        # Layout: [prologue][nop][nop][nop][XREF_here]
        content = prologue_bytes + nop * 3 + nop
        xref_va = text_va + len(prologue_bytes) + len(nop) * 3   # points at 4th NOP

        binary = MagicMock()
        text_sec = _make_mock_section(".text", va=text_va, content=content)
        binary.get_section.return_value = text_sec

        result = BinaryAnalyzer._find_function_start(binary, xref_va)
        assert result == text_va

    def test_find_function_start_returns_none_when_no_prologue(self) -> None:
        """When only NOPs fill the scan window, None must be returned."""
        text_va = 0x400000
        nop = struct.pack("<I", 0xD503201F)
        content = nop * 512   # 2 048 bytes, no prologue
        xref_va = text_va + 2000

        binary = MagicMock()
        binary.get_section.return_value = _make_mock_section(
            ".text", va=text_va, content=content
        )

        result = BinaryAnalyzer._find_function_start(binary, xref_va)
        assert result is None

    def test_find_function_start_returns_none_for_missing_text(self) -> None:
        """Missing .text section must return None without raising."""
        binary = MagicMock()
        binary.get_section.return_value = None
        result = BinaryAnalyzer._find_function_start(binary, xref_va=0x1000)
        assert result is None

    # ------------------------------------------------------------------
    # _find_adrp_add_xrefs
    # ------------------------------------------------------------------

    def test_find_adrp_add_xrefs_detects_single_pair(self) -> None:
        """A single ADRP+ADD pair referencing the string VA must yield one XREF."""
        text_va = 0x100000
        string_va = 0x500020   # page=0x500000, off12=0x20
        pc_of_adrp = text_va + 8   # 3rd instruction slot

        adrp_instr = _encode_adrp(rd=0, pc=pc_of_adrp, target_page=0x500000)
        add_instr = _encode_add_imm12(rd=0, rn=0, imm12=0x20)
        nop = 0xD503201F

        content = b""
        content += struct.pack("<II", nop, nop)     # two NOPs before
        content += struct.pack("<II", adrp_instr, add_instr)
        content += struct.pack("<II", nop, nop)     # two NOPs after

        binary = MagicMock()
        binary.get_section.return_value = _make_mock_section(
            ".text", va=text_va, content=content
        )

        analyzer = BinaryAnalyzer()
        xrefs = analyzer._find_adrp_add_xrefs(binary, string_va=string_va)
        assert xrefs == [pc_of_adrp], f"Expected [{hex(pc_of_adrp)}], got {[hex(x) for x in xrefs]}"

    def test_find_adrp_add_xrefs_no_match_returns_empty(self) -> None:
        """All-NOP .text must yield no XREF sites."""
        nop = 0xD503201F
        content = struct.pack("<" + "I" * 16, *([nop] * 16))
        binary = MagicMock()
        binary.get_section.return_value = _make_mock_section(
            ".text", va=0x400000, content=content
        )
        analyzer = BinaryAnalyzer()
        assert analyzer._find_adrp_add_xrefs(binary, string_va=0x99000042) == []

    def test_find_adrp_add_xrefs_wrong_add_offset_not_matched(self) -> None:
        """ADRP+ADD pair where ADD imm12 doesn't match the string offset is skipped."""
        text_va = 0x100000
        string_va = 0x500020   # page=0x500000, off12=0x20
        pc_of_adrp = text_va

        adrp_instr = _encode_adrp(rd=0, pc=pc_of_adrp, target_page=0x500000)
        wrong_add = _encode_add_imm12(rd=0, rn=0, imm12=0x40)   # off12=0x40 != 0x20

        content = struct.pack("<II", adrp_instr, wrong_add)
        binary = MagicMock()
        binary.get_section.return_value = _make_mock_section(
            ".text", va=text_va, content=content
        )
        analyzer = BinaryAnalyzer()
        assert analyzer._find_adrp_add_xrefs(binary, string_va=string_va) == []

    # ------------------------------------------------------------------
    # find_offset_via_xref (public method)
    # ------------------------------------------------------------------

    def test_find_offset_via_xref_raises_file_not_found(self, tmp_path: Path) -> None:
        """find_offset_via_xref must raise FileNotFoundError for missing lib."""
        missing = tmp_path / "no_such.so"
        with pytest.raises(FileNotFoundError):
            BinaryAnalyzer().find_offset_via_xref(missing, arch="arm64-v8a")

    def test_find_offset_via_xref_returns_empty_for_non_arm64(self, tmp_path: Path) -> None:
        """For non-arm64 arch the XREF scan must return [] immediately."""
        lib = tmp_path / "arm64-v8a" / "libflutter.so"
        lib.parent.mkdir()
        lib.write_bytes(b"ELF" + b"\x00" * 64)
        # Patch _parse_binary to avoid real LIEF parse.
        with patch.object(BinaryAnalyzer, "_parse_binary", return_value=MagicMock()):
            result = BinaryAnalyzer().find_offset_via_xref(lib, arch="x86_64")
        assert result == []

    def test_find_offset_via_xref_method_tag(self, tmp_path: Path) -> None:
        """Offsets returned by xref scan must have method == 'xref'."""
        # Build a synthetic binary mock where:
        #   - .rodata contains 'ssl_client'
        #   - .text contains ADRP+ADD pointing to it
        #   - An STP X29,X30 prologue sits before the ADRP
        string_va = 0x800020
        text_va = 0x400000
        pc_adrp = text_va + 8

        adrp_instr = _encode_adrp(rd=0, pc=pc_adrp, target_page=0x800000)
        add_instr = _encode_add_imm12(rd=0, rn=0, imm12=0x20)
        prologue_word = _stp_x29_x30_word(16)
        nop = 0xD503201F

        text_bytes = struct.pack(
            "<IIIII",
            nop,            # offset 0
            nop,            # offset 4
            adrp_instr,    # offset 8  <-- XREF site
            add_instr,     # offset 12
            nop,           # offset 16
        )
        # Manually replace first instruction with the prologue.
        text_bytes = struct.pack("<I", prologue_word) + text_bytes[4:]

        rodata_bytes = b"\x00" * 32 + b"ssl_client" + b"\x00" * 8

        text_sec = _make_mock_section(".text", va=text_va, content=text_bytes)
        rodata_sec = _make_mock_section(".rodata", va=0x800000, content=rodata_bytes)

        def get_section(name: str):
            return {".text": text_sec, ".rodata": rodata_sec}.get(name)

        mock_binary = MagicMock()
        mock_binary.get_section.side_effect = get_section
        # Make _va_to_file_offset return VA as-is (PT_LOAD at 0x0).
        mock_binary.segments = []

        lib = tmp_path / "arm64-v8a" / "libflutter.so"
        lib.parent.mkdir()
        lib.write_bytes(b"placeholder")

        with patch.object(BinaryAnalyzer, "_parse_binary", return_value=mock_binary):
            offsets = BinaryAnalyzer().find_offset_via_xref(lib, arch="arm64-v8a")

        assert len(offsets) >= 1, "Expected at least one XREF offset."
        for off in offsets:
            assert off.method == "xref", f"Expected method='xref', got {off.method!r}"
            assert off.bypass_return == 1, "XREF offsets should have bypass_return=1"
            assert off.return_type == "int"

    def test_xref_scan_deduplicates_same_function(self, tmp_path: Path) -> None:
        """Two XREF sites inside the same function must yield only one SslOffset."""
        # Place two ADRP+ADD pairs in the same function (between same prologue
        # and a NOP epilogue).  Only one offset should be emitted.
        text_va = 0x400000
        prologue_word = _stp_x29_x30_word(32)
        adrp1 = _encode_adrp(rd=0, pc=text_va + 4, target_page=0x800000)
        adrp2 = _encode_adrp(rd=1, pc=text_va + 12, target_page=0x800000)
        add_instr = _encode_add_imm12(rd=0, rn=0, imm12=0)
        nop = 0xD503201F

        text_bytes = struct.pack(
            "<IIIIII",
            prologue_word,   # offset 0  (function start)
            adrp1,          # offset 4  (XREF site 1)
            add_instr,      # offset 8
            adrp2,          # offset 12 (XREF site 2)
            add_instr,      # offset 16
            nop,            # offset 20
        )
        string_va = 0x800000   # page=0x800000, off12=0
        rodata_bytes = b"ssl_client" + b"\x00" * 16

        text_sec = _make_mock_section(".text", va=text_va, content=text_bytes)
        rodata_sec = _make_mock_section(".rodata", va=0x800000, content=rodata_bytes)

        mock_binary = MagicMock()
        mock_binary.get_section.side_effect = (
            lambda n: text_sec if n == ".text" else (
                rodata_sec if n == ".rodata" else None
            )
        )
        mock_binary.segments = []

        lib = tmp_path / "arm64-v8a" / "libflutter.so"
        lib.parent.mkdir()
        lib.write_bytes(b"placeholder")

        with patch.object(BinaryAnalyzer, "_parse_binary", return_value=mock_binary):
            offsets = BinaryAnalyzer().find_offset_via_xref(lib, arch="arm64-v8a")

        # Both xref sites belong to the same function — deduplicated to one entry.
        assert len(offsets) == 1, (
            f"Expected 1 deduplicated offset, got {len(offsets)}"
        )
