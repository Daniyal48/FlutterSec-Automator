"""Unit tests for fluttersec.core.script_generator."""

from __future__ import annotations

from pathlib import Path

from fluttersec.core.apk_parser import ApkInfo, ManifestInfo
from fluttersec.core.binary_analyzer import SslOffset
from fluttersec.core.script_generator import ScriptGenerator
from fluttersec.core.version_detector import EngineVersion


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------
def _apk_info(package: str = "com.example.flutter") -> ApkInfo:
    return ApkInfo(
        manifest=ManifestInfo(
            package_name=package,
            version_name="1.2.3",
            version_code=123,
            source="fallback",
        ),
        abis=["arm64-v8a"],
        libflutter_paths={},
    )


def _engine_version(ver: str = "3.22.0") -> EngineVersion:
    return EngineVersion(
        version_string=ver,
        build_id="deadbeef" * 5,
        engine_hash="a" * 40,
        detection_method="string_scan",
        sections_found=[".rodata"],
    )


def _two_offsets() -> list[SslOffset]:
    return [
        SslOffset(
            symbol="ssl_verify_peer_cert",
            virtual_address=0x0512AB80,
            file_offset=0x0112AB80,
            method="symbol",
            arch="arm64-v8a",
        ),
        SslOffset(
            symbol="SSL_CTX_set_custom_verify",
            virtual_address=0x0512CD00,
            file_offset=0x0112CD00,
            method="pattern",
            arch="arm64-v8a",
        ),
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestScriptGenerator:
    """Unit tests for :class:`ScriptGenerator`."""

    def test_generate_creates_js_file(self, tmp_path: Path) -> None:
        """generate() must write a .js file into the output directory."""
        gen = ScriptGenerator()
        path = gen.generate(
            offsets=_two_offsets(),
            apk_info=_apk_info(),
            engine_version=_engine_version(),
            mode="server",
            output_dir=tmp_path,
        )
        assert path.exists(), "Output file must exist after generate()."
        assert path.suffix == ".js", "Output file must have .js extension."

    def test_output_filename_derived_from_package(self, tmp_path: Path) -> None:
        """Generated filename should use the sanitized package name."""
        gen = ScriptGenerator()
        path = gen.generate(
            offsets=[],
            apk_info=_apk_info("com.target.myapp"),
            engine_version=_engine_version(),
            mode="server",
            output_dir=tmp_path,
        )
        assert "com_target_myapp" in path.name

    def test_generate_contains_package_name(self, tmp_path: Path) -> None:
        """Rendered script must include the target package name."""
        gen = ScriptGenerator()
        path = gen.generate(
            offsets=_two_offsets(),
            apk_info=_apk_info("com.target.app"),
            engine_version=_engine_version(),
            mode="server",
            output_dir=tmp_path,
        )
        content = path.read_text(encoding="utf-8")
        assert "com.target.app" in content

    def test_generate_contains_flutter_version(self, tmp_path: Path) -> None:
        """Rendered script must include the detected Flutter version."""
        gen = ScriptGenerator()
        path = gen.generate(
            offsets=_two_offsets(),
            apk_info=_apk_info(),
            engine_version=_engine_version("3.19.5"),
            mode="server",
            output_dir=tmp_path,
        )
        content = path.read_text(encoding="utf-8")
        assert "3.19.5" in content

    def test_generate_contains_offset_addresses(self, tmp_path: Path) -> None:
        """Rendered script must include the hex virtual addresses for each hook.

        The template must use ``offset.virtual_address`` (not ``file_offset``)
        because the dynamic linker maps the ELF LOAD segments at the library
        base using virtual addresses, not raw file byte offsets.
        """
        gen = ScriptGenerator()
        path = gen.generate(
            offsets=_two_offsets(),
            apk_info=_apk_info(),
            engine_version=_engine_version(),
            mode="server",
            output_dir=tmp_path,
        )
        content = path.read_text(encoding="utf-8")
        # 0x0512AB80 (virtual_address) → "512ab80" should appear in base.add(...)
        # 0x0112AB80 (file_offset) must NOT be used — that would be the old bug.
        assert "512ab80" in content.lower(), "Virtual address must appear in hook"
        assert "112ab80" not in content.lower(), "File offset must NOT appear in hook"

    def test_generate_no_offsets_inserts_placeholder(self, tmp_path: Path) -> None:
        """Rendering with no offsets should include a manual-analysis placeholder comment."""
        gen = ScriptGenerator()
        path = gen.generate(
            offsets=[],
            apk_info=_apk_info(),
            engine_version=_engine_version(),
            mode="server",
            output_dir=tmp_path,
        )
        content = path.read_text(encoding="utf-8")
        assert "No SSL offsets" in content or "auto-detected" in content

    def test_generate_gadget_mode_skips_polling(self, tmp_path: Path) -> None:
        """Gadget-mode script should call hookFlutterSSL() directly, not via polling."""
        gen = ScriptGenerator()
        path = gen.generate(
            offsets=_two_offsets(),
            apk_info=_apk_info(),
            engine_version=_engine_version(),
            mode="gadget",
            output_dir=tmp_path,
        )
        content = path.read_text(encoding="utf-8")
        assert "hookFlutterSSL()" in content
        # Should NOT contain the interval-based polling logic
        assert "setInterval" not in content

    def test_generate_server_mode_uses_polling(self, tmp_path: Path) -> None:
        """Server-mode script should poll for libflutter.so via setInterval."""
        gen = ScriptGenerator()
        path = gen.generate(
            offsets=_two_offsets(),
            apk_info=_apk_info(),
            engine_version=_engine_version(),
            mode="server",
            output_dir=tmp_path,
        )
        content = path.read_text(encoding="utf-8")
        assert "setInterval" in content

    def test_generate_creates_output_dir_if_missing(self, tmp_path: Path) -> None:
        """generate() should create the output_dir if it does not exist."""
        nested = tmp_path / "deep" / "nested" / "out"
        assert not nested.exists()
        gen = ScriptGenerator()
        path = gen.generate(
            offsets=[],
            apk_info=_apk_info(),
            engine_version=_engine_version(),
            mode="server",
            output_dir=nested,
        )
        assert nested.is_dir()
        assert path.is_file()

    def test_generate_unknown_version_renders_cleanly(self, tmp_path: Path) -> None:
        """Rendering with unknown version should use 'unknown' string without crashing."""
        unknown_ver = EngineVersion(
            version_string=None,
            build_id=None,
            engine_hash=None,
            detection_method="unknown",
            sections_found=[],
        )
        gen = ScriptGenerator()
        path = gen.generate(
            offsets=[],
            apk_info=_apk_info(),
            engine_version=unknown_ver,
            mode="server",
            output_dir=tmp_path,
        )
        content = path.read_text(encoding="utf-8")
        assert "unknown" in content



