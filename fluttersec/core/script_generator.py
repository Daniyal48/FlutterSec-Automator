"""Frida script generation using Jinja2 templates."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from fluttersec.core.apk_parser import ApkInfo
from fluttersec.core.binary_analyzer import SslOffset
from fluttersec.core.version_detector import EngineVersion
from fluttersec.utils.logger import get_logger

log = get_logger(__name__)

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class ScriptGenerator:
    """Render a customized Frida bypass script using a Jinja2 template.

    The template is loaded from
    ``fluttersec/templates/frida_ssl_bypass.js.j2``.  The Jinja2 environment
    uses ``trim_blocks`` and ``lstrip_blocks`` so template control tags don't
    leave stray blank lines in the output.

    Example::

        gen = ScriptGenerator()
        out = gen.generate(offsets, apk_info, engine_version, "server", output_dir)
        print(f"Script written to {out}")
    """

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape([]),  # JavaScript — no HTML escaping
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )
        # Custom filter: converts a Python list of strings into a JavaScript
        # array literal so arg_types can be rendered directly in the template.
        # Example: ["pointer", "pointer"] → '["pointer", "pointer"]'
        self._env.filters["js_array"] = lambda lst: (
            "[" + ", ".join(f'"{item}"' for item in lst) + "]"
        )

    def generate(
        self,
        offsets: list[SslOffset],
        apk_info: ApkInfo,
        engine_version: EngineVersion,
        mode: str = "server",
        output_dir: Path = Path("./output"),
    ) -> Path:
        """Render the Frida bypass script and write it to *output_dir*.

        Args:
            offsets: SSL pinning offsets discovered by :class:`~BinaryAnalyzer`.
            apk_info: APK metadata from :class:`~ApkParser`.
            engine_version: Engine version from :class:`~VersionDetector`.
            mode: Frida deployment mode — ``"gadget"``, ``"server"``, or
                ``"both"``.
            output_dir: Directory to write the generated ``.js`` file.

        Returns:
            Absolute :class:`Path` of the written Frida script file.
        """
        template = self._env.get_template("frida_ssl_bypass.js.j2")

        rendered = template.render(
            package_name=apk_info.package_name,
            version_name=apk_info.version_name,
            flutter_version=engine_version.version_string or "unknown",
            engine_hash=engine_version.engine_hash or "unknown",
            build_id=engine_version.build_id or "unknown",
            offsets=offsets,
            mode=mode,
            # Enable the runtime Memory.scanSync XREF fallback when all four
            # static strategies found nothing.  This lets the injected script
            # locate ssl_crypto_x509_session_verify_cert_chain at runtime by
            # tracing references to the "ssl_client" TLS alert string.
            xref_runtime_fallback=len(offsets) == 0,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

        output_dir.mkdir(parents=True, exist_ok=True)
        safe_pkg = apk_info.package_name.replace(".", "_")
        output_path = output_dir / f"{safe_pkg}_frida_bypass.js"
        output_path.write_text(rendered, encoding="utf-8")
        log.info("Frida script written: %s", output_path)
        return output_path
