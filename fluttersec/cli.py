"""Command-line interface for FlutterSec-Automator."""

from __future__ import annotations

import platform
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from fluttersec import __version__
from fluttersec.utils.logger import get_console

# ---------------------------------------------------------------------------
# Typer application
# ---------------------------------------------------------------------------
app = typer.Typer(
    name="fluttersec",
    help="[bold cyan]FlutterSec-Automator[/] — Automate dynamic analysis of Flutter apps.",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console: Console = get_console()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class FridaMode(str, Enum):
    """Frida script deployment mode."""

    GADGET = "gadget"
    SERVER = "server"
    BOTH = "both"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _print_banner() -> None:
    """Print the branded startup banner."""
    banner = Text()
    banner.append("FlutterSec", style="bold cyan")
    banner.append("-Automator", style="bold white")
    banner.append(f"  v{__version__}", style="dim green")
    console.print(
        Panel(
            banner,
            subtitle="[dim]Flutter SSL Bypass Generator[/]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
@app.command()
def analyze(
    apk: Path | None = typer.Option(
        None,
        "--apk",
        help="Path to the target Flutter APK file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
    ),
    ipa: Path | None = typer.Option(
        None,
        "--ipa",
        help="Path to the target Flutter IPA file (macOS only).",
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
    ),
    output_dir: Path = typer.Option(
        Path("./output"),
        "--output-dir",
        "-o",
        help="Directory to write generated Frida scripts.",
    ),
    frida_mode: FridaMode = typer.Option(
        FridaMode.SERVER,
        "--frida-mode",
        "-m",
        help="Frida deployment mode: gadget | server | both.",
    ),
    cleanup: bool = typer.Option(
        True,
        "--cleanup/--no-cleanup",
        help="Remove extraction workspace after analysis.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable debug-level logging output.",
    ),
    offset: str | None = typer.Option(
        None,
        "--offset",
        help="Manual SSL offset provided by user",
    )
) -> None:
    """Analyze a Flutter APK/IPA and generate a Frida SSL bypass script.

    Extracts ``libflutter.so``, detects the Flutter Engine version, locates
    SSL pinning offsets, and renders a customized Frida script.
    """
    import logging

    if verbose:
        logging.getLogger("fluttersec").setLevel(logging.DEBUG)
    else:
        logging.getLogger("fluttersec").setLevel(logging.WARNING)

    _print_banner()

    # ── Input validation ──────────────────────────────────────────────────
    if apk is None and ipa is None:
        console.print("[bold red]Error:[/] Provide at least --apk or --ipa.")
        raise typer.Exit(code=1)

    if ipa is not None and platform.system() != "Darwin":
        console.print(
            "[bold yellow]Warning:[/] Full IPA analysis requires macOS. "
            "Proceeding with limited ZIP extraction."
        )

    # ── Lazy imports (keeps startup fast) ────────────────────────────────
    from fluttersec.core.apk_parser import ApkInfo, ApkParser
    from fluttersec.core.binary_analyzer import BinaryAnalyzer
    from fluttersec.core.script_generator import ScriptGenerator
    from fluttersec.core.version_detector import VersionDetector
    from fluttersec.utils.fs import cleanup_workspace, make_workspace

    workspace = make_workspace(output_dir / ".workspace")

    try:
        # ── Step 1: Parse the APK ─────────────────────────────────────────
        apk_info: ApkInfo
        if apk is not None:
            with console.status("[cyan]Parsing APK…[/]", spinner="dots"):
                parser = ApkParser()
                apk_info = parser.parse(apk, workspace)
            console.print(
                f"[green]✔[/] Package: [bold]{apk_info.package_name}[/] "
                f"([dim]{apk_info.version_name}[/])"
            )
            console.print(f"[green]✔[/] ABIs found: {', '.join(apk_info.abis)}")

        # ── Step 2: Detect Flutter Engine version ─────────────────────────
        lib_path = list(apk_info.libflutter_paths.values())[0]

        with console.status("[cyan]Detecting Flutter Engine version…[/]", spinner="dots"):
            detector = VersionDetector()
            engine_version = detector.detect(lib_path)

        if engine_version.version_string:
            console.print(
                f"[green]✔[/] Flutter Engine: [bold]{engine_version.version_string}[/] "
                f"([dim]{engine_version.detection_method}[/])"
            )
        else:
            console.print("[yellow]⚠[/]  Flutter Engine version could not be determined.")

        # ── Step 3: Locate SSL pinning offsets ────────────────────────────
        if offset:
            from fluttersec.core.binary_analyzer import SslOffset
            
            try:
                # Convert the input string (supports raw strings or 0x prefixes) into an integer
                parsed_offset = int(offset, 16)
            except ValueError:
                console.print(f"[bold red]Error:[/] Invalid hex format provided for offset: '{offset}'")
                raise typer.Exit(code=1)

            # Create a manual entry mapping directly into the existing array format
            offsets = [
                SslOffset(
                    symbol="manual_override_hook",
                    virtual_address=parsed_offset,
                    file_offset=parsed_offset,
                    method="manual",
                    arch=apk_info.abis[0] if apk_info.abis else "arm64-v8a"
                )
            ]
            console.print(f"[green]✔[/] Manual offset override applied: [bold]{offset}[/]")
        else:
            with console.status("[cyan]Scanning for SSL pinning offsets…[/]", spinner="dots"):
                analyzer = BinaryAnalyzer()
                offsets = analyzer.find_ssl_offsets(lib_path, engine_version)
                
        # ── Step 4: Generate Frida script ─────────────────────────────────
        with console.status("[cyan]Generating Frida script…[/]", spinner="dots"):
            generator = ScriptGenerator()
            script_path = generator.generate(
                offsets=offsets,
                apk_info=apk_info,
                engine_version=engine_version,
                mode=frida_mode.value,
                output_dir=output_dir,
            )

        console.print(f"[green]✔[/] Frida script written to: [bold]{script_path}[/]")
        console.print(
            Panel(
                f"[cyan]frida -U -f {apk_info.package_name} "
                f"-l {script_path} --no-pause[/]",
                title="[bold]Inject Command[/]",
                border_style="green",
                padding=(0, 2),
            )
        )

    except Exception:
        from rich.traceback import Traceback

        console.print(Traceback(show_locals=verbose))
        raise typer.Exit(code=1)
    finally:
        if cleanup and workspace.exists():
            cleanup_workspace(workspace)


@app.command()
def version() -> None:
    """Print the FlutterSec-Automator version and exit."""
    console.print(
        f"[bold cyan]fluttersec[/]-automator [bold green]{__version__}[/]"
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app()
