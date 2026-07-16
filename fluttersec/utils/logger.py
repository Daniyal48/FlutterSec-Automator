"""Logging utilities for FlutterSec-Automator."""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler

_console: Console | None = None


def get_console() -> Console:
    """Return the singleton Rich Console instance.

    Returns:
        A shared :class:`rich.console.Console` writing to stdout.
    """
    global _console
    if _console is None:
        _console = Console(stderr=False)
    return _console


def get_logger(name: str) -> logging.Logger:
    """Return a standard-library logger wired to a Rich handler.

    Args:
        name: Logger name (typically ``__name__`` of the calling module).

    Returns:
        Configured :class:`logging.Logger` instance with Rich formatting.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = RichHandler(
            console=get_console(),
            rich_tracebacks=True,
            markup=True,
            show_path=False,
        )
        handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    return logger
