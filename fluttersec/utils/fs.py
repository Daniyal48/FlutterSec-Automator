"""File-system helpers for FlutterSec-Automator."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fluttersec.utils.logger import get_logger

log = get_logger(__name__)


def make_workspace(base: Path) -> Path:
    """Create a temporary extraction workspace directory under *base*.

    Args:
        base: Parent directory to create the workspace inside.

    Returns:
        Path to the newly created, unique workspace directory.
    """
    base.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="fluttersec_", dir=base))
    log.debug("Created workspace: %s", workspace)
    return workspace


def ensure_dir(path: Path) -> Path:
    """Ensure a directory exists, creating it and all parents if necessary.

    Args:
        path: Directory path to guarantee.

    Returns:
        The same *path* after creation.
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


def cleanup_workspace(path: Path) -> None:
    """Recursively remove a workspace directory and all its contents.

    Args:
        path: Root of the workspace to delete.  No-op if it does not exist.
    """
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
        log.debug("Removed workspace: %s", path)
