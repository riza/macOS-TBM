"""Application identity shown by the CLI banner and version flag."""

from __future__ import annotations

import os
import subprocess


VERSION = "0.1.0"


def build_id() -> str:
    """Return a short source build identifier without failing the CLI."""
    configured = os.environ.get("TBM_BUILD")
    if configured:
        return configured
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1.0,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return f"git:{result.stdout.strip()}"
    except (OSError, subprocess.SubprocessError):
        pass
    return "source"


def version_string() -> str:
    return f"macOS-TBM {VERSION} ({build_id()})"
