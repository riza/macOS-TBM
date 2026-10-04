"""Property-list loading with binary plist support and graceful fallback.

Uses :mod:`plistlib` (stdlib) which transparently handles XML, binary and
openstep plists. If ``plistlib`` fails (rare, e.g. a malformed file), falls back
to Apple's ``plutil`` before giving up. Returns ``None`` for unreadable files
rather than raising, so a single corrupt plist cannot crash a full scan.
"""

from __future__ import annotations

import plistlib
from typing import Any, Optional

from .commands import run


def load_plist(path: str) -> Optional[Any]:
    """Load *path* as a plist, returning ``None`` on any failure."""
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except Exception:
        pass

    # Fallback: convert to XML on stdout via plutil.
    res = run(["plutil", "-convert", "xml1", "-o", "-", "--", path], timeout=20.0)
    if res.ok and res.stdout:
        try:
            return plistlib.loads(res.stdout.encode("utf-8"))
        except Exception:
            return None
    return None


def load_plist_bytes(data: bytes) -> Optional[Any]:
    """Parse plist bytes (used for entitlements piped from ``codesign``)."""
    try:
        return plistlib.loads(data)
    except Exception:
        # Entitlements may arrive as binary plist; retry explicitly.
        try:
            return plistlib.loads(data, fmt=plistlib.FMT_BINARY)
        except Exception:
            return None
