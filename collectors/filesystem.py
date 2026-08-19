"""Filesystem enumeration of XPC services and interesting executable roots.

This complements launchd discovery by finding ``.xpc`` bundles embedded inside
frameworks/apps/system components and by walking the standard executable roots
for binaries that may not be registered as launchd jobs.
"""

from __future__ import annotations

import logging
import os
from typing import Iterable, List

log = logging.getLogger(__name__)

DEFAULT_BINARY_ROOTS: List[str] = [
    "/usr/libexec",
    "/usr/sbin",
    "/usr/bin",
]

DEFAULT_XPC_ROOTS: List[str] = [
    "/System/Library/PrivateFrameworks",
    "/System/Library/Frameworks",
    "/System/Library/CoreServices",
    "/Library/Apple/System/Library/Frameworks",
]


def iter_files_with_suffix(root: str, suffix: str, max_depth: int = 6) -> Iterable[str]:
    """Yield files under *root* ending in *suffix* (bounded depth, safe walk)."""
    if not os.path.isdir(root):
        return
    base_depth = root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = dirpath.rstrip("/").count("/") - base_depth
        if depth > max_depth:
            dirnames[:] = []
            continue
        for fn in filenames:
            if fn.endswith(suffix):
                yield os.path.join(dirpath, fn)


def discover_xpc_bundles(roots: List[str] | None = None) -> List[str]:
    """Return ``*.xpc`` bundle paths discovered under *roots*."""
    if roots is None:
        roots = DEFAULT_XPC_ROOTS
    found: List[str] = []
    for root in roots:
        try:
            found.extend(iter_files_with_suffix(root, ".xpc", max_depth=6))
        except OSError as exc:
            log.warning("cannot walk %s: %s", root, exc)
    return found


def discover_executables(roots: List[str] | None = None) -> List[str]:
    """Return executable paths discovered under *roots* (regular files only)."""
    if roots is None:
        roots = DEFAULT_BINARY_ROOTS
    found: List[str] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            for entry in sorted(os.listdir(root)):
                path = os.path.join(root, entry)
                if os.path.isfile(path) and os.access(path, os.R_OK):
                    found.append(path)
        except OSError as exc:
            log.warning("cannot list %s: %s", root, exc)
    return found
