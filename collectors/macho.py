"""Mach-O static analysis via ``lipo``/``otool``/``nm``/``strings`` (read-only).

All tool execution is abstracted here so a native Mach-O parser can be dropped
in later without touching analyzers. Every step is optional and failure-isolated;
the returned :class:`MachOInfo` records per-step errors.
"""

from __future__ import annotations

import logging
import os
import re
from typing import List, Optional, Set, Tuple

from models.executable import MachOInfo
from utils.commands import ResultCache, run

log = logging.getLogger(__name__)

_RPATH_RE = re.compile(r"^\s*path\s+(.+)\s+\(offset.*\)$")

# Tokens considered "interesting" for downstream signal detection. We extract
# only strings matching these, instead of blindly dumping the whole string table.
_INTERESTING_RE = re.compile(
    r"(?i)(SecTask|SecCode|SecStaticCode|Authorization|audit_token|xpc_|NSXPC|"
    r"bootstrap_|mach_msg|mach_port|OpenDirectory|DirectoryService|dscl|odutil|"
    r"LocalAuthentication|AuthenticationServices|SecKeychain|SecItem|kSecClass|"
    r"TCC|tccd|kTCCService|AVCapture|CLLocation|CGWindowList|SCScreenshot|"
    r"chown|chmod|setxattr|chflags|quarantine|sandbox|seatbelt|posix_spawn|"
    r"SMJobBless|AuthorizationExecuteWithPrivileges|launchd|launchctl|NSTask|"
    r"PackageKit|PKInstall|softwareupdated|MobileSoftwareUpdate|installer|"
    r"nw_listener|nw_connection|CFSocket|getaddrinfo|SecAssessment|syspolicyd|"
    r"Gatekeeper|es_new_client|es_subscribe|com\.apple\.private\.|com\.apple\.TCC|"
    r"com\.apple\.opendirectoryd|com\.apple\.installer|com\.apple\.network)"
)

_MAX_STRINGS = 4000


def _architectures(path: str) -> List[str]:
    res = run(["lipo", "-info", path], timeout=20.0)
    archs: List[str] = []
    if res.ok:
        if "Architectures in the fat file" in res.stdout:
            archs = res.stdout.split("are:", 1)[-1].strip().split()
        elif "is architecture:" in res.stdout:
            archs = [res.stdout.split("is architecture:", 1)[-1].strip()]
    else:
        # Fallback: otool -hv lists one header per architecture.
        ot = run(["otool", "-hv", path], timeout=20.0)
        if ot.ok:
            archs = re.findall(r"cputype \d+ cpusubtype \d+", ot.stdout)
    return [a for a in archs if a]


def _linked_libs(path: str) -> Tuple[List[str], List[str]]:
    """Return ``(all linked libraries, the weakly-linked subset)``.

    Weak links matter for evidence weighting: a weak-linked framework may never
    be resolved at runtime, so it is the thinnest possible signal that a binary
    uses that subsystem.
    """
    res = run(["otool", "-L", path], timeout=40.0)
    libs: List[str] = []
    weak: List[str] = []
    if not res.ok:
        return libs, weak
    for line in res.stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.endswith(":"):
            # Header line such as "/path (architecture x86_64):"
            continue
        entry, _, attrs = s.partition("(")
        entry = entry.strip()
        if entry and entry != path:
            libs.append(entry)
            if "weak" in attrs:
                weak.append(entry)
    seen: Set[str] = set()
    uniq: List[str] = []
    for l in libs:
        if l not in seen:
            seen.add(l)
            uniq.append(l)
    return uniq, [l for l in uniq if l in set(weak)]


def _symbols(path: str, undefined_only: bool) -> List[str]:
    args = ["nm", "-arch", "all"]
    if undefined_only:
        args.append("-u")
    args.append(path)
    res = run(args, timeout=60.0)
    syms: List[str] = []
    if not res.ok:
        return syms
    for line in res.stdout.splitlines():
        s = line.strip()
        if not s or s.endswith(":") or "(for architecture" in s:
            continue
        parts = s.split()
        if not parts:
            continue
        name = parts[-1].lstrip("_")
        if name and not name.startswith("."):
            syms.append(name)
    seen: Set[str] = set()
    return [s for s in syms if not (s in seen or seen.add(s))]


def _defined_and_classes(path: str):
    """One full ``nm`` run -> (defined symbols, Objective-C class names)."""
    res = run(["nm", "-arch", "all", path], timeout=60.0)
    defined: List[str] = []
    classes: List[str] = []
    if not res.ok:
        return defined, classes
    addr_re = re.compile(r"^[0-9a-fA-F]{8,}$")
    for line in res.stdout.splitlines():
        s = line.strip()
        if not s or s.endswith(":") or "(for architecture" in s:
            continue
        tokens = s.split()
        if not tokens:
            continue
        name = tokens[-1]
        # Determine symbol type: address-prefixed => type is tokens[1]; else tokens[0].
        typ = tokens[1] if (len(tokens) > 1 and addr_re.match(tokens[0])) else tokens[0]

        if name.startswith("_OBJC_CLASS_$_") or name.startswith("_OBJC_METACLASS_$_"):
            cls = name.split("$_", 1)[-1]
            if cls:
                classes.append(cls)

        if typ in ("U", "u", "-", "?"):
            continue  # undefined / debug symbols
        clean = name.lstrip("_")
        if clean and not clean.startswith("."):
            defined.append(clean)

    seen: Set[str] = set()
    classes = [c for c in classes if not (c in seen or seen.add(c))]
    seen = set()
    defined = [s for s in defined if not (s in seen or seen.add(s))]
    return defined, classes


def _rpaths(path: str) -> List[str]:
    res = run(["otool", "-l", path], timeout=40.0)
    rpaths: List[str] = []
    if not res.ok:
        return rpaths
    in_rpath = False
    for line in res.stdout.splitlines():
        if "LC_RPATH" in line:
            in_rpath = True
            continue
        if in_rpath:
            m = _RPATH_RE.match(line)
            if m:
                rpaths.append(m.group(1).strip())
            elif "cmd LC_" in line:
                in_rpath = False
    seen: Set[str] = set()
    return [r for r in rpaths if not (r in seen or seen.add(r))]


def _interesting_strings(path: str) -> List[str]:
    res = run(["strings", "-a", "-n", "5", path], timeout=60.0)
    if not res.ok:
        return []
    out: List[str] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if _INTERESTING_RE.search(line):
            out.append(line)
            if len(out) >= _MAX_STRINGS:
                break
    # Dedupe.
    seen: Set[str] = set()
    return [s for s in out if not (s in seen or seen.add(s))]


def inspect_macho(path: str, cache: Optional[ResultCache] = None) -> MachOInfo:
    """Analyze *path*, memoizing results in *cache* keyed by path+mtime."""
    key = _cache_key(path)
    if cache is not None and key in cache:
        return cache.get(key)

    info = MachOInfo(path=path)
    if not os.path.exists(path) or not os.path.isfile(path):
        info.errors.append("not a regular file or does not exist")
        return _store(cache, key, info)

    # file(1) to confirm Mach-O / fat status.
    res = run(["file", path], timeout=10.0)
    if res.ok:
        text = res.stdout
        info.is_macho = "Mach-O" in text
        info.is_fat = "universal" in text or "fat" in text
    if not info.is_macho:
        info.errors.append("not a Mach-O file")
        return _store(cache, key, info)

    info.architectures = _architectures(path)
    info.linked_libs, info.weak_linked_libs = _linked_libs(path)
    info.imported_symbols = _symbols(path, undefined_only=True)
    info.exported_symbols, info.objc_classes = _defined_and_classes(path)
    info.rpaths = _rpaths(path)
    info.interesting_strings = _interesting_strings(path)

    return _store(cache, key, info)


def _cache_key(path: str) -> str:
    try:
        st = os.stat(path)
        return f"macho:{path}:{st.st_size}:{int(st.st_mtime)}"
    except OSError:
        return f"macho:{path}:missing"


def _store(cache: Optional[ResultCache], key: str, info: MachOInfo) -> MachOInfo:
    if cache is not None:
        cache.put(key, info)
    return info
