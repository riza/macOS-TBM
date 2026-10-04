"""Mach-O static analysis via ``lipo``/``otool``/``nm``/``strings`` (read-only).

All tool execution is abstracted here so a native Mach-O parser can be dropped
in later without touching analyzers. Every step is optional and failure-isolated;
the returned :class:`MachOInfo` records per-step errors.
"""

from __future__ import annotations

import logging
import os
import re
import struct
from typing import Dict, List, Optional, Set, Tuple

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
    r"com\.apple\.opendirectoryd|com\.apple\.installer|com\.apple\.network|"
    r"valueForEntitlement|remoteProcessHasBooleanEntitlement|boolValue|"
    r"shouldAcceptNewConnection|not entitled|"
    r"missing entitlement|SecKeyCreateSignature|SecKeyCreateDecryptedData|"
    r"SecKeyCopyExternalRepresentation|SecKeyCopyKeyExchangeResult|PlatformSSO|"
    r"PlatformSSOCore|AppSSO|Kerberos|OpenDirectory|removeItemAtPath|"
    r"moveItemAtPath|copyItemAtPath|replaceItemAtURL|setAttributes:ofItemAtPath|"
    r"createFileAtPath|createDirectoryAtPath|createSymbolicLinkAtPath|"
    r"fileExistsAtPath|isReadableFileAtPath|isWritableFileAtPath|"
    r"/private/tmp|/var/tmp|/tmp/|Library/Caches|Library/LaunchDaemons|"
    r"Library/PrivilegedHelperTools|Library/Preferences|Library/Security|"
    r"/private/etc|/etc/authorization|/Library/Scripts|/private/var/root|"
    r"SecTaskCreateFromSelf|"
    r"TeamIdentifier|SigningIdentifier|designated requirement)"
)

# Bundle-identifier-shaped strings (``com.apple.foo.bar``). A binary that names a
# Mach service is a candidate client of it, which is the only honest way to draw
# a client edge in the trust-boundary graph from static data.
_IDENTIFIER_RE = re.compile(r"^[a-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+){2,}$")

_MAX_STRINGS = 4000

# Mach-O constants used by the LC_FUNCTION_STARTS reader. Function starts are
# the authoritative function boundaries in a stripped image: `otool` emits no
# per-function labels and `nm` has nothing to report, so without this the whole
# text section reads as one function and no direct call can be resolved.
_MH_MAGIC_64 = 0xFEEDFACF
_MH_CIGAM_64 = 0xCFFAEDFE
_MH_MAGIC_32 = 0xFEEDFACE
_MH_CIGAM_32 = 0xCEFAEDFE
_FAT_MAGIC = (0xCAFEBABE, 0xCAFEBABF)
_LC_SEGMENT = 0x1
_LC_SEGMENT_64 = 0x19
_LC_LOAD_DYLIB = 0xC
_LC_LOAD_WEAK_DYLIB = 0x80000018
_LC_RPATH = 0x8000001C
_LC_FUNCTION_STARTS = 0x26
_LC_MAIN = 0x80000028
_CPU_ARCH_ABI64 = 0x01000000
_CPU_TYPE_X86_64 = _CPU_ARCH_ABI64 | 7
_CPU_TYPE_ARM64 = _CPU_ARCH_ABI64 | 12
_CPU_SUBTYPE_ARM64E = 2


def _arch_from_cputype(cputype: int) -> str:
    if cputype == _CPU_TYPE_X86_64:
        return "x86_64"
    if cputype == _CPU_TYPE_ARM64:
        return "arm64"
    return f"cpu_{cputype:x}"


def _display_arch(cputype: int, cpusubtype: int) -> str:
    """Human-facing architecture name, preserving the arm64e subtype."""
    if cputype == _CPU_TYPE_ARM64 and (cpusubtype & 0x00FFFFFF) == _CPU_SUBTYPE_ARM64E:
        return "arm64e"
    return _arch_from_cputype(cputype)


def decode_uleb128_deltas(blob: bytes) -> List[int]:
    """Decode the cumulative addresses encoded by ``LC_FUNCTION_STARTS``.

    The payload is a sequence of ULEB128 deltas from the image base, each
    relative to the previous address, terminated by a zero byte. A malformed
    encoding (more than 64 bits) fails closed with whatever decoded so far.
    """
    starts: List[int] = []
    address = 0
    index = 0
    length = len(blob)
    while index < length:
        if blob[index] == 0:
            break
        value = 0
        shift = 0
        while index < length:
            byte = blob[index]
            index += 1
            value |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
            if shift > 63:
                return starts
        address += value
        starts.append(address)
    return starts


def parse_fat_slices(data: bytes) -> List[Dict]:
    """Return the fat-archive slices as ``{arch, offset, size}`` (empty if thin)."""
    if len(data) < 8:
        return []
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in _FAT_MAGIC:
        return []
    count = struct.unpack_from(">I", data, 4)[0]
    slices: List[Dict] = []
    for index in range(count):
        base = 8 + index * 20
        if base + 20 > len(data):
            break
        cputype, _sub, offset, size, _align = struct.unpack_from(">IIIII", data, base)
        slices.append({"arch": _arch_from_cputype(cputype),
                       "offset": offset, "size": size})
    return slices


def function_starts_from_slice(data: bytes, slice_offset: int, dataoff: int,
                               datasize: int, text_base: int) -> List[int]:
    """Decode one slice's function starts; ``dataoff`` is slice-relative."""
    start = slice_offset + dataoff
    if dataoff <= 0 or datasize <= 0 or start + datasize > len(data):
        return []
    return [text_base + offset for offset in decode_uleb128_deltas(
        data[start:start + datasize])]


def _macho_function_starts(data: bytes, slice_offset: int) -> Optional[Dict]:
    """Walk one slice's load commands and decode ``LC_FUNCTION_STARTS``."""
    if slice_offset + 28 > len(data):
        return None
    magic = struct.unpack_from("<I", data, slice_offset)[0]
    if magic in (_MH_MAGIC_64, _MH_MAGIC_32):
        endian, is64 = "<", magic == _MH_MAGIC_64
    elif magic in (_MH_CIGAM_64, _MH_CIGAM_32):
        endian, is64 = ">", magic == _MH_CIGAM_64
    else:
        return None
    cputype = struct.unpack_from(endian + "I", data, slice_offset + 4)[0]
    ncmds = struct.unpack_from(endian + "I", data, slice_offset + 16)[0]
    offset = slice_offset + (32 if is64 else 28)
    function_starts_lc: Optional[Tuple[int, int]] = None
    text: Optional[Tuple[int, int]] = None
    for _ in range(ncmds):
        if offset + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            break
        if cmd == _LC_FUNCTION_STARTS:
            function_starts_lc = struct.unpack_from(endian + "II", data, offset + 8)
        elif cmd == _LC_SEGMENT_64 and is64 and cmdsize >= 72:
            segname = data[offset + 8:offset + 24].rstrip(b"\x00")
            if segname == b"__TEXT":
                vmaddr, vmsize = struct.unpack_from(endian + "QQ", data, offset + 24)
                text = (vmaddr, vmsize)
        offset += cmdsize
    if not function_starts_lc or not text:
        return None
    dataoff, datasize = function_starts_lc
    text_base, text_size = text
    starts = function_starts_from_slice(data, slice_offset, dataoff, datasize, text_base)
    # Fail closed: if the decoded addresses do not land in the executable
    # segment the offset was misread, and a wrong boundary set is worse than
    # none at all.
    if text_size and starts:
        starts = [value for value in starts
                  if text_base <= value < text_base + text_size]
    return {"arch": _arch_from_cputype(cputype), "starts": sorted(set(starts))}


def _cstr(data: bytes, start: int, limit: int) -> str:
    if start < 0 or start >= len(data) or start >= limit:
        return ""
    end = data.find(b"\x00", start, limit)
    if end < 0:
        end = limit
    return data[start:end].decode("utf-8", "replace")


def _parse_slice(data: bytes, slice_offset: int) -> Optional[Dict]:
    """Parse one Mach-O slice's load commands natively (no otool)."""
    if slice_offset + 28 > len(data):
        return None
    magic = struct.unpack_from("<I", data, slice_offset)[0]
    if magic in (_MH_MAGIC_64, _MH_MAGIC_32):
        endian, is64 = "<", magic == _MH_MAGIC_64
    elif magic in (_MH_CIGAM_64, _MH_CIGAM_32):
        endian, is64 = ">", magic == _MH_CIGAM_64
    else:
        return None
    def u32(off):
        return struct.unpack_from(endian + "I", data, off)[0]

    def u64(off):
        return struct.unpack_from(endian + "Q", data, off)[0]

    cputype = u32(slice_offset + 4)
    cpusubtype = u32(slice_offset + 8)
    ncmds = u32(slice_offset + 16)
    out: Dict = {
        "arch": _arch_from_cputype(cputype),
        "display_arch": _display_arch(cputype, cpusubtype),
        "is64": is64, "endian": endian, "cputype": cputype,
        "offset": slice_offset,
        "entry": None, "linked_libs": [], "weak_linked_libs": [],
        "rpaths": [], "sections": [], "text": None, "function_starts": [],
    }
    offset = slice_offset + (32 if is64 else 28)
    function_starts_lc: Optional[Tuple[int, int]] = None
    for _ in range(ncmds):
        if offset + 8 > len(data):
            break
        cmd, cmdsize = u32(offset), u32(offset + 4)
        if cmdsize < 8 or offset + cmdsize > len(data):
            break
        if cmd == _LC_SEGMENT_64 and is64 and cmdsize >= 72:
            segname = data[offset + 8:offset + 24].rstrip(b"\x00").decode("ascii", "replace")
            vmaddr, vmsize = u64(offset + 24), u64(offset + 32)
            nsects = u32(offset + 64)
            if segname == "__TEXT":
                out["text"] = (vmaddr, vmsize)
            section = offset + 72
            for _ in range(nsects):
                if section + 80 > offset + cmdsize:
                    break
                out["sections"].append({
                    "sectname": data[section:section + 16].rstrip(b"\x00").decode("ascii", "replace"),
                    "segname": data[section + 16:section + 32].rstrip(b"\x00").decode("ascii", "replace"),
                    "addr": u64(section + 32), "size": u64(section + 40),
                    "offset": u32(section + 48),
                })
                section += 80
        elif cmd in (_LC_LOAD_DYLIB, _LC_LOAD_WEAK_DYLIB):
            name = _cstr(data, offset + u32(offset + 8), offset + cmdsize)
            if name:
                out["linked_libs"].append(name)
                if cmd == _LC_LOAD_WEAK_DYLIB:
                    out["weak_linked_libs"].append(name)
        elif cmd == _LC_RPATH:
            path = _cstr(data, offset + u32(offset + 8), offset + cmdsize)
            if path:
                out["rpaths"].append(path)
        elif cmd == _LC_MAIN:
            base = out["text"][0] if out["text"] else 0
            out["entry"] = base + u64(offset + 8)
        elif cmd == _LC_FUNCTION_STARTS:
            function_starts_lc = (u32(offset + 8), u32(offset + 12))
        offset += cmdsize
    if function_starts_lc and out["text"]:
        dataoff, datasize = function_starts_lc
        starts = function_starts_from_slice(data, slice_offset, dataoff, datasize,
                                            out["text"][0])
        base, size = out["text"]
        if size:
            starts = [value for value in starts if base <= value < base + size]
        out["function_starts"] = sorted(set(starts))
    out["linked_libs"] = list(dict.fromkeys(out["linked_libs"]))
    out["weak_linked_libs"] = list(dict.fromkeys(out["weak_linked_libs"]))
    out["rpaths"] = list(dict.fromkeys(out["rpaths"]))
    return out


def read_macho(path: str) -> Dict:
    """Parse a Mach-O natively: slices, libs, rpaths, sections, entry, starts."""
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return {}
    slices = parse_fat_slices(data)
    offsets = [int(entry["offset"]) for entry in slices] if slices else [0]
    parsed = [info for info in (_parse_slice(data, offset) for offset in offsets) if info]
    if not parsed:
        return {}
    return {
        "is_fat": bool(slices),
        "architectures": [info["display_arch"] for info in parsed],
        "slices": parsed,
    }


def text_ranges(image: Dict) -> List[Tuple[int, int]]:
    """Executable ``__TEXT,__text`` ranges from a parsed image."""
    ranges: List[Tuple[int, int]] = []
    for info in image.get("slices", []):
        for section in info.get("sections", []):
            if section["sectname"] == "__text" and section["segname"] == "__TEXT" and section["size"]:
                ranges.append((section["addr"], section["addr"] + section["size"]))
    return ranges


def objc_selector_refs(path: str, image: Optional[Dict] = None) -> Dict[str, Dict[int, str]]:
    """Map ``__objc_selrefs`` pointer addresses to selector strings.

    On modern arm64e images the pointers are chained fixups (base-relative
    rebases), so the target is decoded as ``image_base + low36`` and the string
    is read from ``__objc_methname``. Anything that does not decode to a string
    in that section is dropped rather than guessed.
    """
    if image is None:
        image = read_macho(path)
    if not image:
        return {}
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return {}
    out: Dict[str, Dict[int, str]] = {}
    for info in image.get("slices", []):
        arch = info.get("arch")
        if not arch or not info.get("text"):
            continue
        selrefs = next((s for s in info["sections"] if s["sectname"] == "__objc_selrefs"), None)
        methname = next((s for s in info["sections"] if s["sectname"] == "__objc_methname"), None)
        if not selrefs or not methname:
            continue
        slice_offset = int(info.get("offset", 0))
        sel_off = slice_offset + int(selrefs["offset"])
        blob = data[sel_off:sel_off + int(selrefs["size"])]
        meth_off = slice_offset + int(methname["offset"])
        meth = data[meth_off:meth_off + int(methname["size"])]
        meth_addr = int(methname["addr"])
        mapping: Dict[int, str] = {}
        for index in range(len(blob) // 8):
            encoded = struct.unpack_from("<Q", blob, index * 8)[0]
            target = int(info["text"][0]) + (encoded & 0xFFFFFFFFF)
            position = target - meth_addr
            if not 0 <= position < len(meth):
                continue
            end = meth.find(b"\x00", position)
            if end <= position:
                continue
            value = meth[position:end].decode("ascii", "replace")
            if value:
                mapping[int(selrefs["addr"]) + index * 8] = value
        if mapping:
            out[arch] = mapping
    return out


def function_starts(path: str) -> Dict[str, List[int]]:
    """Return ``{arch: sorted function-start VAs}`` for a Mach-O (best effort)."""
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return {}
    slices = parse_fat_slices(data)
    if not slices:
        slices = [{"arch": None, "offset": 0, "size": len(data)}]
    out: Dict[str, List[int]] = {}
    for entry in slices:
        info = _macho_function_starts(data, int(entry["offset"]))
        if not info or not info["starts"]:
            continue
        arch = entry.get("arch") or info["arch"]
        out.setdefault(arch, [])
        out[arch] = sorted(set(out[arch]) | set(info["starts"]))
    return out


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
    for lib in libs:
        if lib not in seen:
            seen.add(lib)
            uniq.append(lib)
    return uniq, [lib for lib in uniq if lib in set(weak)]


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
        if _INTERESTING_RE.search(line) or _IDENTIFIER_RE.match(line):
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

    image = read_macho(path)
    info.architectures = image.get("architectures") or _architectures(path)
    if image.get("slices"):
        primary = image["slices"][0]
        info.linked_libs = primary["linked_libs"] or _linked_libs(path)[0]
        info.weak_linked_libs = primary["weak_linked_libs"]
        info.rpaths = primary["rpaths"] or _rpaths(path)
        info.function_starts = {slice_info["arch"]: slice_info["function_starts"]
                                for slice_info in image["slices"]
                                if slice_info["function_starts"]}
        info.text_ranges = text_ranges(image)
    else:
        info.linked_libs, info.weak_linked_libs = _linked_libs(path)
        info.rpaths = _rpaths(path)
        info.function_starts = function_starts(path)
    info.imported_symbols = _symbols(path, undefined_only=True)
    info.exported_symbols, info.objc_classes = _defined_and_classes(path)
    info.interesting_strings = _interesting_strings(path)
    info.objc_selector_refs = objc_selector_refs(path, image=image)

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
