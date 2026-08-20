"""NSXPC protocol extraction from a Mach-O binary (read-only).

Given a daemon that exports an NSXPC interface, this recovers the exported
Objective-C protocol (name + method signatures) from ``otool -ov`` / ``nm`` and
decodes the ObjC type encodings into readable signatures, e.g.::

    v40@0:8@16@24@?32  ->  - (void)handleActivationInfo:(id)arg0 options:(id)arg1 withCompletionBlock:(id)block

Detection of "NSXPC-exported": a class conforms to ``NSXPCListenerDelegate``
and references the protocol in its protocol list (the other protocols in that
list are the exported interfaces).

Two ``otool -ov`` layouts are handled:

* **absolute** (``x86_64`` / pre-relative binaries) — ``name`` fields resolve
  to the selector string directly;
* **relative** (modern ``arm64e``) — ``name`` fields hold a relative offset to a
  ``__objc_selrefs`` entry, which points at the selector in ``__objc_methname``.
  ``otool -ov`` prints the resolved *types* but not the *names* for these, so we
  resolve the two-level indirection ourselves (field + offset -> selref ->
  chained pointer -> selector string).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from utils.commands import run

# --------------------------------------------------------------------------
# ObjC type-encoding decode
# --------------------------------------------------------------------------

_TYPE_NAMES = {
    "v": "void",
    "B": "BOOL",
    "c": "char",
    "s": "short",
    "i": "int",
    "l": "long",
    "q": "long long",
    "C": "unsigned char",
    "S": "unsigned short",
    "I": "unsigned int",
    "L": "unsigned long",
    "Q": "unsigned long long",
    "f": "float",
    "d": "double",
    "*": "char *",
    "#": "Class",
    ":": "SEL",
    "@": "id",
    "@?": "id",  # a block; rendered as id (the skeleton cannot know its shape)
}

_QUALIFIERS = "rnNoORV"


def _read_type(s: str, i: int) -> Tuple[str, int]:
    """Read one type token starting at *i*; return ``(token, next_index)``."""
    if i >= len(s):
        return "", i
    c = s[i]
    if c in _QUALIFIERS:
        inner, i = _read_type(s, i + 1)
        return inner, i
    if c == "@":
        if i + 1 < len(s) and s[i + 1] == "?":
            return "@?", i + 2
        return "@", i + 1
    if c == "^":
        inner, i = _read_type(s, i + 1)
        return "^" + inner, i
    if c in "{[(":
        closer = {"{": "}", "[": "]", "(": ")"}[c]
        depth = 0
        j = i
        while j < len(s):
            if s[j] == c:
                depth += 1
            elif s[j] == closer:
                depth -= 1
                if depth == 0:
                    return s[i:j + 1], j + 1
            j += 1
        return s[i:], len(s)
    if c == "b":  # bitfield: b<width>
        j = i + 1
        while j < len(s) and s[j].isdigit():
            j += 1
        return s[i:j], j
    return c, i + 1


def decode_type(token: str) -> str:
    """Map an ObjC type token to a readable C type (best effort)."""
    if token == "@?":
        return _TYPE_NAMES["@?"]
    if token.startswith("^"):
        return decode_type(token[1:]) + " *"
    if token.startswith("{"):
        inner = token[1:-1].split("=", 1)[0]
        return inner or "struct"
    if token.startswith("["):
        m = re.match(r"\[(\d*)(.*)\]", token, re.S)
        if m:
            return decode_type(m.group(2)) + "[]"
        return "array"
    if token.startswith("("):
        return "union"
    if token.startswith("b"):
        return "int"
    return _TYPE_NAMES.get(token, token)


def parse_method_types(types: str) -> Tuple[str, List[str]]:
    """Decode a method encoding into ``(return_type, [arg_type, ...])``.

    ``v40@0:8@16@24@?32`` -> ``("v", ["@", "@", "@?"])``: return type, then the
    frame size, the ``@0:8`` self/_cmd header, then type/offset pairs.
    """
    if not types:
        return "void", []
    i = 0
    ret, i = _read_type(types, i)
    while i < len(types) and types[i].isdigit():
        i += 1
    if i >= len(types) or types[i] != "@":
        return ret, []
    i += 1
    while i < len(types) and types[i].isdigit():
        i += 1
    if i < len(types) and types[i] == ":":
        i += 1
    while i < len(types) and types[i].isdigit():
        i += 1
    args: List[str] = []
    while i < len(types):
        token, i = _read_type(types, i)
        while i < len(types) and types[i].isdigit():
            i += 1
        if token:
            args.append(token)
    return ret, args


def method_signature(name: str, types: str) -> str:
    """Render ``- (void)label:(id)arg0 ... reply:(id)block`` for a method."""
    ret, args = parse_method_types(types)
    labels = (name or "").split(":")[:-1]
    parts: List[str] = []
    for i, token in enumerate(args):
        label = labels[i] if i < len(labels) else ("reply" if token == "@?" else f"arg{i}")
        argname = "block" if token == "@?" else f"arg{i}"
        parts.append(f"{label}:({decode_type(token)}){argname}")
    return f"- ({decode_type(ret)})" + " ".join(parts)


# --------------------------------------------------------------------------
# otool -ov parsing
# --------------------------------------------------------------------------

@dataclass
class Method:
    name: Optional[str]        # selector; None when the relative name is unresolved
    selref: Optional[int]      # selref address to resolve (relative layout only)
    types: str = ""

    @property
    def signature(self) -> str:
        return method_signature(self.name or "", self.types)

    def to_dict(self) -> Dict[str, Any]:
        ret, args = parse_method_types(self.types)
        return {
            "name": self.name,
            "types": self.types,
            "signature": self.signature,
            "return_type": decode_type(ret),
            "args": [{"type": decode_type(t), "is_block": t == "@?"} for t in args],
        }


@dataclass
class Protocol:
    name: str
    methods: List[Method] = field(default_factory=list)
    exported: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "methods": [m.to_dict() for m in self.methods]}


def _parse_name_field(stripped: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse a method-list ``name`` line into ``(selector, selref_addr)``.

    Absolute layout: ``name 0x10005de9f copyAutomaticTimeEnabledWithCompletion:``
    Relative layout: ``name 0x35990 (0x10009d700)`` — the paren is the selref.
    """
    tokens = stripped.split()
    if len(tokens) < 3:
        return None, None
    if tokens[2].startswith("("):
        try:
            return None, int(tokens[2].strip("()"), 16)
        except ValueError:
            return None, None
    return tokens[2], None


def _parse_types_field(stripped: str) -> str:
    tokens = stripped.split()
    if len(tokens) < 2:
        return ""
    candidate = tokens[-1]
    # A method encoding always carries self (@) and _cmd (:); a bare address does not.
    return candidate if ("@" in candidate and ":" in candidate) else ""


def _parse_method_lists(text: str) -> Dict[str, List[Method]]:
    """Return ``{protocol_name: [Method, ...]}`` keyed by the method-list symbol."""
    out: Dict[str, List[Method]] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("instanceMethods "):
            m = re.search(r"__OBJC_\$_PROTOCOL_INSTANCE_METHODS_(\S+)", stripped)
            if m:
                proto = m.group(1)
                base_indent = len(line) - len(line.lstrip())
                methods: List[Method] = []
                cur_name: Optional[str] = None
                cur_selref: Optional[int] = None
                j = i + 1
                while j < len(lines):
                    ln = lines[j]
                    s = ln.strip()
                    if not s:
                        j += 1
                        continue
                    indent = len(ln) - len(ln.lstrip())
                    if indent <= base_indent:
                        break
                    if s.startswith("name "):
                        cur_name, cur_selref = _parse_name_field(s)
                    elif s.startswith("types "):
                        methods.append(Method(name=cur_name, selref=cur_selref,
                                              types=_parse_types_field(s)))
                        cur_name = cur_selref = None
                    j += 1
                out[proto] = methods
                i = j
                continue
        i += 1
    return out


def _parse_exported_protocol_names(text: str) -> set:
    """Protocols referenced by a class that also conforms to NSXPCListenerDelegate."""
    exported: set = set()
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("baseProtocols "):
            continue
        base_indent = len(line) - len(line.lstrip())
        protos: List[str] = []
        j = idx + 1
        while j < len(lines):
            ln = lines[j]
            s = ln.strip()
            if not s:
                j += 1
                continue
            indent = len(ln) - len(ln.lstrip())
            if indent <= base_indent:
                break
            m = re.search(r"__OBJC_PROTOCOL_\$_(\S+)", s)
            if m:
                protos.append(m.group(1))
            j += 1
        if "NSXPCListenerDelegate" in protos:
            for p in protos:
                if p not in ("NSXPCListenerDelegate", "NSObject"):
                    exported.add(p)
    return exported


def parse_otool_ov(text: str) -> List[Protocol]:
    """Parse ``otool -ov`` into a list of NSXPC-exported protocols."""
    method_lists = _parse_method_lists(text)
    exported = _parse_exported_protocol_names(text)
    protocols: List[Protocol] = []
    for name in sorted(exported):
        protocols.append(Protocol(name=name, methods=list(method_lists.get(name, [])),
                                  exported=True))
    return protocols


# --------------------------------------------------------------------------
# Relative-name resolution (modern arm64e binaries)
# --------------------------------------------------------------------------

def parse_methname(text: str) -> Dict[int, str]:
    """Parse ``otool -v -s __TEXT __objc_methname`` -> ``{addr: selector}``."""
    out: Dict[int, str] = {}
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F]{16})\s+(.*)$", line)
        if m:
            out[int(m.group(1), 16)] = m.group(2)
    return out


def parse_selrefs(text: str, image_base: int) -> Dict[int, int]:
    """Parse ``otool -s __DATA __objc_selrefs`` -> ``{selref_addr: selector_addr}``.

    Each entry is 8 bytes; the low 32 bits are a chained-pointer offset from the
    image base (for non-chained binaries they are the absolute low half, and
    ``image_base + low32`` still reproduces the address).
    """
    out: Dict[int, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or not re.match(r"^[0-9a-fA-F]{16}$", parts[0]):
            continue
        addr = int(parts[0], 16)
        words = parts[1:]
        for k in range(0, len(words) - 1, 2):
            low = int(words[k], 16) & 0xFFFFFFFF
            out[addr + k * 4] = image_base + low
    return out


def resolve_names(protocols: List[Protocol], methname: Dict[int, str],
                  selrefs: Dict[int, int]) -> None:
    """Fill in unresolved method names via the selref -> selector indirection."""
    for proto in protocols:
        for method in proto.methods:
            if method.name is not None or method.selref is None:
                continue
            selector_addr = selrefs.get(method.selref)
            if selector_addr is None:
                continue
            method.name = methname.get(selector_addr, "")


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def _otool_ov(path: str, run_fn=run) -> str:
    """Best-effort ``otool -ov``, preferring arm64e and falling back."""
    for arch in ("arm64e", "arm64", "x86_64"):
        res = run_fn(["otool", "-arch", arch, "-ov", path], timeout=120.0)
        if res.ok and res.stdout.strip():
            return res.stdout
    res = run_fn(["otool", "-ov", path], timeout=120.0)
    return res.stdout if res.ok else ""


def _image_base(path: str, arch: str, run_fn=run) -> int:
    res = run_fn(["nm", "-arch", arch, path], timeout=60.0)
    if res.ok:
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[-1] == "__mh_execute_header":
                try:
                    return int(parts[0], 16)
                except ValueError:
                    pass
    return 0x100000000


def _selector_tables(path: str, arch: str, run_fn=run) -> Tuple[Dict[int, str], Dict[int, int]]:
    methname: Dict[int, str] = {}
    res = run_fn(["otool", "-arch", arch, "-v", "-s", "__TEXT", "__objc_methname", path],
                 timeout=60.0)
    if res.ok:
        methname = parse_methname(res.stdout)

    selrefs: Dict[int, int] = {}
    image_base = _image_base(path, arch, run_fn)
    res = run_fn(["otool", "-arch", arch, "-s", "__DATA", "__objc_selrefs", path], timeout=60.0)
    if res.ok:
        selrefs = parse_selrefs(res.stdout, image_base)
    return methname, selrefs


def extract_protocols(path: str, run_fn=run) -> Dict[str, Any]:
    """Extract NSXPC-exported protocols from *path* into a JSON-ready dict."""
    text = _otool_ov(path, run_fn)
    protocols = parse_otool_ov(text)

    if any(m.name is None for p in protocols for m in p.methods):
        # Relative method lists: resolve names via the selref indirection.
        arch = "arm64e"
        res = run_fn(["otool", "-arch", arch, "-ov", path], timeout=120.0)
        if not res.ok:
            arch = "x86_64"
        methname, selrefs = _selector_tables(path, arch, run_fn)
        resolve_names(protocols, methname, selrefs)

    return {
        "binary": path,
        "mach_service": None,
        "protocols": [p.to_dict() for p in protocols],
    }
