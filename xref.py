"""Find code cross-references to a string in a Mach-O binary.

Given a binary and a substring of a C string, locate every ``adrp``/``add``
pair in the code that references the string's address, identify the containing
function, and return disassembly context. Read-only; shells out to ``lipo``
and ``otool``.
"""

import os
import re
import struct
import subprocess
import tempfile
from collections import deque
from dataclasses import dataclass, field
from typing import List, Optional

_LINE_RE = re.compile(r"^([0-9a-f]{16})\t(.*)$")
_ADRP_RE = re.compile(r"^adrp\tx(\d+),\s*(-?\d+)\s*;\s*(0x[0-9a-f]+)$")
_ADD_LIT_RE = re.compile(
    r"^add\tx(\d+),\s*x(\d+),\s*#(0x[0-9a-f]+|\d+)\s*;\s*literal pool"
)
_PROLOGUE_RE = re.compile(
    r"^(pacibsp|sub\s+sp, sp, #|stp\s+x29, x30)"
)
_WINDOW = 20000  # lines kept for backward function-start searches


@dataclass
class XRef:
    string_vaddr: int
    ref_vaddr: int
    function: Optional[int]
    context: List[str] = field(default_factory=list)


def _thin_binary(path: str, arch: Optional[str]) -> str:
    """Return a path to an arch-thin copy of ``path`` (may be the original)."""
    with open(path, "rb") as fh:
        magic = struct.unpack("<I", fh.read(4))[0]
    if magic != 0xBEBAFECA:  # FAT_MAGIC, read little-endian
        return path
    if arch is None:
        raise ValueError(
            f"{path} is a fat binary; pass --arch (try arm64e, arm64, x86_64)"
        )
    fd, tmp = tempfile.mkstemp(prefix="tbm-xref-", suffix=f".{arch}")
    os.close(fd)
    subprocess.run(
        ["lipo", path, "-thin", arch, "-output", tmp],
        check=True,
        capture_output=True,
    )
    return tmp


def _parse_segments(path: str):
    data = open(path, "rb").read()
    if struct.unpack("<I", data[:4])[0] != 0xFEEDFACF:
        raise ValueError("not a 64-bit Mach-O")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, csize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[off + 8 : off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                "<QQQQ", data, off + 24
            )
            segs.append((segname, vmaddr, vmsize, fileoff, filesize))
        off += csize
    return data, segs


def _vaddr_for_fileoff(segs, fileoff: int) -> Optional[int]:
    for _segname, vmaddr, _vmsize, fileoff0, filesize in segs:
        if filesize and fileoff0 <= fileoff < fileoff0 + filesize:
            return vmaddr + (fileoff - fileoff0)
    return None


def find_string(data: bytes, needle: str) -> List[int]:
    """All file offsets at which ``needle`` occurs in ``data``."""
    n = needle.encode()
    out = []
    idx = 0
    while True:
        i = data.find(n, idx)
        if i < 0:
            break
        out.append(i)
        idx = i + 1
    return out


def _function_start(window: deque, pos: int) -> Optional[int]:
    """Walk backward through ``window`` (oldest..pos) to a prologue.

    ``pos`` indexes into the materialized view of the window.
    """
    lines = list(window)
    if not lines or pos < 0 or pos >= len(lines):
        return None
    for j in range(pos, max(-1, pos - len(lines)), -1):
        m = _LINE_RE.match(lines[j])
        if not m:
            continue
        ins = m.group(2)
        if ins == "pacibsp":
            return int(m.group(1), 16)
        if ins.startswith("retab") or ins == "ret":
            for k in range(j + 1, min(len(lines), j + 6)):
                mk = _LINE_RE.match(lines[k])
                if mk and _PROLOGUE_RE.match(mk.group(2)):
                    return int(mk.group(1), 16)
    return None


def xref_string(
    path: str,
    needle: str,
    arch: Optional[str] = None,
    context: int = 16,
    max_refs: int = 20,
) -> List[XRef]:
    """Find code references to ``needle`` in ``path``.

    Matches any C string containing ``needle``; each distinct resolved string
    address is cross-referenced through the disassembly (``adrp``+``add``
    pairs annotated as literal pools by otool). arm64/arm64e supported.
    """
    thin = _thin_binary(path, arch)
    try:
        data, segs = _parse_segments(thin)
        fileoffs = find_string(data, needle)
        seen = set()
        for fo in fileoffs:
            vaddr = _vaddr_for_fileoff(segs, fo)
            if vaddr is not None:
                seen.add(vaddr)
        if not seen:
            return []

        cmd = ["otool", "-tvV", thin]
        window: deque = deque(maxlen=_WINDOW)
        adrp_reg: dict = {}
        pending: List[dict] = []
        found: List[XRef] = []
        line_no = 0
        with subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        ) as p:
            for raw in p.stdout:
                line = raw.decode("utf-8", "replace").rstrip("\n")
                m = _LINE_RE.match(line)
                if m:
                    ins = m.group(2)
                    ma = _ADRP_RE.match(ins)
                    if ma:
                        adrp_reg[int(ma.group(1))] = int(ma.group(3), 16)
                    else:
                        mi = _ADD_LIT_RE.match(ins)
                        if mi:
                            reg = int(mi.group(2))
                            base = adrp_reg.get(reg)
                            if base is not None:
                                cand = base + int(mi.group(3), 0)
                                if cand in seen and len(found) + len(
                                    [e for e in pending if not e["done"]]
                                ) < max_refs:
                                    pending.append(
                                        {
                                            "xref": XRef(
                                                string_vaddr=cand,
                                                ref_vaddr=int(m.group(1), 16),
                                                function=None,
                                            ),
                                            "abs": line_no,
                                            "seen": 0,
                                            "done": False,
                                        }
                                    )
                window.append(line)
                line_no += 1
                for entry in pending:
                    if entry["done"]:
                        continue
                    if entry["seen"] < context:
                        entry["seen"] += 1
                    if entry["seen"] >= context:
                        entry["done"] = True
                        view = list(window)
                        abs_start = line_no - len(view)
                        rel = entry["abs"] - abs_start
                        entry["xref"].function = _function_start(view, rel)
                        if 0 <= rel < len(view):
                            half = context // 2
                            start = max(0, rel - half)
                            end = min(len(view), start + max(context, 1))
                            start = max(0, end - context)
                            entry["xref"].context = view[start:end]
                        found.append(entry["xref"])
                if len(found) >= max_refs and not any(
                    not e["done"] for e in pending
                ):
                    break
            try:
                p.terminate()
            except OSError:
                pass
            p.wait()
        for entry in pending:
            if not entry["done"]:
                entry["done"] = True
                view = list(window)
                abs_start = line_no - len(view)
                rel = entry["abs"] - abs_start
                entry["xref"].function = _function_start(view, rel)
                if 0 <= rel < len(view):
                    half = context // 2
                    start = max(0, rel - half)
                    end = min(len(view), start + max(context, 1))
                    start = max(0, end - context)
                    entry["xref"].context = view[start:end]
                found.append(entry["xref"])
        return found
    finally:
        if thin != path and os.path.exists(thin):
            os.unlink(thin)


def format_xref(results: List[XRef]) -> str:
    if not results:
        return "no references found"
    out = []
    for r in results:
        out.append(f"string vaddr: {hex(r.string_vaddr)}")
        out.append(f"  ref at:     {hex(r.ref_vaddr)}")
        out.append(f"  function:   {hex(r.function) if r.function else 'unknown'}")
        out.append("  context:")
        for line in r.context:
            out.append(f"    {line}")
        out.append("")
    return "\n".join(out).rstrip()
