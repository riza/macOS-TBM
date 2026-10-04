"""Regression tests for the native Mach-O reader (no otool)."""

from __future__ import annotations

import struct
import unittest

import _paths  # noqa: F401

from collectors.macho import read_macho, text_ranges


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def _pad(value: bytes, multiple: int = 8) -> bytes:
    remainder = len(value) % multiple
    return value if not remainder else value + b"\x00" * (multiple - remainder)


def _dylib_command(cmd: int, name: str) -> bytes:
    raw = name.encode() + b"\x00"
    body = struct.pack("<IIII", 24, 0, 0, 0) + raw
    padded = _pad(body)
    return struct.pack("<II", cmd, 8 + len(padded)) + padded


def _rpath_command(path: str) -> bytes:
    raw = path.encode() + b"\x00"
    body = struct.pack("<I", 12) + raw
    padded = _pad(body)
    return struct.pack("<II", 0x8000001C, 8 + len(padded)) + padded


def _thin_macho(*, cputype=0x0100000C, cpusubtype=2, weak=False,
                fs_dataoff=0x200, text_addr=0x100000400, text_size=0x100):
    fs_blob = _uleb(0x400) + _uleb(0x40) + b"\x00"
    section = (b"__text\x00" + b"\x00" * 9 + b"__TEXT\x00" + b"\x00" * 9
               + struct.pack("<QQIIIIIIII", text_addr, text_size, 0x400, 0, 0, 0, 0, 0, 0, 0))
    segment = (b"__TEXT\x00" + b"\x00" * 9
               + struct.pack("<QQQQIIII", 0x100000000, 0x1000, 0, 0x1000, 7, 5, 1, 0)
               + section)
    cmds = (
        struct.pack("<II", 0x19, 8 + len(segment)) + segment
        + _dylib_command(0xC, "/usr/lib/libSystem.B.dylib")
        + _dylib_command(0x80000018 if weak else 0xC, "/usr/lib/libz.1.dylib")
        + _rpath_command("@executable_path/../Frameworks")
        + struct.pack("<IIQQ", 0x80000028, 24, 0x400, 0)
        + struct.pack("<IIII", 0x26, 16, fs_dataoff, len(fs_blob))
    )
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, cputype, cpusubtype, 2,
                         6, len(cmds), 0, 0)
    blob = bytearray(header + cmds)
    blob.extend(b"\x00" * (fs_dataoff - len(blob)))
    blob.extend(fs_blob)
    blob.extend(b"\x00" * (0x400 - len(blob)))
    blob.extend(b"\x00" * text_size)
    return bytes(blob)


def _fat(slices):
    header = struct.pack(">II", 0xCAFEBABE, len(slices))
    table = b"".join(struct.pack(">IIIII", ct, cs, off, size, 14)
                     for ct, cs, off, size in slices)
    data = bytearray(header + table)
    data.extend(b"\x00" * (0x2000 - len(data)))
    for _index, (_ct, _cs, offset, _size) in enumerate(slices):
        thin = _thin_macho(cputype=_ct, cpusubtype=_cs)
        data[offset:offset + len(thin)] = thin
    return bytes(data)


class TestNativeMachOReader(unittest.TestCase):
    def test_reads_a_thin_image_natively(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(_thin_macho())
            path = handle.name
        try:
            result = read_macho(path)
        finally:
            os.unlink(path)
        self.assertEqual(result["architectures"], ["arm64e"])
        self.assertFalse(result["is_fat"])
        slice_info = result["slices"][0]
        self.assertIn("/usr/lib/libSystem.B.dylib", slice_info["linked_libs"])
        self.assertIn("@executable_path/../Frameworks", slice_info["rpaths"])
        self.assertEqual(slice_info["entry"], 0x100000400)
        self.assertEqual(slice_info["function_starts"], [0x100000400, 0x100000440])
        self.assertEqual(text_ranges(result), [(0x100000400, 0x100000500)])

    def test_reads_a_fat_image(self):
        import os
        import tempfile
        fat = _fat([(0x01000007, 3, 0x1000, 0x1000), (0x0100000C, 2, 0x2000, 0x1000)])
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(fat)
            path = handle.name
        try:
            result = read_macho(path)
        finally:
            os.unlink(path)
        self.assertTrue(result["is_fat"])
        self.assertEqual(result["architectures"], ["x86_64", "arm64e"])

    def test_malformed_input_is_empty(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b"not a mach-o at all")
            path = handle.name
        try:
            self.assertEqual(read_macho(path), {})
        finally:
            os.unlink(path)
        self.assertEqual(read_macho("/nonexistent/path"), {})


if __name__ == "__main__":
    unittest.main()
