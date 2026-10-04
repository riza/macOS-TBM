"""Regression tests for LC_FUNCTION_STARTS-driven function boundaries."""

from __future__ import annotations

import struct
import unittest

import _paths  # noqa: F401

from collectors.dataflow import _parse_functions
from collectors.macho import (
    decode_uleb128_deltas,
    function_starts_from_slice,
    parse_fat_slices,
)


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


class TestUlebDecode(unittest.TestCase):
    def test_decodes_cumulative_deltas_and_stops_at_zero(self):
        blob = _uleb(0x1000) + _uleb(0x20) + _uleb(0x30) + b"\x00" + _uleb(0x999)
        self.assertEqual(decode_uleb128_deltas(blob), [0x1000, 0x1020, 0x1050])

    def test_malformed_overflow_fails_closed(self):
        self.assertEqual(decode_uleb128_deltas(b"\xff" * 16), [])

    def test_empty_blob_has_no_starts(self):
        self.assertEqual(decode_uleb128_deltas(b""), [])
        self.assertEqual(decode_uleb128_deltas(b"\x00"), [])


class TestFatSlices(unittest.TestCase):
    def test_parses_fat_slice_offsets_and_arch(self):
        header = struct.pack(">II", 0xCAFEBABE, 2)
        x86 = struct.pack(">IIIII", 0x01000007, 3, 0x4000, 0x1000, 14)
        arm = struct.pack(">IIIII", 0x0100000C, 2, 0x20000, 0x2000, 14)
        slices = parse_fat_slices(header + x86 + arm)
        self.assertEqual([s["arch"] for s in slices], ["x86_64", "arm64"])
        self.assertEqual(slices[1]["offset"], 0x20000)

    def test_thin_file_has_no_fat_slices(self):
        self.assertEqual(parse_fat_slices(b"\xcf\xfa\xed\xfe" + b"\x00" * 28), [])


class TestFunctionStartsFromSlice(unittest.TestCase):
    def test_starts_are_slice_relative_and_text_base_relative(self):
        blob = _uleb(0x1468) + _uleb(0xB8) + b"\x00"
        slice_offset = 0x10
        data = b"\x00" * slice_offset + b"\x00" * 0x100 + blob
        starts = function_starts_from_slice(
            data, slice_offset=slice_offset, dataoff=0x100,
            datasize=len(blob), text_base=0x100000000)
        self.assertEqual(starts, [0x100001468, 0x100001520])

    def test_out_of_range_dataoff_fails_closed(self):
        self.assertEqual(
            function_starts_from_slice(b"\x00" * 16, slice_offset=0,
                                       dataoff=0x1000, datasize=0x100,
                                       text_base=0),
            [])


class TestParseFunctionsBoundaries(unittest.TestCase):
    TEXT = """
handle:
0000000100001000 mov x0, x0
0000000100001004 ret
0000000100001010 mov x0, x0
0000000100001014 ret
"""

    def test_authoritative_starts_split_a_stripped_style_text(self):
        functions = _parse_functions(
            self.TEXT, function_starts={"arm64": [0x100001000, 0x100001010]})
        names = sorted(func.name for func in functions.values())
        self.assertEqual(len(names), 2)
        self.assertIn("handle", names)
        self.assertIn("sub_100001010", names)

    def test_without_starts_the_label_remains_one_function(self):
        functions = _parse_functions(self.TEXT)
        self.assertEqual(len(functions), 1)
        self.assertEqual(next(iter(functions.values())).name, "handle")

    def test_percent_in_a_comment_does_not_split_the_function(self):
        text = """
handle_request:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "100% done"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c ret
"""
        functions = _parse_functions(
            text, function_starts={"arm64": [0x100001000]})
        self.assertEqual(len(functions), 1)
        self.assertEqual(next(iter(functions.values())).name, "handle_request")


if __name__ == "__main__":
    unittest.main()
