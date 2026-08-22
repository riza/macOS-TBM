"""Tests for Mach-O string cross-reference helpers."""

from __future__ import annotations

import unittest

import _paths  # noqa: F401

import xref


DATA = b"\x00" * 16 + b"needle" + b"\x00"
SEGS = [("__TEXT", 0x1000, 0x1000, 0, 0x20)]
LINES = [
    "0000000000000000\tpacibsp",
    "0000000000000004\tsub\tsp, sp, #0x10",
    "0000000000000008\tret",
    "000000000000000c\tpacibsp",
    "0000000000000010\tsub\tsp, sp, #0x10",
    "0000000000000014\tstp\tx29, x30, [sp, #0x10]",
    "0000000000000018\tadrp\tx3, 0 ; 0x1000",
    "000000000000001c\tadd\tx3, x3, #0x10 ; literal pool",
    "0000000000000020\tmov\tx0, #0x0",
    "0000000000000024\tret",
]


class _FakeStdout:
    def __init__(self, lines):
        self._lines = iter(lines)

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._lines).encode()


class _FakePopen:
    def __init__(self, cmd, stdout=None, stderr=None):
        self.stdout = _FakeStdout(LINES)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def terminate(self):
        self.terminated = True

    def wait(self):
        if not getattr(self, "terminated", False):
            raise AssertionError("process wait was called before terminate")
        return 0


class TestXRefString(unittest.TestCase):
    def test_resolves_function_and_context(self):
        original_thin = xref._thin_binary
        original_segments = xref._parse_segments
        original_popen = xref.subprocess.Popen
        xref._thin_binary = lambda path, arch: path
        xref._parse_segments = lambda path: (DATA, SEGS)
        xref.subprocess.Popen = lambda *args, **kwargs: _FakePopen(*args, **kwargs)
        try:
            refs = xref.xref_string("/fake", "needle", context=4, max_refs=5)
        finally:
            xref._thin_binary = original_thin
            xref._parse_segments = original_segments
            xref.subprocess.Popen = original_popen

        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0].string_vaddr, 0x1010)
        self.assertEqual(refs[0].ref_vaddr, 0x1C)
        self.assertEqual(refs[0].function, 0xC)
        self.assertEqual(len(refs[0].context), 4)
        self.assertIn("literal pool", refs[0].context[2])


class TestFunctionStart(unittest.TestCase):
    def test_out_of_range_returns_none(self):
        from collections import deque

        self.assertIsNone(xref._function_start(deque(), 0))
        self.assertIsNone(xref._function_start(deque(["ret"]), 1))


if __name__ == "__main__":
    unittest.main()
