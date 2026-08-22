"""CLI output destination behaviour."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import os
import tempfile
import unittest

import _paths  # noqa: F401

import tbm


class TestOutputDestinations(unittest.TestCase):
    def test_missing_destination_writes_to_stdout(self):
        stream = io.StringIO()
        with redirect_stdout(stream):
            tbm._write_output("payload", None)
        self.assertEqual(stream.getvalue(), "payload\n")

    def test_file_destination_is_written_and_announced(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nested", "result.txt")
            stream = io.StringIO()
            with redirect_stdout(stream):
                tbm._write_output("payload", path)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "payload\n")
            self.assertIn(path, stream.getvalue())

    def test_scan_defaults_to_saving_artifacts_in_the_default_directory(self):
        args = tbm.build_parser().parse_args(["scan"])
        self.assertIsNone(args.output)
        self.assertFalse(args.detail)
        self.assertEqual(tbm.DEFAULT_OUTDIR, "./results")

    def test_out_alias_is_available_on_streaming_commands(self):
        parser = tbm.build_parser()
        cases = [
            ["scan"],
            ["protocol", "target"],
            ["clientgen", "protocol.json"],
            ["graph", "--node", "node"],
            ["probe"],
            ["hunt"],
            ["xref", "binary", "string"],
            ["entowners", "entitlement"],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                self.assertIsNone(parser.parse_args(argv).output)


if __name__ == "__main__":
    unittest.main()
