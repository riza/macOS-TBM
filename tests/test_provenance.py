"""Research provenance must identify content and expose unavailable evidence."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: F401

from models.executable import Executable, MachOInfo
from reporting.json_report import build_report
from scanner import _analyze_executable
from utils.commands import CommandResult, ResultCache
from utils.provenance import binary_identity, research_provenance


class TestProvenance(unittest.TestCase):
    def test_binary_digest_and_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture"
            path.write_bytes(b"fixture")
            first = binary_identity(str(path))
            self.assertEqual(first["sha256"], hashlib.sha256(b"fixture").hexdigest())
            path.write_bytes(b"changed")
            self.assertNotEqual(binary_identity(str(path))["sha256"], first["sha256"])
            path.unlink()
            self.assertEqual(binary_identity(str(path))["status"], "UNAVAILABLE")

    def test_rule_hashes_and_schema_are_serialized(self):
        provenance = research_provenance()
        self.assertIn("capabilities.json", provenance["rules_sha256"])
        self.assertEqual(len(provenance["rules_sha256"]["capabilities.json"]), 64)
        report = build_report([], meta={"scan_options": {"deep_analysis": None}})
        self.assertEqual(report["schema_version"], "2.2")
        self.assertIn("host", report["provenance"])
        self.assertIsNone(report["meta"]["scan_options"]["deep_analysis"])
        self.assertEqual(Executable("/missing").to_dict()["identity"], {})

    def test_analysis_marks_changed_binary(self):
        from collectors.dataflow import DataflowAnalysis
        with patch("scanner.binary_identity", side_effect=[
                {"status": "HASHED", "sha256": "first"},
                {"status": "HASHED", "sha256": "second"}]), \
                patch("scanner.inspect_macho", return_value=MachOInfo("/fixture")), \
                patch("scanner.inspect_dataflow", return_value=DataflowAnalysis()), \
                patch("scanner.inspect_codesign", return_value=None):
            executable = _analyze_executable("/fixture", ResultCache())
        self.assertEqual(executable.identity["status"], "UNVERIFIED_OR_CHANGED")


class TestVersionIsolation(unittest.TestCase):
    def test_default_provenance_does_not_invoke_radare2(self):
        with patch("utils.provenance.run") as runner:
            provenance = research_provenance()
        runner.assert_not_called()
        self.assertIsNone(provenance["radare2_version"])

    def test_requested_backend_records_bounded_version_query(self):
        with patch("utils.provenance.which", return_value="/fake/r2"), \
                patch("utils.provenance.run", return_value=CommandResult(stdout="radare2 fixture\n")) as runner:
            provenance = research_provenance(include_radare2=True)
        runner.assert_called_once_with(["/fake/r2", "-v"], timeout=2)
        self.assertEqual(provenance["radare2_version"], "radare2 fixture")
