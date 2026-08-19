"""Tests for the per-entity CSV / Markdown export."""

from __future__ import annotations

import csv
import os
import tempfile
import unittest

import _paths  # noqa: F401

from reporting.export import build_tables, export_report


def _report():
    return {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "tool": "macOS-TBM",
        "summary": {"total_services": 1},
        "targets": [{
            "label": "com.example.demo",
            "score": 42,
            "priority": "MEDIUM",
            "ipc_classification": "mach-service-provider",
            "validation": "WEAK",
            "sensitive_sinks": ["FILESYSTEM"],
            "reasons": [{"weight": 20, "reason": "runs as root"}],
            "findings": [{"category": "ipc", "level": "FACT", "message": "registers x", "evidence": "plist"}],
            "entitlement_findings": ["com.apple.private.demo"],
            "why_interesting": ["privileged"],
            "research_questions": ["how is the caller checked?"],
            "service": {
                "label": "com.example.demo",
                "plist_path": "/Library/LaunchDaemons/com.example.demo.plist",
                "service_type": "daemon", "scope": "local-daemon",
                "run_as": "root", "run_as_user": "root", "run_as_derivation": "no UserName",
                "enabled": True, "enabled_derivation": "no Disabled key",
                "mach_services": ["com.example.demo.xpc"],
                "associated_executable": "/usr/local/bin/demo",
                "run_at_load": True,
            },
            "executable": {
                "path": "/usr/local/bin/demo",
                "codesign": {"is_signed": True, "signer_identifier": "demo",
                             "platform_binary": False,
                             "entitlements": {"com.apple.private.demo": True}},
                "macho": {"architectures": ["arm64e"], "linked_libs": ["/usr/lib/libSystem.B.dylib"],
                          "weak_linked_libs": [], "imported_symbols_count": 3,
                          "linked_libs_count": 1, "objc_classes_count": 0},
            },
            "sink_assessments": [{
                "sink": "filesystem", "label": "FILESYSTEM", "score": 10,
                "confidence": "HIGH", "aspects": ["mount"],
                "evidence": [{"kind": "import", "needle": "unmount", "match": "unmount",
                              "aspect": "mount", "weight": 8}],
                "evidence_text": ["import: unmount [mount]"],
            }],
            "validation_assessment": {
                "confidence": "WEAK", "score": 4, "classes": ["sandbox-check"],
                "evidence": [{"kind": "import", "needle": "sandbox_check", "match": "sandbox_check",
                              "aspect": "sandbox-check", "weight": 4}],
                "evidence_text": ["import: sandbox_check [sandbox-check]"],
                "not_observed": [{"class": "sectask-entitlement", "weight": 8,
                                  "description": "builds a SecTask", "looked_for": "SecTaskCopyValueForEntitlement"}],
            },
        }],
        "graph": {"nodes": [{"id": "service:demo", "type": "LaunchService", "label": "demo",
                             "data": {"privileged": True}}],
                  "edges": [{"source": "exec:demo", "target": "service:demo",
                             "type": "LAUNCHED_BY", "label": "launched by"}]},
    }


class TestTables(unittest.TestCase):
    def setUp(self):
        self.tables = {name: (headers, rows) for name, headers, rows in build_tables(_report())}

    def test_every_entity_gets_a_table(self):
        for name in ["services", "executables", "mach_services", "entitlements",
                     "entitlement_summary", "frameworks", "sinks", "sink_evidence",
                     "caller_validation", "findings", "score_reasons",
                     "graph_nodes", "graph_edges"]:
            self.assertIn(name, self.tables)

    def test_rows_match_their_headers(self):
        for name, (headers, rows) in self.tables.items():
            for row in rows:
                self.assertEqual(len(row), len(headers), f"{name} row width")

    def test_evidence_table_carries_the_matched_symbol(self):
        headers, rows = self.tables["sink_evidence"]
        row = dict(zip(headers, rows[0]))
        self.assertEqual(row["match"], "unmount")
        self.assertEqual(row["aspect"], "mount")
        self.assertEqual(row["weight"], 8)

    def test_validation_table_lists_observed_and_missing_classes(self):
        headers, rows = self.tables["caller_validation"]
        states = {dict(zip(headers, r))["state"] for r in rows}
        self.assertEqual(states, {"observed", "not_observed"})

    def test_mach_service_rows_name_their_provider(self):
        headers, rows = self.tables["mach_services"]
        row = dict(zip(headers, rows[0]))
        self.assertEqual(row["mach_service"], "com.example.demo.xpc")
        self.assertEqual(row["provided_by"], "com.example.demo")


class TestWrittenFiles(unittest.TestCase):
    def test_csv_is_parseable_and_has_a_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            export_report(_report(), tmp, formats=["csv"], dossiers=False)
            with open(os.path.join(tmp, "services.csv"), encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(rows[0]["label"], "com.example.demo")
            self.assertEqual(rows[0]["state"], "enabled")

    def test_markdown_dossier_per_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            export_report(_report(), tmp, formats=["md"])
            path = os.path.join(tmp, "services", "com.example.demo.md")
            self.assertTrue(os.path.exists(path))
            text = open(path, encoding="utf-8").read()
            self.assertIn("# com.example.demo", text)
            self.assertIn("FILESYSTEM", text)
            self.assertIn("sandbox_check", text)      # observed validation class
            self.assertIn("sectask-entitlement", text)  # class looked for and not found
            self.assertIn("- [ ] how is the caller checked?", text)

    def test_index_links_every_service_and_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            export_report(_report(), tmp, formats=["md"])
            text = open(os.path.join(tmp, "index.md"), encoding="utf-8").read()
            self.assertIn("services/com.example.demo.md", text)
            self.assertIn("sink_evidence.md", text)

    def test_pipes_in_values_do_not_break_markdown_tables(self):
        report = _report()
        report["targets"][0]["label"] = "com.example|pipe"
        with tempfile.TemporaryDirectory() as tmp:
            export_report(report, tmp, formats=["md"], dossiers=False)
            text = open(os.path.join(tmp, "services.md"), encoding="utf-8").read()
            self.assertIn("com.example\\|pipe", text)


if __name__ == "__main__":
    unittest.main()
