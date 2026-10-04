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
                          "linked_libs_count": 1, "objc_classes_count": 0,
                          "ipc_operations": [{
                              "request_key": "request",
                              "operation": "RepairPermissionsForCloudItems",
                              "handler": "repair_handler", "input_keys": ["Paths"],
                              "dispatcher": "dispatch", "relationship": "PROVEN",
                              "evidence": []}]},
            },
            "capability_findings": [{
                "finding_id": "cap-1", "primitive": "CHOWN_SINK_CANDIDATE",
                "candidate_capability": "CHOWN_SINK_CANDIDATE",
                "maturity": "CONTROLLED_SINK", "confidence": "MEDIUM",
                "research_priority_score": 60,
                "dataflow": ["xpc_dictionary_get_string@1000", "fchown@1010"],
                "attacker_control": "HIGH",
                "controlled_arguments": {"file_descriptor": "HIGH", "resource_path": "HIGH"},
                "expected_caller_identity": "UNKNOWN", "identity_verification": "WEAK",
                "authorization_decision": "AUTHORIZATION_NOT_OBSERVED",
                "reachability": ["LOCAL_USER"], "post_condition": "FILE_OWNER_CHANGED",
                "missing_proof": [], "sink": {"api": "fchown", "operation": "change ownership"},
                "authorization": {"scope": "AUTHORIZATION_NOT_OBSERVED",
                                  "strength": "NONE_OBSERVED", "guard_evidence": {},
                                  "unknown_reason": "UNKNOWN_CONTROL_FLOW"},
                "caller_profiles": [{
                    "profile": "SANDBOXED", "entry_reachability": "CONDITIONAL",
                    "mach_lookup": "UNKNOWN",
                    "authorization": "AUTHORIZATION_PROFILE_ALLOWLIST"}],
                "policy_paths": [{
                    "predicate": "sandbox_check_by_audit_token",
                    "allowed_operation": "fchown", "success_semantics": "UNKNOWN",
                    "relationship": "PREDICATE_OBSERVED"}],
                "descriptor_provenance": {"0": [{"api": "open", "address": "1004"}]},
            }],
            "lpe_findings": [{
                "finding_id": "lpe-1",
                "lpe_classes": ["FS_USER_PATH_TO_ROOT_SINK"],
                "operation": "chown", "sink": {"api": "fchown", "address": "1010"},
                "severity": "HIGH", "confidence": "CONFIRMED_FLOW", "score": 80,
                "input_origin": "xpc", "input_name": "path",
                "caller_validation": "NONE_OBSERVED",
                "caller_validation_scope": "OPERATION_GUARD_NOT_OBSERVED",
                "operation_authorization": "NONE_OBSERVED",
                "operation_authorization_scope": "AUTHORIZATION_NOT_OBSERVED",
                "resource_validation": "DESCRIPTOR_BASED_REFERENCE",
                "resource_authorization": "UNKNOWN",
                "resource_scope": "DESCRIPTOR_BINDING",
                "resource_scope_confidence": "UNKNOWN",
                "descriptor_provenance": {"0": [{"api": "open", "address": "1004"}]},
                "target": "unresolved", "target_category": "unresolved",
                "toctou_candidate": False,
                "missing_evidence": ["caller authority not proven"],
                "research_questions": [
                    "resource authorization unresolved: is the target constrained to an allowed root?"],
            }],
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
        row = dict(zip(headers, rows[0], strict=False))
        self.assertEqual(row["match"], "unmount")
        self.assertEqual(row["aspect"], "mount")
        self.assertEqual(row["weight"], 8)

    def test_validation_table_lists_observed_and_missing_classes(self):
        headers, rows = self.tables["caller_validation"]
        states = {dict(zip(headers, r, strict=False))["state"] for r in rows}
        self.assertEqual(states, {"observed", "not_observed"})

    def test_mach_service_rows_name_their_provider(self):
        headers, rows = self.tables["mach_services"]
        row = dict(zip(headers, rows[0], strict=False))
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

    def test_markdown_dossier_surfaces_xpc_profiles_and_resource_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            export_report(_report(), tmp, formats=["md"])
            path = os.path.join(tmp, "services", "com.example.demo.md")
            text = open(path, encoding="utf-8").read()
        self.assertIn("RepairPermissionsForCloudItems", text)
        self.assertIn("SANDBOXED", text)
        self.assertIn("AUTHORIZATION_PROFILE_ALLOWLIST", text)
        self.assertIn("sandbox_check_by_audit_token", text)
        self.assertIn("DESCRIPTOR_BINDING", text)
        self.assertIn("resource authorization unresolved", text)

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


class TestCoreGraphForTheExplorer(unittest.TestCase):
    """The page embeds an index-encoded core graph, not the whole thing."""

    def _graph(self):
        return {
            "nodes": [
                {"id": "service:d", "type": "LaunchService", "label": "d",
                 "data": {"privileged": True, "enabled": True, "score": 90, "validation": "WEAK"}},
                {"id": "exec:/d", "type": "Executable", "label": "/d", "data": {"privileged": True}},
                {"id": "mach:m", "type": "MachService", "label": "m", "data": {}},
                {"id": "ent:e", "type": "Entitlement", "label": "e", "data": {}},
                {"id": "fw:F", "type": "Framework", "label": "F", "data": {}},
            ],
            "edges": [
                {"source": "exec:/d", "target": "service:d", "type": "LAUNCHED_BY", "data": {}},
                {"source": "service:d", "target": "mach:m", "type": "PROVIDES", "data": {}},
                {"source": "exec:/d", "target": "ent:e", "type": "HAS_ENTITLEMENT", "data": {}},
                {"source": "exec:/d", "target": "fw:F", "type": "LINKS_TO", "data": {}},
            ],
        }

    def test_entitlement_and_framework_nodes_are_left_out(self):
        from reporting.html_report import _graph_core
        core = _graph_core(self._graph())
        labels = {n[1] for n in core["nodes"]}
        self.assertEqual(labels, {"d", "/d", "m"})
        self.assertEqual(len(core["edges"]), 2)

    def test_edges_reference_nodes_by_index(self):
        from reporting.html_report import _graph_core
        core = _graph_core(self._graph())
        for src, dst, etype, _evidence in core["edges"]:
            self.assertLess(src, len(core["nodes"]))
            self.assertLess(dst, len(core["nodes"]))
            self.assertLess(etype, len(core["edge_types"]))

    def test_service_rows_carry_what_the_explorer_shows(self):
        from reporting.html_report import _graph_core
        core = _graph_core(self._graph())
        row = next(n for n in core["nodes"] if n[1] == "d")
        self.assertEqual(core["node_types"][row[0]], "LaunchService")
        self.assertEqual(row[2], 90)          # score
        self.assertEqual(row[3], 1)           # privileged
        self.assertEqual(row[4], 1)           # enabled
        self.assertEqual(core["validation"][row[5]], "WEAK")

    def test_lookup_evidence_survives_the_encoding(self):
        from reporting.html_report import _graph_core
        data = self._graph()
        data["nodes"].append({"id": "exec:/c", "type": "Executable", "label": "/c",
                              "data": {"privileged": False}})
        data["edges"].append({"source": "exec:/c", "target": "mach:m", "type": "LOOKS_UP",
                              "data": {"evidence": "entitlement"}})
        core = _graph_core(data)
        lookup = next(e for e in core["edges"] if core["edge_types"][e[2]] == "LOOKS_UP")
        self.assertEqual(lookup[3], 1)        # 1 == entitlement, 2 == string
