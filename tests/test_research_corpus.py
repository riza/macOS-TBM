"""Portable, authored r2-response corpus; no binary analysis or runtime probes."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import _paths  # noqa: F401
from test_optional_backends import _FakeR2, _finding, _Target

from backends.base import BackendEvidence, FindingUpdate
from backends.merge import merge_finding_update
from backends.radare2 import Radare2Backend, run_radare2

CORPUS = Path(__file__).parent / "fixtures" / "research" / "r2_callsites.json"


class CorpusSession:
    def __init__(self, case):
        self.case = case

    def cmd(self, command):
        c = self.case
        if command == "axtj @@f":
            return json.dumps([{"type": c["edge_type"], "from": c["edge_address"],
                                "fcn_name": c["source_function"],
                                "refname": c["sink_function"]}])
        return ""

    def cmdj(self, command):
        c = self.case
        if command == "iSj":
            return [{"name": "__text", "perm": "r-x", "vaddr": 4096, "vsize": 8192}]
        if command == "aflj":
            return [{"name": c["sink_function"], "addr": 8192}]
        if command == "axtj @ 8192":
            return [{"from": c["incoming_address"], "type": c["incoming_type"]}]
        if command == "axtj @ sym.imp.open":
            return [{"from": c["sink_address"], "fcn_name": c["sink_function"],
                     "type": c["sink_type"]}]
        if command == "axtj @ sym.imp.xpc_dictionary_get_string":
            return [{"from": c["source_address"], "fcn_name": c["source_function"],
                     "type": c["source_type"]}]
        # A containing function must never substitute for the missing sink xref.
        if command.startswith("afij"):
            return [{"name": c["sink_function"]}]
        return []

    def quit(self):
        pass


def evaluate():
    results = []
    for case in json.loads(CORPUS.read_text()):
        finding = _finding()
        finding.maturity_level = "SINK_CANDIDATE"
        finding.handler_function = case["handler"]
        finding.sink_address = case["finding_address"]
        authorization_scope = finding.authorization.scope
        finding.unknown_reasons = ["UNKNOWN_NO_CALL_PATH", "UNKNOWN_WRAPPER",
                                   "UNKNOWN_RETURN_VALUE"]
        with tempfile.NamedTemporaryFile() as binary:
            backend = Radare2Backend()
            with patch.object(backend, "available", return_value=True), \
                    patch.object(backend, "_open", return_value=CorpusSession(case)):
                try:
                    update, _ = backend.analyze(binary.name, finding)
                finally:
                    backend.close()
        merge_finding_update(finding, update, "RADARE2")
        expected_maturity = "REACHABLE_SINK" if case["expected"] else "SINK_CANDIDATE"
        passed = (update.call_path_confirmed == case["expected"]
                  and finding.maturity_level == expected_maturity
                  and finding.confidence == "LOW"
                  and "UNKNOWN_RETURN_VALUE" in finding.unknown_reasons
                  and "UNKNOWN_WRAPPER" in finding.unknown_reasons
                  and finding.proven_primitive is None
                  and finding.authorization.scope == authorization_scope)
        results.append({"name": case["name"], "expected": case["expected"],
                        "observed": update.call_path_confirmed, "passed": passed})
    return results


class TestResearchCorpus(unittest.TestCase):
    def test_authored_callsite_corpus(self):
        for row in evaluate():
            with self.subTest(case=row["name"]):
                self.assertTrue(row["passed"], row)

    def test_unresolved_evidence_preserves_confidence_and_unknowns(self):
        finding = _finding()
        finding.confidence = "SPECULATIVE"
        before = list(finding.unknown_reasons)
        merge_finding_update(finding, FindingUpdate(
            finding.finding_id, evidence=[BackendEvidence("RADARE2", "unresolved", "UNRESOLVED")]),
            "RADARE2")
        self.assertEqual(finding.confidence, "SPECULATIVE")
        self.assertEqual(finding.unknown_reasons, before)

    def test_conflicting_argument_evidence_does_not_raise_confidence(self):
        finding = _finding()
        finding.controlled_arguments["path"] = "CONSTANT"
        merge_finding_update(finding, FindingUpdate(
            finding.finding_id, call_path_confirmed=True,
            controlled_arguments={"path": "HIGH"}), "RADARE2")
        self.assertEqual(finding.controlled_arguments["path"], "CONSTANT")
        self.assertEqual(finding.confidence, "LOW")
        self.assertTrue(finding.evidence_conflicts)
        self.assertNotEqual(finding.maturity_level, "CONTROLLED_SINK")


class TestUpdateIsolation(unittest.TestCase):
    def test_wrong_finding_update_is_rejected(self):
        finding = _finding()
        with self.assertRaises(ValueError):
            merge_finding_update(finding, FindingUpdate("different", call_path_confirmed=True), "RADARE2")
        self.assertEqual(finding.analysis_sources, ["NATIVE"])

    def test_call_path_preserves_unknown_argument_control(self):
        finding = _finding()
        merge_finding_update(finding, FindingUpdate(finding.finding_id, call_path_confirmed=True), "RADARE2")
        self.assertEqual(finding.attacker_control, "UNKNOWN")

    def test_changed_binary_discards_optional_updates(self):
        target = _Target()
        target.capability_findings[0].maturity_level = "SINK_CANDIDATE"
        with tempfile.NamedTemporaryFile() as binary:
            target.executable.path = binary.name
            with patch.object(Radare2Backend, "available", return_value=True), \
                    patch.object(Radare2Backend, "_open", return_value=_FakeR2()), \
                    patch("backends.radare2.binary_identity", side_effect=[
                        {"status": "HASHED", "sha256": "first"},
                        {"status": "HASHED", "sha256": "second"}]):
                stats = run_radare2([target], min_score=0)
        self.assertEqual(stats.analyzed, 0)
        self.assertTrue(stats.errors)
        self.assertEqual(target.capability_findings[0].maturity_level, "SINK_CANDIDATE")
        self.assertEqual(target.capability_findings[0].optional_evidence, [])
