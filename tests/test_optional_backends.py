"""Optional deep/runtime backend isolation and evidence-merge regressions."""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import _paths  # noqa: F401

import tbm
from backends.base import BackendEvidence, BackendStats, FindingUpdate
from backends.merge import merge_finding_update
from backends.orchestrator import run_optional_backends
from backends.radare2 import Radare2AnalysisTimeout, Radare2Backend, run_radare2
from models.capability import (
    CapabilityFinding,
    DataSource,
    ExploitabilityEvidenceScore,
    SecurityControl,
)


def _finding():
    return CapabilityFinding(
        finding_id="cap-test", entry_point="mach", transport="XPC",
        sources=[DataSource("xpc_dictionary_get_string", "string")],
        caller_identity="local", expected_caller_identity="UNKNOWN",
        identity=SecurityControl(), authorization=SecurityControl(),
        sink_category="filesystem", sink_api="open", sink_operation="access file",
        candidate_capability="FILE_ACCESS_SINK_CANDIDATE",
        maturity_level="REACHABLE_SINK", proven_primitive=None,
        attacker_control="UNKNOWN", controlled_arguments={"path": "UNKNOWN"},
        reachability=["LOCAL_USER"], post_condition="FILE_HANDLE_OBTAINED",
        post_condition_confidence="LOW", potential_impact="candidate",
        confidence="LOW", evidence=[], missing_evidence=[], next_research_steps=[],
        unknown_reasons=["UNKNOWN_WRAPPER"],
        exploitability_score=ExploitabilityEvidenceScore(maturity_level="REACHABLE_SINK"),
        research_priority_score=80,
    )


class _Service:
    mach_services = ["com.example.safe"]


class _Executable:
    path = "/tmp/example"


class _Target:
    def __init__(self):
        self.service = _Service()
        self.executable = _Executable()
        self.capability_findings = [_finding()]
        self.optional_analysis = {}


class _Observation:
    def __init__(self, status="CONNECTION_ESTABLISHED", connection="CONFIRMED"):
        self.value = {
            "mach_service": "com.example.safe", "status": status,
            "connection": connection, "request": "NOT_TESTED",
            "operation_reachability": "NOT_PROVEN",
            "authorization_bypass": "NOT_PROVEN", "reply": "NOT_TESTED",
            "error": "", "evidence_source": "RUNTIME_XPC", "events": [],
        }

    def to_dict(self):
        return dict(self.value)


class _Runtime:
    def __init__(self, observation=None):
        self.observation = observation or _Observation()
        self.calls = []

    def probe(self, name, timeout=1.0, send_empty=False):
        self.calls.append((name, timeout, send_empty))
        return self.observation


class TestOptionalIsolation(unittest.TestCase):
    def test_normal_cli_defaults_disable_both_backends(self):
        args = tbm.build_parser().parse_args(["scan", "com.example"])
        self.assertIsNone(args.deep_analysis)
        self.assertFalse(args.runtime_probe)
        self.assertEqual(args.deep_workers, 3)
        self.assertEqual(args.deep_binary_timeout, 300.0)

    def test_normal_orchestrator_runs_no_optional_backend(self):
        with patch("backends.orchestrator.run_radare2") as deep:
            exploding = _Runtime()
            result = run_optional_backends([_Target()], runtime_backend=exploding)
        deep.assert_not_called()
        self.assertEqual(exploding.calls, [])
        self.assertEqual(result["analysis_sources"], {
            "NATIVE": True, "RADARE2": False, "RUNTIME_XPC": False})

    def test_radare2_runs_only_when_requested(self):
        with patch("backends.orchestrator.run_radare2") as deep:
            deep.return_value = BackendStats("RADARE2", requested=True, available=False)
            run_optional_backends([_Target()], deep_analysis="radare2")
        deep.assert_called_once()

    def test_runtime_runs_only_when_requested(self):
        backend = _Runtime()
        run_optional_backends([_Target()], runtime_probe=True, runtime_backend=backend)
        self.assertEqual(len(backend.calls), 1)
        self.assertFalse(backend.calls[0][2])

    def test_unavailable_reason_distinguishes_binary_from_binding(self):
        with patch("backends.radare2.which", return_value=None), \
                patch("importlib.util.find_spec", return_value=None):
            self.assertIn("both missing", Radare2Backend.unavailable_reason())
        with patch("backends.radare2.which", return_value="/opt/homebrew/bin/r2"), \
                patch("importlib.util.find_spec", return_value=None):
            self.assertIn("r2pipe", Radare2Backend.unavailable_reason())
        with patch("backends.radare2.which", return_value=None), \
                patch("importlib.util.find_spec", return_value=object()):
            self.assertIn("radare2 binary is missing",
                          Radare2Backend.unavailable_reason())

    def test_missing_radare2_fails_gracefully(self):
        with patch("backends.radare2.Radare2Backend.available", return_value=False):
            result = run_optional_backends([_Target()], deep_analysis="radare2")
        self.assertFalse(result["radare2"]["available"])
        self.assertTrue(result["radare2"]["errors"])


class TestEvidenceMerge(unittest.TestCase):
    def test_radare2_evidence_merges_and_promotes_only_with_proof(self):
        finding = _finding()
        update = FindingUpdate(
            finding_id=finding.finding_id, call_path_confirmed=True,
            controlled_arguments={"path": "HIGH"},
            resolved_unknown_reasons=["UNKNOWN_WRAPPER"],
            evidence=[BackendEvidence("RADARE2", "x0 traced", "PROVEN")],
        )
        merge_finding_update(finding, update, "RADARE2")
        self.assertEqual(finding.maturity_level, "CONTROLLED_SINK")
        self.assertEqual(finding.attacker_control, "HIGH")
        self.assertEqual(finding.analysis_sources, ["NATIVE", "RADARE2"])

    def test_evidence_without_call_path_does_not_promote(self):
        finding = _finding()
        merge_finding_update(finding, FindingUpdate(
            finding.finding_id,
            evidence=[BackendEvidence("RADARE2", "xref candidate")]), "RADARE2")
        self.assertEqual(finding.maturity_level, "REACHABLE_SINK")

    def test_connection_success_never_proves_authorization_bypass(self):
        target, backend = _Target(), _Runtime()
        run_optional_backends([target], runtime_probe=True, runtime_backend=backend)
        dynamic = target.capability_findings[0].dynamic_reachability
        self.assertEqual(dynamic["mach_reachability"], "CONFIRMED")
        self.assertEqual(dynamic["authorization_bypass"], "NOT_PROVEN")
        self.assertIsNone(target.capability_findings[0].proven_primitive)

    def test_dynamic_rejection_preserves_static_finding(self):
        target = _Target()
        before = target.capability_findings[0].maturity_level
        backend = _Runtime(_Observation("CONNECTION_REJECTED", "REJECTED"))
        run_optional_backends([target], runtime_probe=True, runtime_backend=backend)
        self.assertEqual(target.capability_findings[0].maturity_level, before)
        self.assertTrue(target.capability_findings[0].optional_evidence)

    def test_empty_request_requires_explicit_flag(self):
        backend = _Runtime()
        run_optional_backends([_Target()], runtime_probe=True,
                              probe_send_empty=True, runtime_backend=backend)
        self.assertTrue(backend.calls[0][2])


class _FakeR2:
    def cmd(self, _command):
        return ""

    def cmdj(self, command):
        if command == "iSj":
            return [{"name": "0.__TEXT.__text", "perm": "-r-x",
                     "vaddr": 0x1000, "vsize": 0x1000}]
        if command == "aflj":
            return [{"name": "handler", "addr": 0x1000, "size": 0x100}]
        if command == "axtj @ 4096":
            return [{"from": 0x1100, "type": "CALL"}]
        if "xpc_dictionary_get_string" in command:
            return [{"from": 0x1001, "fcn_name": "handler", "type": "CALL"}]
        return ([{"from": 0x1010, "fcn_name": "handler", "type": "CALL"}]
                if command.startswith("axtj") else [])

    def quit(self):
        return None


class TestDeepCache(unittest.TestCase):
    def test_aaa_has_per_binary_timeout(self):
        with tempfile.NamedTemporaryFile() as fh:
            backend = Radare2Backend(analysis_timeout=1)
            with patch.object(backend, "available", return_value=True), \
                    patch.object(backend, "_open", return_value=_FakeR2()), \
                    patch("backends.radare2.time.monotonic", side_effect=[0.0, 2.0]):
                with self.assertRaises(Radare2AnalysisTimeout):
                    backend.analyze(fh.name, _finding())

    def test_repeated_deep_analysis_uses_cache(self):
        with tempfile.NamedTemporaryFile() as fh:
            backend = Radare2Backend()
            with patch.object(backend, "available", return_value=True), \
                    patch.object(backend, "_open", return_value=_FakeR2()) as opened:
                first, cached_first = backend.analyze(fh.name, _finding())
                second, cached_second = backend.analyze(fh.name, _finding())
        self.assertTrue(first.call_path_confirmed)
        self.assertFalse(cached_first)
        self.assertTrue(cached_second)
        self.assertIs(first, second)
        opened.assert_called_once()

    def test_header_xref_outside_text_is_ignored(self):
        class HeaderR2(_FakeR2):
            def cmdj(self, command):
                if command == "iSj":
                    return [{"name": "0.__TEXT.__text", "perm": "-r-x",
                             "vaddr": 0x100001100, "vsize": 0x1000}]
                if command.startswith("axtj"):
                    return [{"from": 0x100000b54,
                             "fcn_name": "unknown_arm64_100000ad0"}]
                return super().cmdj(command)

        with tempfile.NamedTemporaryFile() as fh:
            backend = Radare2Backend()
            with patch.object(backend, "available", return_value=True), \
                    patch.object(backend, "_open", return_value=HeaderR2()):
                update, _ = backend.analyze(fh.name, _finding())
        self.assertFalse(update.call_path_confirmed)
        self.assertEqual(update.evidence, [])

    def test_dead_and_live_callsites_are_not_conflated(self):
        class MixedR2(_FakeR2):
            def cmd(self, command):
                if command == "axtj @@f":
                    # one JSON array per function: xrefs *to* that function.
                    # source -> live edge is recovered from the live line.
                    return ('[]\n'
                            '[{"from": 4116, "type": "CALL", '
                            '"fcn_name": "source", "refname": "live"}]\n'
                            '[]\n')
                return ""

            def cmdj(self, command):
                if command == "iSj":
                    return [{"name": "0.__TEXT.__text", "perm": "-r-x",
                             "vaddr": 0x1000, "vsize": 0x4000}]
                if command == "aflj":
                    return [
                        {"name": "source", "addr": 0x1000, "size": 0x100},
                        {"name": "dead", "addr": 0x2000, "size": 0x100},
                        {"name": "live", "addr": 0x3000, "size": 0x100},
                    ]
                if command.startswith("axtj @ sym.imp.open"):
                    return [{"from": 0x2010, "fcn_name": "dead", "type": "CALL"},
                            {"from": 0x3010, "fcn_name": "live", "type": "CALL"}]
                if command.startswith("axtj @ sym.imp.xpc_dictionary_get_string"):
                    return [{"from": 0x1010, "fcn_name": "source", "type": "CALL"}]
                if command == "axtj @ 8192":
                    return []
                if command == "axtj @ 12288":
                    return [{"from": 0x1014, "type": "CALL"}]
                return []

        with tempfile.NamedTemporaryFile() as fh:
            backend = Radare2Backend()
            with patch.object(backend, "available", return_value=True), \
                    patch.object(backend, "_open", return_value=MixedR2()):
                update, _ = backend.analyze(fh.name, _finding())
        self.assertTrue(update.call_path_confirmed)
        by_function = {e.function: e for e in update.evidence}
        self.assertEqual(by_function["dead"].relationship, "UNRESOLVED")
        self.assertFalse(by_function["dead"].detail["callsite_reachable"])
        self.assertEqual(by_function["dead"].detail["callsite_maturity"],
                         "SINK_CANDIDATE")
        self.assertEqual(by_function["live"].relationship, "PROVEN")
        self.assertTrue(by_function["live"].detail["callsite_reachable"])
        self.assertEqual(by_function["live"].detail["callsite_maturity"],
                         "REACHABLE_SINK")

    def test_progress_reports_current_path_remaining_and_completion(self):
        target = _Target()
        events = []
        with tempfile.NamedTemporaryFile() as fh:
            target.executable.path = fh.name
            with patch.object(Radare2Backend, "available", return_value=True), \
                    patch.object(Radare2Backend, "_open", return_value=_FakeR2()):
                run_radare2([target], min_score=0, progress=events.append)
        self.assertTrue(events)
        self.assertEqual(events[0]["path"], target.executable.path)
        self.assertEqual(events[-1]["stage"], "complete")
        self.assertEqual(events[-1]["findings_remaining"], 0)
        self.assertEqual(events[-1]["binaries_remaining"], 0)

    def test_session_is_closed_after_each_binary(self):
        targets = [_Target(), _Target()]
        handles = []
        with tempfile.NamedTemporaryFile() as first, tempfile.NamedTemporaryFile() as second:
            targets[0].executable.path = first.name
            targets[1].executable.path = second.name
            def opened(_path, flags=None):
                handle = _FakeR2()
                handle.closed = False
                original_quit = handle.quit
                def quit_session():
                    handle.closed = True
                    return original_quit()
                handle.quit = quit_session
                handles.append(handle)
                return handle
            with patch.object(Radare2Backend, "available", return_value=True), \
                    patch.object(Radare2Backend, "_open", side_effect=opened):
                run_radare2(targets, min_score=0)
        self.assertEqual(len(handles), 2)
        self.assertTrue(all(handle.closed for handle in handles))

    def test_multiple_binaries_run_in_parallel(self):
        targets = [_Target(), _Target()]
        lock = threading.Lock()
        active = 0
        maximum = 0

        class SlowR2(_FakeR2):
            def cmd(self, command):
                nonlocal active, maximum
                if command == "aaa":
                    with lock:
                        active += 1
                        maximum = max(maximum, active)
                    time.sleep(0.05)
                    with lock:
                        active -= 1
                return ""

        with tempfile.NamedTemporaryFile() as first, tempfile.NamedTemporaryFile() as second:
            targets[0].executable.path = first.name
            targets[1].executable.path = second.name
            with patch.object(Radare2Backend, "available", return_value=True), \
                    patch.object(Radare2Backend, "_open", side_effect=lambda _path: SlowR2()):
                run_radare2(targets, min_score=0, workers=2)
        self.assertEqual(maximum, 2)


if __name__ == "__main__":
    unittest.main()
