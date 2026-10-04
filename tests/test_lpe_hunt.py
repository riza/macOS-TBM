"""Regression coverage for privileged-filesystem LPE hunting."""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import _paths  # noqa: F401

import tbm
from analyzers.capabilities import analyze_capabilities
from analyzers.lpe import analyze_lpe, refresh_lpe_findings
from analyzers.security_signals import detect_signals
from backends.base import BackendEvidence, FindingUpdate
from backends.merge import merge_finding_update
from collectors.dataflow import analyze_disassembly
from graph.model import build_graph
from hunt import format_lpe_text, score_target
from models.capability import VALIDATION_PRESENT_IN_BINARY
from models.common import RunAs, ServiceScope, ServiceType
from models.executable import CodeSigningInfo, Executable, MachOInfo
from models.finding import Target
from models.service import LaunchService
from reporting.export import build_tables
from reporting.html_report import write_html_report
from reporting.json_report import build_report, write_json_report
from ui import _dossier_lines


def _service(run_as=RunAs.ROOT):
    return LaunchService(
        label="com.example.lpe-helper",
        plist_path="/Library/LaunchDaemons/com.example.lpe-helper.plist",
        service_type=ServiceType.DAEMON,
        scope=ServiceScope.LOCAL_DAEMON,
        mach_services=["com.example.lpe-helper"],
        run_as=run_as,
        run_as_user="root" if run_as == RunAs.ROOT else "nobody",
        enabled=True,
    )


def _flow(api="rename", address="1100", controlled=(0, 1), literals=(),
          descriptor_provenance=None):
    return {
        "source_api": "xpc_dictionary_get_string",
        "source_address": "1000",
        "source_function": "handle_move",
        "source_binding": "INFERRED",
        "sink_api": api,
        "sink_address": address,
        "function": "handle_move",
        "entry_point_function": "handle_move",
        "call_path": ["handle_move"],
        "reachability_confirmed": True,
        "reachability_evidence": "ENTRY_HANDLER",
        "controlled_argument_indexes": list(controlled),
        "constant_argument_indexes": [],
        "descriptor_provenance": dict(descriptor_provenance or {}),
        "propagation": ["xpc_dictionary_get_string@1000", f"{api}@{address}"],
        "reply_dataflow": [],
        "validation_controls": [],
        "authorization_controls": [],
        "unknown_reasons": [],
        "confidence": "HIGH",
        "path_literals": list(literals),
    }


_DESCRIPTOR_PROVENANCE = {
    "0": [{
        "api": "open", "address": "1004", "path_argument": 0,
        "origins": ["SOURCE|xpc_dictionary_get_string|1000|handle_move|path"],
    }],
}


def _analyze(*, flows=(), imports=("xpc_dictionary_get_string", "rename"),
             strings=(), run_as=RunAs.ROOT):
    service = _service(run_as)
    macho = MachOInfo(
        path="/fixture/helper", is_macho=True,
        imported_symbols=list(imports), interesting_strings=list(strings),
        dataflow_facts=list(flows),
    )
    codesign = CodeSigningInfo(path=macho.path, is_signed=True)
    signals = detect_signals(service, macho, codesign)
    capabilities, edges = analyze_capabilities(service, macho, signals, codesign)
    findings = analyze_lpe(service, macho, capabilities)
    target = Target(
        service=service, executable=Executable(
            path=macho.path, macho=macho, codesign=codesign, analyzed=True),
        capability_findings=capabilities, primitive_edges=edges,
        lpe_findings=findings, validation=signals.validation,
        validation_assessment=signals.validation_assessment,
        checked_entitlements=signals.checked_entitlements,
    )
    return target


class TestLPEAnalysis(unittest.TestCase):
    def test_native_dataflow_records_check_then_mutation_for_toctou(self):
        disassembly = """
handle_move:
0000000100001200 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001204 mov x19, x0
0000000100001208 mov x0, x19
000000010000120c bl 0x100008100 ; symbol stub for: _lstat
0000000100001210 mov x0, x19
0000000100001214 mov x1, x19
0000000100001218 bl 0x100008200 ; symbol stub for: _rename
"""
        analysis = analyze_disassembly(
            disassembly,
            source_patterns=["xpc_dictionary_get_string"],
            sink_patterns=["lstat", "rename"],
            executable_ranges=[(0x100001100, 0x100002000)],
        )
        self.assertEqual([fact["sink_api"] for fact in analysis.facts],
                         ["lstat", "rename"])
        self.assertEqual(analysis.facts[0]["source_address"],
                         analysis.facts[1]["source_address"])
        self.assertEqual(analysis.facts[1]["controlled_argument_indexes"], [0, 1])

    def test_native_dataflow_binds_path_literal_to_sink_argument(self):
        disassembly = """
handle_move:
0000000100001200 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001204 mov x19, x0
0000000100001208 adr x20, 0x100009000 ; literal pool for: "/private/tmp/job"
000000010000120c mov x0, x19
0000000100001210 mov x1, x20
0000000100001214 bl 0x100008200 ; symbol stub for: _rename
"""
        analysis = analyze_disassembly(
            disassembly,
            source_patterns=["xpc_dictionary_get_string"],
            sink_patterns=["rename"],
            executable_ranges=[(0x100001100, 0x100002000)],
        )
        self.assertEqual(analysis.facts[0]["path_literals"], ["/private/tmp/job"])

    def test_native_dataflow_binds_privileged_executable_literal(self):
        disassembly = """
handle_copy:
0000000100001200 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001204 mov x19, x0
0000000100001208 adr x20, 0x100009000 ; literal pool for: "/usr/local/bin/tool"
000000010000120c mov x0, x19
0000000100001210 mov x1, x20
0000000100001214 bl 0x100008200 ; symbol stub for: _copyfile
"""
        analysis = analyze_disassembly(
            disassembly,
            source_patterns=["xpc_dictionary_get_string"],
            sink_patterns=["copyfile"],
            executable_ranges=[(0x100001100, 0x100002000)],
        )
        self.assertEqual(analysis.facts[0]["path_literals"], ["/usr/local/bin/tool"])

    def test_confirmed_ipc_path_to_root_rename(self):
        target = _analyze(flows=[_flow()])
        self.assertEqual(len(target.lpe_findings), 1)
        finding = target.lpe_findings[0]
        self.assertIn("FS_USER_PATH_TO_ROOT_SINK", finding.lpe_classes)
        self.assertIn("FS_PRIVILEGED_RENAME", finding.lpe_classes)
        self.assertEqual(finding.confidence, "CONFIRMED_FLOW")
        self.assertTrue(finding.user_controlled)
        self.assertEqual(finding.caller_validation, "NONE_OBSERVED")
        self.assertEqual(finding.resource_validation, "NONE_OBSERVED")
        self.assertFalse(finding.to_dict()["exploitability_confirmed"])

    def test_import_only_filesystem_api_is_not_an_lpe_finding(self):
        target = _analyze(flows=[])
        self.assertEqual(target.lpe_findings, [])

    def test_non_privileged_service_is_not_an_lpe_finding(self):
        target = _analyze(flows=[_flow()], run_as=RunAs.SPECIFIC_USER)
        self.assertEqual(target.lpe_findings, [])

    def test_toctou_and_unsafe_temp_require_correlated_flow(self):
        check = _flow("lstat", "1050", controlled=(0,), literals=("/private/tmp/job",))
        mutation = _flow("rename", "1100", literals=("/private/tmp/job",))
        target = _analyze(
            flows=[check, mutation],
            imports=("xpc_dictionary_get_string", "lstat", "rename"),
        )
        finding = target.lpe_findings[0]
        self.assertTrue(finding.toctou_candidate)
        self.assertTrue(finding.unsafe_temporary_path)
        self.assertEqual(finding.resource_validation, "POTENTIAL_TOCTOU")
        self.assertIn("FS_TOCTOU", finding.lpe_classes)
        self.assertIn("FS_UNSAFE_TEMP", finding.lpe_classes)
        self.assertIn("FS_WRITABLE_PARENT", finding.lpe_classes)

    def test_sensitive_plist_target_is_flow_bound(self):
        target = _analyze(flows=[_flow(
            literals=("/Library/LaunchDaemons/com.example.payload.plist",))])
        finding = target.lpe_findings[0]
        self.assertTrue(finding.target_sensitive)
        self.assertEqual(finding.target_category, "launch_daemon_plist")
        self.assertIn("FS_PLIST_OVERWRITE", finding.lpe_classes)
        self.assertIn("sensitive_target", finding.score_signals)

    def test_sink_specific_and_executable_overwrite_detectors(self):
        cases = (
            ("chmod", (0,), "FS_PRIVILEGED_CHMOD", ()),
            ("chown", (0,), "FS_PRIVILEGED_CHOWN", ()),
            ("open", (0,), "FS_SYMLINK_FOLLOW", ()),
            ("copyfile", (0, 1), "FS_EXECUTABLE_OVERWRITE",
             ("/Library/PrivilegedHelperTools/com.example.helper",)),
        )
        for api, controlled, expected, literals in cases:
            with self.subTest(api=api):
                target = _analyze(
                    flows=[_flow(api, controlled=controlled, literals=literals)],
                    imports=("xpc_dictionary_get_string", api),
                )
                self.assertIn(expected, target.lpe_findings[0].lpe_classes)

    def test_binary_wide_path_string_is_context_only_not_sensitive_proof(self):
        target = _analyze(
            flows=[_flow()],
            strings=("/Library/LaunchDaemons/unbound.plist",),
        )
        finding = target.lpe_findings[0]
        self.assertFalse(finding.target_sensitive)
        self.assertNotIn("FS_PLIST_OVERWRITE", finding.lpe_classes)
        self.assertNotIn("sensitive_target", finding.score_signals)
        self.assertTrue(any("not bound" in evidence for evidence in finding.evidence))

    def test_binary_wide_caller_check_is_not_credited_as_operation_guard(self):
        target = _analyze(flows=[_flow()])
        capability = target.capability_findings[0]
        capability.identity.strength = "STRONG"
        capability.identity.scope = VALIDATION_PRESENT_IN_BINARY
        target.lpe_findings = analyze_lpe(
            target.service, target.executable.macho, target.capability_findings)
        finding = target.lpe_findings[0]
        self.assertEqual(finding.caller_validation, "PRESENT_NOT_BOUND")
        self.assertNotIn("caller_validation_none_observed", finding.score_signals)

    def test_radare2_confirmed_call_path_promotes_native_lpe_candidate(self):
        flow = _flow()
        flow["reachability_confirmed"] = False
        target = _analyze(flows=[flow])
        self.assertEqual(target.lpe_findings, [])
        capability = target.capability_findings[0]
        self.assertEqual(capability.maturity_level, "SINK_CANDIDATE")
        merge_finding_update(capability, FindingUpdate(
            finding_id=capability.finding_id,
            call_path_confirmed=True,
            evidence=[BackendEvidence(
                "RADARE2", "source reaches filesystem sink", "PROVEN")],
        ), "RADARE2")
        refresh_lpe_findings([target])
        self.assertEqual(len(target.lpe_findings), 1)
        self.assertIn("RADARE2", target.lpe_findings[0].analysis_sources)
        self.assertEqual(target.lpe_findings[0].confidence, "CONFIRMED_FLOW")


class TestLPEIntegration(unittest.TestCase):
    def test_json_summary_target_and_graph_include_lpe_layer(self):
        target = _analyze(flows=[_flow()])
        graph = build_graph([target])
        report = build_report([target], graph)
        self.assertEqual(report["schema_version"], "2.2")
        self.assertEqual(report["summary"]["lpe_findings"], 1)
        self.assertEqual(len(report["targets"][0]["lpe_findings"]), 1)
        node_types = {node["type"] for node in report["graph"]["nodes"]}
        edge_types = {edge["type"] for edge in report["graph"]["edges"]}
        self.assertIn("FilesystemResource", node_types)
        self.assertIn("PERFORMS_FILESYSTEM_OPERATION", edge_types)
        self.assertIn("SUPPLIES_IPC_INPUT", edge_types)

    def test_json_summary_counts_new_evidence_axes(self):
        target = _analyze(
            imports=("xpc_dictionary_get_string", "fchown"),
            flows=[_flow("fchown", controlled=(0,),
                         descriptor_provenance=_DESCRIPTOR_PROVENANCE)],
        )
        report = build_report([target])
        summary = report["summary"]
        self.assertIn("resource_scope", summary)
        self.assertIn("operation_authorization_scope", summary)
        self.assertIn("xpc_operations", summary)
        capability = report["targets"][0]["capability_findings"][0]
        self.assertIn("caller_profiles", capability)
        self.assertIn("descriptor_provenance", capability)
        self.assertIn("resource_scope", report["targets"][0]["lpe_findings"][0])

    def test_export_and_hunt_use_structured_lpe_findings(self):
        target = _analyze(flows=[_flow()])
        report = build_report([target], build_graph([target]))
        table_names = {name for name, _headers, _rows in build_tables(report)}
        self.assertIn("lpe_findings", table_names)
        scored = score_target(report["targets"][0])
        self.assertIsNotNone(scored)
        self.assertEqual(scored.lpe, target.lpe_findings[0].score)
        text = format_lpe_text([scored])
        self.assertIn("FS_USER_PATH_TO_ROOT_SINK", text)
        self.assertIn("PRIVILEGED FILESYSTEM LPE CANDIDATES", text)

    def test_html_and_text_dossiers_render_lpe_section(self):
        target = _analyze(flows=[_flow()])
        report = build_report([target], build_graph([target]))
        text = "\n".join(_dossier_lines(report["targets"][0]))
        self.assertIn("LPE hunting - privileged filesystem", text)
        self.assertIn("FS_USER_PATH_TO_ROOT_SINK", text)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.html")
            write_html_report(path, report)
            with open(path, encoding="utf-8") as handle:
                html = handle.read()
        self.assertIn("LPE hunting &mdash; privileged filesystem", html)
        self.assertIn("FS_USER_PATH_TO_ROOT_SINK", html)

    def test_hunt_class_lpe_cli_reads_report_without_new_scan(self):
        target = _analyze(flows=[_flow()])
        report = build_report([target], build_graph([target]))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            write_json_report(path, report)
            args = tbm.build_parser().parse_args([
                "hunt", "--report", path, "--class", "lpe", "--top", "5",
                "--confidence", "CONFIRMED_FLOW",
            ])
            output = io.StringIO()
            with redirect_stdout(output):
                status = args.func(args)
        self.assertEqual(status, 0)
        self.assertIn("FS_USER_PATH_TO_ROOT_SINK", output.getvalue())
        self.assertIn("com.example.lpe-helper", output.getvalue())


class TestResourceScope(unittest.TestCase):
    def test_lstat_alone_is_not_a_path_scope_guard(self):
        target = _analyze(
            imports=("xpc_dictionary_get_string", "lstat", "rename"),
            flows=[_flow("rename", controlled=(0, 1))],
        )
        finding = target.lpe_findings[0]
        self.assertNotEqual(finding.resource_scope, "PATH_SCOPE_GUARD")
        self.assertEqual(finding.resource_scope, "METADATA_CHECK")
        self.assertEqual(finding.resource_authorization, "UNKNOWN")

    def test_realpath_prefix_check_is_a_conditional_scope_guard(self):
        target = _analyze(
            imports=("xpc_dictionary_get_string", "realpath", "fchown"),
            flows=[_flow("fchown", controlled=(0,),
                         descriptor_provenance=_DESCRIPTOR_PROVENANCE)],
        )
        finding = target.lpe_findings[0]
        self.assertEqual(finding.resource_scope, "PATH_SCOPE_GUARD")
        self.assertEqual(finding.resource_scope_confidence, "CONDITIONAL")
        self.assertEqual(finding.resource_authorization, "UNKNOWN")

    def test_controlled_chown_without_scope_guard_raises_research_question(self):
        target = _analyze(
            imports=("xpc_dictionary_get_string", "fchown"),
            flows=[_flow("fchown", controlled=(0,),
                         descriptor_provenance=_DESCRIPTOR_PROVENANCE)],
        )
        finding = target.lpe_findings[0]
        self.assertEqual(finding.resource_authorization, "UNKNOWN")
        self.assertTrue(any("resource" in q.lower() and "authoriz" in q.lower()
                            for q in finding.research_questions))


if __name__ == "__main__":
    unittest.main()
