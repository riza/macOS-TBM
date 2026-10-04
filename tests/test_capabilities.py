"""Regression tests for conservative operation-level capability analysis."""

from __future__ import annotations

import unittest

import _paths  # noqa: F401

import tbm
from analyzers.capabilities import analyze_capabilities
from analyzers.security_signals import detect_signals
from collectors.dataflow import (
    analyze_disassembly,
    parse_disassembly,
    parse_executable_text_ranges,
)
from models.capability import AUTHORIZATION_PER_MESSAGE
from models.common import RunAs, ServiceScope, ServiceType
from models.executable import CodeSigningInfo, MachOInfo
from models.service import LaunchService


def _service(*, enabled=True, mach=True):
    return LaunchService(
        label="com.example.capability",
        plist_path="/System/Library/LaunchDaemons/com.example.capability.plist",
        service_type=ServiceType.DAEMON,
        scope=ServiceScope.SYSTEM_DAEMON,
        mach_services=["com.example.capability"] if mach else [],
        run_as=RunAs.ROOT,
        run_as_user="root",
        enabled=enabled,
    )


def _flow(sink_api, *, controlled=None, constants=None, reply=None,
          validation=None, authorization=None, unknown=None):
    return {
        "source_api": "xpc_dictionary_get_string",
        "source_address": "1000",
        "source_function": "handle_request",
        "source_binding": "INFERRED",
        "sink_api": sink_api,
        "sink_address": "1100",
        "function": "handle_request",
        "entry_point_function": "handle_request",
        "call_path": ["handle_request"],
        "controlled_argument_indexes": list(controlled or []),
        "constant_argument_indexes": list(constants or []),
        "propagation": ["xpc_dictionary_get_string@1000", f"{sink_api}@1100"],
        "reply_dataflow": list(reply or []),
        "validation_controls": list(validation or []),
        "authorization_controls": list(authorization or []),
        "unknown_reasons": list(unknown or []),
        "confidence": "HIGH",
    }


def _analyze(*imports, flows=None, enabled=True, mach=True):
    svc = _service(enabled=enabled, mach=mach)
    macho = MachOInfo(
        path="/fixture", is_macho=True, imported_symbols=list(imports),
        dataflow_facts=list(flows or []),
    )
    codesign = CodeSigningInfo(path="/fixture", is_signed=True)
    signals = detect_signals(svc, macho, codesign)
    findings, edges = analyze_capabilities(svc, macho, signals, codesign)
    return findings, edges


def _candidate(findings, name):
    return next(f for f in findings if f.candidate_capability == name)


class TestAccuracyRegressions(unittest.TestCase):
    def test_a_ftruncate_import_without_path_is_only_candidate(self):
        findings, _ = _analyze("ftruncate")
        finding = _candidate(findings, "FILE_WRITE_SINK_CANDIDATE")
        self.assertEqual(finding.maturity_level, "SINK_CANDIDATE")
        self.assertIsNone(finding.proven_primitive)
        self.assertEqual(finding.controlled_arguments["file_descriptor"], "UNKNOWN")
        self.assertLessEqual(finding.exploitability_evidence_score, 20)

    def test_b_reachable_chown_with_constant_args_is_not_arbitrary(self):
        findings, _ = _analyze(
            "xpc_dictionary_get_string", "chown",
            flows=[_flow("chown", constants=[0, 1, 2])],
        )
        finding = _candidate(findings, "CHOWN_SINK_CANDIDATE")
        self.assertEqual(finding.maturity_level, "REACHABLE_SINK")
        self.assertEqual(finding.attacker_control, "LOW")
        self.assertEqual(finding.controlled_arguments["path"], "CONSTANT")
        self.assertEqual(finding.controlled_arguments["uid"], "CONSTANT")
        self.assertIsNone(finding.proven_primitive)

    def test_c_path_control_and_constant_ids_are_argument_scoped(self):
        findings, _ = _analyze(
            "xpc_dictionary_get_string", "chown",
            flows=[_flow("chown", controlled=[0], constants=[1, 2])],
        )
        finding = _candidate(findings, "CHOWN_SINK_CANDIDATE")
        self.assertEqual(finding.maturity_level, "CONTROLLED_SINK")
        self.assertEqual(finding.controlled_arguments["path"], "HIGH")
        self.assertEqual(finding.controlled_arguments["uid"], "CONSTANT")
        self.assertEqual(finding.controlled_arguments["gid"], "CONSTANT")
        self.assertIsNone(finding.proven_primitive)

    def test_d_signature_import_is_not_an_oracle(self):
        findings, _ = _analyze("SecKeyCreateSignature")
        finding = _candidate(findings, "SIGNATURE_OPERATION_CANDIDATE")
        self.assertEqual(finding.maturity_level, "SINK_CANDIDATE")
        self.assertIsNone(finding.proven_primitive)
        self.assertNotIn("SIGNING_ORACLE", {f.proven_primitive for f in findings})

    def test_e_controlled_signing_without_reply_is_not_an_oracle(self):
        findings, _ = _analyze(
            "xpc_dictionary_get_data", "SecKeyCreateSignature",
            flows=[_flow("SecKeyCreateSignature", controlled=[2])],
        )
        finding = _candidate(findings, "SIGNATURE_OPERATION_CANDIDATE")
        self.assertEqual(finding.maturity_level, "CONTROLLED_SINK")
        self.assertIsNone(finding.proven_primitive)
        self.assertTrue(any("reply" in item.lower() for item in finding.missing_evidence))

    def test_f_validation_elsewhere_is_not_a_sink_guard(self):
        findings, _ = _analyze(
            "xpc_dictionary_get_string", "unlink", "SecCodeCheckValidity",
            flows=[_flow("unlink", controlled=[0])],
        )
        finding = _candidate(findings, "FILE_DELETE_SINK_CANDIDATE")
        self.assertEqual(finding.identity.scope, "VALIDATION_PRESENT_IN_BINARY")
        self.assertNotEqual(finding.identity.scope, "VALIDATION_GUARDS_SINK")

    def test_g_strong_identity_does_not_imply_operation_authorization(self):
        findings, _ = _analyze(
            "xpc_dictionary_get_string", "unlink",
            "xpc_connection_get_audit_token", "SecCodeCopyGuestWithAttributes",
            "SecCodeCheckValidity", flows=[_flow("unlink", controlled=[0])],
        )
        finding = _candidate(findings, "FILE_DELETE_SINK_CANDIDATE")
        self.assertEqual(finding.identity.strength, "STRONG")
        self.assertEqual(finding.identity.scope, "VALIDATION_PRESENT_IN_BINARY")
        self.assertEqual(finding.authorization.scope, "AUTHORIZATION_NOT_OBSERVED")

    def test_h_root_service_can_be_high_priority_but_low_exploitability(self):
        findings, _ = _analyze("ftruncate")
        finding = _candidate(findings, "FILE_WRITE_SINK_CANDIDATE")
        self.assertGreaterEqual(finding.research_priority_score, 60)
        self.assertLessEqual(finding.exploitability_evidence_score, 20)
        self.assertGreater(
            finding.research_priority_score, finding.exploitability_evidence_score)

    def test_candidate_does_not_create_a_primitive_chain(self):
        _findings, edges = _analyze("copyfile")
        self.assertEqual(edges, [])

    def test_log_and_membership_query_names_are_not_operations(self):
        findings, _ = _analyze("GSSOSLog", "mbr_check_membership")
        self.assertEqual(findings, [])

    def test_json_and_mermaid_keep_candidate_and_proof_separate(self):
        findings, _ = _analyze("SecKeyCreateSignature")
        data = findings[0].to_dict()
        self.assertEqual(data["candidate_capability"], "SIGNATURE_OPERATION_CANDIDATE")
        self.assertIsNone(data["proven_primitive"])
        self.assertIn("Primitive: primitive not proven", data["mermaid"])
        self.assertIn("UNRESOLVED", data["mermaid"])


class TestBoundedDataflow(unittest.TestCase):
    def test_usermanagerd_header_bytes_outside_text_are_not_decoded(self):
        text = """
header_artifact:
0000000100000b54 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_value
0000000100000b58 bl 0x100008100 ; symbol stub for: _SecItemDelete
0000000100000b8c bl 0x100008200 ; symbol stub for: _SecItemAdd
0000000100000c94 bl 0x100008300 ; symbol stub for: _SecItemCopyMatching
live_handler:
0000000100001200 bl 0x100008400 ; symbol stub for: _xpc_dictionary_get_value
0000000100001204 bl 0x100008500 ; symbol stub for: _mount
"""
        facts = parse_disassembly(
            text, ["xpc_dictionary_get_value"],
            ["SecItemAdd", "SecItemDelete", "SecItemCopyMatching", "mount"],
            executable_ranges=[(0x100001100, 0x100002000)],
        )
        self.assertEqual([fact["sink_api"] for fact in facts], ["mount"])
        self.assertFalse(
            {"SecItemAdd", "SecItemDelete", "SecItemCopyMatching"}
            & {fact["sink_api"] for fact in facts})

    def test_otool_load_commands_yield_only_text_range(self):
        fixture = """
Section
  sectname __text
   segname __TEXT
      addr 0x0000000100001100
      size 0x0000000000002000
Section
  sectname __cstring
   segname __TEXT
      addr 0x0000000100004000
      size 0x0000000000000800
"""
        self.assertEqual(
            parse_executable_text_ranges(fixture),
            [(0x100001100, 0x100003100)],
        )

    def test_unconditional_nsxpc_listener_is_structural_evidence(self):
        text = """
-[RDXPCListener listener:shouldAcceptNewConnection:]:
0000000100001200 mov w0, #0x1
0000000100001204 ret
"""
        analysis = analyze_disassembly(
            text, executable_ranges=[(0x100001100, 0x100002000)])
        self.assertEqual(
            analysis.unconditional_accept_listeners,
            ["-[RDXPCListener listener:shouldAcceptNewConnection:]"],
        )

    def test_unreferenced_dead_sink_stays_candidate(self):
        flow = _flow("chmod", controlled=[0])
        flow["reachability_confirmed"] = False
        flow["reachability_evidence"] = "NO_CALLER_REFERENCE"
        findings, _ = _analyze(
            "xpc_dictionary_get_string", "chmod", flows=[flow])
        finding = _candidate(findings, "CHMOD_SINK_CANDIDATE")
        self.assertEqual(finding.maturity_level, "SINK_CANDIDATE")
        self.assertIn("UNKNOWN_NO_CALL_PATH", finding.unknown_reasons)

    def test_usermanagerd_three_dead_helpers_all_stay_candidates(self):
        fixtures = (
            ("chmod", "createVolumeMountsDir:", "0x10003b78c",
             "CHMOD_SINK_CANDIDATE"),
            ("chown", "fixupPath:withMode:toUser:group:error:", "0x100038128",
             "CHOWN_SINK_CANDIDATE"),
            ("mkdir", "sym.func.1000347d4", "0x1000347d4",
             "DIRECTORY_CREATE_SINK_CANDIDATE"),
        )
        for sink, function, address, candidate in fixtures:
            with self.subTest(function=function):
                flow = _flow(sink, controlled=[0])
                flow.update({
                    "function": function,
                    "sink_address": address,
                    "reachability_confirmed": False,
                    "reachability_evidence": "NO_CALLER_REFERENCE",
                })
                findings, _ = _analyze(
                    "xpc_dictionary_get_string", sink, flows=[flow])
                finding = _candidate(findings, candidate)
                self.assertEqual(finding.maturity_level, "SINK_CANDIDATE")
                self.assertIn("UNKNOWN_NO_CALL_PATH", finding.unknown_reasons)

    def test_referenced_mount_chain_remains_reachable(self):
        text = """
createPersona_handler:
0000000100001200 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_value
0000000100001204 bl 0x100003000 <_mount_volume>
mount_volume:
0000000100003000 mov x0, x20
0000000100003004 bl 0x100008100 ; symbol stub for: _mkdir
"""
        facts = parse_disassembly(
            text, ["xpc_dictionary_get_value"], ["mkdir"],
            executable_ranges=[(0x100001100, 0x100004000)],
        )
        self.assertEqual(len(facts), 1)
        self.assertTrue(facts[0]["reachability_confirmed"])
        self.assertEqual(facts[0]["reachability_evidence"], "CALL_REFERENCE")

    def test_duplicate_flows_to_the_same_sink_collapse_to_one_finding(self):
        findings, _ = _analyze(
            "xpc_dictionary_get_string", "unlink",
            flows=[_flow("unlink", controlled=[0]), _flow("unlink", controlled=[0]),
                   _flow("unlink", controlled=[0])],
        )
        caps = [f for f in findings
                if f.candidate_capability == "FILE_DELETE_SINK_CANDIDATE"]
        self.assertEqual(len(caps), 1)
        self.assertEqual(caps[0].controlled_arguments["path"], "HIGH")

    def test_objc_selector_sink_is_resolved(self):
        text = """
handle_request:
0000000100001000 adrp x1, 0x1000
0000000100001004 add x1, x1, #0x10 ; literal pool for: "path"
0000000100001008 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
000000010000100c mov x19, x0
0000000100001010 adrp x8, 0x1000 ; 0x10000000
0000000100001014 ldr x1, [x8, #0x20]
0000000100001018 mov x0, x20
000000010000101c mov x2, x19
0000000100001020 bl 0x100008100 ; symbol stub for: _objc_msgSend
0000000100001024 ret
"""
        facts = parse_disassembly(
            text, ["xpc_dictionary_get_string"], ["removeItemAtPath:"],
            selector_refs={"arm64": {0x10000020: "removeItemAtPath:error:"}})
        self.assertTrue(any(f["sink_api"] == "removeItemAtPath:error:" for f in facts))
        fact = next(f for f in facts if f["sink_api"] == "removeItemAtPath:error:")
        self.assertEqual(fact["controlled_argument_indexes"], [2])

    def test_arm64_register_and_stack_flow(self):
        text = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 str x0, [sp, #16]
0000000100001008 ldr x20, [sp, #16]
000000010000100c mov x0, x20
0000000100001010 bl 0x100008100 ; symbol stub for: _unlink
0000000100001014 ret
"""
        facts = parse_disassembly(text, ["xpc_dictionary_get_string"], ["unlink"])
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["controlled_argument_indexes"], [0])
        self.assertEqual(facts[0]["source_address"], "0000000100001000")

    def test_reachable_sink_is_recorded_without_argument_flow(self):
        text = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 mov x0, x21
0000000100001008 bl 0x100008100 ; symbol stub for: _unlink
"""
        facts = parse_disassembly(text, ["xpc_dictionary_get_string"], ["unlink"])
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["controlled_argument_indexes"], [])

    def test_direct_helper_propagates_source_to_sink(self):
        text = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 bl 0x100002000 <_delete_helper>
0000000100001008 ret
delete_helper:
0000000100002000 bl 0x100008100 ; symbol stub for: _unlink
0000000100002004 ret
"""
        facts = parse_disassembly(text, ["xpc_dictionary_get_string"], ["unlink"])
        self.assertEqual(facts[0]["controlled_argument_indexes"], [0])
        self.assertEqual(facts[0]["call_path"], ["handle_request", "delete_helper"])

    def test_source_wrapper_return_flows_into_caller_sink(self):
        text = """
handle_request:
0000000100001000 bl 0x100002000 <_read_field>
0000000100001004 bl 0x100008100 ; symbol stub for: _unlink
0000000100001008 ret
read_field:
0000000100002000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100002004 ret
"""
        facts = parse_disassembly(text, ["xpc_dictionary_get_string"], ["unlink"])
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["controlled_argument_indexes"], [0])
        self.assertEqual(facts[0]["source_function"], "read_field")

    def test_sensitive_result_reaches_reply(self):
        text = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_data
0000000100001004 mov x2, x0
0000000100001008 adrp x0, 0x1000
000000010000100c adrp x1, 0x2000
0000000100001010 bl 0x100008100 ; symbol stub for: _SecKeyCreateSignature
0000000100001014 mov x2, x0
0000000100001018 adrp x0, 0x3000
000000010000101c adrp x1, 0x4000
0000000100001020 bl 0x100008200 ; symbol stub for: _xpc_dictionary_set_value
0000000100001024 ret
"""
        facts = parse_disassembly(
            text, ["xpc_dictionary_get_data"], ["SecKeyCreateSignature"])
        self.assertEqual(facts[0]["controlled_argument_indexes"], [2])
        self.assertTrue(facts[0]["reply_dataflow"])

    def test_only_a_control_result_branch_can_guard_the_sink(self):
        text = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 mov x19, x0
0000000100001008 bl 0x100008010 ; symbol stub for: _SecCodeCheckValidity
000000010000100c cbnz x0, 0x100001030
0000000100001010 mov x0, x19
0000000100001014 bl 0x100008100 ; symbol stub for: _unlink
0000000100001030 ret
"""
        facts = parse_disassembly(text, ["xpc_dictionary_get_string"], ["unlink"])
        controls = facts[0]["validation_controls"]
        self.assertEqual(controls[0]["scope"], "VALIDATION_GUARDS_SINK")

    def test_a_success_branch_that_skips_the_sink_is_not_a_guard(self):
        text = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 mov x19, x0
0000000100001008 bl 0x100008010 ; symbol stub for: _SecCodeCheckValidity
000000010000100c cbz x0, 0x100001030
0000000100001010 mov x0, x19
0000000100001014 bl 0x100008100 ; symbol stub for: _unlink
0000000100001030 ret
"""
        facts = parse_disassembly(text, ["xpc_dictionary_get_string"], ["unlink"])
        controls = facts[0]["validation_controls"]
        self.assertNotEqual(controls[0]["scope"], "VALIDATION_GUARDS_SINK")

    def test_guard_evidence_is_carried_on_the_authorization_control(self):
        findings, _ = _analyze(
            "xpc_dictionary_get_string", "unlink", "AuthorizationCopyRights",
            flows=[_flow("unlink", controlled=[0], authorization=[{
                "kind": "authorization", "api": "AuthorizationCopyRights",
                "scope": "AUTHORIZATION_GUARDS_SINK", "function": "handle_request",
                "branch_address": "10000010",
                "guard_evidence": {"dominance": True, "used_result": True,
                                   "semantics": "zero"},
            }])],
        )
        finding = _candidate(findings, "FILE_DELETE_SINK_CANDIDATE")
        self.assertEqual(finding.authorization.scope, "AUTHORIZATION_GUARDS_SINK")
        self.assertTrue(finding.authorization.guard_evidence["dominance"])

    def test_unresolved_authorization_raises_research_priority_not_exploitability(self):
        unguarded, _ = _analyze(
            "xpc_dictionary_get_string", "chown",
            flows=[_flow("chown", controlled=[0], constants=[1, 2])],
        )
        guarded, _ = _analyze(
            "xpc_dictionary_get_string", "chown", "AuthorizationCopyRights",
            flows=[_flow("chown", controlled=[0], constants=[1, 2],
                         authorization=[{
                             "kind": "authorization", "api": "AuthorizationCopyRights",
                             "scope": "AUTHORIZATION_GUARDS_SINK",
                             "function": "handle_request", "branch_address": "10000010",
                             "guard_evidence": {"dominance": True}}])],
        )
        first = _candidate(unguarded, "CHOWN_SINK_CANDIDATE")
        second = _candidate(guarded, "CHOWN_SINK_CANDIDATE")
        self.assertGreater(first.research_priority_score, second.research_priority_score)
        self.assertIsNone(first.proven_primitive)
        self.assertIsNone(second.proven_primitive)

    def test_objc_dispatch_uncertainty_is_instrumented(self):
        text = """
handle_request:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 bl 0x100008010 ; symbol stub for: _objc_msgSend
0000000100001008 bl 0x100008100 ; symbol stub for: _unlink
"""
        analysis = analyze_disassembly(
            text, ["xpc_dictionary_get_string"], ["unlink"])
        self.assertIn("UNKNOWN_OBJC_DISPATCH", analysis.unknown_reasons)
        self.assertIn("UNKNOWN_OBJC_DISPATCH", analysis.facts[0]["unknown_reasons"])

    def test_x86_and_fat_architecture_parsing_do_not_crash(self):
        text = """
/fixture (architecture x86_64):
handle_x86:
0000000100000100 callq 0x1000 ; symbol stub for: _xpc_dictionary_get_string
0000000100000104 movq %rax, %rdi
0000000100000108 callq 0x1100 ; symbol stub for: _unlink
/fixture (architecture arm64e):
handle_arm:
0000000100001000 bl 0x100008000 ; symbol stub for: _xpc_dictionary_get_string
0000000100001004 ldr q0, [sp, #0x70]
0000000100001008 mov x19, x0
000000010000100c mov x0, x19
0000000100001010 bl 0x100008100 ; symbol stub for: _unlink
"""
        facts = parse_disassembly(text, ["xpc_dictionary_get_string"], ["unlink"])
        self.assertEqual(len(facts), 2)
        self.assertTrue(all(f["controlled_argument_indexes"] == [0] for f in facts))


class TestNSXPCPerMessageValidation(unittest.TestCase):
    def test_correlated_markers_add_per_message_class_and_authorization_scope(self):
        svc = _service()
        macho = MachOInfo(
            path="/fixture/usermanagerd", is_macho=True,
            imported_symbols=["xpc_dictionary_get_string", "chmod"],
            objc_classes=["NSXPCConnection"],
            interesting_strings=[
                "valueForEntitlement:", "boolValue",
                "com.apple.usermanagerd.persona.create",
            ],
            nsxpc_unconditional_accept_listeners=[
                "-[RDXPCListener listener:shouldAcceptNewConnection:]"],
        )
        codesign = CodeSigningInfo(path=macho.path, is_signed=True)
        signals = detect_signals(svc, macho, codesign)
        self.assertIn("per-message-entitlement",
                      signals.validation_assessment.by_class)
        self.assertIn("com.apple.usermanagerd.persona.create",
                      signals.checked_entitlements)
        findings, _ = analyze_capabilities(svc, macho, signals, codesign)
        finding = _candidate(findings, "CHMOD_SINK_CANDIDATE")
        self.assertEqual(finding.authorization.scope, AUTHORIZATION_PER_MESSAGE)
        self.assertIn("valueForEntitlement", finding.authorization.method)

    def test_value_for_entitlement_string_alone_is_not_validation(self):
        svc = _service()
        macho = MachOInfo(path="/fixture", is_macho=True,
                          interesting_strings=["valueForEntitlement:"])
        signals = detect_signals(svc, macho, CodeSigningInfo(path="/fixture"))
        self.assertNotIn("per-message-entitlement",
                         signals.validation_assessment.by_class)


class TestCapabilityCli(unittest.TestCase):
    def test_scan_accepts_maturity_and_evidence_filters(self):
        args = tbm.build_parser().parse_args([
            "scan", "--primitive", "SIGNATURE_OPERATION_CANDIDATE",
            "--maturity", "CONTROLLED_SINK", "--min-exploitability", "30",
            "--confidence", "HIGH", "--reachable-by", "LOCAL_USER",
            "--sink", "credential", "--framework", "Security",
            "--validation", "CONDITIONAL", "--proven-only",
        ])
        self.assertEqual(args.maturity, ["CONTROLLED_SINK"])
        self.assertEqual(args.min_exploitability, 30)
        self.assertTrue(args.proven_only)

    def test_hunt_accepts_maturity_and_evidence_filters(self):
        args = tbm.build_parser().parse_args([
            "hunt", "--primitive", "SIGNATURE_OPERATION_CANDIDATE",
            "--maturity", "SINK_CANDIDATE", "--min-exploitability", "10",
            "--confidence", "MEDIUM", "--reachable-by", "LOCAL_USER",
            "--sink", "credential", "--framework", "Security",
            "--validation", "WEAK",
        ])
        self.assertEqual(args.maturity, "SINK_CANDIDATE")
        self.assertEqual(args.min_exploitability, 10)


if __name__ == "__main__":
    unittest.main()
