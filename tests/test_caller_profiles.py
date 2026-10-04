"""Regression tests for per-caller-profile reachability and policy paths."""

from __future__ import annotations

import unittest

import _paths  # noqa: F401

from analyzers.capabilities import analyze_capabilities
from analyzers.security_signals import detect_signals
from models.capability import AUTHORIZATION_GUARDS_SINK
from models.common import RunAs, ServiceScope, ServiceType
from models.executable import CodeSigningInfo, MachOInfo
from models.service import LaunchService


def _service(*, enabled=True, mach=True):
    return LaunchService(
        label="com.example.profile",
        plist_path="/System/Library/LaunchDaemons/com.example.profile.plist",
        service_type=ServiceType.DAEMON,
        scope=ServiceScope.SYSTEM_DAEMON,
        mach_services=["com.example.profile"] if mach else [],
        run_as=RunAs.ROOT,
        run_as_user="root",
        enabled=enabled,
    )


def _auth(api, scope="AUTHORIZATION_REACHABLE_FROM_HANDLER"):
    return {"kind": "authorization", "api": api, "scope": scope,
            "function": "handle_request", "branch_address": ""}


def _flow(sink_api, *, controlled=None, authorization=None):
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
        "constant_argument_indexes": [],
        "propagation": ["xpc_dictionary_get_string@1000", f"{sink_api}@1100"],
        "reply_dataflow": [],
        "validation_controls": [],
        "authorization_controls": list(authorization or []),
        "unknown_reasons": [],
        "confidence": "HIGH",
    }


def _analyze(*imports, flows=None):
    svc = _service()
    macho = MachOInfo(path="/fixture", is_macho=True,
                      imported_symbols=list(imports),
                      dataflow_facts=list(flows or []))
    codesign = CodeSigningInfo(path="/fixture", is_signed=True)
    signals = detect_signals(svc, macho, codesign)
    findings, _ = analyze_capabilities(svc, macho, signals, codesign)
    return findings


def _candidate(findings, name):
    return next(f for f in findings if f.candidate_capability == name)


class TestCallerProfiles(unittest.TestCase):
    def test_sandbox_check_alone_is_conditional_not_strong(self):
        findings = _analyze(
            "xpc_dictionary_get_string", "unlink", "sandbox_check_by_audit_token",
            flows=[_flow("unlink", controlled=[0],
                         authorization=[_auth("sandbox_check_by_audit_token")])],
        )
        finding = _candidate(findings, "FILE_DELETE_SINK_CANDIDATE")
        self.assertEqual(finding.authorization.strength, "CONDITIONAL")
        self.assertNotEqual(finding.authorization.scope, AUTHORIZATION_GUARDS_SINK)

    def test_sandboxed_and_unsandboxed_profiles_differ(self):
        findings = _analyze(
            "xpc_dictionary_get_string", "unlink", "sandbox_check_by_audit_token",
            flows=[_flow("unlink", controlled=[0],
                         authorization=[_auth("sandbox_check_by_audit_token")])],
        )
        finding = _candidate(findings, "FILE_DELETE_SINK_CANDIDATE")
        profiles = {p["profile"]: p for p in finding.caller_profiles}
        self.assertNotEqual(profiles["SANDBOXED"]["authorization"],
                            profiles["UNSANDBOXED"]["authorization"])
        self.assertEqual(profiles["SANDBOXED"]["authorization"],
                         "AUTHORIZATION_PROFILE_ALLOWLIST")
        self.assertEqual(profiles["UNSANDBOXED"]["authorization"],
                         "AUTHORIZATION_NOT_OBSERVED")

    def test_unknown_mach_lookup_stays_unknown(self):
        findings = _analyze(
            "xpc_dictionary_get_string", "unlink",
            flows=[_flow("unlink", controlled=[0])],
        )
        finding = _candidate(findings, "FILE_DELETE_SINK_CANDIDATE")
        profiles = {p["profile"]: p for p in finding.caller_profiles}
        self.assertEqual(profiles["SANDBOXED"]["mach_lookup"], "UNKNOWN")
        self.assertEqual(profiles["UNSANDBOXED"]["mach_lookup"], "NOT_REQUIRED")

    def test_profile_predicate_does_not_produce_guards_sink(self):
        findings = _analyze(
            "xpc_dictionary_get_string", "unlink", "sandbox_check_by_audit_token",
            flows=[_flow("unlink", controlled=[0],
                         authorization=[_auth("sandbox_check_by_audit_token")])],
        )
        finding = _candidate(findings, "FILE_DELETE_SINK_CANDIDATE")
        self.assertNotEqual(finding.authorization.scope, AUTHORIZATION_GUARDS_SINK)
        self.assertIsNone(finding.proven_primitive)
        self.assertNotEqual(finding.maturity_level, "PRIMITIVE")

    def test_sandbox_predicate_is_reported_as_a_policy_path(self):
        findings = _analyze(
            "xpc_dictionary_get_string", "unlink", "sandbox_check_by_audit_token",
            flows=[_flow("unlink", controlled=[0],
                         authorization=[_auth("sandbox_check_by_audit_token")])],
        )
        finding = _candidate(findings, "FILE_DELETE_SINK_CANDIDATE")
        self.assertTrue(finding.policy_paths)
        path = finding.policy_paths[0]
        self.assertEqual(path["predicate"], "sandbox_check_by_audit_token")
        self.assertEqual(path["allowed_operation"], "unlink")
        self.assertEqual(path["success_semantics"], "UNKNOWN")
        self.assertEqual(path["relationship"], "PREDICATE_OBSERVED")


if __name__ == "__main__":
    unittest.main()
