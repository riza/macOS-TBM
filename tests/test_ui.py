"""Tests for optional terminal presentation helpers."""

from __future__ import annotations

import asyncio
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import _paths  # noqa: F401

from ui import (
    Radare2Progress,
    ScanProgress,
    _dossier_lines,
    build_dashboard,
    print_banner,
    render_dossiers,
    render_scan_cli,
    render_scan_result,
    render_tui,
)

DOSSIER_SECTIONS = ("launchd metadata", "code signing", "caller validation",
                    "entitlements", "findings", "binary detail",
                    "manual research questions")

TARGET = {
    "label": "com.example.daemon",
    "score": 80,
    "priority": "HIGH",
    "validation": "WEAK",
    "ipc_classification": "provider",
    "sensitive_sinks": ["CREDENTIAL"],
    "reasons": [{"weight": 20, "reason": "runs as root / system service"}],
    "service": {
        "label": "com.example.daemon",
        "plist_path": "/Library/LaunchDaemons/com.example.daemon.plist",
        "service_type": "daemon", "scope": "system-daemon",
        "program_arguments": ["/usr/local/bin/exampled"],
        "mach_services": ["com.example.daemon.xpc"],
        "run_as_user": "root", "run_as_derivation": "LaunchDaemon with no UserName",
        "enabled": True, "enabled_derivation": "no Disabled key",
        "associated_executable": "/usr/local/bin/exampled",
    },
    "executable": {
        "path": "/usr/local/bin/exampled",
        "codesign": {
            "is_signed": True, "signer_identifier": "com.example.daemon",
            "platform_binary": False, "authority": ["Example CA"],
            "entitlements": {"com.apple.private.example": True, "com.example.public": "yes"},
        },
        "macho": {"architectures": ["arm64e"], "linked_libs": ["/usr/lib/libSystem.dylib",
                                                               "/usr/lib/libz.dylib"],
                  "ipc_operations": [{
                      "request_key": "request",
                      "operation": "RepairPermissionsForCloudItems",
                      "handler": "repair_handler", "input_keys": ["Paths"],
                      "dispatcher": "dispatch", "relationship": "PROVEN",
                      "evidence": []}]},
    },
    "entitlement_findings": ["com.apple.private.example"],
    "checked_entitlements": ["com.example.client-allowed"],
    "capability_findings": [{
        "finding_id": "cap-1", "primitive": "CHOWN_SINK_CANDIDATE",
        "candidate_capability": "CHOWN_SINK_CANDIDATE", "maturity": "CONTROLLED_SINK",
        "confidence": "MEDIUM", "research_priority_score": 60,
        "dataflow": ["xpc_dictionary_get_string@1000", "open@1004", "fchown@1010"],
        "attacker_control": "HIGH",
        "controlled_arguments": {"file_descriptor": "HIGH", "resource_path": "HIGH"},
        "expected_caller_identity": "UNKNOWN", "identity_verification": "WEAK",
        "authorization_decision": "AUTHORIZATION_NOT_OBSERVED",
        "reachability": ["LOCAL_USER"], "post_condition": "FILE_OWNER_CHANGED",
        "missing_proof": [],
        "sink": {"api": "fchown", "operation": "change ownership",
                 "controlled_arguments": {"file_descriptor": "HIGH"}},
        "authorization": {"scope": "AUTHORIZATION_NOT_OBSERVED", "strength": "NONE_OBSERVED",
                          "guard_evidence": {}, "unknown_reason": "UNKNOWN_CONTROL_FLOW"},
        "call_path_state": "CONFIRMED_INDIRECT",
        "call_path": ["sub_100001000", "sub_100002000"],
        "caller_profiles": [{
            "profile": "SANDBOXED", "entry_reachability": "CONDITIONAL",
            "mach_lookup": "UNKNOWN",
            "authorization": "AUTHORIZATION_PROFILE_ALLOWLIST"}],
        "policy_paths": [{
            "predicate": "sandbox_check_by_audit_token",
            "allowed_operation": "fchown", "success_semantics": "UNKNOWN",
            "relationship": "PREDICATE_OBSERVED"}],
    }],
    "lpe_findings": [{
        "finding_id": "lpe-1",
        "lpe_classes": ["FS_USER_PATH_TO_ROOT_SINK", "FS_PRIVILEGED_CHOWN"],
        "operation": "chown", "sink": {"api": "fchown", "address": "1010",
                                       "function": "handle"},
        "severity": "HIGH", "confidence": "CONFIRMED_FLOW", "score": 80,
        "input_origin": "xpc", "input_name": "path",
        "caller_validation": "NONE_OBSERVED",
        "caller_validation_scope": "OPERATION_GUARD_NOT_OBSERVED",
        "operation_authorization": "NONE_OBSERVED",
        "operation_authorization_scope": "AUTHORIZATION_NOT_OBSERVED",
        "resource_validation": "DESCRIPTOR_BASED_REFERENCE",
        "resource_authorization": "UNKNOWN", "resource_scope": "DESCRIPTOR_BINDING",
        "resource_scope_confidence": "UNKNOWN",
        "descriptor_provenance": {"0": [{"api": "open", "address": "1004"}]},
        "target": "unresolved", "target_category": "unresolved",
        "toctou_candidate": False,
        "missing_evidence": ["caller authority over the selected resource is not proven"],
        "research_questions": [
            "resource authorization unresolved: is the target constrained to an allowed root?"],
    }],
    "sink_assessments": [{"label": "CREDENTIAL", "score": 12, "confidence": "MEDIUM",
                          "aspects": ["keychain"],
                          "evidence": [{"kind": "import", "match": "SecItemCopyMatching",
                                        "aspect": "keychain", "weight": 8}]}],
    "validation_assessment": {
        "score": 5,
        "evidence": [{"kind": "import", "match": "xpc_connection_get_audit_token",
                      "aspect": "audit-token-extraction", "weight": 5}],
        "not_observed": [{"class": "entitlement-check", "weight": 6,
                          "description": "checks an entitlement on the caller",
                          "looked_for": "SecTaskCopyValueForEntitlement"}],
    },
    "findings": [{"category": "ipc", "level": "FACT", "message": "registers a Mach service",
                  "evidence": "launchd MachServices key"}],
    "why_interesting": ["privileged system daemon"],
    "research_questions": ["How is caller identity established?"],
}

REPORT = {
    "summary": {"total_services": 1, "privileged_services": 1,
                "mach_xpc_services": 1, "high_priority_targets": 1},
    "targets": [TARGET],
}


class TestUI(unittest.TestCase):
    def test_progress_callback_is_safe_when_disabled(self):
        with ScanProgress("none", enabled=True) as progress:
            progress.update(1, 2)

    def test_rich_progress_uses_supported_console_api(self):
        with ScanProgress("rich", enabled=True, stream=io.StringIO()) as progress:
            progress.update(1, 2)

    def test_radare2_progress_shows_counts_and_current_binary(self):
        output = io.StringIO()
        with Radare2Progress(enabled=True, stream=output) as progress:
            progress.update({
                "findings_done": 25, "findings_total": 2425,
                "findings_remaining": 2400,
                "binaries_done": 0, "binaries_total": 399,
                "path": "/usr/libexec/exampled", "stage": "analyzing",
                "active_paths": ["/usr/libexec/exampled", "/usr/libexec/otherd"],
            })
        text = output.getvalue()
        self.assertIn("25/2425 findings", text)
        self.assertIn("0/399 binaries", text)
        self.assertIn("exampled", text)
        self.assertIn("otherd", text)

    def test_radare2_plain_fallback_lists_active_binaries(self):
        output = io.StringIO()
        with patch.dict("sys.modules", {"rich.console": None}), \
                Radare2Progress(enabled=True, stream=output) as progress:
            self.assertIsNone(progress._progress)
            progress.update({
                "findings_done": 25, "findings_total": 2425,
                "findings_remaining": 2400,
                "binaries_done": 0, "binaries_total": 399,
                "path": "/usr/libexec/exampled", "stage": "analyzing",
                "active_paths": ["/usr/libexec/exampled", "/usr/libexec/otherd"],
            })
        text = output.getvalue()
        self.assertIn("25/2425 findings", text)
        self.assertIn("0/399 binaries", text)
        self.assertIn("exampled, otherd", text)

    def test_banner_contains_identity_version_and_build(self):
        output = io.StringIO()
        print_banner("test", stream=output)
        text = output.getvalue()
        self.assertIn("macOS-TBM", text)
        self.assertIn("build", text)
        self.assertIn("test", text)

    def test_scan_result_uses_readable_completion_label(self):
        output = io.StringIO()
        render_scan_result(
            {"total_services": 3, "privileged_services": 1,
             "mach_xpc_services": 2, "high_priority_targets": 1},
            output_dir="./results", artifacts=["report.json"], stream=output,
        )
        text = output.getvalue()
        self.assertIn("Scan complete", text)
        self.assertIn("report.json", text)

    def test_tui_renders_report_without_mutating_it(self):
        before = repr(REPORT)
        output = io.StringIO()
        with redirect_stdout(output):
            render_tui(REPORT, limit=1)
        self.assertIn("com.example.daemon", output.getvalue())
        self.assertEqual(repr(REPORT), before)


class TestDossier(unittest.TestCase):
    """The terminal dossier must carry the same evidence as the HTML drawer."""

    def _rendered(self, **kwargs):
        output = io.StringIO()
        render_dossiers([TARGET], stream=output, **kwargs)
        return output.getvalue()

    def test_dossier_covers_every_html_section(self):
        text = self._rendered()
        for section in DOSSIER_SECTIONS:
            self.assertIn(section, text)

    def test_dossier_shows_full_entitlements_and_daemon_metadata(self):
        text = self._rendered()
        self.assertIn("com.apple.private.example", text)
        self.assertIn("com.example.public", text)
        self.assertIn("/Library/LaunchDaemons/com.example.daemon.plist", text)
        self.assertIn("com.example.daemon.xpc", text)
        self.assertIn("com.example.client-allowed", text)

    def test_dossier_preserves_not_observed_wording(self):
        text = self._rendered()
        self.assertIn("entitlement-check", text)
        self.assertIn("Not observed", text)

    def test_long_lists_report_the_number_withheld(self):
        text = self._rendered(list_limit=1)
        self.assertIn("1 more", text)

    def test_plain_fallback_covers_the_same_sections(self):
        text = "\n".join(_dossier_lines(TARGET))
        for section in DOSSIER_SECTIONS:
            self.assertIn(section, text)

    def test_dossier_surfaces_xpc_operations_profiles_and_resource_scope(self):
        text = self._rendered()
        self.assertIn("XPC operations", text)
        self.assertIn("RepairPermissionsForCloudItems", text)
        self.assertIn("Paths", text)
        self.assertIn("SANDBOXED", text)
        self.assertIn("AUTHORIZATION_PROFILE_ALLOWLIST", text)
        self.assertIn("sandbox_check_by_audit_token", text)
        self.assertIn("DESCRIPTOR_BINDING", text)
        self.assertIn("resource authorization unresolved", text)
        self.assertIn("CONFIRMED_INDIRECT", text)
        self.assertIn("sub_100001000 -> sub_100002000", text)
        self.assertIn("com.apple.private.example", text)

    def test_scan_view_prints_dossiers_only_when_detail_is_asked_for(self):
        full, summary = io.StringIO(), io.StringIO()
        render_scan_cli(REPORT, detail=True, stream=full)
        render_scan_cli(REPORT, detail=False, stream=summary)
        self.assertIn("launchd metadata", full.getvalue())
        self.assertNotIn("launchd metadata", summary.getvalue())
        self.assertIn("scan summary", summary.getvalue())


class TestDashboard(unittest.TestCase):
    def test_dashboard_detail_pane_holds_the_selected_dossier(self):
        app = build_dashboard(REPORT)
        if app is None:
            self.skipTest("textual is not installed")

        async def drive():
            async with app.run_test(size=(200, 60)) as pilot:
                await pilot.pause()
                await pilot.press("f")
                await pilot.press("f")
                await pilot.press("r")
                await pilot.pause()
                return app.shown

        self.assertEqual([t["label"] for t in asyncio.run(drive())], ["com.example.daemon"])


if __name__ == "__main__":
    unittest.main()
