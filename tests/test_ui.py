"""Tests for optional terminal presentation helpers."""

from __future__ import annotations

import asyncio
from contextlib import redirect_stdout
import io
import unittest

import _paths  # noqa: F401

from ui import (ScanProgress, _dossier_lines, build_dashboard, print_banner,
                render_dossiers, render_scan_cli, render_scan_result, render_tui)


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
                                                               "/usr/lib/libz.dylib"]},
    },
    "entitlement_findings": ["com.apple.private.example"],
    "checked_entitlements": ["com.example.client-allowed"],
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
