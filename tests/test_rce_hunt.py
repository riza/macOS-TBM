"""Regression coverage for network-ingress x parser RCE hunting."""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import _paths  # noqa: F401

import tbm
from analyzers.rce import analyze_rce, refresh_rce_findings
from hunt import format_rce_text, format_single, score_target
from models.common import RunAs, ServiceScope, ServiceType
from models.executable import CodeSigningInfo, Executable, MachOInfo
from models.finding import Target
from models.service import LaunchService
from reporting.export import build_tables
from reporting.html_report import write_html_report
from reporting.json_report import build_report, write_json_report


def _service(run_as=RunAs.ROOT, sockets=None):
    return LaunchService(
        label="com.example.net-svc",
        plist_path="/System/Library/LaunchDaemons/com.example.net-svc.plist",
        service_type=ServiceType.DAEMON,
        scope=ServiceScope.LOCAL_DAEMON,
        mach_services=["com.example.net-svc"],
        run_as=run_as,
        run_as_user="root" if run_as == RunAs.ROOT else "nobody",
        sockets=sockets or {},
        enabled=True,
    )


def _macho(*, imports=(), libs=()):
    return MachOInfo(
        path="/fixture/net-svc", is_macho=True,
        imported_symbols=list(imports), linked_libs=list(libs),
        interesting_strings=[],
    )


def _target(run_as=RunAs.ROOT, sockets=None, imports=(), libs=()):
    service = _service(run_as, sockets)
    macho = _macho(imports=imports, libs=libs)
    codesign = CodeSigningInfo(path=macho.path, is_signed=True)
    findings = analyze_rce(service, macho, validation="NONE_OBSERVED")
    return Target(
        service=service, executable=Executable(
            path=macho.path, macho=macho, codesign=codesign, analyzed=True),
        validation="NONE_OBSERVED",
        validation_assessment=None,
        checked_entitlements=[],
        rce_findings=findings,
    )


class TestRCEAnalysis(unittest.TestCase):
    def test_launchd_network_socket_plus_archive_parser_is_candidate(self):
        target = _target(
            sockets={"Listener": {"SockServiceName": "foo", "SockType": "stream"}},
            imports=("xar_open", "xar_extract_toBuffer"),
        )
        self.assertEqual(len(target.rce_findings), 1)
        finding = target.rce_findings[0]
        self.assertIn("NETWORK_LISTENER", finding.rce_classes)
        self.assertIn("PARSER_ARCHIVE", finding.rce_classes)
        self.assertIn("RCE_ROOT_LISTENER_PARSER", finding.rce_classes)
        self.assertEqual(finding.confidence, "POSSIBLE")
        self.assertTrue(any("not proven to reach the parser" in m
                            for m in finding.missing_evidence))
        self.assertEqual(finding.ingress_kind, "listener")
        self.assertEqual(finding.privilege, "root")
        self.assertFalse(finding.to_dict()["exploitability_confirmed"])

    def test_no_network_ingress_is_not_an_rce_finding(self):
        target = _target(imports=("xar_open",))
        self.assertEqual(target.rce_findings, [])

    def test_client_only_ingress_never_claims_root_listener(self):
        target = _target(
            sockets={},
            imports=("nw_connection_create", "xar_open"),
        )
        finding = target.rce_findings[0]
        self.assertNotIn("RCE_ROOT_LISTENER_PARSER", finding.rce_classes)
        self.assertIn("NETWORK_CLIENT", finding.rce_classes)
        self.assertEqual(finding.ingress_kind, "client")
        self.assertIn("daemon connects outbound", finding.missing_evidence[0])

    def test_listener_without_high_parser_is_low_value(self):
        target = _target(
            sockets={"Listener": {"SockServiceName": "ssh"}},
            imports=("CFPropertyListCreateWithData",),
        )
        finding = target.rce_findings[0]
        self.assertNotIn("BINARY_WIDE_PARSER_SURFACE", finding.rce_classes)
        self.assertIn("no high-complexity parser", finding.missing_evidence[0])

    def test_framework_link_alone_is_conservative_client(self):
        target = _target(
            sockets={},
            libs=("/System/Library/Frameworks/Network.framework/Versions/A/Network",),
            imports=("xar_open",),
        )
        self.assertEqual(len(target.rce_findings), 1)
        # A bare framework link cannot prove the daemon listens; classify as client.
        self.assertEqual(target.rce_findings[0].ingress_kind, "client")
        self.assertNotIn("NETWORK_LISTENER", target.rce_findings[0].rce_classes)

    def test_listener_import_requires_network_framework_for_socket_apis(self):
        target = _target(
            sockets={},
            imports=("bind", "listen", "accept", "xar_open"),
        )
        # bind/listen/accept alone serve local unix/XPC sockets too.
        self.assertEqual(target.rce_findings, [])
        target = _target(
            sockets={},
            libs=("/System/Library/Frameworks/Network.framework/Versions/A/Network",),
            imports=("bind", "accept", "xar_open"),
        )
        self.assertEqual(len(target.rce_findings), 1)
        self.assertEqual(target.rce_findings[0].ingress_kind, "listener_api")

    def test_refresh_recomputes_after_validation_change(self):
        target = _target(
            sockets={"Listener": {"SockServiceName": "foo"}},
            imports=("xar_open",),
        )
        target.rce_findings = []
        refresh_rce_findings([target])
        self.assertEqual(len(target.rce_findings), 1)


class TestRCEIntegration(unittest.TestCase):
    def test_json_summary_target_include_rce_layer(self):
        target = _target(
            sockets={"Listener": {"SockServiceName": "foo"}},
            imports=("xar_open",),
        )
        report = build_report([target])
        self.assertEqual(report["schema_version"], "2.2")
        self.assertGreaterEqual(report["summary"]["rce_findings"], 1)
        self.assertEqual(len(report["targets"][0]["rce_findings"]), 1)

    def test_export_and_hunt_use_structured_rce_findings(self):
        target = _target(
            sockets={"Listener": {"SockServiceName": "foo"}},
            imports=("xar_open",),
        )
        report = build_report([target])
        table_names = {name for name, _headers, _rows in build_tables(report)}
        self.assertIn("rce_findings", table_names)
        scored = score_target(report["targets"][0])
        self.assertIsNotNone(scored)
        self.assertEqual(scored.rce, target.rce_findings[0].score)
        self.assertGreaterEqual(scored.rce, 40)
        text = format_rce_text([scored])
        self.assertIn("NETWORK_LISTENER", text)
        self.assertIn("NETWORK INGRESS x PARSER RCE CANDIDATES", text)

    def test_html_and_single_dossier_render_rce_section(self):
        target = _target(
            sockets={"Listener": {"SockServiceName": "foo"}},
            imports=("xar_open", "xar_extract_toBuffer"),
        )
        report = build_report([target])
        scored = score_target(report["targets"][0])
        single = format_single(scored)
        self.assertIn("RCE findings", single)
        self.assertIn("NETWORK_LISTENER", single)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.html")
            write_html_report(path, report)
            with open(path, encoding="utf-8") as handle:
                html = handle.read()
        self.assertIn("RCE hunting &mdash; network ingress x parser", html)
        self.assertIn("PARSER_ARCHIVE", html)

    def test_hunt_class_rce_cli_reads_report_without_new_scan(self):
        target = _target(
            sockets={"Listener": {"SockServiceName": "foo"}},
            imports=("xar_open",),
        )
        report = build_report([target])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            write_json_report(path, report)
            args = tbm.build_parser().parse_args([
                "hunt", "--report", path, "--class", "rce", "--top", "5",
            ])
            output = io.StringIO()
            with redirect_stdout(output):
                status = args.func(args)
        self.assertEqual(status, 0)
        self.assertIn("com.example.net-svc", output.getvalue())
        self.assertIn("NETWORK_LISTENER", output.getvalue())


if __name__ == "__main__":
    unittest.main()
