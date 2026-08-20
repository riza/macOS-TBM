"""Tests for the active Mach-service probe.

The XPC layer is mocked with a fake backend so these are deterministic and need
neither root nor a live system: they pin the classification decision tree, the
sub-probe sequencing, service selection, and the two output formats.
"""

from __future__ import annotations

import json
import unittest

import _paths  # noqa: F401

from probes.classify import (
    BUCKETS,
    REACHABLE_BUCKETS,
    classify,
    format_json,
    format_text,
    probe_service,
    run_probe,
    services_from_report,
    summarize,
)


class FakeBackend:
    """Scripts fixed outcomes for connect/send, and records the call order.

    ``connect`` is a single outcome; ``sends`` is consumed one per send_probe
    call (first empty, then malformed).
    """

    def __init__(self, connect="alive", sends=("silent", "silent"), error=""):
        self._connect = connect
        self._sends = list(sends)
        self.last_error = error
        self.calls = []

    def connect_probe(self, name, timeout):
        self.calls.append(("connect", name))
        return self._connect

    def send_probe(self, name, payload, timeout):
        self.calls.append(("send", "empty" if payload is None else "malformed"))
        return self._sends.pop(0) if self._sends else "silent"


class TestClassify(unittest.TestCase):
    def test_unreachable_when_connect_is_invalid(self):
        self.assertEqual(classify("invalid", "invalid", "invalid"), "unreachable")

    def test_empty_interrupt_beats_everything_below_it(self):
        self.assertEqual(classify("alive", "interrupted", "silent", spawned=True),
                         "empty-interrupted")

    def test_malformed_interrupt(self):
        self.assertEqual(classify("alive", "silent", "interrupted"), "malformed-interrupted")

    def test_reply_is_spawn(self):
        self.assertEqual(classify("alive", "reply", "silent"), "spawn")
        self.assertEqual(classify("alive", "silent", "reply"), "spawn")

    def test_running_provider_with_silent_sends_is_spawn(self):
        self.assertEqual(classify("alive", "silent", "silent", spawned=True), "spawn")

    def test_alive_and_tolerant_is_connect_alive(self):
        self.assertEqual(classify("alive", "silent", "silent", spawned=False), "connect-alive")

    def test_timeout_is_the_degenerate_fallback(self):
        # connect neither invalid nor alive: nothing responded at all.
        self.assertEqual(classify("timeout", "silent", "silent", spawned=False), "timeout")

    def test_interrupt_outranks_spawn(self):
        # A running daemon that still drops our empty message is empty-interrupted,
        # not spawn — the sharper signal wins.
        self.assertEqual(classify("alive", "interrupted", "silent", spawned=True),
                         "empty-interrupted")

    def test_every_bucket_is_reachable(self):
        produced = {
            classify("invalid", "invalid", "invalid"),
            classify("alive", "interrupted", "silent"),
            classify("alive", "silent", "interrupted"),
            classify("alive", "reply", "silent"),
            classify("alive", "silent", "silent", spawned=False),
            classify("timeout", "silent", "silent"),
        }
        self.assertEqual(produced, set(BUCKETS))


class TestProbeService(unittest.TestCase):
    def test_invalid_connection_skips_the_sends(self):
        backend = FakeBackend(connect="invalid", error="Connection invalid")
        row = probe_service(backend, "com.x", "prov", "root", timeout=0.01)
        self.assertEqual(row["classification"], "unreachable")
        self.assertEqual([c[0] for c in backend.calls], ["connect"])  # no sends
        self.assertEqual(row["error_message"], "Connection invalid")

    def test_empty_interrupt_does_not_send_malformed(self):
        backend = FakeBackend(connect="alive", sends=["interrupted"], error="Connection interrupted")
        row = probe_service(backend, "com.x", "prov", "root", timeout=0.01)
        self.assertEqual(row["classification"], "empty-interrupted")
        # exactly one send (empty); malformed is only tried when empty is inconclusive
        self.assertEqual(sum(1 for c in backend.calls if c[0] == "send"), 1)

    def test_escalates_to_malformed_when_empty_is_silent(self):
        backend = FakeBackend(connect="alive", sends=["silent", "interrupted"],
                              error="Connection interrupted")
        row = probe_service(backend, "com.x", "prov", "root", timeout=0.01)
        self.assertEqual(row["classification"], "malformed-interrupted")
        self.assertEqual([c[1] for c in backend.calls if c[0] == "send"], ["empty", "malformed"])

    def test_liveness_promotes_silent_to_spawn(self):
        backend = FakeBackend(connect="alive", sends=["silent", "silent"])
        row = probe_service(backend, "com.x", "prov", "root", timeout=0.01,
                            liveness=lambda label: True)
        self.assertEqual(row["classification"], "spawn")
        self.assertTrue(row["detail"]["spawned"])

    def test_connect_alive_when_not_running(self):
        backend = FakeBackend(connect="alive", sends=["silent", "silent"])
        row = probe_service(backend, "com.x", "prov", "root", timeout=0.01,
                            liveness=lambda label: False)
        self.assertEqual(row["classification"], "connect-alive")


class TestServiceSelection(unittest.TestCase):
    def _report(self):
        return {"targets": [
            {"label": "root.one", "service": {"label": "root.one", "run_as_user": "root",
                                              "mach_services": ["com.a", "com.b"]}},
            {"label": "user.svc", "service": {"label": "user.svc", "run_as_user": "current-user",
                                              "mach_services": ["com.c"]}},
            {"label": "root.two", "service": {"label": "root.two", "run_as": "root",
                                              "mach_services": ["com.b", "com.d"]}},
            {"label": "root.none", "service": {"label": "root.none", "run_as_user": "root",
                                               "mach_services": []}},
        ]}

    def test_only_root_services_with_mach_names(self):
        rows = services_from_report(self._report())
        names = [r["mach_service"] for r in rows]
        self.assertIn("com.a", names)
        self.assertNotIn("com.c", names)          # user service excluded
        self.assertEqual(len(names), len(set(names)))  # de-duplicated (com.b once)

    def test_dedup_keeps_first_provider(self):
        rows = services_from_report(self._report())
        comb = next(r for r in rows if r["mach_service"] == "com.b")
        self.assertEqual(comb["provider_label"], "root.one")

    def test_filter_by_label_substring(self):
        rows = services_from_report(self._report(), only=["root.two"])
        self.assertEqual({r["provider_label"] for r in rows}, {"root.two"})


class TestFormatting(unittest.TestCase):
    def _rows(self):
        backend_rows = [
            probe_service(FakeBackend("alive", ["interrupted"], "Connection interrupted"),
                          "com.reach", "prov.a", "root", 0.01),
            probe_service(FakeBackend("invalid", error="Connection invalid"),
                          "com.gone", "prov.b", "root", 0.01),
            probe_service(FakeBackend("alive", ["silent", "silent"]),
                          "com.hold", "prov.c", "root", 0.01, liveness=lambda l: False),
        ]
        return backend_rows

    def test_summary_counts_and_shortlist(self):
        summary = summarize(self._rows())
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["counts"]["empty-interrupted"], 1)
        self.assertEqual(summary["counts"]["unreachable"], 1)
        self.assertEqual(summary["counts"]["connect-alive"], 1)
        reachable = {r["mach_service"] for r in summary["reachable"]}
        self.assertEqual(reachable, {"com.reach", "com.hold"})
        for item in summary["reachable"]:
            self.assertIn(item["classification"], REACHABLE_BUCKETS)

    def test_json_shape_and_columns(self):
        payload = json.loads(format_json(self._rows()))
        self.assertEqual(payload["probed"], 3)
        self.assertEqual(set(payload["results"][0]),
                         {"mach_service", "provider_label", "run_as", "classification", "error_message"})
        self.assertEqual(payload["summary"]["total"], 3)

    def test_text_names_the_reachable_set_and_active_nature(self):
        text = format_text(self._rows())
        self.assertIn("ACTIVE", text)
        self.assertIn("com.reach", text)
        self.assertIn("actually reachable", text)

    def test_text_handles_no_rows(self):
        self.assertIn("no root/system", format_text([]))


class TestRunProbe(unittest.TestCase):
    def test_limit_caps_the_run(self):
        services = [{"mach_service": f"com.{i}", "provider_label": "p", "run_as": "root"}
                    for i in range(10)]
        rows = run_probe(services, FakeBackend("alive", ["interrupted"]), timeout=0.01, limit=3)
        self.assertEqual(len(rows), 3)

    def test_progress_callback_fires_per_service(self):
        services = [{"mach_service": "com.a", "provider_label": "p", "run_as": "root"},
                    {"mach_service": "com.b", "provider_label": "p", "run_as": "root"}]
        seen = []
        run_probe(services, FakeBackend("alive", ["interrupted"]), timeout=0.01,
                  progress=lambda i, n: seen.append((i, n)))
        self.assertEqual(seen, [(1, 2), (2, 2)])


if __name__ == "__main__":
    unittest.main()
