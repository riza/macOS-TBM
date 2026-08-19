"""Tests for entitlement categorization and scoring."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

import _paths  # noqa: F401

from analyzers.entitlements import analyze_entitlements, categorize_key
from analyzers.scoring import ScoringEngine


class TestEntitlements(unittest.TestCase):
    def test_private_apple(self):
        cat, sens = categorize_key("com.apple.private.tcc.allow")
        self.assertEqual(cat, "tcc_privacy")
        self.assertGreater(sens, 0)

    def test_keychain_group(self):
        cat, _ = categorize_key("keychain-access-groups")
        self.assertEqual(cat, "keychain_access_group")

    def test_security_entitlement(self):
        cat, _ = categorize_key("com.apple.security.app-sandbox")
        self.assertEqual(cat, "sandbox")

    def test_other_fallback(self):
        cat, _ = categorize_key("com.example.custom")
        self.assertEqual(cat, "other")

    def test_high_value(self):
        result = analyze_entitlements({"com.apple.private.foo": True, "com.apple.security.app-sandbox": True})
        self.assertIn("com.apple.private.foo", result.high_value)
        self.assertNotIn("com.apple.security.app-sandbox", result.high_value)


def _service(**kw):
    base = dict(
        label="t", is_privileged=False, exposes_ipc=False, mach_services=[], sockets={}
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _ent(high_value=(), categorized=None):
    return SimpleNamespace(high_value=list(high_value), categorized=categorized or {})


def _assessment(sink, *evidence):
    """Build a SinkAssessment from (kind, name) pairs."""
    from models.evidence import Evidence, SinkAssessment
    from analyzers.sinks import SINK_LABELS
    return SinkAssessment(
        sink=sink,
        label=SINK_LABELS.get(sink, sink.upper()),
        evidence=[Evidence(kind, name, name) for kind, name in evidence],
    )


def _signals(assessments=(), caller_validation=(), validation="NONE_OBSERVED"):
    assessments = list(assessments)
    return SimpleNamespace(
        assessments=assessments,
        sensitive={a.sink: [e.needle for e in a.evidence] for a in assessments},
        caller_validation=list(caller_validation),
        validation=validation,
        by_sink=lambda: {a.sink: a for a in assessments},
    )


def _ipc(classification="unknown-ipc-participant"):
    return SimpleNamespace(classification=classification)


class TestScoring(unittest.TestCase):
    def setUp(self):
        self.engine = ScoringEngine()

    def test_empty_target_zero(self):
        r = self.engine.score(_service(), _ipc(), _ent(), _signals())
        self.assertEqual(r.score, 0)

    def test_privileged_exposes_entitlement(self):
        r = self.engine.score(
            _service(is_privileged=True, exposes_ipc=True, mach_services=["com.x"]),
            _ipc("mach-service-provider"),
            _ent(high_value=["com.apple.private.x"]),
            _signals(),
        )
        # +20 privileged +20 ipc +15 entitlement = 55
        self.assertEqual(r.score, 55)

    def test_caller_validation_does_not_move_the_score(self):
        """Absence of a static signal says nothing about the service."""
        from models.evidence import IMPORT
        base = self.engine.score(_service(is_privileged=True), _ipc(), _ent(), _signals())
        validated = self.engine.score(
            _service(is_privileged=True), _ipc(), _ent(),
            _signals(caller_validation=["SecTaskCopyValueForEntitlement", "audit_token_to_euid"],
                     validation="STRONG"),
        )
        self.assertEqual(base.score, validated.score)
        self.assertEqual(base.score, 20)

    def test_sinks_scale_with_confidence(self):
        from models.evidence import IMPORT
        # Two imports each: HIGH confidence, so the full rule weight applies.
        r = self.engine.score(
            _service(), _ipc(), _ent(),
            _signals([_assessment("account", (IMPORT, "ODRecordCopyValues"), (IMPORT, "ODSessionCreate")),
                      _assessment("network", (IMPORT, "socket"), (IMPORT, "connect"))]),
        )
        # +15 account_credential +10 network = 25
        self.assertEqual(r.score, 25)

    def test_a_library_only_sink_scores_a_fraction(self):
        from models.evidence import LIBRARY
        r = self.engine.score(
            _service(), _ipc(), _ent(),
            _signals([_assessment("network", (LIBRARY, "CFNetwork"))]),
        )
        # LOW confidence: 30% of the +10 network weight
        self.assertEqual(r.score, 3)
        self.assertIn("LOW", r.reasons[0].reason)

    def test_reasons_explainable(self):
        r = self.engine.score(_service(is_privileged=True), _ipc(), _ent(), _signals())
        self.assertTrue(any("root" in reason.reason for reason in r.reasons))


if __name__ == "__main__":
    unittest.main()
