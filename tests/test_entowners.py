"""Tests for entitlement-owner report queries."""

from __future__ import annotations

import unittest

import _paths  # noqa: F401

from entowners import entowners_contains, entowners_exact


def _report():
    return {
        "targets": [
            {
                "label": "com.apple.current",
                "score": 20,
                "validation": "WEAK",
                "service": {"run_as": "current-user", "mach_services": []},
                "entitlement_findings": [{"entitlement": "com.apple.beta"}],
            },
            {
                "label": "com.apple.root",
                "score": 40,
                "validation": "NONE_OBSERVED",
                "service": {"run_as": "root", "mach_services": []},
                "entitlement_findings": [],
                "executable": {
                    "codesign": {
                        "entitlements": {
                            "com.apple.alpha": True,
                            "com.apple.beta": True,
                        }
                    }
                },
            },
        ]
    }


class TestEntowners(unittest.TestCase):
    def test_exact_matches_findings_and_codesign(self):
        rows = entowners_exact(_report(), "com.apple.alpha")
        self.assertEqual([r["label"] for r in rows], ["com.apple.root"])

    def test_exact_deduplicates_duplicate_sources(self):
        rows = entowners_exact(_report(), "com.apple.beta")
        self.assertEqual([r["label"] for r in rows], ["com.apple.root",
                                                       "com.apple.current"])
        self.assertEqual(rows[0]["matching"], ["com.apple.beta"])

    def test_contains_collects_all_matching_keys(self):
        rows = entowners_contains(_report(), "com.apple.")
        self.assertEqual([r["label"] for r in rows], ["com.apple.root",
                                                       "com.apple.current"])
        self.assertEqual(rows[0]["matching"], ["com.apple.alpha",
                                               "com.apple.beta"])

    def test_no_match_returns_empty(self):
        self.assertEqual(entowners_exact(_report(), "com.apple.gamma"), [])


if __name__ == "__main__":
    unittest.main()
