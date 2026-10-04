"""Tests for the deputy-chain map (deputy_all)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

import _paths  # noqa: F401

import deputy_all
from graph.query import TrustGraph


def _graph():
    return {
        "nodes": [
            {"id": "service:com.example.rootd", "type": "LaunchService",
             "label": "com.example.rootd",
             "data": {"privileged": True, "enabled": True, "score": 100,
                      "validation": "NONE_OBSERVED", "run_as_user": "root"}},
            {"id": "exec:/usr/libexec/rootd", "type": "Executable",
             "label": "/usr/libexec/rootd",
             "data": {"privileged": True, "service": "com.example.rootd",
                      "run_as_user": "root"}},
            {"id": "mach:com.example.rootd", "type": "MachService",
             "label": "com.example.rootd"},
            {"id": "exec:/usr/libexec/setupagent", "type": "Executable",
             "label": "/usr/libexec/setupagent",
             "data": {"privileged": False, "service": "com.example.setupagent",
                      "run_as_user": "current-user", "validation": "STRONG"}},
            {"id": "exec:/usr/libexec/bystander", "type": "Executable",
             "label": "/usr/libexec/bystander",
             "data": {"privileged": False, "service": "com.example.other",
                      "run_as_user": "current-user"}},
            {"id": "ent:com.example.rootd.spi", "type": "Entitlement",
             "label": "com.example.rootd.spi"},
            {"id": "ent:com.example.rootd.bridge", "type": "Entitlement",
             "label": "com.example.rootd.bridge"},
        ],
        "edges": [
            {"source": "exec:/usr/libexec/rootd", "target": "service:com.example.rootd",
             "type": "LAUNCHED_BY", "label": "launched by", "data": {}},
            {"source": "service:com.example.rootd", "target": "mach:com.example.rootd",
             "type": "PROVIDES", "label": "provides", "data": {}},
            {"source": "exec:/usr/libexec/setupagent", "target": "mach:com.example.rootd",
             "type": "LOOKS_UP", "label": "looks up", "data": {"evidence": "entitlement"}},
            {"source": "exec:/usr/libexec/setupagent", "target": "ent:com.example.rootd.spi",
             "type": "HAS_ENTITLEMENT", "label": "has entitlement", "data": {}},
            {"source": "exec:/usr/libexec/bystander", "target": "mach:com.example.rootd",
             "type": "LOOKS_UP", "label": "looks up", "data": {"evidence": "string"}},
            {"source": "exec:/usr/libexec/rootd", "target": "ent:com.example.rootd.bridge",
             "type": "HAS_ENTITLEMENT", "label": "has entitlement", "data": {}},
        ],
    }


class TestDeputyAll(unittest.TestCase):
    def setUp(self):
        self.tg = TrustGraph(_graph())

    def test_build_maps_chains_to_their_root(self):
        by_root = deputy_all.build(self.tg)
        self.assertIn("com.example.rootd", by_root)
        chains = by_root["com.example.rootd"]
        self.assertEqual({c[0]["client"] for c in chains}, {"com.example.rootd"})
        self.assertEqual({c[-1]["client"] for c in chains}, {"/usr/libexec/setupagent"})

    def test_counts_split_privileged_and_unprivileged_leaves(self):
        counts = deputy_all.counts(deputy_all.build(self.tg))
        self.assertEqual(counts["roots"], 1)
        self.assertEqual(counts["chains"], 1)
        self.assertEqual(counts["unprivileged_leaves"], 1)

    def test_render_text_marks_unprivileged_leaves(self):
        text = deputy_all.render_text(deputy_all.build(self.tg), limit=5)
        self.assertIn("[UNPRIV]", text)
        self.assertIn("com.example.rootd", text)

    def test_write_outputs_round_trips_json(self):
        by_root = deputy_all.build(self.tg)
        with tempfile.TemporaryDirectory() as tmp:
            prefix = os.path.join(tmp, "deputy-all")
            deputy_all.write_outputs(by_root, prefix)
            for ext in (".json", ".csv", ".md"):
                self.assertTrue(os.path.exists(prefix + ext))
            with open(prefix + ".json", encoding="utf-8") as fh:
                loaded = json.load(fh)
            self.assertEqual(set(loaded), set(by_root))


if __name__ == "__main__":
    unittest.main()
