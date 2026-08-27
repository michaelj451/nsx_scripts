#!/usr/bin/env python3
"""
tests/test_transform_gm_export_to_lm.py

Offline tests for the GM -> LM export transform. No NSX calls.

    python -m unittest tests/test_transform_gm_export_to_lm.py -v
"""

from __future__ import annotations

import importlib.util
import logging
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "app") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "app"))

logging.disable(logging.CRITICAL)


def _load():
    spec = importlib.util.spec_from_file_location(
        "transform_gm_export_to_lm", REPO_ROOT / "tools" / "nsx" / "transform_gm_export_to_lm.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


t = _load()


class RewriteTests(unittest.TestCase):
    def test_surface_rewrite(self):
        s, n = t.rewrite_string("/global-infra/domains/default/groups/vm1", None, None)
        self.assertEqual((s, n), ("/infra/domains/default/groups/vm1", 1))
        s, n = t.rewrite_string("/global-infra/services/svc-a", None, None)
        self.assertEqual((s, n), ("/infra/services/svc-a", 1))

    def test_bare_root_parent_path(self):
        self.assertEqual(t.rewrite_string("/global-infra", None, None), ("/infra", 1))

    def test_non_paths_untouched(self):
        for v in ("ANY", "vm1", "10.6.0.0/24", "/infra/domains/default/groups/vm1"):
            s, n = t.rewrite_string(v, None, None)
            self.assertEqual((s, n), (v, 0))

    def test_domain_rename_applies_after_surface(self):
        s, n = t.rewrite_string("/global-infra/domains/nsx-lm1.lab.local/groups/g",
                                "nsx-lm1.lab.local", "default")
        self.assertEqual(s, "/infra/domains/default/groups/g")
        self.assertEqual(n, 2)

    def test_domain_rename_leaves_other_domains(self):
        s, n = t.rewrite_string("/infra/domains/other/groups/g", "nsx-lm1.lab.local", "default")
        self.assertEqual((s, n), ("/infra/domains/other/groups/g", 0))

    def test_payload_recursion(self):
        rule = {
            "id": "r1",
            "source_groups": ["/global-infra/domains/default/groups/a", "ANY"],
            "scope": ["/global-infra/domains/default/groups/b"],
            "services": ["/global-infra/services/s1"],
            "nested": {"list": [{"path": "/global-infra/domains/default/groups/c"}]},
            "logged": False,
            "sequence_number": 10,
        }
        out, n = t.rewrite_payload(rule, None, None)
        self.assertEqual(n, 4)
        self.assertEqual(out["source_groups"], ["/infra/domains/default/groups/a", "ANY"])
        self.assertEqual(out["services"], ["/infra/services/s1"])
        self.assertEqual(out["nested"]["list"][0]["path"], "/infra/domains/default/groups/c")
        self.assertEqual(out["logged"], False)
        self.assertEqual(out["sequence_number"], 10)


class TreeTests(unittest.TestCase):
    def test_transform_tree_layout_counts_and_exclusions(self):
        src = Path(tempfile.mkdtemp())
        (src / "sub").mkdir()
        (src / "g.yaml").write_text(yaml.safe_dump({
            "id": "g", "expression": [
                {"resource_type": "PathExpression",
                 "paths": ["/global-infra/domains/default/groups/other"]},
            ],
        }, sort_keys=False))
        (src / "sub" / "r.json").write_text('{"scope": ["/global-infra/services/x"]}')
        (src / "plain.yaml").write_text(yaml.safe_dump({"id": "plain", "note": "no refs"}))
        (src / "push_report").mkdir()
        (src / "push_report" / "row.json").write_text('{"x": "/global-infra/services/x"}')

        dst = Path(tempfile.mkdtemp()) / "out"
        result = t.transform_tree(src, dst, source_domain=None, target_domain=None)
        self.assertEqual(result["files_seen"], 3)
        self.assertEqual(result["files_changed"], 2)
        self.assertEqual(result["refs_rewritten"], 2)
        self.assertEqual(result["parse_errors"], [])
        g = yaml.safe_load((dst / "g.yaml").read_text())
        self.assertEqual(g["expression"][0]["paths"], ["/infra/domains/default/groups/other"])
        self.assertTrue((dst / "sub" / "r.json").exists())
        self.assertTrue((dst / "plain.yaml").exists())
        self.assertFalse((dst / "push_report").exists())

    def test_parse_error_reported_not_fatal(self):
        src = Path(tempfile.mkdtemp())
        (src / "bad.json").write_text("{not json")
        (src / "ok.yaml").write_text(yaml.safe_dump({"id": "ok"}))
        dst = Path(tempfile.mkdtemp()) / "out"
        result = t.transform_tree(src, dst, source_domain=None, target_domain=None)
        self.assertEqual(len(result["parse_errors"]), 1)
        self.assertTrue((dst / "ok.yaml").exists())
        self.assertFalse((dst / "bad.json").exists())


if __name__ == "__main__":
    unittest.main()
