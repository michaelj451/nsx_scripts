"""Rollback safety, after 2026-09-28: WF-A's rules baseline (for lm2) and WF-D's
D3 baselines (for lm1) shared nsx_rules_export/nsx-lm1.lab.local/, where a
rollback takes the newest. An A rollback would have restored lm1's rules onto
lm2; a D3 rollback could have reached A's empty baseline and deleted every rule
on lm1, because the rules rollback deleted every rule its baseline lacked.

Now:
1. every apply records, beside its baseline, the manager it was taken from,
   and every rollback refuses another manager's baseline before sending anything;
2. a rules rollback deletes only the rules its push created;
3. C5 / D3 keep their rules baselines in their own run directory.
"""
import contextlib
import copy
import importlib.util
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "tools/nsx"))

from nsx import baseline_meta  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(f"rbs_{name}", ROOT / f"tools/nsx/{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


TOOLS = {n: load(n) for n in ("services", "groups", "policies", "rules")}
workflow = load("run_workflow")
HOST = "lm2.test"


def dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


class MetaTests(unittest.TestCase):

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.b = Path(t.name) / "20260928_194939_target_baseline.json"
        self.b.write_text("{}")

    def test_meta_sits_beside_the_baseline_and_survives_revert_rename(self):
        self.assertEqual(baseline_meta.meta_path(self.b).name, "20260928_194939_target_meta.json")
        reverted = self.b.with_name(self.b.name + ".reverted")
        self.assertEqual(baseline_meta.meta_path(reverted).name, "20260928_194939_target_meta.json")

    def test_matching_manager_is_allowed(self):
        baseline_meta.write_meta(self.b, target_host=HOST, step="rules.push")
        self.assertIsNone(baseline_meta.refuse_reason(self.b, HOST, explicit=False))

    def test_other_manager_is_refused_even_when_named(self):
        baseline_meta.write_meta(self.b, target_host="lm1.test", step="rules.amend-refs")
        for explicit in (False, True):
            why = baseline_meta.refuse_reason(self.b, HOST, explicit=explicit)
            self.assertIn("lm1.test", why)
            self.assertIn("rules.amend-refs", why)

    def test_unrecorded_baseline_needs_to_be_named(self):
        self.assertIn("--from-baseline", baseline_meta.refuse_reason(self.b, HOST, explicit=False))
        self.assertIsNone(baseline_meta.refuse_reason(self.b, HOST, explicit=True))


class RevertTests(unittest.TestCase):
    """Drives each tool's real `revert` against a fake target."""

    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)

    def revert(self, name, *, baseline, current, meta_host=HOST, pushed=None,
               extra=(), explicit=False):
        mod = TOOLS[name]
        reports = self.root / name / "push_report"
        b = reports / "baselines" / "20260928_120000_target_baseline.json"
        dump(b, baseline)
        if meta_host:
            baseline_meta.write_meta(b, target_host=meta_host, step=f"{name}.push")
        if pushed is not None:
            dump(b.with_name("20260928_120000_pushed_ids.json"), pushed)
        writes, clients = [], []

        class Client:
            def __init__(self, **kwargs):
                clients.append(kwargs)

            def __getattr__(self, method):
                if not method.startswith(("put_", "patch_", "delete_")):
                    raise AssertionError(f"Unexpected API call: {method}")
                return lambda *a, **k: writes.append((method, k.get("rule_id") or (a[0] if a else None)))

        def setup_logging(directory, label):
            directory.mkdir(parents=True, exist_ok=True)
            return directory / "t.log", directory / "e.log"

        argv = [name, "revert", "--target", "nsx-lm2", "--reports-dir", str(reports), "--apply",
                *extra] + (["--from-baseline", str(b)] if explicit else [])
        with contextlib.ExitStack() as s:
            s.enter_context(patch.object(mod, "NsxPolicyClient", Client))
            s.enter_context(patch.object(mod, f"_capture_target_{name}",
                                         return_value=copy.deepcopy(current)))
            if hasattr(mod, "target_ref_names"):
                s.enter_context(patch.object(mod, "target_ref_names", return_value={}))
            s.enter_context(patch.object(mod, "_setup_logging", setup_logging))
            s.enter_context(patch.object(mod, "resolve_manager", return_value=HOST))
            s.enter_context(patch.object(mod, "init_cli"))
            s.enter_context(patch.object(mod.time, "sleep"))
            s.enter_context(patch("builtins.input", side_effect=itertools.repeat("")))
            s.enter_context(patch.object(sys, "argv", argv))
            rc = mod.main()
        summaries = sorted(reports.glob("revert_summary_*.json"))
        return rc, writes, (json.loads(summaries[-1].read_text()) if summaries else None), b

    def test_every_tool_refuses_another_managers_baseline(self):
        for name in TOOLS:
            with self.subTest(tool=name):
                rc, writes, summary, b = self.revert(name, baseline={}, current={},
                                                     meta_host="lm1.test")
                self.assertEqual(rc, 2)
                self.assertEqual(writes, [])
                self.assertTrue(b.exists(), "a refused baseline must not be consumed")

    def test_every_tool_refuses_an_unrecorded_baseline_unless_named(self):
        for name in TOOLS:
            with self.subTest(tool=name):
                rc, writes, _, _ = self.revert(name, baseline={}, current={}, meta_host=None)
                self.assertEqual(rc, 2)
                self.assertEqual(writes, [])

    def test_a_named_unrecorded_baseline_is_used(self):
        rc, writes, summary, _ = self.revert("services", baseline={}, current={},
                                             meta_host=None, explicit=True)
        self.assertEqual(rc, 0)

    RULE = {"policy_id": "p0", "rule_id": "r", "payload": {"id": "r", "resource_type": "Rule"}}

    def _rule(self, rid):
        r = copy.deepcopy(self.RULE)
        r["rule_id"] = rid
        r["payload"]["id"] = rid
        return r

    def test_rules_rollback_deletes_only_what_its_push_created(self):
        current = {"p0::mine": self._rule("mine"), "p0::theirs": self._rule("theirs")}
        rc, writes, summary, _ = self.revert("rules", baseline={}, current=current,
                                             pushed=["p0::mine"])
        self.assertEqual(rc, 0)
        self.assertEqual(writes, [("delete_security_rule", "mine")])
        self.assertEqual(summary["deletes_blocked"], ["p0::theirs"])

    def test_rules_rollback_without_created_record_deletes_nothing(self):
        # The empty-baseline case that would have wiped every rule on lm1.
        current = {f"p0::r{i}": self._rule(f"r{i}") for i in range(4)}
        rc, writes, summary, _ = self.revert("rules", baseline={}, current=current)
        self.assertEqual(rc, 0)
        self.assertEqual(writes, [])
        self.assertEqual(len(summary["deletes_blocked"]), 4)


class RulesPushRecordsTests(unittest.TestCase):
    """A rules push writes the manager record and the rules it created."""

    def test_push_records_manager_and_created_rules(self):
        mod = TOOLS["rules"]
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            data, reports = root / "data", root / "reports"
            for rid in ("new", "old"):
                dump(data / "p0" / "rules" / f"{rid}.json",
                     {"id": rid, "display_name": rid, "resource_type": "Rule",
                      "_parent_policy_id": "p0", "action": "ALLOW"})
            existing = {"p0::old": {"policy_id": "p0", "rule_id": "old",
                                    "payload": {"id": "old", "resource_type": "Rule",
                                                "action": "DROP"}}}

            class Client:
                def __init__(self, **kwargs):
                    pass

                def __getattr__(self, method):
                    if not method.startswith(("put_", "patch_")):
                        raise AssertionError(f"Unexpected API call: {method}")
                    return lambda *a, **k: None

            def setup_logging(directory, label):
                directory.mkdir(parents=True, exist_ok=True)
                return directory / "t.log", directory / "e.log"

            argv = ["rules", "push", "--target", "nsx-lm2", "--rules-dir", str(data),
                    "--reports-dir", str(reports), "--apply"]
            with contextlib.ExitStack() as s:
                s.enter_context(patch.object(mod, "NsxPolicyClient", Client))
                s.enter_context(patch.object(mod, "_capture_target_rules",
                                             return_value=copy.deepcopy(existing)))
                s.enter_context(patch.object(mod, "target_ref_names", return_value={}))
                s.enter_context(patch.object(mod, "_setup_logging", setup_logging))
                s.enter_context(patch.object(mod, "resolve_manager", return_value=HOST))
                s.enter_context(patch.object(mod, "init_cli"))
                s.enter_context(patch.object(mod.time, "sleep"))
                s.enter_context(patch("builtins.input", side_effect=itertools.repeat("")))
                s.enter_context(patch.object(sys, "argv", argv))
                self.assertEqual(mod.main(), 0)
            b = next((reports / "baselines").glob("*_target_baseline.json"))
            self.assertEqual(baseline_meta.read_meta(b)["target_host"], HOST)
            self.assertEqual(baseline_meta.read_meta(b)["step"], "rules.push")
            created = json.loads(b.with_name(b.name.replace("_target_baseline", "_pushed_ids")).read_text())
            self.assertEqual(created, ["p0::new"])


class DriverTests(unittest.TestCase):

    def test_amend_steps_and_their_rollbacks_use_the_run_directory(self):
        run, sib = Path("/tmp/run"), Path("/tmp/run/nsx_sibling_groups/lm1.test")
        amend = workflow.amend_dir(run, "lm2.test")
        self.assertEqual(amend, run / "rules_amend" / "lm2.test")
        c5 = workflow.phase_c_steps("lm1.test", "nsx-lm2", True, sib, "lm2.test", amend)[1]
        d3 = workflow.phase_d_steps("d3", "nsx-lm2", True, sib, "lm2.test", amend)[0]
        for step in (c5, d3):
            cmd = step["cmd"]
            self.assertEqual(cmd[cmd.index("--reports-dir") + 1], str(amend / "push_report"))
            self.assertEqual(step["roots"], [str(amend)])
        for phase in ("c", "d3"):
            rb = [s for s in workflow.rollback_steps(phase, "nsx-lm2", True, sib, "lm1.test",
                                                     "lm2.test", amend)
                  if s["label"].endswith("amend_revert")][0]["cmd"]
            self.assertEqual(rb[rb.index("--reports-dir") + 1], str(amend / "push_report"))
        a4 = [s for s in workflow.rollback_steps("a", "nsx-lm2", True, sib, "lm1.test",
                                                 "lm2.test", amend)
              if s["label"] == "a4_rules_revert"][0]["cmd"]
        self.assertEqual(a4[a4.index("--reports-dir") + 1], "nsx_rules_export/lm1.test/push_report")


if __name__ == "__main__":
    unittest.main()
