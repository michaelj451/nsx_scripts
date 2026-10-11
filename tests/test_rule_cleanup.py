"""Unused rule cleanup (app/nsx/rule_cleanup.py and tools/nsx/rule_cleanup/),
Mike 2026-10-10: step 1 disables never-hit rules, step 2 deletes them, then
empty policies and unreferenced groups. Services are never touched.

Covers: rule classes (a missing counter row is never "0 hits"), comparisons
that ignore NSX bookkeeping, write payloads (_revision kept on update, dropped
on create, a policy re-created without its rules), group references (own path
ignored, nested, load balancer, gateway, NSX's own groups), delete order
(parents before nested groups), the step 2 planner, restore order, and the
apply paths of both steps and both undos against an in-memory manager.
"""
import builtins
import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import nsx.rule_cleanup as rc  # noqa: E402

G = "/infra/domains/default/groups/"


def load_script(name):
    spec = importlib.util.spec_from_file_location(f"rule_cleanup_{name}",
                                                  ROOT / "tools/nsx/rule_cleanup" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeErr(Exception):
    def __init__(self, code, msg=""):
        self.status_code = code
        super().__init__(f"[HTTP {code}] {msg}")


def rule(rid, irid, src=("ANY",), dst=("ANY",), action="ALLOW", disabled=False, seq=10, rev=0):
    return {"id": rid, "rule_id": irid, "display_name": rid, "action": action, "sequence_number": seq,
            "source_groups": list(src), "destination_groups": list(dst), "services": ["ANY"],
            "scope": ["ANY"], "disabled": disabled, "_revision": rev, "_create_time": 0,
            "path": f"/infra/domains/default/security-policies/p/rules/{rid}"}


def group(gid, nested=(), system=False):
    g = {"id": gid, "display_name": gid, "path": G + gid, "_revision": 0,
         "expression": [{"resource_type": "PathExpression", "paths": [G + n for n in nested]}] if nested else []}
    if system:
        g["_system_owned"] = True
    return g


class FakeNsx:
    """Just enough of NsxPolicyClient for these scripts, kept in memory."""

    def __init__(self, policies, rules, groups, extra=None):
        self.policies = {p["id"]: copy.deepcopy(p) for p in policies}
        self.rules = {pid: {r["id"]: copy.deepcopy(r) for r in rs} for pid, rs in rules.items()}
        self.groups = {g["id"]: copy.deepcopy(g) for g in groups}
        self.extra = extra or {}
        self.writes = []
        self._next_irid = 9000

    _q = staticmethod(lambda v: v)

    def _policy_path(self, suffix):
        return suffix

    def _get_all_results(self, path):
        v = self.extra.get(path, 404)
        if isinstance(v, int):
            raise FakeErr(v, "not here")
        return copy.deepcopy(v)

    def _get(self, path):
        return self._get_all_results(path)

    def list_security_policies(self, domain_id="default"):
        return [copy.deepcopy(p) for p in self.policies.values()]

    def list_security_rules(self, security_policy_id, domain_id="default"):
        return [copy.deepcopy(r) for r in self.rules.get(security_policy_id, {}).values()]

    def list_groups(self, domain_id="default"):
        return [copy.deepcopy(g) for g in self.groups.values()]

    def get_security_rule(self, security_policy_id, rule_id, domain_id="default"):
        try:
            return copy.deepcopy(self.rules[security_policy_id][rule_id])
        except KeyError:
            raise FakeErr(404, "rule not found")

    def put_security_rule(self, security_policy_id, rule_id, payload, domain_id="default"):
        cur = self.rules.setdefault(security_policy_id, {}).get(rule_id)
        if cur is not None and payload.get("_revision") != cur["_revision"]:
            raise FakeErr(412, "revision mismatch")
        new = copy.deepcopy(payload)
        if cur is None:
            self._next_irid += 1
            new["rule_id"] = self._next_irid
        new["_revision"] = (cur["_revision"] + 1) if cur else 0
        self.rules[security_policy_id][rule_id] = new
        self.writes.append(("put_rule", security_policy_id, rule_id))

    def delete_security_rule(self, security_policy_id, rule_id, domain_id="default"):
        del self.rules[security_policy_id][rule_id]
        self.writes.append(("delete_rule", security_policy_id, rule_id))

    def get_security_policy(self, security_policy_id, domain_id="default"):
        if security_policy_id not in self.policies:
            raise FakeErr(404, "policy not found")
        p = copy.deepcopy(self.policies[security_policy_id])
        p["rules"] = self.list_security_rules(security_policy_id)
        p["rule_count"] = len(p["rules"])
        return p

    def put_security_policy(self, security_policy_id, payload, domain_id="default"):
        assert "rules" not in payload and "rule_count" not in payload
        self.policies[security_policy_id] = copy.deepcopy(payload)
        self.rules.setdefault(security_policy_id, {})
        self.writes.append(("put_policy", security_policy_id))

    def delete_security_policy(self, security_policy_id, domain_id="default"):
        del self.policies[security_policy_id]
        self.rules.pop(security_policy_id, None)
        self.writes.append(("delete_policy", security_policy_id))

    def get_group(self, group_id, domain_id="default"):
        if group_id not in self.groups:
            raise FakeErr(404, "group not found")
        return copy.deepcopy(self.groups[group_id])

    def put_group(self, group_id, payload, domain_id="default"):
        self.groups[group_id] = copy.deepcopy(payload)
        self.writes.append(("put_group", group_id))

    def delete_group(self, group_id, domain_id="default"):
        path = G + group_id
        users = [r for rs in self.rules.values() for r in rs.values() if path in rc.group_refs(r)]
        users += [g for g in self.groups.values() if g["id"] != group_id and path in rc.group_refs(g)]
        if users:
            raise FakeErr(400, "object is being referenced by other objects (500030)")
        del self.groups[group_id]
        self.writes.append(("delete_group", group_id))


def counters(hits):
    """policy_counters stand-in: hits maps internal rule id -> hit_count (None = no row)."""
    def fake(client, policy):
        rows = {}
        for r in client.rules.get(policy["id"], {}).values():
            h = hits.get(r["rule_id"], 0)
            if h is not None:
                rows[str(r["rule_id"])] = {"hit_count": h, "packet_count": h, "byte_count": 0, "session_count": 0}
        return rows, "old_firewall_api", None
    return fake


class ClassifyTests(unittest.TestCase):
    Z = {"hit_count": 0, "packet_count": 0, "byte_count": 0, "session_count": 0}

    def test_classes(self):
        now = 40 * 86_400_000
        self.assertEqual(rc.classify(rule("a", 1), None, now_ms=now), rc.NO_STATS)
        self.assertEqual(rc.classify(rule("a", 1), {**self.Z, "packet_count": 3}, now_ms=now), rc.USED)
        self.assertEqual(rc.classify(rule("a", 1), self.Z, now_ms=now), rc.DISABLE)
        self.assertEqual(rc.classify(rule("a", 1, disabled=True), self.Z, now_ms=now), rc.ALREADY_DISABLED)
        self.assertEqual(rc.classify(rule("a", 1, action="DROP"), self.Z, now_ms=now, keep_deny=True), rc.KEEP_DENY)
        self.assertEqual(rc.classify(rule("a", 1, action="DROP"), self.Z, now_ms=now), rc.DISABLE)
        young = {**rule("a", 1), "_create_time": now - 5 * 86_400_000}
        self.assertEqual(rc.classify(young, self.Z, now_ms=now, min_age_days=30), rc.TOO_NEW)
        self.assertEqual(rc.classify(young, self.Z, now_ms=now, min_age_days=3), rc.DISABLE)

    def test_missing_counter_row_is_not_zero_hits(self):
        self.assertIsNone(rc.rule_usage(rule("a", 7), {"8": {"hit_count": 0}}))
        self.assertEqual(rc.rule_usage(rule("a", 7), {"7": {"hit_count": 0}})["hit_count"], 0)

    def test_default_sections_are_never_cleanup_policies(self):
        self.assertFalse(rc.is_cleanup_policy({"id": "default-layer3-section"}))
        self.assertFalse(rc.is_cleanup_policy({"id": "x", "is_default": True}))
        self.assertFalse(rc.is_cleanup_policy({"id": "x", "_create_user": "system"}))
        self.assertTrue(rc.is_cleanup_policy({"id": "app", "_create_user": "admin"}))


class PayloadTests(unittest.TestCase):
    def test_content_ignores_bookkeeping_and_internal_id(self):
        a = rule("r", 1, rev=3)
        b = {**rule("r", 99, rev=7), "_last_modified_time": 5}
        self.assertEqual(rc.content(a), rc.content(b))
        self.assertNotEqual(rc.content(a), rc.content({**a, "disabled": True}))
        self.assertEqual(rc.content(a, ("disabled",)), rc.content({**a, "disabled": True}, ("disabled",)))

    def test_update_keeps_revision_create_drops_it(self):
        live = {**rule("r", 1, rev=4), "_create_user": "admin", "_links": []}
        up = rc.update_payload(live, disabled=True)
        self.assertEqual((up["_revision"], up["disabled"]), (4, True))
        self.assertNotIn("_create_user", up)
        cr_ = rc.create_payload(live)
        self.assertNotIn("_revision", cr_)
        pol = rc.create_payload({"id": "p", "rules": [], "rule_count": 0, "_revision": 2}, rc.POLICY_CREATE_DROP)
        self.assertEqual(pol, {"id": "p"})


class GroupRefTests(unittest.TestCase):
    def test_refs_skip_own_path_and_find_nested_and_lb(self):
        self.assertEqual(rc.group_refs(group("a", nested=["b"])), {G + "b"})
        self.assertEqual(rc.group_refs({"id": "pool", "member_group": {"group_path": G + "c"}}), {G + "c"})
        self.assertEqual(rc.group_refs(rule("r", 1, src=[G + "x"], dst=["ANY"])), {G + "x"})

    def test_parents_first(self):
        nested = {G + "a": {G + "b"}, G + "b": {G + "c"}, G + "c": set(), G + "z": set()}
        order = rc.parents_first([G + "c", G + "z", G + "b", G + "a"], nested)
        self.assertLess(order.index(G + "a"), order.index(G + "b"))
        self.assertLess(order.index(G + "b"), order.index(G + "c"))
        self.assertEqual(sorted(order), sorted(nested))

    def test_unavailable_family_is_noted_other_errors_stop(self):
        nsx = FakeNsx([], {}, [], extra={"/domains/default/gateway-policies": [{"id": "gw"}],
                                         "/domains/default/gateway-policies/gw/rules":
                                             [{"id": "r", "source_groups": [G + "k"]}],
                                         "/settings/firewall/security/exclude-list": {"id": "x", "members": []},
                                         "/lb-pools": [], "/lb-virtual-servers": []})
        out, checked = rc.other_consumers(nsx)
        self.assertIn(G + "k", set().union(*(rc.group_refs(o["obj"]) for o in out)))
        self.assertTrue(checked["intrusion-service-policies"].startswith("not available"))
        nsx.extra["/lb-pools"] = 500
        with self.assertRaises(SystemExit):
            rc.other_consumers(nsx)


def lab_state(**over):
    """Policies: app (r-used, r-dead, r-pre), dead-pol (only r-gone), empty-pol, default L3.
    Groups: used-g (kept rule), dead-g (dead rule), child-g (nested in dead-g),
    shared-g (nested in dead-g and in used-g), gw-g (gateway rule), orphan-g, sys-g, sys-child."""
    policies = [{"id": "app", "category": "Application"}, {"id": "dead-pol", "category": "Application"},
                {"id": "empty-pol", "category": "Infrastructure"},
                {"id": "scoped", "category": "Application", "scope": [G + "scope-g"]},
                {"id": "default-layer3-section", "is_default": True}]
    rules = {"app": [rule("r-used", 1, src=[G + "used-g"]), rule("r-dead", 2, src=[G + "dead-g"], disabled=True),
                     rule("r-pre", 3, disabled=True)],
             "dead-pol": [rule("r-gone", 4, dst=[G + "dead-g"], disabled=True)],
             "empty-pol": [], "scoped": [rule("r-scoped", 5)],
             "default-layer3-section": [rule("default", 6)]}
    groups = [group("used-g", nested=["shared-g"]), group("dead-g", nested=["child-g", "shared-g"]),
              group("child-g"), group("shared-g"), group("gw-g"), group("orphan-g"), group("scope-g"),
              group("sys-g", nested=["sys-child"], system=True), group("sys-child")]
    state = {"policies": policies, "rules": rules, "groups": groups,
             "consumers": [{"kind": "gateway-policies rule", "id": "gw/r", "obj": {"source_groups": [G + "gw-g"]}}],
             "consumers_checked": {}}
    state.update(over)
    return state


def cand(state, pid, rid, origin="disabled by step 1"):
    ref = next(r for r in state["rules"][pid] if r["id"] == rid)
    return {"policy_id": pid, "rule_id": rid, "origin": origin, "reference": copy.deepcopy(ref)}


class PlanStep2Tests(unittest.TestCase):
    def test_full_plan(self):
        s = lab_state()
        plan = rc.plan_step2(s, [cand(s, "app", "r-dead"), cand(s, "dead-pol", "r-gone")], {})
        self.assertEqual({(r["policy_id"], r["rule_id"]) for r in plan["rules"]},
                         {("app", "r-dead"), ("dead-pol", "r-gone")})
        pols = {p["id"]: p["origin"] for p in plan["policies"]}
        self.assertEqual(pols, {"dead-pol": "emptied by this run", "empty-pol": "already empty"})
        groups = [g["id"] for g in plan["groups"]]
        self.assertEqual(set(groups), {"dead-g", "child-g", "orphan-g"})
        self.assertLess(groups.index("dead-g"), groups.index("child-g"))
        origin = {g["id"]: g["origin"] for g in plan["groups"]}
        self.assertEqual(origin["orphan-g"], "already unreferenced")
        self.assertEqual(origin["dead-g"], "freed by this run")
        # kept: shared-g (nested in used-g), gw-g (gateway), scope-g (policy Applied To), NSX's groups
        for kept in ("used-g", "shared-g", "gw-g", "scope-g", "sys-g", "sys-child"):
            self.assertNotIn(kept, groups)

    def test_candidates_that_must_stay(self):
        s = lab_state()
        enabled = cand(s, "app", "r-dead")
        changed = cand(s, "app", "r-dead")
        changed["reference"]["services"] = ["/infra/services/SSH"]
        gone = {"policy_id": "app", "rule_id": "nope", "origin": "x", "reference": rule("nope", 99)}
        s_en = lab_state()
        s_en["rules"]["app"][1]["disabled"] = False
        self.assertEqual(rc.plan_step2(s_en, [enabled], {})["rules_kept"][0]["reason"], "enabled again since step 1")
        self.assertEqual(rc.plan_step2(s, [changed], {})["rules_kept"][0]["reason"], "changed since step 1")
        self.assertEqual(rc.plan_step2(s, [gone], {})["rules_kept"][0]["reason"], "no longer on the manager")
        hit = rc.plan_step2(s, [cand(s, "app", "r-dead")],
                            {"app/r-dead": {"hit_count": 2, "packet_count": 2, "byte_count": 0, "session_count": 0}})
        self.assertTrue(hit["rules_kept"][0]["reason"].startswith("has hits now"))
        # a kept candidate keeps its groups and its policy
        self.assertNotIn("dead-g", [g["id"] for g in hit["groups"]])

    def test_default_section_never_deleted_even_if_empty(self):
        s = lab_state()
        s["rules"]["default-layer3-section"] = []
        self.assertNotIn("default-layer3-section", [p["id"] for p in rc.plan_step2(s, [], {})["policies"]])

    def test_restore_order(self):
        deleted = [{"kind": "rule", "policy_id": "p", "rule_id": "b", "obj": {"sequence_number": 20}},
                   {"kind": "rule", "policy_id": "p", "rule_id": "a", "obj": {"sequence_number": 10}},
                   {"kind": "policy", "policy_id": "p", "obj": {}},
                   {"kind": "group", "group_id": "parent", "obj": {}},
                   {"kind": "group", "group_id": "child", "obj": {}}]
        got = [d.get("group_id") or d.get("rule_id") or d["policy_id"] for d in rc.restore_order(deleted)]
        self.assertEqual(got, ["child", "parent", "p", "a", "b"])


class RunFolderTests(unittest.TestCase):
    def test_new_and_resolve_and_check(self):
        with tempfile.TemporaryDirectory() as t:
            base = Path(t)
            run = rc.new_run("nsx-lm2", "lm2.h", base=base)
            self.assertEqual(rc.resolve_run("nsx-lm2", base=base), run)
            rec = rc.load_record(run)
            rc.check_run(rec, "nsx-lm2", "lm2.h")
            with self.assertRaises(SystemExit):
                rc.check_run(rec, "nsx-lm2", "other.h")
            with self.assertRaises(SystemExit):
                rc.check_run(rec, "nsx-lm3", "lm2.h")
            with self.assertRaises(SystemExit):
                rc.resolve_run("nsx-lm3", base=base)

    def test_step2_candidates(self):
        with tempfile.TemporaryDirectory() as t:
            run = Path(t)
            rc.write_json(run / "step1" / "disabled.json", {"rules": [
                {"policy_id": "p", "rule_id": "a", "after": {"id": "a"}},
                {"policy_id": "p", "rule_id": "b", "after": {"id": "b"}, "reenabled_at": "x"}]})
            rc.write_json(run / "step1" / "plan.json", {"rules": [
                {"class": rc.ALREADY_DISABLED, "policy_id": "p", "rule_id": "c", "rule": {"id": "c"}},
                {"class": rc.USED, "policy_id": "p", "rule_id": "d", "rule": {"id": "d"}}]})
            got, counts = rc.step2_candidates(run, False)
            self.assertEqual([c["rule_id"] for c in got], ["a"])
            got, counts = rc.step2_candidates(run, True)
            self.assertEqual([c["rule_id"] for c in got], ["a", "c"])
            self.assertEqual(counts, {"disabled_by_step1": 1, "reenabled": 1, "pre_disabled": 1,
                                      "pre_disabled_included": 1})


class EndToEndTests(unittest.TestCase):
    """Step 1 plan + apply, undo one, step 2 plan + apply, step 2 undo, on a fake manager."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.run = Path(self.tmp.name) / "run"
        (self.run / "step1").mkdir(parents=True)
        rc.save_record(self.run, {"target": "nsx-lm2", "target_host": "h", "steps": {}, "history": []})
        s = lab_state()
        for r in s["rules"]["app"]:
            r["disabled"] = r["id"] == "r-pre"
        s["rules"]["dead-pol"][0]["disabled"] = False
        self.nsx = FakeNsx(s["policies"], s["rules"], s["groups"],
                           extra={"/domains/default/gateway-policies": [{"id": "gw"}],
                                  "/domains/default/gateway-policies/gw/rules": [{"id": "r", "source_groups": [G + "gw-g"]}]})
        self.hits = {1: 50, 2: 0, 3: 0, 4: 0, 5: 7, 6: 100}
        self.s1 = load_script("step1_disable")
        self.s2 = load_script("step2_delete")

    def tearDown(self):
        self.tmp.cleanup()

    def _step1(self):
        with patch.object(rc, "policy_counters", counters(self.hits)):
            plan = self.s1.build_plan(self.nsx, "h", 0, False)
            rc.write_json(self.run / "step1" / "plan.json", plan)
            with patch.object(builtins, "input", lambda *_: ""):
                return plan, self.s1.apply_plan(self.run, self.nsx, plan, False)

    def test_step1_disables_only_never_hit_enabled_rules(self):
        plan, res = self._step1()
        by = {e["rule_id"]: e["class"] for e in plan["rules"]}
        self.assertEqual(by, {"r-used": rc.USED, "r-dead": rc.DISABLE, "r-pre": rc.ALREADY_DISABLED,
                              "r-gone": rc.DISABLE, "r-scoped": rc.USED})
        self.assertNotIn("default", by)
        self.assertTrue(res["ok"])
        self.assertEqual(res["disabled_now"], 2)
        self.assertTrue(self.nsx.rules["app"]["r-dead"]["disabled"])
        self.assertFalse(self.nsx.rules["app"]["r-used"]["disabled"])
        # a second apply changes nothing
        with patch.object(rc, "policy_counters", counters(self.hits)), patch.object(builtins, "input", lambda *_: ""):
            again = self.s1.apply_plan(self.run, self.nsx, plan, False)
        self.assertEqual(again["disabled_now"], 0)

    def test_step1_skips_rules_that_changed_or_got_hits(self):
        with patch.object(rc, "policy_counters", counters(self.hits)):
            plan = self.s1.build_plan(self.nsx, "h", 0, False)
        self.nsx.rules["app"]["r-dead"]["services"] = ["/infra/services/SSH"]
        self.hits[4] = 3
        with patch.object(rc, "policy_counters", counters(self.hits)), patch.object(builtins, "input", lambda *_: ""):
            res = self.s1.apply_plan(self.run, self.nsx, plan, False)
        reasons = {r["rule_id"]: r.get("reason") for r in res["results"]}
        self.assertEqual(reasons["r-dead"], "changed since the plan")
        self.assertTrue(reasons["r-gone"].startswith("has hits now"))
        self.assertEqual(self.nsx.writes, [])

    def test_step2_then_undo_round_trip(self):
        self._step1()
        before_groups = set(self.nsx.groups)
        with patch.object(rc, "policy_counters", counters(self.hits)):
            plan = self.s2.make_plan(self.run, self.nsx, "h", False)
        self.assertEqual({r["rule_id"] for r in plan["rules"]}, {"r-dead", "r-gone"})
        rc.write_json(self.run / "step2" / "plan.json", plan)
        with patch.object(rc, "policy_counters", counters(self.hits)), patch.object(builtins, "input", lambda *_: ""):
            res = self.s2.apply_plan(self.run, self.nsx, plan)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["deleted_now"], {"rule": 2, "policy": 2, "group": 3})
        self.assertEqual(set(self.nsx.policies), {"app", "scoped", "default-layer3-section"})
        self.assertEqual(before_groups - set(self.nsx.groups), {"dead-g", "child-g", "orphan-g"})
        self.assertIn("r-pre", self.nsx.rules["app"])           # pre-disabled kept by default
        kinds = [w[0] for w in self.nsx.writes if w[0].startswith("delete")]
        self.assertEqual(kinds, ["delete_rule"] * 2 + ["delete_policy"] * 2 + ["delete_group"] * 3)

        undo = load_script("step2_undo")
        deleted = rc.read_json(self.run / "step2" / "deleted.json")
        for d in rc.restore_order(deleted["objects"]):
            _, read, create = undo.calls(self.nsx, d)
            create()
            read()
        self.assertEqual(before_groups, set(self.nsx.groups))
        self.assertIn("dead-pol", self.nsx.policies)
        self.assertTrue(self.nsx.rules["dead-pol"]["r-gone"]["disabled"])
        # step1_undo's check still matches a restored rule (new internal id, same content)
        rec = rc.read_json(self.run / "step1" / "disabled.json")
        after = next(d["after"] for d in rec["rules"] if d["rule_id"] == "r-gone")
        self.assertEqual(rc.content(self.nsx.rules["dead-pol"]["r-gone"], ("disabled",)),
                         rc.content(after, ("disabled",)))

    def test_step2_apply_deletes_nothing_outside_the_reviewed_plan(self):
        self._step1()
        with patch.object(rc, "policy_counters", counters(self.hits)):
            plan = self.s2.make_plan(self.run, self.nsx, "h", False)
        plan["groups"] = [g for g in plan["groups"] if g["id"] != "orphan-g"]
        plan["policies"] = [p for p in plan["policies"] if p["id"] != "empty-pol"]
        # someone re-enables r-gone after the plan was reviewed
        self.nsx.rules["dead-pol"]["r-gone"]["disabled"] = False
        with patch.object(rc, "policy_counters", counters(self.hits)), patch.object(builtins, "input", lambda *_: ""):
            res = self.s2.apply_plan(self.run, self.nsx, plan)
        self.assertIn("orphan-g", self.nsx.groups)
        self.assertIn("empty-pol", self.nsx.policies)
        self.assertIn("r-gone", self.nsx.rules["dead-pol"])
        self.assertIn("dead-pol", self.nsx.policies)            # still has r-gone
        self.assertIn("group orphan-g", res["not_in_reviewed_plan"])
        self.assertNotIn("r-dead", self.nsx.rules["app"])       # still disabled, so it went
        self.assertIn("dead-g", self.nsx.groups)                # r-gone (kept) still references it
        self.assertIn("child-g", self.nsx.groups)               # nested in dead-g

    def test_nsx_refusal_keeps_group_and_continues(self):
        state = lab_state()
        nsx = FakeNsx(state["policies"], state["rules"], state["groups"])
        plan = {"rules": [], "policies": [], "groups": [{"id": "orphan-g", "path": G + "orphan-g"}],
                "include_pre_disabled": False}
        rc.write_json(self.run / "step1" / "plan.json", {"rules": []})
        nsx.groups["orphan-g"]["expression"] = []
        real_delete = nsx.delete_group
        nsx.delete_group = lambda group_id, domain_id="default": (_ for _ in ()).throw(
            FakeErr(400, "is being referenced by other objects"))
        with patch.object(rc, "policy_counters", counters({})), patch.object(builtins, "input", lambda *_: ""):
            res = self.s2.apply_plan(self.run, nsx, plan)
        nsx.delete_group = real_delete
        self.assertTrue(res["ok"])
        self.assertEqual([r["status"] for r in res["results"] if r["kind"] == "group"], ["kept"])
        self.assertEqual(rc.read_json(self.run / "step2" / "deleted.json")["objects"], [])


class ManagerChoiceTests(unittest.TestCase):
    def test_scripts_offer_every_lm(self):
        import nsx.critical_rules as cr
        self.assertEqual(cr.LM_CHOICES, [f"nsx-lm{i}" for i in range(1, 7)])
        for name in ("step1_disable", "step1_undo", "step2_delete", "step2_undo"):
            self.assertIn("cr.LM_CHOICES", (ROOT / "tools/nsx/rule_cleanup" / f"{name}.py").read_text())


if __name__ == "__main__":
    unittest.main()
