#!/usr/bin/env python3
"""tools/nsx/rule_cleanup/step2_delete.py

Unused rule cleanup, step 2 of 2: delete the unused rules, then every policy
left empty, then every group nothing references. Services are never touched.

Run it after the soak period, on the run step 1 used (newest for the target,
or --run).

Without --apply (always first): reads the target (read only) and writes the
plan:
  rules     the rules step 1 disabled, if each is still on the manager, still
            disabled, unchanged since step 1, and has no hits. With
            --include-pre-disabled also the never-hit rules that were already
            disabled when step 1 planned (left out by default: rules are often
            staged disabled ahead of a change window).
  policies  every customer DFW policy with no rules once those are gone,
            including policies that were already empty. NSX's default
            sections are never deleted.
  groups    every customer group nothing references once those are gone.
            References are looked for in every remaining DFW rule and policy
            (default sections included), gateway, IDS, redirection, forwarding
            and endpoint policies and their rules, the DFW exclusion list,
            load-balancer pools and virtual servers, and in other groups
            (nested). A group nested only in a group being deleted goes too,
            after its parent. NSX's own groups are never deleted.

With --apply: carries out that plan only. It re-reads the target, deletes
nothing the plan did not list, and re-checks every object right before
deleting it (a rule must still be disabled and unchanged, a policy must have
no rules). Before the first delete it saves policies, rules and groups to
step2/before_<ts>.json; each object's full JSON goes to step2/deleted.json
just before it is deleted, which step2_undo.py uses to put it back. A group
NSX refuses to delete because something still references it is kept and
reported. Asks before every batch (Enter=continue, number=batch size, n=reset
to 1, x=stop), so it needs a terminal; --piped-answers allows answers fed on
stdin (only with the operator's approval). Rerunning --apply continues where
a stopped apply left off.

USAGE:
    python tools/nsx/rule_cleanup/step2_delete.py --target nsx-lm2
    python tools/nsx/rule_cleanup/step2_delete.py --target nsx-lm2 --apply

Undo: step2_undo.py. Runbook: docs/nsx/RUNBOOK_RULE_CLEANUP.md
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "app"))
from common.logs import setup_logging                  # noqa: E402
from common.timeutil import run_ts                     # noqa: E402
from nsx.apply_batch import ApplyBatch                 # noqa: E402
from nsx.nsx_constants import resolve_manager          # noqa: E402
import nsx.critical_rules as cr                        # noqa: E402
import nsx.rule_cleanup as rc                          # noqa: E402

log = logging.getLogger("rule_cleanup")


def collect_usage(client: Any, state: Dict[str, Any],
                  candidates: List[Dict[str, Any]]) -> Dict[str, Optional[Dict[str, int]]]:
    """Counters now for every candidate rule still on the manager."""
    pols = {p["id"]: p for p in state["policies"]}
    live = {(pid, r.get("id")): r for pid, rs in state["rules"].items() for r in rs}
    usage: Dict[str, Optional[Dict[str, int]]] = {}
    for pid in sorted({c["policy_id"] for c in candidates if c["policy_id"] in pols}):
        rows, source, _ = rc.policy_counters(client, pols[pid])
        log.info("Counters for %s: %s", pid, source)
        for c in candidates:
            r = live.get((pid, c["rule_id"])) if c["policy_id"] == pid else None
            if r is not None:
                usage[f"{pid}/{c['rule_id']}"] = rc.rule_usage(r, rows)
    return usage


def soak_line(run: Path) -> Optional[str]:
    rules = (rc.read_json(run / "step1" / "disabled.json", {}) or {}).get("rules", [])
    times = sorted(d["disabled_at"] for d in rules if not d.get("reenabled_at"))
    if not times:
        return None
    newest = datetime.fromisoformat(times[-1])
    hours = (datetime.now(timezone.utc) - newest).total_seconds() / 3600
    return (f"Step 1 disabled {len(times)} rule(s) between {times[0][:19]} and {times[-1][:19]} UTC; "
            f"the newest has been disabled {hours / 24:.1f} days ({hours:.1f} hours).")


def print_plan(plan: Dict[str, Any]) -> None:
    c = plan["counts"]
    print()
    print(f"Step 2 plan for {plan['target_host']}: delete {c['rules']} rule(s), then {c['policies']} "
          f"policy/-ies, then {c['groups']} group(s) of {c['groups_total']}. Services are never touched.")
    print(f"Candidates: {plan['candidates']}")
    print()
    print("Rules:")
    for r in plan["rules"]:
        print(f"  DELETE {r['policy_id']:<28} {str(r.get('display_name') or r['rule_id']):<34} "
              f"{r.get('action') or '':<7} {r['origin']}")
    for r in plan["rules_kept"]:
        print(f"  keep   {r['policy_id']:<28} {str(r.get('display_name') or r['rule_id']):<34} {r['reason']}")
    print("Policies:")
    for p in plan["policies"]:
        print(f"  DELETE {p['id']:<28} {p.get('category') or '':<15} {p['origin']}")
    print("Groups (delete order):")
    for g in plan["groups"]:
        nests = f"  nests {', '.join(g['nests'])}" if g["nests"] else ""
        print(f"  DELETE {g['id']:<40} {g['origin']}{nests}")
    print(f"Other group consumers checked: {plan['consumers_checked']}")
    pre = plan["candidates"]
    if pre.get("pre_disabled") and not plan["include_pre_disabled"]:
        print()
        print(f"Left out: {pre['pre_disabled']} never-hit rule(s) that were already disabled before step 1 "
              "(add --include-pre-disabled to delete them too).")


def make_plan(run: Path, client: Any, host: str, include_pre: bool) -> Dict[str, Any]:
    candidates, counts = rc.step2_candidates(run, include_pre)
    state = rc.read_state(client)
    plan = rc.plan_step2(state, candidates, collect_usage(client, state, candidates))
    plan.update(target_host=host, planned_at=datetime.now(timezone.utc).isoformat(),
                include_pre_disabled=include_pre, candidates=counts)
    return plan


def apply_plan(run: Path, client: Any, approved: Dict[str, Any]) -> Dict[str, Any]:
    include_pre = approved["include_pre_disabled"]
    candidates, _ = rc.step2_candidates(run, include_pre)
    reference = {(c["policy_id"], c["rule_id"]): c["reference"] for c in candidates}
    state = rc.read_state(client)
    fresh = rc.plan_step2(state, candidates, collect_usage(client, state, candidates))

    snap = run / "step2" / f"before_{run_ts()}.json"
    rc.write_json(snap, {"taken_at": datetime.now(timezone.utc).isoformat(),
                         "policies": state["policies"], "rules": state["rules"], "groups": state["groups"]})
    log.info("Saved policies, rules and groups before deleting: %s", snap)

    ok_rules = {(r["policy_id"], r["rule_id"]) for r in approved["rules"]}
    ok_pols = {p["id"] for p in approved["policies"]}
    ok_groups = {g["path"] for g in approved["groups"]}
    not_reviewed = ([f"rule {r['policy_id']}/{r['rule_id']}" for r in fresh["rules"]
                     if (r["policy_id"], r["rule_id"]) not in ok_rules]
                    + [f"policy {p['id']}" for p in fresh["policies"] if p["id"] not in ok_pols])
    kept_now = {(r["policy_id"], r["rule_id"]): r["reason"] for r in fresh["rules_kept"]}

    del_path = run / "step2" / "deleted.json"
    deleted = rc.read_json(del_path, {"objects": []})
    batch = ApplyBatch(True, log)
    results: List[Dict[str, Any]] = []
    state_flags = {"failed": False, "stopped": False}

    def save(kind: str, obj: Dict[str, Any], **ids: Any) -> None:
        deleted["objects"].append({"kind": kind, **ids, "order": len(deleted["objects"]) + 1,
                                   "deleted_at": datetime.now(timezone.utc).isoformat(), "obj": obj})
        rc.write_json(del_path, deleted)

    def delete(label: str, row: Dict[str, Any], fn, kind: str, obj: Dict[str, Any], ids: Dict[str, Any]) -> bool:
        """Ask, save the object, delete it. False stops the whole apply."""
        if not batch.before_write():
            state_flags["stopped"] = True
            row.update(status="not_done", reason="operator stopped")
            return False
        save(kind, obj, **ids)
        try:
            fn()
        except Exception as exc:
            deleted["objects"].pop()
            rc.write_json(del_path, deleted)
            if kind == "group" and rc.is_still_referenced(exc):
                row.update(status="kept", reason=f"NSX refused: still referenced ({str(exc)[:160]})")
                log.warning("%s kept: %s", label, row["reason"])
                return True
            row.update(status="failed", error=str(exc)[:300])
            log.error("%s FAILED: %s", label, exc)
            state_flags["failed"] = True
            return False
        row["status"] = "deleted"
        log.info("%s DELETED", label)
        batch.record({"display_name": label, "status": "deleted"})
        return True

    for r in approved["rules"]:
        pid, rid = r["policy_id"], r["rule_id"]
        row = {"kind": "rule", "id": f"{pid}/{rid}"}
        results.append(row)
        label = f"rule {pid}/{rid}"
        try:
            live = client.get_security_rule(security_policy_id=pid, rule_id=rid, domain_id=rc.DOMAIN)
        except Exception as exc:
            if not rc.is_not_found(exc):
                raise
            live = None
        if live is None:
            reason = "no longer on the manager"
        elif (pid, rid) in kept_now:
            reason = kept_now[(pid, rid)]
        elif (pid, rid) not in reference:
            reason = "no longer a candidate (re-enabled by step1_undo.py?)"
        elif not live.get("disabled") or rc.content(live) != rc.content(reference[(pid, rid)]):
            reason = "enabled or changed since the plan"
        else:
            reason = None
        if reason:
            row.update(status="skipped", reason=reason)
            log.warning("%s skip: %s", label, reason)
            continue
        if not delete(label, row, lambda: client.delete_security_rule(
                security_policy_id=pid, rule_id=rid, domain_id=rc.DOMAIN),
                "rule", live, {"policy_id": pid, "rule_id": rid}):
            break

    if not (state_flags["failed"] or state_flags["stopped"]):
        live_pols = {p["id"] for p in client.list_security_policies(domain_id=rc.DOMAIN)}
        for p in approved["policies"]:
            pid = p["id"]
            row = {"kind": "policy", "id": pid}
            results.append(row)
            label = f"policy {pid}"
            if pid not in live_pols:
                row.update(status="skipped", reason="no longer on the manager")
                continue
            left = client.list_security_rules(security_policy_id=pid, domain_id=rc.DOMAIN)
            if left:
                row.update(status="skipped", reason=f"still has {len(left)} rule(s): "
                                                     f"{', '.join(str(x.get('id')) for x in left[:10])}")
                log.warning("%s skip: %s", label, row["reason"])
                continue
            pol = client.get_security_policy(security_policy_id=pid, domain_id=rc.DOMAIN)
            if not delete(label, row, lambda: client.delete_security_policy(
                    security_policy_id=pid, domain_id=rc.DOMAIN), "policy", pol, {"policy_id": pid}):
                break

    if not (state_flags["failed"] or state_flags["stopped"]):
        now = rc.plan_step2(rc.read_state(client), [], {})
        unused_now = {g["path"] for g in now["groups"]}
        order = [g for g in now["groups"] if g["path"] in ok_groups]
        for g in approved["groups"]:
            if g["path"] not in unused_now:
                results.append({"kind": "group", "id": g["id"], "status": "skipped",
                                "reason": "referenced now, or no longer on the manager"})
        not_reviewed += [f"group {g['id']}" for g in now["groups"] if g["path"] not in ok_groups]
        for g in order:
            row = {"kind": "group", "id": g["id"]}
            results.append(row)
            label = f"group {g['id']}"
            try:
                obj = client.get_group(group_id=g["id"], domain_id=rc.DOMAIN)
            except Exception as exc:
                if not rc.is_not_found(exc):
                    raise
                row.update(status="skipped", reason="no longer on the manager")
                continue
            if not delete(label, row, lambda: client.delete_group(group_id=g["id"], domain_id=rc.DOMAIN),
                          "group", obj, {"group_id": g["id"]}):
                break

    ok = not state_flags["failed"] and not state_flags["stopped"]
    return {"ok": ok, **state_flags, "before_snapshot": str(snap), "deleted_record": str(del_path),
            "not_in_reviewed_plan": not_reviewed, "results": results,
            "deleted_now": {k: sum(1 for r in results if r["kind"] == k and r.get("status") == "deleted")
                            for k in ("rule", "policy", "group")},
            "batch": batch.totals(), "decisions": batch.decisions}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--target", required=True, choices=cr.LM_CHOICES)
    p.add_argument("--run", help="run folder (default: newest for this target)")
    rc.add_runs_dir_arg(p)
    p.add_argument("--include-pre-disabled", action="store_true",
                   help="also delete never-hit rules that were already disabled before step 1")
    p.add_argument("--apply", action="store_true", help="delete what the plan lists (default: plan only)")
    cr.add_piped_answers_arg(p)
    args = p.parse_args()
    cr.require_terminal(args.apply, args.piped_answers)

    host = resolve_manager(args.target)
    run = rc.resolve_run(args.target, args.run, base=rc.runs_base(args.runs_dir))
    rec = rc.load_record(run)
    rc.check_run(rec, args.target, host)
    if not rc.read_json(run / "step1" / "plan.json"):
        raise SystemExit(f"no step 1 plan in {run}; step 2 works on a step 1 run")
    mode = "apply" if args.apply else "plan"
    setup_logging(f"step2_{mode}", run / "logs")
    log.info("Run: %s", run)
    from nsx.nsx_policy_client import NsxPolicyClient
    client = NsxPolicyClient(nsxmanager=host, federation_global=False)

    if not args.apply:
        rc.lock_read_only(client)
        if not any(h.get("step") == "disable_apply" for h in rec.get("history", [])):
            log.warning("step 1 was never applied in this run: no rules disabled by step 1 to delete")
        plan = make_plan(run, client, host, args.include_pre_disabled)
        rc.write_json(run / "step2" / "plan.json", plan)
        (run / "step2" / "plan.md").write_text(rc.step2_markdown(plan), encoding="utf-8")
        line = soak_line(run)
        if line:
            print()
            print(line)
        print_plan(plan)
        print()
        print(f"Plan: {run / 'step2' / 'plan.md'}")
        if not any(plan["counts"][k] for k in ("rules", "policies", "groups")):
            print("Nothing to delete; nothing was changed.")
        else:
            print("Nothing was changed. Review the plan, then apply it:")
            print("  " + rc.next_command("step2_delete.py", args, "--apply"))
        rc.record_step(run, "delete_plan", {"ok": True, "plan": str(run / "step2" / "plan.json"),
                                            "counts": plan["counts"], "candidates": plan["candidates"]})
        return 0

    approved = rc.read_json(run / "step2" / "plan.json")
    if not approved:
        raise SystemExit(f"no step 2 plan in {run}; run step2_delete.py without --apply first")
    if args.include_pre_disabled and not approved["include_pre_disabled"]:
        raise SystemExit("the reviewed plan was made without --include-pre-disabled; plan again with it")
    log.info("Applying the plan from %s", approved["planned_at"])
    res = apply_plan(run, client, approved)

    print()
    d = res["deleted_now"]
    print(f"Step 2 APPLY on {host}: deleted {d['rule']} rule(s), {d['policy']} policy/-ies, {d['group']} group(s)")
    for r in res["results"]:
        if r.get("status") != "deleted":
            print(f"  {r.get('status', '?'):<9} {r['kind']} {r['id']}: {r.get('reason') or r.get('error')}")
    if res["not_in_reviewed_plan"]:
        print(f"Unused now but not in the reviewed plan, so not deleted (plan again to review them): "
              f"{', '.join(res['not_in_reviewed_plan'])}")
    print(f"Result: {'OK' if res['ok'] else ('STOPPED by operator' if res['stopped'] else 'FAILED')}")
    print(f"Saved before deleting: {res['before_snapshot']}")
    print(f"Deleted objects (full JSON): {res['deleted_record']}")
    print("Undo (puts every deleted object back; rules return disabled):")
    print("  " + rc.next_command("step2_undo.py", args))
    rc.record_step(run, "delete_apply", {**res, "piped_answers": args.piped_answers})
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
