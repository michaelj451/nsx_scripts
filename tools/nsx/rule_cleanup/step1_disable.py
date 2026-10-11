#!/usr/bin/env python3
"""tools/nsx/rule_cleanup/step1_disable.py

Unused rule cleanup, step 1 of 2: disable every customer DFW rule that has
never been hit.

Without --apply (always first): starts a new run folder, reads every customer
policy and rule on the target with its hit counters (read only; the client is
locked against writes), and writes the plan. A rule is DISABLE when NSX
returned a counter row for it, its hit, packet, byte and session counts are
all 0, and it is enabled. NSX's default sections and their rules are never
looked at; a rule without a counter row is NO_STATS and left alone.

With --apply: carries out the newest run's plan (or --run). Right before each
write it re-reads the rule and its policy's counters, and skips the rule if it
is gone, already disabled, changed since the plan, or has hits now. The write
sends the rule back with only `disabled: true` changed and its _revision, so a
concurrent edit makes NSX refuse it (skipped). Asks before every batch
(Enter=continue, number=batch size, n=reset to 1, x=stop), so it needs a
terminal; --piped-answers allows answers fed on stdin (only with the
operator's approval). Rerunning --apply continues where a stopped apply left
off.

USAGE:
    python tools/nsx/rule_cleanup/step1_disable.py --target nsx-lm2
    python tools/nsx/rule_cleanup/step1_disable.py --target nsx-lm2 --apply

OPTIONS:
    --min-age-days N   leave never-hit rules younger than N days (TOO_NEW); default 0
    --keep-deny        leave never-hit DROP/REJECT rules enabled (KEEP_DENY)

OUTPUT (run folder, see app/nsx/rule_cleanup.py):
    step1/plan.json, step1/plan.md, step1/disabled.json, logs/

Undo: step1_undo.py. Next, after the soak period: step2_delete.py.
Runbook: docs/nsx/RUNBOOK_RULE_CLEANUP.md
"""
from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "app"))
from common.logs import setup_logging                  # noqa: E402
from nsx.apply_batch import ApplyBatch                 # noqa: E402
from nsx.nsx_constants import resolve_manager          # noqa: E402
import nsx.critical_rules as cr                        # noqa: E402
import nsx.rule_cleanup as rc                          # noqa: E402

log = logging.getLogger("rule_cleanup")


def build_plan(client: Any, host: str, min_age_days: int, keep_deny: bool) -> Dict[str, Any]:
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    entries: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []
    sources: Counter = Counter()
    for pol in client.list_security_policies(domain_id=rc.DOMAIN):
        if not rc.is_cleanup_policy(pol):
            skipped.append({"id": pol.get("id"), "reason": "NSX default section or system object"})
            continue
        if pol.get("locked"):
            skipped.append({"id": pol.get("id"), "reason": "policy is locked"})
            continue
        rules = client.list_security_rules(security_policy_id=pol["id"], domain_id=rc.DOMAIN)
        rows, source, err = rc.policy_counters(client, pol)
        sources[source] += 1
        log.info("Policy %-30s %-15s rules=%-3d counters=%s%s", pol["id"], pol.get("category"),
                 len(rules), source, f" (Policy API: {err[:60]})" if err and source != "policy_api" else "")
        for r in sorted(rules, key=lambda x: (x.get("sequence_number") or 0, str(x.get("id")))):
            if cr.is_system_default(r):
                continue
            usage = rc.rule_usage(r, rows)
            entries.append({
                "class": rc.classify(r, usage, now_ms=now_ms, min_age_days=min_age_days, keep_deny=keep_deny),
                "policy_id": pol["id"], "policy_display": pol.get("display_name"),
                "category": pol.get("category"), "rule_id": r.get("id"),
                "display_name": r.get("display_name"), "sequence_number": r.get("sequence_number"),
                "action": r.get("action"), "disabled": bool(r.get("disabled")),
                "counters": usage, "stats_source": source, "age_days": rc.age_days(r, now_ms),
                "rule": r,
            })
    return {
        "target_host": host, "planned_at": datetime.now(timezone.utc).isoformat(),
        "min_age_days": min_age_days, "keep_deny": keep_deny,
        "stats_sources": dict(sources), "skipped_policies": skipped, "rules": entries,
        "counts": {"rules": len(entries), "by_class": dict(Counter(e["class"] for e in entries))},
    }


def print_plan(plan: Dict[str, Any]) -> None:
    by = plan["counts"]["by_class"]
    todo = [e for e in plan["rules"] if e["class"] == rc.DISABLE]
    print()
    print(f"Customer rules on {plan['target_host']}: {plan['counts']['rules']}  "
          f"(counters per policy: {plan['stats_sources']})")
    for cls in rc.CLASS_ORDER:
        if by.get(cls):
            print(f"  {cls:<17} {by[cls]}")
    print()
    print(f"Step 1 would DISABLE {len(todo)} rule(s) (never hit, enabled now):")
    for e in todo:
        print(f"  {e['category'] or '':<15} {e['policy_id']:<28} {str(e['display_name'] or e['rule_id']):<34} "
              f"seq {e['sequence_number']!s:<5} {e['action']}")
    deny = [e for e in todo if str(e["action"] or "").upper() in rc.DENY_ACTIONS]
    if deny:
        print()
        print(f"CHECK: {len(deny)} of them are DROP/REJECT rules. Disabling a never-hit deny rule lets "
              "traffic it would have blocked fall through to later rules if that traffic ever "
              "arrives. Use --keep-deny to leave them enabled.")
    if by.get(rc.NO_STATS):
        print()
        print(f"WARNING: {by[rc.NO_STATS]} rule(s) have no counter row (NO_STATS) and are left alone; "
              "see plan.md.")
    pre = [e for e in plan["rules"] if e["class"] == rc.ALREADY_DISABLED]
    if pre:
        print()
        print(f"{len(pre)} never-hit rule(s) are already disabled (not changed by step 1; step 2 deletes "
              "them only with --include-pre-disabled).")


def apply_plan(run: Path, client: Any, plan: Dict[str, Any], piped: bool) -> Dict[str, Any]:
    todo = [e for e in plan["rules"] if e["class"] == rc.DISABLE]
    rec_path = run / "step1" / "disabled.json"
    record = rc.read_json(rec_path, {"rules": []})
    done = {(d["policy_id"], d["rule_id"]): d for d in record["rules"]}

    live_pols = {p["id"]: p for p in client.list_security_policies(domain_id=rc.DOMAIN)}
    counters = {pid: rc.policy_counters(client, live_pols[pid])[0]
                for pid in sorted({e["policy_id"] for e in todo}) if pid in live_pols}

    batch = ApplyBatch(True, log)
    results: List[Dict[str, Any]] = []
    failed = stopped = False
    for i, e in enumerate(todo, start=1):
        pid, rid = e["policy_id"], e["rule_id"]
        row = {"policy_id": pid, "rule_id": rid, "display_name": e["display_name"]}
        results.append(row)
        tag = f"[{i}/{len(todo)}] {pid}/{rid}"
        if (pid, rid) in done:
            row["status"] = "skipped"
            row["reason"] = ("re-enabled by step1_undo.py; start a new run to disable it again"
                             if done[(pid, rid)].get("reenabled_at") else "already disabled by this run")
            log.info("%s skip: %s", tag, row["reason"])
            continue
        try:
            live = client.get_security_rule(security_policy_id=pid, rule_id=rid, domain_id=rc.DOMAIN)
        except Exception as exc:
            if not rc.is_not_found(exc):
                raise
            live = None
        usage = rc.rule_usage(live, counters.get(pid, {})) if live else None
        if live is None:
            reason = "no longer on the manager"
        elif live.get("disabled"):
            reason = "already disabled (not by this run)"
        elif rc.content(live) != rc.content(e["rule"]):
            reason = "changed since the plan"
        elif usage is None:
            reason = "no counter row now"
        elif any(usage.values()):
            reason = f"has hits now (hit_count {usage['hit_count']})"
        else:
            reason = None
        if reason:
            row.update(status="skipped", reason=reason)
            log.warning("%s skip: %s", tag, reason)
            continue

        if not batch.before_write():
            stopped = True
            row.update(status="not_done", reason="operator stopped")
            break
        try:
            client.put_security_rule(security_policy_id=pid, rule_id=rid,
                                     payload=rc.update_payload(live, disabled=True), domain_id=rc.DOMAIN)
        except Exception as exc:
            if rc.is_412(exc):
                row.update(status="skipped", reason="changed during the apply (HTTP 412)")
                log.warning("%s skip: %s", tag, row["reason"])
                continue
            row.update(status="failed", error=str(exc)[:300])
            log.error("%s FAILED: %s", tag, exc)
            failed = True
            break
        after = client.get_security_rule(security_policy_id=pid, rule_id=rid, domain_id=rc.DOMAIN)
        if after.get("disabled"):
            record["rules"].append({
                "policy_id": pid, "rule_id": rid, "display_name": e["display_name"],
                "action": e["action"], "disabled_at": datetime.now(timezone.utc).isoformat(),
                "revision_before": live.get("_revision"), "revision_after": after.get("_revision"),
                "before": live, "after": after,
            })
            rc.write_json(rec_path, record)
        if not after.get("disabled") or rc.content(after, ("disabled",)) != rc.content(live, ("disabled",)):
            row.update(status="failed", error="after the write the rule is not exactly the old rule with "
                                              "disabled=true; stopping")
            log.error("%s FAILED: %s", tag, row["error"])
            failed = True
            break
        row["status"] = "disabled"
        log.info("%s DISABLED (%s)", tag, e["action"])
        batch.record({"display_name": f"{pid}/{e['display_name'] or rid}", "status": "disabled"})

    return {"ok": not failed and not stopped, "failed": failed, "stopped": stopped,
            "piped_answers": piped, "planned": len(todo),
            "disabled_now": sum(1 for r in results if r.get("status") == "disabled"),
            "disabled_in_run_total": len([d for d in record["rules"] if not d.get("reenabled_at")]),
            "results": results, "batch": batch.totals(), "decisions": batch.decisions}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--target", required=True, choices=cr.LM_CHOICES, help="Local Manager to clean up")
    p.add_argument("--run", help="run folder for --apply (default: newest for this target)")
    rc.add_runs_dir_arg(p)
    p.add_argument("--apply", action="store_true", help="disable the planned rules (default: plan only)")
    p.add_argument("--min-age-days", type=int, default=0,
                   help="leave never-hit rules younger than this many days (default 0: no age limit)")
    p.add_argument("--keep-deny", action="store_true", help="leave never-hit DROP/REJECT rules enabled")
    cr.add_piped_answers_arg(p)
    args = p.parse_args()
    cr.require_terminal(args.apply, args.piped_answers)
    host = resolve_manager(args.target)
    if not host:
        raise SystemExit(f"{args.target} is not defined in .env")

    from nsx.nsx_policy_client import NsxPolicyClient
    if not args.apply:
        if args.run:
            raise SystemExit("--run is for --apply; a plan always starts a new run")
        run = rc.new_run(args.target, host, base=rc.runs_base(args.runs_dir))
        setup_logging("step1_plan", run / "logs")
        log.info("Run: %s", run)
        client = NsxPolicyClient(nsxmanager=host, federation_global=False)
        rc.lock_read_only(client)
        plan = build_plan(client, host, args.min_age_days, args.keep_deny)
        rc.write_json(run / "step1" / "plan.json", plan)
        (run / "step1" / "plan.md").write_text(rc.step1_markdown(plan), encoding="utf-8")
        print_plan(plan)
        print()
        print(f"Plan: {run / 'step1' / 'plan.md'}")
        if not plan["counts"]["by_class"].get(rc.DISABLE):
            print("No rule to disable; nothing was changed.")
        else:
            print("Nothing was changed. Review the plan, then apply it:")
            print("  " + rc.next_command("step1_disable.py", args, "--apply"))
        rc.record_step(run, "disable_plan", {"ok": True, "plan": str(run / "step1" / "plan.json"),
                                             "counts": plan["counts"], "stats_sources": plan["stats_sources"]})
        return 0

    run = rc.resolve_run(args.target, args.run, base=rc.runs_base(args.runs_dir))
    rec = rc.load_record(run)
    rc.check_run(rec, args.target, host)
    plan = rc.read_json(run / "step1" / "plan.json")
    if not plan:
        raise SystemExit(f"no step 1 plan in {run}; run step1_disable.py without --apply first")
    setup_logging("step1_apply", run / "logs")
    log.info("Run: %s (plan from %s)", run, plan["planned_at"])
    client = NsxPolicyClient(nsxmanager=host, federation_global=False)
    res = apply_plan(run, client, plan, args.piped_answers)

    print()
    print(f"Step 1 APPLY on {host}: {res['disabled_now']} disabled now, "
          f"{res['disabled_in_run_total']} disabled by this run in total, of {res['planned']} planned")
    for r in res["results"]:
        if r.get("status") != "disabled":
            print(f"  {r.get('status', '?'):<9} {r['policy_id']}/{r['rule_id']}: {r.get('reason') or r.get('error')}")
    print(f"Result: {'OK' if res['ok'] else ('STOPPED by operator' if res['stopped'] else 'FAILED')}")
    print(f"Record: {run / 'step1' / 'disabled.json'}")
    print()
    print("Leave the rules disabled for the agreed soak period. If something breaks, re-enable:")
    print("  " + rc.next_command("step1_undo.py", args, "--rule <policy_id>/<rule_id>"))
    print("After the soak period, plan step 2:")
    print("  " + rc.next_command("step2_delete.py", args))
    rc.record_step(run, "disable_apply", res)
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
