#!/usr/bin/env python3
"""tools/nsx/rule_cleanup/step1_disable.py

Unused rule cleanup, step 1 of 2: disable every customer DFW rule that has
not been hit for more than N days.

N is NSX_CLEANUP_NO_HIT_DAYS in .env (default 90); --no-hit-days
overrides it. NSX keeps no last-hit time, only running counters, so the last
hit comes from counter snapshots over time (see app/nsx/rule_cleanup.py):

Without --apply (always first): starts a new run folder and runs the
rules-usage report once (read only), which adds a counter snapshot to the
history under --history-root (default $NSX_LOG_DIR/reports, where that report
keeps its runs; schedule the report daily so the history is dense). Then it
reads every customer policy and rule with its live counters (read only; the
client is locked against writes), works out each rule's last hit from the
history plus the live counters, and writes the plan:
  DISABLE           not hit for more than N days, enabled
  ALREADY_DISABLED  the same, already disabled (step 2 only with --include-pre-disabled)
  TOO_NEW           never hit, but created within the last N days
  RECENT            hit within the last N days, or the history does not reach
                    back N days, so that cannot be ruled out
  NO_STATS          no counter row: never touched
  KEEP_DENY         would be DISABLE, but DROP/REJECT and --keep-deny
A never-hit rule needs no history (its counters cover its whole life); a rule
that was ever hit qualifies only once the history reaches back N days.
NSX's default sections and their rules are never looked at.

With --apply: carries out the newest run's plan (or --run). Right before each
write it re-reads the rule and its policy's counters, and skips the rule if it
is gone, already disabled, changed since the plan, or its counters moved
since the plan (traffic, or a counter reset: plan again). The write
sends the rule back with only `disabled: true` changed and its _revision, so a
concurrent edit makes NSX refuse it (skipped). Asks before every batch
(Enter=continue, number=batch size, n=reset to 1, x=stop), so it needs a
terminal; --piped-answers allows answers fed on stdin (only with the
operator's approval). Rerunning --apply continues where a stopped apply left
off.

USAGE:
    python tools/nsx/rule_cleanup/step1_disable.py --target nsx-lm2
    python tools/nsx/rule_cleanup/step1_disable.py --target nsx-lm2 --apply

OPTIONS (plan only):
    --no-hit-days N     disable only rules not hit for more than N days (overrides
                        NSX_CLEANUP_NO_HIT_DAYS in .env; default 90)
    --history-root DIR  counter history root (default $NSX_LOG_DIR/reports)
    --keep-deny         leave DROP/REJECT rules enabled (KEEP_DENY)

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


def take_snapshot(target: str, history_root: Path, run: Path) -> bool:
    """Run the rules-usage report once (read only): it adds a counter snapshot
    to the history. Its output goes to the run's log, not the screen."""
    import subprocess
    step_log = run / "logs" / "step1_rules_usage_snapshot.log"
    step_log.parent.mkdir(parents=True, exist_ok=True)
    cmd = [cr.PY, cr.tool("tools/reports/report_rules_usage.py"), "--target", target,
           "--output-base", str(history_root)]
    log.info("Taking a counter snapshot (rules-usage report, read only) into %s", history_root)
    with step_log.open("w", encoding="utf-8") as fh:
        rc_ = subprocess.run(cmd, cwd=str(cr.REPO_ROOT), stdout=fh, stderr=subprocess.STDOUT).returncode
    if rc_ != 0:
        tail = step_log.read_text(encoding="utf-8", errors="replace").splitlines()[-15:]
        log.error("rules-usage report failed (rc=%d); last lines of %s:\n%s", rc_, step_log, "\n".join(tail))
        return False
    log.info("Snapshot taken (log: %s)", step_log)
    return True


def build_plan(client: Any, host: str, no_hit_days: int, keep_deny: bool,
               no_hit_source: str, history_dir: Path) -> Dict[str, Any]:
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    history, snaps = rc.load_hit_history(history_dir)
    log.info("Counter history: %d snapshot(s) in %s", len(snaps), history_dir)
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
            series = list(history.get((pol["id"], r.get("id")), []))
            if usage is not None:
                series.append((now_ms, tuple(usage[k] for k in rc.COUNTERS)))
            ev = rc.no_hit_since(series, r.get("_create_time"))
            since = ev["since_ms"]
            entries.append({
                "class": rc.classify(r, usage, ev, now_ms=now_ms, no_hit_days=no_hit_days, keep_deny=keep_deny),
                "policy_id": pol["id"], "policy_display": pol.get("display_name"),
                "category": pol.get("category"), "rule_id": r.get("id"),
                "display_name": r.get("display_name"), "sequence_number": r.get("sequence_number"),
                "action": r.get("action"), "disabled": bool(r.get("disabled")),
                "counters": usage, "stats_source": source, "age_days": rc.age_days(r, now_ms),
                "last_hit": ev["last_hit"], "reset_seen": ev["reset_seen"],
                "no_hit_days": round((now_ms - since) / rc.DAY_MS, 1) if since is not None else None,
                "readings": len(series), "rule": r,
            })
    iso = lambda ms: datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat() if ms else None  # noqa: E731
    return {
        "target_host": host, "planned_at": datetime.now(timezone.utc).isoformat(),
        "no_hit_days": no_hit_days, "no_hit_source": no_hit_source, "keep_deny": keep_deny,
        "history": {"dir": str(history_dir), "snapshots": len(snaps),
                    "oldest": iso(snaps[0]) if snaps else None, "newest": iso(snaps[-1]) if snaps else None,
                    "covers_days": round((now_ms - snaps[0]) / rc.DAY_MS, 1) if snaps else 0},
        "stats_sources": dict(sources), "skipped_policies": skipped, "rules": entries,
        "counts": {"rules": len(entries), "by_class": dict(Counter(e["class"] for e in entries))},
    }


def print_plan(plan: Dict[str, Any]) -> None:
    by = plan["counts"]["by_class"]
    n = plan["no_hit_days"]
    h = plan["history"]
    todo = [e for e in plan["rules"] if e["class"] == rc.DISABLE]
    print()
    print(f"Customer rules on {plan['target_host']}: {plan['counts']['rules']}  "
          f"(counters per policy: {plan['stats_sources']})")
    print(f"Window: disable only rules not hit for more than {n} days (from {plan['no_hit_source']})")
    print(f"Counter history: {h['snapshots']} snapshot(s), oldest {h['oldest'] or '-'} "
          f"({h['covers_days']} days back)")
    for cls in rc.CLASS_ORDER:
        if by.get(cls):
            print(f"  {cls:<17} {by[cls]}")
    print()
    print(f"Step 1 would DISABLE {len(todo)} rule(s):")
    for e in todo:
        print(f"  {e['category'] or '':<15} {e['policy_id']:<28} {str(e['display_name'] or e['rule_id']):<34} "
              f"{e['action'] or '':<7} last hit: {e['last_hit']}")
    deny = [e for e in todo if str(e["action"] or "").upper() in rc.DENY_ACTIONS]
    if deny:
        print()
        print(f"CHECK: {len(deny)} of them are DROP/REJECT rules. Disabling a deny rule lets traffic it "
              "would have blocked fall through to later rules if that traffic ever arrives. Use "
              "--keep-deny to leave them enabled.")
    if by.get(rc.NO_STATS):
        print()
        print(f"WARNING: {by[rc.NO_STATS]} rule(s) have no counter row (NO_STATS) and are left alone; "
              "see plan.md.")
    if h["covers_days"] <= n:
        print()
        print(f"NOTE: the counter history reaches back {h['covers_days']} days, not {n}. Until it does, a "
              f"rule that was ever hit stays RECENT; only never-hit rules created more than {n} days ago "
              "can qualify. Schedule the rules-usage report (daily) to build the history.")
    if by.get(rc.TOO_NEW):
        print()
        print(f"{by[rc.TOO_NEW]} never-hit rule(s) were created within the last {n} days (TOO_NEW) and are "
              "left alone; ages are in plan.md.")
    pre = [e for e in plan["rules"] if e["class"] == rc.ALREADY_DISABLED]
    if pre:
        print()
        print(f"{len(pre)} qualifying rule(s) are already disabled (not changed by step 1; step 2 deletes "
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
        elif usage != e["counters"]:
            reason = (f"counters moved since the plan (hit_count {e['counters']['hit_count']} -> "
                      f"{usage['hit_count']}, bytes {e['counters']['byte_count']} -> {usage['byte_count']})")
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
                "counters": usage, "last_hit": e.get("last_hit"), "before": live, "after": after,
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
    p.add_argument("--no-hit-days", type=int, default=None,
                   help=f"disable only rules not hit for more than N days; overrides {rc.NO_HIT_ENV} "
                        f"in .env (default {rc.DEFAULT_NO_HIT_DAYS})")
    p.add_argument("--history-root", default=None,
                   help="counter history root: <root>/<host>/rules_usage/<ts>/ "
                        "(default: $NSX_LOG_DIR/reports, where report_rules_usage.py keeps its runs)")
    p.add_argument("--keep-deny", action="store_true", help="leave DROP/REJECT rules enabled")
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
        no_hit, no_hit_source = rc.resolve_no_hit_days(args.no_hit_days)
        from nsx.report_paths import reports_root
        root = reports_root(args.history_root)
        if not take_snapshot(args.target, root, run):
            rc.record_step(run, "disable_plan", {"ok": False, "error": "rules-usage snapshot failed"})
            raise SystemExit("the rules-usage snapshot failed; see the log above")
        client = NsxPolicyClient(nsxmanager=host, federation_global=False)
        rc.lock_read_only(client)
        plan = build_plan(client, host, no_hit, args.keep_deny, no_hit_source, root / host / "rules_usage")
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

    if args.no_hit_days is not None or args.keep_deny or args.history_root:
        raise SystemExit("--no-hit-days, --history-root and --keep-deny are plan options; --apply carries "
                         "out the reviewed plan. Plan again with them, then --apply.")
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
