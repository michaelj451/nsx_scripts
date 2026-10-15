#!/usr/bin/env python3
"""tools/nsx/rule_cleanup/step1_undo.py

Unused rule cleanup: undo step 1 by re-enabling rules it disabled.

All of them, or only those named with --rule (repeatable: <policy id>/<rule
id>, a rule id, or a rule display name). A rule is re-enabled only if it is
still disabled and otherwise unchanged since step 1 disabled it, and the
write changes nothing but `disabled` back to false. A rule step 2 already
deleted is reported: put it back with step2_undo.py first (it returns
disabled, with the same id), then run this again.

Dry run by default; --apply writes, in a terminal: asks before every batch
(Enter=continue, number=batch size, n=reset to 1, x=stop). --piped-answers
allows answers fed on stdin (only with the operator's approval).

USAGE:
    python tools/nsx/rule_cleanup/step1_undo.py --target nsx-lm2
    python tools/nsx/rule_cleanup/step1_undo.py --target nsx-lm2 --rule Start_Policy/ssh-network-0 --apply
    python tools/nsx/rule_cleanup/step1_undo.py --target nsx-lm2 --apply

Runbook: docs/nsx/RUNBOOK_RULE_CLEANUP.md
"""
from __future__ import annotations

import argparse
import logging
import sys
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


def select(records: List[Dict[str, Any]], names: List[str]) -> List[Dict[str, Any]]:
    """Records matching any --rule value; exits listing any value that matches nothing."""
    if not names:
        return records
    picked, unmatched = [], []
    for n in names:
        hits = [d for d in records if n in (f"{d['policy_id']}/{d['rule_id']}", d["rule_id"], d.get("display_name"))]
        if not hits:
            unmatched.append(n)
        picked += [d for d in hits if d not in picked]
    if unmatched:
        raise SystemExit(f"not among the rules step 1 disabled in this run: {', '.join(unmatched)}")
    return picked


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--target", required=True, choices=cr.LM_CHOICES)
    p.add_argument("--run", help="run folder (default: newest for this target)")
    rc.add_runs_dir_arg(p)
    p.add_argument("--rule", action="append", default=[],
                   help="re-enable only this rule: <policy id>/<rule id>, rule id or display name (repeatable)")
    p.add_argument("--apply", action="store_true", help="write to the manager (default: dry run)")
    cr.add_piped_answers_arg(p)
    args = p.parse_args()
    cr.require_terminal(args.apply, args.piped_answers)

    host = resolve_manager(args.target)
    run = rc.resolve_run(args.target, args.run, base=rc.runs_base(args.runs_dir))
    rec = rc.load_record(run)
    rc.check_run(rec, args.target, host)
    rec_path = run / "step1" / "disabled.json"
    record = rc.read_json(rec_path, {"rules": []})
    open_records = [d for d in record["rules"] if not d.get("reenabled_at")]
    if not open_records:
        raise SystemExit(f"nothing to re-enable in {run}: step 1 disabled no rule there, "
                         "or every one was re-enabled already")
    targets = select(open_records, args.rule)
    mode = "apply" if args.apply else "dryrun"
    setup_logging(f"step1_undo_{mode}", run / "logs")
    log.info("Run: %s", run)

    from nsx.nsx_policy_client import NsxPolicyClient
    client = NsxPolicyClient(nsxmanager=host, federation_global=False)
    if not args.apply:
        rc.lock_read_only(client)

    batch = ApplyBatch(args.apply, log)
    results: List[Dict[str, Any]] = []
    failed = stopped = False
    for i, d in enumerate(targets, start=1):
        pid, rid = d["policy_id"], d["rule_id"]
        tag = f"[{i}/{len(targets)}] {pid}/{rid}"
        row = {"policy_id": pid, "rule_id": rid, "display_name": d.get("display_name")}
        results.append(row)
        try:
            live = client.get_security_rule(security_policy_id=pid, rule_id=rid, domain_id=rc.DOMAIN)
        except Exception as exc:
            if not rc.is_not_found(exc):
                raise
            live = None
        if live is None:
            reason = "not on the manager (deleted by step 2? put it back with step2_undo.py first)"
        elif not live.get("disabled"):
            reason = "already enabled"
        elif rc.content(live, ("disabled",)) != rc.content(d["after"], ("disabled",)):
            reason = "changed since step 1 disabled it; not touched"
        else:
            reason = None
        if reason:
            row.update(status="skipped", reason=reason)
            log.warning("%s skip: %s", tag, reason)
            continue
        if not args.apply:
            row["status"] = "would_enable"
            log.info("%s DRY: would re-enable (%s)", tag, d.get("action"))
            continue
        if not batch.before_write():
            stopped = True
            row.update(status="not_done", reason="operator stopped")
            break
        try:
            client.put_security_rule(security_policy_id=pid, rule_id=rid,
                                     payload=rc.update_payload(live, disabled=False), domain_id=rc.DOMAIN)
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
            row.update(status="failed", error="still disabled after the write")
            log.error("%s FAILED: %s", tag, row["error"])
            failed = True
            break
        d["reenabled_at"] = datetime.now(timezone.utc).isoformat()
        rc.write_json(rec_path, record)
        row["status"] = "enabled"
        log.info("%s RE-ENABLED", tag)
        batch.record({"display_name": f"{pid}/{d.get('display_name') or rid}", "status": "enabled"})

    ok = not failed and not stopped
    print()
    print(f"Step 1 undo {mode.upper()} on {host}:")
    for r in results:
        print(f"  {r.get('status', '?'):<12} {r['policy_id']}/{r['rule_id']}"
              + (f"  ({r.get('reason') or r.get('error')})" if r.get("reason") or r.get("error") else ""))
    print(f"Result: {'OK' if ok else ('STOPPED by operator' if stopped else 'FAILED')}")
    if ok and not args.apply and any(r["status"] == "would_enable" for r in results):
        print("Read the dry run above, then: " + rc.next_command(
            "step1_undo.py", args, " ".join(f'--rule "{n}"' for n in args.rule) + " --apply"))
    rc.record_step(run, f"undo_step1_{mode}", {"ok": ok, "rules_selected": args.rule or "all",
                                               "piped_answers": args.piped_answers, "results": results,
                                               "decisions": batch.decisions})
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
