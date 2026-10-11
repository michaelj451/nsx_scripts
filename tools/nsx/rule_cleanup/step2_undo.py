#!/usr/bin/env python3
"""tools/nsx/rule_cleanup/step2_undo.py

Unused rule cleanup: undo step 2 by putting back every object it deleted.

Reads step2/deleted.json (each object's full JSON, saved right before it was
deleted) and re-creates the objects with their original ids: groups first,
nested ones before the groups that nest them, then policies (without rules),
then rules with their original sequence numbers. Rules come back disabled,
as they were when deleted; step1_undo.py can then re-enable them. An object
that is already on the manager is left alone.

Dry run by default; --apply writes, in a terminal: asks before every batch
(Enter=continue, number=batch size, n=reset to 1, x=stop). --piped-answers
allows answers fed on stdin (only with the operator's approval). Stops at the
first write that fails.

USAGE:
    python tools/nsx/rule_cleanup/step2_undo.py --target nsx-lm2
    python tools/nsx/rule_cleanup/step2_undo.py --target nsx-lm2 --apply

Runbook: docs/nsx/RUNBOOK_RULE_CLEANUP.md
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "app"))
from common.logs import setup_logging                  # noqa: E402
from nsx.apply_batch import ApplyBatch                 # noqa: E402
from nsx.nsx_constants import resolve_manager          # noqa: E402
import nsx.critical_rules as cr                        # noqa: E402
import nsx.rule_cleanup as rc                          # noqa: E402

log = logging.getLogger("rule_cleanup")


def calls(client: Any, d: Dict[str, Any]) -> Tuple[str, Callable[[], Any], Callable[[], Any]]:
    """(label, read the object, re-create it) for one deleted object."""
    obj, dom = d["obj"], rc.DOMAIN
    if d["kind"] == "group":
        gid = d["group_id"]
        return (f"group {gid}", lambda: client.get_group(group_id=gid, domain_id=dom),
                lambda: client.put_group(gid, rc.create_payload(obj), domain_id=dom))
    if d["kind"] == "policy":
        pid = d["policy_id"]
        return (f"policy {pid}", lambda: client.get_security_policy(security_policy_id=pid, domain_id=dom),
                lambda: client.put_security_policy(pid, rc.create_payload(obj, rc.POLICY_CREATE_DROP),
                                                   domain_id=dom))
    pid, rid = d["policy_id"], d["rule_id"]
    return (f"rule {pid}/{rid}",
            lambda: client.get_security_rule(security_policy_id=pid, rule_id=rid, domain_id=dom),
            lambda: client.put_security_rule(security_policy_id=pid, rule_id=rid,
                                             payload=rc.create_payload(obj), domain_id=dom))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--target", required=True, choices=cr.LM_CHOICES)
    p.add_argument("--run", help="run folder (default: newest for this target)")
    rc.add_runs_dir_arg(p)
    p.add_argument("--apply", action="store_true", help="write to the manager (default: dry run)")
    cr.add_piped_answers_arg(p)
    args = p.parse_args()
    cr.require_terminal(args.apply, args.piped_answers)

    host = resolve_manager(args.target)
    run = rc.resolve_run(args.target, args.run, base=rc.runs_base(args.runs_dir))
    rec = rc.load_record(run)
    rc.check_run(rec, args.target, host)
    del_path = run / "step2" / "deleted.json"
    deleted = rc.read_json(del_path, {"objects": []})
    pending = [d for d in deleted["objects"] if not d.get("restored_at")]
    if not pending:
        raise SystemExit(f"nothing to put back in {run}: step 2 deleted nothing there, or all of it was restored")
    mode = "apply" if args.apply else "dryrun"
    setup_logging(f"step2_undo_{mode}", run / "logs")
    log.info("Run: %s", run)

    from nsx.nsx_policy_client import NsxPolicyClient
    client = NsxPolicyClient(nsxmanager=host, federation_global=False)
    if not args.apply:
        rc.lock_read_only(client)

    batch = ApplyBatch(args.apply, log)
    results: List[Dict[str, Any]] = []
    failed = stopped = False
    order = rc.restore_order(pending)
    for i, d in enumerate(order, start=1):
        label, read, create = calls(client, d)
        tag = f"[{i}/{len(order)}] {label}"
        row = {"kind": d["kind"], "label": label}
        results.append(row)
        try:
            read()
            row.update(status="skipped", reason="already on the manager")
            log.info("%s skip: already on the manager", tag)
            continue
        except Exception as exc:
            if not rc.is_not_found(exc):
                raise
        if not args.apply:
            row["status"] = "would_restore"
            log.info("%s DRY: would re-create", tag)
            continue
        if not batch.before_write():
            stopped = True
            row.update(status="not_done", reason="operator stopped")
            break
        try:
            create()
            read()
        except Exception as exc:
            row.update(status="failed", error=str(exc)[:300])
            log.error("%s FAILED: %s", tag, exc)
            failed = True
            break
        d["restored_at"] = datetime.now(timezone.utc).isoformat()
        rc.write_json(del_path, deleted)
        row["status"] = "restored"
        log.info("%s RESTORED", tag)
        batch.record({"display_name": label, "status": "restored"})

    ok = not failed and not stopped
    print()
    print(f"Step 2 undo {mode.upper()} on {host}:")
    for r in results:
        print(f"  {r.get('status', '?'):<13} {r['label']}"
              + (f"  ({r.get('reason') or r.get('error')})" if r.get("reason") or r.get("error") else ""))
    print(f"Result: {'OK' if ok else ('STOPPED by operator' if stopped else 'FAILED')}")
    if ok and not args.apply and any(r["status"] == "would_restore" for r in results):
        print("Read the dry run above, then: " + rc.next_command("step2_undo.py", args, "--apply"))
    elif ok and args.apply:
        print("Rules are back, still disabled. To re-enable them: " + rc.next_command("step1_undo.py", args))
    rc.record_step(run, f"undo_step2_{mode}", {"ok": ok, "piped_answers": args.piped_answers,
                                               "results": results, "decisions": batch.decisions})
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
