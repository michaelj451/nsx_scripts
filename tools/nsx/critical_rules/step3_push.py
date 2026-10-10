#!/usr/bin/env python3
"""tools/nsx/critical_rules/step3_push.py

Critical-rules copy, step 3 of 4: push the two bundles to the new manager.

Checks first that the target holds no customer policies, groups or services
(only NSX's two default sections). Then runs the four push tools for the
Infrastructure bundle, then for the hit-rules bundle: services, groups
(segment references stripped), policies, rules. It stops at the first step
that fails.

Dry run by default: every push reports what it would do and nothing is
written. Read that output, then run again with --apply, in a terminal: the
push tools ask before every batch (Enter=continue, number=batch size, x=stop).
Without a terminal --apply is refused, so it can never stop after one object
and leave the target half done; --piped-answers allows answers fed on stdin
(only with the operator's approval). --apply refuses a
target that is not empty; after a partial apply, rerun with
--allow-non-empty to continue (pushes skip objects that are already identical).

USAGE:
    python tools/nsx/critical_rules/step3_push.py --source nsx-lm2 --target nsx-lm3
    python tools/nsx/critical_rules/step3_push.py --source nsx-lm2 --target nsx-lm3 --apply

Each push writes its report and revert baseline under <bundle>/<class>/push_report/.
Next: step4_verify.py. Undo: revert.py. Runbook: docs/nsx/RUNBOOK_CRITICAL_RULES.md
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "app"))
from common.logs import setup_logging                  # noqa: E402
import nsx.critical_rules as cr                        # noqa: E402

log = logging.getLogger("critical_rules")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--source", required=True, choices=cr.LM_CHOICES)
    p.add_argument("--target", required=True, choices=cr.LM_CHOICES)
    p.add_argument("--run", help="run folder (default: newest for this source/target)")
    cr.add_runs_dir_arg(p)
    p.add_argument("--apply", action="store_true", help="write to the target (default: dry run)")
    p.add_argument("--allow-non-empty", action="store_true",
                   help="apply even though the target already holds customer objects")
    p.add_argument("--segments-mode", default="strip", choices=["strip", "keep", "convert"],
                   help="segment references inside groups (default: strip)")
    cr.add_piped_answers_arg(p)
    args = p.parse_args()
    cr.require_terminal(args.apply, args.piped_answers)

    run = cr.resolve_run(args.source, args.target, args.run, base=cr.runs_base(args.runs_dir))
    rec = cr.load_record(run)
    cr.check_pair(rec, args.source, args.target)
    cr.check_target_host(rec, args.target)
    pull = rec.get("steps", {}).get("pull") or {}
    if not pull.get("ok"):
        raise SystemExit(f"no successful step 2 in {run}; run step2_pull.py first")
    bundles = {"infra": Path(pull["infra"]), "hits": Path(pull["hits"])}
    mode = "apply" if args.apply else "dryrun"
    cr.use_run_environment(run)
    setup_logging(f"step3_push_{mode}", run / "logs")
    log.info("Run: %s", run)

    from nsx.nsx_policy_client import NsxPolicyClient
    client = NsxPolicyClient(nsxmanager=rec["target_host"], federation_global=False)
    current = cr.target_objects(client)
    empty = cr.is_empty(current)
    log.info("Target %s customer objects now: %s", rec["target_host"],
             {k: len(v) for k, v in current.items()})
    if not empty:
        for k in cr.CLASSES:
            if current[k]:
                log.warning("  already on the target, %s (%d): %s", k, len(current[k]), sorted(current[k])[:25]
                            + (["..."] if len(current[k]) > 25 else []))
        if args.apply and not args.allow_non_empty:
            log.error("target is not empty; refusing to apply (use --allow-non-empty to continue a partial apply)")
            cr.record_step(run, f"push_{mode}", {"ok": False, "refused": "target not empty",
                                                 "target_objects": {k: sorted(v) for k, v in current.items()}})
            return 2
        log.warning("target is not empty: objects that already exist will show as update or unchanged")

    results = []
    for label, cmd in cr.push_steps(bundles, args.target, args.apply, args.segments_mode):
        res = cr.run_tool(label, cmd, run / "logs" / f"push_{mode}")
        results.append(res)
        if not res["ok"]:
            break

    print()
    print(f"Push {mode.upper()} to {rec['target_host']}:")
    for r in results:
        print(f"  {'OK  ' if r['ok'] else 'FAIL'} {r['label']:<32} {r['summary'] or ''}")
    ok = len(results) == 2 * len(cr.CLASSES) and all(r["ok"] for r in results)
    print(f"Result: {'OK' if ok else 'FAILED'}")
    print()
    if ok and not args.apply:
        print("Read the dry run above, then apply:")
        print("  " + cr.next_command("step3_push.py", args, "--apply"))
    elif ok:
        print("Next:")
        print("  " + cr.next_command("step4_verify.py", args))

    cr.record_step(run, f"push_{mode}", {"ok": ok, "target_was_empty": empty,
                                         "piped_answers": args.piped_answers, "steps": results})
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
