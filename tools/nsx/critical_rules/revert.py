#!/usr/bin/env python3
"""tools/nsx/critical_rules/revert.py

Critical-rules copy: undo step 3 on the target.

Hit-rules bundle first, then Infrastructure; within each bundle rules,
policies, groups, services. Every push step 3 made is undone, newest first,
including an earlier apply that stopped partway: each push left a baseline
under <bundle>/<class>/push_report/baselines/, and the push tool renames a
baseline to *.reverted once a revert completes, so this repeats each class's
revert until no baseline is left. That returns the target to empty. Groups are
reverted with --allow-delete: without it groups.py leaves the groups its push
created and still exits 0.

Dry run by default (shows every pending push's plan); --apply to write. The
revert tools ask before every batch, so --apply needs a terminal (or
--piped-answers, only with the operator's approval). Stops at the first step
that fails.

USAGE:
    python tools/nsx/critical_rules/revert.py --source nsx-lm2 --target nsx-lm3
    python tools/nsx/critical_rules/revert.py --source nsx-lm2 --target nsx-lm3 --apply

Runbook: docs/nsx/RUNBOOK_CRITICAL_RULES.md
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
    cr.add_piped_answers_arg(p)
    args = p.parse_args()
    cr.require_terminal(args.apply, args.piped_answers)

    run = cr.resolve_run(args.source, args.target, args.run, base=cr.runs_base(args.runs_dir))
    rec = cr.load_record(run)
    cr.check_pair(rec, args.source, args.target)
    cr.check_target_host(rec, args.target)
    pull = rec.get("steps", {}).get("pull") or {}
    if not pull.get("ok"):
        raise SystemExit(f"no successful step 2 in {run}; nothing to revert")
    bundles = {"infra": Path(pull["infra"]), "hits": Path(pull["hits"])}
    mode = "apply" if args.apply else "dryrun"
    cr.use_run_environment(run)
    setup_logging(f"revert_{mode}", run / "logs")
    log.info("Run: %s", run)

    results = []
    failed = False
    log_dir = run / "logs" / f"revert_{mode}"
    for label, cmd in cr.revert_steps(bundles, args.target, args.apply):
        reports = Path(cmd[cmd.index("--reports-dir") + 1])
        pending = cr.unreverted_baselines(reports)
        if not pending:
            why = "already reverted" if cr.reverted_baselines(reports) else "never applied"
            results.append({"label": label, "ok": True, "skipped": why})
            continue
        for i, baseline in enumerate(pending, start=1):
            step = f"{label}_{i}of{len(pending)}" if len(pending) > 1 else label
            if args.apply:
                # the tool takes the newest un-reverted baseline and marks it reverted when done
                res = cr.run_tool(step, cmd, log_dir)
                left = cr.unreverted_baselines(reports)
                if res["ok"] and baseline in left:
                    res.update(ok=False, error=f"baseline {baseline.name} was not marked reverted "
                                              f"(stopped at a prompt?)")
            else:
                res = cr.run_tool(step, cmd + ["--from-baseline", str(baseline)], log_dir)
            res["baseline"] = baseline.name
            results.append(res)
            if not res["ok"]:
                failed = True
                break
        if failed:
            break

    ok = not failed and all(r["ok"] for r in results)
    print()
    print(f"Revert {mode.upper()} on {rec['target_host']}:")
    for r in results:
        note = f"  ({r['skipped']})" if r.get("skipped") else f"  baseline {r.get('baseline')}"
        if r.get("error"):
            note += f"  {r['error']}"
        print(f"  {'SKIP' if r.get('skipped') else ('OK  ' if r['ok'] else 'FAIL')} {r['label']:<36}{note}")
    if all(r.get("skipped") for r in results):
        print("Nothing left to revert in this run (never applied, or already reverted).")
    print(f"Result: {'OK' if ok else 'FAILED'}")
    if ok and not args.apply and not all(r.get("skipped") for r in results):
        print("Read the dry run above, then: " + cr.next_command("revert.py", args, "--apply"))

    cr.record_step(run, f"revert_{mode}", {"ok": ok, "piped_answers": args.piped_answers, "steps": results})
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
