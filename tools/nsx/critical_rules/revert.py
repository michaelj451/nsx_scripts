#!/usr/bin/env python3
"""tools/nsx/critical_rules/revert.py

Critical-rules copy: undo step 3 on the target.

Hit-rules bundle first, then Infrastructure; within each bundle rules,
policies, groups, services. Each revert uses the baseline its own push wrote
under <bundle>/<class>/push_report/ and removes what that push created, which
returns the target to empty. Groups are reverted with --allow-delete: without
it groups.py leaves the groups its push created and still exits 0.

Dry run by default; --apply to write. Stops at the first step that fails.

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
    args = p.parse_args()

    run = cr.resolve_run(args.source, args.target, args.run, base=cr.runs_base(args.runs_dir))
    rec = cr.load_record(run)
    cr.check_pair(rec, args.source, args.target)
    pull = rec.get("steps", {}).get("pull") or {}
    if not pull.get("ok"):
        raise SystemExit(f"no successful step 2 in {run}; nothing to revert")
    bundles = {"infra": Path(pull["infra"]), "hits": Path(pull["hits"])}
    mode = "apply" if args.apply else "dryrun"
    cr.use_run_environment(run)
    setup_logging(f"revert_{mode}", run / "logs")
    log.info("Run: %s", run)

    results = []
    for label, cmd in cr.revert_steps(bundles, args.target, args.apply):
        reports = Path(cmd[cmd.index("--reports-dir") + 1])
        if not any((reports / "baselines").glob("*")):
            # step 3 never applied this class (dry runs write no baseline)
            results.append({"label": label, "ok": True, "skipped": "never applied"})
            continue
        res = cr.run_tool(label, cmd, run / "logs" / f"revert_{mode}")
        results.append(res)
        if not res["ok"]:
            break

    ok = len(results) == 2 * len(cr.CLASSES) and all(r["ok"] for r in results)
    print()
    print(f"Revert {mode.upper()} on {rec['target_host']}:")
    for r in results:
        print(f"  {'SKIP' if r.get('skipped') else ('OK  ' if r['ok'] else 'FAIL')} {r['label']}"
              f"{'  (' + r['skipped'] + ')' if r.get('skipped') else ''}")
    if all(r.get("skipped") for r in results):
        print("Nothing was applied in this run, so there is nothing to revert.")
    print(f"Result: {'OK' if ok else 'FAILED'}")
    if ok and not args.apply and not all(r.get("skipped") for r in results):
        print("Read the dry run above, then: " + cr.next_command("revert.py", args, "--apply"))

    cr.record_step(run, f"revert_{mode}", {"ok": ok, "steps": results})
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
