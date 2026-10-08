#!/usr/bin/env python3
"""tools/nsx/critical_rules/step1_stats.py

Critical-rules copy, step 1 of 4: gather hit stats on the source.

Starts a new run folder, runs the rules-usage report against the source
(read only; it falls back to the older firewall API when NSX 3.2.x answers the
Policy-API statistics call with HTTP 500), and lists every customer rule with
hits. The Application rules in that list are the ones step 2 keeps.

USAGE:
    python tools/nsx/critical_rules/step1_stats.py --source nsx-lm2 --target nsx-lm3

OUTPUT:
    nsx_critical_runs/<source>_to_<target>/<UTC_TS>/
        run.json, hits.json, stats/<host>/rules_usage/<ts>/, logs/

Next: step2_pull.py. Runbook: docs/nsx/RUNBOOK_CRITICAL_RULES.md
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "app"))
from common.logs import setup_logging                  # noqa: E402
from nsx.nsx_constants import resolve_manager          # noqa: E402
import nsx.critical_rules as cr                        # noqa: E402

log = logging.getLogger("critical_rules")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--source", required=True, choices=cr.LM_CHOICES, help="manager the rules come from (read only)")
    p.add_argument("--target", required=True, choices=cr.LM_CHOICES, help="new, empty manager they go to")
    cr.add_runs_dir_arg(p)
    args = p.parse_args()
    if args.source == args.target:
        raise SystemExit("source and target are the same manager")

    src_host, tgt_host = resolve_manager(args.source), resolve_manager(args.target)
    run = cr.new_run(args.source, args.target, src_host, tgt_host, base=cr.runs_base(args.runs_dir))
    cr.use_run_environment(run)
    setup_logging("step1_stats", run / "logs")
    log.info("Run: %s", run)

    res = cr.run_tool("step1_rules_usage", [
        cr.PY, cr.tool("tools/reports/report_rules_usage.py"), "--target", args.source,
        "--include-defaults", "--output-base", str(run / "stats"),
    ], run / "logs")
    if not res["ok"]:
        cr.record_step(run, "stats", {"ok": False, "tools": [res]})
        log.error("rules-usage report failed; see %s", res["log"])
        return 1

    report = cr.newest_report(run / "stats", src_host)
    rows = cr.hit_rows(report)
    (run / "hits.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    summary = json.loads((report / "summary.json").read_text(encoding="utf-8"))

    print()
    print(f"Rules with hits on {src_host} (default sections left out):")
    for r in rows:
        print(f"  {r.get('policy_category', ''):<15} {r['policy_id']:<26} {r['rule_id']:<32} "
              f"{r.get('action', ''):<6} {r['hit_count']}")
    by_cat = Counter(r.get("policy_category", "?") for r in rows)
    print(f"Statistics source per policy: {summary.get('stats_source_summary')}")
    print(f"Rules with hits by category: {dict(by_cat)}")
    print(f"Report: {report}")
    print()
    print("Next:")
    print("  " + cr.next_command("step2_pull.py", args))

    cr.record_step(run, "stats", {
        "ok": True, "report": str(report), "rules_with_hits": len(rows),
        "by_category": dict(by_cat), "stats_source_summary": summary.get("stats_source_summary"),
        "tools": [res],
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
