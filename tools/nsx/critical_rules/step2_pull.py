#!/usr/bin/env python3
"""tools/nsx/critical_rules/step2_pull.py

Critical-rules copy, step 2 of 4: pull those objects into two bundles.

In the newest run folder for this source/target (or --run):
  1. capture the source (read only; refreshes the flat exports the bundle
     tools read; --no-capture reuses the current ones);
  2. Infrastructure bundle: every Infrastructure policy, whole, original order
     (filter_policy_bundle.py);
  3. hit-rules bundle: every Application rule with hit_count > --min-hits, in
     one new policy, busiest first (consolidate_hot_rules.py);
then prints the new policy's rule order with each action, so a DROP or REJECT
that moved above an ALLOW can be checked, and compares the kept rules with
step 1's list. Each bundle goes into its own folder of the run, so the two
can never collide.

USAGE:
    python tools/nsx/critical_rules/step2_pull.py --source nsx-lm2 --target nsx-lm3

Next: step3_push.py. Runbook: docs/nsx/RUNBOOK_CRITICAL_RULES.md
"""
from __future__ import annotations

import argparse
import json
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
    p.add_argument("--no-capture", action="store_true", help="reuse the current flat exports")
    p.add_argument("--whole-categories", default="Infrastructure",
                   help="categories copied whole (default: Infrastructure)")
    p.add_argument("--hit-categories", default="Application",
                   help="categories filtered by hits (default: Application)")
    p.add_argument("--min-hits", type=int, default=0, help="keep rules with hit_count > this (default 0)")
    p.add_argument("--policy-id", default="critical-rules", help="id of the new policy")
    p.add_argument("--policy-name", default="Critical Rules", help="display name of the new policy")
    args = p.parse_args()

    run = cr.resolve_run(args.source, args.target, args.run)
    rec = cr.load_record(run)
    cr.check_pair(rec, args.source, args.target)
    src_host = rec["source_host"]
    setup_logging("step2_pull", run / "logs")
    log.info("Run: %s", run)
    if (run / "infra").exists() or (run / "hits").exists():
        raise SystemExit(f"this run already has bundles ({run}); start a new run with step1_stats.py")

    tools = []
    if not args.no_capture:
        tools.append(cr.run_tool("step2_capture", [
            cr.PY, "tools/nsx/capture_nsx_state.py", "--source", args.source, "--live-query"], run / "logs"))
        if not tools[-1]["ok"]:
            cr.record_step(run, "pull", {"ok": False, "tools": tools})
            return 1
    tools.append(cr.run_tool("step2_infra_bundle", [
        cr.PY, "tools/nsx/filter_policy_bundle.py", "--source", args.source,
        "--categories", args.whole_categories, "--output-base", str(run / "infra")], run / "logs"))
    tools.append(cr.run_tool("step2_hits_bundle", [
        cr.PY, "tools/nsx/consolidate_hot_rules.py", "--source", args.source,
        "--categories", args.hit_categories, "--min-hits", str(args.min_hits),
        "--new-policy-id", args.policy_id, "--new-policy-display", args.policy_name,
        "--output-base", str(run / "hits")], run / "logs"))
    if not all(t["ok"] for t in tools):
        cr.record_step(run, "pull", {"ok": False, "tools": tools})
        log.error("a bundle tool failed; nothing to push")
        return 1

    infra = cr.single_bundle(run / "infra", src_host)
    hits = cr.single_bundle(run / "hits", src_host)
    im = json.loads((infra / "manifest.json").read_text(encoding="utf-8"))
    hm = json.loads((hits / "manifest.json").read_text(encoding="utf-8"))
    order = cr.hit_rules_order(hits)

    print()
    print(f"Infrastructure bundle: {infra}")
    print(f"  {im['counts']}")
    print(f"  unresolved: {im.get('unresolved')}")
    print(f"Hit-rules bundle: {hits}")
    print(f"  statistics source per policy: {hm.get('stats_source')}")
    print(f"  policy {args.policy_id!r}, new order:")
    for r in order:
        print(f"    {r['sequence']:>3} {r['action']:<6} {r['id']:<32} hits={r['hits']}")
    print(f"  skipped (no hits): {sorted(s['rule_id'] for s in hm.get('skipped_rules', []))}")
    print(f"  unresolved: {hm.get('unresolved')}  segments: {hm.get('segments_referenced_by_groups')}  "
          f"id collisions: {hm['counts'].get('id_collisions')}")
    blocking = [r for r in order if r["action"] in ("DROP", "REJECT")]
    if blocking:
        print(f"  CHECK: {len(blocking)} DROP/REJECT rule(s) in the new order: "
              f"{[(r['sequence'], r['id']) for r in blocking]}; compare each with the ALLOW rules below it")

    hit_cats = {c.strip() for c in args.hit_categories.split(",")}
    step1 = {r["rule_id"] for r in json.loads((run / "hits.json").read_text(encoding="utf-8"))
             if r.get("policy_category") in hit_cats and r["hit_count"] > args.min_hits} \
        if (run / "hits.json").is_file() else None
    kept = {k["orig_id"] for k in hm.get("kept_rules", [])}
    if step1 is not None and step1 != kept:
        print(f"  NOTE: kept rules differ from step 1 (counters moved?): "
              f"only in step 1 {sorted(step1 - kept)}, only now {sorted(kept - step1)}")
    elif step1 is not None:
        print(f"  kept rules match step 1 ({len(kept)})")
    print()
    print("Next (dry run):")
    print(f"  python tools/nsx/critical_rules/step3_push.py --source {args.source} --target {args.target}")

    cr.record_step(run, "pull", {
        "ok": True, "infra": str(infra), "hits": str(hits), "policy_id": args.policy_id,
        "infra_counts": im["counts"], "hits_counts": hm["counts"], "kept_rules": sorted(kept),
        "order": order, "tools": tools,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
