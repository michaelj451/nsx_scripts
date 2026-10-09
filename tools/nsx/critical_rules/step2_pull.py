#!/usr/bin/env python3
"""tools/nsx/critical_rules/step2_pull.py

Critical-rules copy, step 2 of 4: pull those objects into two bundles.

Policies and rules are copied exactly as they are on the source: same ids,
names, sequence numbers and settings. Nothing is renamed, merged or reordered.

In the newest run folder for this source/target (or --run):
  1. capture the source (read only) into the run, and write the flat exports
     the bundles are built from into the run as well (nothing lands in the repo);
  2. Infrastructure bundle: every Infrastructure policy with every one of its
     rules (--whole-categories);
  3. hot-rules bundle: every Application policy that holds at least one active
     (hot) rule, with only its hot rules (--hit-categories). Hot means the
     rule's hit count in step 1's report is above --min-hits (default 0).
     A policy with no hot rule is not copied.
NSX's own system defaults are never copied (default sections and their rules,
anything _system_owned, anything NSX created itself).

Then it checks, and stops if either fails: no system default is in either
bundle, and every non-default policy of the copied-whole categories is in the
Infrastructure bundle with all its rules. It lists every policy as it will land
on the target, the hot rules left out because of their category, and every
DROP/REJECT rule not copied (no hits), so the effect of leaving it out can be
checked.

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


def _categories(text: str) -> set:
    return {c.strip() for c in text.split(",") if c.strip()}


def _print_bundle(title: str, bundle: Path, hits: dict) -> dict:
    m = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    print(f"{title}: {bundle}")
    for p in m["policies"]:
        print(f"  policy {p['id']} ({p['display_name']}), {p['category']}, sequence {p['sequence_number']}")
        for r in p["rules"]:
            print(f"      {r['sequence_number']:>4} {r['action']:<6} {r['id']:<32} "
                  f"hits={hits.get((p['id'], r['id']), 0)}{'  (disabled)' if r['disabled'] else ''}")
        if p["not_copied"]:
            print(f"      not copied (no hits): {[r['id'] for r in p['not_copied']]}")
    for s in m["skipped_policies"]:
        print(f"  not copied: policy {s['policy']} ({s['reason']})")
    print(f"  counts: {m['counts']}")
    print(f"  unresolved: {m['unresolved']}  segments: {m['segments_referenced_by_groups']}")
    return m


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--source", required=True, choices=cr.LM_CHOICES)
    p.add_argument("--target", required=True, choices=cr.LM_CHOICES)
    p.add_argument("--run", help="run folder (default: newest for this source/target)")
    cr.add_runs_dir_arg(p)
    p.add_argument("--whole-categories", default="Infrastructure",
                   help="categories copied whole, every rule (default: Infrastructure)")
    p.add_argument("--hit-categories", default="Application",
                   help="categories copied with their hot rules only (default: Application)")
    p.add_argument("--min-hits", type=int, default=0, help="a rule is hot when hit_count > this (default 0)")
    args = p.parse_args()

    whole_cats, hit_cats = _categories(args.whole_categories), _categories(args.hit_categories)
    if whole_cats & hit_cats:
        raise SystemExit(f"a category cannot be both whole and hot-only: {sorted(whole_cats & hit_cats)}")
    run = cr.resolve_run(args.source, args.target, args.run, base=cr.runs_base(args.runs_dir))
    rec = cr.load_record(run)
    cr.check_pair(rec, args.source, args.target)
    if not (run / "hits.json").is_file():
        raise SystemExit(f"no step 1 hit list in {run}; run step1_stats.py first")
    src_host = rec["source_host"]
    cr.use_run_environment(run)
    setup_logging("step2_pull", run / "logs")
    log.info("Run: %s", run)
    if any((run / d).exists() for d in ("capture", "infra", "hits")):
        raise SystemExit(f"this run already has a capture or bundles ({run}); start a new run with step1_stats.py")

    tools = [cr.run_tool("step2_capture", [
        cr.PY, cr.tool("tools/nsx/capture_nsx_state.py"), "--source", args.source,
        "--output-dir", str(run / "capture"), "--no-flat-exports"], run / "logs")]
    if not tools[-1]["ok"]:
        cr.record_step(run, "pull", {"ok": False, "tools": tools})
        return 1
    exported = cr.emit_flat_exports(run / "capture", src_host, run)
    log.info("Flat exports in the run: %s", exported)

    rows = json.loads((run / "hits.json").read_text(encoding="utf-8"))
    hits = {(r["policy_id"], r["rule_id"]): r["hit_count"] for r in rows}
    hot = {(r["policy_id"], r["rule_id"]) for r in rows
           if r.get("policy_category") in hit_cats and r["hit_count"] > args.min_hits}
    hot_elsewhere = sorted(f"{r['policy_id']}/{r['rule_id']} ({r.get('policy_category')})" for r in rows
                           if r.get("policy_category") not in hit_cats | whole_cats)

    infra = cr.build_bundle(run, src_host, run / "infra", whole_cats)
    hot_bundle = cr.build_bundle(run, src_host, run / "hits", hit_cats, hot=hot)

    sources = cr.source_policies(run, src_host)
    system_found = cr.system_defaults_in_bundle(infra) + cr.system_defaults_in_bundle(hot_bundle)
    gaps = cr.whole_category_gaps(sources, whole_cats, infra)
    copied_hot = cr.bundle_objects(hot_bundle)["rules"]
    hot_missing = sorted(f"{pid}/{rid}" for pid, rid in hot if f"{pid}/{rid}" not in copied_hot)
    left_out = [f"{s['id']} ({s['category']})" for s in sources if s["system_default"]]
    whole = [s for s in sources if s["category"] in whole_cats and not s["system_default"]]

    print()
    im = _print_bundle(f"{', '.join(sorted(whole_cats))} bundle (every rule)", infra, hits)
    print()
    hm = _print_bundle(f"{', '.join(sorted(hit_cats))} bundle (hot rules only, hit_count > {args.min_hits})",
                       hot_bundle, hits)
    print()
    if gaps:
        print(f"MISSING from the {', '.join(sorted(whole_cats))} bundle: {gaps}")
    else:
        print(f"{', '.join(sorted(whole_cats))} copied whole: all {len(whole)} policies, "
              f"{sum(len(s['rules']) for s in whole)} rules")
    print(f"Hot rules copied: {len(copied_hot)} of {len(hot)}"
          + (f"; MISSING {hot_missing}" if hot_missing else ""))
    if hot_elsewhere:
        print(f"NOTE: rules with hits in other categories, not copied: {hot_elsewhere}")
    print(f"System defaults left out (never copied): {left_out or 'none'}")
    print(f"System defaults in the bundles: {system_found or 'none'}")
    not_copied = [(q["id"], r) for q in hm["policies"] for r in q["not_copied"]]
    not_copied += [(s["policy"], r) for s in hm["skipped_policies"] for r in s.get("rules", [])]
    blocking = [f"{pid}/{r['id']} ({r['action']}{', disabled' if r['disabled'] else ''})"
                for pid, r in not_copied if r["action"] in ("DROP", "REJECT")]
    if blocking:
        print(f"CHECK: DROP/REJECT rules not copied (no hits): {blocking}; traffic they would block "
              f"falls through to later rules on the target")

    if system_found or gaps or hot_missing:
        print()
        print("STOP: " + "; ".join(
            ([f"system default objects in the bundles: {system_found}"] if system_found else []) +
            ([f"copied-whole policies or rules missing: {gaps}"] if gaps else []) +
            ([f"hot rules missing: {hot_missing}"] if hot_missing else [])))
        cr.record_step(run, "pull", {"ok": False, "system_defaults_in_bundles": system_found,
                                     "whole_category_gaps": gaps, "hot_missing": hot_missing,
                                     "infra": str(infra), "hits": str(hot_bundle), "tools": tools})
        return 1
    print()
    print("Next (dry run):")
    print("  " + cr.next_command("step3_push.py", args))

    cr.record_step(run, "pull", {
        "ok": True, "capture": str(run / "capture"), "flat_exports": exported,
        "infra": str(infra), "hits": str(hot_bundle),
        "infra_counts": im["counts"], "hits_counts": hm["counts"],
        "hot_rules": sorted(f"{a}/{b}" for a, b in hot), "min_hits": args.min_hits,
        "system_defaults_left_out": left_out, "whole_policies": [s["id"] for s in whole],
        "tools": tools,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
