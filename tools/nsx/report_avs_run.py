#!/usr/bin/env python3
"""tools/nsx/report_avs_run.py

One consolidated "what did this run change?" report for an AVS / WF-A / WF-C
sequence, built entirely from the per-tool push reports already on disk.

Offline: reads JSON, contacts no NSX manager. Pair it with
verify_avs_run.py, which is the live check.

Each push tool writes <bundle>/push_report/{services,groups,policies,rules}.json
plus baselines/. This walks every report root it is given, classifies each row
(created / updated / ip-removal / skipped / failed), and emits:

    <out-dir>/avs_run_report.json    machine-readable, every row
    <out-dir>/avs_run_report.md      operator-facing summary table

USAGE:
    python tools/nsx/report_avs_run.py \\
        --report-root nsx_services_export/nsx-lm1.lab.local \\
        --report-root nsx_groups_export/nsx-lm1.lab.local \\
        --report-root nsx_policies_export/nsx-lm1.lab.local \\
        --report-root nsx_rules_export/nsx-lm1.lab.local \\
        --report-root nsx_avs_runs/v2/nsx_sibling_groups/nsx-lm1.lab.local \\
        --report-root nsx_avs_runs/v2/nsx_stripped_groups/nsx-lm1.lab.local \\
        --out-dir nsx_avs_runs/v2/report

    # Only rows from this run (skip older baselines in the same bundle)
    ... --since 2026-09-09T02:00:00

Exit code is 1 when any row failed, so it is safe as a pipeline gate.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

log = logging.getLogger("report_avs_run")

# Report basenames a push tool can leave behind, mapped to the object class.
REPORT_FILES = {
    "services.json": "service",
    "groups.json": "group",
    "policies.json": "policy",
    "rules.json": "rule",
    "amend_refs.json": "rule-amend",
}

# Row status -> the bucket an operator cares about.
STATUS_BUCKETS = {
    "ok": "applied",
    "success": "applied",
    "success_patch": "applied",
    "success_put": "applied",
    "changed": "applied",
    "created": "applied",
    "updated": "applied",
    "dry_run": "planned",
    "skipped": "skipped",
    "no_change": "no_change",
    "failed": "failed",
    "error": "failed",
}


def bucket_for(status: Optional[str]) -> str:
    return STATUS_BUCKETS.get((status or "").lower(), "other")


# Which workflow step a bundle belongs to. Without this the same object id shows
# up twice with no way to tell the WF-A push from the WF-C stripped push, which
# reads like a duplicate-row bug.
def phase_for(bundle: str, report: str) -> str:
    b = bundle.replace("\\", "/")
    if report == "amend_refs.json":
        return "C5 amend-refs"
    if "nsx_sibling_groups" in b:
        return "C3 siblings"
    if "nsx_stripped_groups" in b:
        return "C4 stripped"
    if "nsx_pure_ip_remap" in b:
        return "C  pure-ip"
    if "nsx_services_export" in b:
        return "A1 services"
    if "nsx_groups_export" in b:
        return "A2 groups"
    if "nsx_policies_export" in b:
        return "A3 policies"
    if "nsx_rules_export" in b:
        return "A4 rules"
    return "?"


# IP deltas only exist for group pushes. Everything else has no IP concept, so
# saying "not measured" there would imply a gap that is not there.
IP_BEARING = {"group"}


def ip_cell(row: Dict[str, Any]) -> str:
    if row["kind"] not in IP_BEARING:
        return "n/a"
    added, removed = row.get("ips_added"), row.get("ips_removed")
    if added is None and removed is None:
        return "not measured"
    if not added and not removed:
        return "0"
    return f"+{len(added or [])}/-{len(removed or [])}"


def load_rows(root: Path, since: Optional[datetime]) -> List[Dict[str, Any]]:
    """Every row from every recognised report file under <root>/push_report."""
    rows: List[Dict[str, Any]] = []
    pr = root / "push_report"
    if not pr.is_dir():
        log.warning("no push_report/ under %s (nothing pushed from this bundle?)", root)
        return rows

    for name, kind in REPORT_FILES.items():
        f = pr / name
        if not f.is_file():
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            log.error("unreadable report %s: %s", f, exc)
            continue

        # Tools write either a bare list of rows or {rows: [...]}. Accept both.
        raw = data if isinstance(data, list) else (
            data.get("rows") or data.get("results") or [])
        for r in raw:
            if not isinstance(r, dict):
                continue
            ts = r.get("timestamp")
            if since and ts:
                try:
                    if datetime.fromisoformat(str(ts).replace("Z", "+00:00")) < since:
                        continue
                except ValueError:
                    pass
            rows.append({
                "kind": kind,
                "bundle": str(root),
                "report": name,
                "phase": phase_for(str(root), name),
                "id": r.get("id") or r.get("group_id") or r.get("rule_id")
                      or r.get("policy_id") or r.get("service_id"),
                "display_name": r.get("display_name") or r.get("group_name"),
                "status": r.get("status"),
                "bucket": bucket_for(r.get("status")),
                "reason": r.get("reason"),
                "ips_added": r.get("ips_added"),
                "ips_removed": r.get("ips_removed"),
                "refs_added_total": r.get("refs_added_total"),
                "timestamp": ts,
            })
    return rows


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("USAGE:", 1)[1] if "USAGE:" in __doc__ else None)
    p.add_argument("--report-root", action="append", required=True, metavar="DIR",
                   help="Bundle directory containing a push_report/ subdir. Repeatable.")
    p.add_argument("--out-dir", required=True,
                   help="Where to write avs_run_report.{json,md}.")
    p.add_argument("--since", default=None,
                   help="ISO timestamp; drop rows older than this (one run's worth).")
    p.add_argument("--label", default="AVS run",
                   help="Title for the markdown report.")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = __import__("time").gmtime

    since = None
    if args.since:
        since = datetime.fromisoformat(args.since.replace("Z", "+00:00"))
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)

    rows: List[Dict[str, Any]] = []
    for root in args.report_root:
        rows.extend(load_rows(Path(root).expanduser(), since))

    totals: Dict[str, Dict[str, int]] = {}
    for r in rows:
        totals.setdefault(r["kind"], {}).setdefault(r["bucket"], 0)
        totals[r["kind"]][r["bucket"]] += 1

    ips_added = sum(len(r["ips_added"] or []) for r in rows)
    ips_removed = sum(len(r["ips_removed"] or []) for r in rows)
    refs_added = sum(r["refs_added_total"] or 0 for r in rows)
    failed = [r for r in rows if r["bucket"] == "failed"]

    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "label": args.label,
        "report_roots": args.report_root,
        "since": args.since,
        "totals_by_kind": totals,
        "ips_added_total": ips_added,
        "ips_removed_total": ips_removed,
        "refs_added_total": refs_added,
        "failed_count": len(failed),
        "rows": rows,
    }
    (out_dir / "avs_run_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    buckets = ["applied", "planned", "no_change", "skipped", "failed", "other"]
    md = [f"# {args.label}", "",
          f"Generated {report['generated_at']}", ""]
    if args.since:
        md.append(f"Rows since `{args.since}`.\n")
    md += ["## Changes by object class", "",
           "| Class | " + " | ".join(b.replace("_", " ") for b in buckets) + " |",
           "|---|" + "---|" * len(buckets)]
    for kind in sorted(totals):
        md.append(f"| {kind} | " + " | ".join(
            str(totals[kind].get(b, 0)) for b in buckets) + " |")
    md += ["",
           f"- IPs added: **{ips_added}**",
           f"- IPs removed: **{ips_removed}**",
           f"- Rule refs added: **{refs_added}**",
           f"- Failures: **{len(failed)}**", ""]

    # Detail table covers applied AND planned rows: on a dry-run pass every row
    # is 'planned', and a pre-apply report that lists no objects is useless for
    # the review it exists to support.
    applied = [r for r in rows if r["bucket"] == "applied"]
    detail = [r for r in rows if r["bucket"] in ("applied", "planned")]
    if detail:
        planned_only = not applied
        md += ["## Objects " + ("that WOULD change (dry run)" if planned_only
                                else "changed"), ""]
        if planned_only:
            md.append("Nothing has been written.")
        unmeasured = [r for r in detail
                      if r["kind"] in IP_BEARING
                      and r.get("ips_added") is None and r.get("ips_removed") is None]
        if unmeasured:
            md.append(f"{len(unmeasured)} group row(s) show `not measured`: that pass ran "
                      "without `--diff-target`, so its IP delta is unknown (not zero).")
        md += ["", "An object appears once per phase that touches it, so a group in both "
               "the WF-A push and the WF-C stripped push is listed twice.", "",
               "| Phase | Class | Id | Status | IPs +/- | Refs + |",
               "|---|---|---|---|---|---|"]
        for r in sorted(detail, key=lambda x: (x["phase"], x["kind"], str(x["id"]))):
            md.append(f"| {r['phase']} | {r['kind']} | `{r['id']}` | {r['status']} | "
                      f"{ip_cell(r)} | {r['refs_added_total'] or ''} |")
        md.append("")

    if failed:
        md += ["## FAILURES", "", "| Class | Id | Reason |", "|---|---|---|"]
        for r in failed:
            md.append(f"| {r['kind']} | `{r['id']}` | {str(r['reason'])[:120]} |")
        md.append("")

    (out_dir / "avs_run_report.md").write_text("\n".join(md), encoding="utf-8")

    log.info("Rows: %d  applied=%d failed=%d  ips +%d/-%d  refs +%d",
             len(rows), len(applied), len(failed), ips_added, ips_removed, refs_added)
    log.info("Report: %s", out_dir / "avs_run_report.md")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
