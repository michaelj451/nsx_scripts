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
import collections
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

# Object classes get their own section, in push dependency order, so a reviewer
# can answer "which rules changed?" without filtering a mixed table by eye.
KIND_ORDER = ["service", "group", "policy", "rule", "rule-amend"]
KIND_LABEL = {"service": "Services", "group": "Groups", "policy": "Policies",
              "rule": "Rules", "rule-amend": "Rule reference amendments"}


def table(headers: List[str], body: List[List[str]]) -> List[str]:
    """Render a markdown table with every column padded to a fixed width.

    Markdown renders either way, but these reports are read as plain text in a
    terminal and pasted into change records, where a ragged table is hard to
    scan. Padding costs nothing and makes the columns line up.
    """
    if not body:
        return []
    cols = len(headers)
    grid = [[("" if c is None else str(c)) for c in (r + [""] * (cols - len(r)))[:cols]]
            for r in body]
    width = [max(len(headers[i]), max((len(r[i]) for r in grid), default=0))
             for i in range(cols)]
    out = ["| " + " | ".join(h.ljust(width[i]) for i, h in enumerate(headers)) + " |",
           "|" + "|".join("-" * (width[i] + 2) for i in range(cols)) + "|"]
    for r in grid:
        out.append("| " + " | ".join(c.ljust(width[i]) for i, c in enumerate(r)) + " |")
    return out


def name_of(row: Dict[str, Any]) -> str:
    """What a reviewer recognises. NSX ids are frequently UUIDs or truncated
    slugs, so the display name is what appears in the UI and in a change
    request. Falls back to the id only when a name is genuinely absent."""
    return str(row.get("display_name") or row.get("id") or "?")


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

    # Fixed-name reports are the latest pass only. push_report/runs/ holds a
    # timestamped copy of EVERY pass, which is what makes a pre-apply dry-run
    # report reconstructable after the apply has overwritten the fixed names.
    runs = pr / "runs"
    archived: Dict[str, List[Path]] = {}
    if runs.is_dir():
        for f in sorted(runs.glob("*.json")):
            if f.name.endswith("_summary.json"):
                continue
            for n, k in REPORT_FILES.items():
                if f.name.startswith(n.removesuffix(".json")):
                    archived.setdefault(k, []).append(f)
                    break

    sources: List[tuple] = []
    for name, kind in REPORT_FILES.items():
        if kind in archived:
            # The archive is a superset: it contains this pass AND every
            # earlier one. Reading the fixed-name file too would double-count
            # the most recent pass.
            sources.extend((f, kind) for f in archived[kind])
        else:
            sources.append((pr / name, kind))

    for f, kind in sources:
        name = f.name
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

    # One report describes ONE pass. groups.py archives every pass, so a window
    # containing both a dry run and the apply that followed would otherwise list
    # each object twice (once planned, once applied) and double every total.
    # When any row was actually written, this is an apply report: drop the
    # planned rows. A report with no applied rows is a dry-run report and keeps
    # them.
    applied_any = any(r["bucket"] in ("applied", "failed") for r in rows)
    if applied_any:
        dropped = [r for r in rows if r["bucket"] == "planned"]
        rows = [r for r in rows if r["bucket"] != "planned"]
        if dropped:
            log.info("Apply report: dropped %d dry-run row(s) from the same window.",
                     len(dropped))

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

    applied = [r for r in rows if r["bucket"] == "applied"]
    detail = [r for r in rows if r["bucket"] in ("applied", "planned")]
    mode = "APPLY" if applied_any else "DRY RUN"

    # Classify what each row actually DID, not merely that it was pushed.
    #   created   - the object did not exist (PUT succeeded outright)
    #   changed   - a measurable delta: IPs moved, or rule refs added
    #   rewritten - pushed over an object that already existed, with no
    #               measurable delta. For groups that means the IPs are
    #               identical; for other classes we cannot see inside the
    #               payload, so this is NOT a promise that nothing changed.
    def verdict(r: Dict[str, Any]) -> str:
        if r["bucket"] == "failed":
            return "failed"
        if (r.get("ips_added") or r.get("ips_removed") or r.get("refs_added_total")):
            return "changed"
        if str(r.get("status", "")).endswith("_put"):
            return "created"
        return "rewritten"

    for r in detail:
        r["verdict"] = verdict(r)
    created   = [r for r in detail if r["verdict"] == "created"]
    changed   = [r for r in detail if r["verdict"] == "changed"]
    rewritten = [r for r in detail if r["verdict"] == "rewritten"]
    opaque    = [r for r in rewritten if r["kind"] not in IP_BEARING]

    md = [f"# {args.label}", "",
          f"**{mode}** | generated {report['generated_at']}"
          + (f" | rows since `{args.since}`" if args.since else ""), ""]

    # ---- the answer, first -------------------------------------------------
    verb = "would be" if not applied_any else ""
    past = "were" if applied_any else "would be"
    md += ["## What changed", ""]
    if not (created or changed or failed):
        md += [f"**Nothing{' would be' if not applied_any else ''} changed.** "
               f"{len(rewritten)} object(s) {past} pushed over existing, identical content.", ""]
    else:
        md += table(["Outcome", "Count"], [
            [f"Created {verb}".strip(),  f"**{len(created)}**"],
            [f"Changed {verb}".strip(),  f"**{len(changed)}**"],
            ["Failed",                   f"**{len(failed)}**"],
            ["Pushed, no measurable change", str(len(rewritten))],
        ]) + [""]
        # Broken out per object class: a reviewer signing off a change window
        # cares about "which RULES changed" as a separate question from
        # "which GROUPS changed", and a single mixed table forces them to
        # filter it by eye.
        for kind in KIND_ORDER:
            hits = [r for r in (created + changed) if r["kind"] == kind]
            if not hits:
                continue
            md += [f"### {KIND_LABEL[kind]} ({len(hits)})", ""]
            md += table(["Phase", "Name", "Verdict", "IPs +/-", "Refs +"],
                        [[r["phase"], name_of(r), r["verdict"], ip_cell(r),
                          str(r["refs_added_total"] or "")]
                         for r in sorted(hits, key=lambda x: (x["verdict"], x["phase"],
                                                             name_of(x)))]) + [""]

    md += [f"- IPs added: **{ips_added}**   removed: **{ips_removed}**   "
           f"rule refs added: **{refs_added}**", ""]

    if failed:
        md += ["## Failures", ""]
        md += table(["Class", "Name", "Reason"],
                    [[r["kind"], name_of(r), str(r["reason"])[:120]] for r in failed]) + [""]

    # ---- caveats that change how the numbers should be read ----------------
    caveats = []
    unmeasured = [r for r in detail if r["kind"] in IP_BEARING
                  and r.get("ips_added") is None and r.get("ips_removed") is None]
    if unmeasured:
        caveats.append(f"{len(unmeasured)} group row(s) have an unmeasured IP delta: that "
                       "pass ran without `--diff-target`, so the delta is unknown, not zero.")
    if opaque:
        caveats.append(f"{len(opaque)} non-group object(s) are listed as no measurable change. "
                       "Only groups expose an IP diff, so a policy, rule or service whose "
                       "payload differs would look identical here.")
    if caveats:
        md += ["## Read this before trusting the counts", ""] + [f"- {c}" for c in caveats] + [""]

    # ---- full detail, demoted and split per class --------------------------
    if detail:
        md += ["## Appendix: every object touched", "",
               f"{len(detail)} row(s). An object appears once per phase that touches it, so a "
               "group in both the WF-A push and the WF-C stripped push is listed twice.", ""]
        for kind in KIND_ORDER:
            hits = [r for r in detail if r["kind"] == kind]
            if not hits:
                continue
            v = collections.Counter(r["verdict"] for r in hits)
            tally = ", ".join(f"{n} {k}" for k, n in sorted(v.items()))
            md += [f"### {KIND_LABEL[kind]} ({len(hits)}: {tally})", ""]
            md += table(["Phase", "Name", "Verdict", "Status", "IPs +/-", "Refs +"],
                        [[r["phase"], name_of(r), r["verdict"], str(r["status"]),
                          ip_cell(r), str(r["refs_added_total"] or "")]
                         for r in sorted(hits, key=lambda x: (x["phase"], name_of(x)))]) + [""]
        # Anything whose class is not in KIND_ORDER still has to appear.
        rest = [r for r in detail if r["kind"] not in KIND_ORDER]
        if rest:
            md += [f"### Other ({len(rest)})", ""]
            md += table(["Phase", "Class", "Name", "Verdict", "Status"],
                        [[r["phase"], r["kind"], name_of(r), r["verdict"], str(r["status"])]
                         for r in sorted(rest, key=lambda x: (x["phase"], name_of(x)))]) + [""]

    (out_dir / "avs_run_report.md").write_text("\n".join(md), encoding="utf-8")

    log.info("Rows: %d  applied=%d failed=%d  ips +%d/-%d  refs +%d",
             len(rows), len(applied), len(failed), ips_added, ips_removed, refs_added)
    log.info("Report: %s", out_dir / "avs_run_report.md")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
