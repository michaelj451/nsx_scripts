#!/usr/bin/env python3
"""tools/nsx/report_avs_run.py

One consolidated "what did this run change?" report for an AVS / WF-A / WF-C /
WF-D sequence, built entirely from the per-tool push reports already on disk.

WF-C and WF-D push from the same bundle directories, so pass --workflow d on a
WF-D run to get its phase labels (D2a / D2b / D3 / D5) instead of WF-C's.

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

try:
    import yaml
except ImportError:                                   # pragma: no cover
    # Only the created-object payload detail needs it; the rest of the report
    # is pure JSON and still works without it.
    yaml = None                                       # type: ignore[assignment]

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
#
# WF-C and WF-D push from the SAME bundle directories (nsx_sibling_groups,
# nsx_stripped_groups), so the path alone cannot say which one ran. --workflow
# supplies what the path cannot. Without it the labels stay on WF-C, which is
# what every report before this flag existed already said.
WF_STEP_LABELS = {
    "c": {"siblings": "C3 siblings", "stripped": "C4 stripped",
          "pure_ip": "C pure-ip", "amend": "C5 amend-refs"},
    "d": {"siblings": "D2a siblings", "stripped": "D5 stripped",
          "pure_ip": "D2b pure-ip", "amend": "D3 amend-refs"},
}


def phase_for(bundle: str, report: str, workflow: Optional[str] = None) -> str:
    b = bundle.replace("\\", "/")
    steps = WF_STEP_LABELS["d" if workflow == "d" else "c"]
    if report == "amend_refs.json":
        return steps["amend"]
    if "nsx_sibling_groups" in b:
        return steps["siblings"]
    if "nsx_stripped_groups" in b:
        return steps["stripped"]
    if "nsx_pure_ip_remap" in b:
        return steps["pure_ip"]
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


# How many values to print per list in the audit section. The JSON report keeps
# the full set regardless; this only stops one 4000-entry group from burying the
# rest of the change record.
AUDIT_CAP = 50


def _vals(items: Optional[List[Any]]) -> str:
    """Render a value list as inline code, truncated, with the true count."""
    items = [str(x) for x in (items or [])]
    shown = ", ".join(f"`{x}`" for x in items[:AUDIT_CAP])
    if len(items) > AUDIT_CAP:
        shown += f", ... and {len(items) - AUDIT_CAP} more"
    return shown


def _short(path: str) -> str:
    """Group paths are long and repetitive; the id is what a reviewer reads."""
    s = str(path)
    return s.rsplit("/", 1)[-1] if s.startswith("/") else s


def payload_lines(r: Dict[str, Any]) -> List[str]:
    """What a created object actually IS, read from the YAML being pushed.

    A create has no before/after to diff, so without this the audit record can
    only say the name. For a firewall rule the name is the least interesting
    part: what matters is what it permits, between what, over which services.
    """
    path = r.get("file")
    if not path or yaml is None:
        return []
    p = Path(path)
    if not p.is_file():
        return []
    try:
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (ValueError, OSError, yaml.YAMLError) as exc:
        log.warning("unreadable payload %s: %s", p, exc)
        return []
    if not isinstance(d, dict):
        return []

    out: List[str] = []
    k = r["kind"]
    if k == "rule":
        out.append(f"- action: **{d.get('action')}**, direction: {d.get('direction')}, "
                   f"protocol: {d.get('ip_protocol')}, disabled: {d.get('disabled')}, "
                   f"logged: {d.get('logged')}")
        for label, field in (("sources", "source_groups"),
                             ("destinations", "destination_groups"),
                             ("services", "services"),
                             ("applied to (scope)", "scope")):
            vals = d.get(field) or []
            if vals:
                out.append(f"- {label} ({len(vals)}): {_vals([_short(x) for x in vals])}")
    elif k == "service":
        entries = d.get("service_entries") or []
        out.append(f"- type: {d.get('service_type')}, entries: {len(entries)}")
        for e in entries[:AUDIT_CAP]:
            if not isinstance(e, dict):
                continue
            proto = e.get("l4_protocol") or e.get("protocol") or e.get("resource_type")
            dports = ", ".join(str(x) for x in (e.get("destination_ports") or [])) or "any"
            sports = ", ".join(str(x) for x in (e.get("source_ports") or [])) or "any"
            out.append(f"  - {proto}  dst ports: `{dports}`  src ports: `{sports}`")
    elif k == "policy":
        out.append(f"- category: {d.get('category')}, sequence: {d.get('sequence_number')}, "
                   f"stateful: {d.get('stateful')}")
        vals = d.get("scope") or []
        if vals:
            out.append(f"- applied to (scope) ({len(vals)}): "
                       f"{_vals([_short(x) for x in vals])}")
    elif k == "group":
        crit, ipc = [], 0
        def walk(ex):
            nonlocal ipc
            for e in ex or []:
                if not isinstance(e, dict):
                    continue
                rt = e.get("resource_type")
                if rt == "Condition":
                    crit.append(str(e.get("value")))
                elif rt == "IPAddressExpression":
                    ipc += len(e.get("ip_addresses") or [])
                elif rt == "NestedExpression":
                    walk(e.get("expressions"))
        walk(d.get("expression"))
        if crit:
            out.append(f"- tag criteria ({len(crit)}): {_vals(crit)}")
        if ipc:
            out.append(f"- static IP entries: {ipc}")
    out.append(f"- payload: `{path}`")
    return out


def audit_lines(r: Dict[str, Any]) -> List[str]:
    """The concrete before/after for one row: what actually moved.

    Deliberately shows removals first. A removal is the direction that breaks
    traffic, so it should never be something a reader has to scroll for.
    """
    out: List[str] = []
    removed, added = r.get("ips_removed") or [], r.get("ips_added") or []
    if removed:
        out.append(f"- IPs REMOVED ({len(removed)}): {_vals(removed)}")
    if added:
        out.append(f"- IPs added ({len(added)}): {_vals(added)}")
    before, after = r.get("ips_before"), r.get("ips_after")
    if (removed or added) and before is not None and after is not None:
        out.append(f"- IPs before ({len(before)}) -> after ({len(after)})")

    refs_removed = r.get("refs_removed") or []
    if refs_removed:
        out.append(f"- Group refs REMOVED ({len(refs_removed)}): "
                   f"{_vals([_short(x) for x in refs_removed])}")
    kept = r.get("refs_preserved") or []
    if kept:
        out.append(f"- Target-only group refs kept ({len(kept)}): "
                   f"{_vals([_short(x) for x in kept])}")

    # amend-refs records a per-field before/after/added structure.
    pfd = r.get("per_field_diff") or {}
    for field, d in (pfd.items() if isinstance(pfd, dict) else []):
        if not isinstance(d, dict):
            continue
        gained = d.get("added") or []
        if gained:
            out.append(f"- `{field}` gained ({len(gained)}): "
                       f"{_vals([_short(x) for x in gained])}")
    csv_added = r.get("csv_added_values") or []
    if csv_added:
        out.append(f"- CSV-mapped values added ({len(csv_added)}): {_vals(csv_added)}")

    # A created object has nothing to diff against, so its payload IS the
    # change record. Show it rather than reporting an empty delta.
    if r["verdict"] == "created":
        out += payload_lines(r)
    if not out:
        out.append("- No value-level detail recorded for this row.")
    return out


def ip_cell(row: Dict[str, Any]) -> str:
    if row["kind"] not in IP_BEARING:
        return "n/a"
    added, removed = row.get("ips_added"), row.get("ips_removed")
    if added is None and removed is None:
        return "not measured"
    if not added and not removed:
        return "0"
    return f"+{len(added or [])}/-{len(removed or [])}"


# Every push tool records its own mode in its summary. That is the authority on
# whether a pass wrote anything; row statuses are not.
SUMMARY_FILES = ("summary.json", "amend_refs_summary.json")


def load_modes(root: Path, since: Optional[datetime]) -> set:
    """Modes ("APPLY" / "DRY-RUN") recorded under <root>/push_report in window.

    Inferring the mode from row statuses is not safe: a dry run that raises on
    one file (an unparseable YAML in the bundle, say) writes a `failed` row, and
    a failed row is not evidence that anything was written. Reading the mode the
    push tool itself recorded removes the guess.
    """
    modes: set = set()
    pr = root / "push_report"
    if not pr.is_dir():
        return modes
    files = [pr / n for n in SUMMARY_FILES]
    runs = pr / "runs"
    if runs.is_dir():
        files.extend(sorted(runs.glob("*_summary.json")))
    for f in files:
        if not f.is_file():
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            log.warning("unreadable summary %s: %s", f, exc)
            continue
        ran_at = data.get("ran_at")
        if since and ran_at:
            try:
                if datetime.fromisoformat(str(ran_at).replace("Z", "+00:00")) < since:
                    continue
            except ValueError:
                pass
        mode = str(data.get("mode") or "").strip().upper()
        if mode:
            modes.add(mode)
    return modes


def load_rows(root: Path, since: Optional[datetime],
              workflow: Optional[str] = None) -> List[Dict[str, Any]]:
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
                "phase": phase_for(str(root), name, workflow),
                "id": r.get("id") or r.get("group_id") or r.get("rule_id")
                      or r.get("policy_id") or r.get("service_id"),
                "display_name": r.get("display_name") or r.get("group_name"),
                "status": r.get("status"),
                "bucket": bucket_for(r.get("status")),
                "reason": r.get("reason"),
                "ips_added": r.get("ips_added"),
                "ips_removed": r.get("ips_removed"),
                "refs_added_total": r.get("refs_added_total"),
                # Group refs that existed only on the target. Preserved means a
                # push kept WF-C/WF-D sibling refs instead of clobbering them;
                # removed means it dropped them, which needs to be loud.
                "refs_preserved_total": r.get("refs_preserved_total"),
                "refs_removed_total": r.get("refs_removed_total"),
                "refs_removed": r.get("refs_removed"),
                # True/False when the push held a target baseline, absent when
                # it did not. Absent is not False: a plain offline dry run knows
                # nothing about the target.
                "exists_on_target": r.get("exists_on_target"),
                # Concrete before/after values, for the audit section. Counts
                # answer "how much", these answer "what", which is what a change
                # record has to show.
                "ips_before": r.get("ips_before"),
                "ips_after": r.get("ips_after"),
                "refs_preserved": r.get("refs_preserved"),
                "per_field_diff": r.get("per_field_diff"),
                "csv_added_values": r.get("csv_added_values"),
                # The exact YAML the push sends. For a CREATED object this is
                # the only record of what it actually is: no diff exists,
                # because there was nothing to diff against.
                "file": r.get("file"),
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
    p.add_argument("--workflow", choices=["a", "c", "d"], default=None,
                   help="Which workflow ran. WF-C and WF-D push from the same "
                        "bundle directories, so only you can say which it was; "
                        "this picks the phase labels. Default: WF-C labels.")
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
    modes: set = set()
    for root in args.report_root:
        root_path = Path(root).expanduser()
        rows.extend(load_rows(root_path, since, args.workflow))
        modes |= load_modes(root_path, since)

    # Is this an apply report? Two independent signals, either of which is
    # sufficient: a row that was actually written, or a push tool that recorded
    # mode APPLY in its own summary. The second covers an apply in which every
    # row failed.
    #
    # A `failed` row deliberately does NOT count. A dry run can produce one (an
    # unparseable YAML in the bundle raises per-file), and treating that as an
    # apply relabelled the entire dry-run report APPLY and then discarded every
    # planned row in it as a duplicate, leaving a pre-apply review document that
    # said nothing would change.
    is_apply = any(r["bucket"] == "applied" for r in rows) or "APPLY" in modes

    # One report describes ONE pass. groups.py archives every pass, so a window
    # containing both a dry run and the apply that followed would otherwise list
    # each object twice (once planned, once applied) and double every total. On
    # an apply report the planned rows are the earlier pass: drop them.
    if is_apply:
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

    applied = [r for r in rows if r["bucket"] == "applied"]
    detail = [r for r in rows if r["bucket"] in ("applied", "planned")]
    mode = "APPLY" if is_apply else "DRY RUN"

    # Classify what each row actually DID, not merely that it was pushed.
    #   created   - the object did not exist before this push
    #   changed   - it existed, and something measurable moved: IPs or rule refs
    #   rewritten - pushed over an existing object with no measurable delta. For
    #               groups that means identical IPs; for other classes we cannot
    #               see inside the payload, so this is NOT a promise that nothing
    #               changed.
    #
    # Create-ness is tested FIRST. An object created WITH content is still a
    # create, and its delta is still shown in the IPs column, so nothing is lost
    # by saying so. Testing the delta first (as this did until 2026-09-11) meant
    # only objects that landed empty were ever called created: a from-empty WF-A
    # clone reported 5 creates and 7 changes when all 12 were creates.
    #
    # Two independent signals, because neither covers every case:
    #   success_put        - the PUT succeeded outright, so the object was new.
    #                        Absent on a dry run, and absent when a create went
    #                        through the already-exists PATCH fallback.
    #   exists_on_target   - recorded by groups.py whenever it holds a target
    #                        baseline (--apply, or --diff-target on a dry run).
    #                        This is what lets a DRY RUN say "would create".
    def verdict(r: Dict[str, Any]) -> str:
        if r["bucket"] == "failed":
            return "failed"
        if r.get("exists_on_target") is False or str(r.get("status", "")).endswith("_put"):
            return "created"
        if (r.get("ips_added") or r.get("ips_removed") or r.get("refs_added_total")
                or r.get("refs_removed_total")):
            return "changed"
        # Nothing observed, and nothing was checked: say so. Calling this
        # "rewritten" asserts the object already existed, which is a claim the
        # run never made. A new service pushed with --no-diff-target read as
        # "rewritten" on 2026-09-11 while it was in fact about to be created.
        if r.get("exists_on_target") is None and r["bucket"] == "planned":
            return "unknown"
        return "rewritten"

    for r in detail:
        r["verdict"] = verdict(r)
    for r in failed:
        r["verdict"] = "failed"

    # Written AFTER the verdicts so the machine-readable artifact carries the
    # same classification the markdown shows.
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "label": args.label,
        "mode": mode,
        "workflow": args.workflow,
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
    created   = [r for r in detail if r["verdict"] == "created"]
    changed   = [r for r in detail if r["verdict"] == "changed"]
    rewritten = [r for r in detail if r["verdict"] == "rewritten"]
    unknown   = [r for r in detail if r["verdict"] == "unknown"]
    opaque    = [r for r in rewritten if r["kind"] not in IP_BEARING]

    md = [f"# {args.label}", "",
          f"**{mode}** | generated {report['generated_at']}"
          + (f" | rows since `{args.since}`" if args.since else ""), ""]

    # ---- the answer, first -------------------------------------------------
    # Same table in both modes, in the tense that matches what actually
    # happened, so a dry run never reads as a statement of fact.
    past = "were" if is_apply else "would be"
    md += ["## What changed", ""]
    if not (created or changed or failed or unknown):
        md += [f"**Nothing{' would be' if not is_apply else ''} changed.** "
               f"{len(rewritten)} object(s) {past} pushed over existing, identical content.", ""]
    else:
        rows_out = [
            ["Created" if is_apply else "Would create", f"**{len(created)}**"],
            ["Changed" if is_apply else "Would change", f"**{len(changed)}**"],
            ["Failed",                                  f"**{len(failed)}**"],
            ["Pushed, no measurable change" if is_apply
             else "Would be pushed, no measurable change", str(len(rewritten))],
        ]
        # Only ever shown when it is non-zero, so the normal report stays four
        # lines. A non-zero count here means the run was told not to read the
        # target, and those rows could be creates.
        if unknown:
            rows_out.append(["**Unknown (target not read)**", f"**{len(unknown)}**"])
        md += table(["Outcome", "Count"], rows_out) + [""]
        if unknown:
            md += [f"> **{len(unknown)} row(s) are UNKNOWN.** That pass ran with "
                   "`--no-diff-target`, so it never contacted the target and cannot say "
                   "whether these objects exist there. Any of them may be a create. "
                   "Re-run without `--no-diff-target` for an exact answer.", ""]
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

    refs_kept = sum(r.get("refs_preserved_total") or 0 for r in rows)
    refs_lost = sum(r.get("refs_removed_total") or 0 for r in rows)
    md += [f"- IPs added: **{ips_added}**   removed: **{ips_removed}**   "
           f"rule refs added: **{refs_added}**"
           + (f"   target-only refs kept: **{refs_kept}**" if refs_kept else ""), ""]
    if refs_lost:
        # A clone push that drops target-only group refs deletes exactly the
        # sibling references that keep rules matching literal IPs. Never let
        # this sit in a totals line.
        md += ["> **WARNING: this run REMOVES "
               f"{refs_lost} group reference(s) that exist only on the target.** "
               "Those are typically WF-C / WF-D sibling refs, and dropping them stops "
               "the affected rules matching the literal IPs they were given. Re-run "
               "without `--replace-refs` to merge instead.", ""]
        md += table(["Class", "Name", "Refs removed"],
                    [[r["kind"], name_of(r), ", ".join(r.get("refs_removed") or [])]
                     for r in rows if r.get("refs_removed_total")]) + [""]

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
    # Rows whose create-ness was never checked are reported as `unknown` and
    # called out above the fold, so no caveat is needed for them here.
    if caveats:
        md += ["## Read this before trusting the counts", ""] + [f"- {c}" for c in caveats] + [""]

    # ---- what actually changed, value by value -----------------------------
    # The tables above answer "how many". A change record has to answer "what",
    # and a reviewer signing one cannot do that from "+2/-0". Only objects that
    # were created or changed appear here; the untouched majority would bury it.
    audit = [r for r in detail if r["verdict"] in ("created", "changed")]
    if audit:
        md += ["## Change detail (audit)", "",
               f"Every value that {'moved' if is_apply else 'would move'}, for the "
               f"{len(audit)} object(s) above. Lists longer than {AUDIT_CAP} entries are "
               "truncated here; `avs_run_report.json` always holds the full set.", ""]
        for kind in KIND_ORDER:
            hits = [r for r in audit if r["kind"] == kind]
            if not hits:
                continue
            md += [f"### {KIND_LABEL[kind]}", ""]
            for r in sorted(hits, key=lambda x: (x["phase"], name_of(x))):
                md += [f"**{name_of(r)}** ({r['verdict']}, {r['phase']}, `{r['status']}`)", ""]
                md += audit_lines(r)
                md += [""]

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
