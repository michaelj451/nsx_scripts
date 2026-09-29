#!/usr/bin/env python3
"""tools/nsx/report_avs_run.py

One consolidated "what did this run change?" report for an AVS / WF-A / WF-C /
WF-D sequence, built entirely from the per-tool push reports already on disk.

WF-C and WF-D push from the same bundle directories, so pass --workflow d on a
WF-D run to get its phase labels (D2a / D3) and its own report layout (original
group -> AVS group -> IP mapping -> rules) instead of WF-C's.

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

from nsx.names import NameMap  # noqa: E402

log = logging.getLogger("report_avs_run")

# Display names for every object and reference this report mentions. Filled in
# main() from the bundles and push rows, before anything is rendered.
NAMES = NameMap()

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
    # Written on the push's retry pass: the first attempt failed (typically a
    # nested group pushed before the group it references existed) and the
    # retry succeeded. Uncounted, a WF-A report said 74 created when 76 were.
    "success_put_retry": "applied",
    "success_patch_retry": "applied",
    "changed": "applied",
    "created": "applied",
    "updated": "applied",
    "dry_run": "planned",
    "skipped": "skipped",
    "no_change": "no_change",
    # Skip-unchanged (the push default): the target already held identical
    # content, so nothing was sent. Counted, never shown as a change.
    "skipped_unchanged": "unchanged",
    "failed": "failed",
    "error": "failed",
}


def bucket_for(status: Optional[str]) -> str:
    return STATUS_BUCKETS.get((status or "").lower(), "other")


# Which workflow step a bundle belongs to. Without this the same object id shows
# up twice with no way to tell the WF-A push from the WF-C sibling push, which
# reads like a duplicate-row bug.
#
# WF-C and WF-D push from the SAME bundle directory (nsx_sibling_groups), so
# the path alone cannot say which one ran. --workflow supplies what the path
# cannot. Without it the labels stay on WF-C, which is what every report before
# this flag existed already said.
WF_STEP_LABELS = {
    "c": {"siblings": "C3 siblings",
          "pure_ip": "C pure-ip", "amend": "C5 amend-refs"},
    "d": {"siblings": "D2a siblings",
          "pure_ip": "D2b pure-ip", "amend": "D3 amend-refs"},
}


def phase_for(bundle: str, report: str, workflow: Optional[str] = None) -> str:
    b = bundle.replace("\\", "/")
    steps = WF_STEP_LABELS["d" if workflow == "d" else "c"]
    if report == "amend_refs.json":
        return steps["amend"]
    if "nsx_sibling_groups" in b:
        return steps["siblings"]
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


RULE_KINDS = ("rule", "rule-amend")


def policy_of(row: Dict[str, Any]) -> str:
    """The policy a rule row belongs to, by display name. Rules are only
    unambiguous inside their policy, and the same rule name can appear in more
    than one, so every rule table carries this next to the rule name."""
    pid = row.get("policy_id")
    if not pid:
        return ""
    return NAMES.label(f"/security-policies/{pid}")


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
    """A reference as a reviewer should read it: the object's display name.

    Paths are long and repetitive, and the id at the end of one is often an
    opaque token (`vm1` is "vm-group-1", a UUID is "ip-address-group-..."). The
    id is added only when the display name is shared by more than one object.
    Push rows record target-only refs as "<field>:<path>"; those keep the field.
    """
    s = str(path)
    if ":/" in s:
        field, ref = s.split(":", 1)
        return f"{field}: {NAMES.label(ref)}"
    return NAMES.label(s) if s.startswith("/") else s


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


def _clip(v: Any, limit: int = 80) -> str:
    """One-line rendering of a field value for a before/after line."""
    s = json.dumps(v, sort_keys=True, default=str) if not isinstance(v, str) else v
    return s if len(s) <= limit else s[:limit - 3] + "..."


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
    kept_ips = r.get("ips_kept_from_target") or []
    if kept_ips:
        out.append(f"- IPs kept, already on the target but not in the source "
                   f"({len(kept_ips)}): {_vals(kept_ips)}")
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

    # Per-field delta: recorded by amend-refs, and by every plain push that
    # writes over an existing object. Removals first, because a lost reference
    # is the direction that stops a rule matching.
    pfd = r.get("per_field_diff") or {}
    fields = [(f, d) for f, d in (pfd.items() if isinstance(pfd, dict) else [])
              if isinstance(d, dict)]
    for field, d in fields:
        lost = d.get("removed") or []
        if lost:
            out.append(f"- `{field}` LOST ({len(lost)}): {_vals([_short(x) for x in lost])}")
    for field, d in fields:
        gained = d.get("added") or []
        if gained:
            out.append(f"- `{field}` gained ({len(gained)}): "
                       f"{_vals([_short(x) for x in gained])}")
    for field, d in fields:
        if "added" in d or "removed" in d:
            continue
        before, after = d.get("before"), d.get("after")
        out.append(f"- `{field}`: `{_clip(before)}` -> `{_clip(after)}`")
    csv_added = r.get("csv_added_values") or []
    if csv_added:
        out.append(f"- CSV-mapped values added ({len(csv_added)}): {_vals(csv_added)}")

    # Build-time outcomes. `copied` reached the sibling verbatim; `dropped` did
    # not reach it at all, and is the number that matters: an address the CSV
    # could not map is a workload that stops matching after cutover.
    copied = r.get("ips_manual_copied") or []
    if copied:
        out.append(f"- Manually entered IPs copied verbatim ({len(copied)}): {_vals(copied)}")
    dropped = [ip for ip in (r.get("ips_uncovered") or []) if ip not in copied]
    if dropped:
        out.append(f"- **IPs DROPPED, no CSV mapping ({len(dropped)}): {_vals(dropped)}**")

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


def load_sibling_map(root: Path) -> Dict[str, Dict[str, Any]]:
    """Per-sibling build audit, keyed by sibling id, or {} if there is none.

    The push reports say which addresses reached the target. Only the BUILD
    knows which ones never made it into the payload: an address with no CSV
    mapping is absent from the sibling, so no push row can mention it. That
    detail lives in sibling_map.json beside the bundle, and without reading it
    the report cannot show what a WF-D run dropped.
    """
    f = root / "sibling_map.json"
    if not f.is_file():
        return {}
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        log.warning("unreadable sibling map %s: %s", f, exc)
        return {}
    return {e["sibling_id"]: e for e in (data.get("map") or [])
            if isinstance(e, dict) and e.get("sibling_id")}


def load_no_sibling(root: Path) -> List[Dict[str, Any]]:
    """Groups the build gave no sibling, with the reason, or [] if none."""
    f = root / "sibling_map.json"
    if not f.is_file():
        return []
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return []
    return [e for e in (data.get("no_sibling") or []) if isinstance(e, dict)]


def load_rows(root: Path, since: Optional[datetime],
              workflow: Optional[str] = None) -> List[Dict[str, Any]]:
    """Every row from every recognised report file under <root>/push_report."""
    rows: List[Dict[str, Any]] = []
    smap = load_sibling_map(root)
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
                # On the target, absent from the source, pushed back as part of
                # the union. Not a change; listed so a stale address is visible.
                "ips_kept_from_target": r.get("ips_kept_from_target"),
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
                "ref_names": r.get("ref_names"),
                # The policy a rule sits in: its id, and the display name the
                # push tool resolved (the bundle's policy file, else the target).
                "policy_id": r.get("policy_id"),
                "policy_display_name": r.get("policy_display_name"),
                "csv_added_values": r.get("csv_added_values"),
                # The exact YAML the push sends. For a CREATED object this is
                # the only record of what it actually is: no diff exists,
                # because there was nothing to diff against.
                "file": r.get("file"),
                # Build-time audit for a sibling: which source addresses had no
                # CSV mapping, and which hand-entered ones were copied verbatim.
                "ips_uncovered": (smap.get(str(r.get("id"))) or {}).get("ips_uncovered"),
                "ips_manual_copied": (smap.get(str(r.get("id"))) or {}).get("ips_manual_copied"),
                # WF-D: the group a sibling was built from, and what each of
                # its current addresses mapped to ([[ip, [mapped...]], ...]).
                "original_display_name": (smap.get(str(r.get("id"))) or {}).get("original_display_name"),
                "ip_pairs": (smap.get(str(r.get("id"))) or {}).get("ip_pairs"),
                # amend-refs dry run: siblings a rule would gain that the target
                # does not hold yet (an apply skips them).
                "siblings_not_on_target": r.get("siblings_not_on_target"),
                "timestamp": ts,
            })
    return rows


# ---- WF-D report --------------------------------------------------------------
# WF-D answers three questions, and the report is laid out around them: which
# AVS group does each original group get (D2a), what did each current address
# map to, and which rules pick the AVS groups up (D3). One row per object, one
# row per address, no repeated sections.

def _few(items: List[Any], n: int = 5) -> str:
    items = [str(x) for x in items or []]
    shown = ", ".join(f"`{x}`" for x in items[:n])
    return shown + (f" +{len(items) - n} more" if len(items) > n else "")


def _d_group_result(r: Dict[str, Any], is_apply: bool) -> str:
    if r["bucket"] == "failed":
        return "**FAILED**"
    if r["bucket"] == "unchanged":
        return "already up to date"
    if r.get("verdict") == "created":
        return "created" if is_apply else "would create"
    n = len(r.get("ips_added") or [])
    if n:
        return f"added {n} IP(s)" if is_apply else f"would add {n} IP(s)"
    # Sent although its IPs did not change: only happens without
    # --skip-no-ip-change, or with --force-push. Never call it "up to date".
    return "re-sent, no IP change" if is_apply else "would be re-sent, no IP change"


def render_wf_d(label: str, header: str, rows: List[Dict[str, Any]],
                no_sibling: List[Dict[str, Any]], is_apply: bool) -> List[str]:
    md = [f"# {label}", "", header, ""]
    groups = [r for r in rows if r["kind"] == "group"]
    amends = [r for r in rows if r["kind"] == "rule-amend"]
    if groups or no_sibling:
        md += _render_d2a(groups, no_sibling, is_apply)
    if amends:
        md += _render_d3(amends, is_apply)
    if not (groups or no_sibling or amends):
        md += ["Nothing was pushed in this window.", ""]
    return md


def _render_d2a(groups: List[Dict[str, Any]], no_sibling: List[Dict[str, Any]],
                is_apply: bool) -> List[str]:
    def orig_name(r: Dict[str, Any]) -> str:
        return str(r.get("original_display_name") or name_of(r))

    def unmapped(r: Dict[str, Any]) -> List[str]:
        return [ip for ip, mapped in (r.get("ip_pairs") or []) if not mapped]

    groups = sorted(groups, key=orig_name)
    results = [_d_group_result(r, is_apply) for r in groups]
    created = sum(1 for x in results if x in ("created", "would create"))
    added = sum(1 for x in results if "IP(s)" in x)
    current = sum(1 for x in results if x == "already up to date")
    resent = sum(1 for x in results if "re-sent" in x)
    failed = sum(1 for x in results if "FAILED" in x)
    no_map = sum(len(unmapped(r)) for r in groups)
    kept_total = sum(len(r.get("ips_kept_from_target") or []) for r in groups)
    verb = "" if is_apply else "would be "

    md = ["## Summary", ""]
    summary = [[f"AVS groups {verb}created", f"**{created}**"]]
    if added:
        summary.append([f"AVS groups {verb}given new IPs", f"**{added}**"])
    if current:
        summary.append(["AVS groups already up to date (nothing sent)", str(current)])
    if resent:
        summary.append([f"AVS groups {verb}re-sent with no IP change", f"**{resent}**"])
    summary.append(["Failed", f"**{failed}**" if failed else "0"])
    summary.append(["Groups with no AVS group", str(len(no_sibling))])
    summary.append(["Current IPs with no AVS mapping", str(no_map)])
    if kept_total:
        summary.append(["IPs kept (on target, not in capture)", str(kept_total)])
    md += table(["Item", "Count"], summary) + [""]
    md += ["Existing groups and rules are not changed in this phase. Rules start "
           "using the AVS groups in D3. An IP with no AVS mapping stays on its "
           "original group, where the rule still matches it.", ""]

    if groups:
        md += ["## AVS groups", ""]
        head = ["Original group", "AVS group", "Result", "AVS IPs", "No AVS mapping"]
        if kept_total:
            head.append("Kept")
        body = []
        for r, res in zip(groups, results):
            line = [orig_name(r), name_of(r), res,
                    str(len(r.get("ips_after") or [])), str(len(unmapped(r)) or "")]
            if kept_total:
                line.append(str(len(r.get("ips_kept_from_target") or []) or ""))
            body.append(line)
        md += table(head, body) + [""]

        fails = [r for r in groups if r["bucket"] == "failed"]
        if fails:
            md += ["## Failures", ""]
            md += table(["AVS group", "Error"],
                        [[name_of(r), str(r.get("reason") or "")[:160]] for r in fails]) + [""]

        md += ["## IP mapping", "",
               "What each current IP maps to in its AVS group.", ""]
        for r in groups:
            pairs = r.get("ip_pairs") or []
            kept = r.get("ips_kept_from_target") or []
            if not (pairs or kept):
                continue
            md += [f"### {orig_name(r)} -> {name_of(r)}", ""]
            lines = [[f"`{ip}`", ", ".join(f"`{m}`" for m in mapped)]
                     for ip, mapped in pairs if mapped]
            lines += [[f"`{ip}`", "no AVS mapping"] for ip, mapped in pairs if not mapped]
            lines += [["(not in capture)", f"`{ip}` kept, already on target"] for ip in kept]
            more = len(lines) - AUDIT_CAP
            md += table(["Current IP", "AVS IP"], lines[:AUDIT_CAP])
            if more > 0:
                md += ["", f"... and {more} more; the full list is in avs_run_report.json."]
            md += [""]

    if no_sibling:
        md += ["## Groups with no AVS group", ""]
        md += table(["Group", "Reason", "Current IPs"],
                    [[str(e.get("original_display_name") or e.get("original_id")),
                      str(e.get("reason") or e.get("reason_code") or ""),
                      (f"{len(e.get('ips_source') or [])}: {_few(e.get('ips_source'))}"
                       if e.get("ips_source") else "none")]
                     for e in sorted(no_sibling, key=lambda e: str(
                         e.get("original_display_name") or e.get("original_id")))]) + [""]
    return md


def _render_d3(amends: List[Dict[str, Any]], is_apply: bool) -> List[str]:
    changed = [r for r in amends if r["bucket"] in ("applied", "planned")
               and r.get("per_field_diff")]
    failed = [r for r in amends if r["bucket"] == "failed"]
    nothing = len(amends) - len(changed) - len(failed)
    refs = sum(r.get("refs_added_total") or 0 for r in changed)
    pending = sorted({s for r in changed for s in (r.get("siblings_not_on_target") or [])})
    verb = "" if is_apply else "would be "

    md = ["## Summary", ""]
    summary = [[f"Rules {verb}updated", f"**{len(changed)}**"],
               [f"AVS group references {verb}added", f"**{refs}**"],
               ["Rules with nothing to add", str(nothing)],
               ["Failed", f"**{len(failed)}**" if failed else "0"]]
    if pending:
        summary.append(["AVS groups not on the target yet", f"**{len(pending)}**"])
    md += table(["Item", "Count"], summary) + [""]
    md += ["Nothing is removed from any rule: each AVS group is added next to the "
           "original group it came from.", ""]
    # Before D2a is applied NONE of them exist, and marking every cell says
    # nothing the banner does not. Mark per cell only when some are missing.
    referenced = {p.rsplit("/", 1)[-1] for r in changed
                  for d in (r.get("per_field_diff") or {}).values() for p in d.get("added") or []}
    mark_cells = bool(pending) and set(pending) != referenced
    if pending and not mark_cells:
        md += [f"> **None of the {len(pending)} AVS groups below exist on the target "
               "yet.** Apply D2a first: an apply adds only the AVS groups that exist "
               "when it runs.", ""]
    elif pending:
        md += [f"> **{len(pending)} AVS group(s) are not on the target yet.** Apply "
               "D2a first: an apply adds only the AVS groups that exist when it runs. "
               "They are marked *(not on target yet)* below.", ""]

    if changed:
        fields = ["source_groups", "destination_groups"]
        if any("scope" in (r.get("per_field_diff") or {}) for r in changed):
            fields.append("scope")
        titles = {"source_groups": "Source gains", "destination_groups": "Destination gains",
                  "scope": "Applied To gains"}

        def cell(r: Dict[str, Any], field: str) -> str:
            miss = set(r.get("siblings_not_on_target") or []) if mark_cells else set()
            names = []
            for path in ((r.get("per_field_diff") or {}).get(field) or {}).get("added") or []:
                nm = _short(path)
                if path.rsplit("/", 1)[-1] in miss:
                    nm += " *(not on target yet)*"
                names.append(nm)
            return ", ".join(names)

        md += ["## Rules updated" if is_apply else "## Rules to update", ""]
        md += table(["Policy", "Rule"] + [titles[f] for f in fields],
                    [[policy_of(r), name_of(r)] + [cell(r, f) for f in fields]
                     for r in sorted(changed, key=lambda x: (policy_of(x), name_of(x)))]) + [""]
    if failed:
        md += ["## Failures", ""]
        md += table(["Policy", "Rule", "Error"],
                    [[policy_of(r), name_of(r), str(r.get("reason") or "")[:160]]
                     for r in failed]) + [""]
    return md


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
    no_sibling: List[Dict[str, Any]] = []
    for root in args.report_root:
        root_path = Path(root).expanduser()
        rows.extend(load_rows(root_path, since, args.workflow))
        modes |= load_modes(root_path, since)
        NAMES.add_bundle(root_path)
        no_sibling.extend(load_no_sibling(root_path))
    # The rows themselves name the objects they push, and the push tools record
    # display names for target-side references no bundle on this side holds.
    for r in rows:
        NAMES.add(None, r.get("id"), r.get("display_name"),
                  {"group": "groups", "service": "services", "policy": "security-policies",
                   "rule": "rules"}.get(r.get("kind"), ""))
        NAMES.add_mapping(r.get("ref_names"))
        if r.get("policy_id"):
            NAMES.add(None, r["policy_id"], r.get("policy_display_name"), "security-policies")

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
    ips_kept = sum(len(r.get("ips_kept_from_target") or []) for r in rows)
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
        if r.get("exists_on_target") is False or \
                str(r.get("status", "")).endswith(("_put", "_put_retry")):
            return "created"
        if (r.get("ips_added") or r.get("ips_removed") or r.get("refs_added_total")
                or r.get("refs_removed_total") or r.get("per_field_diff")):
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
        "ips_kept_total": ips_kept,
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
               + (f"{len(rewritten)} object(s) {past} pushed over existing content with no "
                  "recorded delta." if rewritten else ""), ""]
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
            if kind in RULE_KINDS:
                md += table(["Phase", "Name", "Policy", "Verdict", "IPs +/-", "Refs +"],
                            [[r["phase"], name_of(r), policy_of(r), r["verdict"], ip_cell(r),
                              str(r["refs_added_total"] or "")]
                             for r in sorted(hits, key=lambda x: (x["verdict"], x["phase"],
                                                                 policy_of(x), name_of(x)))]) + [""]
            else:
                md += table(["Phase", "Name", "Verdict", "IPs +/-", "Refs +"],
                            [[r["phase"], name_of(r), r["verdict"], ip_cell(r),
                              str(r["refs_added_total"] or "")]
                             for r in sorted(hits, key=lambda x: (x["verdict"], x["phase"],
                                                                 name_of(x)))]) + [""]

    # An address with no CSV mapping never reaches the sibling, so no push row
    # can report it. Surfaced above the fold because a dropped address is a
    # workload that silently stops matching after cutover.
    dropped_by_row = [(r, [ip for ip in (r.get("ips_uncovered") or [])
                           if ip not in (r.get("ips_manual_copied") or [])])
                      for r in detail]
    dropped_by_row = [(r, d) for r, d in dropped_by_row if d]
    copied_total = sum(len(r.get("ips_manual_copied") or []) for r in detail)
    if dropped_by_row:
        n = sum(len(d) for _, d in dropped_by_row)
        md += [f"> **{n} source address(es) had no CSV mapping and are NOT in the "
               f"sibling groups.** They reach no rule through the sibling, so any "
               "workload on them stops matching once enforcement moves. Extend the CSV, "
               "or re-run the build with `--skip-uncovered` to skip those groups "
               "entirely rather than emit a partial sibling.", ""]
        md += table(["Sibling", "Dropped addresses"],
                    [[name_of(r), ", ".join(d)] for r, d in
                     sorted(dropped_by_row, key=lambda x: name_of(x[0]))]) + [""]
    if copied_total:
        md += [f"- {copied_total} manually entered address(es) were copied into siblings "
               "verbatim (no mapping applied). Listed per group below.", ""]

    refs_kept = sum(r.get("refs_preserved_total") or 0 for r in rows)
    refs_lost = sum(r.get("refs_removed_total") or 0 for r in rows)
    md += [f"- IPs added: **{ips_added}**   removed: **{ips_removed}**   "
           + (f"kept from target: **{ips_kept}**   " if ips_kept else "")
           + f"rule refs added: **{refs_added}**"
           + (f"   target-only refs kept: **{refs_kept}**" if refs_kept else ""), ""]
    # Every row, not just the changed ones: a group whose union already equals
    # the target is skipped as unchanged, and its kept addresses are exactly
    # the ones a reviewer should look at (a powered-off, re-addressed or
    # decommissioned VM). Nothing removes them; that is a manual decision.
    kept_rows = [r for r in rows if r.get("ips_kept_from_target")]
    if kept_rows:
        md += [f"### IPs kept on the target ({ips_kept})", "",
               "Already on the target, not in the source capture, so the push sends "
               "the union and keeps them. Usually a VM that was powered off at capture "
               "time; check any you do not expect. Nothing here is ever removed "
               "automatically.", ""]
        md += table(["Name", "Kept", "IPs"],
                    [[name_of(r), str(len(r["ips_kept_from_target"])),
                      _vals(r["ips_kept_from_target"])]
                     for r in sorted(kept_rows, key=name_of)]) + [""]
    same = [r for r in rows if r["bucket"] == "unchanged"]
    if same:
        md += [f"- Already identical on the target, so skipped with nothing sent: "
               f"**{len(same)}** object(s).", ""]
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
        caveats.append(f"{len(opaque)} non-group object(s) were pushed with no recorded "
                       "delta. Identical objects are skipped by default and differing ones "
                       "record what changed, so this happens only when the target was not "
                       "read (`--no-diff-target`) or the push was forced (`--force-push`).")
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
                where = (f" in policy **{policy_of(r)}**"
                         if r["kind"] in RULE_KINDS and policy_of(r) else "")
                md += [f"**{name_of(r)}**{where} ({r['verdict']}, {r['phase']}, `{r['status']}`)", ""]
                md += audit_lines(r)
                md += [""]

    # ---- full detail, demoted and split per class --------------------------
    if detail:
        md += ["## Appendix: every object touched", "",
               f"{len(detail)} row(s). An object appears once per phase that touches it, so a "
               "group in both the WF-A push and a later sibling push is listed twice.", ""]
        for kind in KIND_ORDER:
            hits = [r for r in detail if r["kind"] == kind]
            if not hits:
                continue
            v = collections.Counter(r["verdict"] for r in hits)
            tally = ", ".join(f"{n} {k}" for k, n in sorted(v.items()))
            md += [f"### {KIND_LABEL[kind]} ({len(hits)}: {tally})", ""]
            if kind in RULE_KINDS:
                md += table(["Phase", "Name", "Policy", "Verdict", "Status", "IPs +/-", "Refs +"],
                            [[r["phase"], name_of(r), policy_of(r), r["verdict"], str(r["status"]),
                              ip_cell(r), str(r["refs_added_total"] or "")]
                             for r in sorted(hits, key=lambda x: (x["phase"], policy_of(x),
                                                                 name_of(x)))]) + [""]
            else:
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

    # WF-D gets its own layout, built around original group -> AVS group ->
    # rule. The generic one above stays for A and C.
    if args.workflow == "d":
        md = render_wf_d(args.label, md[2], rows, no_sibling, is_apply)
    (out_dir / "avs_run_report.md").write_text("\n".join(md), encoding="utf-8")

    log.info("Rows: %d  applied=%d failed=%d  ips +%d/-%d  refs +%d",
             len(rows), len(applied), len(failed), ips_added, ips_removed, refs_added)
    log.info("Report: %s", out_dir / "avs_run_report.md")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
