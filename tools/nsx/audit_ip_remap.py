#!/usr/bin/env python3
"""
tools/nsx/audit_ip_remap.py

Read-only audit of an in-place CSV IP remap (Workflow B): what LOOKS mapped
on a manager right now, and what might be a gap.

For every customer group it collects every IP entry (including entries inside
NestedExpression bodies, which the remap itself does not touch) and checks it
against the CSV:

  original present, mapped equivalent present      -> MAPPED   (section 2)
  original present, mapped equivalent MISSING      -> GAP      (section 1a)
  mapped-side value present, original ABSENT       -> REVIEW   (section 1b)
  IPv4 entry no CSV row covers                     -> UNCOVERED(section 1c)
  IP range (a-b) or IPv6                           -> BY DESIGN(section 3)

Never writes to NSX. Never proposes removals. Exit code is 1 when section 1a
or 1b is non-empty so it can run from a scheduler.

INPUT (one of):
  --target <alias>        Live GET of customer groups from this manager
                          (add --federation-global for a GM).
  --groups-dir <path>     A directory of exported group YAML/JSON files.

REQUIRED:
  --csv <path>            The same old_subnet,new_subnet CSV the remap used.

OUTPUT (default: $NSX_LOG_DIR/reports/ip_remap_audit/<label>/<UTC ts>/):
  ip_remap_audit.md       the report (gaps on top, then mapped, then by-design)
  ip_remap_audit.json     per-group rows, full detail
  gaps.json               sections 1a / 1b / 1c only
  summary.json            counters
  audit_ip_remap_<ts>.log

Examples:
  python tools/nsx/audit_ip_remap.py --target nsx-lm1 --csv data/nonprod_map.csv
  python tools/nsx/audit_ip_remap.py --target nsx-gm1 --federation-global --csv data/nonprod_map.csv
  python tools/nsx/audit_ip_remap.py --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups --csv data/nonprod_map.csv
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nsx.cli_bootstrap import init_cli                       # noqa: E402
from nsx.md_utils import align_markdown_tables                # noqa: E402
from nsx.nsx_constants import nsx_log_dir, resolve_manager    # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient             # noqa: E402
from nsx_group_ip_remap_offline import (                      # noqa: E402
    SKIP_INVALID, SKIP_IPV6, SKIP_RANGE, PrefixMappingTable,
    _canonical_ip_token, _load_mapping_csv, _token_kind,
)

log = logging.getLogger(__name__)
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]
EXCLUDED_FILENAMES = {"manifest.json", "summary.json", "summary.txt"}
MAX_INLINE = 8   # entries shown inline per group in the uncovered table


# =============================================================================
# Loading
# =============================================================================

def _is_system_object(g: Dict[str, Any]) -> bool:
    return bool(g.get("_system_owned") or g.get("system_owned") or g.get("marked_for_delete"))


def load_groups_from_dir(groups_dir: Path) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if not groups_dir.exists():
        raise SystemExit(f"Groups dir does not exist: {groups_dir}")
    files: List[Path] = []
    for ext in ("*.yaml", "*.yml", "*.json"):
        files.extend(p for p in groups_dir.rglob(ext) if p.name not in EXCLUDED_FILENAMES)
    for f in sorted(files):
        try:
            text = f.read_text(encoding="utf-8")
            data = json.loads(text) if f.suffix.lower() == ".json" else (yaml.safe_load(text) or {})
        except Exception as exc:
            log.warning("Could not parse %s: %s (skipping)", f.name, exc)
            continue
        if not isinstance(data, dict):
            continue
        gid = data.get("id")
        if gid and not _is_system_object(data):
            out[gid] = data
    return out


def load_groups_live(client: NsxPolicyClient, domain_id: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for g in client.list_groups(domain_id):
        gid = g.get("id")
        if gid and not _is_system_object(g):
            out[gid] = g
    return out


def reverse_table(forward: PrefixMappingTable) -> PrefixMappingTable:
    """new_subnet -> old_subnet, so a mapped-side value can be traced back."""
    rev = PrefixMappingTable()
    for r in forward.rows:
        rev.add(r["destination"], r["source"], r["row"], "reverse")
    rev.finalize()
    return rev


# =============================================================================
# Per-group audit
# =============================================================================

def walk_ip_entries(expression: Any, prefix: str = "expression") -> Iterator[Tuple[str, str]]:
    """Yield (value, location) for every ip_addresses entry, recursing into
    NestedExpression bodies. Location is like `expression[2].expressions[0]`."""
    if not isinstance(expression, list):
        return
    for i, e in enumerate(expression):
        if not isinstance(e, dict):
            continue
        loc = f"{prefix}[{i}]"
        if e.get("resource_type") == "IPAddressExpression" or "ip_addresses" in e:
            for v in e.get("ip_addresses") or []:
                if isinstance(v, str) and v.strip():
                    yield v.strip(), loc
        nested = e.get("expressions")
        if isinstance(nested, list):
            yield from walk_ip_entries(nested, f"{loc}.expressions")


def audit_group(
    group: Dict[str, Any],
    fwd: PrefixMappingTable,
    rev: PrefixMappingTable,
    *,
    include_generic: bool = False,
) -> Dict[str, Any]:
    """Audit one group. `include_generic` mirrors the push's --remap-generic:
    by default only IP-Addresses-Only groups are EXPECTED to be remapped, so a
    CSV-covered original in a generic group is a "candidate" (informational),
    not a gap. With include_generic=True it counts as a gap, matching a push
    that ran with --remap-generic."""
    gid = str(group.get("id"))
    is_ip_only = "IPAddress" in (group.get("group_type") or [])
    entries = list(walk_ip_entries(group.get("expression")))
    canon_present = {_canonical_ip_token(v) for v, _ in entries}

    mapped: List[Dict[str, Any]] = []
    gaps: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    orphans: List[Dict[str, Any]] = []
    uncovered: List[Dict[str, Any]] = []
    by_design: List[Dict[str, Any]] = []
    invalid: List[Dict[str, Any]] = []
    seen_pairs: set = set()

    for value, loc in entries:
        kind = _token_kind(value)
        if kind in (SKIP_RANGE, SKIP_IPV6):
            by_design.append({"value": value, "reason": kind, "location": loc})
            continue
        if kind == SKIP_INVALID:
            invalid.append({"value": value, "location": loc})
            continue

        mapped_vals, row = fwd.map_token(value)
        back_vals, rrow = rev.map_token(value)

        if mapped_vals:
            expected = mapped_vals[0]
            pair = (_canonical_ip_token(value), _canonical_ip_token(expected))
            if pair[1] in canon_present:
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    mapped.append({"original": value, "mapped": expected, "csv_row": row["row"], "location": loc})
            elif is_ip_only or include_generic:
                gaps.append({"original": value, "expected_mapped": expected, "csv_row": row["row"], "location": loc})
            else:
                candidates.append({"original": value, "expected_mapped": expected, "csv_row": row["row"], "location": loc})
        elif back_vals:
            original = back_vals[0]
            if _canonical_ip_token(original) not in canon_present:
                orphans.append({"present_value": value, "expected_original": original,
                                "csv_row": rrow["row"], "location": loc})
            # else: it is the mapped side of a pair already counted above
        else:
            uncovered.append({"value": value, "location": loc})

    if not entries:
        status = "no_ips"
    elif gaps or orphans:
        status = "gap"
    elif candidates:
        status = "candidate"
    elif mapped:
        status = "mapped"
    else:
        status = "no_csv_match"

    return {
        "id": gid,
        "display_name": group.get("display_name") or gid,
        "path": group.get("path"),
        "group_type": "ip-only" if is_ip_only else "generic",
        "status": status,
        "entry_count": len(entries),
        "has_nested_ips": any(".expressions[" in loc for _, loc in entries),
        "mapped_pairs": mapped,
        "gaps_missing_mapped": gaps,
        "generic_remap_candidates": candidates,
        "orphan_mapped_values": orphans,
        "uncovered_ipv4": uncovered,
        "not_remapped_by_design": by_design,
        "invalid_entries": invalid,
    }


def audit_groups(
    groups: Dict[str, Dict[str, Any]],
    fwd: PrefixMappingTable,
    rev: PrefixMappingTable,
    *,
    include_generic: bool = False,
) -> List[Dict[str, Any]]:
    return [audit_group(groups[gid], fwd, rev, include_generic=include_generic) for gid in sorted(groups)]


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    def total(key: str) -> int:
        return sum(len(r[key]) for r in rows)
    status_counts: Dict[str, int] = {}
    for r in rows:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1
    return {
        "groups_total": len(rows),
        "groups_ip_only": sum(1 for r in rows if r["group_type"] == "ip-only"),
        "groups_with_ip_entries": sum(1 for r in rows if r["entry_count"]),
        "groups_by_status": status_counts,
        "groups_with_nested_ips": sum(1 for r in rows if r["has_nested_ips"]),
        "mapped_pairs": total("mapped_pairs"),
        "gaps_missing_mapped": total("gaps_missing_mapped"),
        "generic_remap_candidates": total("generic_remap_candidates"),
        "generic_candidate_groups": sum(1 for r in rows if r["generic_remap_candidates"]),
        "orphan_mapped_values": total("orphan_mapped_values"),
        "uncovered_ipv4_entries": total("uncovered_ipv4"),
        "uncovered_ipv4_groups": sum(1 for r in rows if r["uncovered_ipv4"]),
        "not_remapped_by_design": total("not_remapped_by_design"),
        "invalid_entries": total("invalid_entries"),
    }


def has_gaps(summary: Dict[str, Any]) -> bool:
    return bool(summary["gaps_missing_mapped"] or summary["orphan_mapped_values"])


# =============================================================================
# Markdown
# =============================================================================

def _code(s: Any) -> str:
    return f"`{s}`"


def _label(r: Dict[str, Any]) -> str:
    """Group cell: display name first (the GUI identity), id in backticks when
    it differs; GUI-created groups get a UUID id but a readable name."""
    gid = r.get("id")
    name = r.get("display_name")
    if name and name != gid:
        return f"{name} ({_code(gid)})"
    return _code(gid)


def _inline(values: List[str]) -> str:
    shown = ", ".join(_code(v) for v in values[:MAX_INLINE])
    extra = len(values) - MAX_INLINE
    return shown + (f", +{extra} more" if extra > 0 else "")


def render_markdown(
    rows: List[Dict[str, Any]],
    summary: Dict[str, Any],
    *,
    label: str,
    source_desc: str,
    domain_id: str,
    csv_path: Path,
    csv_rows: int,
    csv_invalid: List[Dict[str, Any]],
    include_generic: bool = False,
) -> str:
    gap = has_gaps(summary)
    result = (f"GAPS FOUND: {summary['gaps_missing_mapped']} missing mapped, "
              f"{summary['orphan_mapped_values']} mapped-side without original") if gap else "CLEAN: no gaps"
    L: List[str] = []
    L.append(f"# IP remap audit: {label}")
    L.append("")
    L.append("| Field | Value |")
    L.append("|---|---|")
    L.append(f"| Generated (UTC) | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} |")
    L.append(f"| Source of truth | {source_desc} |")
    L.append(f"| Domain | {_code(domain_id)} |")
    L.append(f"| CSV | {_code(csv_path)} ({csv_rows} rows loaded, {len(csv_invalid)} rejected) |")
    L.append(f"| Customer groups | {summary['groups_total']} ({summary['groups_ip_only']} IP-only, "
             f"{summary['groups_total'] - summary['groups_ip_only']} generic; "
             f"{summary['groups_with_ip_entries']} with IP entries) |")
    L.append(f"| Remap scope | {'all groups (--include-generic)' if include_generic else 'IP-Addresses-Only groups (default; generic groups reported as candidates)'} |")
    L.append(f"| Mapped pairs present | {summary['mapped_pairs']} |")
    if not include_generic:
        L.append(f"| Generic-group candidates | {summary['generic_remap_candidates']} |")
    L.append(f"| **Result** | **{result}** |")
    L.append("")
    L.append("Read-only audit. Nothing here proposes a removal; gaps are entries the CSV "
             "says should have a mapped equivalent that is not present on the manager.")
    L.append("")

    # ---- 1. Gaps --------------------------------------------------------
    L.append("## 1. Gaps (review first)")
    L.append("")
    L.append(f"### 1a. Originals with no mapped equivalent present ({summary['gaps_missing_mapped']})")
    L.append("")
    if summary["gaps_missing_mapped"]:
        L.append("The original IP is on the manager and the CSV maps it, but the mapped value is not "
                 "there. Either the remap never reached this group (check the push report's "
                 "`failures.json`), or the entry was added after the remap ran.")
        L.append("")
        L.append("| Group | Original | Expected mapped | CSV row | Location |")
        L.append("|---|---|---|---:|---|")
        for r in rows:
            for g in r["gaps_missing_mapped"]:
                L.append(f"| {_label(r)} | {_code(g['original'])} | {_code(g['expected_mapped'])} "
                         f"| {g['csv_row']} | {_code(g['location'])} |")
    else:
        L.append("None.")
    L.append("")

    L.append(f"### 1b. Generic-group candidates: CSV-covered originals not remapped by default "
             f"({summary['generic_remap_candidates']} in {summary['generic_candidate_groups']} groups)")
    L.append("")
    if include_generic:
        L.append("Not applicable: this audit ran with --include-generic, so generic-group "
                 "misses are counted as gaps in section 1a.")
    elif summary["generic_remap_candidates"]:
        L.append("These originals sit in GENERIC groups. The push remaps only IP-Addresses-Only "
                 "groups by default, so these are informational, not gaps. A push with "
                 "--remap-generic would add the expected mapped values below.")
        L.append("")
        L.append("| Group | Original | Would map to | CSV row | Location |")
        L.append("|---|---|---|---:|---|")
        for r in rows:
            for g in r["generic_remap_candidates"]:
                L.append(f"| {_label(r)} | {_code(g['original'])} | {_code(g['expected_mapped'])} "
                         f"| {g['csv_row']} | {_code(g['location'])} |")
    else:
        L.append("None.")
    L.append("")

    L.append(f"### 1c. Mapped-side values whose original is absent ({summary['orphan_mapped_values']})")
    L.append("")
    if summary["orphan_mapped_values"]:
        L.append("The value sits inside a `new_subnet` from the CSV but the matching `old_subnet` "
                 "value is not on the manager. Either the original was removed after the remap, "
                 "or the value legitimately lived in the new range before the remap. Review; "
                 "do not remove.")
        L.append("")
        L.append("| Group | Present value | Expected original | CSV row | Location |")
        L.append("|---|---|---|---:|---|")
        for r in rows:
            for o in r["orphan_mapped_values"]:
                L.append(f"| {_label(r)} | {_code(o['present_value'])} | {_code(o['expected_original'])} "
                         f"| {o['csv_row']} | {_code(o['location'])} |")
    else:
        L.append("None.")
    L.append("")

    L.append(f"### 1d. IPv4 entries not covered by the CSV "
             f"({summary['uncovered_ipv4_entries']} entries in {summary['uncovered_ipv4_groups']} groups)")
    L.append("")
    if summary["uncovered_ipv4_entries"]:
        L.append("No CSV row covers these, so the remap left them alone. Expected for IPs outside "
                 "the remapped ranges; if any of these should have been remapped, the CSV needs a row.")
        L.append("")
        L.append("| Group | Entries | Count |")
        L.append("|---|---|---:|")
        for r in rows:
            if r["uncovered_ipv4"]:
                vals = [u["value"] for u in r["uncovered_ipv4"]]
                L.append(f"| {_label(r)} | {_inline(vals)} | {len(vals)} |")
    else:
        L.append("None.")
    L.append("")

    # ---- 2. Mapped --------------------------------------------------------
    mapped_groups = [r for r in rows if r["mapped_pairs"]]
    L.append(f"## 2. Mapped ({summary['mapped_pairs']} pairs in {len(mapped_groups)} groups)")
    L.append("")
    if mapped_groups:
        L.append("Both the original and its CSV-mapped equivalent are present on the manager.")
        L.append("")
        L.append("| Group | Original | Mapped | CSV row | Location |")
        L.append("|---|---|---|---:|---|")
        for r in mapped_groups:
            for m in r["mapped_pairs"]:
                L.append(f"| {_label(r)} | {_code(m['original'])} | {_code(m['mapped'])} "
                         f"| {m['csv_row']} | {_code(m['location'])} |")
    else:
        L.append("None.")
    L.append("")

    # ---- 3. By design -----------------------------------------------------
    L.append(f"## 3. Not remapped by design ({summary['not_remapped_by_design']})")
    L.append("")
    if summary["not_remapped_by_design"]:
        L.append("IP ranges and IPv6 entries are never remapped. Listed so nobody wonders why.")
        L.append("")
        L.append("| Group | Entry | Reason | Location |")
        L.append("|---|---|---|---|")
        for r in rows:
            for b in r["not_remapped_by_design"]:
                L.append(f"| {_label(r)} | {_code(b['value'])} | {b['reason']} | {_code(b['location'])} |")
    else:
        L.append("None.")
    L.append("")

    # ---- 4. Per-group status --------------------------------------------
    L.append("## 4. Per-group status")
    L.append("")
    L.append("| Group | Type | Status | IP entries | Mapped | Gaps | Candidates | Review | Uncovered | By design | Nested IPs |")
    L.append("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|")
    for r in rows:
        if not r["entry_count"]:
            continue
        L.append(f"| {_label(r)} | {r['group_type']} | {r['status']} | {r['entry_count']} | {len(r['mapped_pairs'])} "
                 f"| {len(r['gaps_missing_mapped'])} | {len(r['generic_remap_candidates'])} | {len(r['orphan_mapped_values'])} "
                 f"| {len(r['uncovered_ipv4'])} | {len(r['not_remapped_by_design'])} "
                 f"| {'yes' if r['has_nested_ips'] else ''} |")
    no_ip = summary["groups_total"] - summary["groups_with_ip_entries"]
    L.append("")
    L.append(f"{no_ip} group(s) have no IP entries at all (tag / path / segment criteria only) and are not listed.")
    if summary["groups_with_nested_ips"]:
        L.append("")
        L.append(f"{summary['groups_with_nested_ips']} group(s) carry IP entries inside a `NestedExpression`. "
                 "The remap does not touch nested bodies, so any of those entries that the CSV covers "
                 "will appear in section 1a until that is addressed.")
    L.append("")

    # ---- 5. Data quality --------------------------------------------------
    if summary["invalid_entries"] or csv_invalid:
        L.append("## 5. Data quality")
        L.append("")
        if csv_invalid:
            L.append(f"### CSV rows rejected ({len(csv_invalid)})")
            L.append("")
            L.append("Rejected rows map nothing, so their IPs show up in section 1c.")
            L.append("")
            L.append("| Row | old | new | Reason |")
            L.append("|---:|---|---|---|")
            for inv in csv_invalid:
                L.append(f"| {inv.get('row')} | {_code(inv.get('left_value'))} | {_code(inv.get('right_value'))} | {inv.get('reason')} |")
            L.append("")
        if summary["invalid_entries"]:
            L.append(f"### Entries that are not an IP, CIDR, or range ({summary['invalid_entries']})")
            L.append("")
            L.append("| Group | Entry | Location |")
            L.append("|---|---|---|")
            for r in rows:
                for x in r["invalid_entries"]:
                    L.append(f"| {_label(r)} | {_code(x['value'])} | {_code(x['location'])} |")
            L.append("")

    return align_markdown_tables("\n".join(L)) + "\n"


# =============================================================================
# Main
# =============================================================================

def _setup_logging(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / f"audit_ip_remap_{RUN_TS}.log"
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%S")
    for h in (logging.StreamHandler(), logging.FileHandler(log_file, encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    return log_file


def main() -> int:
    p = argparse.ArgumentParser(
        description="Read-only audit: what looks CSV-remapped on a manager, and what might be a gap.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--target", choices=NSX_MANAGER_CHOICES, default=None,
                     help="Live GET of customer groups from this manager (read-only).")
    src.add_argument("--groups-dir", default=None,
                     help="Directory of exported group YAML/JSON files instead of a live GET.")
    p.add_argument("--csv", required=True, help="old_subnet,new_subnet CSV the remap used.")
    p.add_argument("--domain-id", default="default")
    p.add_argument("--federation-global", action="store_true", help="Target is a Global Manager.")
    p.add_argument("--output-base", default=None,
                   help="Report root (default: $NSX_LOG_DIR/reports/ip_remap_audit/<label>/<ts>/).")
    p.add_argument("--label", default=None, help="Override the label used in the report and output path.")
    p.add_argument("--include-generic", action="store_true",
                   help="Treat CSV-covered originals in GENERIC groups as gaps too. Default mirrors "
                        "the push (--csv-remap remaps only IP-Addresses-Only groups), so generic "
                        "misses are reported as informational candidates in section 1b. Use this "
                        "when the push ran with --remap-generic.")
    p.add_argument("--no-fail-on-gaps", action="store_true",
                   help="Always exit 0 (default: exit 1 when section 1a or 1b is non-empty).")
    args = p.parse_args()

    init_cli()

    csv_path = Path(args.csv).expanduser().resolve()
    if not csv_path.exists():
        raise SystemExit(f"--csv file not found: {csv_path}")

    if args.target:
        host = resolve_manager(args.target)
        if not host:
            raise SystemExit(f"Manager not defined: {args.target}")
        label = args.label or host
        source_desc = f"live GET from {args.target} ({host}){' [federation-global]' if args.federation_global else ''}"
    else:
        groups_dir = Path(args.groups_dir).expanduser().resolve()
        label = args.label or groups_dir.parent.name if groups_dir.name == "groups" else (args.label or groups_dir.name)
        source_desc = f"export dir {groups_dir}"
        host = None

    base = Path(args.output_base).expanduser().resolve() if args.output_base else Path(nsx_log_dir).expanduser().resolve() / "reports" / "ip_remap_audit"
    out_dir = base / label / RUN_TS
    log_file = _setup_logging(out_dir)

    log.info("=" * 60)
    log.info("IP REMAP AUDIT (read-only)")
    log.info("  Source   : %s", source_desc)
    log.info("  CSV      : %s", csv_path)
    log.info("  Output   : %s", out_dir)
    log.info("=" * 60)

    fwd, csv_invalid = _load_mapping_csv(csv_path, bidirectional=False)
    rev = reverse_table(fwd)
    log.info("CSV: %d row(s) loaded, %d rejected", len(fwd.rows), len(csv_invalid))
    for inv in csv_invalid:
        log.warning("  CSV row %s rejected: %s", inv.get("row"), inv.get("reason"))

    if args.target:
        client = NsxPolicyClient(nsxmanager=host, federation_global=args.federation_global)
        groups = load_groups_live(client, args.domain_id)
    else:
        groups = load_groups_from_dir(groups_dir)
    log.info("Customer groups: %d", len(groups))

    rows = audit_groups(groups, fwd, rev, include_generic=args.include_generic)
    summary = summarize(rows)
    for r in rows:
        if r["status"] == "gap":
            log.warning("[gap] %s: %d missing mapped, %d mapped-side without original",
                        r["id"], len(r["gaps_missing_mapped"]), len(r["orphan_mapped_values"]))

    md = render_markdown(rows, summary, label=label, source_desc=source_desc, domain_id=args.domain_id,
                         csv_path=csv_path, csv_rows=len(fwd.rows), csv_invalid=csv_invalid,
                         include_generic=args.include_generic)
    (out_dir / "ip_remap_audit.md").write_text(md, encoding="utf-8")
    (out_dir / "ip_remap_audit.json").write_text(json.dumps(rows, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "gaps.json").write_text(json.dumps({
        "missing_mapped": [{"group_id": r["id"], **g} for r in rows for g in r["gaps_missing_mapped"]],
        "orphan_mapped_values": [{"group_id": r["id"], **o} for r in rows for o in r["orphan_mapped_values"]],
        "uncovered_ipv4": [{"group_id": r["id"], **u} for r in rows for u in r["uncovered_ipv4"]],
    }, indent=2, sort_keys=True), encoding="utf-8")
    full_summary = {
        "command": "audit_ip_remap",
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "label": label,
        "source": source_desc,
        "domain_id": args.domain_id,
        "csv": str(csv_path),
        "csv_rows_loaded": len(fwd.rows),
        "csv_rows_rejected": csv_invalid,
        "include_generic": args.include_generic,
        "result": "gaps" if has_gaps(summary) else "clean",
        "totals": summary,
        "report_md": str(out_dir / "ip_remap_audit.md"),
        "log_file": str(log_file),
    }
    (out_dir / "summary.json").write_text(json.dumps(full_summary, indent=2, sort_keys=True), encoding="utf-8")

    log.info("=" * 60)
    log.info("Result: %s  mapped_pairs=%d  missing_mapped=%d  generic_candidates=%d  "
             "mapped_side_without_original=%d  uncovered=%d  by_design=%d",
             full_summary["result"].upper(), summary["mapped_pairs"], summary["gaps_missing_mapped"],
             summary["generic_remap_candidates"], summary["orphan_mapped_values"],
             summary["uncovered_ipv4_entries"], summary["not_remapped_by_design"])
    log.info("Report: %s", out_dir / "ip_remap_audit.md")
    log.info("=" * 60)
    print(json.dumps(full_summary, indent=2))

    if has_gaps(summary) and not args.no_fail_on_gaps:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
