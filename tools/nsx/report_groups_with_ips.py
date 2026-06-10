#!/usr/bin/env python3
"""
tools/nsx/report_groups_with_ips.py

Read-only analysis tool that walks an exported group bundle and reports
which groups contain IP addresses, their shape (tag-only / pure-IP /
hybrid / nested), and — if a CSV mapping is provided — which of those
IPs have a non-prod equivalent in the mapping.

Built for the WF-D (in-place remap-to-siblings on a live prod manager)
planning phase: operator runs this against the source capture / export
to understand the scope BEFORE designing the push.

INPUTS (one of):
  --source <alias>     Read from nsx_groups_export/<host>/groups/
  --groups-dir <path>  Explicit path to a directory of group YAMLs
  --capture <alias>    Read from nsx_capture/<host>/groups_additive/
                       domains/<domain>/groups/ (the additive-enriched bundle)

OPTIONAL:
  --csv <path>         Path to a 2-col CSV (old_subnet,new_subnet) to
                       cross-reference each group's IPs against the
                       mapping. Reports per-group coverage.

OUTPUT:
  $NSX_LOG_DIR/groups_ip_report/<label>/
    groups_with_ips.json    full report (rows + summary)
    groups_with_ips.jsonl   one row per line (greppable)
    summary.json            counters only
    logs/

Read-only against NSX — no API calls.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.cli_bootstrap import init_cli            # noqa: E402
from nsx.nsx_constants import resolve_manager, nsx_log_dir   # noqa: E402

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]


# =============================================================================
# Recursive expression walkers — mirror build_sibling_groups.py so the
# "decomposable" verdict matches what WF-C would actually do.
# =============================================================================

def _has_condition_anywhere(expression: List[Any]) -> bool:
    for e in expression or []:
        if isinstance(e, dict):
            if e.get("resource_type") == "Condition":
                return True
            if e.get("resource_type") == "NestedExpression":
                if _has_condition_anywhere(e.get("expressions")):
                    return True
    return False


def _has_nested_expression(expression: List[Any]) -> bool:
    for e in expression or []:
        if isinstance(e, dict) and e.get("resource_type") == "NestedExpression":
            return True
    return False


def _has_path_expression(expression: List[Any]) -> bool:
    for e in expression or []:
        if isinstance(e, dict):
            if e.get("resource_type") == "PathExpression":
                return True
            if e.get("resource_type") == "NestedExpression":
                if _has_path_expression(e.get("expressions")):
                    return True
    return False


def _collect_ips(expression: List[Any]) -> Tuple[List[str], List[str]]:
    """Return (top_level_ips, nested_ips). Used to attribute where IPs live."""
    top: List[str] = []
    nested: List[str] = []
    seen_top: Set[str] = set()
    seen_nested: Set[str] = set()

    def _walk_nested(items: List[Any]) -> None:
        for e in items or []:
            if not isinstance(e, dict):
                continue
            if e.get("resource_type") == "IPAddressExpression":
                for ip in (e.get("ip_addresses") or []):
                    if isinstance(ip, str) and ip not in seen_nested:
                        seen_nested.add(ip)
                        nested.append(ip)
            elif e.get("resource_type") == "NestedExpression":
                _walk_nested(e.get("expressions"))

    for e in expression or []:
        if not isinstance(e, dict):
            continue
        if e.get("resource_type") == "IPAddressExpression":
            for ip in (e.get("ip_addresses") or []):
                if isinstance(ip, str) and ip not in seen_top:
                    seen_top.add(ip)
                    top.append(ip)
        elif e.get("resource_type") == "NestedExpression":
            _walk_nested(e.get("expressions"))

    return top, nested


def _classify_shape(has_cond: bool, has_ips: bool, has_path: bool) -> str:
    if has_cond and has_ips and has_path: return "tag+segment+ip hybrid"
    if has_cond and has_ips:               return "tag+ip hybrid"
    if has_cond and has_path:              return "tag+segment hybrid (no static ips)"
    if has_cond:                           return "pure-tag"
    if has_ips and has_path:               return "segment+ip"
    if has_ips:                            return "pure-ip"
    if has_path:                           return "pure-segment"
    return "empty"


def _wf_c_outcome(has_cond: bool, has_ips: bool) -> str:
    if has_cond and has_ips: return "DECOMPOSED (sibling + stripped)"
    if has_cond:             return "skipped: tagged but no static ips (skipped_empty_ips)"
    return "skipped: no condition (skipped_no_condition)"


# =============================================================================
# CSV mapping
# =============================================================================

def _load_csv_mapping(path: Path) -> Dict[str, str]:
    """Parse a 2-col CSV: old_subnet, new_subnet. Returns dict of {old: new}."""
    out: Dict[str, str] = {}
    with path.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            # tolerate trailing comma / extra cells
            row = [c.strip() for c in row if c is not None]
            if not row or all(not c for c in row):
                continue
            if i == 0 and row[0].lower() in ("old_subnet", "old", "from", "source"):
                continue  # header
            if len(row) < 2:
                log.warning("CSV row %d malformed (need 2 cols): %r", i, row)
                continue
            old, new = row[0].strip(), row[1].strip()
            if old and new:
                out[old] = new
    return out


def _ip_or_net(s: str) -> Optional[Any]:
    """Parse '10.6.0.1', '10.6.0.0/24', '10.6.0.1-10.6.0.5'. Returns
    IPv4Network/IPv4Address/None. Ranges return tuple."""
    s = s.strip()
    if "-" in s and "/" not in s:
        # IP range
        try:
            a, b = s.split("-", 1)
            return ("range", ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip()))
        except Exception:
            return None
    try:
        if "/" in s:
            return ipaddress.ip_network(s, strict=False)
        return ipaddress.ip_address(s)
    except Exception:
        return None


def _csv_lookup(ip_str: str, mapping: Dict[str, str]) -> Optional[str]:
    """Find a CSV mapping that covers this IP. Exact-string match wins first;
    otherwise check by-network containment for hosts, subnets, and ranges."""
    if ip_str in mapping:
        return mapping[ip_str]
    ip_obj = _ip_or_net(ip_str)
    if ip_obj is None:
        return None
    is_range = isinstance(ip_obj, tuple) and ip_obj[0] == "range"
    # Iterate mapping looking for a network that contains the IP / subnet / range
    for k, v in mapping.items():
        k_obj = _ip_or_net(k)
        if k_obj is None:
            continue
        try:
            if isinstance(ip_obj, ipaddress._BaseAddress) and isinstance(k_obj, ipaddress._BaseNetwork):
                if ip_obj in k_obj:
                    return v
            elif isinstance(ip_obj, ipaddress._BaseNetwork) and isinstance(k_obj, ipaddress._BaseNetwork):
                if ip_obj.subnet_of(k_obj):
                    return v
            elif is_range and isinstance(k_obj, ipaddress._BaseNetwork):
                # Range matches if BOTH endpoints fall inside the CSV's network
                _, lo, hi = ip_obj
                if lo in k_obj and hi in k_obj:
                    return v
        except Exception:
            continue
    return None


# =============================================================================
# Bundle I/O
# =============================================================================

def _setup_logging(reports_dir: Path) -> Path:
    log_dir_path = Path(nsx_log_dir).expanduser().resolve()
    log_dir_path.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    bundle_log = (reports_dir / f"report_groups_with_ips_{RUN_TS}.log").resolve()
    global_log = (log_dir_path / f"report_groups_with_ips_{RUN_TS}.log").resolve()
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                            "%Y-%m-%dT%H:%M:%S")
    for h in (logging.StreamHandler(), logging.FileHandler(bundle_log, encoding="utf-8"),
              logging.FileHandler(global_log, encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    return bundle_log


def _is_system_object(g: Dict[str, Any]) -> bool:
    return bool(g.get("_system_owned") or g.get("system_owned") or g.get("marked_for_delete"))


def _load_groups_from_dir(d: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not d.exists():
        raise SystemExit(f"Group directory does not exist: {d}")
    for f in sorted(d.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            log.warning("Could not parse %s: %s — skipping", f.name, exc)
            continue
        if data.get("id") and not _is_system_object(data):
            out.append(data)
    return out


def _derive_label_from_path(p: Path) -> str:
    """Walk up the path looking for a directory whose name contains '.'
    (e.g. 'nsx-lm1.lab.local'). Falls back to the leaf directory name."""
    for ancestor in [p] + list(p.parents):
        if "." in ancestor.name:
            return ancestor.name
    return p.name


def _resolve_input(args: argparse.Namespace) -> Tuple[Path, str]:
    if args.groups_dir:
        p = Path(args.groups_dir).expanduser().resolve()
        if not p.exists():
            raise SystemExit(f"--groups-dir does not exist: {p}")
        label = args.label or _derive_label_from_path(p)
        return p, label
    if args.source:
        host = resolve_manager(args.source)
        if not host:
            raise SystemExit(f"Source manager not defined: {args.source}")
        p = (REPO_ROOT / "nsx_groups_export" / host / "groups").resolve()
        if not p.exists():
            raise SystemExit(
                f"No groups export at {p}. Run `groups.py export --source {args.source}` first."
            )
        return p, (args.label or host)
    if args.capture:
        host = resolve_manager(args.capture)
        if not host:
            raise SystemExit(f"Capture manager not defined: {args.capture}")
        p = (REPO_ROOT / "nsx_capture" / host / "groups_additive"
                       / "domains" / args.domain_id / "groups").resolve()
        if not p.exists():
            raise SystemExit(
                f"No capture groups_additive at {p}. Run capture_nsx_state.py first."
            )
        return p, (args.label or host)
    raise SystemExit("Provide one of --source / --groups-dir / --capture.")


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(
        description=("Report which groups in an export bundle contain IP addresses, "
                     "their shape, and (optionally) CSV-mapping coverage. Read-only.")
    )
    inp = p.add_mutually_exclusive_group(required=True)
    inp.add_argument("--source", choices=NSX_MANAGER_CHOICES, default=None,
                     help="Read from nsx_groups_export/<host>/groups/.")
    inp.add_argument("--groups-dir", default=None,
                     help="Explicit path to a directory of group YAMLs.")
    inp.add_argument("--capture", choices=NSX_MANAGER_CHOICES, default=None,
                     help="Read from nsx_capture/<host>/groups_additive/domains/<d>/groups/.")
    p.add_argument("--csv", default=None,
                   help="Optional 2-col CSV (old,new) to cross-reference IP coverage.")
    p.add_argument("--domain-id", default="default", help="NSX domain (default: default).")
    p.add_argument("--output-base", default=None,
                   help="Output root; default: $NSX_LOG_DIR.")
    p.add_argument("--label", default=None,
                   help="Explicit label for the report subdirectory. Overrides the "
                        "heuristic that derives it from the input path.")
    args = p.parse_args()

    init_cli()

    bundle_dir, label = _resolve_input(args)
    output_base = (Path(args.output_base).expanduser().resolve()
                   if args.output_base else Path(nsx_log_dir))
    reports_dir = output_base / "groups_ip_report" / label
    log_file = _setup_logging(reports_dir / "logs")

    log.info("=" * 60)
    log.info("GROUPS WITH IPs — REPORT")
    log.info("  Bundle      : %s", bundle_dir)
    log.info("  CSV mapping : %s", args.csv or "(none)")
    log.info("  Reports     : %s", reports_dir)
    log.info("=" * 60)

    groups = _load_groups_from_dir(bundle_dir)
    mapping: Dict[str, str] = {}
    if args.csv:
        csv_path = Path(args.csv).expanduser().resolve()
        if not csv_path.exists():
            raise SystemExit(f"--csv does not exist: {csv_path}")
        mapping = _load_csv_mapping(csv_path)
        log.info("Loaded %d CSV mappings from %s", len(mapping), csv_path)

    rows: List[Dict[str, Any]] = []
    counters: Dict[str, int] = {
        "total_groups": 0,
        "with_ips": 0,
        "empty_groups": 0,  # groups with zero IPs anywhere in static payload
        "decomposable_by_wf_c": 0,
        "skip_no_condition": 0,
        "skip_empty_ips": 0,
        "shape_pure_ip": 0,
        "shape_pure_tag": 0,
        "shape_pure_segment": 0,
        "shape_tag_ip_hybrid": 0,
        "shape_tag_segment_hybrid_no_ips": 0,
        "shape_tag_segment_ip_hybrid": 0,
        "shape_segment_ip": 0,
        "shape_empty": 0,
        "shape_other": 0,
        "with_nested_expression": 0,
        "with_path_expression": 0,
        "total_unique_ips_across_groups": 0,
        "ips_with_csv_mapping": 0,
        "ips_without_csv_mapping": 0,
        "groups_fully_covered_by_csv": 0,
        "groups_partially_covered_by_csv": 0,
        "groups_uncovered_by_csv": 0,
    }
    unique_ips_seen: Set[str] = set()
    empty_groups: List[Dict[str, Any]] = []  # surfaced as its own report

    for g in groups:
        counters["total_groups"] += 1
        expr = g.get("expression") or []
        has_cond = _has_condition_anywhere(expr)
        has_nest = _has_nested_expression(expr)
        has_path = _has_path_expression(expr)
        top_ips, nested_ips = _collect_ips(expr)
        all_ips = sorted(set(top_ips) | set(nested_ips))
        has_ips = len(all_ips) > 0
        shape = _classify_shape(has_cond, has_ips, has_path)
        outcome = _wf_c_outcome(has_cond, has_ips)

        # CSV coverage per group
        csv_covered: List[str] = []
        csv_uncovered: List[str] = []
        csv_mapped_to: List[str] = []
        if mapping and has_ips:
            for ip in all_ips:
                hit = _csv_lookup(ip, mapping)
                if hit:
                    csv_covered.append(ip)
                    csv_mapped_to.append(hit)
                else:
                    csv_uncovered.append(ip)
            if csv_uncovered and csv_covered:
                counters["groups_partially_covered_by_csv"] += 1
            elif csv_covered and not csv_uncovered:
                counters["groups_fully_covered_by_csv"] += 1
            elif all_ips and not csv_covered:
                counters["groups_uncovered_by_csv"] += 1

        row = {
            "group_id":              g.get("id"),
            "display_name":          g.get("display_name"),
            "shape":                 shape,
            "wf_c_outcome":          outcome,
            "decomposable_by_wf_c":  bool(has_cond and has_ips),
            "has_condition":         has_cond,
            "has_nested_expression": has_nest,
            "has_path_expression":   has_path,
            "ip_count_top_level":    len(top_ips),
            "ip_count_nested":       len(nested_ips),
            "ip_count_total":        len(all_ips),
            "ips_top_level":         sorted(top_ips),
            "ips_nested":            sorted(nested_ips),
            "ips_all":               all_ips,
        }
        if mapping:
            row["csv_covered_ips"]   = csv_covered
            row["csv_mapped_to"]     = csv_mapped_to
            row["csv_uncovered_ips"] = csv_uncovered
            row["csv_coverage"]      = (
                "fully" if csv_covered and not csv_uncovered
                else "partial" if csv_covered and csv_uncovered
                else "none" if all_ips
                else "n/a (no ips)"
            )
        rows.append(row)

        if has_ips:
            counters["with_ips"] += 1
            unique_ips_seen |= set(all_ips)
            if mapping:
                counters["ips_with_csv_mapping"] += len(csv_covered)
                counters["ips_without_csv_mapping"] += len(csv_uncovered)
        else:
            counters["empty_groups"] += 1
            empty_groups.append({
                "group_id":              g.get("id"),
                "display_name":          g.get("display_name"),
                "shape":                 shape,
                "has_condition":         has_cond,
                "has_path_expression":   has_path,
                "has_nested_expression": has_nest,
                "reason":                (
                    "pure-tag (Condition only — no static IPs in payload)" if has_cond and not has_path else
                    "pure-segment (PathExpression only)" if has_path and not has_cond else
                    "tag+segment hybrid (Condition + PathExpression, no static IPs)" if has_cond and has_path else
                    "completely empty (no expression entries)"
                ),
            })
        if has_cond and has_ips:
            counters["decomposable_by_wf_c"] += 1
        elif has_cond:
            counters["skip_empty_ips"] += 1
        else:
            counters["skip_no_condition"] += 1
        if has_nest:
            counters["with_nested_expression"] += 1
        if has_path:
            counters["with_path_expression"] += 1
        shape_key = "shape_" + shape.replace("+", "_").replace(" ", "_").replace("(", "").replace(")", "").replace("-", "_")
        if shape_key in counters:
            counters[shape_key] += 1
        else:
            counters["shape_other"] += 1

    counters["total_unique_ips_across_groups"] = len(unique_ips_seen)

    summary = {
        "ran_at":         datetime.now(timezone.utc).isoformat(),
        "source_bundle":  str(bundle_dir),
        "csv_mapping":    str(Path(args.csv).expanduser().resolve()) if args.csv else None,
        "csv_mapping_entries": len(mapping) if mapping else 0,
        "counters":       counters,
        "log_file":       str(log_file),
    }

    (reports_dir / "groups_with_ips.json").write_text(
        json.dumps({"summary": summary, "rows": rows}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    with (reports_dir / "groups_with_ips.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    (reports_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8",
    )
    # Separate empty-groups report so it's directly grep-able / linkable in CAB docs.
    (reports_dir / "empty_groups.json").write_text(
        json.dumps({
            "count": len(empty_groups),
            "ran_at": summary["ran_at"],
            "source_bundle": summary["source_bundle"],
            "groups": empty_groups,
        }, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    log.info("=" * 60)
    log.info("SUMMARY")
    log.info("  Total groups                          : %d", counters["total_groups"])
    log.info("  Groups WITH IP addresses              : %d", counters["with_ips"])
    log.info("  Empty groups (no IPs anywhere)        : %d  (see empty_groups.json)", counters["empty_groups"])
    log.info("  Decomposable by WF-C (Condition+IPs)  : %d", counters["decomposable_by_wf_c"])
    log.info("    .. of those with NestedExpression   : %d", counters["with_nested_expression"])
    log.info("  Skipped by WF-C: no Condition         : %d", counters["skip_no_condition"])
    log.info("  Skipped by WF-C: empty IPs            : %d", counters["skip_empty_ips"])
    log.info("  Shape breakdown:")
    log.info("    pure-ip                             : %d", counters["shape_pure_ip"])
    log.info("    pure-tag                            : %d", counters["shape_pure_tag"])
    log.info("    pure-segment                        : %d", counters["shape_pure_segment"])
    log.info("    tag+ip hybrid                       : %d", counters["shape_tag_ip_hybrid"])
    log.info("    tag+segment hybrid (no static ips)  : %d", counters["shape_tag_segment_hybrid_no_ips"])
    log.info("    tag+segment+ip hybrid               : %d", counters["shape_tag_segment_ip_hybrid"])
    log.info("    segment+ip                          : %d", counters["shape_segment_ip"])
    log.info("    other / empty                       : %d", counters["shape_empty"] + counters["shape_other"])
    log.info("  Unique IPs across all groups          : %d", counters["total_unique_ips_across_groups"])
    if mapping:
        log.info("  CSV mapping rows loaded               : %d", len(mapping))
        log.info("  IPs with a CSV mapping (occurrences)  : %d", counters["ips_with_csv_mapping"])
        log.info("  IPs without a CSV mapping             : %d", counters["ips_without_csv_mapping"])
        log.info("  Groups fully covered by CSV           : %d", counters["groups_fully_covered_by_csv"])
        log.info("  Groups partially covered by CSV       : %d", counters["groups_partially_covered_by_csv"])
        log.info("  Groups with IPs but no CSV coverage   : %d", counters["groups_uncovered_by_csv"])
    log.info("Report: %s", reports_dir)
    log.info("=" * 60)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
