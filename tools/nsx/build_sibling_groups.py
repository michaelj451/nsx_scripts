#!/usr/bin/env python3
"""
tools/nsx/build_sibling_groups.py

Offline transform that decomposes "tag + IP" groups (from a capture bundle)
into two sibling artifacts:

  1. nsx_sibling_groups/<host>/groups/<gid><APPENDIX>.yaml
       New IP-only sibling group, named <original_id><OBJECT_APPENDIX>.
       Contains ONLY the captured IPAddressExpression — no Conditions, no
       PathExpressions, no tags.

Plus a machine-readable map for downstream rule-amend step:
  2. nsx_sibling_groups/<host>/sibling_map.json
       { "original_id": "...", "sibling_id": "...", ... } per row.

INPUTS:
  --capture <path>     Path to a capture bundle (must contain
                       groups_additive/domains/<d>/groups/*.yaml). Defaults
                       to nsx_capture/<source-host>/ if --source is given.
  --source <alias>     NSX manager alias. Resolves to the host directory.
                       Pass either --source or --capture.

OPTIONS:
  --appendix <str>     Override the sibling-id suffix. Defaults to
                       OBJECT_APPENDIX from .env (e.g. "_sibling").
  --output-base <dir>  Root for the output bundles. Default: repo root
                       (so outputs land at nsx_sibling_groups/<host>/).
  --include-empty      Also emit siblings for tagged groups whose captured
                       IPAddressExpression is empty (zero IPs). Default
                       off — pointless siblings are skipped.

OUTPUT:
  Console summary + sibling_map.json. Read-only against NSX (no API calls).
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# Make sibling tools importable so we can grab the short_id_filename helper.
sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.cli_bootstrap import init_cli  # noqa: E402
from nsx.nsx_constants import resolve_manager, object_appendix as ENV_APPENDIX, nsx_log_dir  # noqa: E402
from utilities.file_utilities import short_id_filename  # noqa: E402


log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


# =============================================================================
# Logging
# =============================================================================

def _setup_logging(reports_dir: Path) -> Path:
    """Console + bundle log + global log."""
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    bundle_log = (reports_dir / f"build_sibling_groups_{RUN_TS}.log").resolve()
    global_log = (global_log_dir / f"build_sibling_groups_{RUN_TS}.log").resolve()
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


# =============================================================================
# Decomposition logic
# =============================================================================

# Volatile / read-only fields we strip from both outputs so they push cleanly.
STRIP_KEYS = {
    "_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
    "_revision", "revision", "_protection", "_system_owned",
    "marked_for_delete", "overridden", "remote_path",
    "realization_id", "unique_id", "origin_site_id", "owner_id",
    "_links", "_schema", "_self", "status", "children",
    "path", "relative_path", "parent_path",
}


def _sanitize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items() if k not in STRIP_KEYS}
    if isinstance(obj, list):
        return [_sanitize(x) for x in obj]
    return obj


def _is_tag_condition(expr_entry: Dict[str, Any]) -> bool:
    """True for a Condition expression (tag-based dynamic membership).
    Any Condition counts; the user wants any tagged group to get the
    decomposition treatment.
    """
    return (
        isinstance(expr_entry, dict)
        and expr_entry.get("resource_type") == "Condition"
    )


def _is_ip_expression(expr_entry: Dict[str, Any]) -> bool:
    return (
        isinstance(expr_entry, dict)
        and expr_entry.get("resource_type") == "IPAddressExpression"
    )


def _is_nested_expression(expr_entry: Dict[str, Any]) -> bool:
    return (
        isinstance(expr_entry, dict)
        and expr_entry.get("resource_type") == "NestedExpression"
    )


def _is_path_expression(expr_entry: Dict[str, Any]) -> bool:
    return (
        isinstance(expr_entry, dict)
        and expr_entry.get("resource_type") == "PathExpression"
    )


def _has_path_expression_anywhere(expression: List[Any]) -> bool:
    """True if any PathExpression exists at the top level OR inside any
    NestedExpression at any depth."""
    for e in expression or []:
        if _is_path_expression(e):
            return True
        if _is_nested_expression(e) and _has_path_expression_anywhere(e.get("expressions")):
            return True
    return False


def _member_paths(expression: List[Any]) -> List[str]:
    """Every path in every PathExpression, at any depth."""
    out: List[str] = []
    for e in expression or []:
        if _is_path_expression(e):
            out.extend(p for p in (e.get("paths") or []) if isinstance(p, str))
        elif _is_nested_expression(e):
            out.extend(_member_paths(e.get("expressions")))
    return out


def _is_group_path(path: str) -> bool:
    return "/domains/" in path and "/groups/" in path


def _non_group_paths(expression: List[Any]) -> List[str]:
    """PathExpression members that are NOT other groups: segments, segment
    ports, VIFs and the like. These are what --skip-segment-groups skips. A
    group that only nests other groups by path is not segment-based: its
    effective IPs are its members' IPs, and it gets a sibling like any other."""
    return [p for p in _member_paths(expression) if not _is_group_path(p)]


def _apply_csv_mapping(ips: List[str], csv_mapping: Any
                       ) -> Tuple[List[str], List[str], List[List[Any]]]:
    """Run each source IP through the CSV mapping table.

    Returns (mapped_ips, uncovered_ips, pairs). Order is preserved relative to
    the input list. Duplicates in the mapped output are deduped. `pairs` is
    [[source_ip, [mapped...]], ...] for every source IP (an empty list for an
    uncovered one): the per-address audit a reviewer reads in the report.
    """
    mapped: List[str] = []
    uncovered: List[str] = []
    pairs: List[List[Any]] = []
    seen: set = set()
    for ip in ips:
        mapped_list, _row = csv_mapping.map_token(ip)
        pairs.append([ip, list(mapped_list or [])])
        if not mapped_list:
            uncovered.append(ip)
            continue
        for m in mapped_list:
            if m not in seen:
                seen.add(m)
                mapped.append(m)
    return mapped, uncovered, pairs


def _has_condition_anywhere(expression: List[Any]) -> bool:
    """True if any Condition exists at the top level OR inside any
    NestedExpression at any depth. NSX wraps complex tag policies in
    NestedExpression, so top-level-only checks miss them."""
    for e in expression or []:
        if _is_tag_condition(e):
            return True
        if _is_nested_expression(e) and _has_condition_anywhere(e.get("expressions")):
            return True
    return False


def _collect_ips(expression: List[Any]) -> List[str]:
    """Flatten ip_addresses across every IPAddressExpression entry, recursing
    into NestedExpression bodies."""
    seen: set = set()
    out: List[str] = []

    def _walk(items: List[Any]) -> None:
        for e in items or []:
            if _is_ip_expression(e):
                for ip in (e.get("ip_addresses") or []):
                    if isinstance(ip, str) and ip not in seen:
                        seen.add(ip)
                        out.append(ip)
            elif _is_nested_expression(e):
                _walk(e.get("expressions"))

    _walk(expression)
    return out


def split_group(
    orig_group: Dict[str, Any],
    appendix: str,
    include_empty: bool = False,
    csv_mapping: Any = None,
    include_pure_ip: bool = False,
    skip_segment_groups: bool = False,
    skip_uncovered: bool = False,
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """Decompose one group into (sibling_payload, info).

    `info` is always a dict with these keys:
        source_id            : the original group id
        ips_source           : list of IPs collected from the source group
        ips_sibling          : list of IPs that end up in the sibling
                               (== ips_source when csv_mapping is None,
                                else the CSV-mapped equivalents only)
        ips_uncovered        : source IPs without a CSV mapping
                               (empty when csv_mapping is None or all mapped)
        ip_pairs             : [[source_ip, [mapped...]], ...] with csv_mapping
        segment_paths        : the non-group paths that made it a segment group
        has_condition        : did the source have a Condition anywhere?
        has_path_expression  : did the source have a PathExpression anywhere?
        has_nested_expression: did the source have a NestedExpression anywhere?
        skip_reason          : None if decomposed; otherwise one of
                               "no_condition" | "empty_ips" | "segment_group"
                               | "uncovered_ips" | "no_mapped_ips"

    Returns (None, info) when no decomposition applies.

    Behavior switches:
      include_empty        : emit siblings for tagged groups with empty IPs.
      csv_mapping          : when provided (a PrefixMappingTable), the
                             sibling's IPAddressExpression carries the MAPPED
                             IPs only. Source IPs are NOT included in the
                             sibling: they stay on the original, which every
                             amended rule keeps referencing. A group where no
                             IP maps gets no sibling. WF-D also decomposes
                             groups without a Condition (IP-only, or nesting
                             other groups), so every group rules use gets its
                             AVS counterpart the same way.
      include_pure_ip      : relax the no-Condition gate without a CSV map.
      skip_segment_groups  : skip the group entirely if any PathExpression
                             member is not another group (a segment, segment
                             port, VIF...). A group that only nests other
                             groups by path is decomposed normally.
      skip_uncovered       : when csv_mapping is provided, skip the group
                             entirely if any source IP lacks a mapping.
    """
    orig_id = orig_group.get("id")
    info: Dict[str, Any] = {
        "source_id": orig_id,
        "ips_source": [],
        "ips_sibling": [],
        "ips_uncovered": [],
        "ip_pairs": [],
        "segment_paths": [],
        "has_condition": False,
        "has_path_expression": False,
        "has_nested_expression": False,
        "skip_reason": None,
    }
    if not orig_id:
        info["skip_reason"] = "no_id"
        return None, info

    expression = orig_group.get("expression") or []
    if not isinstance(expression, list):
        info["skip_reason"] = "no_id"
        return None, info

    has_condition = _has_condition_anywhere(expression)
    has_path      = _has_path_expression_anywhere(expression)
    has_nested    = any(_is_nested_expression(e) for e in expression)
    src_ips       = _collect_ips(expression)
    info.update({
        "has_condition": has_condition,
        "has_path_expression": has_path,
        "has_nested_expression": has_nested,
        "ips_source": src_ips,
    })

    # Gate 0 (WF-D): skip a segment-based group, i.e. one with a PathExpression
    # member that is not another group.
    segment_paths = _non_group_paths(expression)
    if skip_segment_groups and segment_paths:
        info["segment_paths"] = segment_paths
        info["skip_reason"] = "segment_group"
        return None, info

    # Gate 1: must have a Condition somewhere, unless a CSV map is in play
    # (WF-D gives every group its mapped sibling) or --include-pure-ip.
    if not has_condition and not include_pure_ip and csv_mapping is None:
        info["skip_reason"] = "no_condition"
        return None, info

    # Gate 2: must have at least one IP, unless --include-empty relaxes it.
    if not src_ips and not include_empty:
        info["skip_reason"] = "empty_ips"
        return None, info

    # CSV mapping (optional): the sibling carries the mapped equivalents only.
    # Source addresses, hand-entered ones included, stay on the original group,
    # which every amended rule keeps referencing, so nothing loses coverage.
    if csv_mapping is not None:
        mapped_ips, uncovered, pairs = _apply_csv_mapping(src_ips, csv_mapping)
        info["ips_uncovered"] = uncovered
        info["ip_pairs"] = pairs
        if skip_uncovered and uncovered:
            info["skip_reason"] = "uncovered_ips"
            return None, info
        if not mapped_ips:
            info["skip_reason"] = "no_mapped_ips"
            return None, info
        sibling_ips = mapped_ips
    else:
        sibling_ips = list(src_ips)

    info["ips_sibling"] = sibling_ips

    sibling_id = f"{orig_id}{appendix}"
    sibling_display = f"{orig_group.get('display_name') or orig_id}{appendix}"
    sibling = _sanitize({
        "id": sibling_id,
        "display_name": sibling_display,
        "description": (f"IP-only sibling of {orig_id}; generated "
                        f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} "
                        f"by build_sibling_groups.py"),
        "resource_type": "Group",
        # Mark as an IP-address-typed group so NSX surfaces it as IP-only in the
        # UI and other consumers (e.g. ip-address-group on lm1 carries this).
        "group_type": ["IPAddress"],
        "expression": [
            {
                "resource_type": "IPAddressExpression",
                "ip_addresses": sibling_ips,
            }
        ],
    })

    return sibling, info


# =============================================================================
# Bundle I/O
# =============================================================================

def _load_yaml(p: Path) -> Dict[str, Any]:
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _write_yaml(p: Path, data: Dict[str, Any]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False),
                 encoding="utf-8")


# Written by the push that consumes a bundle, not by this build: revert
# baselines, pushed-id lists and push reports. Never regenerable.
PRESERVED_ON_REBUILD = ("push_report",)


def _clear_build_output(bundle: Path) -> None:
    """Remove everything this build produces under `bundle`, keeping the
    entries in PRESERVED_ON_REBUILD."""
    if not bundle.exists():
        return
    for child in bundle.iterdir():
        if child.name in PRESERVED_ON_REBUILD:
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _resolve_input(args: argparse.Namespace) -> Tuple[Path, str]:
    """Return (groups_dir, label).

    Three input modes (mutually exclusive):
      --source <alias>     → reads nsx_capture/<host>/groups_additive/domains/<d>/groups/
                             (the captured-VM-IPs view; same as Workflow A Part 3 input)
      --capture <path>     → explicit path to a capture bundle, same layout
      --groups-dir <path>  → explicit path to ANY directory of group YAMLs. Used to
                             read a live target's exported state (e.g. lm2 after
                             WF-A Part 3 drift) so the transform produces siblings
                             reflecting the TARGET's IPs, not the source's.
    """
    if args.groups_dir:
        groups_dir = Path(args.groups_dir).expanduser().resolve()
        if not groups_dir.exists():
            raise SystemExit(f"--groups-dir does not exist: {groups_dir}")
        if args.label:
            label = args.label
        else:
            # Auto-derive: walk up from the groups dir looking for a hostname-shaped parent
            # (heuristic: contains a dot, e.g. "nsx-lm2.lab.local"). Falls back to immediate
            # parent dir name.
            parts = groups_dir.resolve().parts
            label = None
            for p in reversed(parts):
                if "." in p and not p.startswith("."):
                    label = p
                    break
            if label is None:
                label = groups_dir.parent.name or "unknown"
        return groups_dir, label

    if args.capture:
        capture = Path(args.capture).expanduser().resolve()
        if not capture.exists():
            raise SystemExit(f"--capture path does not exist: {capture}")
        label = args.label or capture.name
        groups_dir = capture / "groups_additive" / "domains" / args.domain_id / "groups"
        if not groups_dir.exists():
            raise SystemExit(
                f"groups_additive directory not found: {groups_dir}\n"
                "Run capture_nsx_state.py first, or pass --groups-dir for raw exports."
            )
        return groups_dir, label

    if args.source:
        host = resolve_manager(args.source)
        if not host:
            raise SystemExit(f"Source manager not defined: {args.source}")
        capture = (REPO_ROOT / "nsx_capture" / host).resolve()
        if not capture.exists():
            raise SystemExit(f"No capture bundle at {capture}. Run capture_nsx_state.py first.")
        label = args.label or host
        groups_dir = capture / "groups_additive" / "domains" / args.domain_id / "groups"
        if not groups_dir.exists():
            raise SystemExit(
                f"groups_additive directory not found: {groups_dir}\n"
                "Run capture_nsx_state.py first."
            )
        return groups_dir, label

    raise SystemExit("Provide one of --source <alias>, --capture <path>, or --groups-dir <path>.")


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(
        description=("Offline transform: decompose tagged groups (with captured "
                     "IPs) into IP-only sibling groups. "
                     "Read-only against NSX.")
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--source", choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
                     help="NSX manager alias whose CAPTURE bundle to read. Reads from "
                          "nsx_capture/<host>/groups_additive/... (captured-VM-IPs view).")
    src.add_argument("--capture", default=None,
                     help="Explicit path to a capture bundle (groups_additive layout).")
    src.add_argument("--groups-dir", default=None,
                     help="Explicit path to any directory of group YAMLs (e.g. "
                          "nsx_groups_export/nsx-lm2.lab.local/groups). Use this to "
                          "drive the transform from a TARGET's live exported state "
                          "rather than the source's capture — useful when you want "
                          "siblings reflecting the target's current IPs (including "
                          "any drift since WF-A Part 3).")
    p.add_argument("--label", default=None,
                   help="Override the output-bundle subdirectory name (defaults to the "
                        "source-host or, with --groups-dir, the auto-derived "
                        "hostname-shaped parent dir).")
    p.add_argument("--domain-id", default="default", help="NSX domain id (default: default).")
    p.add_argument("--appendix", default=None,
                   help=f"Suffix appended to original group ID/display_name to form the "
                        f"sibling. Defaults to OBJECT_APPENDIX from .env "
                        f"(currently {ENV_APPENDIX!r}).")
    p.add_argument("--output-base", default=None,
                   help="Output root. Default: repo root (so "
                        "nsx_sibling_groups/<host>/ "
                        "land beside the existing bundles).")
    p.add_argument("--include-empty", action="store_true",
                   help="Also emit siblings for tagged groups whose captured IPs "
                        "list is empty. Off by default (skipped — useless).")
    # ---- WF-D flags (default off so WF-C behavior is unchanged) ----
    p.add_argument("--csv-remap", default=None,
                   help="Path to a 2-col CSV (old,new) of IP/subnet mappings. "
                        "When set, each sibling's IPAddressExpression carries the "
                        "MAPPED equivalents of the source IPs only (source IPs "
                        "stay only on the original group, which on WF-D's prod "
                        "path is left completely untouched). Use with WF-D.")
    p.add_argument("--include-pure-ip", action="store_true",
                   help="Relax the Condition-required gate without a CSV map, so "
                        "groups with no tag Condition also produce siblings. With "
                        "--csv-remap (WF-D) that gate is already off: every group "
                        "that is not segment-based and has at least one mapped IP "
                        "gets a sibling.")
    p.add_argument("--skip-segment-groups", action="store_true",
                   help="Skip a segment-based group: one with a PathExpression member "
                        "that is not another group (a segment, segment port, VIF...). "
                        "A group that only nests other groups by path is decomposed "
                        "normally. WF-D's default. Skipped groups are recorded in "
                        "reports/skipped_segments.json and in sibling_map.json.")
    p.add_argument("--skip-uncovered", action="store_true",
                   help="When --csv-remap is provided, skip a group entirely if ANY "
                        "of its source IPs has no CSV mapping. Default: emit a "
                        "partial sibling (only the mapped IPs) and surface the "
                        "uncovered IPs in sibling_map.json for audit.")
    args = p.parse_args()

    init_cli()

    appendix = args.appendix or ENV_APPENDIX
    if not appendix:
        raise SystemExit(
            "No appendix available: pass --appendix or set OBJECT_APPENDIX in .env."
        )

    groups_in, label = _resolve_input(args)

    # Load CSV mapping early so a missing/bad CSV fails before we touch disk.
    csv_mapping = None
    csv_path_resolved: Optional[str] = None
    if args.csv_remap:
        # Imported lazily so the optional dependency doesn't penalize the
        # common WF-C path that doesn't use --csv-remap.
        from nsx_group_ip_remap_offline import _load_mapping_csv  # type: ignore
        csv_path = Path(args.csv_remap).expanduser().resolve()
        if not csv_path.exists():
            raise SystemExit(f"--csv-remap file not found: {csv_path}")
        csv_mapping, csv_invalid = _load_mapping_csv(csv_path, bidirectional=False)
        if csv_invalid:
            log.warning("CSV had %d invalid row(s) — they were skipped. See report below.",
                        len(csv_invalid))
        csv_path_resolved = str(csv_path)

    output_base = Path(args.output_base).expanduser().resolve() if args.output_base else REPO_ROOT
    sibling_root      = output_base / "nsx_sibling_groups"  / label
    # Carry the label forward so log/manifest reads use it consistently.
    source_host = label

    # Clear the previous build (it is regenerable), but keep push_report/: the
    # push that consumes this bundle stores its revert baselines there, and a
    # rebuild on the next dry run must never cost an earlier apply its rollback.
    # Any nsx_stripped_groups/ dir from before this tool stopped emitting one
    # is removed too, so a stale bundle can never be mistaken for fresh output.
    # An nsx_pure_ip_remap/ dir from before WF-D gave IP-only groups siblings
    # is left alone: nothing reads it any more, but it may hold the revert
    # baseline of an old D2b apply.
    legacy_stripped_root = output_base / "nsx_stripped_groups" / label
    if legacy_stripped_root.exists():
        shutil.rmtree(legacy_stripped_root)
    _clear_build_output(sibling_root)
    (sibling_root / "groups").mkdir(parents=True, exist_ok=True)

    sibling_groups_dir      = sibling_root      / "groups"
    reports_dir = sibling_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    _setup_logging(reports_dir)

    log.info("=" * 60)
    log.info("BUILD SIBLING GROUPS")
    log.info("  Source host       : %s", source_host)
    log.info("  Groups input      : %s", groups_in)
    log.info("  Appendix          : %s", appendix)
    log.info("  Sibling bundle    : %s", sibling_root)
    log.info("  Include empty     : %s", args.include_empty)
    log.info("  Include pure-IP   : %s", args.include_pure_ip)
    log.info("  Skip segments     : %s", args.skip_segment_groups)
    log.info("  Skip uncovered    : %s", args.skip_uncovered)
    log.info("  CSV remap         : %s", csv_path_resolved or "(none)")
    log.info("=" * 60)

    rows: List[Dict[str, Any]] = []
    sibling_map: List[Dict[str, Any]] = []
    skipped_segments: List[Dict[str, Any]] = []
    empty_groups: List[Dict[str, Any]] = []
    skipped_uncovered: List[Dict[str, Any]] = []
    counted = {
        "files_seen": 0,
        "siblings_written": 0,
        "skipped_no_condition": 0,
        "skipped_empty_ips": 0,
        "skipped_segment_groups": 0,
        "skipped_uncovered_ips": 0,
        "skipped_no_mapped_ips": 0,
        "errors": 0,
        "total_ips_in_siblings": 0,
        "total_uncovered_ips":   0,
    }
    # Every group that got no sibling, with the reason, for the run report.
    no_sibling: List[Dict[str, Any]] = []

    for src_yaml in sorted(groups_in.glob("*.yaml")):
        counted["files_seen"] += 1
        try:
            orig = _load_yaml(src_yaml)
        except Exception as exc:
            counted["errors"] += 1
            log.exception("[%d] FAILED to read %s: %s", counted["files_seen"], src_yaml.name, exc)
            rows.append({"source_file": str(src_yaml), "status": "failed",
                         "error": str(exc), "error_type": type(exc).__name__})
            continue

        orig_id = orig.get("id")
        if not orig_id:
            counted["errors"] += 1
            log.warning("[%d] %s — no id in payload, skipping", counted["files_seen"], src_yaml.name)
            continue

        sibling, info = split_group(
            orig,
            appendix=appendix,
            include_empty=args.include_empty,
            csv_mapping=csv_mapping,
            include_pure_ip=args.include_pure_ip,
            skip_segment_groups=args.skip_segment_groups,
            skip_uncovered=args.skip_uncovered,
        )

        if sibling is None:
            reason = info.get("skip_reason")
            audit_payload = {
                "source_file":         str(src_yaml),
                "id":                  orig_id,
                "display_name":        orig.get("display_name"),
                "has_condition":       info["has_condition"],
                "has_path_expression": info["has_path_expression"],
                "ips_source":          info["ips_source"],
                "ips_uncovered":       info["ips_uncovered"],
            }
            # (counter, list to append to, reason as a reviewer reads it)
            known = {
                "segment_group": ("skipped_segment_groups", skipped_segments,
                                  "segment-based (skipped by design)"),
                "no_condition":  ("skipped_no_condition", None,
                                  "not tag-based (WF-C decomposes tag groups only)"),
                "empty_ips":     ("skipped_empty_ips", empty_groups,
                                  "no members (no IPs)"),
                "uncovered_ips": ("skipped_uncovered_ips", skipped_uncovered,
                                  "an IP has no CSV mapping (--skip-uncovered)"),
                "no_mapped_ips": ("skipped_no_mapped_ips", None,
                                  "no IP has a CSV mapping"),
            }
            if reason not in known:
                # Record it so nothing slips through silently.
                counted["errors"] += 1
                rows.append({**audit_payload, "status": "skipped",
                             "reason": f"unknown ({reason})"})
                log.warning("[%d] %s: skipped with unknown reason: %s",
                            counted["files_seen"], orig_id, reason)
                continue
            counter, bucket, why = known[reason]
            counted[counter] += 1
            if reason in ("uncovered_ips", "no_mapped_ips"):
                counted["total_uncovered_ips"] += len(info["ips_uncovered"])
            if bucket is not None:
                bucket.append(audit_payload)
            rows.append({**audit_payload, "status": "skipped", "reason": why})
            no_sibling.append({
                "original_id":           orig_id,
                "original_display_name": orig.get("display_name"),
                "reason_code":           reason,
                "reason":                why,
                "ips_source":            info["ips_source"],
                "ips_uncovered":         info["ips_uncovered"],
                "segment_paths":         info["segment_paths"],
            })
            log.info("[%d] %s: no sibling, %s", counted["files_seen"], orig_id, why)
            continue

        sibling_id = sibling["id"]
        sib_path = sibling_groups_dir / f"{short_id_filename(sibling_id)}.yaml"
        _write_yaml(sib_path, sibling)
        counted["siblings_written"] += 1
        counted["total_ips_in_siblings"] += len(info["ips_sibling"])
        if info["ips_uncovered"]:
            counted["total_uncovered_ips"] += len(info["ips_uncovered"])

        log.info("[%d] %s → sibling %s (+%d IPs)%s%s",
                 counted["files_seen"], orig_id, sibling_id, len(info["ips_sibling"]),
                 f"  •  source had {len(info['ips_source'])} IPs, mapped to {len(info['ips_sibling'])}"
                 if csv_mapping is not None and len(info['ips_source']) != len(info['ips_sibling']) else "",
                 f"  •  {len(info['ips_uncovered'])} uncovered" if info['ips_uncovered'] else "")

        rows.append({
            "source_file":         str(src_yaml),
            "id":                  orig_id,
            "sibling_id":          sibling_id,
            "sibling_file":        str(sib_path),
            "ip_count_source":     len(info["ips_source"]),
            "ip_count_sibling":    len(info["ips_sibling"]),
            "ips_source":          info["ips_source"],
            "ips_sibling_mapped":  info["ips_sibling"] if csv_mapping is not None else None,
            "ips_uncovered":       info["ips_uncovered"],
            "status":              "ok",
        })
        sibling_map.append({
            "original_id":           orig_id,
            "sibling_id":            sibling_id,
            "original_display_name": orig.get("display_name"),
            "sibling_display_name":  sibling["display_name"],
            "ip_count_source":       len(info["ips_source"]),
            "ip_count_sibling":      len(info["ips_sibling"]),
            "ips_source":            info["ips_source"],
            "ips_sibling_mapped":    info["ips_sibling"] if csv_mapping is not None else None,
            "ips_uncovered":         info["ips_uncovered"],
            # [[source_ip, [mapped...]], ...]: what each current address
            # became. Empty without a CSV map.
            "ip_pairs":              info["ip_pairs"],
        })

    # Write the machine-readable map for the rule-amend step.
    sibling_map_path = sibling_root / "sibling_map.json"
    sibling_map_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_host":  source_host,
        "domain_id":    args.domain_id,
        "appendix":     appendix,
        "csv_mapping":  csv_path_resolved,
        "count":        len(sibling_map),
        "map":          sibling_map,
        # Groups that got no sibling, and why. The amend step ignores this;
        # the run report lists it so a reviewer sees every group accounted for.
        "no_sibling":   no_sibling,
    }, indent=2, sort_keys=True), encoding="utf-8")

    # Audit reports — every skipped category gets its own file so CAB / ops
    # can grep / link directly without parsing the full manifest.
    (reports_dir / "skipped_segments.json").write_text(json.dumps({
        "count":         len(skipped_segments),
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "source_host":   source_host,
        "groups":        skipped_segments,
    }, indent=2, sort_keys=True), encoding="utf-8")
    (reports_dir / "empty_groups.json").write_text(json.dumps({
        "count":         len(empty_groups),
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "source_host":   source_host,
        "groups":        empty_groups,
    }, indent=2, sort_keys=True), encoding="utf-8")
    (reports_dir / "skipped_uncovered.json").write_text(json.dumps({
        "count":         len(skipped_uncovered),
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "source_host":   source_host,
        "groups":        skipped_uncovered,
    }, indent=2, sort_keys=True), encoding="utf-8")
    # Write a per-row manifest mirroring the existing tool style.
    manifest = {
        "command": "build_sibling_groups",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_host": source_host,
        "domain_id": args.domain_id,
        "appendix": appendix,
        "include_empty": args.include_empty,
        "include_pure_ip": args.include_pure_ip,
        "skip_segment_groups": args.skip_segment_groups,
        "skip_uncovered": args.skip_uncovered,
        "csv_remap": csv_path_resolved,
        "counts": counted,
        "rows": rows,
        "paths": {
            "sibling_bundle": str(sibling_root),
            "sibling_map": str(sibling_map_path),
            "skipped_segments_report": str(reports_dir / "skipped_segments.json"),
            "empty_groups_report":     str(reports_dir / "empty_groups.json"),
            "skipped_uncovered_report": str(reports_dir / "skipped_uncovered.json"),
        },
    }
    (sibling_root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True),
                                                encoding="utf-8")

    log.info("=" * 60)
    log.info("BUILD SIBLING GROUPS — complete")
    log.info("  files seen               : %d", counted["files_seen"])
    log.info("  siblings written         : %d  (total IPs in siblings: %d)",
             counted["siblings_written"], counted["total_ips_in_siblings"])
    log.info("  skipped: no Condition    : %d", counted["skipped_no_condition"])
    log.info("  skipped: empty IPs       : %d", counted["skipped_empty_ips"])
    log.info("  skipped: segment groups  : %d  (see reports/skipped_segments.json)", counted["skipped_segment_groups"])
    log.info("  empty groups (no IPs)    : %d  (see reports/empty_groups.json)", len(empty_groups))
    if csv_mapping is not None:
        log.info("  skipped: uncovered IPs   : %d  (see reports/skipped_uncovered.json)", counted["skipped_uncovered_ips"])
        log.info("  skipped: no mapped IPs   : %d", counted["skipped_no_mapped_ips"])
        log.info("  total uncovered IPs      : %d", counted["total_uncovered_ips"])
    log.info("  errors                   : %d", counted["errors"])
    log.info("  sibling_map.json         : %s", sibling_map_path)
    log.info("=" * 60)

    print(json.dumps({
        "sibling_bundle": str(sibling_root),
        "sibling_map": str(sibling_map_path),
        "counts": counted,
    }, indent=2))
    return 0 if counted["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
