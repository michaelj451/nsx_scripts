#!/usr/bin/env python3
"""
tools/nsx/build_sibling_groups.py

Offline transform that decomposes "tag + IP" groups (from a capture bundle)
into two sibling artifacts:

  1. nsx_sibling_groups/<host>/groups/<gid><APPENDIX>.yaml
       New IP-only sibling group, named <original_id><OBJECT_APPENDIX>.
       Contains ONLY the captured IPAddressExpression — no Conditions, no
       PathExpressions, no tags.

  2. nsx_stripped_groups/<host>/groups/<gid>.yaml
       The original group, but with IPAddressExpression entries REMOVED.
       Conditions / PathExpressions / tags / display_name all untouched.

Plus a machine-readable map for downstream rule-amend step:
  3. nsx_sibling_groups/<host>/sibling_map.json
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
  --output-base <dir>  Root for the two output bundles. Default:
                       repo root (so outputs land at
                       nsx_sibling_groups/<host>/ and
                       nsx_stripped_groups/<host>/).
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
    NestedExpression at any depth. Used by --skip-segment-groups in WF-D
    to leave any segment-related group untouched."""
    for e in expression or []:
        if _is_path_expression(e):
            return True
        if _is_nested_expression(e) and _has_path_expression_anywhere(e.get("expressions")):
            return True
    return False


def _apply_csv_mapping(ips: List[str], csv_mapping: Any) -> Tuple[List[str], List[str]]:
    """Run each source IP through the CSV mapping table.

    Returns (mapped_ips, uncovered_ips). Order is preserved relative to the
    input list. Duplicates in the mapped output are deduped.
    """
    mapped: List[str] = []
    uncovered: List[str] = []
    seen: set = set()
    for ip in ips:
        mapped_list, _row = csv_mapping.map_token(ip)
        if not mapped_list:
            uncovered.append(ip)
            continue
        for m in mapped_list:
            if m not in seen:
                seen.add(m)
                mapped.append(m)
    return mapped, uncovered


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


def _strip_ip_expressions(expression: List[Any]) -> List[Any]:
    """Recursively remove IPAddressExpression entries at any depth. Empty
    NestedExpressions (those that contained only IPs) are dropped entirely
    so they don't leave a hollow shell behind. Orphan ConjunctionOperators
    inside surviving NestedExpressions are cleaned up locally."""
    out: List[Any] = []
    for e in expression or []:
        if _is_ip_expression(e):
            continue
        if _is_nested_expression(e):
            cleaned = _strip_orphan_operators(_strip_ip_expressions(e.get("expressions") or []))
            if not cleaned:
                continue  # nested expression went empty — drop it
            new_e = dict(e)
            new_e["expressions"] = cleaned
            out.append(new_e)
            continue
        out.append(e)
    return out


def _strip_orphan_operators(expression: List[Any]) -> List[Any]:
    """Drop leading/trailing/back-to-back ConjunctionOperators that became
    orphans after stripping IPAddressExpression neighbors."""
    out: List[Any] = []
    prev_was_op = True   # treat list-start as "after-operator" so leading op gets dropped
    for e in expression:
        is_op = isinstance(e, dict) and e.get("resource_type") == "ConjunctionOperator"
        if is_op and prev_was_op:
            continue
        out.append(e)
        prev_was_op = is_op
    while out and isinstance(out[-1], dict) and out[-1].get("resource_type") == "ConjunctionOperator":
        out.pop()
    return out


def split_group(
    orig_group: Dict[str, Any],
    appendix: str,
    include_empty: bool = False,
    csv_mapping: Any = None,
    include_pure_ip: bool = False,
    skip_segment_groups: bool = False,
    skip_uncovered: bool = False,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
    """Decompose one group into (sibling_payload, stripped_original_payload, info).

    `info` is always a dict with these keys:
        source_id            : the original group id
        ips_source           : list of IPs collected from the source group
        ips_sibling          : list of IPs that end up in the sibling
                               (== ips_source when csv_mapping is None,
                                else the CSV-mapped equivalents only)
        ips_uncovered        : source IPs without a CSV mapping
                               (empty when csv_mapping is None or all mapped)
        has_condition        : did the source have a Condition anywhere?
        has_path_expression  : did the source have a PathExpression anywhere?
        has_nested_expression: did the source have a NestedExpression anywhere?
        skip_reason          : None if decomposed; otherwise one of
                               "no_condition" | "empty_ips" | "segment_group"
                               | "uncovered_ips" | "no_mapped_ips"

    Returns (None, None, info) when no decomposition applies.

    Behavior switches:
      include_empty        : emit siblings for tagged groups with empty IPs.
      csv_mapping          : when provided (a PrefixMappingTable), the
                             sibling's IPAddressExpression carries the MAPPED
                             IPs only. Source IPs are NOT included in the
                             sibling. Audit detail is recorded in info.
      include_pure_ip      : relax the no-Condition gate; pure-IP groups
                             (and other gate-1 skips except segment-skip)
                             produce siblings too.
      skip_segment_groups  : skip the group entirely if ANY PathExpression
                             exists at any depth. WF-D's safety stance for
                             never touching segment-related groups.
      skip_uncovered       : when csv_mapping is provided, skip the group
                             entirely if any source IP lacks a mapping.
    """
    orig_id = orig_group.get("id")
    info: Dict[str, Any] = {
        "source_id": orig_id,
        "ips_source": [],
        "ips_sibling": [],
        "ips_uncovered": [],
        "has_condition": False,
        "has_path_expression": False,
        "has_nested_expression": False,
        "skip_reason": None,
    }
    if not orig_id:
        info["skip_reason"] = "no_id"
        return None, None, info

    expression = orig_group.get("expression") or []
    if not isinstance(expression, list):
        info["skip_reason"] = "no_id"
        return None, None, info

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

    # Gate 0 (WF-D): skip any group with a PathExpression at any depth.
    if skip_segment_groups and has_path:
        info["skip_reason"] = "segment_group"
        return None, None, info

    # Gate 1: must have a Condition somewhere — unless --include-pure-ip
    # relaxes this so pure-IP groups can produce siblings too.
    if not has_condition and not include_pure_ip:
        info["skip_reason"] = "no_condition"
        return None, None, info

    # Gate 2: must have at least one IP — unless --include-empty relaxes it.
    if not src_ips and not include_empty:
        info["skip_reason"] = "empty_ips"
        return None, None, info

    # CSV mapping (optional) — sibling carries only the mapped equivalents.
    if csv_mapping is not None:
        mapped_ips, uncovered = _apply_csv_mapping(src_ips, csv_mapping)
        info["ips_uncovered"] = uncovered
        if skip_uncovered and uncovered:
            info["skip_reason"] = "uncovered_ips"
            return None, None, info
        if not mapped_ips:
            info["skip_reason"] = "no_mapped_ips"
            return None, None, info
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

    # Stripped original: same payload sans IPAddressExpression entries at any
    # depth (NestedExpression bodies are also descended into and cleaned).
    # Orphan ConjunctionOperators left after IP removal are dropped.
    new_expression = _strip_ip_expressions(expression)
    new_expression = _strip_orphan_operators(new_expression)
    stripped = _sanitize({**orig_group, "expression": new_expression})

    return sibling, stripped, info


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
                     "IPs) into IP-only sibling groups + stripped originals. "
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
                        "nsx_sibling_groups/<host>/ and nsx_stripped_groups/<host>/ "
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
                   help="Relax the Condition-required gate so pure-IP groups "
                        "(IPAddressExpression only, no Condition) also produce "
                        "siblings. Required by WF-D's 'decompose pure-IP groups too' "
                        "policy. Has no effect under WF-C semantics.")
    p.add_argument("--skip-segment-groups", action="store_true",
                   help="Skip any group that has a PathExpression anywhere in its "
                        "expression (top-level or nested). WF-D's safety default "
                        "for never touching segment-related groups on a live prod "
                        "target. Skipped groups are recorded in reports/skipped_segments.json.")
    p.add_argument("--no-stripped-originals", action="store_true",
                   help="Do NOT write the nsx_stripped_groups/<host>/ bundle. "
                        "WF-D uses this — the prod path never pushes the strip step, "
                        "so producing the bundle is wasted work + extra cleanup. "
                        "WF-C should NOT use this (it needs the stripped originals "
                        "for step 4).")
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
    sibling_root  = output_base / "nsx_sibling_groups"  / label
    stripped_root = output_base / "nsx_stripped_groups" / label
    # Carry the label forward so log/manifest reads use it consistently.
    source_host = label

    # Wipe previous run's output dirs (idempotent — they're regenerable).
    # When --no-stripped-originals is set, we still wipe the stripped dir so
    # an old WF-C bundle doesn't get accidentally pushed during a WF-D run.
    dirs_to_prepare = [sibling_root]
    if not args.no_stripped_originals:
        dirs_to_prepare.append(stripped_root)
    for d in dirs_to_prepare:
        if d.exists():
            shutil.rmtree(d)
        (d / "groups").mkdir(parents=True, exist_ok=True)
    # If WF-D suppressed the stripped bundle, also wipe any stale dir on disk
    # so a previous run's artifact isn't mistaken for fresh output.
    if args.no_stripped_originals and stripped_root.exists():
        shutil.rmtree(stripped_root)

    sibling_groups_dir  = sibling_root  / "groups"
    stripped_groups_dir = stripped_root / "groups"
    reports_dir = sibling_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    _setup_logging(reports_dir)

    log.info("=" * 60)
    log.info("BUILD SIBLING GROUPS")
    log.info("  Source host       : %s", source_host)
    log.info("  Groups input      : %s", groups_in)
    log.info("  Appendix          : %s", appendix)
    log.info("  Sibling bundle    : %s", sibling_root)
    if args.no_stripped_originals:
        log.info("  Stripped bundle   : (suppressed by --no-stripped-originals)")
    else:
        log.info("  Stripped bundle   : %s", stripped_root)
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
        "stripped_written": 0,
        "skipped_no_condition": 0,
        "skipped_empty_ips": 0,
        "skipped_segment_groups": 0,
        "skipped_uncovered_ips": 0,
        "skipped_no_mapped_ips": 0,
        "errors": 0,
        "total_ips_in_siblings": 0,
        "total_uncovered_ips":   0,
    }

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

        sibling, stripped, info = split_group(
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
            if reason == "segment_group":
                counted["skipped_segment_groups"] += 1
                rows.append({**audit_payload, "status": "skipped",
                             "reason": "has PathExpression (--skip-segment-groups)"})
                skipped_segments.append(audit_payload)
                log.info("[%d] %s — skipped: segment group (PathExpression present)",
                         counted["files_seen"], orig_id)
            elif reason == "no_condition":
                counted["skipped_no_condition"] += 1
                rows.append({**audit_payload, "status": "skipped",
                             "reason": "no Condition (not a tag-based group)"})
                if not info["ips_source"]:
                    empty_groups.append(audit_payload)
                log.info("[%d] %s — skipped (no Condition (not a tag-based group))",
                         counted["files_seen"], orig_id)
            elif reason == "empty_ips":
                counted["skipped_empty_ips"] += 1
                rows.append({**audit_payload, "status": "skipped",
                             "reason": "no captured IPs (and --include-empty not set)"})
                empty_groups.append(audit_payload)
                log.info("[%d] %s — skipped (no captured IPs)",
                         counted["files_seen"], orig_id)
            elif reason == "uncovered_ips":
                counted["skipped_uncovered_ips"] += 1
                rows.append({**audit_payload, "status": "skipped",
                             "reason": "at least one source IP has no CSV mapping (--skip-uncovered)"})
                skipped_uncovered.append(audit_payload)
                counted["total_uncovered_ips"] += len(info["ips_uncovered"])
                log.info("[%d] %s — skipped: %d uncovered IP(s) (--skip-uncovered)",
                         counted["files_seen"], orig_id, len(info["ips_uncovered"]))
            elif reason == "no_mapped_ips":
                counted["skipped_no_mapped_ips"] += 1
                rows.append({**audit_payload, "status": "skipped",
                             "reason": "no source IPs had a CSV mapping"})
                counted["total_uncovered_ips"] += len(info["ips_uncovered"])
                log.info("[%d] %s — skipped: none of %d source IPs had a CSV mapping",
                         counted["files_seen"], orig_id, len(info["ips_source"]))
            else:
                # Fallback (shouldn't happen — but record so nothing slips through silently)
                counted["errors"] += 1
                rows.append({**audit_payload, "status": "skipped",
                             "reason": f"unknown ({reason})"})
                log.warning("[%d] %s — skipped with unknown reason: %s",
                            counted["files_seen"], orig_id, reason)
            continue

        sibling_id = sibling["id"]
        sib_path = sibling_groups_dir / f"{short_id_filename(sibling_id)}.yaml"
        _write_yaml(sib_path, sibling)
        counted["siblings_written"] += 1
        counted["total_ips_in_siblings"] += len(info["ips_sibling"])
        if info["ips_uncovered"]:
            counted["total_uncovered_ips"] += len(info["ips_uncovered"])

        str_path: Optional[Path] = None
        if not args.no_stripped_originals:
            str_path = stripped_groups_dir / f"{short_id_filename(orig_id)}.yaml"
            _write_yaml(str_path, stripped)
            counted["stripped_written"] += 1

        log.info("[%d] %s → sibling %s (+%d IPs)%s%s%s",
                 counted["files_seen"], orig_id, sibling_id, len(info["ips_sibling"]),
                 f"  •  stripped original written" if str_path else "",
                 f"  •  source had {len(info['ips_source'])} IPs, mapped to {len(info['ips_sibling'])}"
                 if csv_mapping is not None and len(info['ips_source']) != len(info['ips_sibling']) else "",
                 f"  •  {len(info['ips_uncovered'])} uncovered" if info['ips_uncovered'] else "")

        rows.append({
            "source_file":         str(src_yaml),
            "id":                  orig_id,
            "sibling_id":          sibling_id,
            "sibling_file":        str(sib_path),
            "stripped_file":       str(str_path) if str_path else None,
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
        "no_stripped_originals": args.no_stripped_originals,
        "csv_remap": csv_path_resolved,
        "counts": counted,
        "rows": rows,
        "paths": {
            "sibling_bundle": str(sibling_root),
            "stripped_bundle": str(stripped_root) if not args.no_stripped_originals else None,
            "sibling_map": str(sibling_map_path),
            "skipped_segments_report": str(reports_dir / "skipped_segments.json"),
            "empty_groups_report":     str(reports_dir / "empty_groups.json"),
            "skipped_uncovered_report": str(reports_dir / "skipped_uncovered.json"),
        },
    }
    (sibling_root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True),
                                                encoding="utf-8")
    if not args.no_stripped_originals:
        (stripped_root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True),
                                                     encoding="utf-8")

    log.info("=" * 60)
    log.info("BUILD SIBLING GROUPS — complete")
    log.info("  files seen               : %d", counted["files_seen"])
    log.info("  siblings written         : %d  (total IPs in siblings: %d)",
             counted["siblings_written"], counted["total_ips_in_siblings"])
    if args.no_stripped_originals:
        log.info("  stripped originals       : (suppressed by --no-stripped-originals)")
    else:
        log.info("  stripped originals       : %d", counted["stripped_written"])
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
        "stripped_bundle": str(stripped_root) if not args.no_stripped_originals else None,
        "sibling_map": str(sibling_map_path),
        "counts": counted,
    }, indent=2))
    return 0 if counted["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
