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


def _collect_ips(expression: List[Any]) -> List[str]:
    """Flatten ip_addresses across every IPAddressExpression entry."""
    seen: set = set()
    out: List[str] = []
    for e in expression or []:
        if not _is_ip_expression(e):
            continue
        for ip in (e.get("ip_addresses") or []):
            if isinstance(ip, str) and ip not in seen:
                seen.add(ip)
                out.append(ip)
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


def split_group(orig_group: Dict[str, Any], appendix: str, include_empty: bool = False
                ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], List[str]]:
    """Decompose one group into (sibling_payload, stripped_original_payload, ips).

    Returns (None, None, []) when no decomposition applies — i.e. when the
    group has no Condition (so there's no tag to separate from) OR has no
    captured IPs (and --include-empty wasn't asked for).
    """
    orig_id = orig_group.get("id")
    if not orig_id:
        return None, None, []

    expression = orig_group.get("expression") or []
    if not isinstance(expression, list):
        return None, None, []

    has_condition = any(_is_tag_condition(e) for e in expression)
    ips = _collect_ips(expression)

    if not has_condition:
        return None, None, []          # pure-IP / pure-path groups — nothing to split
    if not ips and not include_empty:
        return None, None, []          # tagged but no captured IPs — sibling would be empty

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
                "ip_addresses": ips,
            }
        ],
    })

    # Stripped original: same payload sans IPAddressExpression entries (and orphan
    # ConjunctionOperators that were sandwiching them).
    new_expression = [e for e in expression if not _is_ip_expression(e)]
    new_expression = _strip_orphan_operators(new_expression)
    stripped = _sanitize({**orig_group, "expression": new_expression})

    return sibling, stripped, ips


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
    args = p.parse_args()

    init_cli()

    appendix = args.appendix or ENV_APPENDIX
    if not appendix:
        raise SystemExit(
            "No appendix available: pass --appendix or set OBJECT_APPENDIX in .env."
        )

    groups_in, label = _resolve_input(args)

    output_base = Path(args.output_base).expanduser().resolve() if args.output_base else REPO_ROOT
    sibling_root  = output_base / "nsx_sibling_groups"  / label
    stripped_root = output_base / "nsx_stripped_groups" / label
    # Carry the label forward so log/manifest reads use it consistently.
    source_host = label

    # Wipe previous run's output dirs (idempotent — they're regenerable).
    for d in (sibling_root, stripped_root):
        if d.exists():
            shutil.rmtree(d)
        (d / "groups").mkdir(parents=True, exist_ok=True)

    sibling_groups_dir  = sibling_root  / "groups"
    stripped_groups_dir = stripped_root / "groups"
    reports_dir = sibling_root / "reports"
    _setup_logging(reports_dir)

    log.info("=" * 60)
    log.info("BUILD SIBLING GROUPS")
    log.info("  Source host       : %s", source_host)
    log.info("  Groups input      : %s", groups_in)
    log.info("  Appendix          : %s", appendix)
    log.info("  Sibling bundle    : %s", sibling_root)
    log.info("  Stripped bundle   : %s", stripped_root)
    log.info("  Include empty     : %s", args.include_empty)
    log.info("=" * 60)

    rows: List[Dict[str, Any]] = []
    sibling_map: List[Dict[str, Any]] = []
    counted = {
        "files_seen": 0,
        "siblings_written": 0,
        "stripped_written": 0,
        "skipped_no_condition": 0,
        "skipped_empty_ips": 0,
        "errors": 0,
        "total_ips_in_siblings": 0,
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

        sibling, stripped, ips = split_group(orig, appendix=appendix, include_empty=args.include_empty)

        if sibling is None:
            # classify the skip reason for the report
            has_condition = any(_is_tag_condition(e) for e in (orig.get("expression") or []))
            if not has_condition:
                counted["skipped_no_condition"] += 1
                rows.append({"source_file": str(src_yaml), "id": orig_id,
                             "status": "skipped", "reason": "no Condition (not a tag-based group)"})
            else:
                counted["skipped_empty_ips"] += 1
                rows.append({"source_file": str(src_yaml), "id": orig_id,
                             "status": "skipped", "reason": "no captured IPs (and --include-empty not set)"})
            log.info("[%d] %s — skipped (%s)", counted["files_seen"], orig_id, rows[-1]["reason"])
            continue

        sibling_id = sibling["id"]
        sib_path = sibling_groups_dir  / f"{short_id_filename(sibling_id)}.yaml"
        str_path = stripped_groups_dir / f"{short_id_filename(orig_id)}.yaml"
        _write_yaml(sib_path, sibling)
        _write_yaml(str_path, stripped)
        counted["siblings_written"] += 1
        counted["stripped_written"] += 1
        counted["total_ips_in_siblings"] += len(ips)

        log.info("[%d] %s → sibling %s (+%d IPs)  •  stripped original written",
                 counted["files_seen"], orig_id, sibling_id, len(ips))
        rows.append({
            "source_file": str(src_yaml),
            "id": orig_id,
            "sibling_id": sibling_id,
            "sibling_file": str(sib_path),
            "stripped_file": str(str_path),
            "ip_count": len(ips),
            "ips": ips,
            "status": "ok",
        })
        sibling_map.append({
            "original_id": orig_id,
            "sibling_id":  sibling_id,
            "original_display_name": orig.get("display_name"),
            "sibling_display_name":  sibling["display_name"],
            "ip_count": len(ips),
        })

    # Write the machine-readable map for the rule-amend step.
    sibling_map_path = sibling_root / "sibling_map.json"
    sibling_map_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_host":  source_host,
        "domain_id":    args.domain_id,
        "appendix":     appendix,
        "count":        len(sibling_map),
        "map":          sibling_map,
    }, indent=2, sort_keys=True), encoding="utf-8")

    # Write a per-row manifest mirroring the existing tool style.
    manifest = {
        "command": "build_sibling_groups",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_host": source_host,
        "domain_id": args.domain_id,
        "appendix": appendix,
        "include_empty": args.include_empty,
        "counts": counted,
        "rows": rows,
        "paths": {
            "sibling_bundle": str(sibling_root),
            "stripped_bundle": str(stripped_root),
            "sibling_map": str(sibling_map_path),
        },
    }
    (sibling_root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True),
                                                encoding="utf-8")
    (stripped_root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True),
                                                 encoding="utf-8")

    log.info("=" * 60)
    log.info("BUILD SIBLING GROUPS — complete")
    log.info("  files seen             : %d", counted["files_seen"])
    log.info("  siblings written       : %d  (total IPs: %d)",
             counted["siblings_written"], counted["total_ips_in_siblings"])
    log.info("  stripped originals     : %d", counted["stripped_written"])
    log.info("  skipped: no Condition  : %d", counted["skipped_no_condition"])
    log.info("  skipped: empty IPs     : %d", counted["skipped_empty_ips"])
    log.info("  errors                 : %d", counted["errors"])
    log.info("  sibling_map.json       : %s", sibling_map_path)
    log.info("=" * 60)

    print(json.dumps({
        "sibling_bundle": str(sibling_root),
        "stripped_bundle": str(stripped_root),
        "sibling_map": str(sibling_map_path),
        "counts": counted,
    }, indent=2))
    return 0 if counted["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
