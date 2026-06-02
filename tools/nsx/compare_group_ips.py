#!/usr/bin/env python3
"""
tools/nsx/compare_group_ips.py

Detect IP-address drift between a REFERENCE group bundle (e.g. the
groups_additive YAMLs that Workflow A Part 3 pushed) and a TARGET manager's
CURRENT live state. Read-only: GETs from the target, writes a forensic
drift report under nsx_drift_report/<target-host>/.

The whole point is to answer the question:
    "Since we ran Workflow A on lm2, have any IPs been added to (or
    removed from) the groups by anything else (manual NSX UI edits, other
    tools, vCenter changes, etc.)?"

INPUTS (one of):
  --reference <path>           Path to a directory of group YAMLs to treat as
                               the "what should be" baseline. The most common
                               reference is the groups_additive bundle:
                                 nsx_capture/<src-host>/groups_additive/
                                 domains/<d>/groups/

  --reference-source <alias>   Convenience shorthand: derive the reference
                               from a capture bundle for that source.
                               (Resolves to the path above.)

TARGET (one of):
  --target <alias>             Live GET groups from this NSX manager.
  --target-groups-dir <path>   Or read the target's state from a previously
                               exported bundle on disk (e.g.
                                 nsx_groups_export/<target-host>/groups/).
                               Skips the NSX call.

OUTPUT:
  nsx_drift_report/<target-host>/
    drift_report.json           per-group rows + summary
    drift_report.jsonl          one row per line (greppable)
    drift_summary.json          totals only
    logs/

Each row records:
    group_id, display_name
    reference_ips      (sorted union of IPAddressExpression entries in ref)
    current_ips        (same from target)
    ips_added          (on target but not in reference  →  drift IN)
    ips_removed        (in reference but not on target  →  drift OUT)
    only_in_reference  (group exists in reference but not on target)
    only_on_target     (group exists on target but not in reference)
    has_drift          bool

Read-only against NSX. Never PATCH/PUT/DELETE.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.cli_bootstrap import init_cli            # noqa: E402
from nsx.nsx_constants import resolve_manager, nsx_log_dir   # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient            # noqa: E402

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]


# =============================================================================
# Helpers
# =============================================================================

def _setup_logging(reports_dir: Path) -> Path:
    log_dir = Path(nsx_log_dir).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    bundle_log = (reports_dir / f"compare_group_ips_{RUN_TS}.log").resolve()
    global_log = (log_dir / f"compare_group_ips_{RUN_TS}.log").resolve()
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


def _extract_ip_entries(group: Dict[str, Any]) -> List[str]:
    """Sorted unique IPs across every IPAddressExpression in the group."""
    out: Set[str] = set()
    if not isinstance(group, dict):
        return []
    for e in (group.get("expression") or []):
        if isinstance(e, dict) and e.get("resource_type") == "IPAddressExpression":
            for ip in (e.get("ip_addresses") or []):
                if isinstance(ip, str):
                    out.add(ip)
    return sorted(out)


def _is_system_object(g: Dict[str, Any]) -> bool:
    return bool(g.get("_system_owned") or g.get("system_owned") or g.get("marked_for_delete"))


# =============================================================================
# Reference / target loaders
# =============================================================================

def _load_groups_from_dir(d: Path) -> Dict[str, Dict[str, Any]]:
    """Read every *.yaml in d (non-recursive), keyed by group id."""
    out: Dict[str, Dict[str, Any]] = {}
    if not d.exists():
        raise SystemExit(f"Group directory does not exist: {d}")
    for f in sorted(d.glob("*.yaml")):
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            log.warning("Could not parse %s: %s — skipping", f.name, exc)
            continue
        gid = data.get("id")
        if gid and not _is_system_object(data):
            out[gid] = data
    return out


def _live_fetch_groups(client: NsxPolicyClient, domain_id: str) -> Dict[str, Dict[str, Any]]:
    """GET all customer groups from the target manager."""
    out: Dict[str, Dict[str, Any]] = {}
    base = client._policy_path(f"/domains/{client._q(domain_id)}/groups")
    for page in client._get_pages(base):
        for g in (page.get("results") or []):
            if _is_system_object(g):
                continue
            gid = g.get("id")
            if gid:
                out[gid] = g
    return out


def _resolve_reference(args: argparse.Namespace) -> Path:
    if args.reference:
        p = Path(args.reference).expanduser().resolve()
        if not p.exists():
            raise SystemExit(f"--reference path does not exist: {p}")
        return p
    if args.reference_source:
        host = resolve_manager(args.reference_source)
        if not host:
            raise SystemExit(f"Reference manager not defined: {args.reference_source}")
        p = (REPO_ROOT / "nsx_capture" / host / "groups_additive"
                       / "domains" / args.domain_id / "groups").resolve()
        if not p.exists():
            raise SystemExit(
                f"No capture groups_additive at {p}. Run capture_nsx_state.py "
                f"--source {args.reference_source} first."
            )
        return p
    raise SystemExit("Provide one of --reference <path> or --reference-source <alias>.")


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(
        description=("Detect IP drift between a REFERENCE bundle of group YAMLs and "
                     "the CURRENT live state of a target manager. Read-only.")
    )
    ref = p.add_mutually_exclusive_group(required=True)
    ref.add_argument("--reference", default=None,
                     help="Path to a directory of group YAMLs treated as the baseline.")
    ref.add_argument("--reference-source", choices=NSX_MANAGER_CHOICES, default=None,
                     help="Convenience: derive the reference from "
                          "nsx_capture/<host>/groups_additive/domains/<d>/groups/.")
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--target", choices=NSX_MANAGER_CHOICES, default=None,
                     help="Live GET groups from this NSX manager.")
    tgt.add_argument("--target-groups-dir", default=None,
                     help="Or read the target's state from a previously exported "
                          "bundle on disk (e.g. nsx_groups_export/<host>/groups/).")
    p.add_argument("--domain-id", default="default", help="NSX domain (default: default).")
    p.add_argument("--federation-global", action="store_true",
                   help="Hit the GM API surface (federation-global=True).")
    p.add_argument("--output-base", default=None,
                   help="Output root; default: repo root → nsx_drift_report/<target-label>/")
    args = p.parse_args()

    init_cli()

    reference_dir = _resolve_reference(args)
    reference = _load_groups_from_dir(reference_dir)

    # Determine target label (used as the report dir name).
    if args.target:
        target_host = resolve_manager(args.target)
        if not target_host:
            raise SystemExit(f"Target manager not defined: {args.target}")
        target_label = target_host
        client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global)
        log.info("Fetching live groups from %s ...", target_host)
        current = _live_fetch_groups(client, args.domain_id)
        target_mode = "live_get"
        target_path_or_alias = f"alias:{args.target} ({target_host})"
    else:
        td = Path(args.target_groups_dir).expanduser().resolve()
        current = _load_groups_from_dir(td)
        # heuristic label: walk up looking for "hostname.something"
        target_label = td.parent.name if "." in td.parent.name else td.name
        target_mode = "from_disk"
        target_path_or_alias = str(td)

    output_base = Path(args.output_base).expanduser().resolve() if args.output_base else REPO_ROOT
    reports_dir = output_base / "nsx_drift_report" / target_label
    log_file = _setup_logging(reports_dir / "logs")

    log.info("=" * 60)
    log.info("GROUP-IP DRIFT DETECTION")
    log.info("  Reference         : %s  (%d groups)", reference_dir, len(reference))
    log.info("  Target            : %s  (%d groups)  [%s]",
             target_path_or_alias, len(current), target_mode)
    log.info("  Domain            : %s", args.domain_id)
    log.info("  Reports           : %s", reports_dir)
    log.info("=" * 60)

    rows: List[Dict[str, Any]] = []
    counters = {
        "reference_groups": len(reference),
        "target_groups":    len(current),
        "groups_compared":  0,
        "groups_with_drift":            0,
        "groups_only_in_reference":     0,
        "groups_only_on_target":        0,
        "total_ips_added_since_reference":   0,   # on target, not in reference
        "total_ips_removed_since_reference": 0,   # in reference, not on target
    }

    all_ids = sorted(set(reference.keys()) | set(current.keys()))
    for gid in all_ids:
        in_ref = gid in reference
        on_tgt = gid in current
        ref_ips = _extract_ip_entries(reference.get(gid, {})) if in_ref else []
        cur_ips = _extract_ip_entries(current.get(gid,    {})) if on_tgt else []

        ips_added   = sorted(set(cur_ips) - set(ref_ips))
        ips_removed = sorted(set(ref_ips) - set(cur_ips))
        has_drift = bool(ips_added or ips_removed or (in_ref ^ on_tgt))

        row = {
            "group_id":          gid,
            "display_name":      (current.get(gid, {}) if on_tgt else reference.get(gid, {})).get("display_name"),
            "in_reference":      in_ref,
            "on_target":         on_tgt,
            "reference_ip_count": len(ref_ips),
            "current_ip_count":   len(cur_ips),
            "reference_ips":      ref_ips,
            "current_ips":        cur_ips,
            "ips_added":          ips_added,    # on target but not in reference
            "ips_removed":        ips_removed,  # in reference but not on target
            "has_drift":          has_drift,
        }
        rows.append(row)

        counters["groups_compared"] += 1
        if has_drift:
            counters["groups_with_drift"] += 1
        if in_ref and not on_tgt:
            counters["groups_only_in_reference"] += 1
        if on_tgt and not in_ref:
            counters["groups_only_on_target"] += 1
        counters["total_ips_added_since_reference"]   += len(ips_added)
        counters["total_ips_removed_since_reference"] += len(ips_removed)

        if has_drift:
            log.warning(
                "[DRIFT] %s — +%d / -%d IPs%s%s",
                gid, len(ips_added), len(ips_removed),
                "" if in_ref else "  (ONLY ON TARGET — group not in reference)",
                "" if on_tgt else "  (ONLY IN REFERENCE — group missing on target)",
            )
        else:
            log.debug("[match] %s — %d IPs identical", gid, len(ref_ips))

    summary = {
        "ran_at":            datetime.now(timezone.utc).isoformat(),
        "reference":         str(reference_dir),
        "target":            target_path_or_alias,
        "target_mode":       target_mode,
        "domain_id":         args.domain_id,
        "counters":          counters,
        "log_file":          str(log_file),
    }
    (reports_dir / "drift_report.json").write_text(
        json.dumps({"summary": summary, "rows": rows}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    with (reports_dir / "drift_report.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    (reports_dir / "drift_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8",
    )

    log.info("=" * 60)
    log.info("DRIFT SUMMARY")
    log.info("  groups in reference          : %d", counters["reference_groups"])
    log.info("  groups on target             : %d", counters["target_groups"])
    log.info("  groups compared              : %d", counters["groups_compared"])
    log.info("  groups WITH DRIFT            : %d", counters["groups_with_drift"])
    log.info("  groups only in reference     : %d", counters["groups_only_in_reference"])
    log.info("  groups only on target        : %d", counters["groups_only_on_target"])
    log.info("  IPs ADDED to target since ref: %d", counters["total_ips_added_since_reference"])
    log.info("  IPs REMOVED from target since: %d", counters["total_ips_removed_since_reference"])
    log.info("Report: %s", reports_dir)
    log.info("=" * 60)
    print(json.dumps(summary, indent=2))

    # Exit code: 0 = no drift, 1 = drift detected (handy for CI checks)
    return 0 if counters["groups_with_drift"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
