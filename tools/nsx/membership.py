#!/usr/bin/env python3
"""
tools/nsx/membership.py

Export VM ↔ group membership correlation from an NSX manager. Read-only.

Joins three pieces of data the toolkit already collects:
  - Group inventory   (/policy/api/v1/infra/domains/<d>/groups)
  - Per-group evaluated members (/policy/api/v1/.../groups/<id>/members/virtual-machines)
  - VM inventory + IPs (fabric /api/v1/fabric/virtual-machines + .../vifs)

Produces three correlation files so you can answer questions like:
  - "Which VMs are members of group X?"           → group_memberships.json
  - "Which groups does VM Y belong to?"           → vm_group_membership.json
  - "Which VM owns IP 10.6.0.50?"                 → vm_ip_index.json (grep)

Output (overwritten on each run if default path is used):

  nsx_membership_export/<source-host>/
    group_memberships.json    [ {group_id, display_name, members:[{vm_id,name,ips}], ip_count}, ... ]
    vm_group_membership.json  [ {vm_id, display_name, external_id, ips, groups:[group_id,...]}, ... ]
    vm_ip_index.json          { "<vm_id>": ["10.6.0.50", ...], ... }
    manifest.json
    logs/membership_export_<UTC_TS>.log
    logs/membership_export_<UTC_TS>.errors.log

Usage:

  python tools/nsx/membership.py export --source nsx-lm1
  python tools/nsx/membership.py export --source nsx-lm1 --output-dir custom/path
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.nsx_policy_client import NsxPolicyClient


log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
THROTTLE_SECONDS = 0.2

_SAFE_ID_RE = re.compile(r'^[A-Za-z0-9._\-]+$')
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]


def _has_special_chars(value: str) -> bool:
    return not bool(_SAFE_ID_RE.match(str(value or "")))


def _setup_logging(reports_dir: Path, label: str) -> tuple[Path, Path]:
    """Returns (bundle_log, errors_log)."""
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    bundle_log = (reports_dir / f"membership_{label}_{RUN_TS}.log").resolve()
    global_log = (global_log_dir / f"membership_{label}_{RUN_TS}.log").resolve()
    errors_log = (reports_dir / f"membership_{label}_{RUN_TS}.errors.log").resolve()

    logging.Formatter.converter = time.gmtime
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%S")
    for h in (logging.StreamHandler(),
              logging.FileHandler(bundle_log, encoding="utf-8"),
              logging.FileHandler(global_log, encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    eh = logging.FileHandler(errors_log, encoding="utf-8")
    eh.setLevel(logging.ERROR)
    eh.setFormatter(fmt)
    root.addHandler(eh)
    return bundle_log, errors_log


def _is_system_object(obj: Dict[str, Any]) -> bool:
    return (
        obj.get("_system_owned") is True
        or obj.get("system_owned") is True
        or obj.get("marked_for_delete") is True
    )


def _vm_external_id(vm: Dict[str, Any]) -> str:
    """The fabric VM's canonical id is 'external_id'."""
    return vm.get("external_id") or vm.get("id") or ""


def cmd_export(args: argparse.Namespace) -> int:
    source_host = resolve_manager(args.source)
    if not source_host:
        raise SystemExit(f"Manager not defined for {args.source}.")

    using_default = args.output_dir is None
    output_dir = Path(args.output_dir or (REPO_ROOT / "nsx_membership_export" / source_host)).expanduser().resolve()
    if using_default and output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logs_dir = output_dir / "logs"
    log_file, errors_log = _setup_logging(logs_dir, "export")

    log.info("=" * 60)
    log.info("NSX MEMBERSHIP — EXPORT")
    log.info("  Source manager  : %s (%s)", args.source, source_host)
    log.info("  Domain          : %s", args.domain_id)
    log.info("  Federation GM   : %s", args.federation_global)
    log.info("  Include system  : %s", args.include_system)
    log.info("  Output bundle   : %s", output_dir)
    log.info("=" * 60)

    client = NsxPolicyClient(nsxmanager=source_host, federation_global=args.federation_global)

    if args.federation_global:
        # build_vm_ip_index hits the fabric API which only exists on LMs.
        raise SystemExit(
            "Membership export requires a Local Manager (fabric VM/VIFs API). "
            "Run against an LM source — federation_global is GM-only."
        )

    # --- 1. Build VM IP index (fabric VMs + VIFs)  ---------------------------------
    log.info("Step 1/3: Building VM IP index from fabric VMs + VIFs ...")
    vm_ip_index: Dict[str, List[str]] = client.build_vm_ip_index()
    log.info("  Indexed IPs for %d VM(s)", len(vm_ip_index))

    # --- 2. Build VM metadata index (display_name, external_id, etc.) --------------
    log.info("Step 2/3: Fetching VM metadata inventory ...")
    raw_vms = list(client.list_virtual_machines())
    vm_meta: Dict[str, Dict[str, Any]] = {}
    for vm in raw_vms:
        vid = _vm_external_id(vm)
        if not vid:
            continue
        vm_meta[vid] = {
            "vm_id": vid,
            "display_name": vm.get("display_name"),
            "external_id": vm.get("external_id"),
            "power_state": vm.get("power_state"),
            "type": vm.get("type"),
            "host_id": vm.get("host_id"),
            "guest_computer_name": (vm.get("guest_info") or {}).get("computer_name"),
            "tags": vm.get("tags") or [],
        }
    log.info("  Indexed metadata for %d VM(s)", len(vm_meta))

    # --- 3. For each customer group, get its evaluated VM members -----------------
    log.info("Step 3/3: Listing groups + evaluating members ...")
    groups_path = client._policy_path(f"/domains/{client._q(args.domain_id)}/groups")
    all_groups: List[Dict[str, Any]] = []
    for page in client._get_pages(groups_path):
        all_groups.extend(page.get("results", []) or [])
    log.info("  Fetched %d group(s) total.", len(all_groups))

    group_rows: List[Dict[str, Any]] = []
    vm_to_groups: Dict[str, List[str]] = {}  # vm_id -> [group_id, ...]
    groups_processed = 0
    groups_skipped_system = 0
    groups_errors = 0

    for gi, g in enumerate(all_groups, start=1):
        gid = g.get("id")
        gname = g.get("display_name") or gid or "group"

        if not args.include_system and _is_system_object(g):
            groups_skipped_system += 1
            continue

        if not gid:
            log.warning("[%d/%d] group has no id, skipping", gi, len(all_groups))
            continue

        try:
            member_vm_ids = client.list_group_member_vm_ids(group_id=gid, domain_id=args.domain_id)
        except Exception as exc:
            groups_errors += 1
            tb = traceback.format_exc()
            log.error("[%d/%d] FAILED listing members of %s: %s\n%s",
                      gi, len(all_groups), gid, exc, tb)
            group_rows.append({
                "group_id": gid, "display_name": gname,
                "status": "failed", "error": str(exc),
                "error_type": type(exc).__name__, "traceback": tb,
            })
            continue

        members: List[Dict[str, Any]] = []
        for vm_id in member_vm_ids:
            meta = vm_meta.get(vm_id, {})
            members.append({
                "vm_id": vm_id,
                "display_name": meta.get("display_name"),
                "external_id": meta.get("external_id"),
                "guest_computer_name": meta.get("guest_computer_name"),
                "power_state": meta.get("power_state"),
                "ips": vm_ip_index.get(vm_id, []),
            })
            vm_to_groups.setdefault(vm_id, []).append(gid)

        total_member_ips = sum(len(m["ips"]) for m in members)
        group_rows.append({
            "group_id": gid,
            "display_name": gname,
            "status": "ok",
            "vm_count": len(members),
            "total_ip_count": total_member_ips,
            "members": members,
        })
        groups_processed += 1
        log.info("[%d/%d  ok=%d sys-skip=%d err=%d] %s — %d member VM(s), %d IP(s)",
                 gi, len(all_groups), groups_processed, groups_skipped_system, groups_errors,
                 gid, len(members), total_member_ips)
        time.sleep(THROTTLE_SECONDS)

    # --- Assemble vm_group_membership.json (flipped view) ---------------------------
    vm_membership_rows: List[Dict[str, Any]] = []
    for vm_id, meta in vm_meta.items():
        vm_membership_rows.append({
            **meta,
            "ips": vm_ip_index.get(vm_id, []),
            "groups": sorted(vm_to_groups.get(vm_id, [])),
        })
    # Stable ordering: by display_name (case-insensitive), then vm_id
    vm_membership_rows.sort(key=lambda v: ((v.get("display_name") or "").lower(), v.get("vm_id") or ""))

    # --- Write outputs ---------------------------------------------------------------
    (output_dir / "group_memberships.json").write_text(
        json.dumps(group_rows, indent=2, sort_keys=True), encoding="utf-8",
    )
    (output_dir / "vm_group_membership.json").write_text(
        json.dumps(vm_membership_rows, indent=2, sort_keys=True), encoding="utf-8",
    )
    (output_dir / "vm_ip_index.json").write_text(
        json.dumps(vm_ip_index, indent=2, sort_keys=True), encoding="utf-8",
    )

    manifest = {
        "command": "membership.export",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source": {"alias": args.source, "host": source_host,
                   "federation_global": args.federation_global, "domain_id": args.domain_id},
        "counts": {
            "groups_total": len(all_groups),
            "groups_processed": groups_processed,
            "groups_skipped_system_owned": groups_skipped_system,
            "groups_errors": groups_errors,
            "vms_indexed_for_ips": len(vm_ip_index),
            "vms_with_metadata": len(vm_meta),
            "vms_in_at_least_one_group": len(vm_to_groups),
        },
        "paths": {
            "bundle_dir": str(output_dir),
            "group_memberships_file": str(output_dir / "group_memberships.json"),
            "vm_group_membership_file": str(output_dir / "vm_group_membership.json"),
            "vm_ip_index_file": str(output_dir / "vm_ip_index.json"),
            "logs_dir": str(logs_dir),
        },
        "log_file": str(log_file),
        "errors_log": str(errors_log),
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    log.info("=" * 60)
    log.info("Membership export complete:")
    log.info("  groups processed       : %d", groups_processed)
    log.info("  groups system-skipped  : %d", groups_skipped_system)
    log.info("  groups errors          : %d", groups_errors)
    log.info("  VMs with IPs           : %d", len(vm_ip_index))
    log.info("  VMs with metadata      : %d", len(vm_meta))
    log.info("  VMs in 1+ group        : %d", len(vm_to_groups))
    log.info("Bundle:   %s", output_dir)
    log.info("Manifest: %s", manifest_path)
    log.info("=" * 60)

    print(json.dumps({
        "bundle": str(output_dir),
        "manifest": str(manifest_path),
        "counts": manifest["counts"],
    }, indent=2))
    return 0 if groups_errors == 0 else 1


def main() -> int:
    p = argparse.ArgumentParser(
        description="Export NSX VM ↔ group membership correlation. Read-only.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pe = sub.add_parser("export", help="Build group_memberships.json + vm_group_membership.json + vm_ip_index.json. GET-only.")
    pe.add_argument("--source", required=True, choices=NSX_MANAGER_CHOICES,
                    help="NSX Local Manager to query (fabric APIs are LM-only).")
    pe.add_argument("--domain-id", default="default")
    pe.add_argument("--federation-global", action="store_true",
                    help="(Will refuse — fabric API is LM-only.)")
    pe.add_argument("--output-dir", default=None,
                    help="Defaults to nsx_membership_export/<source-host>/. Wiped on each run.")
    pe.add_argument("--include-system", action="store_true",
                    help="Also include system-owned groups (default: skip).")
    pe.set_defaults(func=cmd_export)

    args = p.parse_args()
    init_cli()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
