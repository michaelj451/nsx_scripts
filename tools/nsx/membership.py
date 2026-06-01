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

# Default per-group throttle (overridable via --throttle-seconds).
# 0.2s = ~5 req/s, fine for the lab. Customer environments with thousands
# of groups + a tight NSX rate limit usually want 0.5-1.0s.
DEFAULT_THROTTLE_SECONDS = 0.2
# Default retry/backoff behaviour for 429 / 503 / 504 / transient connection errors.
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_BASE = 2.0   # seconds; attempts wait 2, 4, 8 ... (capped)
DEFAULT_BACKOFF_CAP  = 60.0  # seconds; never sleep longer than this between retries

_SAFE_ID_RE = re.compile(r'^[A-Za-z0-9._\-]+$')
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]


def _has_special_chars(value: str) -> bool:
    return not bool(_SAFE_ID_RE.match(str(value or "")))


def _is_rate_limit_or_transient(exc: Exception) -> bool:
    """Recognise errors NSX returns when it wants us to back off:
      - HTTP 429 (Too Many Requests)
      - HTTP 503 / 504 (Service Unavailable / Gateway Timeout — usually transient)
      - HTTP 502 (Bad Gateway — frontend hiccup)
      - Lower-level connection errors (timeouts, reset)
    Returns False for everything else (auth errors, 4xx body issues, etc.)
    """
    msg = str(exc)
    lower = msg.lower()
    if "[http 429]" in lower or " 429 " in msg or "too many requests" in lower:
        return True
    if "[http 503]" in lower or " 503 " in msg or "service unavailable" in lower:
        return True
    if "[http 504]" in lower or " 504 " in msg or "gateway timeout" in lower:
        return True
    if "[http 502]" in lower or " 502 " in msg or "bad gateway" in lower:
        return True
    # requests / urllib3 transport errors that we should retry rather than fail on
    name = type(exc).__name__.lower()
    if "timeout" in name or "connectionerror" in name or "remotedisconnected" in name:
        return True
    if "connection reset" in lower or "broken pipe" in lower or "read timed out" in lower:
        return True
    return False


def _call_with_backoff(fn, *, label: str, max_retries: int, backoff_base: float,
                       backoff_cap: float, retry_stats: Dict[str, int],
                       **kwargs):
    """Invoke `fn(**kwargs)` with exponential backoff on rate-limit / transient
    errors. Other errors surface immediately. `retry_stats` is mutated with
    counters so the caller can report what NSX pushed back on.
    """
    attempt = 0
    while True:
        try:
            return fn(**kwargs)
        except Exception as exc:
            if not _is_rate_limit_or_transient(exc) or attempt >= max_retries:
                raise
            attempt += 1
            wait = min(backoff_base * (2 ** (attempt - 1)), backoff_cap)
            retry_stats["retries_attempted"] = retry_stats.get("retries_attempted", 0) + 1
            retry_stats["total_backoff_seconds"] = retry_stats.get("total_backoff_seconds", 0.0) + wait
            log.warning("RATE-LIMIT/TRANSIENT on %s (attempt %d/%d): %s — sleeping %.1fs then retrying.",
                        label, attempt, max_retries, type(exc).__name__, wait)
            time.sleep(wait)


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

    # Retry/backoff bookkeeping — initialised here so the bulk calls below
    # (build_vm_ip_index, list_virtual_machines) are also covered.
    retry_stats: Dict[str, Any] = {
        "retries_attempted": 0,
        "total_backoff_seconds": 0.0,
        "max_retries": int(args.max_retries),
        "backoff_base": float(args.backoff_base),
        "throttle_seconds": float(args.throttle_seconds),
    }
    log.info("Throttle: %.2fs between groups  •  max_retries=%d  •  backoff_base=%.1fs (capped %.1fs)",
             args.throttle_seconds, args.max_retries, args.backoff_base, DEFAULT_BACKOFF_CAP)

    # --- 1. Build VM IP index (fabric VMs + VIFs)  ---------------------------------
    log.info("Step 1/3: Building VM IP index from fabric VMs + VIFs ...")
    vm_ip_index: Dict[str, List[str]] = _call_with_backoff(
        client.build_vm_ip_index,
        label="build_vm_ip_index",
        max_retries=args.max_retries, backoff_base=args.backoff_base,
        backoff_cap=DEFAULT_BACKOFF_CAP, retry_stats=retry_stats,
    )
    log.info("  Indexed IPs for %d VM(s)", len(vm_ip_index))

    # --- 2. Build VM metadata index (display_name, external_id, etc.) --------------
    log.info("Step 2/3: Fetching VM metadata inventory ...")
    raw_vms = list(_call_with_backoff(
        client.list_virtual_machines,
        label="list_virtual_machines",
        max_retries=args.max_retries, backoff_base=args.backoff_base,
        backoff_cap=DEFAULT_BACKOFF_CAP, retry_stats=retry_stats,
    ))
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
            member_vm_ids = _call_with_backoff(
                client.list_group_member_vm_ids,
                label=f"list_group_members({gid})",
                max_retries=args.max_retries,
                backoff_base=args.backoff_base,
                backoff_cap=DEFAULT_BACKOFF_CAP,
                retry_stats=retry_stats,
                group_id=gid, domain_id=args.domain_id,
            )
        except Exception as exc:
            groups_errors += 1
            tb = traceback.format_exc()
            log.error("[%d/%d] FAILED listing members of %s (after %d retries): %s\n%s",
                      gi, len(all_groups), gid, args.max_retries, exc, tb)
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
        if args.throttle_seconds > 0:
            time.sleep(args.throttle_seconds)

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
            "retries_attempted": retry_stats["retries_attempted"],
            "total_backoff_seconds": round(retry_stats["total_backoff_seconds"], 2),
        },
        "throttle": {
            "throttle_seconds": retry_stats["throttle_seconds"],
            "max_retries":      retry_stats["max_retries"],
            "backoff_base":     retry_stats["backoff_base"],
            "backoff_cap":      DEFAULT_BACKOFF_CAP,
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
    log.info("  retries attempted      : %d  (total backoff: %.1fs)",
             retry_stats["retries_attempted"], retry_stats["total_backoff_seconds"])
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
    pe.add_argument("--throttle-seconds", type=float, default=DEFAULT_THROTTLE_SECONDS,
                    help=f"Seconds to sleep between per-group member queries (default: "
                         f"{DEFAULT_THROTTLE_SECONDS}). Increase to ~0.5-1.0 for large customer "
                         f"environments that trip NSX rate-limits.")
    pe.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES,
                    help=f"How many times to retry a single API call when NSX returns 429/503/504 "
                         f"or a transient connection error (default: {DEFAULT_MAX_RETRIES}). "
                         f"Exponential backoff between attempts (~2s, 4s, 8s, capped at 60s).")
    pe.add_argument("--backoff-base", type=float, default=DEFAULT_BACKOFF_BASE,
                    help=f"Base seconds for exponential backoff (default: {DEFAULT_BACKOFF_BASE}). "
                         f"Attempt N waits min(base * 2^(N-1), 60s).")
    pe.set_defaults(func=cmd_export)

    args = p.parse_args()
    init_cli()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
