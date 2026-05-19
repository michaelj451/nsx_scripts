#!/usr/bin/env python3
"""
tools/nsx/push_complete_nsx_revert.py

Full-stack rollback for Workflow A pushes.

Counterpart to push_complete_nsx_payload.py. Where the push tool writes
services + groups + policies + rules, this revert tool removes any of those
objects that exist on the target but are NOT in the pre-change snapshot.

Order of operations matters because of NSX referential integrity:

  1. Delete extraneous security rules (rules in shared policies that are
     not in the snapshot — opt-in via --include-shared-policy-rules)
  2. Delete extraneous security policies (cascades to their child rules)
  3. Delete extraneous groups (now safe because nothing references them)

System-owned objects (NSX built-ins like ServiceInsertion_NSGroup,
default-layer2-section, default-layer3-section) are always skipped — they
are platform-managed and must not be deleted.

Services: skipped by default. The push tool only PATCHes existing services,
which doesn't add new ones. If you genuinely added a new service, pass
--include-services and the script will delete services that exist on the
target but not in the snapshot.

Dry-run is the default safe mode. Real deletes require --apply.

Usage (dry-run preview):
  python tools/nsx/push_complete_nsx_revert.py \\
    --target nsx-lm2 \\
    --export-root nsx_export/nsx-lm2.lab.local \\
    --domain-id default

Usage (apply):
  python tools/nsx/push_complete_nsx_revert.py \\
    --target nsx-lm2 \\
    --export-root nsx_export/nsx-lm2.lab.local \\
    --domain-id default \\
    --apply
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.nsx_policy_client import NsxApiError, NsxPolicyClient

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]

# Throttle between API operations
DELETE_INTERVAL_SECONDS = 0.5

# Auto-approve everything by default (set to >0 to prompt interactively)
APPLY_PROMPT_EVERY_N_UPDATES = 0


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

def _resolve_log_dir() -> Path:
    if not nsx_log_dir:
        p = REPO_ROOT / "nsx_logs"
    else:
        expanded = os.path.expandvars(os.path.expanduser(str(nsx_log_dir)))
        p = Path(expanded)
        if not p.is_absolute():
            p = REPO_ROOT / p
    p.mkdir(parents=True, exist_ok=True)
    return p


def setup_logging(verbose: bool) -> Path:
    level = logging.DEBUG if verbose else logging.INFO
    log_dir = _resolve_log_dir()
    log_file = log_dir / "push_complete_nsx_revert.log"

    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S UTC",
    )
    fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(fh)
    root.addHandler(sh)

    log.info("Log file: %s", log_file.resolve())
    log.info("Resolved log dir: %s", log_dir.resolve())
    return log_file


# -----------------------------------------------------------------------------
# Snapshot loaders
# -----------------------------------------------------------------------------

def _load_yaml_or_json(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def _discover_group_ids(export_root: Path, domain_id: str) -> Set[str]:
    """Return the set of group IDs present in the snapshot."""
    candidates = [
        export_root / "domains" / domain_id / "groups",
        export_root / domain_id / "groups",
    ]
    ids: Set[str] = set()
    for root in candidates:
        if not root.exists():
            continue
        for path in root.iterdir():
            if path.is_file() and path.suffix.lower() in (".yaml", ".yml", ".json"):
                try:
                    obj = _load_yaml_or_json(path) or {}
                    gid = obj.get("id")
                    if isinstance(gid, str) and gid:
                        ids.add(gid)
                except Exception as exc:
                    log.warning("Could not parse group snapshot %s: %s", path, exc)
        break  # first matching root only
    return ids


def _discover_policy_ids(export_root: Path, domain_id: str) -> Set[str]:
    """Return the set of security-policy IDs present in the snapshot."""
    candidates = [
        export_root / "domains" / domain_id / "security-policies",
        export_root / domain_id / "security-policies",
    ]
    ids: Set[str] = set()
    for root in candidates:
        if not root.exists():
            continue
        for policy_dir in root.iterdir():
            if not policy_dir.is_dir():
                continue
            # policy_dir.name is the policy id by convention from the exporter
            ids.add(policy_dir.name)
        break
    return ids


def _discover_service_ids(export_root: Path) -> Set[str]:
    """Return the set of service IDs present in the snapshot."""
    services_dir = export_root / "domains" / "default" / "services"
    if not services_dir.exists():
        services_dir = export_root / "services"
    ids: Set[str] = set()
    if not services_dir.exists():
        return ids
    for path in services_dir.iterdir():
        if path.is_file() and path.suffix.lower() in (".yaml", ".yml", ".json"):
            try:
                obj = _load_yaml_or_json(path) or {}
                sid = obj.get("id")
                if isinstance(sid, str) and sid:
                    ids.add(sid)
            except Exception as exc:
                log.warning("Could not parse service snapshot %s: %s", path, exc)
    return ids


# -----------------------------------------------------------------------------
# Pacing
# -----------------------------------------------------------------------------

def _pace(last_ts: float) -> float:
    now = time.monotonic()
    wait = DELETE_INTERVAL_SECONDS - (now - last_ts)
    if wait > 0:
        time.sleep(wait)
    return time.monotonic()


# -----------------------------------------------------------------------------
# Revert logic — policies
# -----------------------------------------------------------------------------

def revert_policies(
    client: NsxPolicyClient,
    *,
    domain_id: str,
    snapshot_policy_ids: Set[str],
    dry_run: bool,
) -> Dict[str, Any]:
    """
    Delete security policies that exist on the target but are NOT in the
    snapshot. Cascades to their child rules. Skips system-owned policies
    (default-layer-2-section, default-layer-3-section, etc.).
    """
    live = client.list_security_policies(domain_id=domain_id)
    live_by_id = {p["id"]: p for p in live if isinstance(p, dict) and p.get("id")}

    to_delete: List[Dict[str, Any]] = []
    skipped_system: List[str] = []
    kept: List[str] = []

    for pid, p in sorted(live_by_id.items()):
        if pid in snapshot_policy_ids:
            kept.append(pid)
            continue
        if p.get("_system_owned") is True:
            skipped_system.append(pid)
            continue
        to_delete.append(p)

    log.info(
        "Policies on target=%d, in snapshot=%d, to-delete=%d, system-owned-kept=%d, in-snapshot-kept=%d",
        len(live_by_id), len(snapshot_policy_ids), len(to_delete),
        len(skipped_system), len(kept),
    )
    for pid in skipped_system:
        live_obj = live_by_id[pid]
        log.info("  KEEP (system-owned): %s (%s)", pid, live_obj.get("display_name") or pid)

    deleted: List[str] = []
    failed: List[Dict[str, str]] = []
    last_ts = 0.0

    for idx, p in enumerate(to_delete, start=1):
        pid = p["id"]
        dname = p.get("display_name") or pid
        prefix = "[DRY-RUN]" if dry_run else "[DELETE]"
        log.info("  %s policy %d/%d: id=%s display_name=%s", prefix, idx, len(to_delete), pid, dname)

        if dry_run:
            continue

        last_ts = _pace(last_ts)
        try:
            client.delete_security_policy(pid, domain_id=domain_id)
            deleted.append(pid)
            log.info("    OK deleted policy %s", pid)
        except Exception as exc:
            failed.append({"id": pid, "display_name": dname, "error": str(exc)})
            log.error("    FAILED deleting policy %s: %s", pid, exc)

    return {
        "live_count": len(live_by_id),
        "snapshot_count": len(snapshot_policy_ids),
        "to_delete_count": len(to_delete),
        "deleted": deleted,
        "failed": failed,
        "system_owned_kept": skipped_system,
        "in_snapshot_kept": kept,
    }


# -----------------------------------------------------------------------------
# Revert logic — groups
# -----------------------------------------------------------------------------

def revert_groups(
    client: NsxPolicyClient,
    *,
    domain_id: str,
    snapshot_group_ids: Set[str],
    dry_run: bool,
) -> Dict[str, Any]:
    """
    Delete groups that exist on the target but are NOT in the snapshot.
    Skips system-owned groups (ServiceInsertion_NSGroup, etc.).
    """
    live = client.list_groups(domain_id=domain_id)
    live_by_id = {g["id"]: g for g in live if isinstance(g, dict) and g.get("id")}

    to_delete: List[Dict[str, Any]] = []
    skipped_system: List[str] = []
    kept: List[str] = []

    for gid, g in sorted(live_by_id.items()):
        if gid in snapshot_group_ids:
            kept.append(gid)
            continue
        if g.get("_system_owned") is True:
            skipped_system.append(gid)
            continue
        to_delete.append(g)

    log.info(
        "Groups on target=%d, in snapshot=%d, to-delete=%d, system-owned-kept=%d, in-snapshot-kept=%d",
        len(live_by_id), len(snapshot_group_ids), len(to_delete),
        len(skipped_system), len(kept),
    )
    for gid in skipped_system:
        live_obj = live_by_id[gid]
        log.info("  KEEP (system-owned): %s (%s)", gid, live_obj.get("display_name") or gid)

    deleted: List[str] = []
    failed: List[Dict[str, str]] = []
    last_ts = 0.0

    for idx, g in enumerate(to_delete, start=1):
        gid = g["id"]
        dname = g.get("display_name") or gid
        prefix = "[DRY-RUN]" if dry_run else "[DELETE]"
        log.info("  %s group %d/%d: id=%s display_name=%s", prefix, idx, len(to_delete), gid, dname)

        if dry_run:
            continue

        last_ts = _pace(last_ts)
        try:
            client.delete_group(gid, domain_id=domain_id)
            deleted.append(gid)
            log.info("    OK deleted group %s", gid)
        except Exception as exc:
            failed.append({"id": gid, "display_name": dname, "error": str(exc)})
            log.error("    FAILED deleting group %s: %s", gid, exc)

    return {
        "live_count": len(live_by_id),
        "snapshot_count": len(snapshot_group_ids),
        "to_delete_count": len(to_delete),
        "deleted": deleted,
        "failed": failed,
        "system_owned_kept": skipped_system,
        "in_snapshot_kept": kept,
    }


# -----------------------------------------------------------------------------
# Revert logic — services (opt-in)
# -----------------------------------------------------------------------------

def revert_services(
    client: NsxPolicyClient,
    *,
    snapshot_service_ids: Set[str],
    dry_run: bool,
) -> Dict[str, Any]:
    """
    Delete services that exist on the target but are NOT in the snapshot.
    Skips system-owned services (the vast majority of services on NSX are
    NSX-built-in).
    """
    live = client.list_services()
    live_by_id = {s["id"]: s for s in live if isinstance(s, dict) and s.get("id")}

    to_delete: List[Dict[str, Any]] = []
    skipped_system: List[str] = []
    kept: List[str] = []

    for sid, s in sorted(live_by_id.items()):
        if sid in snapshot_service_ids:
            kept.append(sid)
            continue
        if s.get("_system_owned") is True:
            skipped_system.append(sid)
            continue
        to_delete.append(s)

    log.info(
        "Services on target=%d, in snapshot=%d, to-delete=%d, system-owned-kept=%d, in-snapshot-kept=%d",
        len(live_by_id), len(snapshot_service_ids), len(to_delete),
        len(skipped_system), len(kept),
    )

    deleted: List[str] = []
    failed: List[Dict[str, str]] = []
    last_ts = 0.0

    for idx, s in enumerate(to_delete, start=1):
        sid = s["id"]
        dname = s.get("display_name") or sid
        prefix = "[DRY-RUN]" if dry_run else "[DELETE]"
        log.info("  %s service %d/%d: id=%s display_name=%s", prefix, idx, len(to_delete), sid, dname)

        if dry_run:
            continue

        last_ts = _pace(last_ts)
        try:
            client.delete_service(sid)
            deleted.append(sid)
            log.info("    OK deleted service %s", sid)
        except Exception as exc:
            failed.append({"id": sid, "display_name": dname, "error": str(exc)})
            log.error("    FAILED deleting service %s: %s", sid, exc)

    return {
        "live_count": len(live_by_id),
        "snapshot_count": len(snapshot_service_ids),
        "to_delete_count": len(to_delete),
        "deleted": deleted,
        "failed": failed,
        "system_owned_kept": skipped_system,
        "in_snapshot_kept": kept,
    }


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Full-stack rollback of a complete-payload push. Deletes any "
            "policies, groups, and (optionally) services that exist on the "
            "target but are NOT in the snapshot."
        )
    )
    parser.add_argument(
        "--target",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        required=True,
        help="NSX manager to revert.",
    )
    parser.add_argument(
        "--export-root",
        required=True,
        help="Snapshot root (e.g. nsx_export/nsx-lm2.lab.local).",
    )
    parser.add_argument(
        "--domain-id",
        default="default",
        help="NSX domain (default: default).",
    )
    parser.add_argument(
        "--federation-global",
        action="store_true",
        help="Use Global Manager federation API.",
    )
    parser.add_argument(
        "--include-services",
        action="store_true",
        help=(
            "Also delete services that exist on the target but are not in "
            "the snapshot. Off by default — the push tool only PATCHes "
            "existing services."
        ),
    )
    parser.add_argument(
        "--skip-groups",
        action="store_true",
        help="Don't touch groups (only revert policies and optionally services).",
    )
    parser.add_argument(
        "--skip-policies",
        action="store_true",
        help="Don't touch policies (only revert groups). Likely to leave groups un-deletable.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually delete. Default is dry-run.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    args = parser.parse_args()

    setup_logging(args.verbose)
    init_cli()

    manager_host = resolve_manager(args.target)
    if not manager_host:
        raise SystemExit(f"Manager not defined for {args.target}. Check your .env.")

    export_root = Path(args.export_root).expanduser().resolve()
    if not export_root.exists():
        raise SystemExit(f"Snapshot not found: {export_root}")

    log.info("Starting push_complete_nsx_revert")
    log.info("Target:                       %s (%s)", args.target, manager_host)
    log.info("Snapshot root:                %s", export_root)
    log.info("Domain ID:                    %s", args.domain_id)
    log.info("Federation GM:                %s", args.federation_global)
    log.info("Include services:             %s", args.include_services)
    log.info("Skip groups:                  %s", args.skip_groups)
    log.info("Skip policies:                %s", args.skip_policies)
    log.info("Mode:                         %s", "APPLY" if args.apply else "DRY-RUN")
    log.info("DELETE_INTERVAL_SECONDS:      %s", DELETE_INTERVAL_SECONDS)

    snapshot_group_ids = _discover_group_ids(export_root, args.domain_id)
    snapshot_policy_ids = _discover_policy_ids(export_root, args.domain_id)
    snapshot_service_ids = _discover_service_ids(export_root)

    log.info(
        "Snapshot summary: groups=%d policies=%d services=%d",
        len(snapshot_group_ids), len(snapshot_policy_ids), len(snapshot_service_ids),
    )

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=args.federation_global)
    dry_run = not args.apply

    result: Dict[str, Any] = {
        "target": args.target,
        "target_host": manager_host,
        "snapshot_root": str(export_root),
        "domain_id": args.domain_id,
        "dry_run": dry_run,
        "snapshot": {
            "group_count": len(snapshot_group_ids),
            "policy_count": len(snapshot_policy_ids),
            "service_count": len(snapshot_service_ids),
        },
    }

    # Order: policies first (cascades to rules), then groups, then services.
    if not args.skip_policies:
        log.info("=" * 60)
        log.info("Phase 1: Revert security policies (cascades to rules)")
        log.info("=" * 60)
        result["policies"] = revert_policies(
            client,
            domain_id=args.domain_id,
            snapshot_policy_ids=snapshot_policy_ids,
            dry_run=dry_run,
        )

    if not args.skip_groups:
        log.info("=" * 60)
        log.info("Phase 2: Revert groups")
        log.info("=" * 60)
        result["groups"] = revert_groups(
            client,
            domain_id=args.domain_id,
            snapshot_group_ids=snapshot_group_ids,
            dry_run=dry_run,
        )

    if args.include_services:
        log.info("=" * 60)
        log.info("Phase 3: Revert services")
        log.info("=" * 60)
        result["services"] = revert_services(
            client,
            snapshot_service_ids=snapshot_service_ids,
            dry_run=dry_run,
        )

    log.info("=" * 60)
    log.info("Revert finished.")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
