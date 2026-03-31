#!/usr/bin/env python3
"""
tools/nsx/push_nsx_groups_revert.py

Rollback NSX Policy groups from an exported snapshot back to NSX.
Reads group files from an export directory and PATCHes them back to the
target manager. Credentials and manager hostnames come from .env via
nsx_constants / cli_bootstrap — no username/password CLI args needed.

Usage (dry-run):
  python tools/nsx/push_nsx_groups_revert.py --target nsx-gm2 --export-root nsx_export/nsx-gm2.lab.local

Usage (apply):
  python tools/nsx/push_nsx_groups_revert.py --target nsx-gm2 --export-root nsx_export/nsx-gm2.lab.local --apply
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.nsx_policy_client import NsxPolicyClient

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_STRIP_KEYS = {
    "_create_time",
    "_create_user",
    "_last_modified_time",
    "_last_modified_user",
    "_links",
    "_protection",
    "_schema",
    "_self",
    "_system_owned",
    "_revision",
    "revision",
    "realization_id",
    "unique_id",
    "marked_for_delete",
    "remote_path",
    "overridden",
    "origin_site_id",
    "owner_id",
}


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    log_dir = Path(nsx_log_dir) if nsx_log_dir else REPO_ROOT / "nsx_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "push_nsx_groups_revert.log"

    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")

    fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)

    root.addHandler(fh)
    root.addHandler(sh)
    log.info("Log file: %s", log_file)


# -----------------------------------------------------------------------------
# File helpers
# -----------------------------------------------------------------------------

def load_file(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def clean_payload(obj: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in obj.items() if k not in DEFAULT_STRIP_KEYS}


def discover_group_files(export_root: Path, domain_id: str) -> List[Path]:
    candidates = [
        export_root / domain_id / "groups",
        export_root / "domains" / domain_id / "groups",
    ]
    for root in candidates:
        if root.exists():
            return sorted(
                p for p in root.iterdir()
                if p.is_file() and p.suffix.lower() in {".yaml", ".yml", ".json"}
            )
    raise FileNotFoundError(
        f"Could not find group export folder under either:\n"
        f"  {candidates[0]}\n"
        f"  {candidates[1]}"
    )


def load_desired_groups(export_root: Path, domain_id: str) -> Dict[str, Dict[str, Any]]:
    desired: Dict[str, Dict[str, Any]] = {}
    for path in discover_group_files(export_root, domain_id):
        obj = load_file(path)
        if not obj:
            continue
        group_id = obj.get("id")
        if not group_id:
            log.warning("Skipping %s — no 'id' field", path)
            continue
        desired[group_id] = clean_payload(obj)
    return desired


# -----------------------------------------------------------------------------
# Rollback logic
# -----------------------------------------------------------------------------

def rollback_groups(
    client: NsxPolicyClient,
    export_root: Path,
    domain_id: str,
    *,
    dry_run: bool = True,
    delete_extraneous: bool = False,
) -> None:
    desired = load_desired_groups(export_root, domain_id)
    if not desired:
        log.warning("No desired groups found in export set — nothing to do.")
        return

    existing_groups = client.list_groups(domain_id)
    existing = {g["id"]: g for g in existing_groups if "id" in g}

    desired_ids = set(desired.keys())
    existing_ids = set(existing.keys())

    to_create = sorted(desired_ids - existing_ids)
    to_update = sorted(desired_ids & existing_ids)
    to_delete = sorted(existing_ids - desired_ids)

    log.info("Rollback summary for domain '%s':", domain_id)
    log.info("  desired groups : %d", len(desired_ids))
    log.info("  existing groups: %d", len(existing_ids))
    log.info("  create (new)   : %d", len(to_create))
    log.info("  update         : %d", len(to_update))
    log.info("  delete extra   : %d", len(to_delete) if delete_extraneous else 0)

    if dry_run:
        for gid in to_create:
            log.info("[DRY-RUN] would create: %s", gid)
        for gid in to_update:
            log.info("[DRY-RUN] would update: %s", gid)
        if delete_extraneous:
            for gid in to_delete:
                log.info("[DRY-RUN] would delete extraneous: %s", gid)
        return

    for gid in sorted(desired.keys()):
        payload = desired[gid]
        log.info("Restoring group: %s", gid)
        try:
            client.patch_group(gid, payload, domain_id)
        except Exception as exc:
            log.error("Failed restoring %s: %s", gid, exc)

    if delete_extraneous:
        for gid in to_delete:
            log.info("Deleting extraneous group: %s", gid)
            try:
                client.delete_group(gid, domain_id)
            except Exception as exc:
                log.error("Failed deleting %s: %s", gid, exc)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rollback NSX Policy groups from an exported snapshot. Credentials from .env."
    )
    parser.add_argument(
        "--target",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        required=True,
        help="NSX manager to push rollback groups into.",
    )
    parser.add_argument(
        "--export-root",
        required=True,
        help="Export root folder containing the snapshot to restore from (e.g. nsx_export/nsx-gm2.lab.local).",
    )
    parser.add_argument(
        "--domain-id",
        default="default",
        help="NSX domain ID (default: default).",
    )
    parser.add_argument(
        "--federation-global",
        action="store_true",
        help="Use Global Manager federation API (global-infra).",
    )
    parser.add_argument(
        "--delete-extraneous",
        action="store_true",
        help="Delete groups that exist in NSX but are not in the rollback snapshot.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually make changes. Default is dry-run.",
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

    log.info("Starting push_nsx_groups_revert")
    log.info("Target:           %s (%s)", args.target, manager_host)
    log.info("Export root:      %s", Path(args.export_root).resolve())
    log.info("Domain ID:        %s", args.domain_id)
    log.info("Federation GM:    %s", args.federation_global)
    log.info("Delete extra:     %s", args.delete_extraneous)
    log.info("Mode:             %s", "APPLY" if args.apply else "DRY-RUN")

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=args.federation_global)

    rollback_groups(
        client=client,
        export_root=Path(args.export_root),
        domain_id=args.domain_id,
        dry_run=not args.apply,
        delete_extraneous=args.delete_extraneous,
    )


if __name__ == "__main__":
    main()
