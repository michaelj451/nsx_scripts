#!/usr/bin/env python3
"""
tools/vm_tags/export_vm_tags.py

Snapshot every VM on an NSX Local Manager along with its current tag set.
Read-only — uses the NSX fabric API. Output is the input for
build_hostname_tag_plan.py and the rollback reference for
revert_hostname_tags.py.

Usage:
  python tools/vm_tags/export_vm_tags.py --manager nsx-lm1 --base-dir vm_tags_export
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_vm_log_dir, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def setup_logging(tool: str) -> Path:
    log_dir = Path(nsx_vm_log_dir).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = (log_dir / f"vm_tags_{tool}_{RUN_TS}.log").resolve()
    log_file.touch(exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter(
        "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S",
    )
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(ch)
    root.addHandler(fh)
    log.info("Logging to %s", log_file)
    return log_file


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Snapshot every VM on an NSX LM along with its current tag set."
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        required=True,
        help="NSX Local Manager to export VM tags from.",
    )
    parser.add_argument(
        "--base-dir",
        default="vm_tags_export",
        help="Output root (default: vm_tags_export).",
    )
    args = parser.parse_args()

    init_cli()
    log_file = setup_logging("export")

    manager_host = resolve_manager(args.manager)
    if not manager_host:
        raise SystemExit(f"Manager not defined for {args.manager}.")

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=False)
    log.info("Listing VMs from %s", manager_host)
    vms = client.list_virtual_machines()
    log.info("Total VMs: %d", len(vms))

    base = Path(args.base_dir).expanduser().resolve() / manager_host
    base.mkdir(parents=True, exist_ok=True)
    out = base / "vms.json"

    payload = {
        "manager": args.manager,
        "manager_host": manager_host,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "vm_count": len(vms),
        "vms": vms,
    }
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    log.info("Wrote VM snapshot: %s", out)

    summary = {
        "manager": args.manager,
        "manager_host": manager_host,
        "exported_at": payload["exported_at"],
        "vm_count": len(vms),
        "vm_types": {},
        "vms_with_any_tags": 0,
        "vms_with_hostname_tag": 0,
        "output_file": str(out),
        "log_file": str(log_file),
    }
    for vm in vms:
        t = vm.get("type", "UNKNOWN")
        summary["vm_types"][t] = summary["vm_types"].get(t, 0) + 1
        tags = vm.get("tags") or []
        if tags:
            summary["vms_with_any_tags"] += 1
            if any(tg.get("scope") == "hostname" for tg in tags if isinstance(tg, dict)):
                summary["vms_with_hostname_tag"] += 1

    print(json.dumps(summary, indent=2, sort_keys=True))
    log.info("Export complete.")


if __name__ == "__main__":
    main()
