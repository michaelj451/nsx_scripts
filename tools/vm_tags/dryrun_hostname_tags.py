#!/usr/bin/env python3
"""
tools/vm_tags/dryrun_hostname_tags.py

Single-command dry-run that produces a complete pre-change report. Composes
export_vm_tags.py + build_hostname_tag_plan.py into one operation and flags
every issue the operator should review before pushing.

This script makes NO NSX writes. It reads the live VM state via the fabric
API and writes plan + classification reports locally.

Flagged conditions (each gets its own JSON report under --output-dir):
  - skip_has_tag       : VMs already carrying a hostname tag
  - skip_invalid_name  : VMs whose names lack 3-6 trailing digits
  - skip_edge          : NSX Edge VMs (always skipped)
  - skip_other_type    : non-REGULAR VMs (NSX appliances, etc.)
  - eligible           : VMs that WILL get tagged on apply

Usage:
  python tools/vm_tags/dryrun_hostname_tags.py \\
    --manager nsx-lm1 \\
    --output-dir vm_tags_plan/nsx-lm1.lab.local \\
    --overwrite
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_vm_log_dir, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient

# Re-use the classifier from build_hostname_tag_plan.py to avoid duplication.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_hostname_tag_plan import classify_vm, write_tag_inventory_jsonl  # type: ignore

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
        description="Single-command dry-run: pull VM state from NSX and produce a full pre-change report."
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        required=True,
        help="NSX Local Manager to query.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Where to write the classification reports (default: <NSX_VM_LOG_DIR>/vm_tags_plan/<manager-host>).",
    )
    parser.add_argument("--overwrite", action="store_true", help="Delete --output-dir before writing.")
    args = parser.parse_args()

    init_cli()
    log_file = setup_logging("dryrun")

    manager_host = resolve_manager(args.manager)
    if not manager_host:
        raise SystemExit(f"Manager not defined for {args.manager}.")

    if args.output_dir:
        host_dir = Path(args.output_dir).expanduser().resolve()
    else:
        host_dir = Path(nsx_vm_log_dir).expanduser().resolve() / "vm_tags_plan" / manager_host

    # Per-run timestamped subdir so successive runs accumulate instead of
    # overwriting each other.
    out_dir = host_dir / RUN_TS
    if out_dir.exists():
        if not args.overwrite:
            raise SystemExit(f"Output dir already exists: {out_dir}. Use --overwrite.")
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=False)
    log.info("Reading VMs from %s", manager_host)
    vms = client.list_virtual_machines()
    log.info("Total VMs: %d", len(vms))

    classified = [classify_vm(v) for v in vms]
    buckets = {
        "eligible": [],
        "skip_has_tag": [],
        "skip_too_many_tags": [],
        "skip_invalid_name": [],
        "skip_edge": [],
        "skip_other_type": [],
    }
    for c in classified:
        buckets[c["classification"]].append(c)

    for key, rows in buckets.items():
        (out_dir / f"{key}.json").write_text(
            json.dumps({"count": len(rows), "vms": rows}, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        log.info("  %s: %d VM(s)", key, len(rows))

    # Per-VM tag inventory (every VM, regardless of classification)
    inv_path = out_dir / "vm_tag_inventory.jsonl"
    inv_count = write_tag_inventory_jsonl(vms, inv_path)
    log.info("  vm_tag_inventory: %d row(s) -> %s", inv_count, inv_path)

    flagged = (
        len(buckets["skip_has_tag"])
        + len(buckets["skip_invalid_name"])
        + len(buckets["skip_too_many_tags"])
    )

    summary = {
        "manager": args.manager,
        "manager_host": manager_host,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "vm_count_total": len(vms),
        "counts": {k: len(v) for k, v in buckets.items()},
        "flagged_for_review": flagged,
        "vm_tag_inventory": str(inv_path),
        "output_dir": str(out_dir),
        "log_file": str(log_file),
    }
    (out_dir / "plan.json").write_text(
        json.dumps({"summary": summary, "classified": classified}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))

    if flagged > 0:
        log.warning(
            "%d VM(s) flagged for review — see skip_has_tag.json / skip_invalid_name.json / skip_too_many_tags.json",
            flagged,
        )


if __name__ == "__main__":
    main()
