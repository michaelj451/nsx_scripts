#!/usr/bin/env python3
"""
tools/vm_tags/build_hostname_tag_plan.py

Offline transform. Read a VM-tag export and classify every VM into one of:

  eligible            — type=REGULAR, name ends in 3-6 trailing digits, no
                        existing hostname tag. Will be tagged.
  skip_has_tag        — already has a hostname-scope tag. Will be skipped.
                        Logged as separate report (operator review).
  skip_invalid_name   — name does not end in a 3-6 digit run. Will be
                        skipped + flagged.
  skip_edge           — NSX Edge VM (type=EDGE). Always skipped.
  skip_other_type    — type is something other than REGULAR / EDGE
                        (e.g. NSX Manager appliances). Always skipped.

Leading zeros in the trailing digit sequence are preserved exactly as they
appear in the name (e.g. `host-0042` -> hostname tag `0042`).

This step writes ONLY local files. No NSX writes.

Usage:
  python tools/vm_tags/build_hostname_tag_plan.py \\
    --vm-export vm_tags_export/nsx-lm1.lab.local/vms.json \\
    --output-dir vm_tags_plan/nsx-lm1.lab.local \\
    --overwrite
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_vm_log_dir

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

TRAILING_DIGITS_RE = re.compile(r"(\d+)$")
ELIGIBLE_DIGIT_LENGTHS = (3, 4, 5, 6)


def supported_vm_types() -> Set[str]:
    """
    Read VM_TAGS_SUPPORTED_TYPES from the environment. Comma-separated list
    of NSX VM type values that are eligible for hostname tagging.
    Default: just REGULAR. Anything not in this list falls into
    skip_other_type (or skip_edge for type=EDGE).
    """
    raw = os.getenv("VM_TAGS_SUPPORTED_TYPES", "REGULAR")
    parsed = {t.strip().upper() for t in raw.split(",") if t.strip()}
    return parsed or {"REGULAR"}


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


def extract_hostname_value(vm_name: str) -> Optional[str]:
    """Return the trailing digit run if it has 3-6 digits, else None."""
    if not vm_name:
        return None
    m = TRAILING_DIGITS_RE.search(vm_name)
    if not m:
        return None
    digits = m.group(1)
    if len(digits) in ELIGIBLE_DIGIT_LENGTHS:
        return digits
    return None


def find_hostname_tag(tags: List[Dict[str, str]]) -> Optional[str]:
    """Return the value of the hostname-scope tag if present, else None."""
    for t in tags or []:
        if isinstance(t, dict) and t.get("scope") == "hostname":
            return t.get("tag")
    return None


def classify_vm(vm: Dict[str, Any]) -> Dict[str, Any]:
    """Classify a single VM. Returns a dict with classification + reasoning."""
    name = vm.get("display_name") or ""
    ext_id = vm.get("external_id") or ""
    vm_type = vm.get("type") or "UNKNOWN"
    tags = vm.get("tags") or []
    existing_hostname = find_hostname_tag(tags)
    proposed = extract_hostname_value(name)

    base = {
        "external_id": ext_id,
        "display_name": name,
        "type": vm_type,
        "existing_tags": tags,
        "existing_hostname_tag": existing_hostname,
        "proposed_hostname_tag": proposed,
    }

    if vm_type == "EDGE":
        base["classification"] = "skip_edge"
        base["reason"] = "NSX Edge VM (type=EDGE)"
        return base

    supported = supported_vm_types()
    if vm_type.upper() not in supported:
        base["classification"] = "skip_other_type"
        base["reason"] = (
            f"VM type {vm_type!r} is not in VM_TAGS_SUPPORTED_TYPES "
            f"({sorted(supported)})"
        )
        return base

    if existing_hostname is not None:
        base["classification"] = "skip_has_tag"
        base["reason"] = f"Already has hostname tag: {existing_hostname!r}"
        return base

    if proposed is None:
        base["classification"] = "skip_invalid_name"
        base["reason"] = "Name does not end with 3-6 trailing digits"
        return base

    base["classification"] = "eligible"
    base["reason"] = f"Will add hostname tag {proposed!r} (from trailing digits in name)"
    return base


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the hostname-tag plan from a VM export. Offline; no NSX writes."
    )
    parser.add_argument("--vm-export", required=True, help="Path to vms.json from export_vm_tags.py")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Where to write the plan JSON files (default: <NSX_VM_LOG_DIR>/vm_tags_plan/<manager-host>, derived from the export).",
    )
    parser.add_argument("--overwrite", action="store_true", help="Delete --output-dir before writing")
    args = parser.parse_args()

    init_cli()
    log_file = setup_logging("build_plan")

    src = Path(args.vm_export).expanduser().resolve()
    if not src.exists():
        raise SystemExit(f"VM export not found: {src}")

    if args.output_dir:
        out_dir = Path(args.output_dir).expanduser().resolve()
    else:
        # Derive default from manager_host inside the export payload
        peek = json.loads(src.read_text(encoding="utf-8"))
        manager_host = peek.get("manager_host") or "unknown-manager"
        out_dir = Path(nsx_vm_log_dir).expanduser().resolve() / "vm_tags_plan" / manager_host
    if out_dir.exists():
        if not args.overwrite:
            raise SystemExit(f"Output dir already exists: {out_dir}. Use --overwrite.")
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    log.info("VM export: %s", src)
    log.info("Output dir: %s", out_dir)

    payload = json.loads(src.read_text(encoding="utf-8"))
    vms = payload.get("vms") or []
    log.info("Loaded %d VMs from export", len(vms))

    classified = [classify_vm(v) for v in vms]

    buckets: Dict[str, List[Dict[str, Any]]] = {
        "eligible": [],
        "skip_has_tag": [],
        "skip_invalid_name": [],
        "skip_edge": [],
        "skip_other_type": [],
    }
    for c in classified:
        buckets[c["classification"]].append(c)

    for key, rows in buckets.items():
        out = out_dir / f"{key}.json"
        out.write_text(json.dumps({"count": len(rows), "vms": rows}, indent=2, sort_keys=True), encoding="utf-8")
        log.info("  %s: %d VM(s) -> %s", key, len(rows), out)

    summary = {
        "source_export": str(src),
        "source_manager": payload.get("manager"),
        "source_manager_host": payload.get("manager_host"),
        "source_exported_at": payload.get("exported_at"),
        "planned_at": datetime.now(timezone.utc).isoformat(),
        "vm_count_total": len(vms),
        "counts": {k: len(v) for k, v in buckets.items()},
        "output_dir": str(out_dir),
        "log_file": str(log_file),
    }
    plan = out_dir / "plan.json"
    plan.write_text(json.dumps({"summary": summary, "classified": classified}, indent=2, sort_keys=True), encoding="utf-8")
    log.info("Plan written: %s", plan)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
