#!/usr/bin/env python3
"""
tools/vm_tags/revert_hostname_tags.py

Un-do the hostname-tag additions from a previous push_hostname_tags.py run.

Reads the manifest produced by push_hostname_tags.py. For every entry with
status=success, fetches the VM's CURRENT tag list from NSX, and removes
ONLY the specific (scope="hostname", tag=<value>) pair that the push
added. All other tags on the VM are preserved exactly as they are right
now in live NSX.

What this script never does:
  - It never deletes a VM.
  - It never removes any tag scope other than "hostname".
  - It never removes a hostname tag whose value differs from what the
    manifest says we added (defends against another operator changing the
    tag between push and revert).
  - It never modifies VMs that aren't in the manifest.

Dry-run is the default. Real writes require --apply.

Usage (dry-run preview):
  python tools/vm_tags/revert_hostname_tags.py \\
    --manager nsx-lm1 \\
    --manifest vm_tags_manifests/nsx-lm1.lab.local/<TS>_apply.json

Usage (apply):
  python tools/vm_tags/revert_hostname_tags.py \\
    --manager nsx-lm1 \\
    --manifest vm_tags_manifests/nsx-lm1.lab.local/<TS>_apply.json \\
    --apply
"""
from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_vm_log_dir, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

TAG_UPDATE_INTERVAL_SECONDS = 0.5


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
        description="Un-do hostname tag additions per a push manifest. Never deletes anything else."
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        required=True,
    )
    parser.add_argument("--manifest", required=True, help="Path to a manifest JSON from push_hostname_tags.py")
    parser.add_argument("--apply", action="store_true", help="Actually write. Default is dry-run.")
    args = parser.parse_args()

    init_cli()
    log_file = setup_logging("revert")

    manager_host = resolve_manager(args.manager)
    if not manager_host:
        raise SystemExit(f"Manager not defined for {args.manager}.")

    manifest_path = Path(args.manifest).expanduser().resolve()
    if not manifest_path.exists():
        raise SystemExit(f"Manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = [e for e in (manifest.get("manifest_entries") or []) if e.get("status") == "success"]
    log.info("Manifest %s contains %d success entries to consider for revert", manifest_path, len(entries))

    if manifest.get("manager_host") and manifest["manager_host"] != manager_host:
        log.warning(
            "Manifest was recorded against %s but --manager resolves to %s. Proceeding only if you're sure.",
            manifest["manager_host"], manager_host,
        )

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=False)
    live = client.list_virtual_machines()
    live_by_id = {vm["external_id"]: vm for vm in live if vm.get("external_id")}

    results = {
        "reverted": [],
        "skipped_value_changed": [],
        "skipped_tag_no_longer_present": [],
        "missing_on_target": [],
        "errors": [],
    }
    dry_run = not args.apply
    last_ts = 0.0

    for entry in entries:
        ext_id = entry["external_id"]
        added_value = entry["added_tag"]
        display = entry.get("display_name") or ext_id

        live_vm = live_by_id.get(ext_id)
        if live_vm is None:
            log.warning("[MISSING] VM not on target anymore: %s (%s)", display, ext_id)
            results["missing_on_target"].append({"external_id": ext_id, "display_name": display})
            continue

        current_tags = live_vm.get("tags") or []
        # Find the hostname tag entry in current_tags
        current_hostname_idx = None
        current_hostname_value = None
        for i, t in enumerate(current_tags):
            if isinstance(t, dict) and t.get("scope") == "hostname":
                current_hostname_idx = i
                current_hostname_value = t.get("tag")
                break

        if current_hostname_idx is None:
            log.info("[NOOP] %s no longer has any hostname tag — nothing to revert", display)
            results["skipped_tag_no_longer_present"].append(
                {"external_id": ext_id, "display_name": display, "manifest_value": added_value}
            )
            continue

        if current_hostname_value != added_value:
            log.warning(
                "[GUARD] %s has hostname=%s but manifest added %s — leaving alone",
                display, current_hostname_value, added_value,
            )
            results["skipped_value_changed"].append(
                {
                    "external_id": ext_id,
                    "display_name": display,
                    "manifest_value": added_value,
                    "current_value": current_hostname_value,
                }
            )
            continue

        # Build new tag list: drop only the matching hostname tag
        new_tags = [t for i, t in enumerate(current_tags) if i != current_hostname_idx]
        prefix = "[DRY-RUN]" if dry_run else "[APPLY]"
        log.info(
            "%s VM=%s ext_id=%s: REMOVE hostname=%s (tags %d -> %d)",
            prefix, display, ext_id, added_value, len(current_tags), len(new_tags),
        )

        row = {
            "external_id": ext_id,
            "display_name": display,
            "removed_scope": "hostname",
            "removed_tag": added_value,
            "tag_count_before": len(current_tags),
            "tag_count_after": len(new_tags),
            "tags_before": current_tags,
            "tags_after": new_tags,
        }

        if dry_run:
            row["status"] = "dry_run"
            results["reverted"].append(row)
            continue

        now = time.monotonic()
        wait = TAG_UPDATE_INTERVAL_SECONDS - (now - last_ts)
        if wait > 0:
            time.sleep(wait)
        try:
            client.update_vm_tags(ext_id, new_tags)
            row["status"] = "success"
            results["reverted"].append(row)
            last_ts = time.monotonic()
        except Exception as exc:
            log.error("FAILED reverting %s (%s): %s", display, ext_id, exc)
            row["status"] = "error"
            row["error"] = str(exc)
            results["errors"].append(row)
            last_ts = time.monotonic()

    # Write revert manifest for audit
    out_dir = Path(nsx_vm_log_dir).expanduser().resolve() / "vm_tags_manifests" / manager_host
    out_dir.mkdir(parents=True, exist_ok=True)
    kind = "dryrun" if dry_run else "apply"
    out_path = out_dir / f"{RUN_TS}_revert_{kind}.json"
    doc = {
        "manager": args.manager,
        "manager_host": manager_host,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "source_manifest": str(manifest_path),
        "counts": {k: len(v) for k, v in results.items()},
        "results": results,
    }
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    log.info("Revert audit written: %s", out_path)
    print(json.dumps(doc["counts"] | {"manifest": str(out_path), "dry_run": dry_run}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
