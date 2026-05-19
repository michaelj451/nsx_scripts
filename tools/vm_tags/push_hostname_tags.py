#!/usr/bin/env python3
"""
tools/vm_tags/push_hostname_tags.py

Apply the hostname-tag plan to NSX.

Reads the plan produced by build_hostname_tag_plan.py (or dryrun_hostname_tags.py),
finds VMs classified as `eligible`, and for each one:

  1. Re-fetch the VM's current tag set from NSX (defensive read so we don't
     wipe tags added since the plan was built).
  2. Append a new tag {"scope": "hostname", "tag": <trailing-digits>}.
  3. POST the FULL combined tag set back via the fabric update_tags action.

Critical behavior:
  - NEVER removes any pre-existing tag on a VM.
  - NEVER touches VMs classified as skip_* in the plan.
  - Writes a per-run manifest to vm_tags_manifests/<host>/<ts>_apply.json
    that records EXACTLY which (external_id, hostname_tag_value) pairs were
    added. revert_hostname_tags.py uses this manifest to un-do precisely
    what was done.

Dry-run is the default. Real writes require --apply.

Usage (dry-run preview):
  python tools/vm_tags/push_hostname_tags.py \\
    --manager nsx-lm1 \\
    --plan-dir vm_tags_plan/nsx-lm1.lab.local

Usage (apply):
  python tools/vm_tags/push_hostname_tags.py \\
    --manager nsx-lm1 \\
    --plan-dir vm_tags_plan/nsx-lm1.lab.local \\
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

# Pacing between writes
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


def _build_combined_tags(
    current_tags: List[Dict[str, str]],
    new_scope: str,
    new_value: str,
) -> List[Dict[str, str]]:
    """
    Build the new tag list. If a tag with the same (scope, tag) already
    exists, the result is identical to the input (idempotent). If a
    different value with the same scope exists, we DO NOT replace it —
    we keep both. This script must never modify existing tags; the plan
    classifies those VMs as skip_has_tag and we wouldn't be here for one
    of those.

    But as a defensive read-modify-write, if NSX state changed between
    plan-build and push (someone else added a hostname tag), we'll detect
    it and refuse the operation for that VM (caller handles the flag).
    """
    combined = list(current_tags or [])
    for t in combined:
        if isinstance(t, dict) and t.get("scope") == new_scope and t.get("tag") == new_value:
            return combined  # already present, no-op
    combined.append({"scope": new_scope, "tag": new_value})
    return combined


def _has_scope(tags: List[Dict[str, str]], scope: str) -> str | None:
    for t in tags or []:
        if isinstance(t, dict) and t.get("scope") == scope:
            return t.get("tag")
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Add hostname tags to VMs per the plan. Never removes existing tags."
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        required=True,
    )
    parser.add_argument(
        "--plan-dir",
        required=True,
        help="Directory containing eligible.json from build_hostname_tag_plan.py.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually write to NSX. Default is dry-run.",
    )
    args = parser.parse_args()

    init_cli()
    log_file = setup_logging("push")

    manager_host = resolve_manager(args.manager)
    if not manager_host:
        raise SystemExit(f"Manager not defined for {args.manager}.")

    plan_dir = Path(args.plan_dir).expanduser().resolve()
    eligible_path = plan_dir / "eligible.json"
    if not eligible_path.exists():
        raise SystemExit(f"eligible.json not found in {plan_dir}")

    eligible_payload = json.loads(eligible_path.read_text(encoding="utf-8"))
    eligible = eligible_payload.get("vms") or []
    log.info("Eligible VMs from plan: %d", len(eligible))

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=False)

    # Pull live VMs once so we can read current tags for read-modify-write
    log.info("Reading current VM tags from %s", manager_host)
    live = client.list_virtual_machines()
    live_by_id = {vm["external_id"]: vm for vm in live if vm.get("external_id")}

    # Read the same cap the planner used. Defensive re-check below: if a VM's
    # live tag count has crept up to the cap between plan and push, we refuse
    # the push for that VM (don't push to a VM at or above the NSX limit).
    import os
    try:
        max_tags_cap = int(os.getenv("VM_TAGS_MAX_TAGS_PER_VM", "30"))
        if max_tags_cap <= 0:
            max_tags_cap = 30
    except ValueError:
        max_tags_cap = 30

    manifest_entries: List[Dict[str, Any]] = []
    results = {
        "applied": [],
        "skipped_already_has_hostname_post_plan": [],
        "skipped_already_has_exact_tag": [],
        "skipped_too_many_tags_post_plan": [],
        "missing_on_target": [],
        "errors": [],
    }
    dry_run = not args.apply
    last_ts = 0.0

    for plan_entry in eligible:
        ext_id = plan_entry["external_id"]
        proposed = plan_entry["proposed_hostname_tag"]
        display = plan_entry.get("display_name") or ext_id

        live_vm = live_by_id.get(ext_id)
        if live_vm is None:
            log.warning("[MISSING] VM not present on target: %s (%s)", display, ext_id)
            results["missing_on_target"].append(
                {"external_id": ext_id, "display_name": display}
            )
            continue

        current_tags = live_vm.get("tags") or []
        current_tag_count = len(current_tags)

        # Defensive: re-check the tag-count cap against live state in case
        # tags grew between plan-build and push.
        if current_tag_count >= max_tags_cap:
            log.warning(
                "[RACE] VM tag count reached cap since plan was built: %s now has %d tags (cap=%d) — skipping",
                display, current_tag_count, max_tags_cap,
            )
            results["skipped_too_many_tags_post_plan"].append(
                {
                    "external_id": ext_id,
                    "display_name": display,
                    "current_tag_count": current_tag_count,
                    "max_tags_cap": max_tags_cap,
                    "plan_proposed_tag": proposed,
                }
            )
            continue

        existing_hostname = _has_scope(current_tags, "hostname")
        if existing_hostname is not None:
            # Race: plan said no hostname tag, but one appeared between plan
            # and push. Don't touch.
            log.warning(
                "[RACE] VM acquired hostname tag since plan was built: %s now has hostname=%s — skipping",
                display, existing_hostname,
            )
            results["skipped_already_has_hostname_post_plan"].append(
                {
                    "external_id": ext_id,
                    "display_name": display,
                    "current_hostname_tag": existing_hostname,
                    "plan_proposed_tag": proposed,
                }
            )
            continue

        # Defensive: if the exact tag exists already (re-run), idempotent no-op
        if any(
            isinstance(t, dict) and t.get("scope") == "hostname" and t.get("tag") == proposed
            for t in current_tags
        ):
            log.info("[NOOP] VM already has hostname=%s: %s", proposed, display)
            results["skipped_already_has_exact_tag"].append(
                {"external_id": ext_id, "display_name": display, "hostname_tag": proposed}
            )
            continue

        combined = _build_combined_tags(current_tags, "hostname", proposed)
        prefix = "[DRY-RUN]" if dry_run else "[APPLY]"
        log.info(
            "%s VM=%s ext_id=%s: ADD hostname=%s (tags %d -> %d)",
            prefix, display, ext_id, proposed, len(current_tags), len(combined),
        )

        manifest_entry = {
            "external_id": ext_id,
            "display_name": display,
            "added_scope": "hostname",
            "added_tag": proposed,
            "tag_count_before": len(current_tags),
            "tag_count_after": len(combined),
            "tags_before": current_tags,
            "tags_after": combined,
        }

        if dry_run:
            manifest_entry["status"] = "dry_run"
            manifest_entries.append(manifest_entry)
            continue

        # Pacing
        now = time.monotonic()
        wait = TAG_UPDATE_INTERVAL_SECONDS - (now - last_ts)
        if wait > 0:
            time.sleep(wait)

        try:
            client.update_vm_tags(ext_id, combined)
            manifest_entry["status"] = "success"
            results["applied"].append(manifest_entry)
            manifest_entries.append(manifest_entry)
            last_ts = time.monotonic()
        except Exception as exc:
            log.error("FAILED updating tags for %s (%s): %s", display, ext_id, exc)
            manifest_entry["status"] = "error"
            manifest_entry["error"] = str(exc)
            results["errors"].append(manifest_entry)
            manifest_entries.append(manifest_entry)
            last_ts = time.monotonic()

    # Write manifest
    manifests_dir = Path(nsx_vm_log_dir).expanduser().resolve() / "vm_tags_manifests" / manager_host
    manifests_dir.mkdir(parents=True, exist_ok=True)
    manifest_kind = "dryrun" if dry_run else "apply"
    manifest_path = manifests_dir / f"{RUN_TS}_{manifest_kind}.json"
    manifest_doc = {
        "manager": args.manager,
        "manager_host": manager_host,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "plan_dir": str(plan_dir),
        "counts": {
            "applied": len(results["applied"]),
            "skipped_already_has_hostname_post_plan": len(results["skipped_already_has_hostname_post_plan"]),
            "skipped_already_has_exact_tag": len(results["skipped_already_has_exact_tag"]),
            "skipped_too_many_tags_post_plan": len(results["skipped_too_many_tags_post_plan"]),
            "missing_on_target": len(results["missing_on_target"]),
            "errors": len(results["errors"]),
        },
        "max_tags_cap": max_tags_cap,
        "results": results,
        "manifest_entries": manifest_entries,
    }
    manifest_path.write_text(json.dumps(manifest_doc, indent=2, sort_keys=True), encoding="utf-8")
    log.info("Manifest written: %s", manifest_path)
    print(json.dumps(manifest_doc["counts"] | {"manifest": str(manifest_path), "dry_run": dry_run}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
