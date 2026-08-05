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


class _InteractiveExit(Exception):
    """Signals operator chose to exit the interactive batch loop cleanly."""


def _prompt_batch_continue(reverted_count: int, current_batch_size: int) -> int:
    """Prompt after a batch of applied VM tag reverts. Returns the batch size
    to use for the next batch.

    Allowed responses:
      y / yes / <Enter>  -> continue at current batch size
      n / no             -> continue but RESET batch size to 1 (be conservative)
      <positive number>  -> continue at that new batch size
      x / exit / quit    -> stop processing cleanly (raise _InteractiveExit)
    """
    while True:
        try:
            answer = input(
                f"\nReverted {reverted_count} VM tag(s). "
                f"Continue with current batch_size={current_batch_size}? "
                f"[Y(es) / n(o, reset to 1) / x(it) / <new size>]: "
            ).strip().lower()
        except EOFError:
            log.warning("Non-interactive stdin at batch boundary; auto-approving "
                        "(batch_size=%d).", current_batch_size)
            return current_batch_size

        if answer in ("", "y", "yes"):
            log.info("Operator approved batch (continue at batch_size=%d) "
                     "after %d reverted tag(s).",
                     current_batch_size, reverted_count)
            return current_batch_size

        if answer in ("n", "no"):
            log.warning("Operator chose RESET-TO-1 after %d reverted tag(s) "
                        "(was batch_size=%d).", reverted_count, current_batch_size)
            return 1

        if answer in ("x", "exit", "quit", "q"):
            log.warning("Operator chose EXIT after %d reverted tag(s).",
                        reverted_count)
            raise _InteractiveExit(f"Stopped by operator after {reverted_count} revert(s).")

        try:
            new_value = int(answer)
            if new_value <= 0:
                print("Please enter a positive integer (e.g. 1, 5, 25).")
                continue
            log.info("Operator changed batch_size from %d to %d after %d reverted tag(s).",
                     current_batch_size, new_value, reverted_count)
            return new_value
        except ValueError:
            print("Please enter Y / Enter, n, x, or a positive integer like 1, 5, or 25.")


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
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help="Interactive batching: pause every N reverted tags and prompt "
             "to continue (y/Enter), reset-to-1 (n), exit (x), or change to a "
             "new size (<number>). Default when --apply is set: 1 "
             "(step-through, safest). Default when dry-run: 0 (no prompts). "
             "Pass --batch-size 0 to disable prompts entirely under --apply.",
    )
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

    # Interactive batch state (mirrors push_hostname_tags.py).
    # Defaults:
    #   --apply set AND --batch-size not specified -> resolved = 1 (step-through)
    #   dry-run  AND --batch-size not specified    -> resolved = 0 (no prompts)
    #   --batch-size N explicitly passed           -> resolved = N
    if args.batch_size is None:
        resolved_batch_size = 1 if args.apply else 0
        if resolved_batch_size == 1:
            log.info("Auto-defaulting --batch-size to 1 (step-through is safer for --apply). "
                     "Pass --batch-size 0 to disable prompts, or --batch-size N to start at N.")
    else:
        resolved_batch_size = int(args.batch_size)
    interactive_mode = args.apply and resolved_batch_size > 0
    batch_size = resolved_batch_size
    reverted_in_batch = 0
    batch_summary: List[Dict[str, Any]] = []
    interactive_exit_requested = False
    if interactive_mode:
        log.info("INTERACTIVE MODE - batch_size=%d. Will prompt after every "
                 "%d reverted tag(s).", batch_size, batch_size)

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

        # ---- Interactive batch boundary ----
        # Only after real successful reverts (not skips / errors / missing / noop).
        if interactive_mode and row.get("status") == "success":
            reverted_in_batch += 1
            batch_summary.append(row)
            if reverted_in_batch >= batch_size:
                log.info("=" * 60)
                log.info("BATCH REVIEW - %d tag(s) just reverted:", reverted_in_batch)
                for j, br in enumerate(batch_summary, start=1):
                    log.info("  [%d] %-45s REMOVED hostname=%s (tags %d -> %d)",
                             j, str(br.get("display_name"))[:45],
                             br.get("removed_tag"),
                             br.get("tag_count_before"),
                             br.get("tag_count_after"))
                log.info("=" * 60)
                try:
                    batch_size = _prompt_batch_continue(reverted_in_batch, batch_size)
                except _InteractiveExit:
                    interactive_exit_requested = True
                    break
                reverted_in_batch = 0
                batch_summary = []

    if interactive_exit_requested:
        log.warning("Interactive exit requested. Reverted %d of %d entries.",
                    len(results["reverted"]), len(entries))

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
        "interactive_mode": interactive_mode,
        "batch_size_initial": resolved_batch_size,
        "batch_size_final": batch_size,
        "interactive_exit_requested": interactive_exit_requested,
        "results": results,
    }
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    log.info("Revert audit written: %s", out_path)
    print(json.dumps(doc["counts"] | {"manifest": str(out_path), "dry_run": dry_run}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
