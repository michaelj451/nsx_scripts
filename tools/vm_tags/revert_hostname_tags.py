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
    --manifest nsx_vm_tags_manifests/nsx-lm1.lab.local/<TS>_apply.json

Usage (apply):
  python tools/vm_tags/revert_hostname_tags.py \\
    --manager nsx-lm1 \\
    --manifest nsx_vm_tags_manifests/nsx-lm1.lab.local/<TS>_apply.json \\
    --apply
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_log_dir, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
CHECKPOINT_TOOL_TAG = "revert_hostname_tags"
CHECKPOINT_SCHEMA_VERSION = 1

TAG_UPDATE_INTERVAL_SECONDS = 0.5


def _sha256_of_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _open_checkpoint(path: Path, header: Dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path, "a", encoding="utf-8")
    if path.stat().st_size == 0:
        rec = {"type": "header", **header}
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    return fh


def _checkpoint_write(fh, entry: Dict[str, Any]) -> None:
    fh.write(json.dumps({"type": "entry", **entry}, sort_keys=True) + "\n")
    fh.flush()
    try:
        os.fsync(fh.fileno())
    except OSError:
        pass


def _load_resume_checkpoint(
    path: Path,
    expected_manager_host: str,
    expected_manifest_path: Path,
    expected_manifest_sha256: str,
    force_manifest_mismatch: bool,
) -> Tuple[Set[str], Dict[str, Any]]:
    """
    Validate an existing revert checkpoint and return (already_reverted_ext_ids, header).

    STRICT by default: refuses on manager mismatch always, and on
    manifest path / sha256 mismatch unless force_manifest_mismatch=True.
    """
    if not path.exists():
        raise SystemExit(f"--resume file not found: {path}")
    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise SystemExit(f"--resume file is empty: {path}")
    try:
        header = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--resume file header is not JSON: {exc}")
    if header.get("type") != "header":
        raise SystemExit(f"--resume first line is not a header (type={header.get('type')!r})")
    if header.get("tool") != CHECKPOINT_TOOL_TAG:
        raise SystemExit(
            f"--resume file was written by tool={header.get('tool')!r}, "
            f"not {CHECKPOINT_TOOL_TAG!r}. Refusing to load."
        )
    if header.get("manager_host") != expected_manager_host:
        raise SystemExit(
            f"--resume manager mismatch: checkpoint recorded manager_host="
            f"{header.get('manager_host')!r} but this run resolves to "
            f"{expected_manager_host!r}. Refusing to proceed."
        )
    manifest_path_ok = str(header.get("source_manifest")) == str(expected_manifest_path)
    manifest_sha_ok = (
        header.get("source_manifest_sha256") == expected_manifest_sha256
        if header.get("source_manifest_sha256") else True
    )
    if (not manifest_path_ok or not manifest_sha_ok) and not force_manifest_mismatch:
        raise SystemExit(
            "--resume manifest mismatch:\n"
            f"  checkpoint source_manifest     = {header.get('source_manifest')!r}\n"
            f"  this run  --manifest           = {str(expected_manifest_path)!r}\n"
            f"  checkpoint source_manifest_sha = {header.get('source_manifest_sha256')!r}\n"
            f"  this run  manifest sha256      = {expected_manifest_sha256!r}\n"
            "Refusing to proceed. Pass --force-manifest-mismatch ONLY if you "
            "are certain the manifest content is unchanged."
        )
    if not manifest_path_ok:
        log.warning("Resume: manifest path differs but --force-manifest-mismatch is set.")
    if not manifest_sha_ok:
        log.warning("Resume: manifest sha256 differs but --force-manifest-mismatch is set.")

    already_reverted: Set[str] = set()
    for ln in lines[1:]:
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if (
            e.get("type") == "entry"
            and e.get("status") == "success"
            and e.get("external_id")
        ):
            already_reverted.add(e["external_id"])
    return already_reverted, header


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
    prompt_text = (f"Reverted {reverted_count} VM tag(s). "
                   f"Continue with current batch_size={current_batch_size}? "
                   f"[Y(es) / n(o, reset to 1) / x(it) / <new size>]:")
    while True:
        log.info("PROMPT: %s", prompt_text)
        try:
            raw = input("\n" + prompt_text + " ")
        except EOFError:
            log.warning("OPERATOR RESPONSE: <EOF> (non-interactive stdin). "
                        "Auto-approving (batch_size=%d).", current_batch_size)
            return current_batch_size

        # Capture raw response verbatim before parsing.
        log.info("OPERATOR RESPONSE: %r", raw)
        answer = raw.strip().lower()

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
                log.info("OPERATOR RESPONSE was non-positive (%r); re-prompting.", raw)
                print("Please enter a positive integer (e.g. 1, 5, 25).")
                continue
            log.info("Operator changed batch_size from %d to %d after %d reverted tag(s).",
                     current_batch_size, new_value, reverted_count)
            return new_value
        except ValueError:
            log.info("OPERATOR RESPONSE was invalid (%r); re-prompting.", raw)
            print("Please enter Y / Enter, n, x, or a positive integer like 1, 5, or 25.")


def setup_logging(tool: str) -> Path:
    log_dir = Path(nsx_log_dir).expanduser().resolve()
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
    parser.add_argument(
        "--resume",
        default=None,
        help="Path to a prior *_revert_apply.progress.jsonl checkpoint from a "
             "crashed or early-exited revert. VMs already recorded as "
             "status=success are skipped IF live NSX confirms the tag is "
             "already gone. Manager and manifest (path + sha256) must match "
             "the checkpoint (strict). See --force-manifest-mismatch.",
    )
    parser.add_argument(
        "--force-manifest-mismatch",
        action="store_true",
        help="With --resume, allow proceeding when the manifest path or "
             "content sha256 differs from the checkpoint's. Only use this "
             "when you are certain the manifest content is unchanged.",
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

    manifest_sha256 = _sha256_of_file(manifest_path)
    log.info("Source manifest sha256: %s", manifest_sha256)

    dry_run = not args.apply

    out_dir = Path(nsx_log_dir).expanduser().resolve() / "reports" / "vm_tags_revert" / manager_host
    out_dir.mkdir(parents=True, exist_ok=True)
    kind = "dryrun" if dry_run else "apply"
    checkpoint_path = out_dir / f"{RUN_TS}_revert_{kind}.progress.jsonl"

    already_reverted_from_resume: Set[str] = set()
    resume_header: Optional[Dict[str, Any]] = None
    if args.resume:
        resume_path = Path(args.resume).expanduser().resolve()
        already_reverted_from_resume, resume_header = _load_resume_checkpoint(
            resume_path,
            expected_manager_host=manager_host,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=manifest_sha256,
            force_manifest_mismatch=args.force_manifest_mismatch,
        )
        log.info(
            "RESUME: %d VM(s) already recorded as reverted in %s. Will "
            "verify each is actually untagged in live NSX before skipping.",
            len(already_reverted_from_resume), resume_path,
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
        "skipped_already_reverted_prior_run": [],
        "checkpoint_vs_live_mismatch": [],
    }
    last_ts = 0.0

    checkpoint_header = {
        "tool": CHECKPOINT_TOOL_TAG,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "manager": args.manager,
        "manager_host": manager_host,
        "source_manifest": str(manifest_path),
        "source_manifest_sha256": manifest_sha256,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "run_ts": RUN_TS,
        "dry_run": dry_run,
        "resumed_from": str(Path(args.resume).expanduser().resolve()) if args.resume else None,
        "prior_success_count_from_resume": len(already_reverted_from_resume),
    }
    cp_fh = _open_checkpoint(checkpoint_path, checkpoint_header)
    log.info("Checkpoint (incremental): %s", checkpoint_path)

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
            row = {"external_id": ext_id, "display_name": display}
            results["missing_on_target"].append(row)
            _checkpoint_write(cp_fh, {"status": "missing_on_target", **row})
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

        # Resume-aware fast path: if this VM was recorded as reverted in a
        # prior crashed run, verify with LIVE NSX before skipping.
        if ext_id in already_reverted_from_resume:
            live_still_has_target = (
                current_hostname_value is not None
                and current_hostname_value == added_value
            )
            if not live_still_has_target:
                log.info(
                    "[RESUME-SKIP] %s already had hostname=%s removed per prior run and live state confirms.",
                    display, added_value,
                )
                row = {
                    "external_id": ext_id,
                    "display_name": display,
                    "manifest_value": added_value,
                }
                results["skipped_already_reverted_prior_run"].append(row)
                _checkpoint_write(cp_fh, {"status": "skipped_already_reverted_prior_run", **row})
                continue
            log.warning(
                "[CHECKPOINT-VS-LIVE MISMATCH] %s recorded as reverted in "
                "the resume checkpoint but live NSX still shows hostname=%s. "
                "Skipping this VM (safest). Investigate manually before "
                "re-running without --resume.",
                display, current_hostname_value,
            )
            row = {
                "external_id": ext_id,
                "display_name": display,
                "manifest_value": added_value,
                "live_hostname_tag": current_hostname_value,
            }
            results["checkpoint_vs_live_mismatch"].append(row)
            _checkpoint_write(cp_fh, {"status": "checkpoint_vs_live_mismatch", **row})
            continue

        if current_hostname_idx is None:
            log.info("[NOOP] %s no longer has any hostname tag; nothing to revert", display)
            row = {"external_id": ext_id, "display_name": display, "manifest_value": added_value}
            results["skipped_tag_no_longer_present"].append(row)
            _checkpoint_write(cp_fh, {"status": "skipped_tag_no_longer_present", **row})
            continue

        if current_hostname_value != added_value:
            log.warning(
                "[GUARD] %s has hostname=%s but manifest added %s. Leaving alone.",
                display, current_hostname_value, added_value,
            )
            row = {
                "external_id": ext_id,
                "display_name": display,
                "manifest_value": added_value,
                "current_value": current_hostname_value,
            }
            results["skipped_value_changed"].append(row)
            _checkpoint_write(cp_fh, {"status": "skipped_value_changed", **row})
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
            _checkpoint_write(cp_fh, row)
            continue

        now = time.monotonic()
        wait = TAG_UPDATE_INTERVAL_SECONDS - (now - last_ts)
        if wait > 0:
            time.sleep(wait)
        try:
            client.update_vm_tags(ext_id, new_tags)
            row["status"] = "success"
            results["reverted"].append(row)
            _checkpoint_write(cp_fh, row)
            last_ts = time.monotonic()
        except Exception as exc:
            log.error("FAILED reverting %s (%s): %s", display, ext_id, exc)
            row["status"] = "error"
            row["error"] = str(exc)
            results["errors"].append(row)
            _checkpoint_write(cp_fh, row)
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

    # Write revert manifest for audit (out_dir + kind computed earlier so the
    # checkpoint lives beside it from the first VM decision, at
    # nsx_logs/reports/vm_tags_revert/<host>/).
    out_path = out_dir / f"{RUN_TS}_revert_{kind}.json"
    doc = {
        "manager": args.manager,
        "manager_host": manager_host,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "source_manifest": str(manifest_path),
        "source_manifest_sha256": manifest_sha256,
        "resumed_from": checkpoint_header.get("resumed_from"),
        "counts": {k: len(v) for k, v in results.items()},
        "interactive_mode": interactive_mode,
        "batch_size_initial": resolved_batch_size,
        "batch_size_final": batch_size,
        "interactive_exit_requested": interactive_exit_requested,
        "checkpoint_path": str(checkpoint_path),
        "results": results,
    }
    out_path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    log.info("Revert audit written: %s", out_path)

    # Close checkpoint and rename to .done.jsonl so orphan-detection
    # (progress files without a sibling manifest) stays reliable.
    try:
        cp_fh.flush()
        os.fsync(cp_fh.fileno())
    except OSError:
        pass
    cp_fh.close()
    done_path = checkpoint_path.with_suffix(".done.jsonl")
    try:
        checkpoint_path.rename(done_path)
        log.info("Checkpoint finalized: %s", done_path)
    except OSError as exc:
        log.warning("Could not rename checkpoint to .done.jsonl (%s); leaving as-is.", exc)

    print(json.dumps(doc["counts"] | {
        "manifest": str(out_path),
        "checkpoint": str(done_path if done_path.exists() else checkpoint_path),
        "dry_run": dry_run,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
