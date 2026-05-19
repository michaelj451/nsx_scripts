#!/usr/bin/env python3
"""
tools/nsx/push_nsx_groups_revert.py

Rollback NSX Policy groups from an exported snapshot back to NSX.
Reads group files from an export directory and PATCHes them back to the
target manager. Credentials and manager hostnames come from .env via
nsx_constants / cli_bootstrap — no username/password CLI args needed.

Scope:
  This is a **groups-only** revert. It restores each group's payload
  (membership / IP list / expression) from the snapshot via PATCH. It does
  NOT touch security policies, rules, or services.

When to use:
  Workflow B (in-place CSV remap on the same manager). The push step only
  PATCHed groups, so reverting groups is the complete rollback.

For Workflow A (the clone push, which writes services + groups + policies +
rules to a new manager), use `push_complete_nsx_revert.py` instead — the
groups-only revert here cannot delete groups that are still referenced by
policies/rules from a Workflow-A push.

Usage (dry-run):
  python tools/nsx/push_nsx_groups_revert.py --target nsx-lm1 --export-root nsx_export/nsx-lm1.lab.local

Usage (apply):
  python tools/nsx/push_nsx_groups_revert.py --target nsx-lm1 --export-root nsx_export/nsx-lm1.lab.local --apply
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.nsx_policy_client import NsxPolicyClient

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]

GROUP_PATCH_INTERVAL_SECONDS = 0.5

# Dry-run review cadence
PROMPT_EVERY_N_UPDATES = 100

# Initial apply batch size.
# Example:
#   1  -> prompt immediately for first item, then allow operator to ramp to 5, 10, 20, etc.
#   0  -> disable checkpoint prompting and auto-approve everything subject only to time pacing.
APPLY_PROMPT_EVERY_N_UPDATES = 1

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

LOCAL_ONLY_KEYS = {
    "_source_file",
}


# -----------------------------------------------------------------------------
# Path / logging helpers
# -----------------------------------------------------------------------------

def _resolve_log_dir() -> Path:
    """
    Resolve nsx_log_dir safely across Linux/macOS/Windows.

    Supports:
      - repo-relative paths like "nsx_logs"
      - absolute paths
      - environment-expanded paths like %USERPROFILE%\\logs or $HOME/logs
      - home-relative paths like ~/logs
    """
    if not nsx_log_dir:
        p = REPO_ROOT / "nsx_logs"
    else:
        expanded = os.path.expandvars(os.path.expanduser(str(nsx_log_dir)))
        p = Path(expanded)
        if not p.is_absolute():
            p = REPO_ROOT / p
    return p


def _ensure_dir(path: Path, *, label: str) -> Path:
    existed_before = path.exists()
    path.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve()

    root = logging.getLogger()
    if root.handlers:
        if existed_before:
            root.info("%s directory already exists: %s", label, resolved)
        else:
            root.info("%s directory created: %s", label, resolved)

    return resolved


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    log_dir = _ensure_dir(_resolve_log_dir(), label="Resolved log")
    log_file = log_dir / "push_nsx_groups_revert.log"

    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%S UTC")

    fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)

    root.addHandler(fh)
    root.addHandler(sh)

    log.info("Log file initialized: %s", log_file.resolve())
    log.info("Repository root resolved to: %s", REPO_ROOT.resolve())
    log.info("Configured nsx_log_dir value: %s", nsx_log_dir)
    log.info("Resolved log directory: %s", log_dir.resolve())


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


def payload_for_patch(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Strip any local-only helper keys before sending payload to NSX.
    """
    return {k: v for k, v in obj.items() if k not in LOCAL_ONLY_KEYS}


def discover_group_files(export_root: Path, domain_id: str) -> List[Path]:
    candidates = [
        export_root / domain_id / "groups",
        export_root / "domains" / domain_id / "groups",
    ]
    for root in candidates:
        if root.exists():
            files = sorted(
                p for p in root.iterdir()
                if p.is_file() and p.suffix.lower() in {".yaml", ".yml", ".json"}
            )
            log.info("Discovered %d group file(s) under %s", len(files), root.resolve())
            return files

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
            log.warning("Skipping %s — empty object", path)
            continue

        group_id = obj.get("id")
        if not group_id:
            log.warning("Skipping %s — no 'id' field", path)
            continue

        cleaned = clean_payload(obj)
        cleaned["_source_file"] = str(path)
        desired[group_id] = cleaned

    log.info("Loaded %d desired group payload(s) from export set", len(desired))
    return desired


# -----------------------------------------------------------------------------
# Diff helpers
# -----------------------------------------------------------------------------

def _extract_ip_address_entries(node: Any) -> List[str]:
    """
    Recursively collect all entries from IPAddressExpression.ip_addresses.
    This captures IPs, CIDRs, and ranges because NSX stores them as strings.
    """
    found: List[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            if obj.get("resource_type") == "IPAddressExpression":
                for value in obj.get("ip_addresses", []) or []:
                    if isinstance(value, str):
                        found.append(value.strip())
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(node)
    return found


def _diff_group_ip_entries(current_group: Optional[dict], desired_group: dict) -> Dict[str, List[str]]:
    current_entries = set(_extract_ip_address_entries(current_group or {}))
    desired_entries = set(_extract_ip_address_entries(desired_group))

    return {
        "current": sorted(current_entries),
        "desired": sorted(desired_entries),
        "to_add": sorted(desired_entries - current_entries),
        "to_remove": sorted(current_entries - desired_entries),
        "already_present": sorted(desired_entries & current_entries),
    }


def _format_entries(entries: Optional[List[str]], *, max_items: int = 200) -> str:
    if entries is None:
        return "[unknown]"

    if not entries:
        return "[]"

    if len(entries) <= max_items:
        return "[" + ", ".join(entries) + "]"

    shown = entries[:max_items]
    return "[" + ", ".join(shown) + f", ... +{len(entries) - max_items} more]"


def _action_word(add_count: int, remove_count: int) -> str:
    if add_count > 0 and remove_count > 0:
        return "ADD+REMOVE"
    if add_count > 0:
        return "ADD"
    if remove_count > 0:
        return "REMOVE"
    return "NO-CHANGE"


# -----------------------------------------------------------------------------
# Pacing / approval helpers
# -----------------------------------------------------------------------------

def _prompt_to_continue(processed_count: int, *, phase: str) -> None:
    while True:
        answer = input(
            f"\nProcessed {processed_count} {phase}. Continue with next item? [y/N]: "
        ).strip().lower()

        if answer in ("y", "yes"):
            log.info("Operator chose to continue after %d %s.", processed_count, phase)
            return

        if answer in ("", "n", "no"):
            log.warning("Operator aborted after %d %s.", processed_count, phase)
            raise KeyboardInterrupt(f"Stopped by operator after {processed_count} {phase}.")

        print("Please enter 'y' or 'n'.")


def _prompt_apply_checkpoint(processed_count: int, *, current_every: int) -> int:
    """
    Prompt after a batch of applied rollback operations.
    Returns the new batch size to use going forward.

    Allowed responses:
      y / yes  -> continue with current batch size
      n / no   -> abort
      <number> -> continue and change batch size to that number
    """
    while True:
        answer = input(
            f"\nApplied {processed_count} rollback updates. "
            f"Continue with current batch size={current_every}? "
            f"[y/N or enter new batch size]: "
        ).strip().lower()

        if answer in ("y", "yes"):
            log.info(
                "Operator chose to continue after %d rollback updates with existing batch size=%d.",
                processed_count,
                current_every,
            )
            return current_every

        if answer in ("", "n", "no"):
            log.warning("Operator aborted after %d rollback updates.", processed_count)
            raise KeyboardInterrupt(f"Stopped by operator after {processed_count} rollback updates.")

        try:
            new_value = int(answer)
            if new_value <= 0:
                print("Please enter a positive integer greater than 0.")
                continue

            log.info(
                "Operator changed rollback apply batch size from %d to %d after %d applied updates.",
                current_every,
                new_value,
                processed_count,
            )
            return new_value
        except ValueError:
            print("Please enter 'y', 'n', or a positive integer like 5, 10, or 20.")


def _prompt_apply_item(*, item_kind: str, group_id: str, display_name: str) -> str:
    while True:
        answer = input(
            f"\nApply this {item_kind}? id={group_id} display_name={display_name} [y/N/s]: "
        ).strip().lower()

        if answer in ("y", "yes"):
            log.info(
                "Operator chose APPLY for %s id=%s display_name=%s",
                item_kind,
                group_id,
                display_name,
            )
            return "apply"

        if answer in ("s", "skip"):
            log.info(
                "Operator chose SKIP for %s id=%s display_name=%s",
                item_kind,
                group_id,
                display_name,
            )
            return "skip"

        if answer in ("", "n", "no"):
            log.warning(
                "Operator chose ABORT for %s id=%s display_name=%s",
                item_kind,
                group_id,
                display_name,
            )
            return "abort"

        print("Please enter 'y', 'n', or 's'.")


def _controlled_checkpoint(*, processed_count: int, last_ts: float, phase: str) -> float:
    now = time.monotonic()
    wait = GROUP_PATCH_INTERVAL_SECONDS - (now - last_ts)
    if wait > 0:
        log.info("%s throttle: waiting %.3f seconds before next item", phase, wait)
        time.sleep(wait)

    new_ts = time.monotonic()

    if PROMPT_EVERY_N_UPDATES > 0 and processed_count % PROMPT_EVERY_N_UPDATES == 0:
        _prompt_to_continue(processed_count, phase=phase)

    return new_ts


def _maybe_refresh_apply_budget(
    *,
    applied_count: int,
    state: Dict[str, Any],
) -> None:
    current_every = state["apply_prompt_every_n_updates"]

    if current_every <= 0:
        state["auto_apply_remaining"] = 10**12
        return

    new_every = _prompt_apply_checkpoint(
        applied_count,
        current_every=current_every,
    )
    state["apply_prompt_every_n_updates"] = new_every
    state["auto_apply_remaining"] = new_every


def _should_prompt_for_apply(state: Dict[str, Any]) -> bool:
    remaining = state.get("auto_apply_remaining", 0)
    return remaining <= 0


def _apply_time_pacing(*, last_ts: float, phase: str) -> float:
    now = time.monotonic()
    wait = GROUP_PATCH_INTERVAL_SECONDS - (now - last_ts)
    if wait > 0:
        log.info("%s throttle: waiting %.3f seconds before next item", phase, wait)
        time.sleep(wait)
    return time.monotonic()


def _log_group_state(
    *,
    phase_label: str,
    index: int,
    total: int,
    group_id: str,
    display_name: str,
    exists_in_nsx: bool,
    current_entries: Optional[List[str]],
    to_add: List[str],
    to_remove: List[str],
    source_file: Optional[str] = None,
) -> None:
    action = _action_word(len(to_add), len(to_remove))

    if total > 0:
        prefix = f"[{phase_label} {index}/{total}]"
    else:
        prefix = f"[{phase_label} {index}]"

    log.info(
        "%s group=%s display_name=%s exists_in_nsx=%s action=%s current=%s add=%d remove=%d%s",
        prefix,
        group_id,
        display_name,
        "yes" if exists_in_nsx else "no",
        action,
        len(current_entries) if current_entries is not None else "unknown",
        len(to_add),
        len(to_remove),
        f" source_file={source_file}" if source_file else "",
    )
    log.info("  [CURRENT EXISTS] %s", _format_entries(current_entries))
    log.info("  [RESTORE ADD]    %s", _format_entries(to_add))
    log.info("  [RESTORE REMOVE] %s", _format_entries(to_remove))


def _write_validation_report(
    records: list,
    *,
    target: str,
    domain_id: str,
    run_ts: str,
    output_base: Path,
) -> Path:
    validation_base = _ensure_dir(output_base, label="Validation base")
    run_dir = _ensure_dir(validation_base / f"{run_ts}_{target}_revert_validate", label="Validation run")

    out = {
        "run_ts": run_ts,
        "target": target,
        "domain_id": domain_id,
        "groups_validated": len(records),
        "groups_missing_in_nsx": sum(1 for r in records if not r["exists_in_nsx"]),
        "groups_with_additions": sum(1 for r in records if r["to_add_count"] > 0),
        "groups_with_removals": sum(1 for r in records if r["to_remove_count"] > 0),
        "groups_with_no_delta": sum(
            1
            for r in records
            if r["exists_in_nsx"] and r["to_add_count"] == 0 and r["to_remove_count"] == 0
        ),
        "groups": records,
    }

    report_file = run_dir / "validation_report.json"
    report_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
    log.info("Validation report file written successfully: %s", report_file.resolve())
    return report_file


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
    target: str,
    run_ts: str,
) -> None:
    desired = load_desired_groups(export_root, domain_id)
    if not desired and not delete_extraneous:
        log.warning("No desired groups found in export set — nothing to do.")
        return
    if not desired and delete_extraneous:
        log.warning(
            "No desired groups in export set, but --delete-extraneous is set. "
            "Every group currently on the target will be considered extraneous."
        )

    existing_groups = client.list_groups(domain_id)
    existing = {g["id"]: g for g in existing_groups if "id" in g}

    desired_ids = set(desired.keys())
    existing_ids = set(existing.keys())

    to_create = sorted(desired_ids - existing_ids)
    to_update = sorted(desired_ids & existing_ids)
    to_delete_all = sorted(existing_ids - desired_ids)

    # Never delete NSX system-owned groups (ServiceInsertion_NSGroup,
    # SystemVM_NSGroup, Edge_NSGroup, etc.). The exporter excludes these
    # from snapshots, so they'll always appear "extraneous" — but they're
    # platform-managed and must remain untouched.
    system_owned_skipped: List[str] = []
    to_delete: List[str] = []
    for gid in to_delete_all:
        live = existing.get(gid, {})
        if live.get("_system_owned") is True:
            system_owned_skipped.append(gid)
            log.info(
                "Skipping delete of system-owned group: id=%s display_name=%s",
                gid,
                live.get("display_name") or gid,
            )
            continue
        to_delete.append(gid)

    log.info("Rollback summary for domain '%s':", domain_id)
    if system_owned_skipped:
        log.info("  system-owned   : %d (kept, never deleted)", len(system_owned_skipped))
    log.info("  desired groups : %d", len(desired_ids))
    log.info("  existing groups: %d", len(existing_ids))
    log.info("  create (new)   : %d", len(to_create))
    log.info("  update         : %d", len(to_update))
    log.info("  delete extra   : %d", len(to_delete) if delete_extraneous else 0)
    log.info("  pacing interval: %s", GROUP_PATCH_INTERVAL_SECONDS)
    log.info("  dry-run prompt : %s", PROMPT_EVERY_N_UPDATES)
    log.info("  apply batch    : %s", APPLY_PROMPT_EVERY_N_UPDATES)

    apply_prompt_every = APPLY_PROMPT_EVERY_N_UPDATES if APPLY_PROMPT_EVERY_N_UPDATES > 0 else 0
    apply_state: Dict[str, Any] = {
        "apply_prompt_every_n_updates": apply_prompt_every,
        "auto_apply_remaining": 0,
        "applied_count": 0,
    }

    validation_records: List[Dict[str, Any]] = []
    ordered_restore_ids = sorted(desired.keys())
    last_ts = 0.0
    skipped_restore_count = 0
    skipped_delete_count = 0
    skipped_no_change_count = 0

    for idx, gid in enumerate(ordered_restore_ids, start=1):
        payload = desired[gid]
        patch_payload = payload_for_patch(payload)
        display_name = payload.get("display_name") or payload.get("name") or gid
        source_file = payload.get("_source_file")
        existing_group = existing.get(gid)

        diff = _diff_group_ip_entries(existing_group, patch_payload)
        current_entries = diff["current"] if existing_group is not None else None
        to_add = diff["to_add"] if existing_group is not None else diff["desired"]
        to_remove = diff["to_remove"] if existing_group is not None else []

        _log_group_state(
            phase_label="REVERT",
            index=idx,
            total=len(ordered_restore_ids),
            group_id=gid,
            display_name=display_name,
            exists_in_nsx=(existing_group is not None),
            current_entries=current_entries,
            to_add=to_add,
            to_remove=to_remove,
            source_file=source_file,
        )

        validation_records.append(
            {
                "group_id": gid,
                "display_name": display_name,
                "source_file": source_file,
                "exists_in_nsx": existing_group is not None,
                "current_entries": current_entries,
                "current_count": len(current_entries) if current_entries is not None else None,
                "desired_entries": diff["desired"],
                "desired_count": len(diff["desired"]),
                "to_add": to_add,
                "to_add_count": len(to_add),
                "to_remove": to_remove,
                "to_remove_count": len(to_remove),
                "already_present": diff["already_present"] if existing_group is not None else [],
                "already_present_count": len(diff["already_present"]) if existing_group is not None else 0,
                "action": _action_word(len(to_add), len(to_remove)),
            }
        )

        if dry_run:
            last_ts = _controlled_checkpoint(
                processed_count=idx,
                last_ts=last_ts,
                phase="dry-run rollback checks",
            )
            continue

        # Hard no-op safeguard:
        # If the group already exists in NSX and there is no IP delta at all,
        # do not touch it.
        if existing_group is not None and not to_add and not to_remove:
            skipped_no_change_count += 1
            log.info(
                "Skipping restore for unchanged group=%s display_name=%s no_change_skipped_total=%d",
                gid,
                display_name,
                skipped_no_change_count,
            )
            continue

        if _should_prompt_for_apply(apply_state):
            _maybe_refresh_apply_budget(
                applied_count=apply_state["applied_count"],
                state=apply_state,
            )

            decision = _prompt_apply_item(
                item_kind="group restore",
                group_id=gid,
                display_name=display_name,
            )

            if decision == "skip":
                skipped_restore_count += 1
                log.info(
                    "Skipped restore for group=%s display_name=%s skipped_restore_total=%d",
                    gid,
                    display_name,
                    skipped_restore_count,
                )
                last_ts = _apply_time_pacing(
                    last_ts=last_ts,
                    phase="rollback updates",
                )
                continue

            if decision == "abort":
                raise KeyboardInterrupt(
                    f"Stopped by operator at restore group id={gid} display_name={display_name}."
                )
        else:
            log.info(
                "Auto-approving restore for group=%s display_name=%s remaining_batch=%d",
                gid,
                display_name,
                apply_state["auto_apply_remaining"],
            )

        last_ts = _apply_time_pacing(
            last_ts=last_ts,
            phase="rollback updates",
        )

        log.info("Restoring group: %s", gid)
        try:
            client.patch_group(gid, patch_payload, domain_id)
            apply_state["applied_count"] += 1
            if apply_state["auto_apply_remaining"] > 0:
                apply_state["auto_apply_remaining"] -= 1

            log.info(
                "Restore PATCH succeeded for group=%s display_name=%s applied_total=%d remaining_batch=%d",
                gid,
                display_name,
                apply_state["applied_count"],
                apply_state["auto_apply_remaining"],
            )
        except Exception as exc:
            log.error("Failed restoring %s: %s", gid, exc)

    if delete_extraneous:
        for delete_idx, gid in enumerate(to_delete, start=1):
            display_name = existing.get(gid, {}).get("display_name") or existing.get(gid, {}).get("name") or gid

            log.info(
                "[DELETE %d/%d] extraneous group=%s display_name=%s action=DELETE",
                delete_idx,
                len(to_delete),
                gid,
                display_name,
            )

            if dry_run:
                log.info("[DRY-RUN] would delete extraneous: %s", gid)
                last_ts = _controlled_checkpoint(
                    processed_count=len(ordered_restore_ids) + delete_idx,
                    last_ts=last_ts,
                    phase="dry-run rollback deletions",
                )
                continue

            if _should_prompt_for_apply(apply_state):
                _maybe_refresh_apply_budget(
                    applied_count=apply_state["applied_count"],
                    state=apply_state,
                )

                decision = _prompt_apply_item(
                    item_kind="group delete",
                    group_id=gid,
                    display_name=display_name,
                )

                if decision == "skip":
                    skipped_delete_count += 1
                    log.info(
                        "Skipped delete for group=%s display_name=%s skipped_delete_total=%d",
                        gid,
                        display_name,
                        skipped_delete_count,
                    )
                    last_ts = _apply_time_pacing(
                        last_ts=last_ts,
                        phase="rollback deletions",
                    )
                    continue

                if decision == "abort":
                    raise KeyboardInterrupt(
                        f"Stopped by operator at delete group id={gid} display_name={display_name}."
                    )
            else:
                log.info(
                    "Auto-approving delete for group=%s display_name=%s remaining_batch=%d",
                    gid,
                    display_name,
                    apply_state["auto_apply_remaining"],
                )

            last_ts = _apply_time_pacing(
                last_ts=last_ts,
                phase="rollback deletions",
            )

            log.info("Deleting extraneous group: %s", gid)
            try:
                client.delete_group(gid, domain_id)
                apply_state["applied_count"] += 1
                if apply_state["auto_apply_remaining"] > 0:
                    apply_state["auto_apply_remaining"] -= 1

                log.info(
                    "Delete succeeded for group=%s display_name=%s applied_total=%d remaining_batch=%d",
                    gid,
                    display_name,
                    apply_state["applied_count"],
                    apply_state["auto_apply_remaining"],
                )
            except Exception as exc:
                log.error("Failed deleting %s: %s", gid, exc)

    validation_base = _resolve_log_dir() / "nsx_validation"
    validation_file = _write_validation_report(
        validation_records,
        target=target,
        domain_id=domain_id,
        run_ts=run_ts,
        output_base=validation_base,
    )
    log.info("Rollback validation report written: %s", validation_file)
    log.info(
        "Rollback finished. applied_total=%d skipped_restore_total=%d skipped_delete_total=%d skipped_no_change_total=%d",
        apply_state["applied_count"],
        skipped_restore_count,
        skipped_delete_count,
        skipped_no_change_count,
    )


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

    run_ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())

    log.info("Starting push_nsx_groups_revert")
    log.info("Target:                        %s (%s)", args.target, manager_host)
    log.info("Export root:                   %s", Path(args.export_root).resolve())
    log.info("Domain ID:                     %s", args.domain_id)
    log.info("Federation GM:                 %s", args.federation_global)
    log.info("Delete extra:                  %s", args.delete_extraneous)
    log.info("Mode:                          %s", "APPLY" if args.apply else "DRY-RUN")
    log.info("GROUP_PATCH_INTERVAL_SECONDS:  %s", GROUP_PATCH_INTERVAL_SECONDS)
    log.info("PROMPT_EVERY_N_UPDATES:        %s", PROMPT_EVERY_N_UPDATES)
    log.info("APPLY_PROMPT_EVERY_N_UPDATES:  %s", APPLY_PROMPT_EVERY_N_UPDATES)
    log.info("Resolved log dir:              %s", _resolve_log_dir().resolve())

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=args.federation_global)

    try:
        rollback_groups(
            client=client,
            export_root=Path(args.export_root),
            domain_id=args.domain_id,
            dry_run=not args.apply,
            delete_extraneous=args.delete_extraneous,
            target=args.target,
            run_ts=run_ts,
        )
    except KeyboardInterrupt as exc:
        log.warning("Rollback interrupted by operator: %s", exc)
        raise SystemExit(130)


if __name__ == "__main__":
    main()