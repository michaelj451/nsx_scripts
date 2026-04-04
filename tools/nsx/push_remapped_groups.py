#!/usr/bin/env python3
# tools/nsx/push_nsx_groups.py
from __future__ import annotations

import argparse
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_gm1, nsx_gm2, nsx_lm1, nsx_lm2, nsx_lm3, nsx_lm4
from nsx.nsx_constants import nsx_log_dir
from nsx.nsx_object_functions.nsx_group_importer import GroupImportConfig, NsxGroupImporter
from nsx.nsx_policy_client import NsxPolicyClient

DEFAULT_INPUT_DIR = "nsx_groups_additive"
DEFAULT_BASELINE_DIR = "nsx_export"
LOG_FILE_NAME = "push_nsx_groups.log"

# These two fields regulate both dry-run validation pacing and apply pacing.
GROUP_PATCH_INTERVAL_SECONDS = 1.0
PROMPT_EVERY_N_UPDATES = 1

log = logging.getLogger("push_nsx_groups")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _ensure_dir(path: Path, *, label: str) -> Path:
    existed_before = path.exists()
    path.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve()

    if log.handlers:
        if existed_before:
            log.info("%s directory already exists: %s", label, resolved)
        else:
            log.info("%s directory created: %s", label, resolved)

    return resolved


def _resolve_log_dir() -> Path:
    """
    Resolve nsx_log_dir safely across Linux/macOS/Windows.

    Supports:
      - repo-relative paths like "nsx_logs"
      - absolute paths
      - environment-expanded paths like %USERPROFILE%\\logs or $HOME/logs
      - home-relative paths like ~/logs
    """
    repo_root = _repo_root()

    if not nsx_log_dir:
        p = repo_root / "nsx_logs"
    else:
        expanded = os.path.expandvars(os.path.expanduser(str(nsx_log_dir)))
        p = Path(expanded)
        if not p.is_absolute():
            p = repo_root / p

    return _ensure_dir(p, label="Resolved log")


def setup_logging() -> logging.Logger:
    log_dir = _resolve_log_dir()
    log_file = log_dir / LOG_FILE_NAME

    logger = logging.getLogger("push_nsx_groups")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)

    logger.info("Log file initialized: %s", log_file.resolve())
    logger.info("Repository root resolved to: %s", _repo_root().resolve())
    logger.info("Configured nsx_log_dir value: %s", nsx_log_dir)

    return logger


def _build_mgr_map() -> Dict[str, str]:
    return {
        "nsx-gm1": nsx_gm1,
        "nsx-gm2": nsx_gm2,
        "nsx-lm1": nsx_lm1,
        "nsx-lm2": nsx_lm2,
        "nsx-lm3": nsx_lm3,
        "nsx-lm4": nsx_lm4,
    }


def _default_input_dir() -> Path:
    return _repo_root() / DEFAULT_INPUT_DIR


def _default_baseline_dir() -> Path:
    return _repo_root() / DEFAULT_BASELINE_DIR


def _manager_dirname(manager_host: str) -> str:
    return manager_host.replace("https://", "").rstrip("/")


def _select_input_root_for_target(input_dir: Path, target_manager_host: str) -> Path:
    target_name = _manager_dirname(target_manager_host)

    if input_dir.name == target_name:
        return input_dir

    candidate = input_dir / target_name
    if candidate.is_dir():
        return candidate

    return input_dir


def _select_baseline_root_for_target(baseline_dir: Path, target_manager_host: str) -> Path:
    target_name = _manager_dirname(target_manager_host)

    if baseline_dir.name == target_name:
        return baseline_dir

    candidate = baseline_dir / target_name
    if candidate.is_dir():
        return candidate

    return baseline_dir


def _find_domain_root(export_root: Path) -> Path:
    if (export_root / "domains").is_dir():
        return export_root

    for sub in export_root.iterdir():
        if sub.is_dir() and (sub / "domains").is_dir():
            return sub

    raise RuntimeError(
        "Could not find a 'domains' directory. Expected either:\n"
        f"  1) {export_root}/domains/<domain-id>/groups\n"
        f"  2) {export_root}/<manager>/domains/<domain-id>/groups"
    )


def _resolve_groups_dir(domain_root: Path, domain_id: str) -> Path:
    new_dir = domain_root / domain_id / "groups"
    old_dir = domain_root / "domains" / domain_id / "groups"
    return new_dir if new_dir.is_dir() else old_dir


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


def _prompt_apply_item(*, group_id: Optional[str], display_name: str) -> str:
    while True:
        answer = input(
            f"\nApply this group? id={group_id} display_name={display_name} [y/N/s]: "
        ).strip().lower()

        if answer in ("y", "yes"):
            log.info("Operator chose APPLY for group id=%s display_name=%s", group_id, display_name)
            return "apply"

        if answer in ("s", "skip"):
            log.info("Operator chose SKIP for group id=%s display_name=%s", group_id, display_name)
            return "skip"

        if answer in ("", "n", "no"):
            log.warning("Operator chose ABORT for group id=%s display_name=%s", group_id, display_name)
            return "abort"

        print("Please enter 'y', 'n', or 's'.")


def _iter_group_files(groups_dir: Path, input_format: str) -> Iterable[Path]:
    suffixes = [".yaml", ".yml"] if input_format == "yaml" else [".json"]
    for suffix in suffixes:
        for path in sorted(groups_dir.rglob(f"*{suffix}")):
            if path.is_file():
                yield path


def _load_group_file(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)

    if not isinstance(data, dict):
        raise ValueError(f"Expected object/dict in {path}, got {type(data).__name__}")
    return data


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


def _diff_group_ip_entries(baseline_group: Optional[dict], desired_group: dict) -> Dict[str, List[str]]:
    baseline_entries = set(_extract_ip_address_entries(baseline_group or {}))
    desired_entries = set(_extract_ip_address_entries(desired_group))

    return {
        "baseline": sorted(baseline_entries),
        "desired": sorted(desired_entries),
        "to_add": sorted(desired_entries - baseline_entries),
        "already_present": sorted(desired_entries & baseline_entries),
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


def _action_word(add_count: int) -> str:
    return "ADD" if add_count > 0 else "NO-CHANGE"


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


def _write_validation_report(
    records: list,
    *,
    target: str,
    domain_id: str,
    run_ts: str,
    output_base: Path,
) -> Path:
    _ensure_dir(output_base, label="Validation base")
    run_dir = output_base / f"{run_ts}_{target}_validate"
    _ensure_dir(run_dir, label="Validation run")

    out = {
        "run_ts": run_ts,
        "target": target,
        "domain_id": domain_id,
        "groups_validated": len(records),
        "groups_missing_in_baseline": sum(1 for r in records if not r["exists_in_baseline"]),
        "groups_with_additions": sum(1 for r in records if r["to_add_count"] > 0),
        "groups_with_no_delta": sum(
            1
            for r in records
            if r["exists_in_baseline"] and r["to_add_count"] == 0
        ),
        "groups": records,
    }

    report_file = run_dir / "validation_report.json"
    report_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
    log.info("Validation report file written successfully: %s", report_file.resolve())
    return report_file


def _log_group_state(
    *,
    phase_label: str,
    index: int,
    total: int,
    group_id: Optional[str],
    display_name: str,
    baseline_path: Optional[str],
    exists_in_baseline: bool,
    current_entries: Optional[List[str]],
    to_add: List[str],
) -> None:
    action = _action_word(len(to_add))

    if total > 0:
        prefix = f"[{phase_label} {index}/{total}]"
    else:
        prefix = f"[{phase_label} {index}]"

    if exists_in_baseline:
        log.info(
            "%s group=%s display_name=%s baseline=yes action=%s current=%d add=%d",
            prefix,
            group_id,
            display_name,
            action,
            len(current_entries or []),
            len(to_add),
        )
        log.info("  [CURRENT EXISTS] %s", _format_entries(current_entries))
    else:
        log.warning(
            "%s group=%s display_name=%s baseline=no%s action=%s current=unknown add=%d",
            prefix,
            group_id,
            display_name,
            f" baseline_path={baseline_path}" if baseline_path else "",
            action,
            len(to_add),
        )
        log.info("  [CURRENT EXISTS] [unknown]")

    log.info("  [ADD]            %s", _format_entries(to_add))


def _build_baseline_index(baseline_groups_dir: Path, input_format: str) -> Dict[str, dict]:
    """
    Build a simple baseline index by group id from nsx_export.
    First match wins unless duplicate ids exist, in which case later file replaces earlier file.
    """
    index: Dict[str, dict] = {}

    if not baseline_groups_dir.exists():
        raise RuntimeError(f"Baseline groups directory does not exist: {baseline_groups_dir}")

    log.info("Building baseline index from: %s", baseline_groups_dir.resolve())

    for group_file in _iter_group_files(baseline_groups_dir, input_format):
        try:
            payload = _load_group_file(group_file)
        except Exception as exc:
            log.warning("Skipping unreadable baseline file %s: %s", group_file, exc)
            continue

        group_id = payload.get("id")
        if not isinstance(group_id, str) or not group_id.strip():
            log.warning("Skipping baseline file with missing id: %s", group_file)
            continue

        payload["_baseline_file"] = str(group_file)
        index[group_id] = payload

    log.info("Baseline index build complete: %d groups indexed", len(index))
    return index


def _validate_groups_against_baseline(
    *,
    desired_groups_dir: Path,
    baseline_groups_dir: Path,
    input_format: str,
) -> list:
    """
    File-to-file comparison only.
    No live NSX lookup.
    No fallback matching.
    No removal logic.
    Additive review only.
    """
    records: list = []
    desired_files = list(_iter_group_files(desired_groups_dir, input_format))
    last_check_ts = 0.0

    baseline_index = _build_baseline_index(baseline_groups_dir, input_format)

    log.info("Validation pass: discovered %d desired group files under %s", len(desired_files), desired_groups_dir)
    log.info("Baseline comparison dir: %s", baseline_groups_dir)
    log.info("Baseline index size: %d groups", len(baseline_index))
    log.info(
        "Validation pacing: GROUP_PATCH_INTERVAL_SECONDS=%s PROMPT_EVERY_N_UPDATES=%s",
        GROUP_PATCH_INTERVAL_SECONDS,
        PROMPT_EVERY_N_UPDATES,
    )

    for idx, desired_group_file in enumerate(desired_files, start=1):
        try:
            desired_payload = _load_group_file(desired_group_file)
        except Exception as exc:
            log.exception(
                "[VALIDATE %d/%d] file=%s failed to load: %s",
                idx,
                len(desired_files),
                desired_group_file,
                exc,
            )
            records.append(
                {
                    "file": str(desired_group_file),
                    "group_id": None,
                    "display_name": desired_group_file.stem,
                    "exists_in_baseline": False,
                    "error": f"file load failed: {exc}",
                    "baseline_file": None,
                    "current_entries": None,
                    "current_count": None,
                    "to_add": [],
                    "to_add_count": 0,
                    "action": "ERROR",
                }
            )
            last_check_ts = _controlled_checkpoint(
                processed_count=idx,
                last_ts=last_check_ts,
                phase="dry-run validation checks",
            )
            continue

        group_id = desired_payload.get("id")
        display_name = desired_payload.get("display_name") or desired_payload.get("name") or group_id or desired_group_file.stem
        desired_entries = sorted(set(_extract_ip_address_entries(desired_payload)))

        if not group_id or not isinstance(group_id, str):
            log.warning(
                "[VALIDATE %d/%d] file=%s has no group id; cannot compare to baseline",
                idx,
                len(desired_files),
                desired_group_file,
            )
            log.info("  [CURRENT EXISTS] [unknown]")
            log.info("  [ADD]            %s", _format_entries(desired_entries))
            records.append(
                {
                    "file": str(desired_group_file),
                    "group_id": None,
                    "display_name": display_name,
                    "exists_in_baseline": False,
                    "error": "missing id in file",
                    "baseline_file": None,
                    "current_entries": None,
                    "current_count": None,
                    "to_add": desired_entries,
                    "to_add_count": len(desired_entries),
                    "action": "UNKNOWN",
                }
            )
            last_check_ts = _controlled_checkpoint(
                processed_count=idx,
                last_ts=last_check_ts,
                phase="dry-run validation checks",
            )
            continue

        baseline_payload = baseline_index.get(group_id)
        exists_in_baseline = baseline_payload is not None
        baseline_file = baseline_payload.get("_baseline_file") if baseline_payload else None

        if exists_in_baseline:
            diff = _diff_group_ip_entries(baseline_payload, desired_payload)
            current_entries = diff["baseline"]
            to_add = diff["to_add"]

            _log_group_state(
                phase_label="VALIDATE",
                index=idx,
                total=len(desired_files),
                group_id=group_id,
                display_name=display_name,
                baseline_path=baseline_file,
                exists_in_baseline=True,
                current_entries=current_entries,
                to_add=to_add,
            )

            records.append(
                {
                    "file": str(desired_group_file),
                    "group_id": group_id,
                    "display_name": display_name,
                    "exists_in_baseline": True,
                    "baseline_file": baseline_file,
                    "current_entries": current_entries,
                    "current_count": len(current_entries),
                    "desired_count": len(diff["desired"]),
                    "to_add": to_add,
                    "to_add_count": len(to_add),
                    "already_present": diff["already_present"],
                    "already_present_count": len(diff["already_present"]),
                    "action": _action_word(len(to_add)),
                }
            )
        else:
            _log_group_state(
                phase_label="VALIDATE",
                index=idx,
                total=len(desired_files),
                group_id=group_id,
                display_name=display_name,
                baseline_path=baseline_file,
                exists_in_baseline=False,
                current_entries=None,
                to_add=desired_entries,
            )

            records.append(
                {
                    "file": str(desired_group_file),
                    "group_id": group_id,
                    "display_name": display_name,
                    "exists_in_baseline": False,
                    "baseline_file": None,
                    "current_entries": None,
                    "current_count": None,
                    "desired_count": len(desired_entries),
                    "to_add": desired_entries,
                    "to_add_count": len(desired_entries),
                    "already_present": [],
                    "already_present_count": 0,
                    "action": "UNKNOWN",
                }
            )

        last_check_ts = _controlled_checkpoint(
            processed_count=idx,
            last_ts=last_check_ts,
            phase="dry-run validation checks",
        )

    return records


def _client_get_json(client: Any, path: str) -> Optional[dict]:
    """
    Best-effort reader across likely client implementations.
    Returns None on 404/not-found style conditions.
    Raises on unexpected failures.
    """
    for method_name in ("_get", "get"):
        method = getattr(client, method_name, None)
        if callable(method):
            try:
                result = method(path)
                return result if isinstance(result, dict) else result
            except Exception as exc:
                msg = str(exc).lower()
                if "404" in msg or "not found" in msg:
                    return None
                raise

    for method_name in ("_request", "request"):
        method = getattr(client, method_name, None)
        if callable(method):
            try:
                result = method("GET", path)
                return result if isinstance(result, dict) else result
            except Exception as exc:
                msg = str(exc).lower()
                if "404" in msg or "not found" in msg:
                    return None
                raise

    raise RuntimeError("NsxPolicyClient does not expose a usable GET/_get/_request method.")


def _group_policy_path(*, domain_id: str, group_id: str, federation_global: bool) -> str:
    prefix = "/global-infra" if federation_global else "/infra"
    encoded_group_id = group_id
    try:
        from urllib.parse import quote
        encoded_group_id = quote(group_id, safe="")
    except Exception:
        encoded_group_id = group_id
    return f"{prefix}/domains/{domain_id}/groups/{encoded_group_id}"


def _wrap_group_patch_controls(
    client: NsxPolicyClient,
    *,
    dry_run: bool,
    baseline_groups_dir: Path,
    input_format: str,
) -> None:
    """
    File-to-file baseline comparison for CLI visibility.
    No fallback matching.
    No removal logic.
    Additive review only.
    """
    if dry_run:
        log.info("Dry-run mode: PATCH wrapper not applied. Validation pass provides paced review.")
        return

    if getattr(client, "_group_patch_controls_wrapped", False):
        log.info("PATCH controls already wrapped on client; skipping duplicate wrap.")
        return

    if not hasattr(client, "_patch"):
        raise RuntimeError("NsxPolicyClient has no _patch method to wrap.")

    orig_patch = client._patch
    baseline_index = _build_baseline_index(baseline_groups_dir, input_format)

    state = {
        "last_patch_ts": 0.0,
        "applied_count": 0,
        "skipped_count": 0,
    }

    log.info(
        "Apply pacing: GROUP_PATCH_INTERVAL_SECONDS=%s PROMPT_EVERY_N_UPDATES=%s",
        GROUP_PATCH_INTERVAL_SECONDS,
        PROMPT_EVERY_N_UPDATES,
    )
    log.info("Apply baseline comparison dir: %s", baseline_groups_dir)
    log.info("Apply baseline index size: %d groups", len(baseline_index))

    def controlled_patch(path, payload, *args, **kwargs):
        now = time.monotonic()
        wait = GROUP_PATCH_INTERVAL_SECONDS - (now - state["last_patch_ts"])
        if wait > 0:
            log.info("apply updates throttle: waiting %.3f seconds before next item", wait)
            time.sleep(wait)

        group_id = None
        display_name = None
        if isinstance(payload, dict):
            group_id = payload.get("id")
            display_name = payload.get("display_name") or payload.get("name") or group_id

        desired_entries = sorted(set(_extract_ip_address_entries(payload if isinstance(payload, dict) else {})))
        baseline_payload = baseline_index.get(group_id) if isinstance(group_id, str) else None
        baseline_file = baseline_payload.get("_baseline_file") if baseline_payload else None

        if baseline_payload is not None and isinstance(payload, dict):
            diff_before = _diff_group_ip_entries(baseline_payload, payload)
            current_entries = diff_before["baseline"]
            to_add_before = diff_before["to_add"]

            _log_group_state(
                phase_label="PATCH",
                index=state["applied_count"] + state["skipped_count"] + 1,
                total=0,
                group_id=group_id,
                display_name=display_name or str(group_id),
                baseline_path=baseline_file,
                exists_in_baseline=True,
                current_entries=current_entries,
                to_add=to_add_before,
            )
        else:
            _log_group_state(
                phase_label="PATCH",
                index=state["applied_count"] + state["skipped_count"] + 1,
                total=0,
                group_id=group_id,
                display_name=display_name or str(group_id),
                baseline_path=baseline_file,
                exists_in_baseline=False,
                current_entries=None,
                to_add=desired_entries,
            )

        decision = _prompt_apply_item(
            group_id=group_id,
            display_name=display_name or str(group_id),
        )

        if decision == "skip":
            state["skipped_count"] += 1
            state["last_patch_ts"] = time.monotonic()
            log.info(
                "Skipped group update #%d%s%s skipped_total=%d",
                state["applied_count"] + state["skipped_count"],
                f" (id={group_id})" if group_id else "",
                f" (display_name={display_name})" if display_name else "",
                state["skipped_count"],
            )
            return {
                "skipped": True,
                "path": path,
                "group_id": group_id,
                "display_name": display_name,
            }

        if decision == "abort":
            raise KeyboardInterrupt(
                f"Stopped by operator at group id={group_id} display_name={display_name}."
            )

        response = orig_patch(path, payload, *args, **kwargs)

        state["last_patch_ts"] = time.monotonic()
        state["applied_count"] += 1

        try:
            live_after = _client_get_json(client, path)
            if live_after is not None and isinstance(payload, dict):
                live_after_entries = sorted(set(_extract_ip_address_entries(live_after)))
                remaining_add = sorted(set(desired_entries) - set(live_after_entries))
                log.info(
                    "Applied group update #%d%s%s remaining_add=%d applied_total=%d skipped_total=%d",
                    state["applied_count"] + state["skipped_count"],
                    f" (id={group_id})" if group_id else "",
                    f" (display_name={display_name})" if display_name else "",
                    len(remaining_add),
                    state["applied_count"],
                    state["skipped_count"],
                )
                log.info("  [POST CURRENT]    %s", _format_entries(live_after_entries))
                log.info("  [POST ADD]        %s", _format_entries(remaining_add))
            else:
                log.info(
                    "Applied group update #%d%s%s post-check current state unavailable applied_total=%d skipped_total=%d",
                    state["applied_count"] + state["skipped_count"],
                    f" (id={group_id})" if group_id else "",
                    f" (display_name={display_name})" if display_name else "",
                    state["applied_count"],
                    state["skipped_count"],
                )
                log.info("  [POST CURRENT]    [unknown]")
                log.info("  [POST ADD]        [unknown]")
        except Exception as exc:
            log.warning(
                "Applied group update #%d%s but post-check lookup failed: %s",
                state["applied_count"] + state["skipped_count"],
                f" (id={group_id})" if group_id else "",
                exc,
            )

        if PROMPT_EVERY_N_UPDATES > 0 and state["applied_count"] % PROMPT_EVERY_N_UPDATES == 0:
            _prompt_to_continue(state["applied_count"], phase="apply updates")

        return response

    client._patch = controlled_patch  # type: ignore[attr-defined]
    setattr(client, "_group_patch_controls_wrapped", True)

    log.info("Enabled group PATCH controls using global pacing constants.")


def _write_snapshot(
    snapshots: list,
    *,
    target: str,
    domain_id: str,
    dry_run: bool,
    run_ts: str,
    snapshots_base: Path,
) -> Path:
    mode = "dryrun" if dry_run else "apply"
    _ensure_dir(snapshots_base, label="Snapshot base")
    run_dir = snapshots_base / f"{run_ts}_{target}_{mode}"
    _ensure_dir(run_dir, label="Snapshot run")

    out = {
        "run_ts": run_ts,
        "target": target,
        "domain_id": domain_id,
        "mode": mode,
        "groups_snapshotted": len(snapshots),
        "groups": snapshots,
    }

    snapshot_file = run_dir / "snapshot.json"
    snapshot_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
    log.info("Snapshot file written successfully: %s", snapshot_file.resolve())
    return snapshot_file


def main() -> None:
    global log

    parser = argparse.ArgumentParser(
        description="Push NSX Group updates from files using nsx_export as the additive-only baseline for review logging."
    )

    parser.add_argument(
        "--target",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        required=True,
        help="NSX manager to push groups into.",
    )

    parser.add_argument(
        "--input-dir",
        type=Path,
        default=_default_input_dir(),
        help=f"Root folder containing desired additive groups (default: <repo>/{DEFAULT_INPUT_DIR}).",
    )

    parser.add_argument(
        "--baseline-dir",
        type=Path,
        default=_default_baseline_dir(),
        help=f"Root folder containing baseline exported groups (default: <repo>/{DEFAULT_BASELINE_DIR}).",
    )

    parser.add_argument(
        "--domain-id",
        default="default",
        choices=["default", nsx_gm1, nsx_gm2, nsx_lm1, nsx_lm2, nsx_lm3, nsx_lm4],
        help="Domain ID to operate on (default: default).",
    )

    parser.add_argument("--input-format", choices=["yaml", "json"], default="yaml")
    parser.add_argument("--apply", action="store_true", help="Actually push changes. Default is dry-run.")
    parser.add_argument("--stop-on-error", action="store_true", help="Stop on first error.")
    parser.add_argument("--federation-global", action="store_true", help="Use GM global endpoints (global-infra).")
    parser.add_argument(
        "--skip-baseline-validate",
        action="store_true",
        help="Skip preflight validation of desired groups against the baseline export directory.",
    )

    args = parser.parse_args()
    init_cli()
    log = setup_logging()

    mgr_map = _build_mgr_map()
    dst_mgr = mgr_map.get(args.target)
    if not dst_mgr:
        raise RuntimeError(f"Target manager env var not set for {args.target}. Check your .env / constants.")

    input_dir: Path = args.input_dir
    baseline_dir: Path = args.baseline_dir

    if not input_dir.exists():
        raise RuntimeError(f"Input directory does not exist: {input_dir}")
    if not baseline_dir.exists():
        raise RuntimeError(f"Baseline directory does not exist: {baseline_dir}")

    selected_root = _select_input_root_for_target(input_dir, dst_mgr)
    selected_baseline_root = _select_baseline_root_for_target(baseline_dir, dst_mgr)

    if selected_root != input_dir:
        log.info("Selected desired manager subtree for %s: %s", args.target, selected_root.resolve())
    else:
        log.info("Using desired input-dir as provided (no manager subtree match found): %s", selected_root.resolve())

    if selected_baseline_root != baseline_dir:
        log.info("Selected baseline manager subtree for %s: %s", args.target, selected_baseline_root.resolve())
    else:
        log.info("Using baseline-dir as provided (no manager subtree match found): %s", selected_baseline_root.resolve())

    desired_domain_root = _find_domain_root(selected_root)
    desired_groups_dir = _resolve_groups_dir(desired_domain_root, args.domain_id)

    baseline_domain_root = _find_domain_root(selected_baseline_root)
    baseline_groups_dir = _resolve_groups_dir(baseline_domain_root, args.domain_id)

    log.info("Starting push_nsx_groups")
    log.info("Target:                        %s (%s)", args.target, dst_mgr)
    log.info("Federation GM:                 %s", args.federation_global)
    log.info("Mode:                          %s", "APPLY" if args.apply else "DRY-RUN")
    log.info("Desired input dir:             %s", input_dir.resolve())
    log.info("Desired selected root:         %s", selected_root.resolve())
    log.info("Desired domain root:           %s", desired_domain_root.resolve())
    log.info("Desired groups dir:            %s", desired_groups_dir.resolve())
    log.info("Baseline dir:                  %s", baseline_dir.resolve())
    log.info("Baseline selected root:        %s", selected_baseline_root.resolve())
    log.info("Baseline domain root:          %s", baseline_domain_root.resolve())
    log.info("Baseline groups dir:           %s", baseline_groups_dir.resolve())
    log.info("Domain ID:                     %s", args.domain_id)
    log.info("Input format:                  %s", args.input_format)
    log.info("Stop on error:                 %s", args.stop_on_error)
    log.info("Skip baseline validation:      %s", args.skip_baseline_validate)
    log.info("GROUP_PATCH_INTERVAL_SECONDS:  %s", GROUP_PATCH_INTERVAL_SECONDS)
    log.info("PROMPT_EVERY_N_UPDATES:        %s", PROMPT_EVERY_N_UPDATES)
    log.info("Resolved log dir:              %s", _resolve_log_dir())

    client = NsxPolicyClient(nsxmanager=dst_mgr, federation_global=args.federation_global)
    run_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    validation_records: list = []
    if not args.skip_baseline_validate:
        validation_records = _validate_groups_against_baseline(
            desired_groups_dir=desired_groups_dir,
            baseline_groups_dir=baseline_groups_dir,
            input_format=args.input_format,
        )
        validation_base = _resolve_log_dir() / "nsx_validation"
        validation_file = _write_validation_report(
            validation_records,
            target=args.target,
            domain_id=args.domain_id,
            run_ts=run_ts,
            output_base=validation_base,
        )
        log.info("Validation report written: %s", validation_file)

        missing = [r for r in validation_records if not r.get("exists_in_baseline")]
        with_additions = [r for r in validation_records if r.get("to_add_count", 0) > 0]

        log.info(
            "Validation summary: total=%d missing_in_baseline=%d with_additions=%d no_delta=%d",
            len(validation_records),
            len(missing),
            len(with_additions),
            sum(
                1
                for r in validation_records
                if r.get("exists_in_baseline") and r.get("to_add_count", 0) == 0
            ),
        )

        if missing:
            log.warning(
                "Validation found %d group file(s) that could not be resolved in the baseline export. "
                "This script does not do fallback matching.",
                len(missing),
            )

    _wrap_group_patch_controls(
        client,
        dry_run=(not args.apply),
        baseline_groups_dir=baseline_groups_dir,
        input_format=args.input_format,
    )

    cfg = GroupImportConfig(
        export_root=desired_domain_root,
        domain_id=args.domain_id,
        input_format=args.input_format,
        dry_run=(not args.apply),
        continue_on_error=(not args.stop_on_error),
        mode="groups_only",
    )

    importer = NsxGroupImporter(client=client, cfg=cfg)

    try:
        result = importer.import_all()
    except KeyboardInterrupt as exc:
        log.warning("Push interrupted by operator: %s", exc)
        raise SystemExit(130)

    log.info("Push complete. Stats=%s Errors=%d", result.get("stats"), len(result.get("errors", [])))

    snapshots = result.get("snapshots", [])
    if snapshots:
        snapshots_base = _resolve_log_dir() / "nsx_snapshots"
        snapshot_file = _write_snapshot(
            snapshots,
            target=args.target,
            domain_id=args.domain_id,
            dry_run=(not args.apply),
            run_ts=run_ts,
            snapshots_base=snapshots_base,
        )
        log.info("Snapshot written: %s", snapshot_file)
    else:
        log.info("No groups snapshotted (nothing matched or all skipped).")

    log.info("Final stats: %s", result.get("stats"))
    log.info("push_nsx_groups finished successfully.")


if __name__ == "__main__":
    main()