#!/usr/bin/env python3
"""
tools/nsx/validate_nsx_groups.py

Validate NSX Policy groups against an expected on-disk group set and show:
- what currently exists in NSX
- what is expected from file
- what is missing from NSX
- what is extra in NSX

This is a validation-only script. It does not PATCH or DELETE anything.

Typical use cases:

1) Validate additive results after push
   python tools/nsx/validate_nsx_groups.py \
     --target nsx-gm2 \
     --expected-root nsx_groups_additive/nsx-gm2.lab.local \
     --baseline-root nsx_export/nsx-gm2.lab.local \
     --domain-id default \
     --federation-global

   In this mode:
   expected = baseline + additive additions
   live NSX should match that merged result

2) Validate rollback results after revert
   python tools/nsx/validate_nsx_groups.py \
     --target nsx-gm2 \
     --expected-root nsx_export/nsx-gm2.lab.local \
     --domain-id default \
     --federation-global

   In this mode:
   expected = export snapshot directly
   live NSX should match snapshot

Notes:
- This script is validation-only.
- No fallback search by display name.
- Direct matching is by group id.
- You can pace validation with:
    GROUP_PATCH_INTERVAL_SECONDS
    PROMPT_EVERY_N_UPDATES
"""
from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_log_dir, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient

REPO_ROOT = Path(__file__).resolve().parents[2]

GROUP_PATCH_INTERVAL_SECONDS = 1.0
PROMPT_EVERY_N_UPDATES = 1

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
    "_baseline_file",
}


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    log_dir = Path(nsx_log_dir) if nsx_log_dir else REPO_ROOT / "nsx_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "validate_nsx_groups.log"

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
    logging.getLogger(__name__).info("Log file: %s", log_file)


log = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def load_file(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def clean_payload(obj: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in obj.items() if k not in DEFAULT_STRIP_KEYS and k not in LOCAL_ONLY_KEYS}


def _manager_dirname(manager_host: str) -> str:
    return manager_host.replace("https://", "").rstrip("/")


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


def _select_root_for_target(root_dir: Path, target_manager_host: str) -> Path:
    target_name = _manager_dirname(target_manager_host)

    if root_dir.name == target_name:
        return root_dir

    candidate = root_dir / target_name
    if candidate.is_dir():
        return candidate

    return root_dir


def _iter_group_files(groups_dir: Path) -> Iterable[Path]:
    for suffix in (".yaml", ".yml", ".json"):
        for path in sorted(groups_dir.rglob(f"*{suffix}")):
            if path.is_file():
                yield path


def _extract_ip_address_entries(node: Any) -> List[str]:
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


def _normalized_entries(node: Any) -> List[str]:
    return sorted(set(_extract_ip_address_entries(node)))


def _format_entries(entries: Optional[List[str]], *, max_items: int = 200) -> str:
    if entries is None:
        return "[unknown]"

    if not entries:
        return "[]"

    if len(entries) <= max_items:
        return "[" + ", ".join(entries) + "]"

    shown = entries[:max_items]
    return "[" + ", ".join(shown) + f", ... +{len(entries) - max_items} more]"


def _controlled_checkpoint(*, processed_count: int, last_ts: float, phase: str) -> float:
    now = time.monotonic()
    wait = GROUP_PATCH_INTERVAL_SECONDS - (now - last_ts)
    if wait > 0:
        log.info("%s throttle: waiting %.3f seconds before next item", phase, wait)
        time.sleep(wait)

    new_ts = time.monotonic()

    if PROMPT_EVERY_N_UPDATES > 0 and processed_count % PROMPT_EVERY_N_UPDATES == 0:
        while True:
            answer = input(
                f"\nProcessed {processed_count} {phase}. Continue with next item? [y/N]: "
            ).strip().lower()

            if answer in ("y", "yes"):
                log.info("Operator chose to continue after %d %s.", processed_count, phase)
                break

            if answer in ("", "n", "no"):
                log.warning("Operator aborted after %d %s.", processed_count, phase)
                raise KeyboardInterrupt(f"Stopped by operator after {processed_count} {phase}.")

            print("Please enter 'y' or 'n'.")

    return new_ts


def _load_groups_from_root(root_dir: Path, domain_id: str) -> Dict[str, Dict[str, Any]]:
    if not root_dir.exists():
        raise RuntimeError(f"Directory does not exist: {root_dir}")

    selected_root = root_dir
    domain_root = _find_domain_root(selected_root)
    groups_dir = _resolve_groups_dir(domain_root, domain_id)

    if not groups_dir.exists():
        raise RuntimeError(f"Groups directory does not exist: {groups_dir}")

    groups: Dict[str, Dict[str, Any]] = {}
    for path in _iter_group_files(groups_dir):
        obj = load_file(path)
        if not obj:
            continue
        group_id = obj.get("id")
        if not group_id:
            log.warning("Skipping %s — no id field", path)
            continue

        cleaned = clean_payload(obj)
        cleaned["_source_file"] = str(path)
        groups[group_id] = cleaned

    return groups


def _merge_additive_expected(
    baseline_groups: Dict[str, Dict[str, Any]],
    additive_groups: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """
    Build expected payloads for additive validation:
    expected entries = baseline entries UNION additive entries

    Non-IP structure is left based on additive file when present, otherwise baseline.
    IPAddressExpression ip_addresses are merged by union.
    """
    merged: Dict[str, Dict[str, Any]] = {}

    all_ids = sorted(set(baseline_groups.keys()) | set(additive_groups.keys()))
    for gid in all_ids:
        baseline = baseline_groups.get(gid)
        additive = additive_groups.get(gid)

        if baseline and additive:
            merged_payload = dict(additive)
            baseline_entries = set(_normalized_entries(baseline))
            additive_entries = set(_normalized_entries(additive))
            union_entries = sorted(baseline_entries | additive_entries)
            merged_payload["_expected_entries"] = union_entries
            merged_payload["_source_file"] = additive.get("_source_file")
            merged_payload["_baseline_file"] = baseline.get("_source_file")
            merged[gid] = merged_payload
        elif additive:
            merged_payload = dict(additive)
            merged_payload["_expected_entries"] = _normalized_entries(additive)
            merged_payload["_source_file"] = additive.get("_source_file")
            merged[gid] = merged_payload
        else:
            merged_payload = dict(baseline)
            merged_payload["_expected_entries"] = _normalized_entries(baseline)
            merged_payload["_source_file"] = baseline.get("_source_file")
            merged[gid] = merged_payload

    return merged


def _expected_entries_from_group(group: Dict[str, Any]) -> List[str]:
    explicit = group.get("_expected_entries")
    if isinstance(explicit, list):
        return sorted(set(v for v in explicit if isinstance(v, str)))
    return _normalized_entries(group)


def _diff_expected_vs_live(expected_group: Dict[str, Any], live_group: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    expected_entries = set(_expected_entries_from_group(expected_group))
    live_entries = set(_normalized_entries(live_group or {}))

    return {
        "expected": sorted(expected_entries),
        "live": sorted(live_entries),
        "missing_in_nsx": sorted(expected_entries - live_entries),
        "extra_in_nsx": sorted(live_entries - expected_entries),
        "matched": sorted(expected_entries & live_entries),
    }


def _log_validation_state(
    *,
    index: int,
    total: int,
    group_id: str,
    display_name: str,
    exists_in_nsx: bool,
    live_entries: Optional[List[str]],
    expected_entries: List[str],
    missing_in_nsx: List[str],
    extra_in_nsx: List[str],
    source_file: Optional[str],
    baseline_file: Optional[str],
) -> None:
    if not exists_in_nsx:
        action = "MISSING-GROUP"
    elif missing_in_nsx and extra_in_nsx:
        action = "MISMATCH"
    elif missing_in_nsx:
        action = "MISSING-EXPECTED"
    elif extra_in_nsx:
        action = "EXTRA-IN-NSX"
    else:
        action = "MATCH"

    log.info(
        "[VALIDATE %d/%d] group=%s display_name=%s exists_in_nsx=%s result=%s current=%s expected=%d missing=%d extra=%d%s%s",
        index,
        total,
        group_id,
        display_name,
        "yes" if exists_in_nsx else "no",
        action,
        len(live_entries) if live_entries is not None else "unknown",
        len(expected_entries),
        len(missing_in_nsx),
        len(extra_in_nsx),
        f" source_file={source_file}" if source_file else "",
        f" baseline_file={baseline_file}" if baseline_file else "",
    )
    log.info("  [CURRENT EXISTS]   %s", _format_entries(live_entries))
    log.info("  [EXPECTED]         %s", _format_entries(expected_entries))
    log.info("  [MISSING IN NSX]   %s", _format_entries(missing_in_nsx))
    log.info("  [EXTRA IN NSX]     %s", _format_entries(extra_in_nsx))


def _write_validation_report(
    records: list,
    *,
    target: str,
    domain_id: str,
    run_ts: str,
    output_base: Path,
) -> Path:
    run_dir = output_base / f"{run_ts}_{target}_live_validate"
    run_dir.mkdir(parents=True, exist_ok=True)

    out = {
        "run_ts": run_ts,
        "target": target,
        "domain_id": domain_id,
        "groups_validated": len(records),
        "groups_missing_in_nsx": sum(1 for r in records if not r["exists_in_nsx"]),
        "groups_with_missing_expected": sum(1 for r in records if r["missing_in_nsx_count"] > 0),
        "groups_with_extra_in_nsx": sum(1 for r in records if r["extra_in_nsx_count"] > 0),
        "groups_exact_match": sum(
            1
            for r in records
            if r["exists_in_nsx"] and r["missing_in_nsx_count"] == 0 and r["extra_in_nsx_count"] == 0
        ),
        "groups": records,
    }

    report_file = run_dir / "validation_report.json"
    report_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
    return report_file


# -----------------------------------------------------------------------------
# Main validation
# -----------------------------------------------------------------------------

def validate_groups(
    client: NsxPolicyClient,
    *,
    expected_groups: Dict[str, Dict[str, Any]],
    domain_id: str,
    target: str,
    run_ts: str,
) -> None:
    existing_groups = client.list_groups(domain_id)
    existing = {g["id"]: g for g in existing_groups if "id" in g}

    ordered_ids = sorted(expected_groups.keys())
    records: List[Dict[str, Any]] = []
    last_ts = 0.0

    log.info("Validation target expected groups: %d", len(ordered_ids))
    log.info("Live NSX groups discovered: %d", len(existing))
    log.info("GROUP_PATCH_INTERVAL_SECONDS: %s", GROUP_PATCH_INTERVAL_SECONDS)
    log.info("PROMPT_EVERY_N_UPDATES: %s", PROMPT_EVERY_N_UPDATES)

    for idx, gid in enumerate(ordered_ids, start=1):
        expected_group = expected_groups[gid]
        display_name = expected_group.get("display_name") or expected_group.get("name") or gid
        source_file = expected_group.get("_source_file")
        baseline_file = expected_group.get("_baseline_file")

        live_group = existing.get(gid)
        diff = _diff_expected_vs_live(expected_group, live_group)

        live_entries = diff["live"] if live_group is not None else None
        expected_entries = diff["expected"]
        missing_in_nsx = diff["missing_in_nsx"] if live_group is not None else expected_entries
        extra_in_nsx = diff["extra_in_nsx"] if live_group is not None else []

        _log_validation_state(
            index=idx,
            total=len(ordered_ids),
            group_id=gid,
            display_name=display_name,
            exists_in_nsx=(live_group is not None),
            live_entries=live_entries,
            expected_entries=expected_entries,
            missing_in_nsx=missing_in_nsx,
            extra_in_nsx=extra_in_nsx,
            source_file=source_file,
            baseline_file=baseline_file,
        )

        records.append(
            {
                "group_id": gid,
                "display_name": display_name,
                "source_file": source_file,
                "baseline_file": baseline_file,
                "exists_in_nsx": live_group is not None,
                "current_entries": live_entries,
                "current_count": len(live_entries) if live_entries is not None else None,
                "expected_entries": expected_entries,
                "expected_count": len(expected_entries),
                "missing_in_nsx": missing_in_nsx,
                "missing_in_nsx_count": len(missing_in_nsx),
                "extra_in_nsx": extra_in_nsx,
                "extra_in_nsx_count": len(extra_in_nsx),
                "matched_entries": diff["matched"] if live_group is not None else [],
                "matched_count": len(diff["matched"]) if live_group is not None else 0,
            }
        )

        last_ts = _controlled_checkpoint(
            processed_count=idx,
            last_ts=last_ts,
            phase="live validation checks",
        )

    validation_base = Path(nsx_log_dir) / "nsx_validation"
    validation_file = _write_validation_report(
        records,
        target=target,
        domain_id=domain_id,
        run_ts=run_ts,
        output_base=validation_base,
    )
    log.info("Validation report written: %s", validation_file)

    log.info(
        "Validation summary: total=%d missing_groups=%d missing_expected=%d extra_in_nsx=%d exact_match=%d",
        len(records),
        sum(1 for r in records if not r["exists_in_nsx"]),
        sum(1 for r in records if r["missing_in_nsx_count"] > 0),
        sum(1 for r in records if r["extra_in_nsx_count"] > 0),
        sum(
            1
            for r in records
            if r["exists_in_nsx"] and r["missing_in_nsx_count"] == 0 and r["extra_in_nsx_count"] == 0
        ),
    )


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate live NSX groups against an expected group set from disk."
    )
    parser.add_argument(
        "--target",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        required=True,
        help="NSX manager to validate against.",
    )
    parser.add_argument(
        "--expected-root",
        required=True,
        help="Expected root folder (e.g. nsx_export/nsx-gm2.lab.local or nsx_groups_additive/nsx-gm2.lab.local).",
    )
    parser.add_argument(
        "--baseline-root",
        help="Optional baseline root for additive validation. When provided, expected entries = baseline UNION expected-root.",
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

    expected_root = Path(args.expected_root)
    if not expected_root.exists():
        raise SystemExit(f"Expected root does not exist: {expected_root}")

    selected_expected_root = _select_root_for_target(expected_root, manager_host)
    if selected_expected_root != expected_root:
        log.info("Selected expected manager subtree: %s", selected_expected_root.resolve())
    else:
        log.info("Using expected root as provided: %s", selected_expected_root.resolve())

    expected_groups = _load_groups_from_root(selected_expected_root, args.domain_id)

    if args.baseline_root:
        baseline_root = Path(args.baseline_root)
        if not baseline_root.exists():
            raise SystemExit(f"Baseline root does not exist: {baseline_root}")

        selected_baseline_root = _select_root_for_target(baseline_root, manager_host)
        if selected_baseline_root != baseline_root:
            log.info("Selected baseline manager subtree: %s", selected_baseline_root.resolve())
        else:
            log.info("Using baseline root as provided: %s", selected_baseline_root.resolve())

        baseline_groups = _load_groups_from_root(selected_baseline_root, args.domain_id)
        expected_groups = _merge_additive_expected(baseline_groups, expected_groups)
        log.info("Validation mode: additive merge (baseline UNION expected-root)")
    else:
        log.info("Validation mode: direct expected-root only")

    run_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    log.info("Starting validate_nsx_groups")
    log.info("Target:                        %s (%s)", args.target, manager_host)
    log.info("Expected root:                 %s", selected_expected_root.resolve())
    log.info("Baseline root:                 %s", Path(args.baseline_root).resolve() if args.baseline_root else "[none]")
    log.info("Domain ID:                     %s", args.domain_id)
    log.info("Federation GM:                 %s", args.federation_global)
    log.info("GROUP_PATCH_INTERVAL_SECONDS:  %s", GROUP_PATCH_INTERVAL_SECONDS)
    log.info("PROMPT_EVERY_N_UPDATES:        %s", PROMPT_EVERY_N_UPDATES)

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=args.federation_global)

    try:
        validate_groups(
            client=client,
            expected_groups=expected_groups,
            domain_id=args.domain_id,
            target=args.target,
            run_ts=run_ts,
        )
    except KeyboardInterrupt as exc:
        log.warning("Validation interrupted: %s", exc)
        raise SystemExit(130)


if __name__ == "__main__":
    main()