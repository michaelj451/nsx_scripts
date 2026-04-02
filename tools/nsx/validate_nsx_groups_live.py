#!/usr/bin/env python3
"""
tools/nsx/validate_nsx_groups_live.py

Validate live NSX groups against expected group files on disk.

What it checks:
- expected groups from disk vs live groups in NSX by id
- missing groups in NSX
- extra groups in NSX
- cleaned payload equality
- extracted IPAddressExpression entries equality

This is validation-only. It does not PATCH, PUT, or DELETE anything.

Examples:

1) Validate direct additive export tree against live NSX
   python tools/nsx/validate_nsx_groups_live.py \
     --target nsx-gm2 \
     --expected-root nsx_export_additive/nsx-gm2.lab.local \
     --domain-id default \
     --federation-global

2) Validate a manager subtree when root contains multiple managers
   python tools/nsx/validate_nsx_groups_live.py \
     --target nsx-lm3 \
     --expected-root nsx_export_additive \
     --domain-id default

Notes:
- Matching is by group id only
- No fallback search by display name
- No mutation of live NSX
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_log_dir, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient

REPO_ROOT = Path(__file__).resolve().parents[2]

GROUP_VALIDATE_INTERVAL_SECONDS = 0.0
PROMPT_EVERY_N_GROUPS = 0

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
    "path",
    "relative_path",
    "parent_path",
}

LOCAL_ONLY_KEYS = {
    "_source_file",
}

COMPARE_ONLY_KEYS = {
    "id",
    "display_name",
    "description",
    "expression",
    "extended_expression",
    "reference",
    "expression_type",
    "group_type",
    "resource_type",
    "tags",
    "scope",
    "category",
    "sequence_number",
}


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    log_dir = Path(nsx_log_dir) if nsx_log_dir else REPO_ROOT / "nsx_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "validate_nsx_groups_live.log"

    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")

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


def _manager_dirname(manager_host: str) -> str:
    return manager_host.replace("https://", "").rstrip("/")


def _find_domain_root(export_root: Path) -> Path:
    if (export_root / "domains").is_dir():
        return export_root

    direct_domain_layout = export_root / "default"
    if direct_domain_layout.is_dir():
        return export_root

    for sub in export_root.iterdir():
        if not sub.is_dir():
            continue
        if (sub / "domains").is_dir():
            return sub
        if (sub / "default").is_dir():
            return sub

    raise RuntimeError(
        "Could not find a valid domain layout. Expected either:\n"
        f"  1) {export_root}/domains/<domain-id>/groups\n"
        f"  2) {export_root}/<manager>/domains/<domain-id>/groups\n"
        f"  3) {export_root}/<domain-id>/groups\n"
        f"  4) {export_root}/<manager>/<domain-id>/groups"
    )


def _resolve_groups_dir(domain_root: Path, domain_id: str) -> Path:
    new_dir = domain_root / domain_id / "groups"
    old_dir = domain_root / "domains" / domain_id / "groups"

    if new_dir.is_dir():
        return new_dir
    if old_dir.is_dir():
        return old_dir

    return new_dir


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


def _strip_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if k in DEFAULT_STRIP_KEYS or k in LOCAL_ONLY_KEYS:
                continue
            out[k] = _strip_keys(v)
        return out
    if isinstance(obj, list):
        return [_strip_keys(v) for v in obj]
    return obj


def _normalize_tags(tags: Any) -> Any:
    if not isinstance(tags, list):
        return tags

    normalized: List[Dict[str, Any]] = []
    for item in tags:
        if isinstance(item, dict):
            normalized.append(
                {
                    "scope": item.get("scope"),
                    "tag": item.get("tag"),
                }
            )
        else:
            normalized.append(item)

    return sorted(
        normalized,
        key=lambda x: (
            x.get("scope") if isinstance(x, dict) else str(x),
            x.get("tag") if isinstance(x, dict) else str(x),
        ),
    )


def _normalize_ip_list(values: Any) -> List[str]:
    if not isinstance(values, list):
        return []
    return sorted(set(v.strip() for v in values if isinstance(v, str) and v.strip()))


def _normalize_structure(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if k == "tags":
                out[k] = _normalize_tags(v)
            elif k == "ip_addresses":
                out[k] = _normalize_ip_list(v)
            else:
                out[k] = _normalize_structure(v)
        return out

    if isinstance(obj, list):
        return [_normalize_structure(v) for v in obj]

    return obj


def clean_payload(obj: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = _strip_keys(obj)
    cleaned = _normalize_structure(cleaned)
    return cleaned


def _payload_subset_for_compare(obj: Dict[str, Any]) -> Dict[str, Any]:
    if not obj:
        return {}

    result: Dict[str, Any] = {}
    for key in COMPARE_ONLY_KEYS:
        if key in obj:
            result[key] = obj[key]
    return result


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
    return sorted(set(v for v in found if v))


def _jsonable(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2)


def _diff_dicts(expected: Any, live: Any, prefix: str = "") -> List[str]:
    diffs: List[str] = []

    if type(expected) != type(live):
        diffs.append(f"{prefix or '$'}: type mismatch expected={type(expected).__name__} live={type(live).__name__}")
        return diffs

    if isinstance(expected, dict):
        expected_keys = set(expected.keys())
        live_keys = set(live.keys())

        for key in sorted(expected_keys - live_keys):
            diffs.append(f"{prefix or '$'}.{key}: missing in live")
        for key in sorted(live_keys - expected_keys):
            diffs.append(f"{prefix or '$'}.{key}: extra in live")
        for key in sorted(expected_keys & live_keys):
            child_prefix = f"{prefix}.{key}" if prefix else key
            diffs.extend(_diff_dicts(expected[key], live[key], child_prefix))
        return diffs

    if isinstance(expected, list):
        if expected != live:
            diffs.append(
                f"{prefix or '$'}: list differs\n"
                f"  expected={_jsonable(expected)}\n"
                f"  live={_jsonable(live)}"
            )
        return diffs

    if expected != live:
        diffs.append(f"{prefix or '$'}: expected={expected!r} live={live!r}")

    return diffs


def _format_entries(entries: Optional[List[str]], *, max_items: int = 100) -> str:
    if entries is None:
        return "[unknown]"
    if not entries:
        return "[]"
    if len(entries) <= max_items:
        return "[" + ", ".join(entries) + "]"
    shown = entries[:max_items]
    return "[" + ", ".join(shown) + f", ... +{len(entries) - max_items} more]"


def _load_groups_from_root(root_dir: Path, domain_id: str) -> Dict[str, Dict[str, Any]]:
    if not root_dir.exists():
        raise RuntimeError(f"Directory does not exist: {root_dir}")

    domain_root = _find_domain_root(root_dir)
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


def _controlled_checkpoint(*, processed_count: int, last_ts: float) -> float:
    now = time.monotonic()
    wait = GROUP_VALIDATE_INTERVAL_SECONDS - (now - last_ts)
    if wait > 0:
        time.sleep(wait)

    new_ts = time.monotonic()

    if PROMPT_EVERY_N_GROUPS > 0 and processed_count % PROMPT_EVERY_N_GROUPS == 0:
        while True:
            answer = input(f"\nProcessed {processed_count} groups. Continue? [y/N]: ").strip().lower()
            if answer in ("y", "yes"):
                break
            if answer in ("", "n", "no"):
                raise KeyboardInterrupt(f"Stopped by operator after {processed_count} groups.")
            print("Please enter 'y' or 'n'.")

    return new_ts


def _write_validation_report(
    *,
    records: List[Dict[str, Any]],
    extra_live_groups: List[Dict[str, Any]],
    target: str,
    domain_id: str,
    run_ts: str,
    output_base: Path,
) -> Path:
    run_dir = output_base / f"{run_ts}_{target}_validate_live_groups"
    run_dir.mkdir(parents=True, exist_ok=True)

    report = {
        "run_ts": run_ts,
        "target": target,
        "domain_id": domain_id,
        "groups_expected": len(records),
        "groups_missing_in_nsx": sum(1 for r in records if not r["exists_in_nsx"]),
        "groups_payload_match": sum(1 for r in records if r["payload_match"] is True),
        "groups_ip_entries_match": sum(1 for r in records if r["ip_entries_match"] is True),
        "groups_with_payload_diff": sum(1 for r in records if r["payload_diff_count"] > 0),
        "groups_with_ip_diff": sum(
            1 for r in records if r["missing_ip_count"] > 0 or r["extra_ip_count"] > 0
        ),
        "extra_live_groups_count": len(extra_live_groups),
        "groups": records,
        "extra_live_groups": extra_live_groups,
    }

    report_file = run_dir / "validation_report.json"
    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report_file


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

def validate_groups(
    client: NsxPolicyClient,
    *,
    expected_groups: Dict[str, Dict[str, Any]],
    domain_id: str,
    target: str,
    run_ts: str,
) -> None:
    live_groups_raw = client.list_groups(domain_id)
    live_groups: Dict[str, Dict[str, Any]] = {}

    for item in live_groups_raw:
        group_id = item.get("id")
        if not group_id:
            continue
        live_groups[group_id] = clean_payload(item)

    expected_ids = set(expected_groups.keys())
    live_ids = set(live_groups.keys())

    extra_live_ids = sorted(live_ids - expected_ids)
    extra_live_groups = [
        {
            "group_id": gid,
            "display_name": live_groups[gid].get("display_name") or gid,
            "source": "live_nsx_only",
            "ip_entries": _extract_ip_address_entries(live_groups[gid]),
        }
        for gid in extra_live_ids
    ]

    ordered_ids = sorted(expected_ids)
    records: List[Dict[str, Any]] = []
    last_ts = 0.0

    log.info("Expected groups on disk: %d", len(expected_ids))
    log.info("Live NSX groups: %d", len(live_ids))
    log.info("Extra live groups not in expected set: %d", len(extra_live_ids))

    for idx, gid in enumerate(ordered_ids, start=1):
        expected_group = expected_groups[gid]
        live_group = live_groups.get(gid)

        display_name = expected_group.get("display_name") or expected_group.get("name") or gid
        source_file = expected_group.get("_source_file")

        if live_group is None:
            expected_ip_entries = _extract_ip_address_entries(expected_group)

            log.warning(
                "[%d/%d] MISSING GROUP: id=%s display_name=%s source_file=%s expected_ip_count=%d",
                idx,
                len(ordered_ids),
                gid,
                display_name,
                source_file,
                len(expected_ip_entries),
            )

            records.append(
                {
                    "group_id": gid,
                    "display_name": display_name,
                    "source_file": source_file,
                    "exists_in_nsx": False,
                    "payload_match": False,
                    "payload_diff_count": 1,
                    "payload_diffs": ["group missing in live NSX"],
                    "expected_ip_entries": expected_ip_entries,
                    "live_ip_entries": [],
                    "missing_ip_entries": expected_ip_entries,
                    "missing_ip_count": len(expected_ip_entries),
                    "extra_ip_entries": [],
                    "extra_ip_count": 0,
                    "ip_entries_match": False,
                }
            )

            last_ts = _controlled_checkpoint(processed_count=idx, last_ts=last_ts)
            continue

        expected_compare = _payload_subset_for_compare(expected_group)
        live_compare = _payload_subset_for_compare(live_group)

        payload_diffs = _diff_dicts(expected_compare, live_compare)
        payload_match = len(payload_diffs) == 0

        expected_ip_entries = _extract_ip_address_entries(expected_group)
        live_ip_entries = _extract_ip_address_entries(live_group)

        missing_ip_entries = sorted(set(expected_ip_entries) - set(live_ip_entries))
        extra_ip_entries = sorted(set(live_ip_entries) - set(expected_ip_entries))
        ip_entries_match = not missing_ip_entries and not extra_ip_entries

        if payload_match and ip_entries_match:
            result = "MATCH"
        elif not payload_match and not ip_entries_match:
            result = "PAYLOAD+IP-MISMATCH"
        elif not payload_match:
            result = "PAYLOAD-MISMATCH"
        else:
            result = "IP-MISMATCH"

        log.info(
            "[%d/%d] %s id=%s display_name=%s payload_diffs=%d expected_ip=%d live_ip=%d missing_ip=%d extra_ip=%d source_file=%s",
            idx,
            len(ordered_ids),
            result,
            gid,
            display_name,
            len(payload_diffs),
            len(expected_ip_entries),
            len(live_ip_entries),
            len(missing_ip_entries),
            len(extra_ip_entries),
            source_file,
        )

        if payload_diffs:
            for diff in payload_diffs[:50]:
                log.info("  [PAYLOAD DIFF] %s", diff)
            if len(payload_diffs) > 50:
                log.info("  [PAYLOAD DIFF] ... +%d more", len(payload_diffs) - 50)

        if missing_ip_entries or extra_ip_entries:
            log.info("  [EXPECTED IPs] %s", _format_entries(expected_ip_entries))
            log.info("  [LIVE IPs]     %s", _format_entries(live_ip_entries))
            log.info("  [MISSING IPs]  %s", _format_entries(missing_ip_entries))
            log.info("  [EXTRA IPs]    %s", _format_entries(extra_ip_entries))

        records.append(
            {
                "group_id": gid,
                "display_name": display_name,
                "source_file": source_file,
                "exists_in_nsx": True,
                "payload_match": payload_match,
                "payload_diff_count": len(payload_diffs),
                "payload_diffs": payload_diffs,
                "expected_ip_entries": expected_ip_entries,
                "live_ip_entries": live_ip_entries,
                "missing_ip_entries": missing_ip_entries,
                "missing_ip_count": len(missing_ip_entries),
                "extra_ip_entries": extra_ip_entries,
                "extra_ip_count": len(extra_ip_entries),
                "ip_entries_match": ip_entries_match,
            }
        )

        last_ts = _controlled_checkpoint(processed_count=idx, last_ts=last_ts)

    validation_base = Path(nsx_log_dir) / "nsx_validation"
    validation_file = _write_validation_report(
        records=records,
        extra_live_groups=extra_live_groups,
        target=target,
        domain_id=domain_id,
        run_ts=run_ts,
        output_base=validation_base,
    )

    log.info("Validation report written: %s", validation_file)
    log.info(
        "Summary: expected=%d missing_groups=%d payload_match=%d ip_match=%d payload_diff=%d ip_diff=%d extra_live=%d",
        len(records),
        sum(1 for r in records if not r["exists_in_nsx"]),
        sum(1 for r in records if r["payload_match"] is True),
        sum(1 for r in records if r["ip_entries_match"] is True),
        sum(1 for r in records if r["payload_diff_count"] > 0),
        sum(1 for r in records if r["missing_ip_count"] > 0 or r["extra_ip_count"] > 0),
        len(extra_live_groups),
    )


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate live NSX groups against expected group files on disk."
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
        help="Expected root folder, such as nsx_export_additive or nsx_export_additive/nsx-gm2.lab.local",
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
    run_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    log.info("Starting validate_nsx_groups_live")
    log.info("Target:                      %s (%s)", args.target, manager_host)
    log.info("Expected root:               %s", selected_expected_root.resolve())
    log.info("Domain ID:                   %s", args.domain_id)
    log.info("Federation GM:               %s", args.federation_global)
    log.info("GROUP_VALIDATE_INTERVAL:     %s", GROUP_VALIDATE_INTERVAL_SECONDS)
    log.info("PROMPT_EVERY_N_GROUPS:       %s", PROMPT_EVERY_N_GROUPS)

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