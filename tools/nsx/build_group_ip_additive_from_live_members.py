#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.nsx_policy_client import NsxPolicyClient

try:
    import yaml
except ImportError:
    yaml = None


log = logging.getLogger(__name__)


# =============================================================================
# Logging / Reports
# =============================================================================


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _setup_logging() -> Path:
    log_dir = Path(nsx_log_dir).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / f"build_group_ip_additive_from_live_members_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S UTC",
    )

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)

    root.addHandler(ch)
    root.addHandler(fh)

    log.info("Logging to %s", log_file)
    return log_file


def _default_reports_dir(output_groups_dir: Path) -> Path:
    # Expected layout:
    #   nsx_groups_additive/<manager>/domains/default/groups
    # Reports:
    #   nsx_groups_additive/<manager>/domains/default/reports/live-member-ip-additive
    if output_groups_dir.name == "groups":
        return output_groups_dir.parent / "reports" / "live-member-ip-additive"
    return output_groups_dir / "reports" / "live-member-ip-additive"


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


# =============================================================================
# File helpers
# =============================================================================


def load_file(path: Path) -> Dict[str, Any]:
    if path.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML is required")
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data if isinstance(data, dict) else {}

    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def write_file(path: Path, data: Dict[str, Any], output_format: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return

    if yaml is None:
        raise RuntimeError("PyYAML is required")

    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            data,
            f,
            sort_keys=True,
            default_flow_style=False,
            width=140,
            allow_unicode=True,
        )


def iter_group_files(groups_dir: Path) -> Iterable[Path]:
    for ext in ("*.yaml", "*.yml", "*.json"):
        yield from groups_dir.rglob(ext)


def normalize_ip_list(values: Any) -> List[str]:
    if not values:
        return []

    if isinstance(values, str):
        values = [values]

    if not isinstance(values, list):
        return []

    return sorted({str(v).strip() for v in values if str(v).strip()})


# =============================================================================
# Group expression logic
# =============================================================================


def ensure_ip_expression(group: Dict[str, Any], ips_to_add: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Add IPAddressExpression additively.

    NSX Policy API requires:
      operand OR operand

    So the expression list must be:
      Condition
      ConjunctionOperator OR
      IPAddressExpression
    """
    ips_to_add = sorted(set(ips_to_add))
    if not ips_to_add:
        return group, []

    expr = group.setdefault("expression", [])

    if not isinstance(expr, list):
        raise ValueError(f"Group expression is not a list for group {group.get('id')}")

    ip_expr = None
    existing_ips: Set[str] = set()

    for item in expr:
        if isinstance(item, dict) and item.get("resource_type") == "IPAddressExpression":
            ip_expr = item
            existing_ips.update(normalize_ip_list(item.get("ip_addresses")))
            break

    new_ips = sorted(ip for ip in ips_to_add if ip not in existing_ips)

    if not new_ips:
        return group, []

    if ip_expr is None:
        if expr:
            last = expr[-1]
            if not (
                isinstance(last, dict)
                and last.get("resource_type") == "ConjunctionOperator"
            ):
                expr.append(
                    {
                        "resource_type": "ConjunctionOperator",
                        "conjunction_operator": "OR",
                    }
                )

        expr.append(
            {
                "resource_type": "IPAddressExpression",
                "ip_addresses": new_ips,
            }
        )
    else:
        current = normalize_ip_list(ip_expr.get("ip_addresses"))
        ip_expr["ip_addresses"] = sorted(set(current + new_ips))

    return group, new_ips


# =============================================================================
# Main
# =============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Add evaluated VM member IPs from source NSX LM into exported group files for target NSX"
    )

    parser.add_argument(
        "--source-manager",
        required=True,
        choices=["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        help="Source Local Manager where current VM group membership and VIF IPs exist.",
    )

    parser.add_argument("--domain-id", default="default")

    parser.add_argument(
        "--source-groups-dir",
        required=True,
        help="Exported groups directory to copy/read. Usually old LM export groups.",
    )

    parser.add_argument(
        "--output-groups-dir",
        required=True,
        help="Destination additive groups directory for the new NSX manager.",
    )

    parser.add_argument(
        "--reports-dir",
        help="Optional reports directory. Default is beside output groups under reports/live-member-ip-additive.",
    )

    parser.add_argument(
        "--output-format",
        choices=["yaml", "json"],
        default="yaml",
    )

    parser.add_argument(
        "--copy-first",
        action="store_true",
        help="Copy source groups to output dir before modifying. Recommended.",
    )

    parser.add_argument(
        "--continue-on-group-error",
        action="store_true",
        help="Continue if one group membership lookup fails.",
    )

    args = parser.parse_args()

    init_cli()
    log_file = _setup_logging()

    source_host = resolve_manager(args.source_manager)
    if not source_host:
        raise RuntimeError(f"Manager not defined for {args.source_manager}")

    client = NsxPolicyClient(
        nsxmanager=source_host,
        federation_global=False,
    )

    source_groups_dir = Path(args.source_groups_dir).expanduser().resolve()
    output_groups_dir = Path(args.output_groups_dir).expanduser().resolve()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    reports_dir = (
        Path(args.reports_dir).expanduser().resolve()
        if args.reports_dir
        else (
            Path(nsx_log_dir).expanduser().resolve()
            / "build_group_ip_additive_from_live_members"
            / ts
        )
    )
    reports_dir.mkdir(parents=True, exist_ok=True)

    if not source_groups_dir.exists():
        raise RuntimeError(f"Source groups dir does not exist: {source_groups_dir}")

    log.info("Starting live member IP additive build")
    log.info("Source manager alias: %s", args.source_manager)
    log.info("Source manager host: %s", source_host)
    log.info("Domain ID: %s", args.domain_id)
    log.info("Source groups dir: %s", source_groups_dir)
    log.info("Output groups dir: %s", output_groups_dir)
    log.info("Reports dir: %s", reports_dir)
    log.info("Output format: %s", args.output_format)
    log.info("Copy first: %s", args.copy_first)
    log.info("Continue on group error: %s", args.continue_on_group_error)

    if args.copy_first:
        if output_groups_dir.exists():
            log.info("Deleting existing output dir: %s", output_groups_dir)
            shutil.rmtree(output_groups_dir)

        log.info("Copying groups: %s -> %s", source_groups_dir, output_groups_dir)
        shutil.copytree(source_groups_dir, output_groups_dir)
        working_groups_dir = output_groups_dir
    else:
        output_groups_dir.mkdir(parents=True, exist_ok=True)
        working_groups_dir = source_groups_dir

    log.info("Building VM IP index from source manager: %s", args.source_manager)
    vm_ip_index = client.build_vm_ip_index()
    log.info("VMs with discovered IPs: %d", len(vm_ip_index))

    group_files = sorted(iter_group_files(working_groups_dir))
    log.info("Group files found: %d", len(group_files))

    groups_seen = 0
    groups_changed = 0
    groups_no_members = 0
    groups_no_ips = 0
    groups_errors = 0
    groups_no_new_ips = 0
    ips_added_total = 0

    changed_rows: List[Dict[str, Any]] = []
    no_members_rows: List[Dict[str, Any]] = []
    no_ips_rows: List[Dict[str, Any]] = []
    no_new_ips_rows: List[Dict[str, Any]] = []
    error_rows: List[Dict[str, Any]] = []
    skipped_rows: List[Dict[str, Any]] = []

    # Keep existing report file name for compatibility with old workflow.
    change_log_path = output_groups_dir.parent / "group_live_member_ip_additive_changes.jsonl"

    with change_log_path.open("w", encoding="utf-8") as change_log:
        for group_file in group_files:
            group = load_file(group_file)

            if not isinstance(group, dict) or not group:
                skipped_rows.append({
                    "group_file": str(group_file),
                    "status": "skipped",
                    "reason": "failed to parse or empty object",
                })
                continue

            group_id = group.get("id")
            group_name = group.get("display_name") or group_id or group_file.stem

            if not group_id:
                row = {
                    "group_file": str(group_file),
                    "group_name": group_name,
                    "status": "skipped",
                    "reason": "missing group id",
                }
                skipped_rows.append(row)
                log.warning("Skipping group file with no id: %s", group_file)
                continue

            groups_seen += 1

            try:
                log.info("Processing group %s (%s)", group_name, group_id)

                vm_to_ips = client.get_group_member_vm_ips(
                    group_id=group_id,
                    domain_id=args.domain_id,
                    vm_ip_index=vm_ip_index,
                )

                if not vm_to_ips:
                    groups_no_members += 1
                    no_members_rows.append({
                        "group_id": group_id,
                        "group_name": group_name,
                        "group_file": str(group_file),
                        "status": "no_members",
                    })
                    log.info("Group %s has no evaluated VM members", group_name)
                    continue

                ips: Set[str] = set()
                for ip_list in vm_to_ips.values():
                    ips.update(ip_list)

                if not ips:
                    groups_no_ips += 1
                    no_ips_rows.append({
                        "group_id": group_id,
                        "group_name": group_name,
                        "group_file": str(group_file),
                        "status": "no_ips",
                        "vm_to_ips": vm_to_ips,
                    })
                    log.info("Group %s has evaluated VM members but no discovered IPs", group_name)
                    continue

                updated_group, added_ips = ensure_ip_expression(group, sorted(ips))

                if not added_ips:
                    groups_no_new_ips += 1
                    no_new_ips_rows.append({
                        "group_id": group_id,
                        "group_name": group_name,
                        "group_file": str(group_file),
                        "status": "no_new_ips",
                        "candidate_ips": sorted(ips),
                        "vm_to_ips": vm_to_ips,
                    })
                    log.info("Group %s already has all candidate IPs", group_name)
                    continue

                rel = group_file.relative_to(working_groups_dir)
                out_file = output_groups_dir / rel

                if args.output_format == "yaml":
                    out_file = out_file.with_suffix(".yaml")
                else:
                    out_file = out_file.with_suffix(".json")

                write_file(out_file, updated_group, args.output_format)

                groups_changed += 1
                ips_added_total += len(added_ips)

                row = {
                    "timestamp": _utc_now_iso(),
                    "group_id": group_id,
                    "group_name": group_name,
                    "source_group_file": str(group_file),
                    "output_group_file": str(out_file),
                    "status": "changed",
                    "ips_added_count": len(added_ips),
                    "ips_added": sorted(added_ips),
                    "candidate_ips": sorted(ips),
                    "vm_to_ips": vm_to_ips,
                }

                changed_rows.append(row)
                change_log.write(json.dumps(row, sort_keys=True) + "\n")

                log.info("Updated group %s: %d IPs added", group_name, len(added_ips))

            except Exception as e:
                groups_errors += 1
                row = {
                    "timestamp": _utc_now_iso(),
                    "group_id": group_id,
                    "group_name": group_name,
                    "group_file": str(group_file),
                    "status": "error",
                    "reason": str(e),
                }
                error_rows.append(row)
                log.exception("Failed processing group %s: %s", group_id, e)

                if not args.continue_on_group_error:
                    raise

    result = {
        "command": "build_group_ip_additive_from_live_members",
        "created_at": _utc_now_iso(),
        "source_manager": args.source_manager,
        "source_manager_host": source_host,
        "domain_id": args.domain_id,
        "source_groups_dir": str(source_groups_dir),
        "output_groups_dir": str(output_groups_dir),
        "reports_dir": str(reports_dir),
        "output_format": args.output_format,
        "copy_first": args.copy_first,
        "continue_on_group_error": args.continue_on_group_error,
        "vm_ip_index_count": len(vm_ip_index),
        "group_files_found": len(group_files),
        "groups_seen": groups_seen,
        "groups_changed": groups_changed,
        "groups_no_members": groups_no_members,
        "groups_no_ips": groups_no_ips,
        "groups_no_new_ips": groups_no_new_ips,
        "groups_errors": groups_errors,
        "groups_skipped": len(skipped_rows),
        "ips_added_total": ips_added_total,
        "change_log": str(change_log_path),
        "log_file": str(log_file),
    }

    # Standard report set
    write_json(reports_dir / "summary.json", result)

    write_json(reports_dir / "groups_changed.json", changed_rows)
    write_jsonl(reports_dir / "groups_changed.jsonl", changed_rows)

    write_json(reports_dir / "groups_no_members.json", no_members_rows)
    write_jsonl(reports_dir / "groups_no_members.jsonl", no_members_rows)

    write_json(reports_dir / "groups_no_ips.json", no_ips_rows)
    write_jsonl(reports_dir / "groups_no_ips.jsonl", no_ips_rows)

    write_json(reports_dir / "groups_no_new_ips.json", no_new_ips_rows)
    write_jsonl(reports_dir / "groups_no_new_ips.jsonl", no_new_ips_rows)

    write_json(reports_dir / "groups_errors.json", error_rows)
    write_jsonl(reports_dir / "groups_errors.jsonl", error_rows)

    write_json(reports_dir / "groups_skipped.json", skipped_rows)
    write_jsonl(reports_dir / "groups_skipped.jsonl", skipped_rows)

    # Also keep manifest next to the generated group directory.
    write_json(output_groups_dir / "manifest.json", result)

    log.info("Live member IP additive build complete")
    log.info("Summary: %s", result)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
