#!/usr/bin/env python3
"""
tools/nsx/nsx_group_ip_remap_offline.py

Offline-only NSX group IP remap tool.

This script does NOT connect to NSX.
This script does NOT contain NSX write APIs.
This script does NOT PATCH, PUT, POST, or DELETE anything.

Purpose:
  Read existing exported NSX group files from disk, use a CSV IP mapping file,
  and generate additive prepared group files for later review/push by a separate
  tool.

Expected workflow:

  1) Export with existing tried/tested exporter:

     python tools/nsx/export_nsx_objects.py \
       --manager nsx-lm1 \
       --domain-id default \
       --base-dir nsx_export \
       --output-format yaml

  2) Run this offline remap script:

     python tools/nsx/nsx_group_ip_remap_offline.py \
       --export-root nsx_export/nsx-lm1.lab.local/default/groups \
       --prepared-root nsx_export_additive/nsx-lm1.lab.local/default/groups \
       --mapping-csv ip_mapping.csv \
       --bidirectional \
       --output-format yaml

  3) Review reports and prepared group payloads.

  4) Push prepared files with a separate, explicitly named push script/tool.

Core behavior:
  - Offline only
  - Additive only
  - Never removes existing IP values
  - Never overwrites expressions
  - Reads YAML/JSON exported group files
  - Writes only changed group files to prepared-root
  - Writes JSON and JSONL reports
  - Uses existing project .env/bootstrap logging style

CSV formats supported:
  old_ip,new_ip
  source,destination
  src,dst
  lm1_ip,lm2_ip
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import shutil
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
import ipaddress

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_log_dir

try:
    import yaml
except ImportError:
    yaml = None

# =============================================================================
# Repo Root
# =============================================================================

REPO_ROOT = Path(__file__).resolve().parents[2]

# =============================================================================
# Logging
# =============================================================================


def _resolve_log_dir() -> Path:
    if not nsx_log_dir:
        raise RuntimeError("nsx_log_dir is empty (NSX_LOG_DIR not loaded?)")

    p = Path(nsx_log_dir).expanduser().resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _setup_logging(tool_name: str) -> Path:
    log_dir = _resolve_log_dir()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = (log_dir / f"{tool_name}_{ts}.log").resolve()
    log_file.touch(exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)

    root.addHandler(ch)
    root.addHandler(fh)

    logging.getLogger(__name__).info("Logging to %s", log_file)
    return log_file


log = logging.getLogger(__name__)

# =============================================================================
# Generic helpers
# =============================================================================


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_object(path: Path) -> dict:
    try:
        if path.suffix.lower() in (".yaml", ".yml"):
            if yaml is None:
                raise RuntimeError("PyYAML is not installed")
            with path.open("r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}

        return json.loads(path.read_text(encoding="utf-8"))

    except Exception as e:
        log.warning("Failed to parse %s: %s", path, e)
        return {}


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def _write_object(base_path: Path, data: dict, output_format: str) -> Path:
    base_path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        path = base_path.with_suffix(".json")
        _write_json(path, data)
        return path

    if output_format == "yaml":
        if yaml is None:
            raise RuntimeError("PyYAML is required for YAML output")
        path = base_path.with_suffix(".yaml")
        with path.open("w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False, default_flow_style=False)
        return path

    raise RuntimeError(f"Unsupported output format: {output_format}")


def _iter_object_files(dir_path: Path) -> list[Path]:
    if not dir_path.exists():
        return []

    files: list[Path] = []
    for ext in ("*.yaml", "*.yml", "*.json"):
        files.extend(dir_path.rglob(ext))

    return sorted(p for p in files if p.name != "manifest.json")


def _safe_name(obj: dict) -> str:
    object_id = obj.get("id") or obj.get("display_name") or "UNKNOWN"
    return str(object_id).replace("/", "_")


def _purge_dir(path: Path) -> None:
    if path.exists():
        log.info("Deleting pre-existing directory: %s", path)
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)

# =============================================================================
# Mapping helpers
# =============================================================================


def _canonical_ip_token(value: str) -> str:
    value = str(value).strip()
    if not value:
        return value

    if "-" in value and "/" not in value:
        left, right = [x.strip() for x in value.split("-", 1)]
        try:
            return f"{ipaddress.ip_address(left)}-{ipaddress.ip_address(right)}"
        except ValueError:
            return value

    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def _validate_ip_token(value: str) -> bool:
    value = str(value).strip()
    if not value:
        return False

    if "-" in value and "/" not in value:
        left, right = [x.strip() for x in value.split("-", 1)]
        try:
            ipaddress.ip_address(left)
            ipaddress.ip_address(right)
            return True
        except ValueError:
            return False

    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _find_csv_columns(fieldnames: list[str]) -> tuple[str, str]:
    lowered = {f.lower().strip(): f for f in fieldnames}
    candidates = [
        ("old_ip", "new_ip"),
        ("old_subnet", "new_subnet"),
        ("old", "new"),
        ("source", "destination"),
        ("src", "dst"),
        ("src_ip", "dst_ip"),
        ("source_ip", "destination_ip"),
        ("lm1_ip", "lm2_ip"),
        ("nsx_lm1_ip", "nsx_lm2_ip"),
    ]

    for left, right in candidates:
        if left in lowered and right in lowered:
            return lowered[left], lowered[right]

    raise RuntimeError(
        "Could not determine mapping CSV columns. Supported pairs: "
        "old_ip,new_ip | old_subnet,new_subnet | old,new | source,destination | "
        "src,dst | src_ip,dst_ip | source_ip,destination_ip | lm1_ip,lm2_ip | nsx_lm1_ip,nsx_lm2_ip"
    )


def _load_mapping_csv(path: Path, bidirectional: bool) -> tuple[dict[str, set[str]], list[dict]]:
    mapping: dict[str, set[str]] = {}
    invalid_rows: list[dict] = []

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise RuntimeError("Mapping CSV has no header row")

        left_col, right_col = _find_csv_columns(reader.fieldnames)
        log.info("Using CSV columns: %s -> %s", left_col, right_col)

        for row_num, row in enumerate(reader, start=2):
            left_raw = str(row.get(left_col, "")).strip()
            right_raw = str(row.get(right_col, "")).strip()

            if not left_raw and not right_raw:
                continue

            left = _canonical_ip_token(left_raw)
            right = _canonical_ip_token(right_raw)

            row_report = {
                "row": row_num,
                "left_column": left_col,
                "right_column": right_col,
                "left_value": left_raw,
                "right_value": right_raw,
            }

            if not _validate_ip_token(left) or not _validate_ip_token(right):
                invalid_rows.append({**row_report, "reason": "Invalid IP/CIDR/range token"})
                continue

            if left == right:
                invalid_rows.append({**row_report, "reason": "Left and right values are the same"})
                continue

            mapping.setdefault(left, set()).add(right)

            if bidirectional:
                mapping.setdefault(right, set()).add(left)

    return mapping, invalid_rows

# =============================================================================
# Group remap logic
# =============================================================================


def _is_ip_expression(expr: dict) -> bool:
    rt = expr.get("resource_type") or expr.get("_type") or ""
    return rt == "IPAddressExpression" or "ip_addresses" in expr


def _expression_ip_values(expr: dict) -> list[str]:
    values = expr.get("ip_addresses", [])
    if not isinstance(values, list):
        return []
    return [_canonical_ip_token(v) for v in values if str(v).strip()]


def _strip_readonly_fields(payload: dict) -> dict:
    cleaned = deepcopy(payload)
    for key in [
        "_create_time",
        "_create_user",
        "_last_modified_time",
        "_last_modified_user",
        "_links",
        "_protection",
        "_revision",
        "_schema",
        "_self",
        "path",
        "relative_path",
        "parent_path",
        "unique_id",
        "realization_id",
        "marked_for_delete",
        "overridden",
    ]:
        cleaned.pop(key, None)
    return cleaned


def _remap_group_payload(group: dict, mapping: dict[str, set[str]]) -> tuple[dict, dict]:
    payload = deepcopy(group)
    group_id = payload.get("id") or payload.get("display_name") or "UNKNOWN"
    display_name = payload.get("display_name") or group_id
    expressions = payload.get("expression", [])

    report = {
        "group_id": group_id,
        "display_name": display_name,
        "path": payload.get("path"),
        "timestamp": _utc_now_iso(),
        "matched_values": [],
        "added_values": [],
        "expression_changes": [],
        "status": "unchanged",
    }

    if not isinstance(expressions, list):
        report["status"] = "skipped"
        report["reason"] = "group expression is not a list"
        return payload, report

    group_added: set[str] = set()

    for idx, expr in enumerate(expressions):
        if not isinstance(expr, dict) or not _is_ip_expression(expr):
            continue

        existing_values = _expression_ip_values(expr)
        existing_set = set(existing_values)
        to_add: list[str] = []
        matched_here: list[str] = []

        for value in existing_values:
            mapped_values = mapping.get(value, set())
            if not mapped_values:
                continue

            matched_here.append(value)
            report["matched_values"].append(value)

            for mapped in sorted(mapped_values):
                if mapped not in existing_set and mapped not in to_add:
                    to_add.append(mapped)
                    existing_set.add(mapped)

        if to_add:
            original = list(expr.get("ip_addresses", []))
            expr["ip_addresses"] = original + to_add
            group_added.update(to_add)

            report["expression_changes"].append({
                "expression_index": idx,
                "matched_values": matched_here,
                "added_values": to_add,
                "original_count": len(original),
                "new_count": len(expr["ip_addresses"]),
            })

    if group_added:
        report["status"] = "changed"
        report["added_values"] = sorted(group_added)
        report["added_count"] = len(group_added)
    else:
        report["matched_values"] = sorted(set(report["matched_values"]))
        report["added_count"] = 0

    return payload, report

# =============================================================================
# Main
# =============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Offline-only NSX group IP remap: exported groups + CSV mapping -> prepared additive groups"
    )

    parser.add_argument("--export-root", required=True, help="Existing exported groups directory")
    parser.add_argument("--prepared-root", required=True, help="Output directory for changed prepared groups")
    parser.add_argument("--mapping-csv", required=True, help="CSV file containing IP mapping")
    parser.add_argument("--reports-dir", help="Optional reports directory")
    parser.add_argument("--output-format", choices=["yaml", "json"], default="yaml")
    parser.add_argument("--bidirectional", action="store_true")
    parser.add_argument("--clean", action="store_true", default=True)
    parser.add_argument(
        "--keep-readonly-fields",
        action="store_true",
        help="Keep NSX metadata fields in prepared files. Default strips read-only fields for push-safe payloads.",
    )

    args = parser.parse_args()

    init_cli()
    log_file = _setup_logging("nsx_group_ip_remap_offline")

    export_root = Path(args.export_root).expanduser().resolve()
    prepared_root = Path(args.prepared_root).expanduser().resolve()
    reports_dir = (
        Path(args.reports_dir).expanduser().resolve()
        if args.reports_dir
        else prepared_root.parent / "reports" / "group-ip-remap"
    )

    if args.clean:
        _purge_dir(prepared_root)
    else:
        prepared_root.mkdir(parents=True, exist_ok=True)

    reports_dir.mkdir(parents=True, exist_ok=True)

    log.info("Starting offline NSX group IP remap")
    log.info("Export root: %s", export_root)
    log.info("Prepared root: %s", prepared_root)
    log.info("Reports dir: %s", reports_dir)
    log.info("Mapping CSV: %s", Path(args.mapping_csv).expanduser().resolve())
    log.info("Bidirectional: %s", args.bidirectional)
    log.info("Output format: %s", args.output_format)

    mapping, invalid_mapping_rows = _load_mapping_csv(Path(args.mapping_csv).expanduser().resolve(), args.bidirectional)
    group_files = _iter_object_files(export_root)

    log.info("Loaded mapping keys: %s", len(mapping))
    log.info("Invalid mapping rows: %s", len(invalid_mapping_rows))
    log.info("Group files found: %s", len(group_files))

    changed: list[dict] = []
    unchanged: list[dict] = []
    skipped: list[dict] = []
    manifest_groups: list[dict] = []

    for group_file in group_files:
        group = _read_object(group_file)
        if not group:
            skipped.append({
                "source_file": str(group_file),
                "status": "skipped",
                "reason": "failed to parse or empty object",
            })
            continue

        updated, report = _remap_group_payload(group, mapping)
        report["source_file"] = str(group_file)

        if report["status"] == "changed":
            output_payload = updated if args.keep_readonly_fields else _strip_readonly_fields(updated)
            base = prepared_root / _safe_name(updated)
            prepared_file = _write_object(base, output_payload, args.output_format)

            report["prepared_file"] = str(prepared_file)
            changed.append(report)

            manifest_groups.append({
                "id": updated.get("id"),
                "display_name": updated.get("display_name"),
                "source_file": str(group_file),
                "prepared_file": str(prepared_file),
                "added_count": report.get("added_count", 0),
                "added_values": report.get("added_values", []),
            })

        elif report["status"] == "skipped":
            skipped.append(report)
        else:
            unchanged.append(report)

    summary = {
        "command": "offline_update",
        "created_at": _utc_now_iso(),
        "export_root": str(export_root),
        "prepared_root": str(prepared_root),
        "reports_dir": str(reports_dir),
        "mapping_csv": str(Path(args.mapping_csv).expanduser().resolve()),
        "bidirectional": args.bidirectional,
        "output_format": args.output_format,
        "total_mapping_keys": len(mapping),
        "invalid_mapping_rows": len(invalid_mapping_rows),
        "total_group_files": len(group_files),
        "groups_changed": len(changed),
        "groups_unchanged": len(unchanged),
        "groups_skipped": len(skipped),
        "total_added_ip_values": sum(int(r.get("added_count", 0)) for r in changed),
        "log_file": str(log_file),
        "groups": manifest_groups,
    }

    _write_json(reports_dir / "summary_update.json", summary)
    _write_json(prepared_root / "manifest.json", summary)

    _write_json(reports_dir / "mapping_invalid_rows.json", invalid_mapping_rows)
    _write_jsonl(reports_dir / "mapping_invalid_rows.jsonl", invalid_mapping_rows)

    _write_json(reports_dir / "groups_changed.json", changed)
    _write_jsonl(reports_dir / "groups_changed.jsonl", changed)

    _write_json(reports_dir / "groups_unchanged.json", unchanged)
    _write_jsonl(reports_dir / "groups_unchanged.jsonl", unchanged)

    _write_json(reports_dir / "groups_skipped.json", skipped)
    _write_jsonl(reports_dir / "groups_skipped.jsonl", skipped)

    log.info("Offline update complete")
    log.info("Changed groups: %s", len(changed))
    log.info("Unchanged groups: %s", len(unchanged))
    log.info("Skipped groups: %s", len(skipped))
    log.info("Total added IP values: %s", summary["total_added_ip_values"])

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
