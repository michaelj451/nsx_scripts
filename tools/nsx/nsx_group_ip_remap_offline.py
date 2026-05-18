#!/usr/bin/env python3
"""
tools/nsx/nsx_group_ip_remap_offline.py

Offline-only NSX group IP remap tool.

Reads exported/additive NSX group files from disk, maps IPs/subnets from CSV,
and writes prepared group files for a separate push step.

No NSX API calls.
No PATCH/PUT/POST/DELETE.

Key behavior:
  - Supports subnet mappings with longest-prefix match
  - /32 wins over /31, /30, /29, /24, /16, etc.
  - Additive by default
  - --mapped-only replaces IPAddressExpression values with mapped values only
  - Keeps original tag/dynamic group conditions unchanged
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import shutil
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_log_dir

try:
    import yaml
except ImportError:
    yaml = None


REPO_ROOT = Path(__file__).resolve().parents[2]
log = logging.getLogger(__name__)


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

    log.info("Logging to %s", log_file)
    return log_file


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
# IP / subnet mapping helpers
# =============================================================================

def _to_network(value: str) -> ipaddress.IPv4Network:
    value = str(value).strip()
    if "/" not in value:
        value = f"{value}/32"
    return ipaddress.ip_network(value, strict=False)


def _format_network_or_ip(net: ipaddress.IPv4Network) -> str:
    if net.prefixlen == 32:
        return str(net.network_address)
    return str(net)


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
        net = _to_network(value)
        return _format_network_or_ip(net)
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
        _to_network(value)
        return True
    except ValueError:
        return False


def _token_is_range(value: str) -> bool:
    return "-" in str(value) and "/" not in str(value)


def _map_network_by_offset(
    source_value: str,
    src_net: ipaddress.IPv4Network,
    dst_net: ipaddress.IPv4Network,
) -> Optional[str]:
    source_net = _to_network(source_value)

    if source_net.prefixlen == 32:
        src_ip = int(source_net.network_address)
        offset = src_ip - int(src_net.network_address)
        mapped_ip_int = int(dst_net.network_address) + offset
        mapped_ip = ipaddress.ip_address(mapped_ip_int)

        if mapped_ip not in dst_net:
            return None

        return str(mapped_ip)

    if source_net.prefixlen < src_net.prefixlen:
        return None

    offset = int(source_net.network_address) - int(src_net.network_address)
    mapped_network_int = int(dst_net.network_address) + offset

    try:
        mapped_net = ipaddress.ip_network(
            f"{ipaddress.ip_address(mapped_network_int)}/{source_net.prefixlen}",
            strict=False,
        )
    except ValueError:
        return None

    if not mapped_net.subnet_of(dst_net):
        return None

    return _format_network_or_ip(mapped_net)


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


class PrefixMappingTable:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def add(self, source: str, destination: str, row_num: int, direction: str) -> None:
        src_net = _to_network(source)
        dst_net = _to_network(destination)

        self.rows.append({
            "source": _format_network_or_ip(src_net),
            "destination": _format_network_or_ip(dst_net),
            "src_net": src_net,
            "dst_net": dst_net,
            "row": row_num,
            "direction": direction,
            "source_prefixlen": src_net.prefixlen,
            "destination_prefixlen": dst_net.prefixlen,
        })

    def finalize(self) -> None:
        self.rows.sort(
            key=lambda r: (
                int(r["source_prefixlen"]),
                int(r["destination_prefixlen"]),
                int(r["row"]),
            ),
            reverse=True,
        )

    def map_token(self, token: str) -> tuple[list[str], Optional[dict[str, Any]]]:
        token = _canonical_ip_token(token)

        if _token_is_range(token):
            for row in self.rows:
                if row["source"] == token:
                    return [row["destination"]], row
            return [], None

        try:
            token_net = _to_network(token)
        except ValueError:
            return [], None

        for row in self.rows:
            src_net: ipaddress.IPv4Network = row["src_net"]

            if not token_net.subnet_of(src_net):
                continue

            mapped = _map_network_by_offset(
                source_value=token,
                src_net=row["src_net"],
                dst_net=row["dst_net"],
            )

            if mapped:
                return [mapped], row

        return [], None


def _load_mapping_csv(path: Path, bidirectional: bool) -> tuple[PrefixMappingTable, list[dict]]:
    table = PrefixMappingTable()
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

            row_report = {
                "row": row_num,
                "left_column": left_col,
                "right_column": right_col,
                "left_value": left_raw,
                "right_value": right_raw,
            }

            if not _validate_ip_token(left_raw) or not _validate_ip_token(right_raw):
                invalid_rows.append({**row_report, "reason": "Invalid IP/CIDR/range token"})
                continue

            left = _canonical_ip_token(left_raw)
            right = _canonical_ip_token(right_raw)

            if left == right:
                invalid_rows.append({**row_report, "reason": "Left and right values are the same"})
                continue

            try:
                table.add(left, right, row_num, "forward")

                if bidirectional:
                    table.add(right, left, row_num, "reverse")

            except Exception as e:
                invalid_rows.append({**row_report, "reason": str(e)})

    table.finalize()
    return table, invalid_rows


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


def _remap_group_payload(
    group: dict,
    mapping: PrefixMappingTable,
    mapped_only: bool = False,
) -> tuple[dict, dict]:
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
        "mapping_hits": [],
        "expression_changes": [],
        "mapped_only": mapped_only,
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

        mapped_for_expression: list[str] = []
        matched_here: list[str] = []

        for value in existing_values:
            mapped_values, mapping_row = mapping.map_token(value)

            if not mapped_values:
                continue

            matched_here.append(value)
            report["matched_values"].append(value)

            if mapping_row:
                report["mapping_hits"].append({
                    "source_value": value,
                    "mapped_values": mapped_values,
                    "mapping_source": mapping_row["source"],
                    "mapping_destination": mapping_row["destination"],
                    "mapping_prefixlen": mapping_row["source_prefixlen"],
                    "mapping_row": mapping_row["row"],
                    "direction": mapping_row["direction"],
                })

            for mapped in sorted(mapped_values):
                mapped = _canonical_ip_token(mapped)
                if mapped not in mapped_for_expression:
                    mapped_for_expression.append(mapped)

        if not mapped_for_expression:
            continue

        if mapped_only:
            final_values = sorted(set(mapped_for_expression))
            added_values = final_values
        else:
            final_values = sorted(set(existing_values + mapped_for_expression))
            added_values = sorted(v for v in final_values if v not in existing_set)

        if not added_values and not mapped_only:
            continue

        original = list(expr.get("ip_addresses", []))
        expr["ip_addresses"] = final_values
        group_added.update(added_values)

        report["expression_changes"].append({
            "expression_index": idx,
            "matched_values": matched_here,
            "added_values": added_values,
            "original_values": original,
            "final_values": final_values,
            "original_count": len(original),
            "new_count": len(final_values),
            "mapped_only": mapped_only,
        })

    if report["expression_changes"]:
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
        description="Offline-only NSX group IP remap: exported groups + CSV subnet mapping -> prepared additive groups"
    )

    parser.add_argument("--export-root", required=True, help="Existing exported/additive groups directory")
    parser.add_argument("--prepared-root", required=True, help="Output directory for changed prepared groups")
    parser.add_argument("--mapping-csv", required=True, help="CSV file containing IP/subnet mapping")
    parser.add_argument("--reports-dir", help="Optional reports directory")
    parser.add_argument("--output-format", choices=["yaml", "json"], default="yaml")
    parser.add_argument("--bidirectional", action="store_true")
    parser.add_argument(
        "--mapped-only",
        action="store_true",
        help="Replace IPAddressExpression values with mapped destination values only.",
    )
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
    log.info("Mapped only: %s", args.mapped_only)
    log.info("Output format: %s", args.output_format)

    mapping, invalid_mapping_rows = _load_mapping_csv(
        Path(args.mapping_csv).expanduser().resolve(),
        args.bidirectional,
    )

    group_files = _iter_object_files(export_root)

    log.info("Loaded mapping rows: %s", len(mapping.rows))
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

        updated, report = _remap_group_payload(
            group=group,
            mapping=mapping,
            mapped_only=args.mapped_only,
        )

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
        "mapped_only": args.mapped_only,
        "output_format": args.output_format,
        "total_mapping_rows": len(mapping.rows),
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

    _write_json(reports_dir / "mapping_table.json", [
        {
            "row": r["row"],
            "direction": r["direction"],
            "source": r["source"],
            "destination": r["destination"],
            "source_prefixlen": r["source_prefixlen"],
            "destination_prefixlen": r["destination_prefixlen"],
        }
        for r in mapping.rows
    ])

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