#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

try:
    import yaml
except ImportError:
    yaml = None


log = logging.getLogger(__name__)


# =============================================================================
# File helpers
# =============================================================================

def load_file(path: Path) -> Any:
    if path.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML is required to read YAML files")
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_file(path: Path, data: Any, output_format: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return

    if yaml is None:
        raise RuntimeError("PyYAML is required to write YAML files")

    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            data,
            f,
            sort_keys=True,
            default_flow_style=False,
            width=120,
            allow_unicode=True,
        )


def iter_group_files(groups_dir: Path) -> Iterable[Path]:
    for ext in ("*.yaml", "*.yml", "*.json"):
        yield from groups_dir.rglob(ext)


# =============================================================================
# Tag/IP normalization
# =============================================================================

def normalize_tag(scope: str | None, tag: str | None) -> str | None:
    tag = (tag or "").strip()
    scope = (scope or "").strip()

    if not tag:
        return None

    if scope:
        return f"{scope}|{tag}"

    return f"|{tag}"


def normalize_vm_tags(tags: Any) -> Set[str]:
    out: Set[str] = set()

    if not isinstance(tags, list):
        return out

    for t in tags:
        if isinstance(t, dict):
            norm = normalize_tag(t.get("scope"), t.get("tag"))
            if norm:
                out.add(norm)

            # Some exports use value instead of tag
            norm = normalize_tag(t.get("scope"), t.get("value"))
            if norm:
                out.add(norm)

        elif isinstance(t, str):
            # Accept either "scope|tag", "scope:tag", or plain tag
            s = t.strip()
            if not s:
                continue

            if "|" in s:
                scope, tag = s.split("|", 1)
                norm = normalize_tag(scope, tag)
            elif ":" in s:
                scope, tag = s.split(":", 1)
                norm = normalize_tag(scope, tag)
            else:
                norm = normalize_tag("", s)

            if norm:
                out.add(norm)

    return out


def is_valid_ip_token(value: str) -> bool:
    value = value.strip()
    if not value:
        return False

    try:
        if "-" in value:
            left, right = value.split("-", 1)
            ipaddress.ip_address(left.strip())
            ipaddress.ip_address(right.strip())
            return True

        if "/" in value:
            ipaddress.ip_network(value, strict=False)
            return True

        ipaddress.ip_address(value)
        return True

    except Exception:
        return False


def normalize_ip_list(values: Any) -> List[str]:
    out: List[str] = []

    if not values:
        return out

    if isinstance(values, str):
        values = [values]

    if not isinstance(values, list):
        return out

    for v in values:
        if not isinstance(v, str):
            continue

        v = v.strip()
        if is_valid_ip_token(v):
            out.append(v)

    return sorted(set(out))


# =============================================================================
# Group condition extraction
# =============================================================================

def extract_group_tag_conditions(obj: Any) -> Set[str]:
    """
    Recursively extract NSX tag conditions from a group payload.

    Supports common NSX shape:
      resource_type: Condition
      key: Tag
      value: app01
      scope: app
    """
    found: Set[str] = set()

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            resource_type = str(x.get("resource_type") or "")
            key = str(x.get("key") or "")

            if resource_type == "Condition" and key.lower() == "tag":
                tag_value = x.get("value") or x.get("tag")
                scope_value = x.get("scope")

                norm = normalize_tag(scope_value, tag_value)
                if norm:
                    found.add(norm)

                # Also add plain-tag version to tolerate scope-less matching
                plain = normalize_tag("", tag_value)
                if plain:
                    found.add(plain)

            for v in x.values():
                walk(v)

        elif isinstance(x, list):
            for item in x:
                walk(item)

    walk(obj)
    return found


# =============================================================================
# IPAddressExpression append
# =============================================================================

def ensure_ip_expression(group: Dict[str, Any], ips_to_add: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Append IPs to an existing IPAddressExpression if one exists.
    Otherwise create a new IPAddressExpression.

    This keeps existing tag conditions untouched.
    """
    if not ips_to_add:
        return group, []

    expr = group.setdefault("expression", [])
    if not isinstance(expr, list):
        raise ValueError(f"Group expression is not a list for group {group.get('id')}")

    existing_ips: Set[str] = set()
    ip_expr = None

    for item in expr:
        if isinstance(item, dict) and item.get("resource_type") == "IPAddressExpression":
            ip_expr = item
            existing_ips.update(normalize_ip_list(item.get("ip_addresses")))
            break

    new_ips = [ip for ip in ips_to_add if ip not in existing_ips]

    if not new_ips:
        return group, []

    if ip_expr is None:
        expr.append(
            {
                "resource_type": "IPAddressExpression",
                "ip_addresses": sorted(new_ips),
            }
        )
    else:
        current = normalize_ip_list(ip_expr.get("ip_addresses"))
        ip_expr["ip_addresses"] = sorted(set(current + new_ips))

    return group, new_ips


# =============================================================================
# VM index
# =============================================================================

def load_vm_tag_ip_index(path: Path) -> List[Dict[str, Any]]:
    """
    Expected shape from tagged_vms_index:

    vms:
      <external-id>:
        display_name: vm01
        tags:
          - scope: app
            tag: web
        ip_addresses:
          - 10.10.10.5
    """
    payload = load_file(path)
    raw_vms = payload.get("vms", payload)

    if not isinstance(raw_vms, dict):
        raise RuntimeError("VM index must contain a 'vms' dict or be a dict of VMs")

    result: List[Dict[str, Any]] = []

    for vm_id, vm in raw_vms.items():
        if not isinstance(vm, dict):
            continue

        tags = normalize_vm_tags(vm.get("tags"))
        ips = normalize_ip_list(
            vm.get("ip_addresses")
            or vm.get("ips")
            or vm.get("ipAddresses")
            or vm.get("addresses")
        )

        if not tags or not ips:
            continue

        result.append(
            {
                "vm_id": vm_id,
                "display_name": vm.get("display_name") or vm.get("name") or vm_id,
                "tags": tags,
                "ip_addresses": ips,
            }
        )

    return result


# =============================================================================
# Main mapping
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Add VM IPs to NSX groups when VM tags match group tag conditions"
    )

    parser.add_argument(
        "--source-groups-dir",
        required=True,
        help="Input groups directory from exported/new groups",
    )

    parser.add_argument(
        "--output-groups-dir",
        required=True,
        help="Output directory for updated additive group files",
    )

    parser.add_argument(
        "--vm-index",
        required=True,
        help="Tagged VM index containing tags and ip_addresses",
    )

    parser.add_argument(
        "--output-format",
        choices=["yaml", "json"],
        default="yaml",
    )

    parser.add_argument(
        "--copy-first",
        action="store_true",
        help="Copy source group tree to output dir before modifying",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    source_groups_dir = Path(args.source_groups_dir).expanduser().resolve()
    output_groups_dir = Path(args.output_groups_dir).expanduser().resolve()
    vm_index_path = Path(args.vm_index).expanduser().resolve()

    if not source_groups_dir.exists():
        raise RuntimeError(f"Source groups directory does not exist: {source_groups_dir}")

    if not vm_index_path.exists():
        raise RuntimeError(f"VM index does not exist: {vm_index_path}")

    if args.copy_first:
        if output_groups_dir.exists():
            shutil.rmtree(output_groups_dir)
        shutil.copytree(source_groups_dir, output_groups_dir)
        working_groups_dir = output_groups_dir
    else:
        working_groups_dir = source_groups_dir
        output_groups_dir.mkdir(parents=True, exist_ok=True)

    vm_index = load_vm_tag_ip_index(vm_index_path)

    log.info("Loaded VMs with tags and IPs: %d", len(vm_index))
    log.info("Source groups dir: %s", source_groups_dir)
    log.info("Output groups dir: %s", output_groups_dir)

    groups_seen = 0
    groups_changed = 0
    ips_added_total = 0

    change_log: List[Dict[str, Any]] = []

    for group_file in iter_group_files(working_groups_dir):
        group = load_file(group_file)
        if not isinstance(group, dict):
            continue

        groups_seen += 1

        group_id = group.get("id") or group_file.stem
        group_name = group.get("display_name") or group_id

        group_tags = extract_group_tag_conditions(group)

        if not group_tags:
            continue

        ips_to_add: Set[str] = set()
        matched_vms: List[Dict[str, Any]] = []

        for vm in vm_index:
            vm_tags = vm["tags"]

            # Match exact scope|tag or plain |tag
            if group_tags.intersection(vm_tags):
                for ip in vm["ip_addresses"]:
                    ips_to_add.add(ip)

                matched_vms.append(
                    {
                        "vm_id": vm["vm_id"],
                        "display_name": vm["display_name"],
                        "ip_addresses": vm["ip_addresses"],
                        "matched_tags": sorted(group_tags.intersection(vm_tags)),
                    }
                )

        if not ips_to_add:
            continue

        updated_group, added_ips = ensure_ip_expression(group, sorted(ips_to_add))

        if not added_ips:
            continue

        groups_changed += 1
        ips_added_total += len(added_ips)

        rel = group_file.relative_to(working_groups_dir)
        out_file = output_groups_dir / rel

        # Normalize extension if needed
        if args.output_format == "yaml":
            out_file = out_file.with_suffix(".yaml")
        else:
            out_file = out_file.with_suffix(".json")

        write_file(out_file, updated_group, args.output_format)

        change_log.append(
            {
                "group_id": group_id,
                "group_name": group_name,
                "group_file": str(out_file),
                "group_tag_conditions": sorted(group_tags),
                "ips_added": sorted(added_ips),
                "matched_vms": matched_vms,
            }
        )

        log.info(
            "Updated group %s: added %d IPs",
            group_name,
            len(added_ips),
        )

    change_log_path = output_groups_dir.parent / "group_ip_additive_changes.jsonl"
    with change_log_path.open("w", encoding="utf-8") as f:
        for row in change_log:
            f.write(json.dumps(row, sort_keys=True) + "\n")

    result = {
        "groups_seen": groups_seen,
        "groups_changed": groups_changed,
        "ips_added_total": ips_added_total,
        "change_log": str(change_log_path),
        "output_groups_dir": str(output_groups_dir),
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()