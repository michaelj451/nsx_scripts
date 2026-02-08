#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Tuple

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e


# =============================================================================
# Logging
# =============================================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# Defaults
# =============================================================================

REPO_ROOT = Path(__file__).resolve().parents[2]
NSX_EXPORT_DIR_DEFAULT = REPO_ROOT / "nsx_export"
NSX_CONVERTED_DIR_DEFAULT = REPO_ROOT / "nsx_new_groups"
CSV_DEFAULT = REPO_ROOT / "data" / "subnet_map.csv"


# =============================================================================
# CSV mapping model
# =============================================================================

@dataclass(frozen=True)
class SubnetMap:
    old: ipaddress._BaseNetwork
    new: ipaddress._BaseNetwork
    vlan: str | None = None
    description: str | None = None


def read_csv_mappings(csv_path: Path) -> list[SubnetMap]:
    required = {"old_subnet", "new_subnet", "vlan", "description"}
    maps: list[SubnetMap] = []

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit("CSV has no headers.")

        missing = required - set(h.strip() for h in reader.fieldnames)
        if missing:
            raise SystemExit(f"CSV missing required headers: {sorted(missing)}")

        for row in reader:
            old_s = (row.get("old_subnet") or "").strip()
            new_s = (row.get("new_subnet") or "").strip()
            if not old_s or not new_s:
                continue

            old_net = ipaddress.ip_network(old_s, strict=False)
            new_net = ipaddress.ip_network(new_s, strict=False)

            if old_net.version != new_net.version:
                raise SystemExit(f"IP version mismatch: {old_net} -> {new_net}")

            maps.append(
                SubnetMap(
                    old=old_net,
                    new=new_net,
                    vlan=(row.get("vlan") or "").strip() or None,
                    description=(row.get("description") or "").strip() or None,
                )
            )

    maps.sort(key=lambda m: (m.old.version, -m.old.prefixlen))
    return maps


# =============================================================================
# YAML / JSON IO
# =============================================================================

def load_doc(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    if path.suffix.lower() in {".yml", ".yaml"}:
        return yaml.safe_load(text)
    raise SystemExit(f"Unsupported input extension: {path.suffix}")


def write_output(path: Path, obj: Any) -> None:
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(obj, indent=2), encoding="utf-8")
        return
    if path.suffix.lower() in {".yml", ".yaml"}:
        path.write_text(yaml.safe_dump(obj, sort_keys=False), encoding="utf-8")
        return
    raise SystemExit(f"Unsupported output extension: {path.suffix}")


# =============================================================================
# Group document shape handling
# =============================================================================

def find_groups_container(doc: Any) -> Tuple[Any, list[dict]]:
    def looks_like_group(g: dict) -> bool:
        return bool(set(g) & {"display_name", "name", "expression", "id", "path"})

    if isinstance(doc, list) and all(isinstance(x, dict) for x in doc):
        return doc, doc

    if isinstance(doc, dict):
        if looks_like_group(doc):
            return doc, [doc]

        for key in ("results", "groups", "items", "data", "resources", "children"):
            if isinstance(doc.get(key), list) and all(isinstance(x, dict) for x in doc[key]):
                return doc, doc[key]

        for v in doc.values():
            if isinstance(v, dict) and isinstance(v.get("groups"), list):
                return v, v["groups"]

        if all(isinstance(v, dict) for v in doc.values()):
            values = list(doc.values())
            if any(looks_like_group(v) for v in values):
                return doc, values

    raise SystemExit("Unrecognized group document shape")


def append_new_to_group_name(group: dict[str, Any]) -> None:
    if "display_name" in group:
        group["display_name"] = f"{group['display_name']} new"
    elif "name" in group:
        group["name"] = f"{group['name']} new"


# =============================================================================
# Path / identity helpers
# =============================================================================

def derive_new_group_path(new_domain_path: str, new_group_id: str) -> str:
    """
    /global-infra/domains/<domain> + group id
    """
    return f"{new_domain_path.rstrip('/')}/groups/{new_group_id}"


def apply_new_identity(group: dict, new_group_id: str, new_domain_path: str) -> None:
    group["_source_id"] = group.get("id")
    group["_source_path"] = group.get("path")

    group["id"] = new_group_id
    group["relative_path"] = new_group_id

    group["parent_path"] = new_domain_path
    group["path"] = derive_new_group_path(new_domain_path, new_group_id)


def rebuild_expression_paths(expr: dict, new_group_path: str) -> None:
    expr_id = expr.get("id") or expr.get("relative_path")
    if not expr_id:
        raise SystemExit("Expression missing id / relative_path")

    expr["parent_path"] = new_group_path
    expr["relative_path"] = expr_id

    rt = expr.get("resource_type", "")
    segment = "expressions"
    if rt == "IPAddressExpression":
        segment = "ip-address-expressions"

    expr["path"] = f"{new_group_path}/{segment}/{expr_id}"


# =============================================================================
# IP / CIDR / Range remapping
# =============================================================================

_RANGE_RE = re.compile(r"^\s*([0-9a-fA-F\.:]+)\s*-\s*([0-9a-fA-F\.:]+)\s*$")


def looks_like_ip_token(s: str) -> bool:
    if not s:
        return False
    if _RANGE_RE.match(s):
        return True
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def _find_mapping_for_ip(ip: ipaddress._BaseAddress, maps: list[SubnetMap]) -> Optional[SubnetMap]:
    for m in maps:
        if ip.version == m.old.version and ip in m.old:
            return m
    return None


def _remap_ip(ip: ipaddress._BaseAddress, m: SubnetMap) -> ipaddress._BaseAddress:
    offset = int(ip) - int(m.old.network_address)
    return ipaddress.ip_address(int(m.new.network_address) + offset)


def remap_token(token: str, maps: list[SubnetMap]) -> str:
    token = token.strip()

    mrange = _RANGE_RE.match(token)
    if mrange:
        a = ipaddress.ip_address(mrange.group(1))
        b = ipaddress.ip_address(mrange.group(2))
        ma = _find_mapping_for_ip(a, maps)
        mb = _find_mapping_for_ip(b, maps)
        if ma and mb and ma.old == mb.old:
            return f"{_remap_ip(a, ma)}-{_remap_ip(b, ma)}"
        return token

    try:
        net = ipaddress.ip_network(token, strict=False)
        for m in maps:
            if net == m.old:
                return str(m.new)
            if net.subnet_of(m.old):
                offset = int(net.network_address) - int(m.old.network_address)
                new_base = ipaddress.ip_address(int(m.new.network_address) + offset)
                return str(ipaddress.ip_network(f"{new_base}/{net.prefixlen}", strict=False))
        return token
    except ValueError:
        pass

    try:
        ip = ipaddress.ip_address(token)
        m = _find_mapping_for_ip(ip, maps)
        if not m:
            return token
        new_ip = _remap_ip(ip, m)
        logger.info("Remapping IP: %s -> %s", ip, new_ip)
        return str(new_ip)
    except ValueError:
        return token


def deep_remap(obj: Any, maps: list[SubnetMap]) -> tuple[Any, int]:
    if isinstance(obj, dict):
        out, n = {}, 0
        for k, v in obj.items():
            v2, dn = deep_remap(v, maps)
            out[k] = v2
            n += dn
        return out, n

    if isinstance(obj, list):
        out, n = [], 0
        for v in obj:
            v2, dn = deep_remap(v, maps)
            out.append(v2)
            n += dn
        return out, n

    if isinstance(obj, str) and looks_like_ip_token(obj):
        new_s = remap_token(obj, maps)
        return new_s, int(new_s != obj)

    return obj, 0


# =============================================================================
# Conversion logic
# =============================================================================

def convert_groups_in_doc(
    doc: Any,
    maps: list[SubnetMap],
    new_domain_path: str,
) -> tuple[Any, int, int]:

    _, groups = find_groups_container(doc)

    converted: list[dict] = []
    replaced_total = 0

    for g in groups:
        new_g, replaced = deep_remap(g, maps)
        if replaced == 0:
            continue

        old_id = new_g.get("id")
        if not old_id:
            raise SystemExit("Group missing id")

        new_group_id = f"{old_id}__new"
        apply_new_identity(new_g, new_group_id, new_domain_path)

        for expr in new_g.get("expression", []) or []:
            if isinstance(expr, dict):
                rebuild_expression_paths(expr, new_g["path"])

        append_new_to_group_name(new_g)

        converted.append(new_g)
        replaced_total += replaced

    if isinstance(doc, dict) and len(groups) == 1 and groups[0] is doc:
        return (converted[0], 1, replaced_total) if converted else (doc, 0, 0)

    if isinstance(doc, list):
        return converted, len(converted), replaced_total

    out = dict(doc)
    for key in ("results", "groups"):
        if key in out:
            out[key] = converted
            return out, len(converted), replaced_total

    return converted, len(converted), replaced_total


# =============================================================================
# File handling
# =============================================================================

def iter_group_files(nsx_export_dir: Path) -> list[Path]:
    return sorted(
        p for p in nsx_export_dir.rglob("*")
        if p.is_file()
        and p.suffix.lower() in {".yml", ".yaml", ".json"}
        and "/groups/" in p.as_posix().lower()
    )


def out_path_for(in_file: Path, src: Path, dst: Path) -> Path:
    return dst / in_file.relative_to(src)


# =============================================================================
# CLI
# =============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Create new NSX groups with remapped IPs")
    ap.add_argument("--csv", default=str(CSV_DEFAULT))
    ap.add_argument("--nsx-export", default=str(NSX_EXPORT_DIR_DEFAULT))
    ap.add_argument("--nsx-converted", default=str(NSX_CONVERTED_DIR_DEFAULT))
    ap.add_argument(
        "--new-domain-path",
        required=True,
        help="Target domain path (e.g. /global-infra/domains/default)",
    )
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    maps = read_csv_mappings(Path(args.csv))
    in_files = iter_group_files(Path(args.nsx_export))

    total_groups = total_replacements = written = 0

    for f in in_files:
        doc = load_doc(f)
        out_doc, groups, replaced = convert_groups_in_doc(
            doc,
            maps,
            args.new_domain_path,
        )
        if groups == 0:
            continue

        out_f = out_path_for(f, Path(args.nsx_export), Path(args.nsx_converted))
        print(f"[convert] {f} -> {out_f}  (groups={groups}, replacements={replaced})")

        total_groups += groups
        total_replacements += replaced

        if not args.dry_run:
            out_f.parent.mkdir(parents=True, exist_ok=True)
            write_output(out_f, out_doc)
            written += 1

    print("\nDone.")
    print(f"- Groups converted: {total_groups}")
    print(f"- Replacements made: {total_replacements}")
    print(f"- Files written: {written}")


if __name__ == "__main__":
    main()