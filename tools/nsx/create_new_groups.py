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
from typing import Any, Iterable, Optional, Tuple

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Defaults
# =============================================================================

REPO_ROOT = Path(__file__).resolve().parents[2]  # nsx_scripts/
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

    # Prefer more specific first
    maps.sort(key=lambda m: (m.old.version, -m.old.prefixlen))
    return maps


# =============================================================================
# YAML/JSON IO
# =============================================================================

def load_doc(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    if path.suffix.lower() in {".yml", ".yaml"}:
        return yaml.safe_load(text)
    raise SystemExit(f"Unsupported input extension: {path.suffix} (use .yaml/.yml/.json)")


def write_output(path: Path, obj: Any) -> None:
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(obj, indent=2, sort_keys=False), encoding="utf-8")
        return
    if path.suffix.lower() in {".yml", ".yaml"}:
        path.write_text(yaml.safe_dump(obj, sort_keys=False), encoding="utf-8")
        return
    raise SystemExit(f"Unsupported output extension: {path.suffix} (use .yaml/.yml/.json)")


# =============================================================================
# Group doc shape handling
# =============================================================================

def find_groups_container(doc: Any) -> Tuple[Any, list[dict]]:
    """
    Return (container, groups_list).

    Supported shapes:
      A) [ {...}, {...} ]
      B) { "results": [ {...}, ... ] }
      C) { "groups":  [ {...}, ... ] }
      D) { "objects": { "groups": [ {...}, ... ] } }
      E) { "<domain>": { "groups": [ {...}, ... ] }, ... }
      F) { "<name>": {...}, ... } (dict keyed by group name -> group dict)
      G) { ...single group object... } (one group per file)
      H) { "items"/"data"/"resources"/"children": [ {...}, ... ] }
    """

    def looks_like_group(g: dict) -> bool:
        keys = set(g.keys())
        return bool(keys & {"display_name", "name", "expression", "id", "path"}) and (
            "expression" in keys or "path" in keys or "id" in keys
        )

    # A) list
    if isinstance(doc, list) and all(isinstance(x, dict) for x in doc):
        return doc, doc

    if isinstance(doc, dict):
        # G) single group object
        if looks_like_group(doc):
            return doc, [doc]

        # B) results
        if isinstance(doc.get("results"), list) and all(isinstance(x, dict) for x in doc["results"]):
            return doc, doc["results"]

        # H) common wrapper lists
        for key in ("items", "data", "resources", "children"):
            if isinstance(doc.get(key), list) and all(isinstance(x, dict) for x in doc[key]):
                return doc, doc[key]

        # C) groups
        if isinstance(doc.get("groups"), list) and all(isinstance(x, dict) for x in doc["groups"]):
            return doc, doc["groups"]

        # D) objects.groups
        obj = doc.get("objects")
        if isinstance(obj, dict) and isinstance(obj.get("groups"), list) and all(isinstance(x, dict) for x in obj["groups"]):
            return obj, obj["groups"]

        # E) nested wrappers
        for v in doc.values():
            if isinstance(v, dict) and isinstance(v.get("groups"), list) and all(isinstance(x, dict) for x in v["groups"]):
                return v, v["groups"]

        # F) keyed dict of group objects
        if doc and all(isinstance(v, dict) for v in doc.values()):
            values = list(doc.values())
            if any(looks_like_group(v) for v in values):
                return doc, values

    raise SystemExit(
        "Unrecognized groups document shape. "
        "Expected list, {results:[...]}, {groups:[...]}, {objects:{groups:[...]}}, "
        "nested dict containing groups, wrapper lists (items/data/resources/children), "
        "or a single group object."
    )


def append_new_to_group_name(group: dict[str, Any]) -> None:
    if "display_name" in group and isinstance(group["display_name"], str):
        group["display_name"] = f"{group['display_name']} new"
        return
    if "name" in group and isinstance(group["name"], str):
        group["name"] = f"{group['name']} new"
        return


# =============================================================================
# Token detection + remap (IP, CIDR, range)
# =============================================================================

_RANGE_RE = re.compile(r"^\s*([0-9a-fA-F\.:]+)\s*-\s*([0-9a-fA-F\.:]+)\s*$")


def looks_like_ip_token(s: str) -> bool:
    s = s.strip()
    if not s:
        return False

    m = _RANGE_RE.match(s)
    if m:
        a, b = m.groups()
        try:
            ipaddress.ip_address(a)
            ipaddress.ip_address(b)
            return True
        except ValueError:
            return False

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
        if ip.version != m.old.version:
            continue
        if ip in m.old:
            return m
    return None


def _remap_ip(ip: ipaddress._BaseAddress, m: SubnetMap) -> ipaddress._BaseAddress:
    old_root = int(m.old.network_address)
    new_root = int(m.new.network_address)
    offset = int(ip) - old_root
    return ipaddress.ip_address(new_root + offset)


def remap_token(token: str, maps: list[SubnetMap]) -> str:
    s = token.strip()
    if not s:
        return token

    # Range: ip-ip
    mrange = _RANGE_RE.match(s)
    if mrange:
        a_s, b_s = mrange.groups()
        a = ipaddress.ip_address(a_s)
        b = ipaddress.ip_address(b_s)

        ma = _find_mapping_for_ip(a, maps)
        mb = _find_mapping_for_ip(b, maps)

        # remap only if both endpoints map to same old subnet
        if ma is None or mb is None or ma.old != mb.old:
            return token

        a2 = _remap_ip(a, ma)
        b2 = _remap_ip(b, ma)
        return f"{a2}-{b2}"

    # CIDR
    try:
        net = ipaddress.ip_network(s, strict=False)

        # exact old->new
        for mp in maps:
            if net == mp.old:
                return str(mp.new)

        # subnet inside old->shift
        for mp in maps:
            if net.version != mp.old.version:
                continue
            if net.subnet_of(mp.old):
                old_base = int(net.network_address)
                old_root = int(mp.old.network_address)
                new_root = int(mp.new.network_address)
                offset = old_base - old_root
                new_base_ip = ipaddress.ip_address(new_root + offset)
                new_net = ipaddress.ip_network(f"{new_base_ip}/{net.prefixlen}", strict=False)
                return str(new_net)

        return token
    except ValueError:
        pass

    # Single IP
    try:
        ip = ipaddress.ip_address(s)
        mp = _find_mapping_for_ip(ip, maps)
        if mp is None:
            return token
        return str(_remap_ip(ip, mp))
    except ValueError:
        return token


def deep_remap(obj: Any, maps: list[SubnetMap]) -> Any:
    if isinstance(obj, dict):
        return {k: deep_remap(v, maps) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deep_remap(v, maps) for v in obj]
    if isinstance(obj, str) and looks_like_ip_token(obj):
        return remap_token(obj, maps)
    return obj


# =============================================================================
# Conversion logic
# =============================================================================

def group_has_any_ip_token(group: dict) -> bool:
    def walk(o: Any) -> bool:
        if isinstance(o, dict):
            return any(walk(v) for v in o.values())
        if isinstance(o, list):
            return any(walk(v) for v in o)
        if isinstance(o, str):
            return looks_like_ip_token(o)
        return False
    return walk(group)


def convert_groups_in_doc(doc: Any, maps: list[SubnetMap]) -> tuple[Any, int]:
    container, groups_list = find_groups_container(doc)

    converted: list[dict] = []
    for g in groups_list:
        if not isinstance(g, dict):
            continue
        if not group_has_any_ip_token(g):
            continue

        new_g = deep_remap(g, maps)
        if not isinstance(new_g, dict):
            continue

        append_new_to_group_name(new_g)
        converted.append(new_g)

    # If input is a single-group file, keep single-group output
    if isinstance(doc, dict) and len(groups_list) == 1 and groups_list[0] is doc:
        if converted:
            return converted[0], 1
        return doc, 0

    # Keep original doc shape but only with converted groups
    if isinstance(doc, list):
        return converted, len(converted)

    if isinstance(doc, dict) and "results" in doc and isinstance(doc["results"], list):
        out_doc = dict(doc)
        out_doc["results"] = converted
        return out_doc, len(converted)

    if isinstance(doc, dict) and "groups" in doc and isinstance(doc["groups"], list):
        out_doc = dict(doc)
        out_doc["groups"] = converted
        return out_doc, len(converted)

    if isinstance(doc, dict):
        out_doc: dict[str, Any] = {}
        for cg in converted:
            key = cg.get("display_name") or cg.get("name") or cg.get("id") or "group_new"
            out_doc[str(key)] = cg
        return out_doc, len(converted)

    return converted, len(converted)


# =============================================================================
# File iteration + output paths
# =============================================================================

def iter_group_files(nsx_export_dir: Path) -> list[Path]:
    """
    Only pick files likely to be group exports.
    This matches your exporter structure where groups are often under a 'groups/' directory.
    """
    exts = {".yml", ".yaml", ".json"}
    files: list[Path] = []

    for p in nsx_export_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in exts:
            continue
        ps = p.as_posix().lower()
        if "/groups/" in ps or p.name.lower().startswith("groups."):
            files.append(p)

    return sorted(files)


def out_path_for(in_file: Path, nsx_export_dir: Path, nsx_converted_dir: Path) -> Path:
    rel = in_file.relative_to(nsx_export_dir)
    return nsx_converted_dir / rel


def debug_doc_shape(file_path: Path, doc: Any) -> None:
    print("\n=== FILE ===", file_path)
    print("TOP LEVEL TYPE:", type(doc))
    if isinstance(doc, dict):
        print("TOP LEVEL KEYS:", list(doc.keys())[:60])


# =============================================================================
# CLI
# =============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Convert NSX groups from nsx_export to nsx_converted using subnet CSV mappings."
    )
    ap.add_argument(
        "--csv",
        dest="csv_path",
        default=str(CSV_DEFAULT),
        help=f"CSV with headers old_subnet,new_subnet,vlan,description (default: {CSV_DEFAULT})",
    )
    ap.add_argument(
        "--nsx-export",
        dest="nsx_export_dir",
        default=str(NSX_EXPORT_DIR_DEFAULT),
        help=f"Input directory (default: {NSX_EXPORT_DIR_DEFAULT})",
    )
    ap.add_argument(
        "--nsx-converted",
        dest="nsx_converted_dir",
        default=str(NSX_CONVERTED_DIR_DEFAULT),
        help=f"Output directory (default: {NSX_CONVERTED_DIR_DEFAULT})",
    )
    ap.add_argument("--dry-run", action="store_true", help="Show what would be converted without writing files")
    ap.add_argument("--debug", action="store_true", help="Print detected YAML/JSON shapes for troubleshooting")
    args = ap.parse_args()

    csv_path = Path(args.csv_path)
    nsx_export_dir = Path(args.nsx_export_dir)
    nsx_converted_dir = Path(args.nsx_converted_dir)

    # Fail loudly if paths are wrong
    if not nsx_export_dir.exists():
        raise SystemExit(f"nsx_export_dir does not exist: {nsx_export_dir}")
    if not csv_path.exists():
        raise SystemExit(f"CSV does not exist: {csv_path}")

    maps = read_csv_mappings(csv_path)

    in_files = iter_group_files(nsx_export_dir)
    if not in_files:
        print(f"No group YAML/JSON files found under: {nsx_export_dir}")
        return

    total_files = 0
    total_groups = 0
    written_files = 0
    skipped_unrecognized = 0

    for f in in_files:
        doc = load_doc(f)
        if args.debug:
            debug_doc_shape(f, doc)

        try:
            out_doc, converted_count = convert_groups_in_doc(doc, maps)
        except SystemExit as e:
            if args.debug:
                print(f"[skip] {f} -> {e}")
            skipped_unrecognized += 1
            continue

        total_files += 1
        total_groups += converted_count

        if converted_count == 0:
            continue

        out_f = out_path_for(f, nsx_export_dir, nsx_converted_dir)
        print(f"[convert] {f} -> {out_f}  (groups converted: {converted_count})")

        if args.dry_run:
            continue

        out_f.parent.mkdir(parents=True, exist_ok=True)
        write_output(out_f, out_doc)
        written_files += 1

    print("\nDone.")
    print(f"- Candidate group files found: {len(in_files)}")
    print(f"- Files parsed as group documents: {total_files}")
    print(f"- Unrecognized/Skipped: {skipped_unrecognized}")
    print(f"- Groups converted: {total_groups}")
    if args.dry_run:
        print("- Dry run: no files written")
    else:
        print(f"- Files written: {written_files}")


if __name__ == "__main__":
    main()