#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from utilities.subnet_conversion import (
    load_groups,
    read_csv_mappings,
    deep_remap,
    append_new_to_group_name,
    write_output,
    find_groups_container,
    looks_like_ip_or_cidr,
)

# ---- Defaults (override via CLI flags if you want) ----
REPO_ROOT = Path(__file__).resolve().parents[2]

NSX_EXPORT_DIR_DEFAULT = REPO_ROOT / "nsx_export"
NSX_CONVERTED_DIR_DEFAULT = REPO_ROOT / "nsx_converted"
CSV_DEFAULT = REPO_ROOT / "data" / "subnet_map.csv"


def group_has_any_ip_or_cidr(group: dict) -> bool:
    """
    Lightweight detection: recurse the group dict and return True if any scalar string
    looks like an IP or CIDR.
    """
    def walk(o: Any) -> bool:
        if isinstance(o, dict):
            return any(walk(v) for v in o.values())
        if isinstance(o, list):
            return any(walk(v) for v in o)
        if isinstance(o, str):
            return looks_like_ip_or_cidr(o.strip())
        return False

    return walk(group)


def convert_groups_in_doc(doc: Any, maps) -> tuple[Any, int]:
    """
    Returns (output_doc, converted_count) in the same overall doc "shape" but
    containing ONLY converted groups.
    """
    _container, groups_list = find_groups_container(doc)

    converted: list[dict] = []
    for g in groups_list:
        if not isinstance(g, dict):
            continue
        if not group_has_any_ip_or_cidr(g):
            continue

        new_g = deep_remap(g, maps)
        if not isinstance(new_g, dict):
            continue

        append_new_to_group_name(new_g)
        converted.append(new_g)

    # Keep original doc shape but only with converted groups
    if isinstance(doc, list):
        return converted, len(converted)

    if isinstance(doc, dict) and "results" in doc and isinstance(doc["results"], list):
        out_doc = dict(doc)
        out_doc["results"] = converted
        return out_doc, len(converted)

    if isinstance(doc, dict):
        # keyed dict case: key by display_name/name/id
        out_doc: dict[str, Any] = {}
        for cg in converted:
            key = cg.get("display_name") or cg.get("name") or cg.get("id") or "group_new"
            out_doc[str(key)] = cg
        return out_doc, len(converted)

    # fallback
    return converted, len(converted)


def iter_group_files(nsx_export_dir: Path) -> list[Path]:
    """
    Only pick files that are likely to contain groups.
    Adjust patterns to match your exporter layout.
    """
    exts = {".yml", ".yaml", ".json"}

    files: list[Path] = []
    for p in nsx_export_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in exts:
            continue

        ps = p.as_posix().lower()

        # common exporter layouts:
        # nsx_export/<mgr>/groups/groups.yaml
        # nsx_export/<mgr>/domains/<domain>/groups/groups.yaml
        # nsx_export/<mgr>/.../groups.yaml
        if "/groups/" in ps or p.name.lower().startswith("groups."):
            files.append(p)

    return sorted(files)

def debug_doc_shape(file_path: Path, doc: Any) -> None:
    print("\n=== FILE ===", file_path)
    print("TOP LEVEL TYPE:", type(doc))
    if isinstance(doc, dict):
        keys = list(doc.keys())
        print("TOP LEVEL KEYS:", keys[:40])
        # helpful peeks for common wrappers
        if "groups" in doc and isinstance(doc["groups"], list):
            print("groups count:", len(doc["groups"]))
        if "results" in doc and isinstance(doc["results"], list):
            print("results count:", len(doc["results"]))
        if "objects" in doc and isinstance(doc["objects"], dict) and isinstance(doc["objects"].get("groups"), list):
            print("objects.groups count:", len(doc["objects"]["groups"]))


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Convert NSX group files from nsx_export to nsx_converted using subnet CSV mappings."
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

    # Fail loudly instead of silently creating wrong paths
    if not nsx_export_dir.exists():
        raise SystemExit(f"nsx_export_dir does not exist: {nsx_export_dir}")
    if not csv_path.exists():
        raise SystemExit(f"CSV does not exist: {csv_path}")

    maps = read_csv_mappings(csv_path)

    in_files = iter_group_files(nsx_export_dir)
    if not in_files:
        print(f"No YAML/JSON files found under: {nsx_export_dir}")
        return

    total_files = 0
    total_groups = 0
    written_files = 0
    skipped_unrecognized = 0

    for f in in_files:
        doc = load_groups(f)

        if args.debug:
            debug_doc_shape(f, doc)

        try:
            out_doc, converted_count = convert_groups_in_doc(doc, maps)
        except SystemExit as e:
            # Usually "Unrecognized groups document shape..." from find_groups_container
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
    print(f"- Files scanned: {len(in_files)}")
    print(f"- Files parsed as group documents: {total_files}")
    print(f"- Unrecognized/Skipped: {skipped_unrecognized}")
    print(f"- Groups converted: {total_groups}")
    if args.dry_run:
        print("- Dry run: no files written")
    else:
        print(f"- Files written: {written_files}")


if __name__ == "__main__":
    main()