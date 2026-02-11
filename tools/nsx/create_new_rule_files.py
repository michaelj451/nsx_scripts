#!/usr/bin/env python3
"""
Add existing NEW groups to GM policy rules whenever the OLD group appears
in source_groups or destination_groups.

ADD-ONLY. Old groups are never removed.
Writes modified copies to ./nsx_updated_rules
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, List

import yaml


# ============================================================
# GLOBAL DEFAULTS (intentionally fixed)
# ============================================================

OUTPUT_DIR_NAME = "nsx_updated_rules"
NEW_GROUP_SUFFIX = "-dc2"   # change if naming ever changes


def derive_new_group(old_group_path: str) -> str:
    """
    Derive the new group path from the old group path.
    """
    if old_group_path.endswith(NEW_GROUP_SUFFIX):
        return old_group_path
    return f"{old_group_path}{NEW_GROUP_SUFFIX}"


# ============================================================
# IO helpers
# ============================================================

def load_doc(path: Path) -> Any:
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text())
    return yaml.safe_load(path.read_text())


def write_doc(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(data, indent=2) + "\n")
    else:
        path.write_text(yaml.safe_dump(data, sort_keys=False))


def iter_docs(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".json", ".yaml", ".yml"}:
            yield p


# ============================================================
# Mutation logic
# ============================================================

def add_group_if_needed(group_list: List[Any], old_group: str) -> bool:
    if old_group not in group_list:
        return False

    new_group = derive_new_group(old_group)

    if new_group in group_list:
        return False

    group_list.append(new_group)
    return True


def walk(obj: Any, changed: List[str], context: str = "$") -> None:
    if isinstance(obj, dict):
        for field in ("source_groups", "destination_groups"):
            groups = obj.get(field)
            if isinstance(groups, list):
                for g in list(groups):
                    if isinstance(g, str):
                        if add_group_if_needed(groups, g):
                            changed.append(
                                f"{context}.{field}: added {derive_new_group(g)}"
                            )

        for k, v in obj.items():
            walk(v, changed, f"{context}.{k}")

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            walk(item, changed, f"{context}[{i}]")


# ============================================================
# CLI
# ============================================================

def main():
    ap = argparse.ArgumentParser(
        description="Add NEW GM groups to rules wherever OLD groups are referenced (additive only)."
    )
    ap.add_argument(
        "--in-dir",
        type=Path,
        required=True,
        help="Directory containing exported GM policy/rule YAML/JSON"
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyze only; do not write nsx_updated_rules"
    )

    args = ap.parse_args()

    in_dir: Path = args.in_dir
    out_dir: Path = Path(OUTPUT_DIR_NAME)

    total_changes = 0

    for src in iter_docs(in_dir):
        rel = src.relative_to(in_dir)
        doc = load_doc(src)

        changes: List[str] = []
        walk(doc, changes)

        if not changes:
            if not args.dry_run:
                write_doc(out_dir / rel, doc)
            continue

        total_changes += len(changes)

        print(f"\n== {rel} ==")
        for c in changes:
            print(f"  {c}")

        if not args.dry_run:
            write_doc(out_dir / rel, doc)

    print(f"\nTotal group additions: {total_changes}")
    if args.dry_run:
        print("Dry-run only. No files written.")
    else:
        print(f"Updated files written to ./{OUTPUT_DIR_NAME}")


if __name__ == "__main__":
    main()