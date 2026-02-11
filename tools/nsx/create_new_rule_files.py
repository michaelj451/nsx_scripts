#!/usr/bin/env python3
"""
tools/nsx/create_new_rule_files.py

Create updated rule files: add existing NEW groups to GM policy rules whenever the OLD group
appears in source_groups or destination_groups.

ADD-ONLY. Old groups are never removed.

CRITICAL SAFETY:
- Only add "<old_group> + NEW_GROUP_SUFFIX" if that NEW group actually exists in the
  remapped-groups output. This prevents dependency errors (phantom groups).

Inputs:
- YAML (.yml/.yaml) and JSON (.json) files anywhere under --in-dir

Outputs:
- Writes modified copies to ./nsx_updated_rules (fixed)
- Supports output format: same as input (default), or force yaml/json

Logging:
- Always logs to ./nsx_logs/create_new_rule_files.log
- Also logs to console
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, List, Set

import yaml


# ============================================================
# GLOBAL DEFAULTS
# ============================================================

OUTPUT_DIR_NAME = "nsx_updated_rules"
REMAPPED_GROUPS_DIR_NAME = "nsx_remapped_groups"

LOG_DIR_NAME = "nsx_logs"
LOG_FILE_NAME = "create_new_rule_files.log"

NEW_GROUP_SUFFIX = "_m2"  # must match create_new_group_files.py output

DEFAULT_GROUP_PREFIX = "/global-infra/domains/default/groups/"


# ============================================================
# Logging (always-on)
# ============================================================

def setup_logging() -> logging.Logger:
    log_dir = Path(LOG_DIR_NAME)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / LOG_FILE_NAME

    logger = logging.getLogger("create_new_rule_files")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

        fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(fmt)

        sh = logging.StreamHandler()
        sh.setLevel(logging.INFO)
        sh.setFormatter(fmt)

        logger.addHandler(fh)
        logger.addHandler(sh)

    return logger


log = setup_logging()


# ============================================================
# Defaults
# ============================================================

def _repo_root() -> Path:
    # repo_root = .../nsx_scripts (because this file is repo/tools/nsx/create_new_rule_files.py)
    return Path(__file__).resolve().parents[2]


def _default_remapped_groups_dir() -> Path:
    return _repo_root() / REMAPPED_GROUPS_DIR_NAME


# ============================================================
# Naming convention
# ============================================================

def derive_new_group(old_group_path: str) -> str:
    """Derive the new group path from the old group path."""
    if old_group_path.endswith(NEW_GROUP_SUFFIX):
        return old_group_path
    return f"{old_group_path}{NEW_GROUP_SUFFIX}"


# ============================================================
# Format helpers
# ============================================================

def detect_format(path: Path) -> str:
    suf = path.suffix.lower()
    if suf == ".json":
        return "json"
    if suf in {".yaml", ".yml"}:
        return "yaml"
    raise ValueError(f"Unsupported file type: {path} (expected .json/.yaml/.yml)")


def out_path_for(src: Path, in_root: Path, out_root: Path, out_format: str) -> Path:
    """Preserve relative structure; optionally convert suffix."""
    rel = src.relative_to(in_root)

    if out_format == "same":
        return out_root / rel
    if out_format == "json":
        return (out_root / rel).with_suffix(".json")
    if out_format == "yaml":
        return (out_root / rel).with_suffix(".yaml")
    raise ValueError(f"Invalid out_format: {out_format}")


# ============================================================
# IO helpers
# ============================================================

def load_doc(path: Path) -> Any:
    fmt = detect_format(path)
    text = path.read_text(encoding="utf-8")
    if fmt == "json":
        return json.loads(text)
    return yaml.safe_load(text)


def write_doc(path: Path, data: Any, fmt: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        return
    if fmt == "yaml":
        path.write_text(
            yaml.safe_dump(
                data,
                sort_keys=False,
                default_flow_style=False,
                width=120,
            ),
            encoding="utf-8",
        )
        return
    raise ValueError(f"Unsupported output format: {fmt}")


def iter_docs(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in {".json", ".yaml", ".yml"}:
            yield p


# ============================================================
# Remapped-groups discovery (what NEW groups actually exist)
# ============================================================

def _find_domain_root(export_root: Path) -> Path:
    """
    Support either:
      <export_root>/domains/...
    or:
      <export_root>/<manager>/domains/...
    Returns the directory that directly contains 'domains/'.
    """
    if (export_root / "domains").is_dir():
        return export_root

    for mgr_dir in export_root.iterdir():
        if mgr_dir.is_dir() and (mgr_dir / "domains").is_dir():
            return mgr_dir

    raise SystemExit(
        "Could not find a 'domains' directory. Expected either:\n"
        f"  1) {export_root}/domains/<domain-id>/groups\n"
        f"  2) {export_root}/<manager>/domains/<domain-id>/groups"
    )


def load_existing_new_group_paths(remapped_root: Path) -> Set[str]:
    """
    Scan remapped group files and return a set of full DEFAULT-domain group paths that exist.
    Record objects where resource_type == 'Group' and 'id' is present.
    """
    domain_root = _find_domain_root(remapped_root)

    paths: Set[str] = set()
    for p in iter_docs(domain_root):
        try:
            doc = load_doc(p)
        except Exception:
            continue

        if not isinstance(doc, dict):
            continue
        if doc.get("resource_type") != "Group":
            continue

        gid = doc.get("id")
        if isinstance(gid, str) and gid:
            # Only default domain per project scope
            paths.add(f"{DEFAULT_GROUP_PREFIX}{gid}")

    return paths


# ============================================================
# Mutation logic
# ============================================================

def add_group_if_needed(group_list: List[Any], old_group: str, existing_new_paths: Set[str]) -> bool:
    """
    If old_group is a DEFAULT-domain group path, add derived new group if missing.
    BUT: only add if that derived new group actually exists in existing_new_paths.
    """
    if not old_group.startswith(DEFAULT_GROUP_PREFIX):
        return False

    new_group = derive_new_group(old_group)

    # old group already suffixed
    if new_group == old_group:
        return False

    # Safety: only reference new groups that exist
    if new_group not in existing_new_paths:
        return False

    if new_group in group_list:
        return False

    group_list.append(new_group)
    return True


def walk(obj: Any, changed: List[str], existing_new_paths: Set[str], context: str = "$") -> None:
    """
    Walk doc; when dict contains source_groups or destination_groups lists,
    add derived new group paths (additive only), but only when those new groups exist.
    """
    if isinstance(obj, dict):
        for field in ("source_groups", "destination_groups"):
            groups = obj.get(field)
            if isinstance(groups, list):
                for g in list(groups):
                    if isinstance(g, str) and add_group_if_needed(groups, g, existing_new_paths):
                        changed.append(f"{context}.{field}: added {derive_new_group(g)}")

        for k, v in obj.items():
            walk(v, changed, existing_new_paths, f"{context}.{k}")

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            walk(item, changed, existing_new_paths, f"{context}[{i}]")


# ============================================================
# CLI
# ============================================================

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Create updated rule files: add NEW groups wherever OLD groups are referenced (additive only)."
    )
    ap.add_argument(
        "--in-dir",
        type=Path,
        required=True,
        help="Directory containing exported GM policy/rule YAML/JSON",
    )
    ap.add_argument(
        "--remapped-groups-dir",
        type=Path,
        default=_default_remapped_groups_dir(),
        help=f"Directory containing newly created group files (default: <repo>/{REMAPPED_GROUPS_DIR_NAME}).",
    )
    ap.add_argument(
        "--out-format",
        choices=["same", "yaml", "json"],
        default="same",
        help="Output format. 'same' keeps each file's input format (default).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyze only; do not write nsx_updated_rules",
    )

    args = ap.parse_args()

    in_dir: Path = args.in_dir
    out_root: Path = Path(OUTPUT_DIR_NAME)
    remapped_dir: Path = args.remapped_groups_dir

    if not in_dir.exists():
        raise SystemExit(f"--in-dir not found: {in_dir}")
    if not remapped_dir.exists():
        raise SystemExit(f"--remapped-groups-dir not found: {remapped_dir}")

    existing_new_paths = load_existing_new_group_paths(remapped_dir)

    log.info("Starting create_new_rule_files")
    log.info("Input directory:        %s", in_dir)
    log.info("Remapped groups dir:    %s", remapped_dir)
    log.info("Loaded new group paths: %d", len(existing_new_paths))
    log.info("Output directory:       %s", out_root.resolve())
    log.info("Output format:          %s", args.out_format)
    log.info("Dry run:                %s", args.dry_run)
    log.info("New group suffix:       %s", NEW_GROUP_SUFFIX)

    total_additions = 0
    processed = 0
    written = 0
    skipped_parse = 0

    for src in iter_docs(in_dir):
        processed += 1
        rel = src.relative_to(in_dir)

        try:
            doc = load_doc(src)
        except Exception as e:
            skipped_parse += 1
            log.warning("SKIP parse error: %s (%s)", rel, e)
            continue

        changes: List[str] = []
        walk(doc, changes, existing_new_paths)

        out_path = out_path_for(src, in_dir, out_root, args.out_format)
        out_fmt = detect_format(src) if args.out_format == "same" else args.out_format

        if changes:
            total_additions += len(changes)
            log.info("CHANGES %s (%d additions)", rel, len(changes))
            for c in changes:
                log.info("  %s", c)

        if args.dry_run:
            continue

        write_doc(out_path, doc, out_fmt)
        written += 1

    log.info("Finished create_new_rule_files")
    log.info("Processed files:        %d", processed)
    log.info("Skipped (parse errors): %d", skipped_parse)
    log.info("Total group additions:  %d", total_additions)
    if args.dry_run:
        log.info("Dry-run only. No files written.")
    else:
        log.info("Written files:          %d", written)
        log.info("Output directory:       %s", out_root.resolve())
        log.info("Log file:               %s", (Path(LOG_DIR_NAME) / LOG_FILE_NAME).resolve())


if __name__ == "__main__":
    main()