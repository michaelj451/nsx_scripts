#!/usr/bin/env python3
"""
tools/nsx/create_new_rule_files.py

Create updated rule files: add existing NEW groups to GM policy rules whenever the OLD group
appears in source_groups or destination_groups.

ADD-ONLY. Old groups are never removed.

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
from typing import Any, List

import yaml


# ============================================================
# GLOBAL DEFAULTS (intentionally fixed)
# ============================================================

OUTPUT_DIR_NAME = "nsx_updated_rules"
LOG_DIR_NAME = "nsx_logs"
LOG_FILE_NAME = "create_new_rule_files.log"

NEW_GROUP_SUFFIX = "-dc2"  # change if naming ever changes


# ============================================================
# Logging (always-on)
# ============================================================

def setup_logging() -> logging.Logger:
    log_dir = Path(LOG_DIR_NAME)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / LOG_FILE_NAME

    logger = logging.getLogger("create_new_rule_files")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # avoid double logging if root logger configured elsewhere

    # If re-run in same interpreter (rare), avoid duplicate handlers
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
    """
    Compute output path preserving relative structure.
    If out_format == "same", keep original suffix.
    Otherwise convert suffix based on requested format.
    """
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
# Mutation logic
# ============================================================

def add_group_if_needed(group_list: List[Any], old_group: str) -> bool:
    """
    If old_group exists in group_list, add derived new group if missing.
    Returns True if list changed.
    """
    if old_group not in group_list:
        return False

    new_group = derive_new_group(old_group)
    if new_group in group_list:
        return False

    group_list.append(new_group)
    return True


def walk(obj: Any, changed: List[str], context: str = "$") -> None:
    """
    Recursively walk the document, and whenever a dict contains source_groups
    or destination_groups list fields, add derived new group paths.
    """
    if isinstance(obj, dict):
        for field in ("source_groups", "destination_groups"):
            groups = obj.get(field)
            if isinstance(groups, list):
                # Iterate over a snapshot so we don't loop on newly appended values
                for g in list(groups):
                    if isinstance(g, str):
                        if add_group_if_needed(groups, g):
                            changed.append(f"{context}.{field}: added {derive_new_group(g)}")

        for k, v in obj.items():
            walk(v, changed, f"{context}.{k}")

    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            walk(item, changed, f"{context}[{i}]")


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

    if not in_dir.exists():
        raise SystemExit(f"--in-dir not found: {in_dir}")

    log.info("Starting create_new_rule_files")
    log.info("Input directory:  %s", in_dir)
    log.info("Output directory: %s", out_root.resolve())
    log.info("Output format:    %s", args.out_format)
    log.info("Dry run:          %s", args.dry_run)
    log.info("New group suffix: %s", NEW_GROUP_SUFFIX)

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
        walk(doc, changes)

        # Determine output path + format for this file
        out_path = out_path_for(src, in_dir, out_root, args.out_format)
        out_fmt = detect_format(src) if args.out_format == "same" else args.out_format

        if changes:
            total_additions += len(changes)
            log.info("CHANGES %s (%d additions)", rel, len(changes))
            for c in changes:
                log.info("  %s", c)
        else:
            log.debug("NOCHANGE %s", rel)

        if args.dry_run:
            continue

        try:
            write_doc(out_path, doc, out_fmt)
            written += 1
        except Exception as e:
            log.error("FAIL write: %s -> %s (%s)", rel, out_path, e)
            raise

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