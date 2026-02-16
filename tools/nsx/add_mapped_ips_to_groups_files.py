#!/usr/bin/env python3
"""
tools/nsx/add_mapped_ips_to_groups_files.py

Additive behavior:
- For any IP-ish token in IPAddressExpression.ip_addresses that matches an old_subnet mapping,
  append the mapped token (new subnet / remapped IP / remapped range).
- Never remove anything.
- Idempotent: does not add duplicates.

Inputs:
- --nsx-export: exported NSX objects (default ./nsx_export)
- --csv: subnet mapping (default ./data/subnet_map.csv)

Outputs:
- --nsx-updated: updated group files (default ./nsx_groups_additive)
- Preserves relative directory structure from nsx_export

Logging:
- Console + ./nsx_logs/add_mapped_ips_to_groups_files.log
- JSONL changes are still written by nsx_group_remap.py to ./nsx_logs/nsx_group_remap_changes.jsonl
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from nsx.nsx_object_functions.nsx_group_remap import (
    read_csv_mappings,
    load_doc,
    write_output,
    out_path_for,
    iter_group_files,
    add_mapped_ips_in_doc,
)

LOG_DIR_NAME = "nsx_logs"
LOG_FILE_NAME = "add_mapped_ips_to_groups_files.log"


def setup_logging() -> logging.Logger:
    repo_root = Path(__file__).resolve().parents[2]
    log_dir = repo_root / LOG_DIR_NAME
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / LOG_FILE_NAME

    logger = logging.getLogger("add_mapped_ips_to_groups_files")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)

    logger.info("Log file: %s", log_file)
    return logger


log = setup_logging()

REPO_ROOT = Path(__file__).resolve().parents[2]
NSX_EXPORT_DIR_DEFAULT = REPO_ROOT / "nsx_export"
NSX_UPDATED_DIR_DEFAULT = REPO_ROOT / "nsx_groups_additive"
CSV_DEFAULT = REPO_ROOT / "data" / "subnet_map.csv"


def main() -> None:
    ap = argparse.ArgumentParser(description="Add mapped IPs/subnets/ranges to existing NSX groups (additive only)")
    ap.add_argument("--csv", default=str(CSV_DEFAULT), help="CSV with old_subnet,new_subnet,vlan,description")
    ap.add_argument("--nsx-export", default=str(NSX_EXPORT_DIR_DEFAULT), help="Input export root (default: ./nsx_export)")
    ap.add_argument("--nsx-updated", default=str(NSX_UPDATED_DIR_DEFAULT), help="Output root (default: ./nsx_groups_additive)")
    ap.add_argument("--dry-run", action="store_true", help="Analyze only; do not write output files.")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    export_root = Path(args.nsx_export)
    out_root = Path(args.nsx_updated)

    log.info("Starting add_mapped_ips_to_groups_files")
    log.info("CSV:           %s", csv_path)
    log.info("NSX export:     %s", export_root)
    log.info("NSX updated:    %s", out_root)
    log.info("Dry-run:        %s", args.dry_run)

    if not csv_path.exists():
        raise SystemExit(f"CSV not found: {csv_path}")
    if not export_root.exists():
        raise SystemExit(f"Export dir not found: {export_root}")

    maps = read_csv_mappings(csv_path)
    in_files = iter_group_files(export_root)

    scanned = 0
    docs_with_changes = 0
    groups_touched_total = 0
    tokens_added_total = 0
    written = 0
    skipped_parse = 0

    for f in in_files:
        scanned += 1
        rel = f.relative_to(export_root)

        try:
            doc = load_doc(f)
        except Exception as e:
            skipped_parse += 1
            log.warning("SKIP parse error: %s (%s)", rel, e)
            continue

        updated_doc, groups_touched, tokens_added = add_mapped_ips_in_doc(doc, maps)

        if tokens_added == 0:
            continue

        docs_with_changes += 1
        groups_touched_total += groups_touched
        tokens_added_total += tokens_added

        out_f = out_path_for(f, export_root, out_root)
        log.info("[update] %s -> %s  (groups_touched=%d, tokens_added=%d)",
                 rel, out_f.relative_to(REPO_ROOT), groups_touched, tokens_added)

        if args.dry_run:
            continue

        out_f.parent.mkdir(parents=True, exist_ok=True)
        write_output(out_f, updated_doc)
        written += 1

    log.info("Finished add_mapped_ips_to_groups_files")
    log.info("Scanned files:        %d", scanned)
    log.info("Docs with changes:    %d", docs_with_changes)
    log.info("Groups touched:       %d", groups_touched_total)
    log.info("Tokens added:         %d", tokens_added_total)
    log.info("Skipped parse errors: %d", skipped_parse)
    if args.dry_run:
        log.info("Dry-run only. No files written.")
    else:
        log.info("Files written:        %d", written)
        log.info("Output directory:     %s", out_root.resolve())


if __name__ == "__main__":
    main()