#!/usr/bin/env python3
"""
tools/nsx/create_new_group_files.py

Create new (remapped) IP-based NSX Group files from subnet_map.csv.

NEW-ONLY behavior:
- The new group's IPAddressExpression.ip_addresses contains ONLY mapped (new/DC) tokens.
- Unmapped tokens are DROPPED from the new group.
- If a group produces zero mapped tokens, no new group is written.

Inputs:
- Reads exported NSX group docs from --nsx-export (default ./nsx_export)
- Reads subnet mappings from --csv (default ./data/subnet_map.csv)

Outputs:
- Writes converted groups to --nsx-converted (default ./nsx_remapped_groups)
- Preserves relative directory structure from nsx_export

Logging:
- Always logs to ./nsx_logs/create_new_group_files.log
- Also logs to console
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
    convert_groups_in_doc,
    iter_group_files,
)

# =============================================================================
# Logging
# =============================================================================

LOG_DIR_NAME = "nsx_logs"
LOG_FILE_NAME = "create_new_group_files.log"


def setup_logging() -> logging.Logger:
    repo_root = Path(__file__).resolve().parents[2]
    log_dir = repo_root / LOG_DIR_NAME
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / LOG_FILE_NAME

    logger = logging.getLogger("create_new_group_files")
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

# =============================================================================
# Defaults
# =============================================================================

REPO_ROOT = Path(__file__).resolve().parents[2]
NSX_EXPORT_DIR_DEFAULT = REPO_ROOT / "nsx_export"
NSX_CONVERTED_DIR_DEFAULT = REPO_ROOT / "nsx_remapped_groups"
CSV_DEFAULT = REPO_ROOT / "data" / "subnet_map.csv"

APPEND_TO_GROUP_NAME_DEFAULT = "_m2"
NEW_DOMAIN_PATH_DEFAULT = "/global-infra/domains/default"


# =============================================================================
# CLI
# =============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Create new NSX groups with NEW (remapped) IPs only")

    ap.add_argument("--csv", default=str(CSV_DEFAULT), help="CSV with old_subnet,new_subnet,vlan,description")
    ap.add_argument("--nsx-export", default=str(NSX_EXPORT_DIR_DEFAULT), help="Input export root (default: ./nsx_export)")
    ap.add_argument("--nsx-converted", default=str(NSX_CONVERTED_DIR_DEFAULT), help="Output root (default: ./nsx_remapped_groups)")

    ap.add_argument(
        "--new-domain-path",
        default=NEW_DOMAIN_PATH_DEFAULT,
        help="Target domain path for new groups (default: /global-infra/domains/default)",
    )
    ap.add_argument(
        "--suffix",
        default=APPEND_TO_GROUP_NAME_DEFAULT,
        help="Suffix appended to new group IDs and display_names (default: _m2)",
    )
    ap.add_argument("--dry-run", action="store_true", help="Analyze only; do not write output files.")

    args = ap.parse_args()

    csv_path = Path(args.csv)
    export_root = Path(args.nsx_export)
    out_root = Path(args.nsx_converted)

    log.info("Starting create_new_group_files")
    log.info("CSV:            %s", csv_path)
    log.info("NSX export dir:  %s", export_root)
    log.info("Output dir:      %s", out_root)
    log.info("New domain path: %s", args.new_domain_path)
    log.info("Suffix:          %s", args.suffix)
    log.info("Dry-run:         %s", args.dry_run)

    if not csv_path.exists():
        raise SystemExit(f"CSV not found: {csv_path}")
    if not export_root.exists():
        raise SystemExit(f"Export dir not found: {export_root}")

    maps = read_csv_mappings(csv_path)
    in_files = iter_group_files(export_root)

    scanned = 0
    docs_with_output = 0
    groups_converted_total = 0
    ip_tokens_changed_total = 0
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

        out_doc, groups_converted, ip_changed = convert_groups_in_doc(
            doc=doc,
            maps=maps,
            new_domain_path=args.new_domain_path,
            group_name_append=args.suffix,
        )

        if groups_converted == 0:
            continue

        docs_with_output += 1
        groups_converted_total += groups_converted
        ip_tokens_changed_total += ip_changed

        out_f = out_path_for(f, export_root, out_root)
        log.info("[convert] %s -> %s  (groups=%d, ip_changed=%d)", rel, out_f.relative_to(REPO_ROOT), groups_converted, ip_changed)

        if args.dry_run:
            continue

        out_f.parent.mkdir(parents=True, exist_ok=True)
        write_output(out_f, out_doc)
        written += 1

    log.info("Finished create_new_group_files")
    log.info("Scanned files:        %d", scanned)
    log.info("Docs with output:     %d", docs_with_output)
    log.info("Groups converted:     %d", groups_converted_total)
    log.info("IP tokens changed:    %d", ip_tokens_changed_total)
    log.info("Skipped parse errors: %d", skipped_parse)
    if args.dry_run:
        log.info("Dry-run only. No files written.")
    else:
        log.info("Files written:        %d", written)
        log.info("Output directory:     %s", out_root.resolve())


if __name__ == "__main__":
    main()