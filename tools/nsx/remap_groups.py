#!/usr/bin/env python3
# tools/nsx/remap_groups.py

from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from pathlib import Path

from nsx.nsx_object_functions.nsx_group_remap import (
    read_csv_mappings,
    load_doc,
    write_output,
    out_path_for,
    convert_groups_in_doc,
    iter_group_files,
)

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e


# # =============================================================================
# # Logging
# # =============================================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# # =============================================================================
# # Defaults
# # =============================================================================

REPO_ROOT = Path(__file__).resolve().parents[2]
NSX_EXPORT_DIR_DEFAULT = REPO_ROOT / "nsx_export"
NSX_CONVERTED_DIR_DEFAULT = REPO_ROOT / "nsx_remapped_groups"
CSV_DEFAULT = REPO_ROOT / "data" / "subnet_map.csv"

APPEND_TO_GROUP_NAME = "_m2"


# # =============================================================================
# # CLI
# # =============================================================================

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
            group_name_append=APPEND_TO_GROUP_NAME
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