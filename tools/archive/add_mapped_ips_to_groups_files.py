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
- Console + <NSX_LOG_DIR>/add_mapped_ips_to_groups_files_YYYYMMDD_HHMMSS.log
- JSONL changes are still written by nsx_group_remap.py to <NSX_LOG_DIR>/nsx_group_remap_changes.jsonl

------------------------------------------------------------------------
Usage
------------------------------------------------------------------------

# Standard run (uses all defaults):
python tools/nsx/add_mapped_ips_to_groups_files.py

# Dry-run only — analyze changes without writing any output files:
python tools/nsx/add_mapped_ips_to_groups_files.py --dry-run

# Custom paths:
python tools/nsx/add_mapped_ips_to_groups_files.py \
  --csv data/subnet_map.csv \
  --nsx-export nsx_export \
  --nsx-updated nsx_groups_additive

# Skip clearing the output directory before writing:
python tools/nsx/add_mapped_ips_to_groups_files.py --no-clean

# All options:
#   --csv          Path to subnet mapping CSV (columns: old_subnet, new_subnet, vlan, description)
#   --nsx-export   Root directory of exported NSX group files (default: ./nsx_export)
#   --nsx-updated  Root directory for additive output files   (default: ./nsx_groups_additive)
#   --dry-run      Analyze and log changes only; do not write output files
#   --no-clean     Skip wiping the output directory before writing
------------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from nsx.nsx_constants import nsx_log_dir
from nsx.nsx_object_functions.nsx_group_remap import (
    read_csv_mappings,
    load_doc,
    write_output,
    out_path_for,
    iter_group_files,
    add_mapped_ips_in_doc,
)

EXPORT_ROOT = "nsx_export"

# =============================================================================
# Paths / Defaults
# =============================================================================

REPO_ROOT = Path(__file__).resolve().parents[2]
NSX_EXPORT_DIR_DEFAULT = REPO_ROOT / EXPORT_ROOT
NSX_UPDATED_DIR_DEFAULT = REPO_ROOT / "nsx_groups_additive"
CSV_DEFAULT = REPO_ROOT / "data" / "subnet_map.csv"


def _resolve_log_dir() -> Path:
    """
    Resolve nsx_log_dir from env/constant and ensure it exists.
    Supports:
      - "nsx_logs" (repo-relative)
      - "logs" (repo-relative)
      - "/abs/path/logs"
      - "$HOME/.../logs" or "$ROOT_DIR/logs" (expanded)
    """
    if not nsx_log_dir:
        # Safe fallback: repo-relative nsx_logs
        p = REPO_ROOT / "nsx_logs"
        p.mkdir(parents=True, exist_ok=True)
        return p.resolve()

    expanded = os.path.expandvars(os.path.expanduser(str(nsx_log_dir)))
    p = Path(expanded)

    if not p.is_absolute():
        p = REPO_ROOT / p

    p = p.resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _setup_logging() -> tuple[logging.Logger, Path]:
    log_dir = _resolve_log_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = (log_dir / f"add_mapped_ips_to_groups_files_{ts}.log").resolve()
    log_file.touch(exist_ok=True)

    logger = logging.getLogger("add_mapped_ips_to_groups_files")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Clear handlers so reruns in same interpreter don't duplicate logs
    for h in list(logger.handlers):
        logger.removeHandler(h)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%dT%H:%M:%S UTC")

    fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)

    logger.info("Log file: %s", log_file)
    return logger, log_file


@dataclass
class Counters:
    scanned: int = 0
    docs_with_changes: int = 0
    groups_touched_total: int = 0
    tokens_added_total: int = 0
    written: int = 0
    skipped_parse: int = 0


def _validate_inputs(csv_path: Path, export_root: Path) -> None:
    if not csv_path.exists():
        raise SystemExit(f"CSV not found: {csv_path}")
    if not export_root.exists():
        raise SystemExit(f"Export dir not found: {export_root}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Add mapped IPs/subnets/ranges to existing NSX groups (additive only)"
    )
    ap.add_argument("--csv", default=str(CSV_DEFAULT), help="CSV with old_subnet,new_subnet,vlan,description")
    ap.add_argument("--nsx-export", default=str(NSX_EXPORT_DIR_DEFAULT), help="Input export root (default: ./nsx_export)")
    ap.add_argument("--nsx-updated", default=str(NSX_UPDATED_DIR_DEFAULT), help="Output root (default: ./nsx_groups_additive)")
    ap.add_argument("--dry-run", action="store_true", help="Analyze only; do not write output files.")
    ap.add_argument("--no-clean", action="store_true", help="Skip clearing the output directory before writing. By default the output dir is wiped so only groups updated in this run are present.")
    args = ap.parse_args()

    log, _log_file = _setup_logging()

    csv_path = Path(args.csv).expanduser()
    export_root = Path(args.nsx_export).expanduser()
    out_root = Path(args.nsx_updated).expanduser()

    log.info("Starting add_mapped_ips_to_groups_files")
    log.info("CSV:        %s", csv_path.resolve())
    log.info("NSX export:  %s", export_root.resolve())
    log.info("NSX updated: %s", out_root.resolve())
    log.info("Dry-run:     %s", args.dry_run)

    _validate_inputs(csv_path, export_root)

    if not args.dry_run and not args.no_clean and out_root.exists():
        log.info("Clearing output directory: %s", out_root.resolve())
        shutil.rmtree(out_root)

    maps = read_csv_mappings(csv_path)
    in_files = iter_group_files(export_root)

    c = Counters()
    all_snapshots: list[dict] = []
    all_range_events: list[dict] = []
    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    for f in in_files:
        c.scanned += 1
        rel = f.relative_to(export_root)

        try:
            doc = load_doc(f)
        except Exception as e:
            c.skipped_parse += 1
            log.warning("SKIP parse error: %s (%s)", rel, e)
            continue

        updated_doc, groups_touched, tokens_added, file_snapshots, file_range_events = add_mapped_ips_in_doc(doc, maps)

        for ev in file_range_events:
            ev["source_file"] = str(rel)
        all_range_events.extend(file_range_events)

        if tokens_added == 0:
            continue

        c.docs_with_changes += 1
        c.groups_touched_total += groups_touched
        c.tokens_added_total += tokens_added

        for snap in file_snapshots:
            snap["source_file"] = str(rel)
        all_snapshots.extend(file_snapshots)

        out_f = out_path_for(f, export_root, out_root)
        log.info(
            "[update] %s -> %s (groups_touched=%d, tokens_added=%d)",
            rel,
            out_f.resolve(),
            groups_touched,
            tokens_added,
        )

        if args.dry_run:
            continue

        out_f.parent.mkdir(parents=True, exist_ok=True)
        write_output(out_f, updated_doc)
        c.written += 1

    log.info("Finished add_mapped_ips_to_groups_files")
    log.info("Scanned files:        %d", c.scanned)
    log.info("Docs with changes:    %d", c.docs_with_changes)
    log.info("Groups touched:       %d", c.groups_touched_total)
    log.info("Tokens added:         %d", c.tokens_added_total)
    log.info("Skipped parse errors: %d", c.skipped_parse)

    if args.dry_run:
        log.info("Dry-run only. No files written.")
    else:
        log.info("Files written:        %d", c.written)
        log.info("Output directory:     %s", out_root.resolve())

    log_dir = _resolve_log_dir()
    mode = "dryrun" if args.dry_run else "run"

    if all_snapshots:
        snapshot_dir = log_dir / "nsx_snapshots" / f"{run_ts}_add_mapped_ips_{mode}"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        snapshot_file = snapshot_dir / "snapshot.json"
        out = {
            "run_ts": run_ts,
            "mode": mode,
            "csv": str(csv_path.resolve()),
            "nsx_export": str(export_root.resolve()),
            "groups_snapshotted": len(all_snapshots),
            "groups": all_snapshots,
        }
        snapshot_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
        log.info("Snapshot written: %s", snapshot_file)

    if all_range_events:
        # JSONL: one record per range found across all files
        jsonl_file = log_dir / f"ip_range_events_{run_ts}.jsonl"
        with jsonl_file.open("w", encoding="utf-8") as fh:
            for ev in all_range_events:
                fh.write(json.dumps(ev) + "\n")
        log.info("IP range events (jsonl): %s", jsonl_file)

        # JSON: ranges grouped by object, showing before/after per group
        groups_map: dict[str, dict] = {}
        for ev in all_range_events:
            key = ev["group_id"]
            if key not in groups_map:
                groups_map[key] = {
                    "group_id": ev["group_id"],
                    "group_display_name": ev["group_display_name"],
                    "source_file": ev.get("source_file"),
                    "ranges": [],
                }
            groups_map[key]["ranges"].append({
                "before": ev["range"],
                "after": ev["proposed_change"],
                "status": ev["status"],
            })

        json_file = log_dir / f"ip_range_summary_{run_ts}.json"
        json_file.write_text(
            json.dumps({
                "run_ts": run_ts,
                "mode": mode,
                "total_ranges_found": len(all_range_events),
                "groups": list(groups_map.values()),
            }, indent=2),
            encoding="utf-8",
        )
        log.info("IP range summary (json):  %s", json_file)
    else:
        log.info("No IP ranges found in any group.")


if __name__ == "__main__":
    main()