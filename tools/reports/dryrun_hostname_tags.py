#!/usr/bin/env python3
"""
tools/reports/dryrun_hostname_tags.py

Single-command dry-run that produces a complete pre-change report. Composes
export_vm_tags.py + build_hostname_tag_plan.py into one operation and flags
every issue the operator should review before pushing.

This script makes NO NSX writes. It reads the live VM state via the fabric
API and writes plan + classification reports locally.

Flagged conditions (each gets its own JSON report under --output-dir):
  - skip_excluded            : hostname value is on the exclusion list (never tagged)
  - skip_has_tag             : VMs already carrying a hostname tag
  - skip_length_out_of_range : trailing token below min / above max length
  - skip_invalid_name        : VMs with no usable trailing token in the name
  - skip_edge                : NSX Edge VMs (always skipped)
  - skip_other_type          : non-REGULAR VMs (NSX appliances, etc.)
  - eligible                 : VMs that WILL get tagged on apply

Usage:
  python tools/reports/dryrun_hostname_tags.py \\
    --manager nsx-lm1 \\
    --output-dir vm_tags_plan/nsx-lm1.lab.local \\
    --overwrite
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_log_dir, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.md_utils import align_markdown_tables
from nsx.report_paths import report_run_dir, reports_root

# Re-use the classifier from build_hostname_tag_plan.py to avoid duplication.
# That file still lives under tools/vm_tags/; we're now under tools/reports/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vm_tags"))
from build_hostname_tag_plan import classify_vm, load_exclude_values, write_tag_inventory_jsonl  # type: ignore

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _fmt_tags(tags):
    """Compact 'scope|value, scope|value' string for a VM tag list. Pipes
    are escaped for markdown table cell safety."""
    if not tags:
        return "(none)"
    parts = []
    for t in tags:
        if isinstance(t, dict):
            parts.append(f"{t.get('scope','') or ''}\\|{t.get('tag','')}")
    return ", ".join(parts) if parts else "(none)"


def write_plan_markdown(out_dir: Path, summary: dict, buckets: dict) -> Path:
    """Write plan.md - one line per eligible VM + skip summary."""
    lines = []
    lines.append(f"# VM Hostname Tag Plan - {summary['manager']} ({summary['manager_host']})\n")
    lines.append(f"- **Ran at**: {summary['ran_at']}")
    lines.append(f"- **Total VMs**: {summary['vm_count_total']}")
    lines.append(f"- **Eligible for tagging**: **{summary['counts']['eligible']}**")
    lines.append(f"- **Flagged for review**: {summary['flagged_for_review']}")
    lines.append(f"- **Read-only**: yes (no NSX writes)\n")

    lines.append("## Classification counts\n")
    lines.append("| Bucket | Count | Meaning |")
    lines.append("|---|---:|---|")
    meanings = {
        "eligible":            "Will be tagged when push runs with --apply",
        "skip_excluded":       "On the hostname exclusion list - deliberately not tagged",
        "skip_has_tag":        "Already has a hostname tag - no action",
        "skip_length_out_of_range": "Trailing token below min / above max length - flag for review",
        "skip_invalid_name":   "Name has no usable trailing token - flag for review",
        "skip_too_many_tags":  "VM at NSX 30-tag cap - flag for cleanup",
        "skip_edge":           "NSX Edge VM - always skipped",
        "skip_other_type":     "System VM (vCLS, NSX Manager, etc.) - always skipped",
    }
    for k, count in summary["counts"].items():
        lines.append(f"| `{k}` | {count} | {meanings.get(k,'')} |")
    lines.append("")

    lines.append("## Eligible VMs (planned to be tagged)\n")
    eligible = buckets.get("eligible") or []
    if not eligible:
        lines.append("_None. Nothing will be tagged._\n")
    else:
        lines.append("| # | VM | External ID | Current tags | Proposed hostname tag |")
        lines.append("|---:|---|---|---|---|")
        for i, v in enumerate(eligible, start=1):
            lines.append(
                f"| {i} | {v.get('display_name','')} | "
                f"`{v.get('external_id','')[:12]}...` | "
                f"{_fmt_tags(v.get('existing_tags'))} | "
                f"**`hostname\\|{v.get('proposed_hostname_tag','')}`** |"
            )
        lines.append("")

    # Bucket sections - one line per VM in each non-empty skip bucket
    for key in ("skip_excluded", "skip_has_tag", "skip_length_out_of_range", "skip_invalid_name", "skip_too_many_tags", "skip_edge", "skip_other_type"):
        rows = buckets.get(key) or []
        if not rows:
            continue
        lines.append(f"## {key} ({len(rows)})\n")
        lines.append("| # | VM | Type | Existing tags | Reason |")
        lines.append("|---:|---|---|---|---|")
        for i, v in enumerate(rows, start=1):
            lines.append(
                f"| {i} | {v.get('display_name','')} | {v.get('type','')} | "
                f"{_fmt_tags(v.get('existing_tags'))} | {v.get('reason','')} |"
            )
        lines.append("")

    md_path = out_dir / "plan.md"
    md_path.write_text(align_markdown_tables("\n".join(lines)), encoding="utf-8")
    return md_path


def setup_logging(tool: str) -> Path:
    log_dir = Path(nsx_log_dir).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = (log_dir / f"vm_tags_{tool}_{RUN_TS}.log").resolve()
    log_file.touch(exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter(
        "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S",
    )
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(ch)
    root.addHandler(fh)
    log.info("Logging to %s", log_file)
    return log_file


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Single-command dry-run: pull VM state from NSX and produce a full pre-change report."
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        required=True,
        help="NSX Local Manager to query.",
    )
    parser.add_argument(
        "--output-base",
        default=None,
        help="Reports root. The run lands at <root>/<manager-host>/hostname_tags_dryrun/<ts>/ "
             "(default root: $NSX_LOG_DIR/reports).",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Exact directory override (run lands at <dir>/<ts>/). Prefer --output-base.",
    )
    parser.add_argument("--overwrite", action="store_true", help="Delete --output-dir before writing.")
    parser.add_argument("--exclude-file", default=None,
                        help="Path to a hostname-value exclusion list (one value per line; blank "
                             "lines and # comments ignored). VMs whose derived hostname value "
                             "matches (case-insensitive) go to skip_excluded. Precedence: this "
                             "flag > VM_TAGS_HOSTNAME_EXCLUDE_FILE (.env) > auto-discovered "
                             "hostname_tag_exclude.txt at repo root.")
    args = parser.parse_args()

    init_cli()
    log_file = setup_logging("dryrun")

    manager_host = resolve_manager(args.manager)
    if not manager_host:
        raise SystemExit(f"Manager not defined for {args.manager}.")

    # Per-run timestamped subdir so successive runs accumulate instead of
    # overwriting each other.
    if args.output_dir:
        out_dir = Path(args.output_dir).expanduser().resolve() / RUN_TS
    else:
        out_dir = report_run_dir("hostname_tags_dryrun", manager_host, args.output_base, RUN_TS, create=False)
    if out_dir.exists():
        if not args.overwrite:
            raise SystemExit(f"Output dir already exists: {out_dir}. Use --overwrite.")
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=False)
    log.info("Reading VMs from %s", manager_host)
    vms = client.list_virtual_machines()
    log.info("Total VMs: %d", len(vms))

    exclude_values = load_exclude_values(args.exclude_file)
    classified = [classify_vm(v, exclude_values) for v in vms]
    buckets = {
        "eligible": [],
        "skip_excluded": [],
        "skip_has_tag": [],
        "skip_too_many_tags": [],
        "skip_length_out_of_range": [],
        "skip_invalid_name": [],
        "skip_edge": [],
        "skip_other_type": [],
    }
    for c in classified:
        buckets[c["classification"]].append(c)

    # Per-VM log lines so operators see exactly what a subsequent push --apply
    # would do, without having to open plan.md. Same [DRY-RUN] prefix that
    # push uses for its own dry-run mode, so the two logs read consistently.
    for c in classified:
        cls = c["classification"]
        name = c.get("display_name", "?")
        ext  = (c.get("external_id") or "")[:12]
        tag_cnt = c.get("existing_tag_count", 0)
        if cls == "eligible":
            log.info("[DRY-RUN] VM=%s ext_id=%s: WOULD ADD hostname=%s (tags %d -> %d)",
                     name, ext, c.get("proposed_hostname_tag"),
                     tag_cnt, tag_cnt + 1)
        elif cls == "skip_has_tag":
            log.info("[DRY-RUN] VM=%s ext_id=%s: SKIP (already has hostname=%s)",
                     name, ext, c.get("existing_hostname_tag"))
        elif cls == "skip_too_many_tags":
            log.info("[DRY-RUN] VM=%s ext_id=%s: SKIP (at tag cap %d)",
                     name, ext, tag_cnt)
        elif cls == "skip_invalid_name":
            log.info("[DRY-RUN] VM=%s ext_id=%s: SKIP (name does not match hostname regex)",
                     name, ext)
        elif cls == "skip_length_out_of_range":
            log.info("[DRY-RUN] VM=%s ext_id=%s: SKIP (%s)",
                     name, ext, c.get("reason", "hostname length out of range"))
        elif cls == "skip_excluded":
            log.info("[DRY-RUN] VM=%s ext_id=%s: SKIP (%s)",
                     name, ext, c.get("reason", "on hostname exclusion list"))
        # skip_edge and skip_other_type are noisy for typical labs; log at DEBUG only.
        elif cls in ("skip_edge", "skip_other_type"):
            log.debug("[DRY-RUN] VM=%s ext_id=%s: SKIP (%s)", name, ext, cls)

    for key, rows in buckets.items():
        (out_dir / f"{key}.json").write_text(
            json.dumps({"count": len(rows), "vms": rows}, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        log.info("  %s: %d VM(s)", key, len(rows))

    # Per-VM tag inventory (every VM, regardless of classification)
    inv_path = out_dir / "vm_tag_inventory.jsonl"
    inv_count = write_tag_inventory_jsonl(vms, inv_path)
    log.info("  vm_tag_inventory: %d row(s) -> %s", inv_count, inv_path)

    flagged = (
        len(buckets["skip_has_tag"])
        + len(buckets["skip_invalid_name"])
        + len(buckets["skip_length_out_of_range"])
        + len(buckets["skip_excluded"])
        + len(buckets["skip_too_many_tags"])
    )

    summary = {
        "manager": args.manager,
        "manager_host": manager_host,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "vm_count_total": len(vms),
        "counts": {k: len(v) for k, v in buckets.items()},
        "flagged_for_review": flagged,
        "vm_tag_inventory": str(inv_path),
        "output_dir": str(out_dir),
        "log_file": str(log_file),
    }
    (out_dir / "plan.json").write_text(
        json.dumps({"summary": summary, "classified": classified}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    md_path = write_plan_markdown(out_dir, summary, buckets)
    log.info("Markdown report: %s", md_path)
    summary["plan_md"] = str(md_path)
    print(json.dumps(summary, indent=2, sort_keys=True))

    if flagged > 0:
        log.warning(
            "%d VM(s) flagged for review — see skip_has_tag.json / skip_invalid_name.json / skip_too_many_tags.json",
            flagged,
        )


if __name__ == "__main__":
    main()
