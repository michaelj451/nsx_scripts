#!/usr/bin/env python3
"""
tools/nsx/backup_nsx_state.py

Workflow BACKUP: read-only configuration backup of one or more NSX managers.

This is deliberately NOT capture_nsx_state.py. The two tools answer different
questions and must not be mixed:

  backup_nsx_state.py (THIS TOOL)          capture_nsx_state.py
  ---------------------------------------  ---------------------------------------
  "Save the config as it is, so it can     "Freeze everything the migration /
   be restored."                            remap workflows need as input."
  Definitions only, exactly as held.       Adds groups_additive/ (evaluated VM
                                           IPs frozen into group definitions),
                                           rule-impact reports, flat export trees.
  Timestamped history under                Single bundle per host, WIPED on every
  nsx_backup/<host>/<UTC_TS>/, kept.       run (always "the latest capture").
  Restore = push the bundle back.          Pushing groups_additive back would
                                           materialize VM IPs into definitions:
                                           NOT a faithful restore.

Every operation is GET-only. Zero writes to any manager. The only writes are
local files under --output-root.

What each bundle contains:
  nsx_backup/<host>/<UTC_TS>/
    manifest.json                        ok flag, per-step records, options
    summary.txt                          human-readable summary
    nsx_export/<host>/domains/<d>/       groups, services, security-policies
                                         (rules nested inside each policy)
    segments/                            segment definitions
    vm_tag_inventory/                    VM + tag state (LM sources only; the
                                         VM fabric API does not exist on a GM)
    logs/                                per-step logs
  nsx_backup/<host>/latest               symlink to the newest bundle

Usage:
  # One or many managers in one run; GM sources are detected by alias and
  # automatically use the Global Manager API surface.
  python tools/nsx/backup_nsx_state.py --source nsx-gm1 nsx-lm1 nsx-lm2

  # Keep only the 14 newest bundles per host (for cron)
  python tools/nsx/backup_nsx_state.py --source nsx-lm1 --retain 14

Exit code: 0 when every manager backed up clean, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from nsx.cli_bootstrap import init_cli                     # noqa: E402
from nsx.nsx_constants import nsx_log_dir, resolve_manager  # noqa: E402

log = logging.getLogger(__name__)

NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
TS_DIR_RE = re.compile(r"^\d{8}_\d{6}$")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_global_manager(source: str) -> bool:
    return source.startswith("nsx-gm")


# =============================================================================
# Pure planning / housekeeping helpers (unit-tested)
# =============================================================================

def plan_steps(
    source: str,
    bundle: Path,
    *,
    domain_id: str = "default",
    all_domains: bool = False,
    with_vm_tags: bool = True,
    python: str = sys.executable,
) -> List[Tuple[str, List[str]]]:
    """The full list of (label, argv) subprocess steps for one manager's backup.
    GM sources get --federation-global on every NSX-facing step and never get
    the VM tag step (the VM fabric API is LM-only)."""
    fed = is_global_manager(source)

    export_cmd = [
        python, "tools/nsx/export_nsx_objects.py",
        "--manager", source,
        "--base-dir", str(bundle / "nsx_export"),
        "--domain-id", domain_id,
        "--output-format", "yaml",
    ]
    if all_domains:
        export_cmd.append("--all-domains")
    if fed:
        export_cmd.append("--federation-global")

    segments_cmd = [
        python, "tools/nsx/segments.py", "export",
        "--source", source,
        "--domain-id", domain_id,
        "--output-dir", str(bundle / "segments"),
    ]
    if fed:
        segments_cmd.append("--federation-global")

    steps: List[Tuple[str, List[str]]] = [
        ("1_export_objects", export_cmd),
        ("2_export_segments", segments_cmd),
    ]

    if with_vm_tags and not fed:
        steps.append(("3_export_vm_tags", [
            python, "tools/vm_tags/export_vm_tags.py",
            "--manager", source,
            "--base-dir", str(bundle / "vm_tag_inventory"),
        ]))

    return steps


def prune_old_backups(host_dir: Path, retain: int) -> List[str]:
    """Delete the oldest timestamped bundles beyond `retain`. retain<=0 keeps
    everything. The `latest` symlink and non-timestamp entries are never touched.
    Returns the names removed."""
    if retain <= 0 or not host_dir.exists():
        return []
    ts_dirs = sorted(
        d for d in host_dir.iterdir()
        if d.is_dir() and not d.is_symlink() and TS_DIR_RE.match(d.name)
    )
    removed: List[str] = []
    for d in ts_dirs[:-retain] if len(ts_dirs) > retain else []:
        shutil.rmtree(d)
        removed.append(d.name)
    return removed


def write_manifest(bundle: Path, manifest: Dict[str, Any]) -> Path:
    path = bundle / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def update_latest_symlink(host_dir: Path, bundle: Path) -> None:
    link = host_dir / "latest"
    try:
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(bundle.name)
    except OSError as exc:   # e.g. filesystems without symlink support
        log.warning("Could not update %s: %s", link, exc)


# =============================================================================
# Step runner
# =============================================================================

def run_step(label: str, cmd: List[str], logs_dir: Path, verbose: bool) -> Dict[str, Any]:
    started = _utc_now_iso()
    log.info("  step %s", label)
    if verbose:
        log.info("    cmd: %s", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    step_log = logs_dir / f"{label}.log"
    step_log.write_text(
        f"# cmd: {' '.join(cmd)}\n# returncode: {proc.returncode}\n"
        f"# ---- stdout ----\n{proc.stdout}\n# ---- stderr ----\n{proc.stderr}\n",
        encoding="utf-8",
    )
    ok = proc.returncode == 0
    if not ok:
        tail = "\n".join((proc.stderr or proc.stdout or "").splitlines()[-6:])
        log.error("  STEP FAILED: %s (exit=%d). See %s\n%s", label, proc.returncode, step_log, tail)
    return {
        "label": label,
        "cmd": cmd,
        "returncode": proc.returncode,
        "ok": ok,
        "started_at": started,
        "finished_at": _utc_now_iso(),
        "log": str(step_log),
    }


def backup_one(source: str, output_root: Path, args: argparse.Namespace) -> Dict[str, Any]:
    host = resolve_manager(source)
    if not host:
        raise SystemExit(f"Manager not defined in .env: {source}")

    host_dir = output_root / host
    bundle = host_dir / RUN_TS
    logs_dir = bundle / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    fed = is_global_manager(source)
    log.info("=" * 60)
    log.info("BACKUP %s (%s)%s -> %s", source, host, " [GM]" if fed else "", bundle)

    steps = [
        run_step(label, cmd, logs_dir, verbose=not args.quiet)
        for label, cmd in plan_steps(
            source, bundle,
            domain_id=args.domain_id,
            all_domains=args.all_domains,
            with_vm_tags=args.with_vm_tags,
        )
    ]
    ok = all(s["ok"] for s in steps)

    manifest = {
        "workflow": "backup",
        "tool": "tools/nsx/backup_nsx_state.py",
        "source": source,
        "host": host,
        "federation_global": fed,
        "domain_id": args.domain_id,
        "all_domains": args.all_domains,
        "with_vm_tags": args.with_vm_tags and not fed,
        "backed_up_at": _utc_now_iso(),
        "bundle": str(bundle),
        "ok": ok,
        "steps": steps,
    }
    write_manifest(bundle, manifest)

    lines = [
        f"NSX BACKUP {'OK' if ok else 'FAILED'}",
        f"  source : {source} ({host}){' [GM]' if fed else ''}",
        f"  bundle : {bundle}",
        f"  taken  : {manifest['backed_up_at']}",
        "  steps  :",
    ]
    lines += [f"    {'OK  ' if s['ok'] else 'FAIL'} {s['label']}" for s in steps]
    lines.append("  restore: push the bundle back with the per-class push tools")
    lines.append("           (dry-run by default; see docs/nsx/RUNBOOK_BACKUP.md)")
    (bundle / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    if ok:
        update_latest_symlink(host_dir, bundle)
        removed = prune_old_backups(host_dir, args.retain)
        if removed:
            log.info("  pruned %d old bundle(s): %s", len(removed), ", ".join(removed))
    else:
        log.error("  bundle NOT marked latest (failed steps); kept for inspection: %s", bundle)

    log.info("BACKUP %s: %s", source, "OK" if ok else "FAILED")
    return manifest


# =============================================================================
# Main
# =============================================================================

def _setup_logging() -> Path:
    log_dir = Path(nsx_log_dir).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"backup_nsx_state_{RUN_TS}.log"
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%S")
    for h in (logging.StreamHandler(), logging.FileHandler(log_file, encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    return log_file


def main() -> int:
    p = argparse.ArgumentParser(
        description="Read-only NSX configuration backup (definitions only, timestamped history kept).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--source", required=True, nargs="+", choices=NSX_MANAGER_CHOICES,
                   help="One or more managers to back up in this run. GM aliases automatically "
                        "use the Global Manager API surface.")
    p.add_argument("--domain-id", default="default")
    p.add_argument("--all-domains", action="store_true",
                   help="Export every domain instead of only --domain-id.")
    p.add_argument("--no-vm-tags", action="store_false", dest="with_vm_tags", default=True,
                   help="Skip the VM tag inventory step on LM sources (GMs never have it).")
    p.add_argument("--output-root", default=None,
                   help=f"Backup root (default: {REPO_ROOT / 'nsx_backup'}). Bundles land at "
                        "<root>/<host>/<UTC ts>/ and are KEPT across runs.")
    p.add_argument("--retain", type=int, default=0,
                   help="Keep only the N newest bundles per host after a clean backup "
                        "(default 0 = keep everything).")
    p.add_argument("--quiet", action="store_true", help="Less per-step console output.")
    args = p.parse_args()

    init_cli()
    log_file = _setup_logging()
    output_root = Path(args.output_root).expanduser().resolve() if args.output_root else REPO_ROOT / "nsx_backup"

    log.info("NSX BACKUP run %s  (GET-only; nothing on any manager is modified)", RUN_TS)
    log.info("  sources: %s", ", ".join(args.source))
    log.info("  output : %s", output_root)

    manifests = [backup_one(source, output_root, args) for source in args.source]

    overall_ok = all(m["ok"] for m in manifests)
    run_summary = {
        "workflow": "backup",
        "run_ts": RUN_TS,
        "ran_at": _utc_now_iso(),
        "output_root": str(output_root),
        "retain": args.retain,
        "ok": overall_ok,
        "log_file": str(log_file),
        "managers": [
            {"source": m["source"], "host": m["host"], "ok": m["ok"], "bundle": m["bundle"]}
            for m in manifests
        ],
    }
    log.info("=" * 60)
    for m in run_summary["managers"]:
        log.info("  %-8s %-24s %s", m["source"], m["host"], "OK" if m["ok"] else "FAILED")
    log.info("Backup run %s", "OK" if overall_ok else "FAILED")
    print(json.dumps(run_summary, indent=2))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
