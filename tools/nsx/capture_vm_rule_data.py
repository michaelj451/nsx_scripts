#!/usr/bin/env python3
"""
tools/nsx/capture_vm_rule_data.py

Read-only snapshot of everything the VM rule membership report needs, for
one or more managers (Local or Global), kept as timestamped history the way
backup_nsx_state.py keeps its bundles:

  nsx_vm_rule_snapshots/<host>/<UTC_TS>/
    vm_rule_snapshot.json   VMs (LM: with their VIF IPs), every domain's
                            groups, NSX's evaluated VM members and IP members
                            per group, every security policy rule
    manifest.json           ok flag, counts, fetch errors
    summary.txt             human-readable summary
    capture.log             this manager's log lines
  nsx_vm_rule_snapshots/<host>/latest   symlink to the newest COMPLETE snapshot

Then answer "which rules do these VMs / IPs hit?" any number of times with
zero NSX calls:

  python tools/reports/report_vms_in_rules.py \\
    --from-snapshot nsx_vm_rule_snapshots/nsx-lm1.lab.local \\
    --targets "web01,10.6.0.101,db02"

The snapshot is collected by the same code as a live report run
(nsx.vm_rule_data.collect_live), so an offline lookup gives the answer a
live run would have given at capture time.

GM aliases (nsx-gm*) use the federation API and talk to the GM ONLY:
member calls are proxied per site with enforcement_point_path, and no LM
session is opened, so GM snapshots carry no VM IPs (name entries match by VM
membership, IP entries by the groups' evaluated IPs). As in a live GM run,
membership is fetched only for groups that rules reference.

Every NSX operation is a GET. The only writes are local files under
--output-root.

Usage:
  python tools/nsx/capture_vm_rule_data.py --source nsx-lm1
  python tools/nsx/capture_vm_rule_data.py --source nsx-gm1 nsx-lm1 --retain 14

Exit code: 0 when every manager captured complete, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from nsx.bundle_history import prune_old_bundles, update_latest_symlink  # noqa: E402
from nsx.cli_bootstrap import init_cli                                   # noqa: E402
from nsx.nsx_constants import nsx_log_dir, resolve_manager               # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient                        # noqa: E402
from nsx.vm_rule_data import SNAPSHOT_FILE, collect_live, write_snapshot  # noqa: E402

log = logging.getLogger(__name__)

NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "nsx_vm_rule_snapshots"
LOG_FORMAT = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                               "%Y-%m-%dT%H:%M:%S")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_global_manager(source: str) -> bool:
    return source.startswith("nsx-gm")


def write_summary(bundle: Path, manifest: Dict[str, Any]) -> None:
    counts = manifest.get("counts") or {}
    lines = [
        f"NSX VM RULE SNAPSHOT {'OK' if manifest['ok'] else 'FAILED'}",
        f"  source : {manifest['source']} ({manifest['host']})"
        f"{' [GM]' if manifest['federation_global'] else ''}",
        f"  bundle : {bundle}",
        f"  taken  : {manifest.get('captured_at') or manifest['started_at']}",
    ]
    if counts:
        lines.append(
            f"  data   : {counts.get('vms', 0)} VM(s) ({counts.get('vms_with_ips', 0)} with IPs), "
            f"{counts.get('groups', 0)} group(s) ({counts.get('groups_member_fetched', 0)} "
            f"member-fetched), {counts.get('rules', 0)} rule(s), "
            f"{counts.get('domains', 0)} domain(s)"
            + (f", {counts['sites']} site(s)" if counts.get("sites") else ""))
    if manifest.get("error"):
        lines.append(f"  error  : {manifest['error']}")
    if counts and not counts.get("rules"):
        lines.append("  WARNING: no rules on this manager; every lookup will come back empty")
    if manifest.get("fetch_error_count"):
        lines.append(f"  fetch errors: {manifest['fetch_error_count']} "
                     "(snapshot incomplete; see vm_rule_snapshot.json fetch_errors)")
    lines.append("  lookup : python tools/reports/report_vms_in_rules.py "
                 f"--from-snapshot {bundle} --targets \"<vm or ip>,...\"")
    (bundle / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def capture_one(source: str, output_root: Path, retain: int = 0) -> Dict[str, Any]:
    host = resolve_manager(source)
    if not host:
        raise SystemExit(f"Manager not defined in .env: {source}")
    fed = is_global_manager(source)
    host_dir = output_root / host
    bundle = host_dir / RUN_TS
    bundle.mkdir(parents=True, exist_ok=True)

    bundle_log = logging.FileHandler(bundle / "capture.log", encoding="utf-8")
    bundle_log.setFormatter(LOG_FORMAT)
    logging.getLogger().addHandler(bundle_log)
    started_at = _utc_now_iso()
    log.info("=" * 60)
    log.info("VM RULE SNAPSHOT %s (%s)%s -> %s", source, host, " [GM]" if fed else "", bundle)

    doc: Dict[str, Any] = {}
    error = None
    try:
        client = NsxPolicyClient(nsxmanager=host, federation_global=fed)
        is_gm = fed and "/global-manager/" in client.POLICY_ROOT
        data = collect_live(client, manager_host=host, is_gm=is_gm)
        doc = write_snapshot(bundle / SNAPSHOT_FILE, data, manager_alias=source)
    except SystemExit as exc:          # collect_live's fatal conditions
        error = str(exc)
    except Exception as exc:           # one manager failing must not stop the others
        error = f"{type(exc).__name__}: {exc}"
        log.exception("capture of %s failed", source)

    ok = error is None and bool(doc.get("complete"))
    if doc and not doc["counts"].get("rules"):
        log.warning("  %s has NO security rules in any domain (%d group(s)). The snapshot "
                    "is valid but every lookup will come back empty.",
                    source, doc["counts"].get("groups", 0))
    manifest = {
        "workflow": "vm_rule_snapshot",
        "tool": "tools/nsx/capture_vm_rule_data.py",
        "source": source,
        "host": host,
        "federation_global": fed,
        "started_at": started_at,
        "captured_at": doc.get("captured_at"),
        "finished_at": _utc_now_iso(),
        "bundle": str(bundle),
        "snapshot": str(bundle / SNAPSHOT_FILE) if doc else None,
        "counts": doc.get("counts") or {},
        "fetch_error_count": doc.get("fetch_error_count", 0),
        "error": error,
        "ok": ok,
    }
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_summary(bundle, manifest)

    if ok:
        update_latest_symlink(host_dir, bundle)
        removed = prune_old_bundles(host_dir, retain)
        if removed:
            log.info("  pruned %d old snapshot(s): %s", len(removed), ", ".join(removed))
    elif error:
        log.error("  %s FAILED: %s", source, error)
    else:
        log.error("  %s snapshot has %d fetch error(s); written but NOT marked latest: %s",
                  source, manifest["fetch_error_count"], bundle)
    log.info("VM RULE SNAPSHOT %s: %s", source, "OK" if ok else "FAILED")
    logging.getLogger().removeHandler(bundle_log)
    bundle_log.close()
    return manifest



def _setup_logging() -> Path:
    log_dir = Path(nsx_log_dir).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"capture_vm_rule_data_{RUN_TS}.log"
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    for h in (logging.StreamHandler(), logging.FileHandler(log_file, encoding="utf-8")):
        h.setFormatter(LOG_FORMAT)
        root.addHandler(h)
    return log_file


def main() -> int:
    p = argparse.ArgumentParser(
        description="Read-only snapshot of VMs, groups, evaluated membership and rules "
                    "for offline VM/IP rule lookups (timestamped history kept).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--source", required=True, nargs="+", choices=NSX_MANAGER_CHOICES,
                   help="One or more managers to capture in this run. GM aliases "
                        "automatically use the Global Manager API surface (GM only, "
                        "no LM sessions).")
    p.add_argument("--output-root", default=None,
                   help=f"Snapshot root (default: {DEFAULT_OUTPUT_ROOT}). Snapshots land at "
                        "<root>/<host>/<UTC ts>/ and are KEPT across runs.")
    p.add_argument("--retain", type=int, default=0,
                   help="Keep only the N newest snapshots per host after a complete "
                        "capture (default 0 = keep everything).")
    p.add_argument("--rate-limit", type=float, default=None, metavar="RPS",
                   help="Cap NSX API requests per second (sets NSX_API_MAX_RPS). "
                        "Default is 2 req/s; 0 disables pacing.")
    args = p.parse_args()
    if args.rate_limit is not None:
        os.environ["NSX_API_MAX_RPS"] = str(args.rate_limit)

    init_cli()
    log_file = _setup_logging()
    output_root = (Path(args.output_root).expanduser().resolve()
                   if args.output_root else DEFAULT_OUTPUT_ROOT)

    log.info("NSX VM RULE SNAPSHOT run %s  (GET-only; nothing on any manager is modified)", RUN_TS)
    log.info("  sources: %s", ", ".join(args.source))
    log.info("  output : %s", output_root)

    manifests = [capture_one(source, output_root, args.retain) for source in args.source]

    overall_ok = all(m["ok"] for m in manifests)
    run_summary = {
        "workflow": "vm_rule_snapshot",
        "run_ts": RUN_TS,
        "ran_at": _utc_now_iso(),
        "output_root": str(output_root),
        "retain": args.retain,
        "ok": overall_ok,
        "log_file": str(log_file),
        "managers": [
            {"source": m["source"], "host": m["host"], "ok": m["ok"],
             "bundle": m["bundle"], "counts": m["counts"],
             "fetch_error_count": m["fetch_error_count"], "error": m["error"]}
            for m in manifests
        ],
    }
    log.info("=" * 60)
    for m in run_summary["managers"]:
        log.info("  %-8s %-24s %s", m["source"], m["host"], "OK" if m["ok"] else "FAILED")
    log.info("VM rule snapshot run %s", "OK" if overall_ok else "FAILED")
    print(json.dumps(run_summary, indent=2))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
