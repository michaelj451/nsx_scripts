#!/usr/bin/env python3
"""
tools/nsx/capture_nsx_state.py

Step 1 of the three-phase capture / transform / push workflow.

Read-only capture of an NSX manager's DFW state into a self-contained,
timestamped bundle directory. EVERY operation here uses GET-only NSX
calls. Zero writes to the source manager.

The bundle produced here can be:
  - carried to another host
  - sat on for weeks
  - fed into transform_capture.py to produce a push-ready transformed bundle
  - re-transformed any number of times with different options, never
    touching the source manager again

What's captured:

  nsx_capture/<source-host>/             ← always reflects the LATEST capture
    manifest.json                          captured-at, captured-from, options, steps
    summary.txt                            human-readable summary
    nsx_export/<host>/                     raw NSX state (groups + services + policies + rules)
    groups_additive/                       groups with captured VM IPs (snapshot at capture time, GET-only)
    segment_inventory/                     every referenced segment + live segment details
    affected_rule_reports/                 cross-reference of rules ↔ groups (offline)
    vm_tag_inventory/                      VM + tag state (LM only, GET-only)
    logs/                                  per-step log files

The default capture bundle directory is wiped at the start of every run so it
always reflects the most recent capture. Per-run history lives in
$NSX_LOG_DIR/capture_nsx_state_<UTC_TS>.log instead. Pass --output-dir to
override the default and preserve specific bundles.

Usage:

  python tools/nsx/capture_nsx_state.py \\
    --source nsx-lm1 \\
    --domain-id default

  # GM source:
  python tools/nsx/capture_nsx_state.py --source nsx-gm1 --federation-global
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir


log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def setup_logging(bundle_logs_dir: Path) -> Path:
    """Initialize logging. UTC, dual-write to a per-run log file inside the bundle."""
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)

    bundle_logs_dir.mkdir(parents=True, exist_ok=True)
    bundle_log_file = (bundle_logs_dir / f"capture_nsx_state_{RUN_TS}.log").resolve()
    global_log_file = (global_log_dir / f"capture_nsx_state_{RUN_TS}.log").resolve()

    import logging as _logging
    import time as _time
    _logging.Formatter.converter = _time.gmtime

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
    fh_bundle = logging.FileHandler(bundle_log_file, encoding="utf-8")
    fh_bundle.setFormatter(fmt)
    fh_global = logging.FileHandler(global_log_file, encoding="utf-8")
    fh_global.setFormatter(fmt)
    root.addHandler(ch)
    root.addHandler(fh_bundle)
    root.addHandler(fh_global)
    log.info("Logging to %s (bundle) and %s (global)", bundle_log_file, global_log_file)
    return bundle_log_file


def run_step(label: str, cmd: List[str], cwd: Path, step_log_dir: Path) -> Dict[str, Any]:
    """Run a subprocess step. Streams stdout/stderr to a per-step log file. Returns a structured record."""
    safe_label = label.replace(" ", "_").replace(":", "").replace("/", "_")
    step_log_file = step_log_dir / f"{safe_label}.log"

    log.info("STEP: %s", label)
    log.info("  cmd: %s", " ".join(cmd))
    log.info("  step log: %s", step_log_file)

    env = dict(os.environ)
    env.setdefault("PYTHONPATH", str(cwd / "app"))

    started_at = datetime.now(timezone.utc).isoformat()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
    )
    finished_at = datetime.now(timezone.utc).isoformat()

    step_log_file.write_text(
        f"# step: {label}\n# started_at: {started_at}\n# finished_at: {finished_at}\n"
        f"# returncode: {proc.returncode}\n# cmd: {' '.join(cmd)}\n\n"
        f"===== STDOUT =====\n{proc.stdout}\n\n===== STDERR =====\n{proc.stderr}\n",
        encoding="utf-8",
    )

    if proc.returncode != 0:
        log.error(
            "STEP FAILED: %s (exit=%d) — see %s for full output",
            label, proc.returncode, step_log_file,
        )
        for line in proc.stderr.splitlines()[-10:]:
            log.error("  | %s", line)
    else:
        log.info("  OK")

    return {
        "label": label,
        "cmd": cmd,
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "started_at": started_at,
        "finished_at": finished_at,
        "step_log": str(step_log_file),
        "stdout_tail": "\n".join(proc.stdout.splitlines()[-20:]),
        "stderr_tail": "\n".join(proc.stderr.splitlines()[-20:]) if proc.returncode != 0 else "",
    }


def write_summary(summary_path: Path, manifest: Dict[str, Any]) -> None:
    """Write a human-readable summary alongside the JSON manifest."""
    lines: List[str] = []
    lines.append("NSX Capture Summary")
    lines.append("=" * 60)
    lines.append(f"Bundle              : {manifest['bundle_dir']}")
    lines.append(f"Captured at         : {manifest['captured_at']}")
    cf = manifest["captured_from"]
    lines.append(f"Captured from       : {cf['manager_alias']} ({cf['manager_host']})")
    lines.append(f"Federation global   : {cf['federation_global']}")
    lines.append(f"Domain              : {cf['domain_id']}")
    lines.append("")
    lines.append("Options")
    lines.append("-" * 60)
    for k, v in manifest["options"].items():
        lines.append(f"  {k:24s}: {v}")
    lines.append("")
    lines.append("Steps")
    lines.append("-" * 60)
    for s in manifest["steps"]:
        status = "OK    " if s["ok"] else "FAILED"
        lines.append(f"  [{status}] {s['label']}")
        if not s["ok"]:
            lines.append(f"            see {s['step_log']}")
    lines.append("")
    if manifest["paths"].get("source_export_dir"):
        lines.append("Artifacts")
        lines.append("-" * 60)
        for k, v in manifest["paths"].items():
            if v:
                lines.append(f"  {k:24s}: {v}")
        lines.append("")
    lines.append(f"Result: {'OK' if manifest['ok'] else 'PARTIAL (some steps failed)'}")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description="Read-only capture of an NSX manager's state into a self-contained bundle.")
    p.add_argument("--source", required=True, choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
                   help="NSX manager to capture FROM (read-only).")
    p.add_argument("--domain-id", default="default", help="NSX domain to capture (default: default).")
    p.add_argument("--federation-global", action="store_true",
                   help="Use the Global Manager API surface for the source. Required for GM source.")
    p.add_argument("--output-dir", default=None,
                   help=(
                       "Capture bundle directory. Defaults to nsx_capture/<source-host>/. "
                       "On each run, the default path is wiped first so it always reflects "
                       "the latest capture (previous capture artifacts are deleted). "
                       "Pass --output-dir to preserve specific bundles."
                   ))
    # Live-member enrichment and segment inventory are MANDATORY — they're what
    # makes the bundle self-sufficient for offline transform. Skipping them would
    # leave dynamic groups without IPs and segment refs unresolvable.
    p.add_argument("--with-vm-tags", action="store_true", default=True,
                   help="Capture VM tag state (LM only). Default ON; ignored for GM.")
    p.add_argument("--no-vm-tags", action="store_false", dest="with_vm_tags",
                   help="Skip VM-tag capture (not used by Workflow A/B transforms — safe to skip if only doing groups/policies).")
    p.add_argument("--with-impact-report", action="store_true", default=True,
                   help="Generate the affected-rules impact report (offline, reads export). Default ON.")
    p.add_argument("--no-impact-report", action="store_false", dest="with_impact_report",
                   help="Skip the affected-rules impact report (review artifact only; doesn't affect transform).")
    p.add_argument("--with-ip-report", action="store_true", default=True,
                   help="Run report_groups_with_ips.py against the captured groups bundle. "
                        "Produces a per-group classification (pure-ip / pure-tag / tag+ip "
                        "hybrid / nested / segment) + optional CSV-mapping coverage. Default ON.")
    p.add_argument("--no-ip-report", action="store_false", dest="with_ip_report",
                   help="Skip the groups-with-IPs report.")
    p.add_argument("--ip-report-csv", default=None,
                   help="Path to a 2-col CSV (old,new) to cross-reference IP coverage in "
                        "the IP report. Optional; report runs without it if omitted.")
    p.add_argument("--emit-flat-exports", action="store_true", default=True,
                   help="Also copy the captured groups / services / policies / rules to the "
                        "standalone-export paths (nsx_groups_export/<host>/groups/, "
                        "nsx_services_export/<host>/services/, "
                        "nsx_policies_export/<host>/security-policies/, "
                        "nsx_rules_export/<host>/security-policies/). Default ON — "
                        "lets RUNBOOK_A / RUNBOOK_D push commands run verbatim against a "
                        "single capture, without their own export step. Existing "
                        "push_report/baselines/ subdirectories inside those flat-export "
                        "trees are preserved (only the data subdir is replaced).")
    p.add_argument("--no-flat-exports", action="store_false", dest="emit_flat_exports",
                   help="Skip the flat-exports copy (sub-step 7). Capture bundle "
                        "still contains all the data internally.")
    args = p.parse_args()

    init_cli()

    source_host = resolve_manager(args.source)
    if not source_host:
        raise SystemExit(f"Manager not defined for {args.source}.")

    using_default_output = args.output_dir is None
    output_dir = Path(
        args.output_dir
        or (REPO_ROOT / "nsx_capture" / source_host)
    ).expanduser().resolve()

    # On the default path, wipe any previous capture so this directory
    # always reflects the latest. Custom --output-dir paths are left
    # alone so the user can preserve specific bundles if they need to.
    if using_default_output and output_dir.exists():
        log.info("Wiping previous capture bundle: %s", output_dir)
        import shutil as _shutil
        _shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logs_dir = output_dir / "logs"
    log_file = setup_logging(logs_dir)

    log.info("=" * 60)
    log.info("NSX CAPTURE — bundle: %s", output_dir)
    log.info("  Source manager   : %s (%s)", args.source, source_host)
    log.info("  Domain           : %s", args.domain_id)
    log.info("  Federation GM    : %s", args.federation_global)
    log.info("  VM tags          : %s", args.with_vm_tags)
    log.info("  Impact report    : %s", args.with_impact_report)
    log.info("  IP report        : %s%s", args.with_ip_report,
             f" (csv={args.ip_report_csv})" if args.with_ip_report and args.ip_report_csv else "")
    log.info("  Flat exports     : %s", args.emit_flat_exports)
    log.info("=" * 60)

    # Per-step output paths inside the bundle
    export_root           = output_dir / "nsx_export"
    additive_groups_dir   = output_dir / "groups_additive" / "domains" / args.domain_id / "groups"
    segment_inv_dir       = output_dir / "segment_inventory"
    impact_report_dir     = output_dir / "affected_rule_reports"
    vm_tags_export_root   = output_dir / "vm_tag_inventory"

    steps: List[Dict[str, Any]] = []

    # 1. Export raw NSX state (groups, services, policies, rules)
    cmd = [
        sys.executable, "tools/nsx/export_nsx_objects.py",
        "--manager", args.source,
        "--base-dir", str(export_root),
        "--domain-id", args.domain_id,
        "--output-format", "yaml",
    ]
    if args.federation_global:
        cmd.append("--federation-global")
    steps.append(run_step("1_export_nsx_objects", cmd, REPO_ROOT, logs_dir))

    source_export_dir = export_root / source_host
    source_groups_dir = source_export_dir / "domains" / args.domain_id / "groups"

    # 2. Snapshot each group's evaluated VM members + their IPs (GET-only).
    # Result is frozen to disk in groups_additive/ — push tools read from
    # disk, NOT from NSX, so this is a one-time live read at capture time.
    # MANDATORY:
    # this is what gives the offline transform actual VM IPs to operate on.
    cmd = [
        sys.executable, "tools/nsx/build_group_ip_additive_from_live_members.py",
        "--source-manager", args.source,
        "--domain-id", args.domain_id,
        "--source-groups-dir", str(source_groups_dir),
        "--output-groups-dir", str(additive_groups_dir),
        "--output-format", "yaml",
        "--copy-first",
        "--continue-on-group-error",
    ]
    steps.append(run_step("2_build_group_ip_additive_from_live_members", cmd, REPO_ROOT, logs_dir))

    # 3. Segment inventory WITH live details so transform can run offline. MANDATORY:
    # the segment-convert mode needs the cached segment_details.json from this step.
    cmd = [
        sys.executable, "tools/nsx/find_segments_referenced.py",
        "--export-root", str(export_root),
        "--source-manager", args.source,
        "--output-dir", str(segment_inv_dir),
    ]
    if args.federation_global:
        cmd.append("--federation-global")
    steps.append(run_step("3_find_segments_referenced", cmd, REPO_ROOT, logs_dir))

    # 4. Affected-rules impact report (offline, reads from local export + additive)
    if args.with_impact_report:
        additive_root_for_impact = output_dir / "groups_additive"
        cmd = [
            sys.executable, "tools/nsx/find_rules_affected_by_group_changes.py",
            "--additive-root", str(additive_root_for_impact),
            "--export-root", str(export_root),
            "--output-dir", str(impact_report_dir),
        ]
        if args.federation_global:
            cmd.append("--federation-global")
        steps.append(run_step("4_find_rules_affected_by_group_changes", cmd, REPO_ROOT, logs_dir))

    # 5. VM tag capture (LM only, GET-only)
    if args.with_vm_tags and not args.federation_global:
        cmd = [
            sys.executable, "tools/vm_tags/export_vm_tags.py",
            "--manager", args.source,
            "--base-dir", str(vm_tags_export_root),
        ]
        steps.append(run_step("5_export_vm_tags", cmd, REPO_ROOT, logs_dir))
    elif args.with_vm_tags and args.federation_global:
        log.info("STEP 5 skipped — VM tag fabric API is LM-only (--federation-global is GM)")

    # 6. Groups-with-IPs report (offline, reads the just-captured source groups)
    #    Read-only against NSX. Produces a per-group classification + CSV coverage
    #    summary under $NSX_LOG_DIR/groups_ip_report/<source_host>/.
    if args.with_ip_report:
        cmd = [
            sys.executable, "tools/nsx/report_groups_with_ips.py",
            "--groups-dir", str(source_groups_dir),
            "--label", source_host,
            "--domain-id", args.domain_id,
        ]
        if args.ip_report_csv:
            cmd.extend(["--csv", args.ip_report_csv])
        steps.append(run_step("6_report_groups_with_ips", cmd, REPO_ROOT, logs_dir))

    # 7. Flat-export emit — copy captured groups/services/policies/rules to the
    #    standalone-export paths so RUNBOOK_A / RUNBOOK_D commands can run
    #    verbatim against a single capture (no separate `groups.py export`,
    #    `services.py export`, etc. needed). Preserves any existing
    #    push_report/baselines/ subdirectories in the destination trees so
    #    revert history is never lost.
    flat_exports_summary: Dict[str, Any] = {}
    if args.emit_flat_exports:
        log.info("STEP 7: emit flat-export bundles (RUNBOOK_A/D compatibility)")
        services_src   = source_export_dir / "domains" / args.domain_id / "services"
        policies_src   = source_export_dir / "domains" / args.domain_id / "security-policies"
        groups_src     = source_groups_dir  # already set above

        copy_targets = [
            (groups_src,   REPO_ROOT / "nsx_groups_export"   / source_host / "groups",            "groups",   False),
            (services_src, REPO_ROOT / "nsx_services_export" / source_host / "services",          "services", False),
            (policies_src, REPO_ROOT / "nsx_policies_export" / source_host / "security-policies", "policies", False),
            (policies_src, REPO_ROOT / "nsx_rules_export"    / source_host / "security-policies", "rules",    True),
        ]
        emitted: List[Dict[str, Any]] = []
        for src, dst, label_name, inject_parent_policy_id in copy_targets:
            if not src.exists():
                log.warning("  flat-export skip: source missing %s (label=%s)", src, label_name)
                emitted.append({"label": label_name, "ok": False, "reason": "source missing",
                                "source": str(src), "destination": str(dst)})
                continue
            try:
                if dst.exists():
                    # Wipe only the DATA subdirectory; preserve push_report/baselines/ etc.
                    import shutil as _shutil
                    _shutil.rmtree(dst)
                dst.parent.mkdir(parents=True, exist_ok=True)
                import shutil as _shutil
                _shutil.copytree(src, dst)
                file_count = sum(1 for _ in dst.rglob("*") if _.is_file())
                # The rules push tool consumes `_parent_policy_id` to know which
                # policy a rule belongs to (the folder name is a slugified hash
                # that doesn't survive a round-trip). The standalone rules.py
                # export injects this field; capture's export_nsx_objects.py
                # doesn't. So we inject it ourselves into the rules-tree copy.
                injected = 0
                if inject_parent_policy_id:
                    import yaml as _yaml
                    for rule_yaml in dst.rglob("rules/*.yaml"):
                        try:
                            data = _yaml.safe_load(rule_yaml.read_text(encoding="utf-8"))
                            if not isinstance(data, dict) or "_parent_policy_id" in data:
                                continue
                            pp = data.get("parent_path") or ""
                            # parent_path looks like /infra/domains/<d>/security-policies/<policy-id>
                            if "/security-policies/" not in pp:
                                continue
                            policy_id = pp.rsplit("/security-policies/", 1)[1].split("/", 1)[0]
                            if not policy_id:
                                continue
                            data["_parent_policy_id"] = policy_id
                            rule_yaml.write_text(_yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
                            injected += 1
                        except Exception:
                            log.exception("  flat-export: could not inject _parent_policy_id into %s", rule_yaml)
                    log.info("  flat-export ok: %s → %s (%d files, %d rules had _parent_policy_id injected)",
                             label_name, dst, file_count, injected)
                else:
                    log.info("  flat-export ok: %s → %s (%d files)", label_name, dst, file_count)
                emitted.append({"label": label_name, "ok": True,
                                "source": str(src), "destination": str(dst),
                                "file_count": file_count,
                                "parent_policy_ids_injected": injected if inject_parent_policy_id else None})
            except Exception as exc:
                log.exception("  flat-export FAILED: %s → %s", src, dst)
                emitted.append({"label": label_name, "ok": False, "reason": str(exc),
                                "source": str(src), "destination": str(dst)})
        flat_exports_summary = {
            "emitted":            emitted,
            "ok":                 all(e["ok"] for e in emitted),
            "destinations": {
                "groups":   str(REPO_ROOT / "nsx_groups_export"   / source_host / "groups"),
                "services": str(REPO_ROOT / "nsx_services_export" / source_host / "services"),
                "policies": str(REPO_ROOT / "nsx_policies_export" / source_host / "security-policies"),
                "rules":    str(REPO_ROOT / "nsx_rules_export"    / source_host / "security-policies"),
            },
        }
        # Synthetic step entry so the manifest reflects this work
        steps.append({
            "label":   "7_emit_flat_exports",
            "ok":      flat_exports_summary["ok"],
            "summary": flat_exports_summary,
        })

    # Manifest
    ok = all(s["ok"] for s in steps)
    manifest = {
        "command": "capture_nsx_state",
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "captured_from": {
            "manager_alias": args.source,
            "manager_host": source_host,
            "federation_global": args.federation_global,
            "domain_id": args.domain_id,
        },
        "options": {
            "with_vm_tags": args.with_vm_tags,
            "with_impact_report": args.with_impact_report,
            "with_ip_report": args.with_ip_report,
            "ip_report_csv": args.ip_report_csv,
            "emit_flat_exports": args.emit_flat_exports,
        },
        "bundle_dir": str(output_dir),
        "paths": {
            "export_root": str(export_root),
            "source_export_dir": str(source_export_dir),
            "source_groups_dir": str(source_groups_dir),
            "additive_groups_dir": str(additive_groups_dir),
            "segment_inventory_dir": str(segment_inv_dir),
            "segment_details_file": str(segment_inv_dir / "segment_details.json"),
            "segments_inventory_file": str(segment_inv_dir / "segments_inventory.json"),
            "impact_report_dir": str(impact_report_dir) if args.with_impact_report else None,
            "vm_tags_export_root": str(vm_tags_export_root) if args.with_vm_tags and not args.federation_global else None,
            "logs_dir": str(logs_dir),
        },
        "log_file": str(log_file),
        "ok": ok,
        "steps": steps,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    log.info("Manifest written: %s", manifest_path)

    summary_path = output_dir / "summary.txt"
    write_summary(summary_path, manifest)
    log.info("Summary written:  %s", summary_path)

    log.info("=" * 60)
    log.info("Capture %s. Bundle: %s", "OK" if ok else "PARTIAL (some steps failed)", output_dir)
    log.info("Next step: tools/nsx/transform_capture.py --capture %s", output_dir)
    log.info("=" * 60)

    print(json.dumps({
        "bundle": str(output_dir),
        "manifest": str(manifest_path),
        "summary": str(summary_path),
        "ok": ok,
        "step_summary": [{"label": s["label"], "ok": s["ok"]} for s in steps],
    }, indent=2))

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
