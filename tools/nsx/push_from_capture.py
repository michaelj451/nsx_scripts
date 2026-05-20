#!/usr/bin/env python3
"""
tools/nsx/push_from_capture.py

Step 3 of the three-phase capture / transform / push workflow.

Pushes a transformed bundle to a target NSX manager. Only ever talks to
the target — never re-contacts the source NSX manager the capture came
from.

Inputs:
  --target nsx-lm2
  --transformed nsx_transformed/nsx-lm1.lab.local/<UTC_TS>

What it does:

  1. Take a baseline export of the target (Step 1b equivalent — rollback insurance)
  2. Assemble a complete push payload from:
       - capture's raw export (services, policies, rules, meta)
       - transformed bundle's groups_transformed/ tree
  3. Dry-run push (default) OR apply push when --apply is given
  4. Validate live target groups against expected files

All artifacts land in:

  nsx_push/<target-host>/                ← always reflects the LATEST push
    manifest.json                          push metadata + links back to capture + transformed
    summary.txt                            human-readable summary
    target_baseline/                       pre-push GET-only export of target
    nsx_build/<target>/                    assembled push payload
    push_report/                           push tool's own JSON/JSONL artifacts
    validate_report/                       validate_nsx_groups_live's output
    logs/                                  per-step log files

The default push bundle directory is wiped at the start of every run so it
always reflects the most recent push. Per-run history lives in
$NSX_LOG_DIR/push_from_capture_*_<UTC_TS>.log instead. Pass --output-dir to
override the default and preserve specific bundles.

Usage:

  # Dry-run (safe default)
  python tools/nsx/push_from_capture.py \\
    --target nsx-lm2 \\
    --transformed nsx_transformed/nsx-lm1.lab.local/20260520_153012

  # Apply
  python tools/nsx/push_from_capture.py \\
    --target nsx-lm2 \\
    --transformed nsx_transformed/nsx-lm1.lab.local/20260520_153012 \\
    --apply
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
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


def setup_logging(bundle_logs_dir: Path, mode_name: str) -> Path:
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)

    bundle_logs_dir.mkdir(parents=True, exist_ok=True)
    bundle_log_file = (bundle_logs_dir / f"push_from_capture_{mode_name}_{RUN_TS}.log").resolve()
    global_log_file = (global_log_dir / f"push_from_capture_{mode_name}_{RUN_TS}.log").resolve()

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


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"Required JSON file does not exist: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Could not parse JSON file {path}: {exc}")


def copy_latest_run_dir(src_parent: Path, dst_dir: Path, label: str) -> Optional[Path]:
    """Copy the latest timestamped subdir from src_parent (a tool's reports root) into dst_dir."""
    try:
        if not src_parent.exists():
            return None
        runs = sorted([p for p in src_parent.iterdir() if p.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)
        if not runs:
            return None
        dst_dir.mkdir(parents=True, exist_ok=True)
        dst = dst_dir / runs[0].name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(runs[0], dst)
        log.info("Mirrored %s report into bundle: %s", label, dst)
        return dst
    except Exception as exc:
        log.warning("Could not mirror %s report: %s", label, exc)
        return None


def write_summary(summary_path: Path, manifest: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("NSX Push Summary")
    lines.append("=" * 60)
    lines.append(f"Bundle              : {manifest['bundle_dir']}")
    lines.append(f"Mode                : {'APPLY' if manifest['apply'] else 'DRY-RUN'}")
    lines.append(f"Pushed at           : {manifest['pushed_at']}")
    lines.append(f"Target              : {manifest['target']['alias']} ({manifest['target']['host']})")
    lines.append(f"Domain              : {manifest['domain_id']}")
    lines.append(f"From transformed    : {manifest['source_transformed']['bundle_dir']}")
    lines.append(f"From capture        : {manifest['source_capture']['bundle_dir']}")
    cf = manifest["source_capture"]["captured_from"]
    lines.append(f"  Original source   : {cf['manager_alias']} ({cf['manager_host']})")
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
    if manifest.get("push_result_summary"):
        lines.append("Push results")
        lines.append("-" * 60)
        for k, v in manifest["push_result_summary"].items():
            lines.append(f"  {k:24s}: {v}")
        lines.append("")
    lines.append("Artifacts")
    lines.append("-" * 60)
    for k, v in manifest["paths"].items():
        if v:
            lines.append(f"  {k:24s}: {v}")
    lines.append("")
    lines.append(f"Result: {'OK' if manifest['ok'] else 'PARTIAL (some steps failed)'}")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description="Push a transformed capture bundle to a target NSX manager. Never touches the source manager.")
    p.add_argument("--target", required=True, choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
                   help="NSX manager to push TO.")
    p.add_argument("--transformed", required=True,
                   help="Path to a transformed bundle (output of transform_capture.py).")
    p.add_argument("--domain-id", default=None,
                   help="Override the domain ID from the transformed manifest.")
    p.add_argument("--federation-global", action="store_true",
                   help="Target is a Global Manager (use /global-infra).")
    p.add_argument("--apply", action="store_true", default=False,
                   help="Actually push to the target. Without this flag, runs as dry-run.")
    p.add_argument("--output-dir", default=None,
                   help=(
                       "Push bundle directory. Defaults to nsx_push/<target-host>/. "
                       "On each run, the default path is wiped first so it always reflects "
                       "the latest push (previous push artifacts are deleted). Pass an explicit "
                       "--output-dir to preserve specific bundles."
                   ))
    p.add_argument("--skip-baseline", action="store_true",
                   help="Skip the pre-push GET-only baseline export of the target (NOT recommended).")
    p.add_argument("--skip-validate", action="store_true",
                   help="Skip the post-push live validation step.")
    p.add_argument("--groups-only", action="store_true",
                   help=(
                       "Push only groups (PATCH). Skip services, policies, rules. Use this for "
                       "Workflow B in-place groups updates. If the transformed bundle has a "
                       "changed_groups_dir (CSV remap output), only those changed groups are pushed."
                   ))
    args = p.parse_args()

    init_cli()

    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Target manager not defined: {args.target}")

    transformed_dir = Path(args.transformed).expanduser().resolve()
    if not transformed_dir.exists() or not transformed_dir.is_dir():
        raise SystemExit(f"Transformed bundle does not exist or is not a directory: {transformed_dir}")

    xf_manifest = load_json(transformed_dir / "manifest.json")
    capture_dir = Path(xf_manifest["source_capture"]["bundle_dir"]).expanduser().resolve()
    if not capture_dir.exists():
        raise SystemExit(
            f"Capture bundle referenced by transformed manifest does not exist: {capture_dir}\n"
            f"(Did you move the capture? Restore it or re-run capture_nsx_state.py.)"
        )
    cap_manifest = load_json(capture_dir / "manifest.json")

    domain_id = args.domain_id or xf_manifest.get("domain_id") or cap_manifest["captured_from"]["domain_id"]
    source_host = cap_manifest["captured_from"]["manager_host"]

    using_default_output = args.output_dir is None
    output_dir = Path(
        args.output_dir
        or (REPO_ROOT / "nsx_push" / target_host)
    ).expanduser().resolve()

    # On the default path, wipe any previous push bundle so this directory
    # always reflects the latest push. Custom --output-dir paths are left
    # alone so the user can preserve specific bundles if they need to.
    if using_default_output and output_dir.exists():
        log.info("Wiping previous push bundle: %s", output_dir)
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logs_dir = output_dir / "logs"
    mode_name = "apply" if args.apply else "dry_run"
    log_file = setup_logging(logs_dir, mode_name)

    log.info("=" * 60)
    log.info("NSX PUSH — bundle: %s", output_dir)
    log.info("  Target           : %s (%s)", args.target, target_host)
    log.info("  Mode             : %s", mode_name.upper())
    log.info("  Scope            : %s", "groups-only" if args.groups_only else "complete (services+groups+policies+rules)")
    log.info("  Domain           : %s", domain_id)
    log.info("  Federation GM    : %s", args.federation_global)
    log.info("  From transformed : %s", transformed_dir)
    log.info("  From capture     : %s (source=%s)", capture_dir, source_host)
    log.info("=" * 60)

    # Resolve key inputs
    source_export_dir = Path(cap_manifest["paths"]["source_export_dir"])
    if not source_export_dir.exists():
        # Re-derive from capture layout if manifest paths are stale
        source_export_dir = capture_dir / "nsx_export" / source_host
    if not source_export_dir.exists():
        raise SystemExit(f"Capture's source export dir not found: {source_export_dir}")

    transformed_groups_dir = Path(xf_manifest["paths"]["transformed_groups_dir"])
    if not transformed_groups_dir.exists():
        transformed_groups_dir = transformed_dir / "groups_transformed" / "domains" / domain_id / "groups"
    if not transformed_groups_dir.exists():
        raise SystemExit(f"Transformed groups dir not found: {transformed_groups_dir}")

    # For groups-only mode, prefer the changed-only subset (CSV remap output) if it
    # exists — that's the minimal-impact set to PATCH onto the target. Falls back to
    # the full transformed tree if no CSV stage ran.
    push_groups_source: Path = transformed_groups_dir
    if args.groups_only:
        changed_path = xf_manifest.get("paths", {}).get("changed_groups_dir")
        if changed_path and Path(changed_path).exists():
            push_groups_source = Path(changed_path).expanduser().resolve()
            log.info("Groups-only push will use the changed-only subset: %s", push_groups_source)
        else:
            log.info("Groups-only push will use the full transformed tree: %s", push_groups_source)

    target_baseline_dir = output_dir / "target_baseline"
    build_dir = output_dir / "nsx_build" / target_host
    push_report_dir = output_dir / "push_report"
    validate_report_dir = output_dir / "validate_report"

    steps: List[Dict[str, Any]] = []

    # 1. Baseline export of target (rollback insurance) — GET-only
    if not args.skip_baseline:
        cmd = [
            sys.executable, "tools/nsx/export_nsx_objects.py",
            "--manager", args.target,
            "--base-dir", str(target_baseline_dir),
            "--domain-id", domain_id,
            "--output-format", "yaml",
        ]
        if args.federation_global:
            cmd.append("--federation-global")
        steps.append(run_step("1_baseline_export_target", cmd, REPO_ROOT, logs_dir))
    else:
        log.warning("STEP 1 skipped — no target baseline (rollback will rely on previously captured state, if any)")

    push_result_summary: Optional[Dict[str, Any]] = None

    if args.groups_only:
        # ---- Groups-only push path (Workflow B) ----
        log.info("STEP 2 skipped — groups-only push does not assemble a complete payload")

        # Direct push_additive_group_ips to write reports inside the push bundle.
        push_report_dir.mkdir(parents=True, exist_ok=True)

        push_cmd = [
            sys.executable, "tools/nsx/push_additive_group_ips.py",
            "--target", args.target,
            "--groups-dir", str(push_groups_source),
            "--domain-id", domain_id,
            "--reports-dir", str(push_report_dir),
        ]
        if args.federation_global:
            push_cmd.append("--federation-global")
        if args.apply:
            push_cmd.append("--apply")
        else:
            push_cmd.append("--dry-run")
        steps.append(run_step(f"3_push_additive_group_ips_{mode_name}", push_cmd, REPO_ROOT, logs_dir))

        # Find and summarize the report
        summary_candidates = list(push_report_dir.rglob("summary*.json"))
        if summary_candidates:
            summary_json = summary_candidates[0]
            try:
                rep = json.loads(summary_json.read_text(encoding="utf-8"))
                push_result_summary = {
                    "pushed_groups": rep.get("group_files_found"),
                    "success": rep.get("success"),
                    "failed": rep.get("failed"),
                    "skipped": rep.get("skipped"),
                    "dry_run_count": rep.get("dry_run_count"),
                }
            except Exception as exc:
                log.warning("Could not summarize push report at %s: %s", summary_json, exc)
    else:
        # ---- Complete-payload push path (Workflow A) ----
        # 2. Assemble complete push payload
        cmd = [
            sys.executable, "tools/nsx/build_complete_nsx_payload.py",
            "--source-manager-dir", str(source_export_dir),
            "--additive-groups-dir", str(transformed_groups_dir),
            "--build-dir", str(build_dir),
            "--domain-id", domain_id,
            "--overwrite",
        ]
        steps.append(run_step("2_build_complete_nsx_payload", cmd, REPO_ROOT, logs_dir))

        # 3. Push (dry-run by default; --apply runs the real push)
        push_cmd = [
            sys.executable, "tools/nsx/push_complete_nsx_payload.py",
            "--target", args.target,
            "--build-dir", str(build_dir),
            "--domain-id", domain_id,
        ]
        if args.federation_global:
            push_cmd.append("--federation-global")
        if args.apply:
            push_cmd.append("--apply")
        else:
            push_cmd.append("--dry-run")
        steps.append(run_step(f"3_push_complete_nsx_payload_{mode_name}", push_cmd, REPO_ROOT, logs_dir))

        # Mirror push tool's per-run report directory into the bundle
        push_report_root = Path(nsx_log_dir).expanduser().resolve() / (
            "push_complete_nsx_payload_apply" if args.apply else "push_complete_nsx_payload_dry_run"
        )
        mirrored_push = copy_latest_run_dir(push_report_root, push_report_dir, "push")

        if mirrored_push:
            summary_json = mirrored_push / "summary.json"
            if summary_json.exists():
                try:
                    rep = json.loads(summary_json.read_text(encoding="utf-8"))
                    push_result_summary = {
                        "pushed_services": rep.get("pushed", {}).get("services"),
                        "pushed_groups": rep.get("pushed", {}).get("groups"),
                        "pushed_policies": rep.get("pushed", {}).get("policies"),
                        "pushed_rules": rep.get("pushed", {}).get("rules"),
                        "success": rep.get("results", {}).get("success"),
                        "failed": rep.get("results", {}).get("failed"),
                        "skipped": rep.get("results", {}).get("skipped"),
                        "dry_run": rep.get("results", {}).get("dry_run"),
                    }
                except Exception as exc:
                    log.warning("Could not summarize push report: %s", exc)

    # 4. Live validation (only meaningful after --apply, but harmless after dry-run too)
    if not args.skip_validate and args.apply:
        cmd = [
            sys.executable, "tools/nsx/validate_nsx_groups_live.py",
            "--target", args.target,
            "--expected-root", str(transformed_dir / "groups_transformed"),
            "--domain-id", domain_id,
        ]
        if args.federation_global:
            cmd.append("--federation-global")
        steps.append(run_step("4_validate_nsx_groups_live", cmd, REPO_ROOT, logs_dir))
        copy_latest_run_dir(Path(nsx_log_dir).expanduser().resolve() / "validate_nsx_groups_live",
                            validate_report_dir, "validate")
    elif args.skip_validate:
        log.info("STEP 4 skipped (--skip-validate)")
    else:
        log.info("STEP 4 skipped — validation only runs after --apply")

    ok = all(s["ok"] for s in steps)

    manifest = {
        "command": "push_from_capture",
        "schema_version": 1,
        "pushed_at": datetime.now(timezone.utc).isoformat(),
        "bundle_dir": str(output_dir),
        "apply": args.apply,
        "domain_id": domain_id,
        "target": {
            "alias": args.target,
            "host": target_host,
            "federation_global": args.federation_global,
        },
        "source_transformed": {
            "bundle_dir": str(transformed_dir),
            "transformed_at": xf_manifest.get("transformed_at"),
            "segment_mode": xf_manifest.get("options", {}).get("segment_mode"),
        },
        "source_capture": {
            "bundle_dir": str(capture_dir),
            "captured_at": cap_manifest.get("captured_at"),
            "captured_from": cap_manifest.get("captured_from", {}),
        },
        "options": {
            "apply": args.apply,
            "groups_only": args.groups_only,
            "skip_baseline": args.skip_baseline,
            "skip_validate": args.skip_validate,
        },
        "paths": {
            "target_baseline_dir": str(target_baseline_dir) if not args.skip_baseline else None,
            "build_dir": str(build_dir) if not args.groups_only else None,
            "transformed_groups_dir": str(transformed_groups_dir),
            "push_groups_source": str(push_groups_source) if args.groups_only else None,
            "source_export_dir": str(source_export_dir),
            "push_report_dir": str(push_report_dir),
            "validate_report_dir": str(validate_report_dir) if not args.skip_validate and args.apply else None,
            "logs_dir": str(logs_dir),
        },
        "push_result_summary": push_result_summary,
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
    log.info("Push %s. Bundle: %s", "OK" if ok else "PARTIAL (some steps failed)", output_dir)
    if not args.apply and ok:
        log.info("Dry-run passed. To apply: re-run with --apply.")
    log.info("=" * 60)

    print(json.dumps({
        "bundle": str(output_dir),
        "manifest": str(manifest_path),
        "summary": str(summary_path),
        "ok": ok,
        "mode": mode_name,
        "step_summary": [{"label": s["label"], "ok": s["ok"]} for s in steps],
        "push_result_summary": push_result_summary,
    }, indent=2))

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
