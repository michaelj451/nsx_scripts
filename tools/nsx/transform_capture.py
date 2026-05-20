#!/usr/bin/env python3
"""
tools/nsx/transform_capture.py

Step 2 of the three-phase capture / transform / push workflow.

Offline transform of a capture bundle. Never touches NSX. Reads from a
capture bundle (produced by capture_nsx_state.py) and writes a new,
self-contained transformed bundle that's ready for push_from_capture.py
to consume.

The original capture bundle is left untouched — you can run multiple
transforms against the same capture (e.g. different segment modes, or
just to evaluate options) without re-hitting the source NSX manager.

What gets written:

  nsx_transformed/<source-host>/<UTC_TS>/
    manifest.json                    transform metadata + link back to capture
    summary.txt                      human-readable summary
    groups_transformed/
      domains/<domain>/groups/...    transformed group YAML files
    transform_report/
      segments_stripped.json         per-group strip/convert detail
    logs/                            per-step log files

Usage:

  python tools/nsx/transform_capture.py \\
    --capture nsx_capture/nsx-lm1.lab.local/20260520_153012 \\
    --segment-mode convert

  # Just strip segment references (no CIDR substitution):
  python tools/nsx/transform_capture.py \\
    --capture nsx_capture/nsx-lm1.lab.local/20260520_153012 \\
    --segment-mode strip
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
from nsx.nsx_constants import nsx_log_dir


log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def setup_logging(bundle_logs_dir: Path) -> Path:
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)

    bundle_logs_dir.mkdir(parents=True, exist_ok=True)
    bundle_log_file = (bundle_logs_dir / f"transform_capture_{RUN_TS}.log").resolve()
    global_log_file = (global_log_dir / f"transform_capture_{RUN_TS}.log").resolve()

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


def load_capture_manifest(capture_dir: Path) -> Dict[str, Any]:
    manifest_path = capture_dir / "manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"Capture bundle missing manifest.json: {manifest_path}")
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Could not parse capture manifest {manifest_path}: {exc}")


def write_summary(summary_path: Path, manifest: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("NSX Transform Summary")
    lines.append("=" * 60)
    lines.append(f"Transformed bundle  : {manifest['bundle_dir']}")
    lines.append(f"Built at            : {manifest['transformed_at']}")
    lines.append(f"From capture        : {manifest['source_capture']['bundle_dir']}")
    cf = manifest["source_capture"]["captured_from"]
    lines.append(f"  Original source   : {cf['manager_alias']} ({cf['manager_host']})")
    lines.append(f"  Captured at       : {manifest['source_capture']['captured_at']}")
    lines.append(f"Domain              : {manifest['domain_id']}")
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
    if manifest.get("transform_report_summary"):
        rep = manifest["transform_report_summary"]
        lines.append("Transform results")
        lines.append("-" * 60)
        for k, v in rep.items():
            lines.append(f"  {k:32s}: {v}")
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
    p = argparse.ArgumentParser(description="Offline transform of an NSX capture bundle. Never touches NSX.")
    p.add_argument("--capture", required=True,
                   help="Path to a capture bundle (output of capture_nsx_state.py).")
    p.add_argument("--output-dir", default=None,
                   help="Transformed bundle directory. Defaults to nsx_transformed/<source-host>/<UTC_TS>/.")
    p.add_argument("--segment-mode", choices=["convert", "strip", "skip"], default=None,
                   help=(
                       "How to handle segment references in groups. "
                       "convert = replace with IPAddressExpression CIDRs (uses cached segment_details.json). "
                       "strip   = drop segment refs entirely. "
                       "skip    = leave segment refs untouched (groups still need segments to exist on target). "
                       "Default: 'convert' for Workflow A (no --csv-remap), 'skip' when --csv-remap is given."
                   ))
    p.add_argument("--csv-remap", default=None,
                   help=(
                       "Path to a CSV mapping file (old_subnet,new_subnet rows). When given, runs "
                       "nsx_group_ip_remap_offline.py after any segment transform. Use this for "
                       "Workflow B (in-place groups-only subnet remap)."
                   ))
    p.add_argument("--mapped-only", action="store_true",
                   help=(
                       "With --csv-remap: replace each IPAddressExpression with only the mapped values. "
                       "Drops any IPs not covered by the CSV. Default: append mapped values, keep originals."
                   ))
    p.add_argument("--bidirectional", action="store_true",
                   help="With --csv-remap: treat each CSV row as a bidirectional mapping.")
    p.add_argument("--domain-id", default=None,
                   help="Override the domain ID from the capture manifest (rarely needed).")
    p.add_argument("--source-groups", choices=["additive", "raw"], default="additive",
                   help=(
                       "Which groups in the capture to use as input. "
                       "additive = the live-member-enriched groups (default; recommended). "
                       "raw      = the raw exported groups (no live IP enrichment)."
                   ))
    args = p.parse_args()

    # Resolve auto-default for --segment-mode based on workflow shape.
    if args.segment_mode is None:
        args.segment_mode = "skip" if args.csv_remap else "convert"

    init_cli()

    capture_dir = Path(args.capture).expanduser().resolve()
    if not capture_dir.exists() or not capture_dir.is_dir():
        raise SystemExit(f"Capture bundle does not exist or is not a directory: {capture_dir}")

    cap_manifest = load_capture_manifest(capture_dir)
    source_host = cap_manifest["captured_from"]["manager_host"]
    domain_id = args.domain_id or cap_manifest["captured_from"]["domain_id"]

    output_dir = Path(
        args.output_dir
        or (REPO_ROOT / "nsx_transformed" / source_host / RUN_TS)
    ).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    logs_dir = output_dir / "logs"
    log_file = setup_logging(logs_dir)

    log.info("=" * 60)
    log.info("NSX TRANSFORM — bundle: %s", output_dir)
    log.info("  From capture     : %s", capture_dir)
    log.info("  Source host      : %s", source_host)
    log.info("  Domain           : %s", domain_id)
    log.info("  Segment mode     : %s", args.segment_mode)
    log.info("  CSV remap        : %s", args.csv_remap or "(none)")
    if args.csv_remap:
        log.info("    Mapped-only    : %s", args.mapped_only)
        log.info("    Bidirectional  : %s", args.bidirectional)
    log.info("  Source groups    : %s", args.source_groups)
    log.info("=" * 60)

    # Resolve input groups dir from capture
    cap_paths = cap_manifest.get("paths", {})
    if args.source_groups == "additive":
        candidate = cap_paths.get("additive_groups_dir")
        if not candidate:
            log.warning("Capture did not include additive groups; falling back to raw exported groups.")
            candidate = cap_paths.get("source_groups_dir")
    else:
        candidate = cap_paths.get("source_groups_dir")

    if not candidate or not Path(candidate).exists():
        # Re-derive from bundle layout if manifest paths are stale (e.g. bundle was moved)
        if args.source_groups == "additive":
            candidate = str(capture_dir / "groups_additive" / "domains" / domain_id / "groups")
            if not Path(candidate).exists():
                candidate = str(capture_dir / "nsx_export" / source_host / "domains" / domain_id / "groups")
        else:
            candidate = str(capture_dir / "nsx_export" / source_host / "domains" / domain_id / "groups")

    input_groups_dir = Path(candidate).expanduser().resolve()
    if not input_groups_dir.exists():
        raise SystemExit(f"Could not locate input groups dir in capture bundle: {input_groups_dir}")
    log.info("Input groups dir: %s", input_groups_dir)

    # Resolve segment details file (for convert mode)
    segment_details_file: Optional[Path] = None
    if args.segment_mode == "convert":
        candidate_seg = cap_paths.get("segment_details_file")
        if not candidate_seg or not Path(candidate_seg).exists():
            # Re-derive from bundle layout
            candidate_seg = str(capture_dir / "segment_inventory" / "segment_details.json")
        if Path(candidate_seg).exists():
            segment_details_file = Path(candidate_seg).expanduser().resolve()
            log.info("Using cached segment details: %s", segment_details_file)
        else:
            log.warning(
                "--segment-mode convert requested but no segment_details.json found in capture. "
                "transform_group_segments will fall back to plain strip behavior."
            )

    # Output paths
    transformed_groups_dir = output_dir / "groups_transformed" / "domains" / domain_id / "groups"
    changed_groups_dir = output_dir / "groups_changed_only" / "domains" / domain_id / "groups"
    transform_report_dir = output_dir / "transform_report"
    transform_report_dir.mkdir(parents=True, exist_ok=True)

    # Staging paths (used when both segment and CSV transforms run)
    stage_segment_dir = output_dir / "stage_segment" / "domains" / domain_id / "groups"

    steps: List[Dict[str, Any]] = []
    segment_report_summary: Optional[Dict[str, Any]] = None
    csv_remap_report_summary: Optional[Dict[str, Any]] = None
    changed_groups_dir_recorded: Optional[Path] = None

    # ----------------------------------------------------------------------
    # Stage 1 — segment transform (optional). Writes a full groups tree.
    # ----------------------------------------------------------------------
    # When the segment stage runs AND CSV remap is also requested, segment
    # output goes to stage_segment_dir so the final transformed_groups_dir
    # can be assembled at the end with CSV changes layered on top.
    # When only segment runs (no CSV), segment writes directly to
    # transformed_groups_dir to avoid an extra copy.
    # ----------------------------------------------------------------------
    if args.segment_mode != "skip":
        seg_output_dir = stage_segment_dir if args.csv_remap else transformed_groups_dir
        cmd = [
            sys.executable, "tools/nsx/transform_group_segments.py",
            "--input-dir", str(input_groups_dir),
            "--output-dir", str(seg_output_dir),
            "--mode", args.segment_mode,
            "--overwrite",
        ]
        if args.segment_mode == "convert" and segment_details_file:
            cmd.extend(["--segments-from", str(segment_details_file)])
        steps.append(run_step(f"1_transform_group_segments_{args.segment_mode}", cmd, REPO_ROOT, logs_dir))

        # Mirror transform_group_segments' report into the bundle
        try:
            tgs_root = Path(nsx_log_dir).expanduser().resolve() / "transform_group_segments"
            if tgs_root.exists():
                runs = sorted([p for p in tgs_root.iterdir() if p.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)
                if runs:
                    src_report = runs[0] / "segments_stripped.json"
                    if src_report.exists():
                        dst_report = transform_report_dir / "segments_stripped.json"
                        shutil.copy2(src_report, dst_report)
                        log.info("Copied segment report into bundle: %s", dst_report)
                        try:
                            rep_json = json.loads(dst_report.read_text(encoding="utf-8"))
                            segment_report_summary = {
                                k: rep_json.get(k) for k in (
                                    "mode",
                                    "files_seen",
                                    "files_modified",
                                    "total_segment_paths_stripped",
                                    "total_segments_converted",
                                    "total_unresolved_segment_paths",
                                    "total_path_expressions_dropped",
                                    "fetch_error",
                                )
                            }
                        except Exception as exc:
                            log.warning("Could not summarize segment report: %s", exc)
        except Exception as exc:
            log.warning("Could not mirror segment report into bundle: %s", exc)
    else:
        log.info("Stage 1 (segment transform) skipped — segment-mode=skip")

    # ----------------------------------------------------------------------
    # Stage 2 — CSV subnet remap (optional). Writes only CHANGED groups.
    # ----------------------------------------------------------------------
    if args.csv_remap:
        csv_path = Path(args.csv_remap).expanduser().resolve()
        if not csv_path.exists():
            raise SystemExit(f"CSV mapping file does not exist: {csv_path}")

        # Input to CSV stage = output of segment stage if it ran, else the
        # capture's input groups dir.
        csv_input_dir = stage_segment_dir if args.segment_mode != "skip" else input_groups_dir

        cmd = [
            sys.executable, "tools/nsx/nsx_group_ip_remap_offline.py",
            "--export-root", str(csv_input_dir),
            "--prepared-root", str(changed_groups_dir),
            "--mapping-csv", str(csv_path),
            "--output-format", "yaml",
        ]
        if args.mapped_only:
            cmd.append("--mapped-only")
        if args.bidirectional:
            cmd.append("--bidirectional")
        steps.append(run_step("2_nsx_group_ip_remap_offline", cmd, REPO_ROOT, logs_dir))

        # Mirror the remap manifest into the bundle's transform_report
        try:
            remap_manifest_src = changed_groups_dir / "manifest.json"
            if remap_manifest_src.exists():
                dst = transform_report_dir / "csv_remap_manifest.json"
                shutil.copy2(remap_manifest_src, dst)
                log.info("Copied CSV remap manifest into bundle: %s", dst)
                try:
                    mj = json.loads(dst.read_text(encoding="utf-8"))
                    csv_remap_report_summary = {
                        k: mj.get(k) for k in (
                            "mapping_csv",
                            "mapped_only",
                            "bidirectional",
                            "total_mapping_rows",
                            "total_group_files",
                            "groups_changed",
                            "groups_unchanged",
                            "groups_skipped",
                            "total_added_ip_values",
                            "invalid_mapping_rows",
                        )
                    }
                    if isinstance(csv_remap_report_summary.get("invalid_mapping_rows"), list):
                        csv_remap_report_summary["invalid_mapping_rows"] = len(csv_remap_report_summary["invalid_mapping_rows"])
                except Exception as exc:
                    log.warning("Could not summarize CSV remap manifest: %s", exc)

            # Mirror reports written alongside the prepared-root
            reports_src = changed_groups_dir.parent / "reports" / "group-ip-remap"
            if reports_src.exists():
                reports_dst = transform_report_dir / "group-ip-remap"
                if reports_dst.exists():
                    shutil.rmtree(reports_dst)
                shutil.copytree(reports_src, reports_dst)
                log.info("Copied CSV remap reports into bundle: %s", reports_dst)
        except Exception as exc:
            log.warning("Could not mirror CSV remap artifacts: %s", exc)

        changed_groups_dir_recorded = changed_groups_dir

    # ----------------------------------------------------------------------
    # Final assembly — build transformed_groups_dir (full tree)
    # ----------------------------------------------------------------------
    # Order of preference for the full tree base:
    #   1. stage_segment_dir if segment ran
    #   2. capture's input_groups_dir otherwise
    # Then overlay any CSV-changed files on top.
    # ----------------------------------------------------------------------
    if transformed_groups_dir.exists() and (args.csv_remap or args.segment_mode == "skip"):
        # Only purge if we still need to populate (segment-only with no CSV
        # already wrote here in-place; don't re-touch).
        shutil.rmtree(transformed_groups_dir)

    if args.csv_remap:
        # Need to assemble the full tree explicitly.
        base_dir = stage_segment_dir if args.segment_mode != "skip" else input_groups_dir
        transformed_groups_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(base_dir, transformed_groups_dir)
        # Overlay changed groups (CSV stage output) on top
        if changed_groups_dir.exists():
            for ext in ("*.yaml", "*.yml", "*.json"):
                for src in changed_groups_dir.rglob(ext):
                    if src.is_file() and src.name != "manifest.json":
                        dst = transformed_groups_dir / src.relative_to(changed_groups_dir)
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src, dst)
        log.info("Assembled full transformed tree at %s (with CSV overlay)", transformed_groups_dir)
    elif args.segment_mode == "skip":
        # Neither stage ran — copy input straight to transformed.
        transformed_groups_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(input_groups_dir, transformed_groups_dir)
        steps.append({
            "label": "0_copy_groups_unchanged",
            "cmd": ["<inline-copy>", str(input_groups_dir), str(transformed_groups_dir)],
            "ok": True,
            "returncode": 0,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "step_log": "",
            "stdout_tail": "",
            "stderr_tail": "",
        })
        log.info("No transform stages ran — copied input to transformed tree")
    else:
        # Segment-only path — segment wrote directly to transformed_groups_dir
        log.info("Transformed tree at %s (segment-only)", transformed_groups_dir)

    ok = all(s["ok"] for s in steps)

    # Combined report summary
    transform_report_summary: Dict[str, Any] = {}
    if segment_report_summary:
        for k, v in segment_report_summary.items():
            transform_report_summary[f"segment_{k}"] = v
    if csv_remap_report_summary:
        for k, v in csv_remap_report_summary.items():
            transform_report_summary[f"csv_{k}"] = v
    if not transform_report_summary:
        transform_report_summary = None  # type: ignore[assignment]

    manifest = {
        "command": "transform_capture",
        "schema_version": 1,
        "transformed_at": datetime.now(timezone.utc).isoformat(),
        "bundle_dir": str(output_dir),
        "domain_id": domain_id,
        "source_capture": {
            "bundle_dir": str(capture_dir),
            "captured_at": cap_manifest.get("captured_at"),
            "captured_from": cap_manifest.get("captured_from", {}),
        },
        "options": {
            "segment_mode": args.segment_mode,
            "source_groups": args.source_groups,
            "segment_details_file": str(segment_details_file) if segment_details_file else None,
            "csv_remap": str(Path(args.csv_remap).expanduser().resolve()) if args.csv_remap else None,
            "mapped_only": args.mapped_only,
            "bidirectional": args.bidirectional,
        },
        "paths": {
            "input_groups_dir": str(input_groups_dir),
            "transformed_groups_dir": str(transformed_groups_dir),
            "changed_groups_dir": str(changed_groups_dir_recorded) if changed_groups_dir_recorded else None,
            "transform_report_dir": str(transform_report_dir),
            "logs_dir": str(logs_dir),
        },
        "transform_report_summary": transform_report_summary,
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
    log.info("Transform %s. Bundle: %s", "OK" if ok else "PARTIAL (some steps failed)", output_dir)
    log.info("Next step: tools/nsx/push_from_capture.py --target <target> --transformed %s --dry-run", output_dir)
    log.info("=" * 60)

    print(json.dumps({
        "bundle": str(output_dir),
        "manifest": str(manifest_path),
        "summary": str(summary_path),
        "ok": ok,
        "step_summary": [{"label": s["label"], "ok": s["ok"]} for s in steps],
        "transform_report_summary": transform_report_summary,
    }, indent=2))

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
