#!/usr/bin/env python3
"""tools/nsx/run_workflow.py

Run a whole workflow phase as ONE command, and always produce its report.

    # Phase A Part 1 (clone). Dry run, then apply.
    python tools/nsx/run_workflow.py --source nsx-lm1 --target nsx-lm2 --phase a
    python tools/nsx/run_workflow.py --source nsx-lm1 --target nsx-lm2 --phase a --apply

    # Phase C (sibling decomposition).
    python tools/nsx/run_workflow.py --source nsx-lm1 --target nsx-lm2 --phase c
    python tools/nsx/run_workflow.py --source nsx-lm1 --target nsx-lm2 --phase c --apply

WHY THIS EXISTS

The per-tool push reports are written to fixed filenames, so each invocation
overwrites the previous one's rows. Generating the consolidated report was a
separate manual command that had to be run in the window between the dry run
and the apply; miss it and the pre-apply report is gone for good. That is a
discipline problem, and discipline is not a safeguard.

This driver closes the window. It runs the phase's steps in dependency order
and then generates the report itself, tagged with the mode it just ran. A dry
run produces the dry-run report; an apply produces the apply report. Neither
can be forgotten, and the two can never be conflated, because one invocation
runs exactly one mode.

WHAT IT DOES NOT DO

  - It does not capture or export. Run capture_nsx_state.py --live-query and
    the per-class exports first; phase A reads those bundles.
  - It does not decide anything. Every step is the same command you would run
    by hand, with --apply passed through.
  - Phase C never rebuilds the sibling bundle during an --apply run, so the
    apply pushes exactly what the dry run previewed. It will build the bundle
    on a dry run if it is missing.

Exit code is 0 only when every step succeeded. The report is written even when
a step fails, so a failed run is still auditable.
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from nsx.cli_bootstrap import init_cli          # noqa: E402
from nsx.nsx_constants import resolve_manager    # noqa: E402

log = logging.getLogger("run_workflow")

PY = sys.executable
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2",
                       "nsx-lm3", "nsx-lm4", "nsx-lm5"]


def run_step(label: str, cmd: List[str], log_dir: Path) -> Dict[str, Any]:
    """Run one push as a subprocess, streaming to a per-step log.

    Mirrors capture_nsx_state.run_step so the two orchestrators behave the
    same way for an operator reading logs.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    step_log = log_dir / f"{label}.log"
    log.info("STEP %s", label)
    log.info("  cmd: %s", " ".join(cmd))
    with step_log.open("w", encoding="utf-8") as fh:
        proc = subprocess.run(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
        fh.write(proc.stdout or "")
    ok = proc.returncode == 0
    log.log(logging.INFO if ok else logging.ERROR,
            "  %s (rc=%d)  log: %s", "OK" if ok else "FAILED",
            proc.returncode, step_log)
    if not ok:
        for line in (proc.stdout or "").splitlines()[-15:]:
            log.error("    %s", line)
    return {"label": label, "cmd": cmd, "rc": proc.returncode, "ok": ok,
            "log": str(step_log)}


def phase_a_steps(src_host: str, target: str, apply: bool) -> List[Dict[str, Any]]:
    """WF-A Part 1: services, groups (segments stripped), policies, rules."""
    a = ["--apply"] if apply else []
    # --diff-target only matters on a dry run: an apply always captures a
    # baseline and diffs against it. Without it a dry run cannot report which
    # IPs it would add or remove.
    d = [] if apply else ["--diff-target"]
    return [
        {"label": "a1_services", "roots": [f"nsx_services_export/{src_host}"],
         "cmd": [PY, "tools/nsx/services.py", "push", "--target", target,
                 "--services-dir", f"nsx_services_export/{src_host}/services"] + a},
        {"label": "a2_groups", "roots": [f"nsx_groups_export/{src_host}"],
         "cmd": [PY, "tools/nsx/groups.py", "push", "--target", target,
                 "--groups-dir", f"nsx_groups_export/{src_host}/groups",
                 "--segments-mode", "strip"] + d + a},
        {"label": "a3_policies", "roots": [f"nsx_policies_export/{src_host}"],
         "cmd": [PY, "tools/nsx/policies.py", "push", "--target", target,
                 "--policies-dir", f"nsx_policies_export/{src_host}/security-policies"] + a},
        {"label": "a4_rules", "roots": [f"nsx_rules_export/{src_host}"],
         "cmd": [PY, "tools/nsx/rules.py", "push", "--target", target,
                 "--rules-dir", f"nsx_rules_export/{src_host}/security-policies"] + a},
    ]


def phase_c_steps(src_host: str, target: str, apply: bool,
                  sib: Path, strip: Path, tgt_host: str) -> List[Dict[str, Any]]:
    """WF-C: push siblings, strip the originals, amend the rules."""
    a = ["--apply"] if apply else []
    d = [] if apply else ["--diff-target"]
    return [
        {"label": "c3_siblings", "roots": [str(sib)],
         "cmd": [PY, "tools/nsx/groups.py", "push", "--target", target,
                 "--groups-dir", str(sib / "groups")] + d + a},
        {"label": "c4_stripped", "roots": [str(strip)],
         "cmd": [PY, "tools/nsx/groups.py", "push", "--target", target,
                 "--groups-dir", str(strip / "groups"),
                 "--intentional-ip-removal"] + d + a},
        {"label": "c5_amend_refs", "roots": [f"nsx_rules_export/{tgt_host}"],
         "cmd": [PY, "tools/nsx/rules.py", "amend-refs", "--target", target,
                 "--sibling-map", str(sib / "sibling_map.json")] + a},
    ]


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("WHY THIS EXISTS", 1)[1] if "WHY THIS EXISTS" in __doc__ else None)
    p.add_argument("--source", required=True, choices=NSX_MANAGER_CHOICES)
    p.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    p.add_argument("--phase", required=True, choices=["a", "c"],
                   help="a = WF-A Part 1 clone; c = WF-C sibling decomposition.")
    p.add_argument("--apply", action="store_true",
                   help="Write to the target. Default is a dry run.")
    p.add_argument("--run-dir", default=None,
                   help="Where bundles and reports land (default: nsx_avs_runs/<src>_to_<tgt>).")
    p.add_argument("--domain-id", default="default")
    p.add_argument("--appendix", default=None,
                   help="Phase C sibling suffix; default OBJECT_APPENDIX from .env.")
    p.add_argument("--continue-on-error", action="store_true",
                   help="Keep going after a failed step (default: stop, so a broken "
                        "push does not cascade into the next dependency level).")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = __import__("time").gmtime
    init_cli()

    if args.source == args.target:
        log.warning("source and target are the same manager (%s): this is the "
                    "supported in-place mode, but confirm that is intended.", args.source)

    src_host = resolve_manager(args.source)
    tgt_host = resolve_manager(args.target)
    mode = "apply" if args.apply else "dryrun"
    started = datetime.now(timezone.utc)
    since = started.strftime("%Y-%m-%dT%H:%M:%S")

    run_dir = Path(args.run_dir) if args.run_dir else \
        REPO_ROOT / "nsx_avs_runs" / f"{args.source}_to_{args.target}"
    run_dir.mkdir(parents=True, exist_ok=True)
    log_dir = run_dir / "logs" / f"{started.strftime('%Y%m%d_%H%M%S')}_{args.phase}_{mode}"

    log.info("=" * 70)
    log.info("WORKFLOW %s  %s -> %s", args.phase.upper(), args.source, args.target)
    log.info("  mode     : %s", "APPLY (writes)" if args.apply else "DRY RUN (no writes)")
    log.info("  run dir  : %s", run_dir)
    log.info("=" * 70)

    sib = run_dir / "nsx_sibling_groups" / src_host
    strip = run_dir / "nsx_stripped_groups" / src_host

    if args.phase == "a":
        steps = phase_a_steps(src_host, args.target, args.apply)
    else:
        # Build the bundle only on a dry run, and only when missing. An apply
        # must push exactly what its dry run previewed, so it never rebuilds.
        if not (sib / "sibling_map.json").exists():
            if args.apply:
                log.error("No sibling bundle at %s. Run the dry run first so the "
                          "apply pushes exactly what was previewed.", sib)
                return 2
            build = [PY, "tools/nsx/build_sibling_groups.py", "--source", args.source,
                     "--output-base", str(run_dir), "--domain-id", args.domain_id]
            if args.appendix:
                build += ["--appendix", args.appendix]
            rec = run_step("c2_build_siblings", build, log_dir)
            if not rec["ok"]:
                log.error("Sibling build failed; nothing pushed.")
                return 1
        else:
            log.info("Using existing sibling bundle: %s", sib)
        steps = phase_c_steps(src_host, args.target, args.apply, sib, strip, tgt_host)

    records, roots = [], []
    for step in steps:
        rec = run_step(step["label"], step["cmd"], log_dir)
        records.append(rec)
        roots.extend(step["roots"])
        if not rec["ok"] and not args.continue_on_error:
            log.error("Stopping: %s failed. Re-run after fixing, or pass "
                      "--continue-on-error.", step["label"])
            break

    # The report is generated HERE, in the same invocation that ran the steps,
    # which is what makes it impossible to forget and impossible to attribute
    # to the wrong mode.
    out_dir = run_dir / "report" / mode
    report_cmd = [PY, "tools/nsx/report_avs_run.py", "--out-dir", str(out_dir),
                  "--since", since,
                  "--label", f"WF-{args.phase.upper()} {mode.upper()}: "
                             f"{args.source} to {args.target}"]
    for r in dict.fromkeys(roots):
        report_cmd += ["--report-root", r]
    rep = run_step("report", report_cmd, log_dir)

    manifest = {
        "workflow": args.phase, "mode": mode,
        "source": args.source, "target": args.target,
        "source_host": src_host, "target_host": tgt_host,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "steps": records, "report_dir": str(out_dir),
        "ok": all(r["ok"] for r in records),
    }
    (log_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    failed = [r["label"] for r in records if not r["ok"]]
    log.info("=" * 70)
    log.info("WF-%s %s: %d/%d steps ok%s", args.phase.upper(), mode,
             len(records) - len(failed), len(records),
             f"  FAILED: {failed}" if failed else "")
    log.info("Report: %s", out_dir / "avs_run_report.md")
    log.info("=" * 70)
    if not args.apply and not failed:
        log.info("Dry run only. Re-run with --apply to write, then compare the "
                 "two reports under %s", run_dir / "report")
    return 0 if not failed and rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
