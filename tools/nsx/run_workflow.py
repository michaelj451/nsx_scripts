#!/usr/bin/env python3
"""tools/nsx/run_workflow.py

Run a whole workflow phase as ONE command, and always produce its report.

Four verbs, same shape for every phase. Define a shell function once, then the
only thing that changes per command is the verb:

    wf() { python tools/nsx/run_workflow.py --source nsx-lm1 --target nsx-lm2 "$@"; }

    wf --phase a                        # dry run
    wf --phase a --apply                # apply
    wf --phase a --verify               # read-only check
    wf --phase a --rollback             # rollback preview
    wf --phase a --rollback --apply     # rollback

Use a function, not a variable: W="python ..." followed by $W --phase a works
in bash but fails in zsh, which does not word-split an unquoted parameter.

Phases: a (WF-A Part 1 clone), c (WF-C decomposition), and d2a / d2b / d3 / d5
(one WF-D change window each; d2a and d2b need --csv-remap). Reports land under
<run-dir>/report/<phase>/<mode>, so no two invocations overwrite each other.
See docs/nsx/RUNBOOK_WORKFLOW.md.

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

CAPTURE FIRST, THEN SWITCH CREDENTIALS

A/C use a two-step process. First run capture_nsx_state.py --source <source>
--live-query using the source credentials. Then change NSX_USERNAME and
NSX_PASSWORD to the target credentials. A/C dry run, apply, verify and rollback
contact only the target; verification compares it with the saved source capture.
C rebuilds siblings from that capture on each dry run, never on apply. Keep the
capture and its flat exports unchanged until the run is finished.

WF-D still re-captures before a dry run by default; --no-capture reuses its saved
capture. No phase captures on apply.

WHAT IT DOES NOT DO

  - It does not decide anything. Every step is the same command you would run
    by hand, with --apply passed through.

Exit code is 0 only when every step succeeded. The report is written even when
a step fails, so a failed run is still auditable.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from nsx.streaming import stream_command
from nsx.cli_bootstrap import init_cli          # noqa: E402
from nsx.nsx_constants import resolve_manager  # noqa: E402
from nsx.captured_source import validate_capture  # noqa: E402

log = logging.getLogger("run_workflow")

PY = sys.executable
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2",
                       "nsx-lm3", "nsx-lm4", "nsx-lm5"]


def run_step(label: str, cmd: List[str], log_dir: Path) -> Dict[str, Any]:
    """Stream a step's combined output live to the terminal and its log file."""
    log_dir.mkdir(parents=True, exist_ok=True)
    step_log = log_dir / f"{label}.log"
    log.info("STEP %s", label)
    log.info("  cmd: %s", " ".join(cmd))
    returncode, _ = stream_command(cmd, REPO_ROOT, step_log)
    ok = returncode == 0
    log.log(logging.INFO if ok else logging.ERROR,
            "  %s (rc=%d)  log: %s", "OK" if ok else "FAILED", returncode, step_log)
    return {"label": label, "cmd": cmd, "rc": returncode, "ok": ok, "log": str(step_log)}


def check_capture_gate(capture: Path, source_host: str, domain_id: str) -> Optional[str]:
    """Reject a missing, failed, mismatched or non-live source capture."""
    try:
        validate_capture(capture, source_host, domain_id)
    except (ValueError, OSError) as exc:
        return str(exc)
    return None


def phase_a_steps(src_host: str, target: str, apply: bool) -> List[Dict[str, Any]]:
    """WF-A Part 1: services, groups (segments stripped), policies, rules."""
    a = ["--apply"] if apply else []
    # Every push tool reads the target on a dry run by default now, so there is
    # nothing to pass here. Kept as an empty list so the step definitions below
    # stay identical in shape to the other phases.
    d: List[str] = []
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
                 "--rules-dir", f"nsx_rules_export/{src_host}/security-policies"] + d + a},
    ]


def phase_c_steps(src_host: str, target: str, apply: bool,
                  sib: Path, strip: Path, tgt_host: str) -> List[Dict[str, Any]]:
    """WF-C: push siblings, strip the originals, amend the rules."""
    a = ["--apply"] if apply else []
    d: List[str] = []
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


def phase_d_steps(phase: str, target: str, apply: bool, sib: Path, strip: Path,
                  pure_ip: Path, tgt_host: str, csv: str) -> List[Dict[str, Any]]:
    """WF-D: exactly ONE change window per invocation.

    RUNBOOK_D's entire stance is that 2a, 2b, 3 and 5 are separately approved
    windows, spaced days or weeks apart by how much risk the operator will
    absorb at a time. Chaining them here would quietly undo that, so each is
    its own --phase and the driver refuses to run more than the one asked for.
    """
    a = ["--apply"] if apply else []
    d: List[str] = []
    if phase == "d2a":
        return [{"label": "d2a_siblings", "roots": [str(sib)],
                 "cmd": [PY, "tools/nsx/groups.py", "push", "--target", target,
                         "--groups-dir", str(sib / "groups")] + d + a}]
    if phase == "d2b":
        return [{"label": "d2b_pure_ip", "roots": [str(pure_ip)],
                 "cmd": [PY, "tools/nsx/groups.py", "push", "--target", target,
                         "--groups-dir", str(pure_ip / "groups"),
                         "--csv-remap", csv] + d + a}]
    if phase == "d3":
        return [{"label": "d3_amend_refs", "roots": [f"nsx_rules_export/{tgt_host}"],
                 "cmd": [PY, "tools/nsx/rules.py", "amend-refs", "--target", target,
                         "--sibling-map", str(sib / "sibling_map.json")] + a}]
    # d5: the only WF-D step that removes IPs from existing groups.
    return [{"label": "d5_stripped", "roots": [str(strip)],
             "cmd": [PY, "tools/nsx/groups.py", "push", "--target", target,
                     "--groups-dir", str(strip / "groups"),
                     "--intentional-ip-removal"] + d + a}]


def verify_steps(phase: str, source: str, target: str, sib: Path,
                 out_dir: Path, run_dir: Path, domain_id: str = "default") -> List[Dict[str, Any]]:
    """The read-only check that belongs to this phase.

    WF-A and WF-C are checked by verify_avs_run (source-to-target parity plus
    the sibling invariants); WF-D by validate_wf_d, which checks the contracts
    WF-D promises instead (nothing deleted, no IP lost, siblings typed right).
    """
    smap = sib / "sibling_map.json"
    if phase in ("a", "c"):
        cmd = [PY, "tools/nsx/verify_avs_run.py", "--source", source,
               "--target", target, "--report-dir", str(out_dir),
               "--domain-id", domain_id, "--source-capture",
               str(REPO_ROOT / "nsx_capture" / resolve_manager(source))]
        # A checks the clone even if a C preview already created a local map.
        # C must have a map, otherwise its sibling checks would silently skip.
        if phase == "c":
            if not smap.is_file():
                log.error("C verification requires the sibling map: %s", smap)
                return []
            cmd += ["--sibling-map", str(smap)]
        return [{"label": f"{phase}_verify", "roots": [], "cmd": cmd}]

    baselines = sorted((sib / "push_report" / "baselines").glob("*_target_baseline.json"))
    if not baselines:
        return []
    cmd = [PY, "tools/nsx/validate_wf_d.py", "--target", target,
           "--baseline", str(baselines[-1]), "--sibling-map", str(smap),
           "--output-base", str(run_dir)]
    if phase == "d5":
        # After the forced strip, IP removal on tag-side originals is the
        # intended outcome, not a contract violation.
        cmd += ["--phase-2-applied"]
    return [{"label": f"{phase}_validate", "roots": [], "cmd": cmd}]


def rollback_steps(phase: str, target: str, apply: bool, sib: Path, strip: Path,
                   pure_ip: Path, src_host: str, tgt_host: str) -> List[Dict[str, Any]]:
    """Undo one phase, in reverse dependency order.

    `--allow-delete` is passed for the bundles whose push CREATED objects
    (siblings, pure-IP). Without it those groups are left behind, listed under
    `deletes_blocked`, and the revert still exits 0, so a forgotten flag gives a
    silent half-rollback. Reverting a push that only updated existing objects
    never needs it, so it is not passed there.
    """
    a = ["--apply"] if apply else []
    def groups_revert(reports: Path, allow_delete: bool = False):
        return [PY, "tools/nsx/groups.py", "revert", "--target", target,
                "--reports-dir", str(reports)] + (["--allow-delete"] if allow_delete else []) + a
    def rules_revert(reports: str):
        return [PY, "tools/nsx/rules.py", "revert", "--target", target,
                "--reports-dir", reports] + a

    if phase == "a":
        return [
            {"label": "a4_rules_revert", "roots": [],
             "cmd": rules_revert(f"nsx_rules_export/{src_host}/push_report")},
            {"label": "a3_policies_revert", "roots": [],
             "cmd": [PY, "tools/nsx/policies.py", "revert", "--target", target,
                     "--reports-dir", f"nsx_policies_export/{src_host}/push_report"] + a},
            {"label": "a2_groups_revert", "roots": [],
             "cmd": groups_revert(Path(f"nsx_groups_export/{src_host}/push_report"),
                                  allow_delete=True)},
            {"label": "a1_services_revert", "roots": [],
             "cmd": [PY, "tools/nsx/services.py", "revert", "--target", target,
                     "--reports-dir", f"nsx_services_export/{src_host}/push_report"] + a},
        ]
    if phase == "c":
        return [
            {"label": "c5_amend_revert", "roots": [],
             "cmd": rules_revert(f"nsx_rules_export/{tgt_host}/push_report")},
            {"label": "c4_stripped_revert", "roots": [],
             "cmd": groups_revert(strip / "push_report")},
            {"label": "c3_siblings_revert", "roots": [],
             "cmd": groups_revert(sib / "push_report", allow_delete=True)},
        ]
    if phase == "d2a":
        return [{"label": "d2a_siblings_revert", "roots": [],
                 "cmd": groups_revert(sib / "push_report", allow_delete=True)}]
    if phase == "d2b":
        return [{"label": "d2b_pure_ip_revert", "roots": [],
                 "cmd": groups_revert(pure_ip / "push_report", allow_delete=True)}]
    if phase == "d3":
        return [{"label": "d3_amend_revert", "roots": [],
                 "cmd": rules_revert(f"nsx_rules_export/{tgt_host}/push_report")}]
    return [{"label": "d5_stripped_revert", "roots": [],
             "cmd": groups_revert(strip / "push_report")}]


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("WHY THIS EXISTS", 1)[1] if "WHY THIS EXISTS" in __doc__ else None)
    p.add_argument("--source", required=True, choices=NSX_MANAGER_CHOICES)
    p.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    p.add_argument("--phase", required=True,
                   choices=["a", "c", "d2a", "d2b", "d3", "d5"],
                   help="a = WF-A Part 1 clone; c = WF-C sibling decomposition; "
                        "d2a/d2b/d3/d5 = one WF-D change window each "
                        "(siblings / pure-IP remap / amend-refs / forced strip).")
    p.add_argument("--csv-remap", default=None, metavar="PATH",
                   help="CSV subnet map. Required for WF-D phases d2a (the build "
                        "maps sibling IPs through it) and d2b.")
    p.add_argument("--apply", action="store_true",
                   help="Write to the target. Default is a dry run.")
    p.add_argument("--verify", action="store_true",
                   help="Read-only check of what this phase produced, instead of "
                        "pushing. verify_avs_run for a/c, validate_wf_d for d*.")
    p.add_argument("--rollback", action="store_true",
                   help="Undo this phase, in reverse dependency order. Dry run "
                        "unless --apply is also given.")
    p.add_argument("--run-dir", default=None,
                   help="Where bundles and reports land (default: nsx_avs_runs/<src>_to_<tgt>).")
    p.add_argument("--domain-id", default="default")
    p.add_argument("--appendix", default=None,
                   help="Sibling suffix. Default: OBJECT_APPENDIX from .env for phase C, "
                        "OBJECT_APPENDIX_AVS for the WF-D phases. The two must differ: "
                        "WF-C siblings hold the SOURCE addresses and WF-D siblings hold "
                        "the CSV-REMAPPED ones, so a shared suffix would merge mapped "
                        "addresses into the source-IP siblings.")
    p.add_argument("--capture", action=argparse.BooleanOptionalAction, default=None,
                   help="WF-D only: re-capture before a dry run (default on for D). "
                        "A/C require a separate source capture and never contact the "
                        "source. --no-capture is accepted for all phases.")
    p.add_argument("--continue-on-error", action="store_true",
                   help="Keep going after a failed step (default: stop, so a broken "
                        "push does not cascade into the next dependency level).")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = __import__("time").gmtime
    init_cli()

    if args.phase in ("a", "c") and args.capture:
        log.error("A/C require a separate capture with the source credentials: "
                  "python tools/nsx/capture_nsx_state.py --source %s --live-query. "
                  "Then switch credentials to the target and run this phase.", args.source)
        return 2
    if args.capture is None:
        args.capture = args.phase.startswith("d")

    # Refuse before creating anything, so a rejected invocation leaves no
    # half-made run directory behind to be mistaken for a real run.
    if args.verify and args.rollback:
        log.error("--verify and --rollback are separate actions; run one at a time.")
        return 2
    # --csv-remap only shapes a push. Verify and rollback consume what an
    # earlier push already produced.
    if args.phase in ("d2a", "d2b") and not args.csv_remap \
            and not (args.verify or args.rollback):
        log.error("--csv-remap is required for %s: WF-D siblings carry the "
                  "MAPPED addresses, not the source ones.", args.phase)
        return 2

    if args.source == args.target:
        log.warning("source and target are the same manager (%s): this is the "
                    "supported in-place mode, but confirm that is intended.", args.source)

    # WF-D siblings carry CSV-REMAPPED addresses; WF-C siblings carry the source
    # addresses. They must land in different groups, so WF-D defaults to its own
    # suffix. Sharing one would make a WF-D push merge mapped IPs into WF-C's
    # siblings, which reads as success and quietly corrupts both sets.
    wf_c_appendix = os.environ.get("OBJECT_APPENDIX")
    if args.appendix is None and args.phase.startswith("d"):
        args.appendix = os.environ.get("OBJECT_APPENDIX_AVS")
        if not args.appendix:
            log.error("OBJECT_APPENDIX_AVS is not set. WF-D needs a suffix distinct "
                      "from OBJECT_APPENDIX (%r), because its siblings hold remapped "
                      "addresses. Set it in .env or pass --appendix.", wf_c_appendix)
            return 2
        log.info("  appendix : %s (OBJECT_APPENDIX_AVS, WF-D remapped siblings)",
                 args.appendix)
    if args.appendix and wf_c_appendix and args.appendix == wf_c_appendix \
            and args.phase.startswith("d"):
        log.error("WF-D suffix %r is the same as OBJECT_APPENDIX. The remapped "
                  "siblings would merge into the WF-C source-IP siblings.", args.appendix)
        return 2

    src_host = resolve_manager(args.source)
    tgt_host = resolve_manager(args.target)
    action = "verify" if args.verify else ("rollback" if args.rollback else "push")
    # A verify never writes, so it has one mode. A push or rollback has two.
    mode = "verify" if args.verify else ("apply" if args.apply else "dryrun")
    if args.rollback:
        mode = f"rollback_{mode}"
    started = datetime.now(timezone.utc)
    since = started.strftime("%Y-%m-%dT%H:%M:%S")

    run_dir = Path(args.run_dir) if args.run_dir else \
        REPO_ROOT / "nsx_avs_runs" / f"{args.source}_to_{args.target}"
    run_dir.mkdir(parents=True, exist_ok=True)
    log_dir = run_dir / "logs" / f"{started.strftime('%Y%m%d_%H%M%S')}_{args.phase}_{mode}"

    log.info("=" * 70)
    log.info("WORKFLOW %s  %s -> %s", args.phase.upper(), args.source, args.target)
    log.info("  action   : %s", action.upper())
    log.info("  mode     : %s", "APPLY (writes)" if args.apply and not args.verify
             else "DRY RUN (no writes)" if not args.verify else "READ-ONLY")
    log.info("  run dir  : %s", run_dir)
    log.info("=" * 70)

    sib = run_dir / "nsx_sibling_groups" / src_host
    strip = run_dir / "nsx_stripped_groups" / src_host
    pure_ip = run_dir / "nsx_pure_ip_remap" / src_host
    wf = "d" if args.phase.startswith("d") else args.phase
    out_dir = run_dir / "report" / args.phase / mode

    capture = REPO_ROOT / "nsx_capture" / src_host
    # Only WF-D can capture here. A/C run after the manual credential switch.
    if action == "push" and not args.apply and args.capture:
        rec = run_step("a0_capture", [PY, "tools/nsx/capture_nsx_state.py",
                                      "--source", args.source, "--live-query",
                                      "--domain-id", args.domain_id], log_dir)
        if not rec["ok"]:
            log.error("Capture failed; nothing pushed.")
            return 1
    if (action == "push" and not args.apply and args.capture) or \
            (args.phase in ("a", "c") and action != "rollback"):
        why = check_capture_gate(capture, src_host, args.domain_id)
        if why:
            log.error("Capture gate FAILED: %s", why)
            log.error("Capture %s with its credentials first, then switch to %s "
                      "credentials. No target steps have run.", args.source, args.target)
            return 2
        log.info("Capture gate passed (ip_source=effective, groups_errors=0).")

    if args.verify:
        steps = verify_steps(args.phase, args.source, args.target, sib, out_dir, run_dir,
                             args.domain_id)
        if not steps:
            log.error("Nothing to verify for %s: required sibling map or baseline "
                      "is missing under %s. Run the phase first.", args.phase, sib)
            return 2
    elif args.rollback:
        steps = rollback_steps(args.phase, args.target, args.apply, sib, strip,
                               pure_ip, src_host, tgt_host)
        if not args.apply:
            log.info("Rollback DRY RUN: each revert prints its plan and writes nothing.")
    elif args.phase == "a":
        steps = phase_a_steps(src_host, args.target, args.apply)
        # A consumes the flat exports emitted by the source capture. Refuse
        # before the first target command if any required bundle is missing.
        manifest = json.loads((capture / "manifest.json").read_text(encoding="utf-8"))
        if not manifest.get("options", {}).get("emit_flat_exports") or any(
                not (REPO_ROOT / step["cmd"][step["cmd"].index(flag) + 1]).is_dir()
                for step, flag in zip(steps, ("--services-dir", "--groups-dir", "--policies-dir", "--rules-dir"))):
            log.error("A requires all four flat exports from capture_nsx_state.py. "
                      "Recapture with --emit-flat-exports using the source credentials.")
            return 2
    elif args.phase in ("c", "d2a"):
        # Rebuild from the saved capture on EVERY dry run. This is offline;
        # --source identifies a local directory, not a source API connection.
        # build_sibling_groups rmtrees its own output dirs, so this leaves
        # nothing behind from a previous build. An apply never rebuilds, so it
        # pushes exactly what its dry run previewed.
        if args.apply:
            if not (sib / "sibling_map.json").exists():
                log.error("No sibling bundle at %s. Run the dry run first so the "
                          "apply pushes exactly what was previewed.", sib)
                return 2
            log.info("Using the bundle the dry run previewed: %s", sib)
        else:
            build = [PY, "tools/nsx/build_sibling_groups.py", "--source", args.source,
                     "--output-base", str(run_dir), "--domain-id", args.domain_id]
            if args.appendix:
                build += ["--appendix", args.appendix]
            if args.phase == "d2a":
                # WF-D's build: map the IPs through the CSV, never touch a group
                # carrying a PathExpression, and do not write the stripped
                # bundle (phase d5 rebuilds it deliberately, in its own window).
                build += ["--csv-remap", args.csv_remap, "--skip-segment-groups",
                          "--no-stripped-originals"]
            # Step numbers follow the runbooks: WF-C step 2, WF-D step 1.
            build_label = "c2_build_siblings" if args.phase == "c" else "d1_build_siblings"
            rec = run_step(build_label, build, log_dir)
            if not rec["ok"]:
                log.error("Sibling build failed; nothing pushed.")
                return 1
        steps = phase_c_steps(src_host, args.target, args.apply, sib, strip, tgt_host) \
            if args.phase == "c" else \
            phase_d_steps(args.phase, args.target, args.apply, sib, strip, pure_ip,
                          tgt_host, args.csv_remap)
    else:
        # d2b / d3 / d5 consume bundles an earlier window produced. Rebuilding
        # here could hand a different payload to a target whose siblings are
        # already live, so a missing bundle is an error, never a rebuild.
        needed = {"d2b": pure_ip / "groups", "d3": sib / "sibling_map.json",
                  "d5": strip / "groups"}[args.phase]
        if not needed.exists():
            log.error("%s needs %s, which does not exist. Phase d2a builds the "
                      "sibling and pure-IP bundles; d5 needs a build WITHOUT "
                      "--no-stripped-originals (RUNBOOK_D step 5a).",
                      args.phase, needed)
            return 2
        steps = phase_d_steps(args.phase, args.target, args.apply, sib, strip,
                              pure_ip, tgt_host, args.csv_remap)

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
    # to the wrong mode. Only a push produces push-report rows to aggregate:
    # verify writes its own report, and a revert writes revert summaries that
    # this aggregator does not read.
    rep = {"ok": True}
    if action == "push":
        report_cmd = [PY, "tools/nsx/report_avs_run.py", "--out-dir", str(out_dir),
                      "--since", since, "--workflow", wf,
                      "--label", f"WF-{args.phase.upper()} {mode.upper()}: "
                                 f"{args.source} to {args.target}"]
        for r in dict.fromkeys(roots):
            report_cmd += ["--report-root", r]
        rep = run_step("report", report_cmd, log_dir)

    manifest = {
        "workflow": args.phase, "action": action, "mode": mode,
        "csv_remap": args.csv_remap,
        "source": args.source, "target": args.target,
        "source_host": src_host, "target_host": tgt_host,
        "source_capture": str(capture) if args.phase in ("a", "c") else None,
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
    if action == "push":
        log.info("Report: %s", out_dir / "avs_run_report.md")
    elif action == "verify":
        log.info("Report: %s", out_dir)
    log.info("=" * 70)
    if not args.apply and not args.verify and not failed:
        log.info("%s. Re-run with --apply to write.",
                 "Rollback dry run only" if args.rollback else "Dry run only")
    return 0 if not failed and rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
