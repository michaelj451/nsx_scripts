#!/usr/bin/env python3
"""
tools/vm_tags/push_hostname_tags.py

Apply the hostname-tag plan to NSX.

Reads the plan produced by build_hostname_tag_plan.py (or dryrun_hostname_tags.py),
finds VMs classified as `eligible`, and for each one:

  1. Re-fetch the VM's current tag set from NSX (defensive read so we don't
     wipe tags added since the plan was built).
  2. Append a new tag {"scope": "hostname", "tag": <trailing-digits>}.
  3. POST the FULL combined tag set back via the fabric update_tags action.

Critical behavior:
  - NEVER removes any pre-existing tag on a VM.
  - NEVER touches VMs classified as skip_* in the plan.
  - Writes a per-run manifest to nsx_vm_tags_manifests/<host>/<ts>_apply.json
    that records EXACTLY which (external_id, hostname_tag_value) pairs were
    added. revert_hostname_tags.py uses this manifest to un-do precisely
    what was done.

Dry-run is the default. Real writes require --apply.

Usage (dry-run preview):
  python tools/vm_tags/push_hostname_tags.py \\
    --manager nsx-lm1 \\
    --plan-dir vm_tags_plan/nsx-lm1.lab.local

Usage (apply):
  python tools/vm_tags/push_hostname_tags.py \\
    --manager nsx-lm1 \\
    --plan-dir vm_tags_plan/nsx-lm1.lab.local \\
    --apply
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_log_dir, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.md_utils import align_markdown_tables

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
CHECKPOINT_TOOL_TAG = "push_hostname_tags"
CHECKPOINT_SCHEMA_VERSION = 1

# Timestamp dir name pattern produced by dryrun/build-plan (matches RUN_TS).
_TS_DIR_RE = __import__("re").compile(r"^\d{8}_\d{6}$")


def resolve_plan_dir(plan_dir: Path) -> Path:
    """
    Accept either:
      - a plan dir that contains eligible.json directly (back-compat), or
      - a host-level dir whose children are timestamped subdirs — in which
        case pick the most recent timestamp.
    """
    if (plan_dir / "eligible.json").exists():
        return plan_dir
    candidates = [
        p for p in plan_dir.iterdir()
        if p.is_dir() and _TS_DIR_RE.match(p.name) and (p / "eligible.json").exists()
    ] if plan_dir.is_dir() else []
    if not candidates:
        raise SystemExit(
            f"No eligible.json found in {plan_dir} and no timestamped run "
            f"subdirs (YYYYMMDD_HHMMSS) with eligible.json inside. "
            f"Pass --plan-dir at either the host-level dir or a specific "
            f"timestamped run dir."
        )
    return sorted(candidates, key=lambda p: p.name)[-1]


# Plan-time skip buckets written by build_hostname_tag_plan.py, in report order.
# These VMs never became eligible, so the push loop never sees them; we read the
# sibling skip_*.json files so the report can show the full picture.
PLAN_SKIP_BUCKETS = [
    ("skip_excluded", "Skipped at plan time - on the hostname exclusion list (deliberately not tagged)"),
    ("skip_length_out_of_range", "Skipped at plan time - hostname length out of range (below min / above max)"),
    ("skip_invalid_name", "Skipped at plan time - no usable trailing token in name"),
    ("skip_edge", "Skipped at plan time - NSX Edge VMs (type=EDGE)"),
    ("skip_other_type", "Skipped at plan time - other / system VM types (non-REGULAR)"),
    ("skip_has_tag", "Skipped at plan time - already has a hostname tag"),
    ("skip_too_many_tags", "Skipped at plan time - at the tag cap"),
]


def load_plan_skips(plan_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Read the plan-time skip buckets that build_hostname_tag_plan.py wrote
    next to eligible.json. Only non-empty buckets are returned."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for key, _label in PLAN_SKIP_BUCKETS:
        p = plan_dir / f"{key}.json"
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows = data.get("vms") or []
        if rows:
            out[key] = rows
    return out


# Pacing between writes
TAG_UPDATE_INTERVAL_SECONDS = 0.5


def _fmt_tags(tags):
    """Compact 'scope\\|value, scope\\|value' string. Pipes escaped for
    markdown table cell safety."""
    if not tags:
        return "(none)"
    parts = []
    for t in tags:
        if isinstance(t, dict):
            parts.append(f"{t.get('scope','') or ''}\\|{t.get('tag','')}")
    return ", ".join(parts) if parts else "(none)"


def write_push_markdown(out_path: Path, manifest_doc: dict) -> Path:
    """Write a one-line-per-VM markdown alongside the JSON manifest."""
    d = manifest_doc
    mode = "APPLY" if not d.get("dry_run") else "DRY-RUN"
    lines = []
    lines.append(f"# VM Hostname Tag Push - {d.get('manager','?')} ({d.get('manager_host','?')})\n")
    lines.append(f"- **Mode**: {mode}")
    lines.append(f"- **Ran at**: {d.get('ran_at','')}")
    lines.append(f"- **Plan dir**: `{d.get('plan_dir','')}`")
    c = d.get("counts") or {}
    lines.append(f"- **Applied**: **{c.get('applied', 0)}**")
    lines.append(f"- **Skipped (already has hostname since plan)**: {c.get('skipped_already_has_hostname_post_plan', 0)}")
    lines.append(f"- **Skipped (already has exact tag)**: {c.get('skipped_already_has_exact_tag', 0)}")
    lines.append(f"- **Skipped (at tag cap)**: {c.get('skipped_too_many_tags_post_plan', 0)}")
    lines.append(f"- **Missing on target**: {c.get('missing_on_target', 0)}")
    lines.append(f"- **Errors**: {c.get('errors', 0)}")
    psc = d.get("plan_skip_counts") or {}
    if psc:
        detail = ", ".join(f"{k}={v}" for k, v in psc.items())
        lines.append(f"- **Skipped at plan time (never eligible)**: {sum(psc.values())}  ({detail})")
    if d.get("interactive_mode") is not None:
        lines.append(f"- **Interactive mode**: {d.get('interactive_mode')}  "
                     f"(batch_size started at {d.get('batch_size_initial')}, ended at {d.get('batch_size_final')})")
        if d.get("interactive_exit_requested"):
            lines.append(f"- **Operator exited early**: yes")
    lines.append("")

    entries = d.get("manifest_entries") or []
    if not entries:
        lines.append("_No VMs processed._\n")
    else:
        header_label = "VMs tagged" if mode == "APPLY" else "VMs planned to be tagged"
        lines.append(f"## {header_label} ({len(entries)})\n")
        lines.append("| # | VM | Ext ID | Added tag | Tags before | Tags after | Status |")
        lines.append("|---:|---|---|---|---:|---:|---|")
        for i, e in enumerate(entries, start=1):
            lines.append(
                f"| {i} | {e.get('display_name','')} | "
                f"`{(e.get('external_id') or '')[:12]}...` | "
                f"**`hostname\\|{e.get('added_tag','')}`** | "
                f"{e.get('tag_count_before','')} | {e.get('tag_count_after','')} | "
                f"{e.get('status','')} |"
            )
        lines.append("")

    # Also surface skipped/missing/errors from results if there's context worth showing
    results = d.get("results") or {}
    for key, label in (
        ("skipped_already_has_hostname_post_plan", "Skipped - already has hostname since plan"),
        ("skipped_already_has_exact_tag",          "Skipped - already has this exact tag"),
        ("skipped_too_many_tags_post_plan",        "Skipped - at tag cap"),
        ("missing_on_target",                       "Missing on target"),
        ("errors",                                  "Errors"),
    ):
        rows = results.get(key) or []
        if not rows:
            continue
        lines.append(f"## {label} ({len(rows)})\n")
        lines.append("| # | VM | Ext ID | Detail |")
        lines.append("|---:|---|---|---|")
        for i, r in enumerate(rows, start=1):
            if key == "errors":
                detail = r.get("error", "")
            elif key == "skipped_too_many_tags_post_plan":
                detail = f"live_tag_count={r.get('live_tag_count','?')}"
            elif key == "skipped_already_has_hostname_post_plan":
                detail = f"current_hostname_tag={r.get('current_hostname_tag','?')}"
            elif key == "skipped_already_has_exact_tag":
                detail = f"hostname_tag={r.get('hostname_tag','?')}"
            else:
                detail = ""
            lines.append(
                f"| {i} | {r.get('display_name','')} | "
                f"`{(r.get('external_id') or '')[:12]}...` | {detail} |"
            )
        lines.append("")

    # Plan-time skips: VMs that never became eligible (edge/system/invalid/
    # out-of-range/etc.), read from the plan's skip_*.json. The push loop never
    # touches these, so surface them here for a complete before/after picture.
    plan_skips = d.get("plan_skips") or {}
    for key, label in PLAN_SKIP_BUCKETS:
        rows = plan_skips.get(key) or []
        if not rows:
            continue
        lines.append(f"## {label} ({len(rows)})\n")
        lines.append("| # | VM | Type | Reason |")
        lines.append("|---:|---|---|---|")
        for i, r in enumerate(rows, start=1):
            lines.append(
                f"| {i} | {r.get('display_name','')} | "
                f"{r.get('type','')} | {r.get('reason','')} |"
            )
        lines.append("")

    out_path.write_text(align_markdown_tables("\n".join(lines)), encoding="utf-8")
    return out_path


class _InteractiveExit(Exception):
    """Signals operator chose to exit the interactive batch loop cleanly."""


def _prompt_batch_continue(applied_count: int, current_batch_size: int) -> int:
    """Prompt after a batch of applied VM tag updates. Returns the batch size
    to use for the next batch.

    Allowed responses:
      y / yes / <Enter>  -> continue at current batch size
      n / no             -> continue but RESET batch size to 1 (be conservative)
      <positive number>  -> continue at that new batch size
      x / exit / quit    -> stop processing cleanly (raise _InteractiveExit)
    """
    prompt_text = (f"Applied {applied_count} VM tag update(s). "
                   f"Continue with current batch_size={current_batch_size}? "
                   f"[Y(es) / n(o, reset to 1) / x(it) / <new size>]:")
    while True:
        # Log the prompt itself so the log file has context for the response.
        log.info("PROMPT: %s", prompt_text)
        try:
            raw = input("\n" + prompt_text + " ")
        except EOFError:
            log.warning("OPERATOR RESPONSE: <EOF> (non-interactive stdin). "
                        "Auto-approving (batch_size=%d).", current_batch_size)
            return current_batch_size

        # Log the RAW response before any parsing so typos, whitespace, and
        # empty-Enter are all captured verbatim in the audit log.
        log.info("OPERATOR RESPONSE: %r", raw)
        answer = raw.strip().lower()

        if answer in ("", "y", "yes"):
            log.info("Operator approved batch (continue at batch_size=%d) "
                     "after %d applied update(s).",
                     current_batch_size, applied_count)
            return current_batch_size

        if answer in ("n", "no"):
            log.warning("Operator chose RESET-TO-1 after %d applied update(s) "
                        "(was batch_size=%d).", applied_count, current_batch_size)
            return 1

        if answer in ("x", "exit", "quit", "q"):
            log.warning("Operator chose EXIT after %d applied update(s).",
                        applied_count)
            raise _InteractiveExit(f"Stopped by operator after {applied_count} update(s).")

        try:
            new_value = int(answer)
            if new_value <= 0:
                log.info("OPERATOR RESPONSE was non-positive (%r); re-prompting.", raw)
                print("Please enter a positive integer (e.g. 1, 5, 25).")
                continue
            log.info("Operator changed batch_size from %d to %d after %d applied update(s).",
                     current_batch_size, new_value, applied_count)
            return new_value
        except ValueError:
            log.info("OPERATOR RESPONSE was invalid (%r); re-prompting.", raw)
            print("Please enter Y / Enter, n, x, or a positive integer like 1, 5, or 25.")


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


def _build_combined_tags(
    current_tags: List[Dict[str, str]],
    new_scope: str,
    new_value: str,
) -> List[Dict[str, str]]:
    """
    Build the new tag list. If a tag with the same (scope, tag) already
    exists, the result is identical to the input (idempotent). If a
    different value with the same scope exists, we DO NOT replace it —
    we keep both. This script must never modify existing tags; the plan
    classifies those VMs as skip_has_tag and we wouldn't be here for one
    of those.

    But as a defensive read-modify-write, if NSX state changed between
    plan-build and push (someone else added a hostname tag), we'll detect
    it and refuse the operation for that VM (caller handles the flag).
    """
    combined = list(current_tags or [])
    for t in combined:
        if isinstance(t, dict) and t.get("scope") == new_scope and t.get("tag") == new_value:
            return combined  # already present, no-op
    combined.append({"scope": new_scope, "tag": new_value})
    return combined


def _has_scope(tags: List[Dict[str, str]], scope: str) -> str | None:
    for t in tags or []:
        if isinstance(t, dict) and t.get("scope") == scope:
            return t.get("tag")
    return None


def _sha256_of_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _open_checkpoint(path: Path, header: Dict[str, Any]):
    """
    Open the checkpoint file for append. Writes the header line if the file
    is new/empty. Every entry written after this MUST go through
    _checkpoint_write() so it is flushed+fsynced.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path, "a", encoding="utf-8")
    if path.stat().st_size == 0:
        rec = {"type": "header", **header}
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    return fh


def _checkpoint_write(fh, entry: Dict[str, Any]) -> None:
    """Append a single entry line, flush + fsync so it survives a hard kill."""
    fh.write(json.dumps({"type": "entry", **entry}, sort_keys=True) + "\n")
    fh.flush()
    try:
        os.fsync(fh.fileno())
    except OSError:
        pass


def _load_resume_checkpoint(
    path: Path,
    expected_manager_host: str,
    expected_plan_dir: Path,
    expected_plan_sha256: str,
    force_plan_mismatch: bool,
) -> Tuple[Set[str], Dict[str, Any]]:
    """
    Validate an existing checkpoint file and return (already_success_ext_ids, header).

    STRICT by default: refuses on manager mismatch always, and on plan_dir /
    plan_sha256 mismatch unless force_plan_mismatch=True.
    """
    if not path.exists():
        raise SystemExit(f"--resume file not found: {path}")
    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise SystemExit(f"--resume file is empty: {path}")
    try:
        header = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--resume file header is not JSON: {exc}")
    if header.get("type") != "header":
        raise SystemExit(f"--resume first line is not a header (type={header.get('type')!r})")
    if header.get("tool") != CHECKPOINT_TOOL_TAG:
        raise SystemExit(
            f"--resume file was written by tool={header.get('tool')!r}, "
            f"not {CHECKPOINT_TOOL_TAG!r}. Refusing to load."
        )
    if header.get("manager_host") != expected_manager_host:
        raise SystemExit(
            f"--resume manager mismatch: checkpoint recorded manager_host="
            f"{header.get('manager_host')!r} but this run resolves to "
            f"{expected_manager_host!r}. Refusing to proceed (never override this)."
        )
    plan_dir_ok = str(header.get("plan_dir")) == str(expected_plan_dir)
    plan_sha_ok = (
        header.get("plan_sha256") == expected_plan_sha256
        if header.get("plan_sha256") else True
    )
    if (not plan_dir_ok or not plan_sha_ok) and not force_plan_mismatch:
        raise SystemExit(
            "--resume plan mismatch:\n"
            f"  checkpoint plan_dir     = {header.get('plan_dir')!r}\n"
            f"  this run  plan_dir      = {str(expected_plan_dir)!r}\n"
            f"  checkpoint plan_sha256  = {header.get('plan_sha256')!r}\n"
            f"  this run  plan_sha256   = {expected_plan_sha256!r}\n"
            "Refusing to proceed. Pass --force-plan-mismatch ONLY if you "
            "are certain the plan content is unchanged (e.g. the plan dir "
            "was moved but its eligible.json is identical)."
        )
    if not plan_dir_ok:
        log.warning("Resume: plan_dir differs but --force-plan-mismatch is set. Proceeding.")
    if not plan_sha_ok:
        log.warning("Resume: plan_sha256 differs but --force-plan-mismatch is set. Proceeding.")

    already_success: Set[str] = set()
    for ln in lines[1:]:
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if (
            e.get("type") == "entry"
            and e.get("status") == "success"
            and e.get("external_id")
        ):
            already_success.add(e["external_id"])
    return already_success, header


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Add hostname tags to VMs per the plan. Never removes existing tags."
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        required=True,
    )
    parser.add_argument(
        "--plan-dir",
        required=True,
        help="Directory containing eligible.json from build_hostname_tag_plan.py.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually write to NSX. Default is dry-run.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help="Interactive batching: pause every N applied updates and prompt "
             "to continue (y/Enter), reset-to-1 (n), exit (x), or change to a "
             "new size (<number>). Default when --apply is set: 1 "
             "(step-through, safest). Default when dry-run: 0 (no prompts). "
             "Pass --batch-size 0 to disable prompts entirely under --apply.",
    )
    parser.add_argument(
        "--resume",
        default=None,
        help="Path to a prior *_apply.progress.jsonl checkpoint from a crashed "
             "or early-exited push. VMs already recorded as status=success in "
             "the checkpoint are skipped IF live NSX confirms the tag is "
             "present. Manager and plan (dir + sha256) must match the "
             "checkpoint (strict). See --force-plan-mismatch to override the "
             "plan check only.",
    )
    parser.add_argument(
        "--force-plan-mismatch",
        action="store_true",
        help="With --resume, allow proceeding when the plan_dir or plan "
             "content sha256 differs from the checkpoint's. Only use this "
             "when you are certain the plan content is unchanged.",
    )
    args = parser.parse_args()

    init_cli()
    log_file = setup_logging("push")

    manager_host = resolve_manager(args.manager)
    if not manager_host:
        raise SystemExit(f"Manager not defined for {args.manager}.")

    plan_dir = resolve_plan_dir(Path(args.plan_dir).expanduser().resolve())
    eligible_path = plan_dir / "eligible.json"
    if not eligible_path.exists():
        raise SystemExit(f"eligible.json not found in {plan_dir}")
    log.info("Using plan dir: %s", plan_dir)

    eligible_payload = json.loads(eligible_path.read_text(encoding="utf-8"))
    eligible = eligible_payload.get("vms") or []
    log.info("Eligible VMs from plan: %d", len(eligible))

    # Plan-time skip buckets (edge/system/invalid/out-of-range/excluded/etc.)
    # so the report shows what was NOT eligible, not just what got tagged.
    plan_skips = load_plan_skips(plan_dir)

    plan_sha256 = _sha256_of_file(eligible_path)
    log.info("Plan eligible.json sha256: %s", plan_sha256)

    dry_run_flag = not args.apply

    # Manifest/checkpoint dir - created early so the checkpoint can be
    # written incrementally starting at the first VM decision.
    manifests_dir = (
        Path(nsx_log_dir).expanduser().resolve()
        / "reports" / "vm_tags_push" / manager_host
    )
    manifests_dir.mkdir(parents=True, exist_ok=True)
    manifest_kind = "dryrun" if dry_run_flag else "apply"
    checkpoint_path = manifests_dir / f"{RUN_TS}_{manifest_kind}.progress.jsonl"

    already_success_from_resume: Set[str] = set()
    resume_header: Optional[Dict[str, Any]] = None
    if args.resume:
        resume_path = Path(args.resume).expanduser().resolve()
        already_success_from_resume, resume_header = _load_resume_checkpoint(
            resume_path,
            expected_manager_host=manager_host,
            expected_plan_dir=plan_dir,
            expected_plan_sha256=plan_sha256,
            force_plan_mismatch=args.force_plan_mismatch,
        )
        log.info(
            "RESUME: %d VM(s) already recorded as success in %s. Will "
            "verify each is still tagged in live NSX before skipping.",
            len(already_success_from_resume), resume_path,
        )

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=False)

    # Pull live VMs once so we can read current tags for read-modify-write
    log.info("Reading current VM tags from %s", manager_host)
    live = client.list_virtual_machines()
    live_by_id = {vm["external_id"]: vm for vm in live if vm.get("external_id")}

    # Read the same cap the planner used. Defensive re-check below: if a VM's
    # live tag count has crept up to the cap between plan and push, we refuse
    # the push for that VM (don't push to a VM at or above the NSX limit).
    try:
        max_tags_cap = int(os.getenv("VM_TAGS_MAX_TAGS_PER_VM", "30"))
        if max_tags_cap <= 0:
            max_tags_cap = 30
    except ValueError:
        max_tags_cap = 30

    manifest_entries: List[Dict[str, Any]] = []
    results = {
        "applied": [],
        "skipped_already_has_hostname_post_plan": [],
        "skipped_already_has_exact_tag": [],
        "skipped_too_many_tags_post_plan": [],
        "missing_on_target": [],
        "errors": [],
        "skipped_already_applied_prior_run": [],
        "checkpoint_vs_live_mismatch": [],
    }
    dry_run = dry_run_flag
    last_ts = 0.0

    checkpoint_header = {
        "tool": CHECKPOINT_TOOL_TAG,
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "manager": args.manager,
        "manager_host": manager_host,
        "plan_dir": str(plan_dir),
        "plan_sha256": plan_sha256,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "run_ts": RUN_TS,
        "dry_run": dry_run,
        "resumed_from": str(Path(args.resume).expanduser().resolve()) if args.resume else None,
        "prior_success_count_from_resume": len(already_success_from_resume),
    }
    cp_fh = _open_checkpoint(checkpoint_path, checkpoint_header)
    log.info("Checkpoint (incremental): %s", checkpoint_path)

    # Interactive batch state.
    # Defaults (mirrors groups.py pattern):
    #   --apply set AND --batch-size not specified -> resolved = 1 (step-through)
    #   dry-run  AND --batch-size not specified    -> resolved = 0 (no prompts)
    #   --batch-size N explicitly passed           -> resolved = N
    if args.batch_size is None:
        resolved_batch_size = 1 if args.apply else 0
        if resolved_batch_size == 1:
            log.info("Auto-defaulting --batch-size to 1 (step-through is safer for --apply). "
                     "Pass --batch-size 0 to disable prompts, or --batch-size N to start at N.")
    else:
        resolved_batch_size = int(args.batch_size)
    interactive_mode = args.apply and resolved_batch_size > 0
    batch_size = resolved_batch_size
    applied_in_batch = 0
    batch_summary: List[Dict[str, Any]] = []
    interactive_exit_requested = False
    if interactive_mode:
        log.info("INTERACTIVE MODE - batch_size=%d. Will prompt after every "
                 "%d applied update(s).", batch_size, batch_size)

    for plan_entry in eligible:
        ext_id = plan_entry["external_id"]
        proposed = plan_entry["proposed_hostname_tag"]
        display = plan_entry.get("display_name") or ext_id

        live_vm = live_by_id.get(ext_id)
        if live_vm is None:
            log.warning("[MISSING] VM not present on target: %s (%s)", display, ext_id)
            row = {"external_id": ext_id, "display_name": display}
            results["missing_on_target"].append(row)
            _checkpoint_write(cp_fh, {"status": "missing_on_target", **row})
            continue

        current_tags = live_vm.get("tags") or []
        current_tag_count = len(current_tags)

        # Resume-aware fast path: if this VM was recorded as success in a
        # prior crashed run, verify with LIVE NSX before skipping.
        if ext_id in already_success_from_resume:
            live_has_expected = any(
                isinstance(t, dict) and t.get("scope") == "hostname" and t.get("tag") == proposed
                for t in current_tags
            )
            if live_has_expected:
                log.info(
                    "[RESUME-SKIP] %s already tagged hostname=%s per prior run and live state confirms.",
                    display, proposed,
                )
                row = {
                    "external_id": ext_id,
                    "display_name": display,
                    "hostname_tag": proposed,
                }
                results["skipped_already_applied_prior_run"].append(row)
                _checkpoint_write(cp_fh, {"status": "skipped_already_applied_prior_run", **row})
                continue
            log.warning(
                "[CHECKPOINT-VS-LIVE MISMATCH] %s recorded success in the "
                "resume checkpoint but live NSX does NOT show hostname=%s. "
                "Skipping this VM (safest). Investigate manually before "
                "re-running without --resume.",
                display, proposed,
            )
            row = {
                "external_id": ext_id,
                "display_name": display,
                "manifest_value": proposed,
                "live_hostname_tag": _has_scope(current_tags, "hostname"),
                "current_tag_count": current_tag_count,
            }
            results["checkpoint_vs_live_mismatch"].append(row)
            _checkpoint_write(cp_fh, {"status": "checkpoint_vs_live_mismatch", **row})
            continue

        # Defensive: re-check the tag-count cap against live state in case
        # tags grew between plan-build and push.
        if current_tag_count >= max_tags_cap:
            log.warning(
                "[RACE] VM tag count reached cap since plan was built: %s now has %d tags (cap=%d). Skipping.",
                display, current_tag_count, max_tags_cap,
            )
            row = {
                "external_id": ext_id,
                "display_name": display,
                "current_tag_count": current_tag_count,
                "max_tags_cap": max_tags_cap,
                "plan_proposed_tag": proposed,
            }
            results["skipped_too_many_tags_post_plan"].append(row)
            _checkpoint_write(cp_fh, {"status": "skipped_too_many_tags_post_plan", **row})
            continue

        existing_hostname = _has_scope(current_tags, "hostname")
        if existing_hostname is not None:
            # Race: plan said no hostname tag, but one appeared between plan
            # and push. Don't touch.
            log.warning(
                "[RACE] VM acquired hostname tag since plan was built: %s now has hostname=%s. Skipping.",
                display, existing_hostname,
            )
            row = {
                "external_id": ext_id,
                "display_name": display,
                "current_hostname_tag": existing_hostname,
                "plan_proposed_tag": proposed,
            }
            results["skipped_already_has_hostname_post_plan"].append(row)
            _checkpoint_write(cp_fh, {"status": "skipped_already_has_hostname_post_plan", **row})
            continue

        # Defensive: if the exact tag exists already (re-run), idempotent no-op
        if any(
            isinstance(t, dict) and t.get("scope") == "hostname" and t.get("tag") == proposed
            for t in current_tags
        ):
            log.info("[NOOP] VM already has hostname=%s: %s", proposed, display)
            row = {"external_id": ext_id, "display_name": display, "hostname_tag": proposed}
            results["skipped_already_has_exact_tag"].append(row)
            _checkpoint_write(cp_fh, {"status": "skipped_already_has_exact_tag", **row})
            continue

        combined = _build_combined_tags(current_tags, "hostname", proposed)
        prefix = "[DRY-RUN]" if dry_run else "[APPLY]"
        log.info(
            "%s VM=%s ext_id=%s: ADD hostname=%s (tags %d -> %d)",
            prefix, display, ext_id, proposed, len(current_tags), len(combined),
        )

        manifest_entry = {
            "external_id": ext_id,
            "display_name": display,
            "added_scope": "hostname",
            "added_tag": proposed,
            "tag_count_before": len(current_tags),
            "tag_count_after": len(combined),
            "tags_before": current_tags,
            "tags_after": combined,
        }

        if dry_run:
            manifest_entry["status"] = "dry_run"
            manifest_entries.append(manifest_entry)
            _checkpoint_write(cp_fh, manifest_entry)
            continue

        # Pacing
        now = time.monotonic()
        wait = TAG_UPDATE_INTERVAL_SECONDS - (now - last_ts)
        if wait > 0:
            time.sleep(wait)

        try:
            client.update_vm_tags(ext_id, combined)
            manifest_entry["status"] = "success"
            results["applied"].append(manifest_entry)
            manifest_entries.append(manifest_entry)
            _checkpoint_write(cp_fh, manifest_entry)
            last_ts = time.monotonic()
        except Exception as exc:
            log.error("FAILED updating tags for %s (%s): %s", display, ext_id, exc)
            manifest_entry["status"] = "error"
            manifest_entry["error"] = str(exc)
            results["errors"].append(manifest_entry)
            manifest_entries.append(manifest_entry)
            _checkpoint_write(cp_fh, manifest_entry)
            last_ts = time.monotonic()

        # ---- Interactive batch boundary ----
        # Only after real applies (not skips / errors / missing / noop).
        if interactive_mode and manifest_entry.get("status") == "success":
            applied_in_batch += 1
            batch_summary.append(manifest_entry)
            if applied_in_batch >= batch_size:
                log.info("=" * 60)
                log.info("BATCH REVIEW - %d update(s) just applied:", applied_in_batch)
                for j, br in enumerate(batch_summary, start=1):
                    log.info("  [%d] %-45s hostname=%s (tags %d -> %d)",
                             j, str(br.get("display_name"))[:45],
                             br.get("added_tag"),
                             br.get("tag_count_before"),
                             br.get("tag_count_after"))
                log.info("=" * 60)
                try:
                    batch_size = _prompt_batch_continue(applied_in_batch, batch_size)
                except _InteractiveExit:
                    interactive_exit_requested = True
                    break
                applied_in_batch = 0
                batch_summary = []

    if interactive_exit_requested:
        log.warning("Interactive exit requested. Processed %d of %d eligible VM(s).",
                    len(results["applied"]), len(eligible))

    # Write manifest (manifests_dir + manifest_kind computed earlier so the
    # checkpoint lives beside it from the first VM decision, at
    # nsx_logs/reports/vm_tags_push/<host>/).
    manifest_path = manifests_dir / f"{RUN_TS}_{manifest_kind}.json"
    manifest_doc = {
        "manager": args.manager,
        "manager_host": manager_host,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "plan_dir": str(plan_dir),
        "plan_sha256": plan_sha256,
        "resumed_from": checkpoint_header.get("resumed_from"),
        "counts": {
            "applied": len(results["applied"]),
            "skipped_already_has_hostname_post_plan": len(results["skipped_already_has_hostname_post_plan"]),
            "skipped_already_has_exact_tag": len(results["skipped_already_has_exact_tag"]),
            "skipped_too_many_tags_post_plan": len(results["skipped_too_many_tags_post_plan"]),
            "missing_on_target": len(results["missing_on_target"]),
            "errors": len(results["errors"]),
            "skipped_already_applied_prior_run": len(results["skipped_already_applied_prior_run"]),
            "checkpoint_vs_live_mismatch": len(results["checkpoint_vs_live_mismatch"]),
        },
        "max_tags_cap": max_tags_cap,
        "interactive_mode": interactive_mode,
        "batch_size_initial": resolved_batch_size,
        "batch_size_final": batch_size,
        "interactive_exit_requested": interactive_exit_requested,
        "checkpoint_path": str(checkpoint_path),
        "results": results,
        "plan_skips": plan_skips,
        "plan_skip_counts": {k: len(v) for k, v in plan_skips.items()},
        "manifest_entries": manifest_entries,
    }
    manifest_path.write_text(json.dumps(manifest_doc, indent=2, sort_keys=True), encoding="utf-8")
    log.info("Manifest written: %s", manifest_path)
    md_path = manifests_dir / f"{RUN_TS}_{manifest_kind}.md"
    write_push_markdown(md_path, manifest_doc)
    log.info("Markdown report: %s", md_path)

    # Close checkpoint and rename to .done.jsonl so orphan-detection
    # (progress files without a sibling manifest) stays reliable.
    try:
        cp_fh.flush()
        os.fsync(cp_fh.fileno())
    except OSError:
        pass
    cp_fh.close()
    done_path = checkpoint_path.with_suffix(".done.jsonl")
    try:
        checkpoint_path.rename(done_path)
        log.info("Checkpoint finalized: %s", done_path)
    except OSError as exc:
        log.warning("Could not rename checkpoint to .done.jsonl (%s); leaving as-is.", exc)

    print(json.dumps(manifest_doc["counts"] | {
        "manifest": str(manifest_path),
        "markdown": str(md_path),
        "checkpoint": str(done_path if done_path.exists() else checkpoint_path),
        "dry_run": dry_run,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
