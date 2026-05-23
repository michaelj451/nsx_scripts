#!/usr/bin/env python3
"""
tools/nsx/policies.py

Single tool for the security-policies round-trip. POLICIES ONLY — child
rules are handled by the separate `rules.py` tool.

Two subcommands:

  export  read /policy/api/v1/infra/domains/<domain>/security-policies from
          a source manager and write one YAML per policy. Read-only.

  push    read per-policy YAMLs from a directory and PUT/PATCH each to a
          target manager. Live per-policy progress. Dry-run by default;
          --apply to actually write.

Policies don't carry IPs or segment refs (they reference groups by path),
so there's no strip/segment concept here. Pure 1-for-1.

Layout written by export (compatible with the existing capture format so
push can also consume a regular capture bundle's security-policies dir):

  nsx_policies_export/<source-host>/
    security-policies/
      <policy-slug>/
        policy.yaml
      ...
    manifest.json
    logs/

After policies are pushed, run `tools/nsx/rules.py push` to land the rules
that belong to those policies.

Examples:

  python tools/nsx/policies.py export --source nsx-lm1

  python tools/nsx/policies.py push \\
    --target nsx-lm2 \\
    --policies-dir nsx_policies_export/nsx-lm1.lab.local/security-policies \\
    --apply
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import shutil
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


# Char-class allowed in NSX object ids without any encoding concerns.
_SAFE_ID_RE = re.compile(r'^[A-Za-z0-9._\-]+$')


def _has_special_chars(value: str) -> bool:
    return not bool(_SAFE_ID_RE.match(str(value or "")))

import yaml

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.nsx_policy_client import NsxPolicyClient, NsxApiError


log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
THROTTLE_SECONDS = 0.2

STRIP_KEYS = {
    "_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
    "_revision", "revision", "_protection", "_system_owned",
    "marked_for_delete", "overridden", "remote_path",
    "realization_id", "unique_id", "origin_site_id", "owner_id",
    "_links", "_schema", "_self", "status", "children",
}

# NSX default policies that can't be deleted/replaced.
SKIP_POLICIES = {"default-layer2-section", "default-layer3-section"}

NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]


def _setup_logging(reports_dir: Path, label: str) -> tuple[Path, Path]:
    """Returns (bundle_log, errors_log). Errors log only captures ERROR+ lines."""
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    bundle_log = (reports_dir / f"policies_{label}_{RUN_TS}.log").resolve()
    global_log = (global_log_dir / f"policies_{label}_{RUN_TS}.log").resolve()
    errors_log = (reports_dir / f"policies_{label}_{RUN_TS}.errors.log").resolve()

    logging.Formatter.converter = time.gmtime
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%S")
    for h in (logging.StreamHandler(),
              logging.FileHandler(bundle_log, encoding="utf-8"),
              logging.FileHandler(global_log, encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    eh = logging.FileHandler(errors_log, encoding="utf-8")
    eh.setLevel(logging.ERROR)
    eh.setFormatter(fmt)
    root.addHandler(eh)
    return bundle_log, errors_log


def _is_system_object(obj: Dict[str, Any]) -> bool:
    return (
        obj.get("_system_owned") is True
        or obj.get("system_owned") is True
        or obj.get("marked_for_delete") is True
    )


def _sanitize(obj: Dict[str, Any]) -> Dict[str, Any]:
    def walk(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items() if k not in STRIP_KEYS}
        if isinstance(x, list):
            return [walk(i) for i in x]
        return x
    return walk(obj)


def _short_id_filename(nsx_id: str) -> str:
    """Deterministic, MAX_PATH-safe, collision-resistant filename stem.

    Format:
      - slug <= 10 chars:  "<slug>-<8hex>"
      - else:              "<first5>-<last5>-<8hex>"
    """
    raw = (nsx_id or "").strip() or "unnamed"
    s = re.sub(r"[^\w\-\.]+", "_", raw)
    s = re.sub(r"_+", "_", s).strip("_") or "unnamed"
    h = hashlib.md5(raw.encode("utf-8")).hexdigest()[:8]
    if len(s) <= 10:
        return f"{s}-{h}"
    return f"{s[:5]}-{s[-5:]}-{h}"


def _slugify(name: str, max_len: int = 40) -> str:
    s = re.sub(r"[^\w\-\.]+", "_", (name or "").strip())
    s = re.sub(r"_+", "_", s).strip("_") or "unnamed"
    if len(s) <= max_len:
        return s
    h = hashlib.md5(s.encode("utf-8")).hexdigest()[:7]
    keep = max(1, max_len - len(h) - 1)
    return f"{s[:keep]}_{h}"


def _load_file(p: Path) -> Dict[str, Any]:
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        return yaml.safe_load(text) or {}
    return json.loads(text)


def _is_missing_dependency_error(err_msg: str) -> bool:
    """A 404 on PUT/PATCH means an object referenced inside the payload
    (e.g. a group in `scope`) doesn't exist on the target yet. NSX surfaces
    this as if the URL itself was missing. Queued and retried.
    """
    lower = err_msg.lower()
    return (
        "404" in err_msg
        and "could not be found" in lower
        and "object identifiers are case sensitive" in lower
    )


def _is_already_exists_error(e: Exception) -> bool:
    msg = str(e)
    lower = msg.lower()
    return (
        "already exists" in lower
        or "500127" in msg
        or "cannot create an object" in lower
        or "500071" in msg
        or "precondition_failed" in lower
        or "different version" in lower
    )


def _iter_rule_files(rules_dir: Path) -> List[Path]:
    if not rules_dir.exists():
        return []
    files: List[Path] = []
    for ext in ("*.yaml", "*.yml", "*.json"):
        for p in rules_dir.rglob(ext):
            if p.name in {"manifest.json", "summary.json", "summary.txt"}:
                continue
            files.append(p)
    return sorted(files)


# =============================================================================
# Baseline stack for revert
# =============================================================================

def _baselines_dir(reports_dir: Path) -> Path:
    d = reports_dir / "baselines"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _capture_target_policies(client: NsxPolicyClient, domain_id: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    path = client._policy_path(f"/domains/{client._q(domain_id)}/security-policies")
    for page in client._get_pages(path):
        for p in page.get("results", []) or []:
            if _is_system_object(p):
                continue
            pid = p.get("id")
            if pid and pid not in SKIP_POLICIES:
                out[pid] = _sanitize(p)
    return out


def _append_baseline(reports_dir: Path, baseline: Dict[str, Dict[str, Any]]) -> Path:
    bdir = _baselines_dir(reports_dir)
    path = bdir / f"{RUN_TS}_target_baseline.json"
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _latest_unreverted_baseline(reports_dir: Path) -> Path | None:
    bdir = _baselines_dir(reports_dir)
    candidates = sorted(p for p in bdir.glob("*_target_baseline.json"))
    return candidates[-1] if candidates else None


def _mark_baseline_reverted(path: Path) -> None:
    path.rename(path.with_suffix(".json.reverted"))


# =============================================================================
# export
# =============================================================================

def cmd_export(args: argparse.Namespace) -> int:
    source_host = resolve_manager(args.source)
    if not source_host:
        raise SystemExit(f"Manager not defined for {args.source}.")

    using_default = args.output_dir is None
    output_dir = Path(args.output_dir or (REPO_ROOT / "nsx_policies_export" / source_host)).expanduser().resolve()
    if using_default and output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    policies_root = output_dir / "security-policies"
    policies_root.mkdir(parents=True, exist_ok=True)
    logs_dir = output_dir / "logs"
    log_file, errors_log = _setup_logging(logs_dir, "export")

    log.info("=" * 60)
    log.info("NSX POLICIES + RULES — EXPORT")
    log.info("  Source manager  : %s (%s)", args.source, source_host)
    log.info("  Domain          : %s", args.domain_id)
    log.info("  Federation GM   : %s", args.federation_global)
    log.info("  Include system  : %s", args.include_system)
    log.info("  Output bundle   : %s", output_dir)
    log.info("=" * 60)

    client = NsxPolicyClient(nsxmanager=source_host, federation_global=args.federation_global)
    base_path = client._policy_path(f"/domains/{client._q(args.domain_id)}/security-policies")

    log.info("Fetching policies from %s ...", source_host)
    all_policies: List[Dict[str, Any]] = []
    for page in client._get_pages(base_path):
        all_policies.extend(page.get("results", []) or [])
    log.info("Fetched %d policy/policies.", len(all_policies))

    policy_rows: List[Dict[str, Any]] = []
    policies_written = 0
    policies_skipped_system = 0
    errors = 0
    special_char_ids: List[Dict[str, str]] = []

    for pi, p in enumerate(all_policies, start=1):
        pid = p.get("id")
        pname = p.get("display_name") or pid or "policy"

        if not args.include_system and _is_system_object(p):
            policies_skipped_system += 1
            continue

        if not pid:
            log.warning("[%d/%d] skip policy with no id: display_name=%s", pi, len(all_policies), pname)
            continue

        if _has_special_chars(pid):
            special_char_ids.append({"type": "policy", "id": pid, "display_name": pname})
            log.warning("[POL %d/%d] special chars in id: %r (URL-encoded on push)",
                        pi, len(all_policies), pid)

        pol_slug = _short_id_filename(pid)
        policy_dir = policies_root / pol_slug
        policy_dir.mkdir(parents=True, exist_ok=True)
        policy_yaml = policy_dir / "policy.yaml"

        try:
            payload = _sanitize(p)
            policy_yaml.write_text(
                yaml.safe_dump(payload, sort_keys=False, default_flow_style=False),
                encoding="utf-8",
            )
            policies_written += 1
            log.info("[POL %d/%d  ok=%d] %s", pi, len(all_policies), policies_written, pid)
            policy_rows.append({"id": pid, "display_name": pname, "file": str(policy_yaml), "status": "ok"})
        except Exception as exc:
            errors += 1
            tb = traceback.format_exc()
            log.exception("[POL %d/%d] FAILED writing %s", pi, len(all_policies), pid)
            policy_rows.append({"id": pid, "display_name": pname, "file": str(policy_yaml),
                                "status": "failed", "error": str(exc),
                                "error_type": type(exc).__name__, "traceback": tb})

    manifest = {
        "command": "policies.export",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source": {"alias": args.source, "host": source_host,
                   "federation_global": args.federation_global, "domain_id": args.domain_id},
        "counts": {
            "policies_total": len(all_policies),
            "policies_written": policies_written,
            "policies_skipped_system_owned": policies_skipped_system,
            "errors": errors,
            "ids_with_special_chars": len(special_char_ids),
        },
        "policies": policy_rows,
        "ids_with_special_chars": special_char_ids,
        "paths": {
            "bundle_dir": str(output_dir),
            "policies_dir": str(policies_root),
            "logs_dir": str(logs_dir),
        },
        "log_file": str(log_file),
        "errors_log": str(errors_log),
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    log.info("=" * 60)
    log.info("Export complete: policies=%d errors=%d (sys-skipped=%d)",
             policies_written, errors, policies_skipped_system)
    log.info("Bundle:   %s", output_dir)
    log.info("Manifest: %s", manifest_path)
    log.info("=" * 60)

    print(json.dumps({"bundle": str(output_dir), "manifest": str(manifest_path),
                      "counts": manifest["counts"]}, indent=2))
    return 0 if errors == 0 else 1


# =============================================================================
# push
# =============================================================================

def cmd_push(args: argparse.Namespace) -> int:
    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Target manager not defined: {args.target}")

    policies_dir = Path(args.policies_dir).expanduser().resolve()
    if not policies_dir.exists():
        raise SystemExit(f"Policies dir does not exist: {policies_dir}")

    reports_dir = Path(args.reports_dir or (policies_dir.parent / "push_report")).expanduser().resolve()
    log_file, errors_log = _setup_logging(reports_dir, "push")

    mode = "APPLY" if args.apply else "DRY-RUN"
    log.info("=" * 60)
    log.info("NSX POLICIES + RULES — PUSH (%s)", mode)
    log.info("  Target          : %s (%s)", args.target, target_host)
    log.info("  Domain          : %s", args.domain_id)
    log.info("  Federation GM   : %s", args.federation_global)
    log.info("  Policies dir    : %s", policies_dir)
    log.info("  Reports dir     : %s", reports_dir)
    log.info("=" * 60)

    # Pre-count for live progress
    policy_dirs = sorted(p for p in policies_dir.iterdir() if p.is_dir())
    log.info("Found %d policy folder(s).", len(policy_dirs))

    client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global) if args.apply else None
    baseline_path = None
    if args.apply:
        log.info("Capturing target baseline (current customer policies on %s) ...", target_host)
        baseline = _capture_target_policies(client, args.domain_id)
        baseline_path = _append_baseline(reports_dir, baseline)
        log.info("  Baseline: %d customer policy/policies → %s", len(baseline), baseline_path)

    policy_rows: List[Dict[str, Any]] = []
    pol_ok = pol_failed = pol_skipped = pol_dry = 0

    for pi, policy_dir in enumerate(policy_dirs, start=1):
        policy_file = None
        for candidate in ("policy.yaml", "policy.yml", "policy.json"):
            p = policy_dir / candidate
            if p.exists():
                policy_file = p
                break

        if not policy_file:
            log.warning("[%d/%d  POL] %s — no policy.yaml found, skipping",
                        pi, len(policy_dirs), policy_dir.name)
            continue

        row = {
            "index": pi,
            "file": str(policy_file),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        policy_id = None
        try:
            policy = _sanitize(_load_file(policy_file))
            policy_id = policy.get("id")
            row["id"] = policy_id
            row["display_name"] = policy.get("display_name")

            if not policy_id:
                row["status"] = "skipped"
                row["reason"] = "missing id"
                pol_skipped += 1
                log.warning("[%d/%d  POL skip] %s — no id", pi, len(policy_dirs), policy_file.name)
                policy_rows.append(row)
                continue

            if policy_id in SKIP_POLICIES:
                row["status"] = "skipped"
                row["reason"] = "built-in/default policy"
                pol_skipped += 1
                log.info("[%d/%d  POL skip] %s — built-in default", pi, len(policy_dirs), policy_id)
                policy_rows.append(row)
                continue

            if not args.apply:
                row["status"] = "dry_run"
                pol_dry += 1
                log.info("[%d/%d  POL DRY  ok=%d fail=%d skip=%d] %s",
                         pi, len(policy_dirs), pol_ok, pol_failed, pol_skipped, policy_id)
                policy_rows.append(row)
            else:
                try:
                    client.put_security_policy(policy_id, policy, domain_id=args.domain_id)
                    row["status"] = "success_put"
                except NsxApiError as e:
                    if _is_already_exists_error(e):
                        client.patch_security_policy(policy_id, policy, domain_id=args.domain_id)
                        row["status"] = "success_patch"
                    else:
                        raise

                pol_ok += 1
                log.info("[%d/%d  POL ok=%d fail=%d skip=%d] %s — %s",
                         pi, len(policy_dirs), pol_ok, pol_failed, pol_skipped, policy_id, row["status"])
                time.sleep(THROTTLE_SECONDS)
                policy_rows.append(row)

        except Exception as e:
            pol_failed += 1
            err_msg = str(e)
            row["error"] = err_msg
            row["error_type"] = type(e).__name__
            row["traceback"] = traceback.format_exc()

            if _is_missing_dependency_error(err_msg):
                row["status"] = "failed_pending_retry"
                pending = sum(
                    1 for r in policy_rows + [row]
                    if r.get("status") == "failed_pending_retry"
                )
                log.warning(
                    "[%d/%d  POL ok=%d fail=%d skip=%d] %s — referenced object missing (404); PENDING RETRY (queued=%d)",
                    pi, len(policy_dirs), pol_ok, pol_failed, pol_skipped,
                    row.get("id") or policy_file.name, pending,
                )
            else:
                row["status"] = "failed"
                log.error(
                    "[%d/%d  POL ok=%d fail=%d skip=%d] %s — FAILED: %s\n%s",
                    pi, len(policy_dirs), pol_ok, pol_failed, pol_skipped,
                    row.get("id") or policy_file.name, e, row["traceback"],
                )
            policy_rows.append(row)

    # ------------------------------------------------------------------
    # Retry pass — policies reference groups in `scope`. If a group hasn't
    # landed yet, the policy PUT 404s. Retry only failed_pending_retry rows;
    # promote leftovers to "failed" if the loop can't make progress.
    # ------------------------------------------------------------------
    MAX_RETRY_ROUNDS = 5
    retry_round = 0
    retry_attempts = 0
    while args.apply and retry_round < MAX_RETRY_ROUNDS:
        to_retry = [r for r in policy_rows if r.get("status") == "failed_pending_retry"]
        if not to_retry:
            break
        retry_round += 1

        log.info("=" * 60)
        log.info("Retry round %d — %d policy/policies pending", retry_round, len(to_retry))
        log.info("=" * 60)

        progress = False
        for row in to_retry:
            retry_attempts += 1
            policy_id = row.get("id") or ""
            try:
                policy = _sanitize(_load_file(Path(row["file"])))
                try:
                    client.put_security_policy(policy_id, policy, domain_id=args.domain_id)
                    row["status"] = "success_put_retry"
                except NsxApiError as e:
                    if _is_already_exists_error(e):
                        client.patch_security_policy(policy_id, policy, domain_id=args.domain_id)
                        row["status"] = "success_patch_retry"
                    else:
                        raise
                row["retry_round"] = retry_round
                row.pop("error", None)
                row.pop("error_type", None)
                row.pop("traceback", None)
                pol_ok += 1
                pol_failed -= 1
                progress = True
                log.info("[retry-%d] %s — %s", retry_round, policy_id, row["status"])
                time.sleep(THROTTLE_SECONDS)
            except Exception as e:
                err_msg = str(e)
                row["error"] = err_msg
                row["error_type"] = type(e).__name__
                row["retry_round"] = retry_round
                if _is_missing_dependency_error(err_msg):
                    log.warning("[retry-%d] %s — still pending (dep still missing)", retry_round, policy_id)
                else:
                    row["status"] = "failed"
                    row["traceback"] = traceback.format_exc()
                    log.error("[retry-%d] %s — FAILED: %s", retry_round, policy_id, err_msg)

        if not progress:
            log.warning("Retry round %d made no progress — promoting %d remaining pending row(s) to FAILED.",
                        retry_round,
                        sum(1 for r in policy_rows if r.get("status") == "failed_pending_retry"))
            break

    for r in policy_rows:
        if r.get("status") == "failed_pending_retry":
            r["status"] = "failed"

    summary = {
        "command": "policies.push",
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "target": {"alias": args.target, "host": target_host,
                   "federation_global": args.federation_global, "domain_id": args.domain_id},
        "policies_dir": str(policies_dir),
        "mode": mode,
        "totals": {
            "policies_files_seen": len(policy_dirs),
            "ok": pol_ok,
            "failed": pol_failed,
            "skipped": pol_skipped,
            "dry_run": pol_dry,
            "retry_rounds": retry_round,
            "retry_attempts": retry_attempts,
        },
        "baseline_file": str(baseline_path) if baseline_path else None,
        "log_file": str(log_file),
        "errors_log": str(errors_log),
    }

    (reports_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (reports_dir / "policies.json").write_text(json.dumps(policy_rows, indent=2, sort_keys=True), encoding="utf-8")
    with (reports_dir / "policies.jsonl").open("w", encoding="utf-8") as fh:
        for r in policy_rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    failures = [r for r in policy_rows if r.get("status") == "failed"]
    if failures:
        (reports_dir / "failures.json").write_text(json.dumps(failures, indent=2, sort_keys=True), encoding="utf-8")

    log.info("=" * 60)
    log.info("Push policies %s — ok=%d failed=%d skipped=%d (dry_run=%d) total=%d",
             mode, pol_ok, pol_failed, pol_skipped, pol_dry, len(policy_dirs))
    log.info("Reports: %s", reports_dir)
    log.info("=" * 60)

    print(json.dumps(summary, indent=2))
    return 0 if pol_failed == 0 else 1


# =============================================================================
# revert
# =============================================================================

def cmd_revert(args: argparse.Namespace) -> int:
    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Target manager not defined: {args.target}")

    reports_dir = Path(args.reports_dir).expanduser().resolve() if args.reports_dir else None
    if reports_dir is None:
        candidates = sorted((REPO_ROOT / "nsx_policies_export").glob("*/push_report"))
        if not candidates:
            raise SystemExit("Could not auto-locate push_report. Pass --reports-dir.")
        reports_dir = candidates[-1]
    if not reports_dir.exists():
        raise SystemExit(f"Reports dir does not exist: {reports_dir}")

    log_file, errors_log = _setup_logging(reports_dir, "revert")
    log.info("=" * 60)
    log.info("NSX POLICIES — REVERT")
    log.info("  Target          : %s (%s)", args.target, target_host)
    log.info("  Domain          : %s", args.domain_id)
    log.info("  Reports dir     : %s", reports_dir)
    log.info("=" * 60)

    if args.from_baseline:
        baseline_path = Path(args.from_baseline).expanduser().resolve()
    else:
        baseline_path = _latest_unreverted_baseline(reports_dir)
    if not baseline_path or not baseline_path.exists():
        raise SystemExit(
            f"No baseline file in {reports_dir / 'baselines'}/. "
            "Run policies.py push --apply first, or pass --from-baseline <path>."
        )

    log.info("Using baseline: %s", baseline_path)
    baseline: Dict[str, Dict[str, Any]] = json.loads(baseline_path.read_text(encoding="utf-8"))
    log.info("  Baseline contains %d customer policy/policies", len(baseline))

    client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global)
    current = _capture_target_policies(client, args.domain_id)
    log.info("  Currently %d customer policy/policies on target", len(current))

    to_restore = [(pid, payload) for pid, payload in baseline.items()]
    to_delete = [pid for pid in current.keys() if pid not in baseline]
    log.info("Plan: restore=%d  delete=%d", len(to_restore), len(to_delete))

    if not args.apply:
        log.info("DRY-RUN — no NSX writes. Add --apply to execute.")
        for pid, _ in to_restore: log.info("[DRY restore] %s", pid)
        for pid in to_delete:     log.info("[DRY delete]  %s", pid)
        return 0

    rows: List[Dict[str, Any]] = []
    restored_ok = restored_failed = deleted_ok = deleted_failed = 0

    # DELETEs first (delete cascades child rules in NSX)
    for i, pid in enumerate(to_delete, start=1):
        try:
            client.delete_security_policy(pid, domain_id=args.domain_id)
            deleted_ok += 1
            log.info("[DELETE %d/%d  ok=%d fail=%d] %s",
                     i, len(to_delete), deleted_ok, deleted_failed, pid)
            rows.append({"action": "delete", "id": pid, "status": "success"})
            time.sleep(THROTTLE_SECONDS)
        except Exception as e:
            deleted_failed += 1
            tb = traceback.format_exc()
            log.error("[DELETE %d/%d FAIL] %s — %s\n%s", i, len(to_delete), pid, e, tb)
            rows.append({"action": "delete", "id": pid, "status": "failed",
                         "error": str(e), "error_type": type(e).__name__, "traceback": tb})

    # RESTOREs
    for i, (pid, payload) in enumerate(to_restore, start=1):
        try:
            try:
                client.put_security_policy(pid, payload, domain_id=args.domain_id)
                rows.append({"action": "restore", "id": pid, "status": "success_put"})
            except NsxApiError as e:
                if _is_already_exists_error(e):
                    client.patch_security_policy(pid, payload, domain_id=args.domain_id)
                    rows.append({"action": "restore", "id": pid, "status": "success_patch"})
                else:
                    raise
            restored_ok += 1
            log.info("[RESTORE %d/%d  ok=%d fail=%d] %s",
                     i, len(to_restore), restored_ok, restored_failed, pid)
            time.sleep(THROTTLE_SECONDS)
        except Exception as e:
            restored_failed += 1
            tb = traceback.format_exc()
            log.error("[RESTORE %d/%d FAIL] %s — %s\n%s", i, len(to_restore), pid, e, tb)
            rows.append({"action": "restore", "id": pid, "status": "failed",
                         "error": str(e), "error_type": type(e).__name__, "traceback": tb})

    _mark_baseline_reverted(baseline_path)

    summary = {
        "command": "policies.revert",
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "target": {"alias": args.target, "host": target_host,
                   "federation_global": args.federation_global, "domain_id": args.domain_id},
        "baseline_file": str(baseline_path) + ".reverted",
        "totals": {
            "restored_ok": restored_ok, "restored_failed": restored_failed,
            "deleted_ok": deleted_ok, "deleted_failed": deleted_failed,
        },
        "log_file": str(log_file),
        "errors_log": str(errors_log),
    }
    revert_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    (reports_dir / f"revert_summary_{revert_ts}.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (reports_dir / f"revert_actions_{revert_ts}.jsonl").write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n", encoding="utf-8")

    log.info("=" * 60)
    log.info("Revert complete — restored ok=%d/%d  deleted ok=%d/%d",
             restored_ok, len(to_restore), deleted_ok, len(to_delete))
    log.info("=" * 60)

    print(json.dumps(summary, indent=2))
    return 0 if (restored_failed == 0 and deleted_failed == 0) else 1


# =============================================================================
# CLI dispatch
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(
        description="Export NSX security policies + rules from a source / push them to a target. Two subcommands.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pe = sub.add_parser("export", help="Export policies + child rules into per-file YAMLs (read-only).")
    pe.add_argument("--source", required=True, choices=NSX_MANAGER_CHOICES)
    pe.add_argument("--domain-id", default="default")
    pe.add_argument("--federation-global", action="store_true")
    pe.add_argument("--output-dir", default=None,
                    help="Defaults to nsx_policies_export/<source-host>/. Wiped on each run.")
    pe.add_argument("--include-system", action="store_true",
                    help="Also export system-owned policies/rules (default: skip).")
    pe.set_defaults(func=cmd_export)

    pp = sub.add_parser("push", help="Push per-file policies + rules to a target. Dry-run by default.")
    pp.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    pp.add_argument("--policies-dir", required=True,
                    help="Directory containing <policy-slug>/policy.yaml + rules/*.yaml subtrees.")
    pp.add_argument("--domain-id", default="default")
    pp.add_argument("--federation-global", action="store_true")
    pp.add_argument("--apply", action="store_true", default=False,
                    help="Actually push. Without this, runs as dry-run.")
    pp.add_argument("--reports-dir", default=None,
                    help="Defaults to <policies-dir>/../push_report/.")
    pp.set_defaults(func=cmd_push)

    pr = sub.add_parser("revert", help="Undo the most recent push using the auto-captured baseline.")
    pr.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    pr.add_argument("--domain-id", default="default")
    pr.add_argument("--federation-global", action="store_true")
    pr.add_argument("--apply", action="store_true", default=False,
                    help="Actually revert. Without this, runs as dry-run.")
    pr.add_argument("--reports-dir", default=None,
                    help="Defaults to nsx_policies_export/<target-host>/push_report/.")
    pr.add_argument("--from-baseline", default=None,
                    help="Specific baseline file (overrides auto-selected latest).")
    pr.set_defaults(func=cmd_revert)

    args = p.parse_args()
    init_cli()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
