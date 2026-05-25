#!/usr/bin/env python3
"""
tools/nsx/rules.py

Single tool for the security-rules round-trip. RULES ONLY — parent policies
are handled by the separate `policies.py` tool.

Two subcommands:

  export  for every customer security-policy on the source manager, fetch
          its child rules and write one YAML per rule, grouped into the
          parent policy's folder. Read-only.

  push    read per-rule YAMLs from a directory tree (grouped by parent
          policy folder) and PUT/PATCH each rule to a target manager. Live
          per-rule progress. Dry-run by default; --apply to actually write.

Rules are children of policies (NSX URL: `.../security-policies/<pid>/rules/<rid>`),
so each rule push needs to know its parent policy id. We capture that two ways:
the parent folder name encodes the policy slug, and each rule YAML also
carries `_parent_policy_id` written by export.

Layout written by export (parallel to policies.py — same security-policies
tree, different sibling files):

  nsx_rules_export/<source-host>/
    security-policies/
      <policy-slug>/
        rules/
          0001_<rule-slug>.yaml
          0002_<rule-slug>.yaml
          ...
      ...
    manifest.json
    logs/

Order: push policies (with `policies.py`) BEFORE rules. Rules push will fail
with HTTP 404 if the parent policy doesn't exist on the target yet.

Examples:

  python tools/nsx/rules.py export --source nsx-lm1

  python tools/nsx/rules.py push \\
    --target nsx-lm2 \\
    --rules-dir nsx_rules_export/nsx-lm1.lab.local/security-policies \\
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

# Parent policies that are NSX defaults — rules under them can't be pushed.
SKIP_POLICIES = {"default-layer2-section", "default-layer3-section"}

NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]

_SAFE_ID_RE = re.compile(r'^[A-Za-z0-9._\-]+$')


def _has_special_chars(value: str) -> bool:
    return not bool(_SAFE_ID_RE.match(str(value or "")))


def _setup_logging(reports_dir: Path, label: str) -> tuple[Path, Path]:
    """Returns (bundle_log, errors_log). Errors log only captures ERROR+ lines."""
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    bundle_log = (reports_dir / f"rules_{label}_{RUN_TS}.log").resolve()
    global_log = (global_log_dir / f"rules_{label}_{RUN_TS}.log").resolve()
    errors_log = (reports_dir / f"rules_{label}_{RUN_TS}.errors.log").resolve()

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


def _slugify(name: str, max_len: int = 44) -> str:
    s = re.sub(r"[^\w\-\.]+", "_", (name or "").strip())
    s = re.sub(r"_+", "_", s).strip("_") or "unnamed"
    if len(s) <= max_len:
        return s
    h = hashlib.md5(s.encode("utf-8")).hexdigest()[:7]
    keep = max(1, max_len - len(h) - 1)
    return f"{s[:keep]}_{h}"


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


def _load_file(p: Path) -> Dict[str, Any]:
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        return yaml.safe_load(text) or {}
    return json.loads(text)


def _is_missing_dependency_error(err_msg: str) -> bool:
    """A 404 on PUT/PATCH means an object referenced inside the rule payload
    (source_groups, destination_groups, services) doesn't exist on the target
    yet. NSX surfaces this as if the URL itself was missing. Queued and retried.
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


def _capture_target_rules(client: NsxPolicyClient, domain_id: str) -> Dict[str, Dict[str, Any]]:
    """Returns {"<policy_id>::<rule_id>": {"policy_id", "rule_id", "payload"}, ...}"""
    out: Dict[str, Dict[str, Any]] = {}
    pol_path = client._policy_path(f"/domains/{client._q(domain_id)}/security-policies")
    for page in client._get_pages(pol_path):
        for p in page.get("results", []) or []:
            if _is_system_object(p):
                continue
            pid = p.get("id")
            if not pid or pid in SKIP_POLICIES:
                continue
            rules_path = client._policy_path(
                f"/domains/{client._q(domain_id)}/security-policies/{client._q(pid)}/rules"
            )
            try:
                for rp in client._get_pages(rules_path):
                    for r in rp.get("results", []) or []:
                        if _is_system_object(r):
                            continue
                        rid = r.get("id")
                        if rid:
                            out[f"{pid}::{rid}"] = {
                                "policy_id": pid, "rule_id": rid, "payload": _sanitize(r),
                            }
            except Exception as e:
                log.warning("Could not list rules under %s: %s", pid, e)
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
    output_dir = Path(args.output_dir or (REPO_ROOT / "nsx_rules_export" / source_host)).expanduser().resolve()
    if using_default and output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    policies_root = output_dir / "security-policies"
    policies_root.mkdir(parents=True, exist_ok=True)
    logs_dir = output_dir / "logs"
    log_file, errors_log = _setup_logging(logs_dir, "export")

    log.info("=" * 60)
    log.info("NSX RULES — EXPORT")
    log.info("  Source manager  : %s (%s)", args.source, source_host)
    log.info("  Domain          : %s", args.domain_id)
    log.info("  Federation GM   : %s", args.federation_global)
    log.info("  Include system  : %s", args.include_system)
    log.info("  Output bundle   : %s", output_dir)
    log.info("=" * 60)

    client = NsxPolicyClient(nsxmanager=source_host, federation_global=args.federation_global)
    policies_path = client._policy_path(f"/domains/{client._q(args.domain_id)}/security-policies")

    log.info("Fetching parent policies from %s ...", source_host)
    all_policies: List[Dict[str, Any]] = []
    for page in client._get_pages(policies_path):
        all_policies.extend(page.get("results", []) or [])
    log.info("Fetched %d policy/policies.", len(all_policies))

    rule_rows: List[Dict[str, Any]] = []
    rules_written = 0
    rules_skipped_system = 0
    policies_skipped_system = 0
    errors = 0
    special_char_ids: List[Dict[str, str]] = []

    for pi, p in enumerate(all_policies, start=1):
        pid = p.get("id")
        if not pid:
            log.warning("[POL %d/%d] policy has no id, skipping its rules", pi, len(all_policies))
            continue
        if not args.include_system and _is_system_object(p):
            policies_skipped_system += 1
            continue

        pol_slug = _short_id_filename(pid)
        rules_dir = policies_root / pol_slug / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)

        rules_path = client._policy_path(
            f"/domains/{client._q(args.domain_id)}/security-policies/{client._q(pid)}/rules"
        )
        try:
            child_rules: List[Dict[str, Any]] = []
            for page in client._get_pages(rules_path):
                child_rules.extend(page.get("results", []) or [])
        except Exception as exc:
            errors += 1
            tb = traceback.format_exc()
            log.error(
                "[POL %d/%d] FAILED listing rules for %s: %s\n%s",
                pi, len(all_policies), pid, exc, tb,
            )
            continue

        log.info("[POL %d/%d] %s — %d rule(s)", pi, len(all_policies), pid, len(child_rules))

        for ri, r in enumerate(child_rules, start=1):
            rid = r.get("id") or r.get("display_name") or f"rule_{ri}"
            rname = r.get("display_name") or rid

            if not args.include_system and _is_system_object(r):
                rules_skipped_system += 1
                continue

            if _has_special_chars(rid):
                special_char_ids.append({"id": rid, "policy_id": pid, "display_name": rname})
                log.warning("[RULE %d/policy=%s] special chars in id: %r (URL-encoded on push)",
                            ri, pid, rid)

            fname = f"{ri:04d}_{_short_id_filename(rid)}.yaml"
            rule_path = rules_dir / fname

            try:
                payload = _sanitize(r)
                # Embed parent policy id so push knows where to PUT.
                payload["_parent_policy_id"] = pid
                rule_path.write_text(
                    yaml.safe_dump(payload, sort_keys=False, default_flow_style=False),
                    encoding="utf-8",
                )
                rules_written += 1
                log.info("[RULE %d/policy=%s  ok=%d] %s", ri, pid, rules_written, rid)
                rule_rows.append({
                    "policy_id": pid, "id": rid, "display_name": rname,
                    "file": str(rule_path), "status": "ok",
                })
            except Exception as exc:
                errors += 1
                tb = traceback.format_exc()
                log.exception("[RULE %d/policy=%s] FAILED writing %s", ri, pid, rid)
                rule_rows.append({
                    "policy_id": pid, "id": rid, "display_name": rname,
                    "file": str(rule_path), "status": "failed",
                    "error": str(exc), "error_type": type(exc).__name__,
                    "traceback": tb,
                })

    manifest = {
        "command": "rules.export",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source": {"alias": args.source, "host": source_host,
                   "federation_global": args.federation_global, "domain_id": args.domain_id},
        "counts": {
            "policies_seen": len(all_policies),
            "policies_skipped_system_owned": policies_skipped_system,
            "rules_written": rules_written,
            "rules_skipped_system_owned": rules_skipped_system,
            "errors": errors,
            "ids_with_special_chars": len(special_char_ids),
        },
        "rules": rule_rows,
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
    log.info("Export complete: rules=%d  errors=%d  (sys-skipped rules=%d, policies=%d)",
             rules_written, errors, rules_skipped_system, policies_skipped_system)
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

    rules_dir = Path(args.rules_dir).expanduser().resolve()
    if not rules_dir.exists():
        raise SystemExit(f"Rules dir does not exist: {rules_dir}")

    reports_dir = Path(args.reports_dir or (rules_dir.parent / "push_report")).expanduser().resolve()
    log_file, errors_log = _setup_logging(reports_dir, "push")

    mode = "APPLY" if args.apply else "DRY-RUN"
    log.info("=" * 60)
    log.info("NSX RULES — PUSH (%s)", mode)
    log.info("  Target          : %s (%s)", args.target, target_host)
    log.info("  Domain          : %s", args.domain_id)
    log.info("  Federation GM   : %s", args.federation_global)
    log.info("  Rules dir       : %s", rules_dir)
    log.info("  Reports dir     : %s", reports_dir)
    log.info("=" * 60)

    # Walk policy folders -> rules
    policy_dirs = sorted(p for p in rules_dir.iterdir() if p.is_dir()) if rules_dir.exists() else []
    all_rule_files: List[tuple[Path, str]] = []  # (rule_file_path, parent_policy_id_from_folder)
    for pd in policy_dirs:
        # Folder slug isn't the raw policy id (it was slugified), so we rely on
        # the _parent_policy_id we wrote into each rule's YAML during export.
        rules_subdir = pd / "rules"
        for f in _iter_rule_files(rules_subdir):
            all_rule_files.append((f, pd.name))
    total = len(all_rule_files)
    log.info("Found %d rule file(s) across %d policy folder(s).", total, len(policy_dirs))

    client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global) if args.apply else None
    baseline_path = None
    if args.apply:
        log.info("Capturing target baseline (current customer rules on %s) ...", target_host)
        baseline = _capture_target_rules(client, args.domain_id)
        baseline_path = _append_baseline(reports_dir, baseline)
        log.info("  Baseline: %d rule(s) across customer policies → %s", len(baseline), baseline_path)

    rows: List[Dict[str, Any]] = []
    ok = failed = skipped = dry_run_count = 0

    for i, (rule_file, folder_slug) in enumerate(all_rule_files, start=1):
        row = {
            "index": i,
            "file": str(rule_file),
            "policy_folder": folder_slug,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            rule = _load_file(rule_file)
            policy_id = rule.pop("_parent_policy_id", None) or folder_slug  # fallback to folder name
            rule = _sanitize(rule)
            rid = rule.get("id")
            row["policy_id"] = policy_id
            row["id"] = rid
            row["display_name"] = rule.get("display_name")

            if not rid:
                row["status"] = "skipped"
                row["reason"] = "missing id"
                skipped += 1
                log.warning("[%d/%d skip] %s — no id", i, total, rule_file.name)
                rows.append(row)
                continue

            if policy_id in SKIP_POLICIES:
                row["status"] = "skipped"
                row["reason"] = "parent is built-in/default policy"
                skipped += 1
                log.info("[%d/%d skip] %s — parent %s is default", i, total, rid, policy_id)
                rows.append(row)
                continue

            if not args.apply:
                row["status"] = "dry_run"
                dry_run_count += 1
                log.info("[%d/%d  DRY  ok=%d fail=%d skip=%d] %s/%s",
                         i, total, ok, failed, skipped, policy_id, rid)
                rows.append(row)
                continue

            try:
                client.put_security_rule(
                    security_policy_id=policy_id, rule_id=rid,
                    payload=rule, domain_id=args.domain_id,
                )
                row["status"] = "success_put"
            except NsxApiError as e:
                if _is_already_exists_error(e):
                    client.patch_security_rule(
                        security_policy_id=policy_id, rule_id=rid,
                        payload=rule, domain_id=args.domain_id,
                    )
                    row["status"] = "success_patch"
                else:
                    raise

            ok += 1
            log.info("[%d/%d  ok=%d fail=%d skip=%d] %s/%s — %s",
                     i, total, ok, failed, skipped, policy_id, rid, row["status"])
            time.sleep(THROTTLE_SECONDS)

        except Exception as e:
            failed += 1
            err_msg = str(e)
            row["error"] = err_msg
            row["error_type"] = type(e).__name__
            row["traceback"] = traceback.format_exc()

            if _is_missing_dependency_error(err_msg):
                row["status"] = "failed_pending_retry"
                pending = sum(
                    1 for r in rows + [row]
                    if r.get("status") == "failed_pending_retry"
                )
                log.warning(
                    "[%d/%d  ok=%d fail=%d skip=%d] %s/%s — referenced object missing (404); PENDING RETRY (queued=%d)",
                    i, total, ok, failed, skipped,
                    row.get("policy_id") or folder_slug,
                    row.get("id") or rule_file.name, pending,
                )
            else:
                row["status"] = "failed"
                log.error(
                    "[%d/%d  ok=%d fail=%d skip=%d] %s/%s — FAILED: %s\n%s",
                    i, total, ok, failed, skipped,
                    row.get("policy_id") or folder_slug,
                    row.get("id") or rule_file.name, e, row["traceback"],
                )

        rows.append(row)

    # ------------------------------------------------------------------
    # Retry pass — rules reference groups + services that may not have
    # landed yet (or were pushed in a parallel run). Retry only
    # failed_pending_retry rows; promote leftovers to "failed".
    # ------------------------------------------------------------------
    MAX_RETRY_ROUNDS = 5
    retry_round = 0
    retry_attempts = 0
    while args.apply and retry_round < MAX_RETRY_ROUNDS:
        to_retry = [r for r in rows if r.get("status") == "failed_pending_retry"]
        if not to_retry:
            break
        retry_round += 1

        log.info("=" * 60)
        log.info("Retry round %d — %d rule(s) pending", retry_round, len(to_retry))
        log.info("=" * 60)

        progress = False
        for row in to_retry:
            retry_attempts += 1
            rid = row.get("id") or ""
            policy_id = row.get("policy_id") or ""
            try:
                rule = _load_file(Path(row["file"]))
                rule.pop("_parent_policy_id", None)
                rule = _sanitize(rule)
                try:
                    client.put_security_rule(
                        security_policy_id=policy_id, rule_id=rid,
                        payload=rule, domain_id=args.domain_id,
                    )
                    row["status"] = "success_put_retry"
                except NsxApiError as e:
                    if _is_already_exists_error(e):
                        client.patch_security_rule(
                            security_policy_id=policy_id, rule_id=rid,
                            payload=rule, domain_id=args.domain_id,
                        )
                        row["status"] = "success_patch_retry"
                    else:
                        raise
                row["retry_round"] = retry_round
                row.pop("error", None)
                row.pop("error_type", None)
                row.pop("traceback", None)
                ok += 1
                failed -= 1
                progress = True
                log.info("[retry-%d] %s/%s — %s", retry_round, policy_id, rid, row["status"])
                time.sleep(THROTTLE_SECONDS)
            except Exception as e:
                err_msg = str(e)
                row["error"] = err_msg
                row["error_type"] = type(e).__name__
                row["retry_round"] = retry_round
                if _is_missing_dependency_error(err_msg):
                    log.warning("[retry-%d] %s/%s — still pending (dep still missing)",
                                retry_round, policy_id, rid)
                else:
                    row["status"] = "failed"
                    row["traceback"] = traceback.format_exc()
                    log.error("[retry-%d] %s/%s — FAILED: %s", retry_round, policy_id, rid, err_msg)

        if not progress:
            log.warning("Retry round %d made no progress — promoting %d remaining pending row(s) to FAILED.",
                        retry_round,
                        sum(1 for r in rows if r.get("status") == "failed_pending_retry"))
            break

    for r in rows:
        if r.get("status") == "failed_pending_retry":
            r["status"] = "failed"

    summary = {
        "command": "rules.push",
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "target": {"alias": args.target, "host": target_host,
                   "federation_global": args.federation_global, "domain_id": args.domain_id},
        "rules_dir": str(rules_dir),
        "mode": mode,
        "totals": {
            "files_seen": total,
            "ok": ok,
            "failed": failed,
            "skipped": skipped,
            "dry_run": dry_run_count,
            "retry_rounds": retry_round,
            "retry_attempts": retry_attempts,
        },
        "baseline_file": str(baseline_path) if baseline_path else None,
        "log_file": str(log_file),
        "errors_log": str(errors_log),
    }

    (reports_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (reports_dir / "rules.json").write_text(json.dumps(rows, indent=2, sort_keys=True), encoding="utf-8")
    with (reports_dir / "rules.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    if failed:
        failures = [r for r in rows if r.get("status") == "failed"]
        (reports_dir / "failures.json").write_text(json.dumps(failures, indent=2, sort_keys=True), encoding="utf-8")

    log.info("=" * 60)
    log.info("Push rules %s — ok=%d failed=%d skipped=%d (dry_run=%d) total=%d",
             mode, ok, failed, skipped, dry_run_count, total)
    log.info("Reports: %s", reports_dir)
    log.info("=" * 60)

    print(json.dumps(summary, indent=2))
    return 0 if failed == 0 else 1


# =============================================================================
# revert
# =============================================================================

def cmd_revert(args: argparse.Namespace) -> int:
    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Target manager not defined: {args.target}")

    reports_dir = Path(args.reports_dir).expanduser().resolve() if args.reports_dir else None
    if reports_dir is None:
        candidates = sorted((REPO_ROOT / "nsx_rules_export").glob("*/push_report"))
        if not candidates:
            raise SystemExit("Could not auto-locate push_report. Pass --reports-dir.")
        reports_dir = candidates[-1]
    if not reports_dir.exists():
        raise SystemExit(f"Reports dir does not exist: {reports_dir}")

    log_file, errors_log = _setup_logging(reports_dir, "revert")
    log.info("=" * 60)
    log.info("NSX RULES — REVERT")
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
            "Run rules.py push --apply first, or pass --from-baseline <path>."
        )

    log.info("Using baseline: %s", baseline_path)
    baseline: Dict[str, Dict[str, Any]] = json.loads(baseline_path.read_text(encoding="utf-8"))
    log.info("  Baseline contains %d rule(s)", len(baseline))

    client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global)
    current = _capture_target_rules(client, args.domain_id)
    log.info("  Currently %d rule(s) on target", len(current))

    to_restore = [(k, v) for k, v in baseline.items()]
    to_delete = [(k, current[k]) for k in current.keys() if k not in baseline]
    log.info("Plan: restore=%d  delete=%d", len(to_restore), len(to_delete))

    if not args.apply:
        log.info("DRY-RUN — no NSX writes. Add --apply to execute.")
        for key, _ in to_restore: log.info("[DRY restore] %s", key)
        for key, _ in to_delete:  log.info("[DRY delete]  %s", key)
        return 0

    rows: List[Dict[str, Any]] = []
    restored_ok = restored_failed = deleted_ok = deleted_failed = 0

    # DELETEs first
    for i, (key, info) in enumerate(to_delete, start=1):
        pid = info["policy_id"]
        rid = info["rule_id"]
        try:
            client.delete_security_rule(security_policy_id=pid, rule_id=rid, domain_id=args.domain_id)
            deleted_ok += 1
            log.info("[DELETE %d/%d  ok=%d fail=%d] %s/%s",
                     i, len(to_delete), deleted_ok, deleted_failed, pid, rid)
            rows.append({"action": "delete", "policy_id": pid, "rule_id": rid, "status": "success"})
            time.sleep(THROTTLE_SECONDS)
        except Exception as e:
            deleted_failed += 1
            tb = traceback.format_exc()
            log.error("[DELETE %d/%d FAIL] %s/%s — %s\n%s", i, len(to_delete), pid, rid, e, tb)
            rows.append({"action": "delete", "policy_id": pid, "rule_id": rid, "status": "failed",
                         "error": str(e), "error_type": type(e).__name__, "traceback": tb})

    # RESTOREs
    for i, (key, info) in enumerate(to_restore, start=1):
        pid = info["policy_id"]
        rid = info["rule_id"]
        payload = info["payload"]
        try:
            try:
                client.put_security_rule(security_policy_id=pid, rule_id=rid,
                                         payload=payload, domain_id=args.domain_id)
                rows.append({"action": "restore", "policy_id": pid, "rule_id": rid, "status": "success_put"})
            except NsxApiError as e:
                if _is_already_exists_error(e):
                    client.patch_security_rule(security_policy_id=pid, rule_id=rid,
                                               payload=payload, domain_id=args.domain_id)
                    rows.append({"action": "restore", "policy_id": pid, "rule_id": rid, "status": "success_patch"})
                else:
                    raise
            restored_ok += 1
            log.info("[RESTORE %d/%d  ok=%d fail=%d] %s/%s",
                     i, len(to_restore), restored_ok, restored_failed, pid, rid)
            time.sleep(THROTTLE_SECONDS)
        except Exception as e:
            restored_failed += 1
            tb = traceback.format_exc()
            log.error("[RESTORE %d/%d FAIL] %s/%s — %s\n%s", i, len(to_restore), pid, rid, e, tb)
            rows.append({"action": "restore", "policy_id": pid, "rule_id": rid, "status": "failed",
                         "error": str(e), "error_type": type(e).__name__, "traceback": tb})

    _mark_baseline_reverted(baseline_path)

    summary = {
        "command": "rules.revert",
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
        description="Export NSX security rules from a source / push them to a target. Rules only.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pe = sub.add_parser("export", help="Export rules under each customer policy into per-file YAMLs (read-only).")
    pe.add_argument("--source", required=True, choices=NSX_MANAGER_CHOICES)
    pe.add_argument("--domain-id", default="default")
    pe.add_argument("--federation-global", action="store_true")
    pe.add_argument("--output-dir", default=None,
                    help="Defaults to nsx_rules_export/<source-host>/. Wiped on each run.")
    pe.add_argument("--include-system", action="store_true",
                    help="Also export system-owned policies/rules (default: skip).")
    pe.set_defaults(func=cmd_export)

    pp = sub.add_parser("push", help="Push per-file rule YAMLs to a target. Dry-run by default.")
    pp.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    pp.add_argument("--rules-dir", required=True,
                    help="Directory containing <policy-slug>/rules/*.yaml subtrees. "
                         "Typically nsx_rules_export/<host>/security-policies/")
    pp.add_argument("--domain-id", default="default")
    pp.add_argument("--federation-global", action="store_true")
    pp.add_argument("--apply", action="store_true", default=False,
                    help="Actually push. Without this, runs as dry-run.")
    pp.add_argument("--reports-dir", default=None,
                    help="Defaults to <rules-dir>/../push_report/.")
    pp.set_defaults(func=cmd_push)

    pr = sub.add_parser("revert", help="Undo the most recent push using the auto-captured baseline.")
    pr.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    pr.add_argument("--domain-id", default="default")
    pr.add_argument("--federation-global", action="store_true")
    pr.add_argument("--apply", action="store_true", default=False,
                    help="Actually revert. Without this, runs as dry-run.")
    pr.add_argument("--reports-dir", default=None,
                    help="Defaults to nsx_rules_export/<target-host>/push_report/.")
    pr.add_argument("--from-baseline", default=None,
                    help="Specific baseline file (overrides auto-selected latest).")
    pr.set_defaults(func=cmd_revert)

    args = p.parse_args()
    init_cli()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
