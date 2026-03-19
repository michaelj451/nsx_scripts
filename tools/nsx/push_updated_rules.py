#!/usr/bin/env python3
"""
tools/nsx/push_updated_rules.py

Push UPDATED Global-Manager security policies + rules from disk to NSX (UPSERT).

Key behavior:
- For each object:
    - GET it first:
        - if 404 -> PUT (create)
        - else   -> PATCH (update)
- Policies are pushed first, then rules.
- DRY-RUN by default. Use --apply to actually push.
- Uses federation_global=True so GM writes go to /global-manager/api/v1/global-infra on a GM.

Expected directory layout (matches nsx_updated_rules convention):

  nsx_updated_rules/<gm-name>/domains/<dst-domain>/<rules-domain>/security-policies/
    <policy-id>.yaml
    <policy-id>/rules/<rule-id>.yaml

Logging (matches your other tools’ style):
- Base log dir defaults to nsx_log_dir (from nsx_constants) or <repo>/nsx_logs
- DRY-RUN uses a sibling subdir under the base log dir:
    <base>/push_updated_rules_dry_run
- APPLY uses:
    <base>/

Files written (ALWAYS, even in dry-run):
- Runtime log file:
    <LOG_DIR>/push_updated_rules_YYYYMMDD_HHMMSS.log
- JSONL records (one per policy/rule processed):
    <LOG_DIR>/nsx_push_updated_rules.jsonl
- Pretty combined JSON:
    <LOG_DIR>/nsx_push_updated_rules.pretty.json
- Pretty per-object JSON:
    <LOG_DIR>/push_updated_rules_objects/<policy|rule>/<...>.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e

from nsx.nsx_policy_client import NsxPolicyClient, NsxApiError
from nsx.nsx_constants import nsx_gm1, nsx_gm2, nsx_lm1, nsx_lm2, nsx_lm3, nsx_lm4, nsx_log_dir  # env-backed values

log = logging.getLogger("push_updated_rules")

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_GM_NAME = nsx_gm1               # used for default paths, not critical
DEFAULT_DST_DOMAIN = "default"
DEFAULT_RULES_DOMAIN = "default"

DEFAULT_INPUT_ROOT = (
    REPO_ROOT
    / "nsx_updated_rules"
    / DEFAULT_GM_NAME
    / "domains"
    / DEFAULT_DST_DOMAIN
    / DEFAULT_RULES_DOMAIN
    / "security-policies"
)


# =============================================================================
# Logging helpers (same vibe as your updater script)
# =============================================================================

def _resolve_base_log_dir(log_dir_arg: Path | None) -> Path:
    """
    Base log dir:
      - if --log-dir is passed -> that
      - else nsx_log_dir (env-backed) -> that
      - else <repo>/nsx_logs
    Always mkdir.
    """
    if log_dir_arg is not None:
        raw = str(log_dir_arg)
    elif nsx_log_dir:
        raw = str(nsx_log_dir)
    else:
        raw = str(REPO_ROOT / "nsx_logs")

    expanded = os.path.expandvars(os.path.expanduser(raw))
    p = Path(expanded)
    if not p.is_absolute():
        p = (REPO_ROOT / p)
    p = p.resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _effective_log_dir(base: Path, *, dry_run: bool) -> Path:
    """
    For dry-run, use a dedicated subdir under the same base log dir.
    This matches the “previous way” you liked (same base, separate run folder).
    """
    if dry_run:
        d = (base / "push_updated_rules_dry_run").resolve()
        d.mkdir(parents=True, exist_ok=True)
        return d
    return base


def _setup_logging(tool_name: str, log_dir: Path, level: str) -> Path:
    """
    Configure console + file logging. Returns runtime log file path.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = (log_dir / f"{tool_name}_{ts}.log").resolve()

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear handlers to prevent duplicates across repeated runs in same interpreter
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, level.upper(), logging.INFO))
    ch.setFormatter(fmt)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(getattr(logging, level.upper(), logging.INFO))
    fh.setFormatter(fmt)

    root.addHandler(ch)
    root.addHandler(fh)

    logging.getLogger(tool_name).info("Logging to %s", log_file)
    return log_file


def write_json(path: Path, data: Any, *, indent: int = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=indent), encoding="utf-8")


def write_jsonl_record(fh, record: Dict[str, Any]) -> None:
    fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    fh.flush()


def safe_filename(name: str, *, max_len: int = 180) -> str:
    s = (name or "").strip()
    s = "".join(c if c.isalnum() or c in ("-", "_", ".", " ") else "_" for c in s)
    s = "_".join(s.split())
    s = s.strip("_")
    if not s:
        s = "unnamed"
    return s[:max_len]


# =============================================================================
# IO + discovery helpers
# =============================================================================

def load_doc(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        return yaml.safe_load(text)
    if path.suffix.lower() == ".json":
        return json.loads(text)
    raise ValueError(f"Unsupported file type: {path}")


def iter_files(root: Path, exts: Tuple[str, ...] = (".yaml", ".yml", ".json")) -> Iterator[Path]:
    if not root.exists():
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in exts:
            yield p


def is_policy_payload(doc: Any) -> bool:
    return isinstance(doc, dict) and doc.get("resource_type") == "SecurityPolicy"


def is_rule_payload(doc: Any) -> bool:
    return isinstance(doc, dict) and doc.get("resource_type") == "Rule"


def safe_id_from_doc(doc: Dict[str, Any], kind: str, path: Path) -> str:
    rid = doc.get("id")
    if isinstance(rid, str) and rid.strip():
        return rid
    stem = path.stem
    if stem:
        return stem
    raise ValueError(f"{kind} missing id and filename stem unusable: {path}")


# =============================================================================
# Manager resolving
# =============================================================================

def resolve_manager(manager: str) -> str:
    """
    Accepts:
      - 'gm1' -> nsx_gm1 constant
      - 'lm1' -> nsx_lm1 constant
      - FQDN like 'nsx-gm1.lab.local' -> returned as-is
    """
    m = (manager or "").strip()
    if not m:
        return nsx_gm1

    aliases = {
        "gm1": nsx_gm1,
        "gm2": nsx_gm2,
        "lm1": nsx_lm1,
        "lm2": nsx_lm2,
        "lm3": nsx_lm3,
        "lm4": nsx_lm4,
    }
    return aliases.get(m, m)


# =============================================================================
# Discovery of policies + rules
# =============================================================================

@dataclass(frozen=True)
class PolicyFile:
    policy_id: str
    file_path: Path
    payload: Dict[str, Any]


@dataclass(frozen=True)
class RuleFile:
    policy_id: str
    rule_id: str
    file_path: Path
    payload: Dict[str, Any]


def discover_policies_and_rules(input_root: Path) -> Tuple[List[PolicyFile], List[RuleFile]]:
    """
    Expects:
      input_root/
        <policy-id>.yaml
        <policy-id>/rules/<rule-id>.yaml
    """
    policies: List[PolicyFile] = []
    rules: List[RuleFile] = []

    # Policies are YAML/JSON directly under input_root (not in nested dirs)
    for p in sorted(input_root.glob("*")):
        if p.is_file() and p.suffix.lower() in (".yaml", ".yml", ".json"):
            doc = load_doc(p)
            if isinstance(doc, dict) and is_policy_payload(doc):
                pid = safe_id_from_doc(doc, "SecurityPolicy", p)
                policies.append(PolicyFile(policy_id=pid, file_path=p, payload=doc))

    # Rules are under input_root/<policy-id>/rules/
    for policy_dir in sorted(input_root.glob("*")):
        if not policy_dir.is_dir():
            continue
        rules_dir = policy_dir / "rules"
        if not rules_dir.exists():
            continue

        policy_id = policy_dir.name
        for rf in iter_files(rules_dir):
            doc = load_doc(rf)
            if isinstance(doc, dict) and is_rule_payload(doc):
                rid = safe_id_from_doc(doc, "Rule", rf)
                rules.append(RuleFile(policy_id=policy_id, rule_id=rid, file_path=rf, payload=doc))

    return policies, rules


# =============================================================================
# UPSERT helpers (used in both dry-run and apply)
# =============================================================================

def exists_security_policy(client: NsxPolicyClient, policy_id: str, domain_id: str) -> bool:
    try:
        client.get_security_policy(policy_id, domain_id=domain_id)
        return True
    except NsxApiError as e:
        if getattr(e, "status_code", None) == 404:
            return False
        raise


def exists_security_rule(client: NsxPolicyClient, policy_id: str, rule_id: str, domain_id: str) -> bool:
    try:
        client.get_security_rule(policy_id, rule_id, domain_id=domain_id)
        return True
    except NsxApiError as e:
        if getattr(e, "status_code", None) == 404:
            return False
        raise


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Push UPDATED GM security policies + rules from nsx_updated_rules (UPSERT).")

    ap.add_argument("--manager", type=str, default="gm1",
                    help="Manager alias (gm1/lm1/...) or FQDN. Default: gm1")
    ap.add_argument("--federation-global", action="store_true",
                    help="Use federation global-infra API roots (required for GM global policy pushes).")

    ap.add_argument("--gm-name", type=str, default=DEFAULT_GM_NAME,
                    help="Used only for default input-root path computation.")
    ap.add_argument("--dst-domain", type=str, default=DEFAULT_DST_DOMAIN,
                    help="Destination domain for default input-root computation (usually 'default').")
    ap.add_argument("--rules-domain", type=str, default=DEFAULT_RULES_DOMAIN,
                    help="Rules domain being pushed (prod: 'default'). This is the NSX domain_id for API paths.")

    ap.add_argument("--input-root", type=Path, default=None,
                    help=f"Directory containing security-policies tree. Default: {DEFAULT_INPUT_ROOT}")

    ap.add_argument("--apply", action="store_true", help="Actually push changes (default is dry-run).")
    ap.add_argument("--log-level", type=str, default="INFO")

    ap.add_argument("--log-dir", type=Path, default=None,
                    help="Base log directory (defaults to nsx_log_dir or <repo>/nsx_logs). Dry-run uses a dedicated subdir.")

    args = ap.parse_args()

    if not args.federation_global:
        raise SystemExit("--federation-global is required for pushing GM global rules safely.")

    dry_run = (not args.apply)

    # Logging setup
    base_log_dir = _resolve_base_log_dir(args.log_dir)
    effective_log_dir = _effective_log_dir(base_log_dir, dry_run=dry_run)
    runtime_log = _setup_logging("push_updated_rules", effective_log_dir, args.log_level)
    log.info("Runtime log:        %s", runtime_log)
    log.info("Dry-run:            %s", dry_run)
    log.info("Effective log dir:  %s", effective_log_dir)

    # Record outputs (ALWAYS written, even dry-run)
    changes_jsonl = effective_log_dir / "nsx_push_updated_rules.jsonl"
    changes_pretty = effective_log_dir / "nsx_push_updated_rules.pretty.json"
    per_obj_dir = effective_log_dir / "push_updated_rules_objects"
    per_policy_dir = per_obj_dir / "policy"
    per_rule_dir = per_obj_dir / "rule"
    per_policy_dir.mkdir(parents=True, exist_ok=True)
    per_rule_dir.mkdir(parents=True, exist_ok=True)

    # Resolve input root
    input_root = args.input_root or (
        REPO_ROOT / "nsx_updated_rules" / args.gm_name / "domains" / args.dst_domain / args.rules_domain / "security-policies"
    )

    domain_id = args.rules_domain  # domain_id in NSX API paths
    manager_fqdn = resolve_manager(args.manager)

    log.info("Manager:            %s", manager_fqdn)
    log.info("Mode:               %s", "APPLY" if args.apply else "DRY-RUN")
    log.info("Input root:         %s", input_root)
    log.info("Domain ID:          %s", domain_id)

    if not input_root.exists():
        raise SystemExit(f"Input root not found: {input_root}")

    policies, rules = discover_policies_and_rules(input_root)
    log.info("Discovered:         %d policy file(s), %d rule file(s)", len(policies), len(rules))

    client = NsxPolicyClient(manager_fqdn, federation_global=True)

    # Open JSONL (ALWAYS)
    changes_jsonl.parent.mkdir(parents=True, exist_ok=True)
    fh = changes_jsonl.open("w", encoding="utf-8")
    all_records: List[Dict[str, Any]] = []

    pushed_policies = 0
    pushed_rules = 0
    errors: List[str] = []

    # 1) Policies first
    for p in policies:
        ts = datetime.now().isoformat(timespec="seconds")
        exists = False
        action = "UNKNOWN"
        status = "ok"
        err_txt = None

        try:
            exists = exists_security_policy(client, p.policy_id, domain_id=domain_id)
            action = "PATCH" if exists else "PUT"

            msg = f"SecurityPolicy {p.policy_id} (domain={domain_id}) from {p.file_path}"
            if dry_run:
                log.info("[DRY-RUN] Would %s %s", action, msg)
            else:
                if exists:
                    client.patch_security_policy(p.policy_id, p.payload, domain_id=domain_id)
                else:
                    client.put_security_policy(p.policy_id, p.payload, domain_id=domain_id)
                log.info("%s %s", action, msg)
                pushed_policies += 1

        except (NsxApiError, Exception) as e:
            status = "error"
            err_txt = str(e)
            err = f"Failed upserting policy {p.file_path}: {e}"
            log.error(err)
            errors.append(err)

        rec = {
            "type": "policy_upsert",
            "timestamp": ts,
            "dry_run": dry_run,
            "manager": manager_fqdn,
            "domain_id": domain_id,
            "policy_id": p.policy_id,
            "file": str(p.file_path),
            "exists": exists,
            "action": action,
            "status": status,
            "error": err_txt,
        }
        all_records.append(rec)
        write_jsonl_record(fh, rec)

        # Per-policy pretty
        per_path = per_policy_dir / f"{safe_filename(p.policy_id)}.json"
        write_json(per_path, rec, indent=2)

    # 2) Rules
    for r in rules:
        ts = datetime.now().isoformat(timespec="seconds")
        exists = False
        action = "UNKNOWN"
        status = "ok"
        err_txt = None

        try:
            exists = exists_security_rule(client, r.policy_id, r.rule_id, domain_id=domain_id)
            action = "PATCH" if exists else "PUT"

            msg = f"Rule {r.rule_id} under policy {r.policy_id} (domain={domain_id}) from {r.file_path}"
            if dry_run:
                log.info("[DRY-RUN] Would %s %s", action, msg)
            else:
                if exists:
                    client.patch_security_rule(r.policy_id, r.rule_id, r.payload, domain_id=domain_id)
                else:
                    client.put_security_rule(r.policy_id, r.rule_id, r.payload, domain_id=domain_id)
                log.info("%s %s", action, msg)
                pushed_rules += 1

        except (NsxApiError, Exception) as e:
            status = "error"
            err_txt = str(e)
            err = f"Failed upserting rule {r.file_path}: {e}"
            log.error(err)
            errors.append(err)

        rec = {
            "type": "rule_upsert",
            "timestamp": ts,
            "dry_run": dry_run,
            "manager": manager_fqdn,
            "domain_id": domain_id,
            "policy_id": r.policy_id,
            "rule_id": r.rule_id,
            "file": str(r.file_path),
            "exists": exists,
            "action": action,
            "status": status,
            "error": err_txt,
        }
        all_records.append(rec)
        write_jsonl_record(fh, rec)

        # Per-rule pretty (include policy in filename to avoid collisions)
        per_path = per_rule_dir / f"{safe_filename(r.policy_id)}__{safe_filename(r.rule_id)}.json"
        write_json(per_path, rec, indent=2)

    fh.close()

    # Pretty combined JSON (ALWAYS)
    write_json(changes_pretty, all_records, indent=2)

    log.info(
        "Push complete. Mode=%s Policies=%d/%d Rules=%d/%d Errors=%d",
        "DRY-RUN" if dry_run else "APPLY",
        pushed_policies, len(policies),
        pushed_rules, len(rules),
        len(errors),
    )
    log.info("JSONL:              %s", changes_jsonl)
    log.info("Pretty combined:    %s", changes_pretty)
    log.info("Per-object records: %s", per_obj_dir)

    if errors and (not dry_run):
        raise SystemExit("One or more pushes failed. See errors above.")


if __name__ == "__main__":
    main()