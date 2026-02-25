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
- Dry-run by default. Use --apply to actually push.
- Uses federation_global=True so GM writes go to /global-manager/api/v1/global-infra on a GM.

Expected directory layout (matches nsx_updated_rules convention):

  nsx_updated_rules/<gm-name>/domains/<dst-domain>/<rules-domain>/security-policies/
    <policy-id>.yaml
    <policy-id>/rules/<rule-id>.yaml
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e

from nsx.nsx_policy_client import NsxPolicyClient, NsxApiError
from nsx.nsx_constants import nsx_gm1, nsx_lm1, nsx_lm2, nsx_lm3, nsx_lm4  # adjust to your env

log = logging.getLogger("push_updated_rules")

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_GM_NAME = "nsx-gm1.lab.local"
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

# -----------------------------
# IO helpers
# -----------------------------

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

# -----------------------------
# Manager resolving
# -----------------------------

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
        "lm1": nsx_lm1,
        "lm2": nsx_lm2,
        "lm3": nsx_lm3,
        "lm4": nsx_lm4,
    }
    return aliases.get(m, m)

# -----------------------------
# Discovery of policies + rules
# -----------------------------

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

# -----------------------------
# UPSERT helpers
# -----------------------------

def exists_security_policy(client: NsxPolicyClient, policy_id: str, domain_id: str) -> bool:
    try:
        client.get_security_policy(policy_id, domain_id=domain_id)
        return True
    except NsxApiError as e:
        if e.status_code == 404:
            return False
        raise

def exists_security_rule(client: NsxPolicyClient, policy_id: str, rule_id: str, domain_id: str) -> bool:
    try:
        client.get_security_rule(policy_id, rule_id, domain_id=domain_id)
        return True
    except NsxApiError as e:
        if e.status_code == 404:
            return False
        raise

# -----------------------------
# Main
# -----------------------------

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

    args = ap.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(levelname)s %(message)s",
    )

    if not args.federation_global:
        raise SystemExit("--federation-global is required for pushing GM global rules safely.")

    manager_fqdn = resolve_manager(args.manager)

    input_root = args.input_root or (
        REPO_ROOT / "nsx_updated_rules" / args.gm_name / "domains" / args.dst_domain / args.rules_domain / "security-policies"
    )

    domain_id = args.rules_domain  # domain_id in NSX API paths

    log.info("Manager:    %s", manager_fqdn)
    log.info("Mode:       %s", "APPLY" if args.apply else "DRY-RUN")
    log.info("Input root: %s", input_root)
    log.info("Domain ID:  %s", domain_id)

    if not input_root.exists():
        raise SystemExit(f"Input root not found: {input_root}")

    policies, rules = discover_policies_and_rules(input_root)
    log.info("Discovered: %d policy file(s), %d rule file(s)", len(policies), len(rules))

    client = NsxPolicyClient(manager_fqdn, federation_global=True)

    pushed_policies = 0
    pushed_rules = 0
    errors: List[str] = []

    # 1) Policies first (UPSERT)
    for p in policies:
        msg = f"SecurityPolicy {p.policy_id} (domain={domain_id}) from {p.file_path}"
        if not args.apply:
            log.info("[DRY-RUN] Would upsert %s", msg)
            continue

        try:
            if exists_security_policy(client, p.policy_id, domain_id=domain_id):
                client.patch_security_policy(p.policy_id, p.payload, domain_id=domain_id)
                log.info("PATCH %s", msg)
            else:
                client.put_security_policy(p.policy_id, p.payload, domain_id=domain_id)
                log.info("PUT %s", msg)
            pushed_policies += 1
        except (NsxApiError, Exception) as e:
            err = f"Failed upserting policy {p.file_path}: {e}"
            log.error(err)
            errors.append(err)

    # 2) Rules (UPSERT)
    for r in rules:
        msg = f"Rule {r.rule_id} under policy {r.policy_id} (domain={domain_id}) from {r.file_path}"
        if not args.apply:
            log.info("[DRY-RUN] Would upsert %s", msg)
            continue

        try:
            if exists_security_rule(client, r.policy_id, r.rule_id, domain_id=domain_id):
                client.patch_security_rule(r.policy_id, r.rule_id, r.payload, domain_id=domain_id)
                log.info("PATCH %s", msg)
            else:
                client.put_security_rule(r.policy_id, r.rule_id, r.payload, domain_id=domain_id)
                log.info("PUT %s", msg)
            pushed_rules += 1
        except (NsxApiError, Exception) as e:
            err = f"Failed upserting rule {r.file_path}: {e}"
            log.error(err)
            errors.append(err)

    log.info(
        "Push complete. Policies=%d/%d Rules=%d/%d Errors=%d",
        pushed_policies, len(policies),
        pushed_rules, len(rules),
        len(errors),
    )

    if errors:
        raise SystemExit("One or more pushes failed. See errors above.")


if __name__ == "__main__":
    main()