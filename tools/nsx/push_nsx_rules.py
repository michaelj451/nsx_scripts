#!/usr/bin/env python3
"""
tools/nsx/push_nsx_rules.py

Push updated Security Policy / Rule artifacts from ./nsx_updated_rules back to NSX Global Manager.

Workflow:
- create_new_rule_files.py writes modified copies to ./nsx_updated_rules
- this script reads those files and PUTs them to GM
- supports YAML/JSON
- supports PLAN (default) vs APPLY (--apply)

Logging:
- Always logs to ./nsx_logs/push_nsx_rules.log
- Also logs to console
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e

from nsx.cli_bootstrap import init_cli
from nsx.nsx_policy_client import NsxPolicyClient


# ============================================================
# GLOBAL DEFAULTS
# ============================================================

DEFAULT_ROOT_DIR = Path("nsx_updated_rules")

LOG_DIR_NAME = "nsx_logs"
LOG_FILE_NAME = "push_nsx_rules.log"

DEFAULT_STRIP_KEYS = {
    "revision", "_revision",
    "_create_time", "_create_user",
    "_last_modified_time", "_last_modified_user",
    "create_time", "create_user",
    "last_modified_time", "last_modified_user",
    "realization_id", "unique_id",
    "marked_for_delete", "overridden",
}


# ============================================================
# Logging (always-on)
# ============================================================

def setup_logging() -> logging.Logger:
    log_dir = Path(LOG_DIR_NAME)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / LOG_FILE_NAME

    logger = logging.getLogger("push_nsx_rules")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # avoid double logging if root logger configured elsewhere

    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

        fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(fmt)

        sh = logging.StreamHandler()
        sh.setLevel(logging.INFO)
        sh.setFormatter(fmt)

        logger.addHandler(fh)
        logger.addHandler(sh)

    return logger


log = setup_logging()


# ============================================================
# Sanitization
# ============================================================

def sanitize_payload(obj: Any, strip_keys: set[str] = DEFAULT_STRIP_KEYS) -> Any:
    """Recursively remove volatile/read-only keys that can cause PUT failures or noisy diffs."""
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if k in strip_keys:
                continue
            out[k] = sanitize_payload(v, strip_keys)
        return out
    if isinstance(obj, list):
        return [sanitize_payload(x, strip_keys) for x in obj]
    return obj


# ============================================================
# IO helpers
# ============================================================

def detect_format(path: Path) -> str:
    suf = path.suffix.lower()
    if suf == ".json":
        return "json"
    if suf in {".yaml", ".yml"}:
        return "yaml"
    raise ValueError(f"Unsupported file type: {path} (expected .json/.yaml/.yml)")


def load_doc(path: Path) -> Any:
    fmt = detect_format(path)
    text = path.read_text(encoding="utf-8")
    if fmt == "json":
        return json.loads(text)
    return yaml.safe_load(text)


def iter_docs(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".json", ".yaml", ".yml"}:
            yield p


# ============================================================
# API path resolution
# ============================================================

@dataclass(frozen=True)
class ResolvedTarget:
    api_path: str
    resource_type: str
    obj_id: str


def infer_domain_from_relpath(rel: Path) -> Optional[str]:
    # expects: domains/<domain>/...
    parts = rel.parts
    if len(parts) >= 2 and parts[0] == "domains":
        return parts[1]
    return None


def resolve_api_target(rel: Path, doc: Dict[str, Any], infra_prefix: str) -> Optional[ResolvedTarget]:
    """
    Returns the API path to PUT.

    Preferred: doc['path'] if present (most reliable).
    Otherwise infer from layout and doc['id'].
    """
    p = doc.get("path")
    if isinstance(p, str) and p.startswith("/"):
        return ResolvedTarget(
            api_path=p,
            resource_type=str(doc.get("resource_type") or "unknown"),
            obj_id=str(doc.get("id") or "unknown"),
        )

    domain = infer_domain_from_relpath(rel)
    if not domain:
        return None

    obj_id = doc.get("id")
    if not isinstance(obj_id, str) or not obj_id:
        return None

    parts = rel.parts

    # SecurityPolicy file case:
    # domains/<domain>/security-policies/<file>.yaml where doc.id is the policy id
    if "security-policies" in parts and "rules" not in parts:
        api_path = f"/{infra_prefix}/domains/{domain}/security-policies/{obj_id}"
        return ResolvedTarget(api_path=api_path, resource_type=str(doc.get("resource_type") or "SecurityPolicy"), obj_id=obj_id)

    # Rule file case:
    # domains/<domain>/security-policies/<policy_id>/rules/<file>.yaml where doc.id is the rule id
    if "security-policies" in parts and "rules" in parts:
        sp_idx = parts.index("security-policies")
        if len(parts) > sp_idx + 1:
            policy_id = parts[sp_idx + 1]
            api_path = f"/{infra_prefix}/domains/{domain}/security-policies/{policy_id}/rules/{obj_id}"
            return ResolvedTarget(api_path=api_path, resource_type=str(doc.get("resource_type") or "Rule"), obj_id=obj_id)

    return None


# ============================================================
# Client PUT adapter
# ============================================================

def put_object(client: NsxPolicyClient, api_path: str, payload: Dict[str, Any]) -> None:
    """
    Uses the policy client to PUT a payload.

    If your NsxPolicyClient uses a different method name, update this function only.
    """
    client.request("PUT", api_path, json=payload)


# ============================================================
# Main
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Push updated NSX rules/policies from nsx_updated_rules to Global Manager."
    )
    parser.add_argument("--target", required=True, help="Target manager key/name (e.g. nsx-gm1).")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT_DIR, help="Root dir containing updated artifacts.")
    parser.add_argument("--apply", action="store_true", help="Actually push changes. Without this, runs in plan mode.")
    parser.add_argument("--federation-global", action="store_true", help="Use /global-infra paths (GM federation objects).")
    parser.add_argument("--strip-keys", action="store_true", help="Strip volatile/read-only keys before PUT (recommended).")
    parser.add_argument("--only", default="", help="Optional substring filter (e.g. 'security-policies').")
    args = parser.parse_args()

    init_cli()  # your standard bootstrap (env/logging defaults, etc.)

    root: Path = args.root
    if not root.exists():
        raise SystemExit(f"Root directory not found: {root}")

    infra_prefix = "global-infra" if args.federation_global else "infra"
    client = NsxPolicyClient(nsxmanager=args.target, federation_global=args.federation_global)

    mode = "APPLY" if args.apply else "PLAN"
    log.info("Starting push_nsx_rules")
    log.info("Mode:            %s", mode)
    log.info("Target:          %s", args.target)
    log.info("Federation GM:   %s", args.federation_global)
    log.info("Infra prefix:    /%s", infra_prefix)
    log.info("Root directory:  %s", root.resolve())
    log.info("Strip keys:      %s", args.strip_keys)
    log.info("Only filter:     %s", args.only or "(none)")
    log.info("Log file:        %s", (Path(LOG_DIR_NAME) / LOG_FILE_NAME).resolve())

    planned = 0
    pushed = 0
    skipped = 0

    for f in iter_docs(root):
        rel = f.relative_to(root)
        if args.only and args.only not in str(rel):
            continue

        try:
            doc_any = load_doc(f)
        except Exception as e:
            log.warning("SKIP parse error: %s (%s)", rel, e)
            skipped += 1
            continue

        if not isinstance(doc_any, dict):
            log.warning("SKIP non-dict doc: %s", rel)
            skipped += 1
            continue

        target = resolve_api_target(rel, doc_any, infra_prefix=infra_prefix)
        if not target:
            log.warning("SKIP cannot resolve API path: %s", rel)
            skipped += 1
            continue

        payload = doc_any
        if args.strip_keys:
            payload = sanitize_payload(payload)

        planned += 1
        log.info("PLAN PUT %s -> %s", rel, target.api_path)

        if not args.apply:
            continue

        try:
            put_object(client, target.api_path, payload)
            pushed += 1
            log.info("OK   %s", target.api_path)
        except Exception as e:
            log.error("FAIL %s (%s)", target.api_path, e)
            raise

    log.info("Finished push_nsx_rules")
    log.info("Summary: planned=%d pushed=%d skipped=%d mode=%s", planned, pushed, skipped, mode)


if __name__ == "__main__":
    main()