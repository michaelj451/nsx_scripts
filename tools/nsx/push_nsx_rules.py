#!/usr/bin/env python3
"""
tools/nsx/push_nsx_rules.py

Push UPDATED NSX policy rule files into a target NSX manager (typically GM).

Design goals for your project:
- Default is PLAN (dry-run): show what would be pushed
- COMMIT only when --commit is provided
- Only push RULES in the GM DEFAULT DOMAIN (domain=default locked)
- Ignore non-rule files (index.json, rules_order, policy.json, meta, manifests, etc.)
- Support YAML/JSON input
- Always log to ./nsx_logs/push_nsx_rules.log (+ console)
- Strip volatile/read-only keys with --strip-keys

Important:
This script pushes rule objects via NsxPolicyClient.put_security_rule().
It does NOT "publish" in the UI sense. If your environment requires manual publish,
you’ll still do that in the UI after pushing the draft/changes (as you requested).
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

import yaml

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_gm1, nsx_lm1, nsx_lm2, nsx_lm3, nsx_lm4
from nsx.nsx_policy_client import NsxPolicyClient


# ============================================================
# Defaults
# ============================================================

DEFAULT_IN_DIR_NAME = "nsx_updated_rules"
LOG_DIR_NAME = "nsx_logs"
LOG_FILE_NAME = "push_nsx_rules.log"

LOCKED_DOMAIN_ID = "default"  # per your requirement: only default domain on GM

DEFAULT_STRIP_KEYS = {
    "revision", "_revision",
    "unique_id", "realization_id",
    "marked_for_delete", "overridden",
    "create_time", "create_time_ms",
    "last_modified_time", "last_modified_time_ms",
    "create_user", "last_modified_user",
    "owner_id", "source",
    "_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
    "_system_owned", "_protection",
    "path", "relative_path", "parent_path",
}

SKIP_BASENAMES = {"_manifest.json", "meta.json", "index.json", "rules_order.json", "policy.json"}


# ============================================================
# Logging
# ============================================================

def setup_logging() -> logging.Logger:
    log_dir = Path(LOG_DIR_NAME)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / LOG_FILE_NAME

    logger = logging.getLogger("push_nsx_rules")
    logger.setLevel(logging.INFO)
    logger.propagate = False

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
# Helpers
# ============================================================

def _build_mgr_map() -> Dict[str, str]:
    return {
        "nsx-gm1": nsx_gm1,
        "nsx-lm1": nsx_lm1,
        "nsx-lm2": nsx_lm2,
        "nsx-lm3": nsx_lm3,
        "nsx-lm4": nsx_lm4,
    }


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _default_in_dir() -> Path:
    return _repo_root() / DEFAULT_IN_DIR_NAME


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


def iter_docs(root: Path):
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in {".json", ".yaml", ".yml"}:
            continue
        yield p


def strip_keys_recursive(obj: Any, strip_keys: Iterable[str]) -> Any:
    if isinstance(obj, dict):
        return {k: strip_keys_recursive(v, strip_keys) for k, v in obj.items() if k not in strip_keys}
    if isinstance(obj, list):
        return [strip_keys_recursive(x, strip_keys) for x in obj]
    return obj


@dataclass(frozen=True)
class RuleTarget:
    domain_id: str
    policy_id: str
    rule_id: str
    src: Path


def parse_rule_target(src: Path, in_root: Path, payload: dict) -> Optional[RuleTarget]:
    """
    Expect file layout:
      domains/<domain>/security-policies/<policy>/rules/<file>.yaml|json

    Domain is locked to 'default' in this project; anything else is ignored.
    rule_id is taken from payload['id'] if present, else inferred from filename.
    """
    # Skip known metadata/control files
    if src.name in SKIP_BASENAMES:
        return None

    rel = src.relative_to(in_root)
    parts = list(rel.parts)

    # Must include ".../domains/<domain>/security-policies/<policy>/rules/..."
    try:
        d_idx = parts.index("domains")
    except ValueError:
        return None

    if len(parts) < d_idx + 6:
        return None

    domain_id = parts[d_idx + 1]
    if domain_id != LOCKED_DOMAIN_ID:
        # Hard requirement: only default domain
        return None

    # Must have security-policies
    if parts[d_idx + 2] != "security-policies":
        return None

    policy_id = parts[d_idx + 3]
    if parts[d_idx + 4] != "rules":
        # We only push rule objects in this script
        return None

    rule_id = payload.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        # Infer from filename: "0001_<ruleid>.yaml" -> "<ruleid>"
        stem = src.stem
        if "_" in stem:
            rule_id = stem.split("_", 1)[1]
        else:
            rule_id = stem

    return RuleTarget(domain_id=domain_id, policy_id=policy_id, rule_id=rule_id, src=src)


def push_rule(client: NsxPolicyClient, target: RuleTarget, payload: dict) -> None:
    # Uses your client method (policy_root already set to global-infra in federation mode)
    client.put_security_rule(
        security_policy_id=target.policy_id,
        rule_id=target.rule_id,
        payload=payload,
        domain_id=target.domain_id,
        timeout=120,
    )


# ============================================================
# CLI
# ============================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Push UPDATED NSX rules into a target NSX manager (GM default domain only).")
    ap.add_argument(
        "--target",
        choices=["nsx-gm1", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        required=True,
        help="NSX manager to push rules into.",
    )
    ap.add_argument(
        "--in-dir",
        type=Path,
        default=_default_in_dir(),
        help=f"Root directory to read UPDATED rules from (default: <repo>/{DEFAULT_IN_DIR_NAME}).",
    )
    ap.add_argument("--federation-global", action="store_true", help="Use GM global-infra policy root (required for GM).")
    ap.add_argument("--strip-keys", action="store_true", help="Strip volatile/read-only keys before pushing.")
    ap.add_argument("--commit", action="store_true", help="Actually push changes (otherwise PLAN only).")
    ap.add_argument("--stop-on-error", action="store_true", help="Stop on first error.")

    args = ap.parse_args()
    init_cli()

    mgr_map = _build_mgr_map()
    dst_mgr = mgr_map.get(args.target)
    if not dst_mgr:
        raise SystemExit(f"Target manager env var not set for {args.target}. Check your .env / constants.")

    in_dir: Path = args.in_dir
    if not in_dir.exists():
        raise SystemExit(f"--in-dir not found: {in_dir}")

    client = NsxPolicyClient(nsxmanager=dst_mgr, federation_global=args.federation_global)

    mode = "COMMIT" if args.commit else "PLAN"
    log_file = (Path(LOG_DIR_NAME) / LOG_FILE_NAME).resolve()

    log.info("Starting push_nsx_rules")
    log.info("Mode:            %s", mode)
    log.info("Target:          %s", args.target)
    log.info("Federation GM:   %s", bool(args.federation_global))
    log.info("Root directory:  %s", in_dir.resolve())
    log.info("Domain:          %s (locked)", LOCKED_DOMAIN_ID)
    log.info("Strip keys:      %s", bool(args.strip_keys))
    log.info("Log file:        %s", log_file)

    planned = pushed = skipped = 0

    for src in iter_docs(in_dir):
        rel = src.relative_to(in_dir)

        # quick skip of known meta files
        if src.name in SKIP_BASENAMES:
            skipped += 1
            continue

        try:
            doc = load_doc(src)
        except Exception as e:
            skipped += 1
            log.warning("SKIP parse error: %s (%s)", rel, e)
            if args.stop_on_error:
                raise
            continue

        if not isinstance(doc, dict):
            skipped += 1
            continue

        target = parse_rule_target(src, in_dir, doc)
        if target is None:
            skipped += 1
            continue

        payload = strip_keys_recursive(doc, DEFAULT_STRIP_KEYS) if args.strip_keys else doc

        planned += 1
        log.info(
            "PLAN PUT %s (policy=%s rule=%s)",
            rel,
            target.policy_id,
            target.rule_id,
        )

        if not args.commit:
            continue

        try:
            push_rule(client, target, payload)
            pushed += 1
            log.info("OK  policy=%s rule=%s", target.policy_id, target.rule_id)
        except Exception as e:
            log.error("FAIL policy=%s rule=%s (%s)", target.policy_id, target.rule_id, e, exc_info=True)
            if args.stop_on_error:
                raise

    log.info("Finished push_nsx_rules")
    log.info("Summary: planned=%d pushed=%d skipped=%d mode=%s", planned, pushed, skipped, mode)


if __name__ == "__main__":
    main()