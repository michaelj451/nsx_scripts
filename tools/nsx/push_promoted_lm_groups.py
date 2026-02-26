#!/usr/bin/env python3
# tools/nsx/push_promoted_lm_groups.py

from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, Tuple

import yaml

from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_constants import (
    nsx_gm1,
    nsx_lm1,
    nsx_lm2,
    nsx_lm3,
    nsx_lm4,
    nsx_log_dir,
)

log = logging.getLogger("push_promoted_lm_groups")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_DIR = REPO_ROOT / "nsx_promoted_groups"


# =============================================================================
# Logging
# =============================================================================

def _resolve_log_dir() -> Path:
    if not nsx_log_dir:
        p = (REPO_ROOT / "nsx_logs").resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    expanded = os.path.expandvars(os.path.expanduser(str(nsx_log_dir)))
    p = Path(expanded).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _setup_logging() -> Path:
    log_dir = _resolve_log_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"push_promoted_lm_groups_{ts}.log"

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)

    root.addHandler(ch)
    root.addHandler(fh)

    log.info("Logging to %s", log_file)
    return log_file


# =============================================================================
# File Helpers
# =============================================================================

def iter_group_files(root: Path) -> Iterator[Path]:
    if not root.exists():
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in {".yaml", ".yml", ".json"}:
            yield p


def load_doc(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        if path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(f)
        else:
            data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Payload is not a dict")
    return data


def is_valid_group(doc: Dict[str, Any]) -> bool:
    """
    Strict validation:
    - resource_type must be 'Group'
    - id must exist and be non-empty
    """
    return (
        isinstance(doc, dict)
        and doc.get("resource_type") == "Group"
        and isinstance(doc.get("id"), str)
        and doc["id"].strip() != ""
    )


def derive_domain_and_group_id(file_path: Path, doc: Dict[str, Any], default_domain: str) -> Tuple[str, str]:
    group_id = doc["id"]
    domain_id = default_domain

    parts = list(file_path.parts)
    if "domains" in parts:
        i = parts.index("domains")
        if i + 1 < len(parts):
            domain_id = parts[i + 1]

    return domain_id, group_id


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Push promoted LM groups into NSX")

    parser.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="Root of promoted groups directory (default: nsx_promoted_groups)",
    )

    parser.add_argument(
        "--manager",
        default="gm1",
        choices=["gm1", "lm1", "lm2", "lm3", "lm4"],
        help="Target NSX manager",
    )

    parser.add_argument(
        "--domain",
        default="default",
        help="Default domain if not derivable from path",
    )

    parser.add_argument("--federation-global", action="store_true")
    parser.add_argument("--no-federation-global", action="store_true")
    parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    _setup_logging()

    manager_map = {
        "gm1": nsx_gm1,
        "lm1": nsx_lm1,
        "lm2": nsx_lm2,
        "lm3": nsx_lm3,
        "lm4": nsx_lm4,
    }

    if args.no_federation_global:
        federation_global = False
    elif args.federation_global:
        federation_global = True
    else:
        federation_global = (args.manager == "gm1")

    target = manager_map[args.manager]
    if not target:
        raise SystemExit(f"Manager hostname not configured for {args.manager}")

    client = NsxPolicyClient(target, federation_global=federation_global)

    input_dir = args.input_dir
    if not input_dir.exists():
        raise SystemExit(f"Input directory does not exist: {input_dir}")

    log.info("Input dir:         %s", input_dir.resolve())
    log.info("Manager:           %s (%s)", args.manager, target)
    log.info("Federation global: %s", federation_global)
    log.info("Dry-run:           %s", args.dry_run)

    total = 0
    skipped = 0
    errors = 0

    for file_path in iter_group_files(input_dir):
        try:
            doc = load_doc(file_path)

            if not is_valid_group(doc):
                skipped += 1
                log.debug("Skipping non-Group file: %s", file_path)
                continue

            domain_id, group_id = derive_domain_and_group_id(file_path, doc, args.domain)

            if args.dry_run:
                log.info("[DRY-RUN] Would push group %s (domain=%s)", group_id, domain_id)
            else:
                log.info("Pushing group %s (domain=%s)", group_id, domain_id)
                client.put_group(group_id=group_id, payload=doc, domain_id=domain_id)

            total += 1

        except Exception as e:
            log.error("Failed pushing %s: %s", file_path, e)
            errors += 1

    log.info("Push complete. Groups=%d Skipped=%d Errors=%d", total, skipped, errors)


if __name__ == "__main__":
    main()