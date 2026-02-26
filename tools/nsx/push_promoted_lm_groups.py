#!/usr/bin/env python3
# tools/nsx/push_promoted_lm_groups.py

from __future__ import annotations

import argparse
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

import yaml

from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_constants import nsx_gm1, nsx_log_dir

# =============================================================================
# Paths / Defaults
# =============================================================================

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_DIR = REPO_ROOT / "nsx_promoted_groups"

# LM domains we want to push from the promoted export tree
DEFAULT_LM_DOMAINS = [
    "nsx-lm1.lab.local",
    "nsx-lm2.lab.local",
    "nsx-lm3.lab.local",
    "nsx-lm4.lab.local",
]

# =============================================================================
# Logging
# =============================================================================

def _resolve_log_dir() -> Path:
    """
    Resolve NSX_LOG_DIR from env/constant and ensure it exists.
    Supports nested vars like $ROOT_DIR/nsx_logs (but best is a literal path).
    """
    if not nsx_log_dir:
        p = REPO_ROOT / "nsx_logs"
        p.mkdir(parents=True, exist_ok=True)
        return p.resolve()

    expanded = os.path.expandvars(os.path.expanduser(str(nsx_log_dir)))
    p = Path(expanded)
    if not p.is_absolute():
        p = REPO_ROOT / p
    p = p.resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def setup_logging() -> Path:
    log_dir = _resolve_log_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = (log_dir / f"push_promoted_lm_groups_{ts}.log").resolve()
    log_file.touch(exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    root.addHandler(sh)
    root.addHandler(fh)

    logging.getLogger(__name__).info("Logging to %s", log_file)
    return log_file


log = logging.getLogger(__name__)

# =============================================================================
# Helpers
# =============================================================================

@dataclass
class Counters:
    scanned_files: int = 0
    considered_files: int = 0
    pushed: int = 0
    skipped_not_group_path: int = 0
    skipped_domain_filter: int = 0
    skipped_parse_error: int = 0
    skipped_missing_id: int = 0
    errors: int = 0


def iter_candidate_files(root: Path) -> Iterator[Path]:
    """
    Yield YAML/JSON files under root.
    """
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".yaml", ".yml", ".json"}:
            yield p


def load_doc(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        if path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(f)
        else:
            data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Document is not a dict")
    return data


def derive_domain_from_path(file_path: Path, default_domain: str) -> str:
    """
    Parse .../domains/<domain_id>/groups/<...>.yaml
    """
    parts = list(file_path.parts)
    if "domains" in parts:
        i = parts.index("domains")
        if i + 1 < len(parts):
            return parts[i + 1]
    return default_domain


def is_under_groups_dir(file_path: Path) -> bool:
    """
    Only push files that are in a ".../groups/..." directory.
    This avoids accidentally trying to push manifests, policies, etc.
    """
    return "groups" in file_path.parts


def relpath_safe(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except Exception:
        return str(p)


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Push ALL Local Manager groups from nsx_promoted_groups to GM (by domain folders)."
    )
    ap.add_argument(
        "--input-dir",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="Directory containing promoted objects (default: nsx_promoted_groups)",
    )
    ap.add_argument(
        "--domain",
        default="default",
        help="Default domain ID if not derivable from path (default: default)",
    )
    ap.add_argument(
        "--lm-domains",
        nargs="*",
        default=DEFAULT_LM_DOMAINS,
        help="Domain IDs treated as local-manager domains (default: nsx-lm1..4.lab.local)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not push, only print what would be pushed",
    )
    ap.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop immediately on first error",
    )
    args = ap.parse_args()

    log_file = setup_logging()

    input_dir: Path = args.input_dir
    if not input_dir.exists():
        raise SystemExit(f"Input directory does not exist: {input_dir}")

    # We are pushing LM groups up to GM, so target is GM with federation_global=True
    if not nsx_gm1:
        raise SystemExit("nsx_gm1 is not set (NSX_GM1). Check your .env.")
    client = NsxPolicyClient(nsx_gm1, federation_global=True)

    lm_domains = set(args.lm_domains)

    log.info("Starting push_promoted_lm_groups")
    log.info("Input dir:      %s", input_dir.resolve())
    log.info("Target GM:      %s", nsx_gm1)
    log.info("Federation GM:  %s", True)
    log.info("LM domains:     %s", sorted(lm_domains))
    log.info("Dry-run:        %s", args.dry_run)
    log.info("Log file:       %s", log_file)

    c = Counters()

    for file_path in iter_candidate_files(input_dir):
        c.scanned_files += 1

        # Only look at group files under groups/ folder
        if not is_under_groups_dir(file_path):
            c.skipped_not_group_path += 1
            continue

        c.considered_files += 1

        domain_id = derive_domain_from_path(file_path, args.domain)
        if domain_id not in lm_domains:
            c.skipped_domain_filter += 1
            continue

        try:
            doc = load_doc(file_path)
        except Exception as e:
            c.skipped_parse_error += 1
            log.warning("SKIP parse error: %s (%s)", relpath_safe(file_path), e)
            continue

        group_id = doc.get("id")
        if not group_id:
            c.skipped_missing_id += 1
            log.warning("SKIP missing id: %s", relpath_safe(file_path))
            continue

        try:
            if args.dry_run:
                log.info("[DRY-RUN] Would push group %s (domain=%s) from %s",
                         group_id, domain_id, relpath_safe(file_path))
            else:
                log.info("Pushing group %s (domain=%s) from %s",
                         group_id, domain_id, relpath_safe(file_path))
                client.put_group(group_id=group_id, payload=doc, domain_id=domain_id)

            c.pushed += 1

        except Exception as e:
            c.errors += 1
            log.error("ERROR pushing %s: %s", relpath_safe(file_path), e)
            if args.stop_on_error:
                break

    log.info("Push complete.")
    log.info("Scanned files:           %d", c.scanned_files)
    log.info("Considered group files:  %d", c.considered_files)
    log.info("Pushed groups:           %d", c.pushed)
    log.info("Skipped (not groups/):   %d", c.skipped_not_group_path)
    log.info("Skipped (domain filter): %d", c.skipped_domain_filter)
    log.info("Skipped (parse error):   %d", c.skipped_parse_error)
    log.info("Skipped (missing id):    %d", c.skipped_missing_id)
    log.info("Errors:                  %d", c.errors)
    log.info("Log file:                %s", log_file)


if __name__ == "__main__":
    main()