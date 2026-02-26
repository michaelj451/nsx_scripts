#!/usr/bin/env python3
# tools/nsx/push_groups_only.py

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterator

import yaml

from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_constants import nsx_gm1, nsx_lm1, nsx_lm2, nsx_lm3, nsx_lm4

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_DIR = REPO_ROOT / "nsx_promoted_groups"


def iter_group_files(root: Path) -> Iterator[Path]:
    for p in root.rglob("*"):
        if p.suffix.lower() in {".yaml", ".yml", ".json"}:
            yield p


def load_doc(path: Path) -> Dict[str, Any]:
    with path.open("r") as f:
        if path.suffix.lower() in {".yaml", ".yml"}:
            return yaml.safe_load(f)
        return json.load(f)


def derive_domain_and_group_id(file_path: Path, doc: Dict[str, Any], default_domain: str) -> tuple[str, str]:
    """
    Prefer IDs from the document, fall back to parsing the promoted directory structure:
      .../domains/<domain_id>/groups/<group_file>.yaml
    """
    group_id = doc.get("id") or doc.get("display_name")
    domain_id = default_domain

    parts = [x for x in file_path.parts]
    if "domains" in parts:
        i = parts.index("domains")
        if i + 1 < len(parts):
            domain_id = parts[i + 1]

    if not group_id:
        raise ValueError("Group document missing 'id' (and no display_name fallback)")

    return domain_id, group_id


def main() -> None:
    parser = argparse.ArgumentParser(description="Push ONLY NSX Groups from nsx_promoted_groups")
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR,
                        help="Directory containing promoted group files (default: nsx_promoted_groups)")
    parser.add_argument("--manager", 
                        default="gm1",
                        choices=["gm1", "lm1", "lm2", "lm3", "lm4"],
                        help="NSX manager target")
    parser.add_argument("--domain", default="default",
                        help="Default domain ID if not derivable from path (default: default)")

    # Federation behavior: you said GM must be federation_global=True
    parser.add_argument("--federation-global", action="store_true",
                        help="Force federation_global=True")
    parser.add_argument("--no-federation-global", action="store_true",
                        help="Force federation_global=False")

    parser.add_argument("--dry-run", action="store_true",
                        help="Do not push, only print what would be pushed")

    args = parser.parse_args()

    manager_map = {
        "gm1": nsx_gm1,
        "lm1": nsx_lm1,
        "lm2": nsx_lm2,
        "lm3": nsx_lm3,
        "lm4": nsx_lm4,
    }

    # Default federation_global True for GM, False otherwise (overrideable)
    if args.no_federation_global:
        federation_global = False
    elif args.federation_global:
        federation_global = True
    else:
        federation_global = (args.manager == "gm1")

    client = NsxPolicyClient(manager_map[args.manager], federation_global=federation_global)

    input_dir = args.input_dir
    if not input_dir.exists():
        raise SystemExit(f"Input directory does not exist: {input_dir}")

    total = 0
    skipped = 0
    errors = 0

    for file_path in iter_group_files(input_dir):
        try:
            doc = load_doc(file_path)

            # Only push actual group objects (cheap guardrail)
            # Typical group docs include 'expression' and 'resource_type'
            if "expression" not in doc and doc.get("resource_type") != "Group":
                # Some exports omit resource_type; expression is a good indicator for IP groups
                log.debug("Skipping non-group-ish file: %s", file_path)
                skipped += 1
                continue

            domain_id, group_id = derive_domain_and_group_id(file_path, doc, args.domain)

            if args.dry_run:
                log.info("[DRY-RUN] Would push group %s in domain %s from %s", group_id, domain_id, file_path)
            else:
                # IMPORTANT: use client.put_group so POLICY_ROOT is applied correctly
                log.info("Pushing group %s (domain=%s) from %s", group_id, domain_id, file_path)
                client.put_group(group_id=group_id, payload=doc, domain_id=domain_id)

            total += 1

        except Exception as e:
            log.error("Failed pushing %s: %s", file_path, e)
            errors += 1

    log.info("Push complete. Groups=%d Skipped=%d Errors=%d", total, skipped, errors)


if __name__ == "__main__":
    main()