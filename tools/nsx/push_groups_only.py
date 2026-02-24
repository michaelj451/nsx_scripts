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
    for path in root.rglob("*"):
        if path.suffix.lower() in {".yaml", ".yml", ".json"}:
            yield path


def load_doc(path: Path) -> Dict[str, Any]:
    with path.open("r") as f:
        if path.suffix.lower() in {".yaml", ".yml"}:
            return yaml.safe_load(f)
        return json.load(f)


def client_put(client: NsxPolicyClient, path: str, payload: Dict[str, Any]) -> None:
    """
    Support different client implementations:
      - client.put(path, payload)
      - client._put(path, payload)   (positional; no json=)
    """
    if hasattr(client, "put") and callable(getattr(client, "put")):
        client.put(path, payload)
        return

    if hasattr(client, "_put") and callable(getattr(client, "_put")):
        client._put(path, payload)  # IMPORTANT: no json= keyword
        return

    raise AttributeError("NsxPolicyClient has neither put() nor _put()")


def push_group(client: NsxPolicyClient, domain_id: str, group_id: str, payload: Dict[str, Any]) -> None:
    path = f"/policy/api/v1/infra/domains/{domain_id}/groups/{group_id}"
    log.info("Pushing group %s to %s", group_id, path)
    client_put(client, path, payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Push ONLY NSX Groups from promoted artifacts")
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR,
                        help="Directory containing promoted group files")
    parser.add_argument("--manager", required=True, choices=["gm1", "lm1", "lm2", "lm3", "lm4"],
                        help="NSX manager target")
    parser.add_argument("--domain", default="default", help="NSX domain ID (default: default)")

    # Federation flag: default True for gm1, False otherwise
    parser.add_argument("--federation-global", action="store_true",
                        help="Use federation global mode (recommended for GM pushes)")
    parser.add_argument("--no-federation-global", action="store_true",
                        help="Force federation global mode off")

    args = parser.parse_args()

    manager_map = {
        "gm1": nsx_gm1,
        "lm1": nsx_lm1,
        "lm2": nsx_lm2,
        "lm3": nsx_lm3,
        "lm4": nsx_lm4,
    }

    # Decide federation_global:
    if args.no_federation_global:
        federation_global = False
    elif args.federation_global:
        federation_global = True
    else:
        federation_global = (args.manager == "gm1")  # sensible default

    # Instantiate client correctly
    client = NsxPolicyClient(manager_map[args.manager], federation_global=federation_global)

    input_dir = args.input_dir
    domain_id = args.domain

    # Allow passing either:
    # - nsx_promoted_groups (root)
    # - nsx_promoted_groups/nsx-gm1.lab.local/domains/default/groups (leaf)
    # We’ll just walk whatever you provide.
    if not input_dir.exists():
        raise SystemExit(f"Input directory does not exist: {input_dir}")

    total = 0
    errors = 0
    skipped = 0

    for file_path in iter_group_files(input_dir):
        try:
            doc = load_doc(file_path)

            group_id = doc.get("id") or doc.get("display_name")
            if not group_id:
                log.warning("Skipping %s (missing id/display_name)", file_path)
                skipped += 1
                continue

            push_group(client, domain_id, group_id, doc)
            total += 1

        except Exception as e:
            log.error("Failed pushing %s: %s", file_path, e)
            errors += 1

    log.info("Push complete. Groups=%d Skipped=%d Errors=%d", total, skipped, errors)


if __name__ == "__main__":
    main()