#!/usr/bin/env python3
# tools/nsx/push_new_groups.py
from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Dict

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_gm1, nsx_lm1, nsx_lm2, nsx_lm3, nsx_lm4
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_object_functions.nsx_group_importer import GroupImportConfig, NsxGroupImporter

log = logging.getLogger(__name__)

DEFAULT_INPUT_DIR = "nsx_remapped_groups"


def _build_mgr_map() -> Dict[str, str]:
    return {
        "nsx-gm1": nsx_gm1,
        "nsx-lm1": nsx_lm1,
        "nsx-lm2": nsx_lm2,
        "nsx-lm3": nsx_lm3,
        "nsx-lm4": nsx_lm4,
    }


def _default_input_dir() -> Path:
    # repo_root = .../nsx_scripts (because this file is repo/tools/nsx/push_new_groups.py)
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / DEFAULT_INPUT_DIR


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Push ONLY new NSX groups from a folder into a target NSX manager"
    )

    parser.add_argument(
        "--target",
        choices=["nsx-gm1", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        required=True,
        help="NSX manager to push groups into.",
    )

    parser.add_argument(
        "--input-dir",
        type=Path,
        default=_default_input_dir(),
        help=f"Root folder containing the exported groups layout (default: <repo>/{DEFAULT_INPUT_DIR}).",
    )

    parser.add_argument("--domain-id", default="default")
    parser.add_argument("--input-format", choices=["yaml", "json"], default="yaml")
    parser.add_argument("--apply", action="store_true", help="Actually push changes (otherwise dry-run).")
    parser.add_argument("--stop-on-error", action="store_true", help="Stop on first error.")
    parser.add_argument("--federation-global", action="store_true")
    parser.add_argument("--new-group-suffix", default=None, help="Only import groups ending with this suffix.")
    parser.add_argument("--new-groups-allowlist", default=None, help="Path to allowlist YAML/JSON (ids/names).")

    args = parser.parse_args()
    init_cli()

    mgr_map = _build_mgr_map()
    dst_mgr = mgr_map.get(args.target)
    if not dst_mgr:
        raise RuntimeError(f"Target manager env var not set for {args.target}. Check your .env / constants.")

    export_root: Path = args.input_dir

    if not export_root.exists():
        raise RuntimeError(f"Input directory does not exist: {export_root}")

    # Determine the actual domain layout root.
    # We support either:
    #   <export_root>/domains/...
    # OR
    #   <export_root>/<manager>/domains/...
    domain_root: Path | None = None

    if (export_root / "domains").is_dir():
        domain_root = export_root
    else:
        # one level of manager directories
        for mgr_dir in export_root.iterdir():
            if not mgr_dir.is_dir():
                continue
            if (mgr_dir / "domains").is_dir():
                domain_root = mgr_dir
                break

    if domain_root is None:
        raise RuntimeError(
            "Could not find a 'domains' directory. Expected either:\n"
            f"  1) {export_root}/domains/<domain-id>/groups\n"
            f"  2) {export_root}/<manager>/domains/<domain-id>/groups"
        )

    log.info("Using domain root: %s", domain_root)
    client = NsxPolicyClient(nsxmanager=dst_mgr, federation_global=args.federation_global)

    cfg = GroupImportConfig(
        export_root=domain_root,   # <-- IMPORTANT: use domain_root, not export_root
        domain_id=args.domain_id,
        input_format=args.input_format,
        dry_run=(not args.apply),
        continue_on_error=(not args.stop_on_error),
        mode="groups_only",
        new_group_suffix=args.new_group_suffix,
        new_groups_allowlist_file=(Path(args.new_groups_allowlist) if args.new_groups_allowlist else None),
    )

    importer = NsxGroupImporter(client=client, cfg=cfg)
    result = importer.import_all()

    log.info("Push complete. Stats=%s Errors=%d", result["stats"], len(result["errors"]))
    print(result)


if __name__ == "__main__":
    main()