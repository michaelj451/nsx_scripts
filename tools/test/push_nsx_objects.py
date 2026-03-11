#!/usr/bin/env python3
# tools/nsx/push_nsx_objects.py

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Dict

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import (
    nsx_gm1,
    nsx_gm2,
    nsx_lm1,
    nsx_lm2,
    nsx_lm3,
    nsx_lm4,
)
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_object_functions.nsx_object_importer import ImportConfig, NsxImporter

log = logging.getLogger(__name__)


def _manager_dirname(mgr: str) -> str:
    """
    Convert a manager URL/hostname into the export folder name.
    Example:
      https://nsx-gm1.lab.local -> nsx-gm1.lab.local
    """
    mgr = (mgr or "").strip()
    mgr = mgr.removeprefix("https://").removeprefix("http://").rstrip("/")
    return mgr or "unknown_manager"


def _resolve_export_root(base_dir: str, manager_name: str) -> Path:
    """
    Support either:
      nsx_export/<manager_name>
    or directly:
      <some/path/already/pointing/to/manager_name>
    """
    base = Path(base_dir)
    return base if base.name == manager_name else (base / manager_name)


def _manager_map() -> Dict[str, str]:
    return {
        "nsx-gm1": nsx_gm1,
        "nsx-gm2": nsx_gm2,
        "nsx-lm1": nsx_lm1,
        "nsx-lm2": nsx_lm2,
        "nsx-lm3": nsx_lm3,
        "nsx-lm4": nsx_lm4,
    }


def _validate_domain_root(export_root: Path, domain_id: str) -> Path:
    """
    Support both layouts:
      NEW: <export_root>/<domain_id>/...
      OLD: <export_root>/domains/<domain_id>/...
    """
    new_root = export_root / domain_id
    old_root = export_root / "domains" / domain_id

    if new_root.exists():
        return new_root
    if old_root.exists():
        return old_root

    raise RuntimeError(
        "Could not find domain export layout.\n"
        f"Checked:\n"
        f"  - {new_root}\n"
        f"  - {old_root}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import NSX objects from exported YAML/JSON into a target NSX manager"
    )
    parser.add_argument(
        "--source",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        required=True,
        help="Manager name used only to locate the export folder on disk",
    )
    parser.add_argument(
        "--target",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        required=True,
        help="Target NSX manager to push objects into",
    )
    parser.add_argument(
        "--base-dir",
        default="nsx_export",
        help="Base export directory, usually nsx_export",
    )
    parser.add_argument(
        "--domain-id",
        default="default",
        help="NSX domain id to import into",
    )
    parser.add_argument(
        "--input-format",
        choices=["yaml", "json"],
        default="yaml",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually push changes. Default is dry-run.",
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop immediately on first error",
    )
    parser.add_argument(
        "--federation-global",
        action="store_true",
        help="Use global/federation paths for GM imports",
    )

    args = parser.parse_args()

    init_cli()

    mgr_map = _manager_map()

    src_mgr = mgr_map.get(args.source)
    dst_mgr = mgr_map.get(args.target)

    if not src_mgr:
        raise RuntimeError(f"Source manager env var not set for {args.source}")
    if not dst_mgr:
        raise RuntimeError(f"Target manager env var not set for {args.target}")

    src_folder = _manager_dirname(src_mgr)
    export_root = _resolve_export_root(args.base_dir, src_folder)

    if not export_root.exists():
        raise RuntimeError(f"Export root does not exist: {export_root}")

    domain_root = _validate_domain_root(export_root, args.domain_id)

    log.info("Source alias        : %s", args.source)
    log.info("Source export folder: %s", export_root)
    log.info("Resolved domain root: %s", domain_root)
    log.info("Target alias        : %s", args.target)
    log.info("Target manager      : %s", dst_mgr)
    log.info("Federation global   : %s", args.federation_global)
    log.info("Mode                : %s", "APPLY" if args.apply else "DRY-RUN")

    client = NsxPolicyClient(
        nsxmanager=dst_mgr,
        federation_global=args.federation_global,
    )

    cfg = ImportConfig(
        export_root=export_root,
        domain_id=args.domain_id,
        input_format=args.input_format,
        dry_run=(not args.apply),
        continue_on_error=(not args.stop_on_error),
    )

    importer = NsxImporter(client=client, cfg=cfg)
    result = importer.import_all()

    log.info("Import complete. Stats=%s Errors=%d", result["stats"], len(result["errors"]))
    print(result)


if __name__ == "__main__":
    main()