from __future__ import annotations

import argparse
import logging
from pathlib import Path

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_gm1, nsx_lm1, nsx_lm2
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_file_import_functions.nsx_tagged_vms_importer import (
    VmTagsImportConfig,
    NsxVmTagsImporter,
)

log = logging.getLogger(__name__)


def _manager_dirname(mgr: str) -> str:
    mgr = (mgr or "").strip()
    mgr = mgr.removeprefix("https://").removeprefix("http://").rstrip("/")
    return mgr or "unknown_manager"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import VM tags from SOURCE NSX into DEST NSX using inventory allowlist"
    )

    parser.add_argument(
        "--source",
        choices=["nsx1", "nsx2"],
        default="nsx1",
        help="Source NSX manager (where tagged-vms index lives)",
    )
    parser.add_argument(
        "--dest",
        choices=["nsx1", "nsx2"],
        default="nsx2",
        help="Destination NSX manager (where tags are applied)",
    )
    parser.add_argument(
        "--base-dir",
        default="nsx_export",
        help="Base directory containing manager export folders",
    )
    parser.add_argument(
        "--input-format",
        choices=["yaml", "json"],
        default="yaml",
        help="Input file format (default: yaml)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes (default is dry-run)",
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop on first error (default continues)",
    )
    parser.add_argument(
        "--only-scope-prefix",
        help="Only apply tags whose scope starts with this prefix (optional)",
    )
    parser.add_argument(
        "--accepted-source-vm-types",
        help='Comma-separated list of allowed source VM types (e.g. "REGULAR"). Omit to allow all.',
    )
    parser.add_argument(
        "--federation-global",
        action="store_true",
        help="Use global federation endpoints",
    )

    args = parser.parse_args()

    init_cli()

    mgr_map = {
        "nsx1": nsx_lm1,
        "nsx2": nsx_lm2,
    }

    src_mgr = mgr_map.get(args.source)
    dst_mgr = mgr_map.get(args.dest)

    if not src_mgr:
        raise RuntimeError(f"Source manager not set for {args.source} (check NSX_LM1/NSX_LM2)")
    if not dst_mgr:
        raise RuntimeError(f"Destination manager not set for {args.dest} (check NSX_LM1/NSX_LM2)")
    source_root = Path(args.base_dir) / _manager_dirname(src_mgr)
    dest_inventory_root = Path(args.base_dir) / _manager_dirname(dst_mgr)

    if not source_root.exists():
        raise RuntimeError(f"Source export root does not exist: {source_root}")
    if not dest_inventory_root.exists():
        raise RuntimeError(f"Destination inventory root does not exist: {dest_inventory_root}")

    client = NsxPolicyClient(
        nsxmanager=dst_mgr,
        federation_global=args.federation_global,
    )

    accepted_types = None
    if args.accepted_source_vm_types:
        accepted_types = tuple(
            x.strip().upper()
            for x in args.accepted_source_vm_types.split(",")
            if x.strip()
        )

    cfg = VmTagsImportConfig(
        export_root=source_root,
        dest_inventory_root=dest_inventory_root,
        input_format=args.input_format,
        dry_run=(not args.apply),
        continue_on_error=(not args.stop_on_error),
        accepted_source_vm_types=accepted_types,
        only_scope_prefix=args.only_scope_prefix,
    )

    importer = NsxVmTagsImporter(client=client, cfg=cfg)
    result = importer.push_tagged_vms()

    log.info("VM tag import complete: %s", result["stats"])
    print(result)


if __name__ == "__main__":
    main()