from __future__ import annotations

import argparse
import logging
from pathlib import Path

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_manager1
from nsx.nsx_policy_client import NsxPolicyClient

from nsx.nsx_file_export_functions.nsx1_vm_file_exporter import (
    VmTagsExportConfig,
    NsxVmTagsExporter,
)

log = logging.getLogger(__name__)


def _manager_dirname(mgr: str) -> str:
    # keep consistent with your object exporter (scheme-less, no trailing slash)
    mgr = (mgr or "").strip()
    mgr = mgr.removeprefix("https://").removeprefix("http://").rstrip("/")
    return mgr or "unknown_manager"


def main() -> None:
    parser = argparse.ArgumentParser(description="Export NSX1 realized-state VM tags to YAML/JSON")
    parser.add_argument("--base-dir", default="nsx_export", help="Base export directory")
    parser.add_argument("--output-format", choices=["yaml", "json", "both"], default="yaml")
    parser.add_argument("--page-size", type=int, default=500)
    parser.add_argument(
        "--accepted-vm-types",
        default="REGULAR",
        help='Comma-separated list of VM types to include (default: "REGULAR"). Use "ALL" to disable filtering.',
    )
    parser.add_argument(
        "--federation-global",
        action="store_true",
        help="Use global federation endpoints",
    )

    args = parser.parse_args()

    init_cli()

    if not nsx_manager1:
        raise RuntimeError("NSX_HOST1 is not set (nsx_manager1). Check your .env.")

    # Build client
    client = NsxPolicyClient(nsxmanager=nsx_manager1, federation_global=args.federation_global)

    # Manager-scoped export root (prevents collisions)
    mgr_dir = _manager_dirname(nsx_manager1)
    export_root = Path(args.base_dir) / mgr_dir

    # Parse accepted VM types
    accepted_raw = (args.accepted_vm_types or "").strip()
    if accepted_raw.upper() == "ALL":
        accepted = ()  # empty => no filtering
    else:
        accepted = tuple(x.strip().upper() for x in accepted_raw.split(",") if x.strip())

    cfg = VmTagsExportConfig(
        export_root=export_root,
        output_format=args.output_format,
        page_size=args.page_size,
        accepted_vm_types=accepted,
    )

    exporter = NsxVmTagsExporter(client=client, cfg=cfg)
    stats = exporter.pull_vm_tags()

    log.info("VM tag export complete: %s", stats)
    print(stats)


if __name__ == "__main__":
    main()