from __future__ import annotations

import argparse
import logging
from pathlib import Path

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_gm1, nsx_lm1, nsx_lm2
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_constants import resolve_manager
from nsx.nsx_vm_functions.nsx_vm_exporter1 import (
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
    parser = argparse.ArgumentParser(description="Export NSX realized-state VM tags to YAML/JSON")
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
        help="Use global federation endpoints (GM /global-manager/api/...)",
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-gm1", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        default="nsx-lm1",
        help="Which NSX manager to export from (default: nsx-lm1)",
    )

    args = parser.parse_args()

    init_cli()

    manager_host = resolve_manager(args.manager)

    # Optional safety note: GM endpoints should usually be used against a GM host
    if args.federation_global and args.manager != "nsx-gm1":
        log.warning("You set --federation-global but selected %s; this usually requires a Global Manager host.", args.manager)

    if args.manager == "nsx-gm1" or args.federation_global:
        log.error("Exporting from a Global Manager is not supported in this script.")
        return

    # Build client
    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=args.federation_global)

    # Manager-scoped export root (prevents collisions)
    mgr_dir = _manager_dirname(manager_host)
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
    stats = exporter.pull_tagged_vms()

    log.info("VM tag export complete: %s", stats)
    print(stats)


if __name__ == "__main__":
    main()