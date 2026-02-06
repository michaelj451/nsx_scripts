from pathlib import Path
import logging
import argparse
from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_lm2, nsx_gm1
from nsx.nsx_file_export_functions.nsx_vm_exporter2 import (
    export_nsx_vm_inventory_to_files,
)
from nsx.nsx_constants import resolve_manager

log = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export NSX VM inventory")
    parser.add_argument(
        "--contains",
        help="Only export VMs whose name contains this string",
        default=None,
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Make the contains filter case-sensitive",
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-gm1", "nsx-lm1", "nsx-lm2"],
        default="nsx-lm2",
        help="Which NSX manager to export from (default: nsx-lm2)",
    )

    args = parser.parse_args()

    init_cli()

    manager_host = resolve_manager(args.manager)

    if not manager_host:
        raise RuntimeError(f"NSX manager host is not set for {args.manager}. Check your .env.")

    
    export_root = Path("nsx_export") / nsx_lm2
    export_nsx_vm_inventory_to_files(
        nsxmanager=nsx_lm2,
        export_root=export_root,
        contains=args.contains,
        case_sensitive=args.case_sensitive,
    )


if __name__ == "__main__":
    main()