from pathlib import Path
import logging
import argparse

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_lm2, nsx_gm1
from nsx.nsx_file_export_functions.nsx2_vm_file_exporter import (
    export_nsx_vm_inventory_to_files,
)

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

    args = parser.parse_args()

    init_cli()

    if not nsx_lm2:
        raise RuntimeError(
            "nsx_lm2 is not set. Check your .env and nsx_constants.py loading."
        )
    

    export_root = Path("nsx_export") / nsx_lm2
    export_nsx_vm_inventory_to_files(
        nsxmanager=nsx_lm2,
        export_root=export_root,
        contains=args.contains,
        case_sensitive=args.case_sensitive,
    )


if __name__ == "__main__":
    main()