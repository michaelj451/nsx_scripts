from pathlib import Path
import argparse
import logging

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_lm1
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_file_export_functions.nsx_object_exporter import run_export

log = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export NSX Policy objects (groups, services, policies, rules) to YAML/JSON"
    )
    parser.add_argument(
        "--base-dir",
        default="nsx_export",
        help="Base output directory (default: nsx_export)",
    )
    parser.add_argument(
        "--domain-id",
        default="default",
        help="NSX Policy domain ID (default: default)",
    )
    parser.add_argument(
        "--federation-global",
        action="store_true",
        help="Use global federation endpoints",
    )

    args = parser.parse_args()

    # Load .env, logging, etc.
    init_cli()

    if not nsx_lm1:
        raise RuntimeError("NSX_HOST1 is not set (nsx_lm1). Check your .env.")

    client = NsxPolicyClient(
        nsxmanager=nsx_lm1,
        federation_global=args.federation_global,
    )

    stats = run_export(
        client=client,
        base_dir=args.base_dir,
        domain_id=args.domain_id,
    )

    log.info("NSX object export complete: %s", stats)
    print(stats)


if __name__ == "__main__":
    main()