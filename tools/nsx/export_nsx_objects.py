from pathlib import Path
import argparse
import logging

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_lm1
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_file_export_functions.nsx_object_exporter import run_export
from nsx.nsx_constants import resolve_manager

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
    parser.add_argument(
        "--manager",
        choices=["nsx-gm1", "nsx-lm1", "nsx-lm2"],
        default="nsx-lm1",
        help="Which NSX manager to export from (default: nsx-lm1)",
    )
    parser.add_argument(
        "--output-format",
        choices=["yaml", "json", "both"],
        default="yaml",
        help="Output format for exported objects (default: yaml)",
    )

    args = parser.parse_args()

    # Load .env, logging, etc.
    init_cli()

    manager_host = resolve_manager(args.manager)

    if not manager_host:
        raise RuntimeError(f"NSX manager host is not set for {args.manager}. Check your .env.")

    client = NsxPolicyClient(
        nsxmanager=manager_host,
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