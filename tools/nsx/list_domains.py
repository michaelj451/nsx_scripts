#!/usr/bin/env python3
"""tools/nsx/list_domains.py

Print every domain id on a manager, one per line. Read-only.

    python tools/nsx/list_domains.py nsx-gm1
    python tools/nsx/list_domains.py nsx-lm1

WHY THIS EXISTS

groups.py (and services/policies/rules) default to --domain-id default and have
no --all-domains option. A Global Manager normally carries one location-scoped
domain per site, and in a federated deployment that is where the customer's
policy actually lives. A run that covers only `default` reports failed=0 and
silently leaves every other domain untouched.

Measured on the lab GM 2026-09-15: the default domain held 13 groups and the
location domain nsx-lm1.lab.local held one more that the remap CSV mapped. Only
the per-domain loop found it.

Output is one id per line so it can drive a shell loop:

    for DOM in $(python tools/nsx/list_domains.py nsx-gm1); do ...; done

A GM alias (nsx-gm*) automatically uses the federation surface, where the
location domains are visible. An LM normally returns just `default`.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from nsx.cli_bootstrap import init_cli            # noqa: E402
from nsx.nsx_constants import resolve_manager     # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient  # noqa: E402

NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2",
                       "nsx-lm3", "nsx-lm4", "nsx-lm5"]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("WHY THIS EXISTS", 1)[1])
    p.add_argument("manager", choices=NSX_MANAGER_CHOICES)
    p.add_argument("--federation-global", action=argparse.BooleanOptionalAction,
                   default=None,
                   help="Force the federation surface on or off. Unset means ON for "
                        "an nsx-gm* alias, OFF otherwise.")
    p.add_argument("--verbose", action="store_true",
                   help="Log which surface was queried, to stderr.")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = __import__("time").gmtime
    init_cli()

    fed = args.federation_global
    if fed is None:
        fed = args.manager.startswith("nsx-gm")
    host = resolve_manager(args.manager)
    if args.verbose:
        logging.getLogger(__name__).info(
            "%s (%s): querying %s", args.manager, host,
            "/global-infra (federation)" if fed else "/infra")

    client = NsxPolicyClient(nsxmanager=host, federation_global=fed)
    for d in client.list_domains():
        did = d.get("id")
        if did:
            print(did)
    return 0


if __name__ == "__main__":
    sys.exit(main())
