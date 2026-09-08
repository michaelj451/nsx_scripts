#!/usr/bin/env python3
"""tools/test/wipe_by_prefix.py

Delete load-test objects by ID prefix. Scoped counterpart to
wipe_app_policies_then_groups.py, which removes every non-system policy and
group and would take pre-existing customer objects with it.

This one only ever touches objects whose id starts with --prefix, so it is
the exact inverse of a create_tag_load_objects.py / create_load_objects.py
run that used that prefix. Everything else is listed as KEPT and left alone.

Order is policies first (rules go with them), then groups, because NSX
refuses to delete a group a rule still references.

DEFAULTS ARE SAFE
    Dry-run unless --apply.
    5 concurrent deletes by default. --workers 1 for strictly one at a time.

USAGE
    # see what would go, send nothing
    python tools/test/wipe_by_prefix.py --target nsx-gm1 --federation-global \\
        --prefix gmload-

    # do it, one at a time
    python tools/test/wipe_by_prefix.py --target nsx-gm1 --federation-global \\
        --prefix gmload- --apply

    # faster, if the manager can take it
    ... --apply --workers 12

Pacing comes from the shared client: NSX_API_MAX_RPS (default 2 req/s), or
--rate-limit for this run only. 429/503 retry with backoff is always on.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Callable, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "app"))

log = logging.getLogger(__name__)


def _delete_all(fn: Callable, ids: List[str], domain_id: str, kind: str,
                workers: int, apply: bool) -> int:
    """Delete ids via fn. Serial when workers <= 1 (no pool is created)."""
    if not ids or not apply:
        return 0
    lock = threading.Lock()
    state = {"done": 0, "failed": 0}
    total = len(ids)

    def one(ident: str) -> None:
        try:
            fn(ident, domain_id=domain_id)
        except Exception as exc:
            with lock:
                state["failed"] += 1
                log.error("  FAIL %s %s: %s", kind, ident, str(exc)[:100])
            return
        with lock:
            state["done"] += 1
            n = state["done"]
        if n % 250 == 0 or n == total:
            log.info("  ... %d/%d %s deleted", n, total, kind)

    if workers <= 1:
        for i in ids:
            one(i)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(one, ids))
    return state["failed"]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Delete policies and groups whose id starts with --prefix.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target", required=True, help="Manager alias from .env")
    p.add_argument("--federation-global", action="store_true",
                   help="Operate on /global-infra (Global Manager).")
    p.add_argument("--domain-id", default="default")
    p.add_argument("--prefix", required=True,
                   help="Object id prefix to delete, e.g. 'gmload-'. Objects "
                        "not carrying it are never touched.")
    p.add_argument("--apply", action="store_true",
                   help="Actually delete. Default is dry-run.")
    p.add_argument("--workers", type=int, default=5, metavar="N",
                   help="Concurrent deletes (default 5, which stays under the "
                        "HTTP session pool of 10). Use 1 for strictly serial, "
                        "one request at a time. Above 10 the session pool is "
                        "resized to match so connections are not discarded.")
    p.add_argument("--rate-limit", type=float, default=None, metavar="RPS",
                   help="Requests per second for this run (sets "
                        "NSX_API_MAX_RPS). 0 disables pacing.")
    args = p.parse_args()

    if args.rate_limit is not None:
        os.environ["NSX_API_MAX_RPS"] = str(args.rate_limit)

    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    from nsx.cli_bootstrap import init_cli
    init_cli()
    from nsx.nsx_policy_client import NsxPolicyClient
    from nsx.nsx_constants import resolve_manager

    host = resolve_manager(args.target)
    if not host:
        raise SystemExit(f"Target manager not defined: {args.target}")
    client = NsxPolicyClient(nsxmanager=host,
                             federation_global=args.federation_global)

    # Match the HTTP connection pool to the worker count. Without this,
    # workers > 10 makes urllib3 discard and reopen connections
    # ("Connection pool is full"), paying a TLS handshake per discard.
    if args.workers > 1:
        try:
            import requests.adapters
            ad = requests.adapters.HTTPAdapter(pool_connections=args.workers,
                                               pool_maxsize=args.workers)
            client.session.mount("https://", ad)
        except Exception as exc:
            log.warning("could not resize connection pool: %s", exc)

    groups = client.list_groups(domain_id=args.domain_id)
    pols = client.list_security_policies(domain_id=args.domain_id)
    gdel = [g["id"] for g in groups if str(g.get("id", "")).startswith(args.prefix)]
    pdel = [x["id"] for x in pols if str(x.get("id", "")).startswith(args.prefix)]
    gkeep = [g["id"] for g in groups if not str(g.get("id", "")).startswith(args.prefix)]
    pkeep = [x["id"] for x in pols if not str(x.get("id", "")).startswith(args.prefix)]

    mode = "APPLY" if args.apply else "DRY-RUN"
    log.info("=" * 62)
    log.info("WIPE BY PREFIX (%s)", mode)
    log.info("  Target   : %s (%s)  domain=%s", args.target, host, args.domain_id)
    log.info("  Prefix   : %r", args.prefix)
    log.info("  Workers  : %d%s", args.workers,
             "  (serial, one at a time)" if args.workers <= 1 else "")
    log.info("=" * 62)
    log.info("  policies : %d to delete, %d KEPT -> %s", len(pdel), len(pkeep), pkeep)
    log.info("  groups   : %d to delete, %d KEPT", len(gdel), len(gkeep))

    if not args.apply:
        log.info("\nDRY-RUN: nothing sent. Re-run with --apply to delete.")
        return 0
    if not pdel and not gdel:
        log.info("\nNothing matches the prefix; nothing to do.")
        return 0

    failed = 0
    if pdel:
        log.info("\nDeleting %d policies ...", len(pdel))
        failed += _delete_all(client.delete_security_policy, pdel,
                              args.domain_id, "policies", args.workers, True)
    if gdel:
        log.info("Deleting %d groups ...", len(gdel))
        failed += _delete_all(client.delete_group, gdel,
                              args.domain_id, "groups", args.workers, True)

    g2 = client.list_groups(domain_id=args.domain_id)
    p2 = client.list_security_policies(domain_id=args.domain_id)
    log.info("\nAFTER: groups=%d  policies=%d  failures=%d", len(g2), len(p2), failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
