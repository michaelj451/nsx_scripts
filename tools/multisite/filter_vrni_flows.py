#!/usr/bin/env python3
"""tools/multisite/filter_vrni_flows.py

Filter a vRNI flow export so Infrastructure rules are left out (Mike,
2026-10-15). Each flow's "firewall ruleid" is looked up among the rules of
the NSX manager the flows were seen on; a flow whose rule sits in an
Infrastructure-category policy is removed. Read-only: the manager is only
read (or not contacted at all with --capture).

Writes, into --out-dir (default $NSX_LOG_DIR/vrni_flow_filter/<UTC_TS>):

  <name>_filtered.csv    the rows kept, original columns
  <name>_removed.csv     the Infrastructure rows, plus a "filter reason" column
  <name>_unmatched.csv   rows with no rule id or a number not on the manager
  <name>_rules.csv       one row per rule seen: rule #, rule name, rule id, policy,
                         category, action, flows, packets, kept or removed
  summary.md             counts, and flows per rule with category and result

Docs: docs/multivendor/RUNBOOK_VRNI_FLOW_FILTER.md

USAGE
    python tools/multisite/filter_vrni_flows.py --flows data/samples/vrni_flows_sample.csv --source nsx-lm1
    python tools/multisite/filter_vrni_flows.py --flows flows.csv \\
        --capture migration_requests/nsx-lm1_to_nsx-lm3/latest/source/capture
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "app") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "app"))

from common.fileio import write_text                     # noqa: E402
from common.logs import setup_logging                    # noqa: E402
from common.paths import repo_relative                   # noqa: E402
from common.timeutil import run_ts                       # noqa: E402
from multisite import vrni_flows as vf                   # noqa: E402

log = logging.getLogger("filter_vrni_flows")
NSX_CHOICES = ["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5", "nsx-lm6"]


def rules_live(alias: str, domain: str) -> Tuple[List[Tuple[Dict[str, Any], Dict[str, Any]]], str]:
    """(policy, rule) pairs read from the manager (GET only)."""
    from nsx.cli_bootstrap import init_cli
    from nsx.nsx_constants import resolve_manager
    from nsx.nsx_policy_client import NsxPolicyClient
    init_cli()
    host = resolve_manager(alias)
    if not host:
        raise SystemExit(f"Manager {alias} is not defined (set it in .env).")
    client = NsxPolicyClient(host)
    pairs = [(pol, rule) for pol in client.list_security_policies(domain_id=domain)
             for rule in client.list_security_rules(pol["id"], domain_id=domain)]
    return pairs, f"{host} (read live)"


def rules_from_capture(capture: Path, host: Optional[str], domain: str
                       ) -> Tuple[List[Tuple[Dict[str, Any], Dict[str, Any]]], str]:
    """(policy, rule) pairs from a capture_nsx_state.py folder (no device contact)."""
    from multisite.migration_request import load_capture
    if host is None:
        hosts = sorted(p.name for p in (capture / "nsx_export").glob("*") if p.is_dir())
        if len(hosts) != 1:
            raise SystemExit(f"{capture} holds {len(hosts)} managers ({', '.join(hosts) or 'none'}); "
                             "name the one the flows came from with --source.")
        host = hosts[0]
    cap = load_capture(capture, host, domain)
    return [(cap.policies[pid], r) for (pid, _rid), r in cap.rules.items()], \
        f"{host} (capture {repo_relative(capture)})"


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n\n", 1)[1])
    p.add_argument("--flows", required=True, metavar="CSV", help="vRNI flow export (CSV).")
    p.add_argument("--source", choices=NSX_CHOICES,
                   help="The manager the flows were seen on: its rules are read live (read-only). "
                        "With --capture, picks the manager inside the capture.")
    p.add_argument("--capture", metavar="DIR",
                   help="Read the rules from a capture_nsx_state.py folder instead of the manager "
                        "(for example a migration request's source/capture).")
    p.add_argument("--exclude-category", action="append", metavar="CATEGORY",
                   help="Policy category to leave out; repeatable (default: Infrastructure).")
    p.add_argument("--domain-id", default="default")
    p.add_argument("--out-dir", metavar="DIR",
                   help="Where the files go (default: $NSX_LOG_DIR/vrni_flow_filter/<UTC_TS>).")
    args = p.parse_args(argv)
    if not args.source and not args.capture:
        p.error("give --source (read the manager) or --capture (read a capture folder)")

    ts = run_ts()
    log_root = Path(os.environ.get("NSX_LOG_DIR") or REPO_ROOT / "nsx_logs")
    out = Path(args.out_dir) if args.out_dir else log_root / "vrni_flow_filter" / ts
    setup_logging("filter_vrni_flows", out / "logs", run_ts=ts)
    excl = args.exclude_category or list(vf.DEFAULT_EXCLUDE)

    flows = Path(args.flows)
    if not flows.is_file():
        raise SystemExit(f"Flow file not found: {flows}")
    header, rows = vf.read_flows(flows)
    try:
        cols = vf.find_columns(header)
    except ValueError as exc:
        raise SystemExit(f"{flows}: {exc}")

    if args.capture:
        host = None
        if args.source:
            from nsx.nsx_constants import resolve_manager
            host = resolve_manager(args.source)
        pairs, rules_from = rules_from_capture(Path(args.capture), host, args.domain_id)
    else:
        pairs, rules_from = rules_live(args.source, args.domain_id)
    index = vf.rule_index(pairs)
    log.info("%d flow row(s) in %s; %d numbered rule(s) from %s", len(rows), flows, len(index), rules_from)

    result = vf.classify(rows, cols, index, excl)
    stem = flows.stem
    files = {"filtered": out / f"{stem}_filtered.csv", "removed": out / f"{stem}_removed.csv",
             "unmatched": out / f"{stem}_unmatched.csv", "rules": out / f"{stem}_rules.csv"}
    vf.write_csv(files["filtered"], header, result["kept"])
    vf.write_csv(files["removed"], header, result["removed"], reason_column="filter reason")
    vf.write_csv(files["unmatched"], header, result["unmatched"], reason_column="filter reason")
    vf.write_rules_csv(files["rules"], vf.rules_rows(result, excl))
    rel = {k: str(repo_relative(v)) for k, v in files.items()}
    summary = out / "summary.md"
    write_text(summary, vf.summary_md(str(flows), rules_from, header, cols, result, rel, excl))

    log.info("kept %d, removed %d (%s), unmatched %d", len(result["kept"]), len(result["removed"]),
             ", ".join(excl), len(result["unmatched"]))
    for k, v in rel.items():
        log.info("  %-9s %s", k, v)
    log.info("  summary   %s", repo_relative(summary))
    print(files["filtered"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
