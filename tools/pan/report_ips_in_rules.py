#!/usr/bin/env python3
"""tools/pan/report_ips_in_rules.py

Rule-centric IP membership report for Panorama: the PAN counterpart of
tools/reports/report_vms_in_rules.py. Given a list of target IPs/subnets,
find every security rule (shared pre/post + every device group's pre/post)
whose source or destination covers any of them, through address objects,
address groups (nested groups expanded), or literal tokens in the rule.

Read-only, REST API as the agent account (keygen is the only XML call).
Managed firewalls are never contacted.

Target list: one IP or subnet per line (bare IP = /32), # comments ignored.
Precedence: --ip-list > PAN_IP_RULE_REPORT_LIST (.env) > auto-discovered
pan_ip_rule_targets.txt at repo root.

Exclusion list: same format, applied to MATCH RESULTS (not targets): a
match whose matching value is equal to or broader than an exclusion entry
is suppressed and reported in its own section. Example: with 10.0.0.0/8
excluded, a match through an object valued 10.0.0.0/8 (or 0.0.0.0/1) is
suppressed, while a match through 10.1.1.0/24 still counts. Precedence:
--exclude-file > PAN_IP_RULE_EXCLUDE_LIST (.env) > auto-discovered
pan_ip_rule_exclude.txt at repo root. Missing exclusion file = none.

Rules with any on BOTH sides match everything, so they are listed once in
their own section instead of per target. A rule with any on one side is a
normal match via the other side, with the any side noted.

USAGE:
    python tools/pan/report_ips_in_rules.py \
        --user-env agent_user --password-env agent_password --no-tls-verify

    python tools/pan/report_ips_in_rules.py --ip-list my_ips.txt \
        --exclude-file my_exclusions.txt --device-groups dg-4 \
        --user-env agent_user --password-env agent_password --no-tls-verify

Outputs: pan_reports/<host>/<TS>/ip_rule_matches/report.md and report.json
(override the directory with --reports-dir).

Exit codes: 0 report written, 1 pull failure, 2 bad arguments/.env/lists.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from palo.pan_ip_rules import match_rules, parse_ip_lines  # noqa: E402
from palo.pan_rest_client import PanRestClient, PanRestError  # noqa: E402

log = logging.getLogger("report_ips_in_rules")

DEFAULT_REPORTS_BASE = REPO_ROOT / "pan_reports"
DEFAULT_LIST_FILENAME = "pan_ip_rule_targets.txt"
DEFAULT_EXCLUDE_FILENAME = "pan_ip_rule_exclude.txt"
LIST_ENV_VAR = "PAN_IP_RULE_REPORT_LIST"
EXCLUDE_ENV_VAR = "PAN_IP_RULE_EXCLUDE_LIST"


def resolve_list_path(flag_value, env_var: str, default_name: str,
                      required: bool) -> Path | None:
    if flag_value:
        p = Path(flag_value).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(p)
        return p
    env_val = os.environ.get(env_var, "").strip()
    if env_val:
        p = Path(env_val).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(p)
        return p
    p = REPO_ROOT / default_name
    if p.exists():
        return p
    if required:
        raise FileNotFoundError(f"no --flag, no {env_var}, and {p} not found")
    return None


def pull_rules(client: PanRestClient, scope: str, rulebase: str) -> List[Dict[str, Any]]:
    resource = f"Policies/Security{rulebase.capitalize()}Rules"
    try:
        if scope == "shared":
            return client.entries(resource, location="shared")
        return client.entries(resource, device_group=scope)
    except PanRestError as exc:
        text = str(exc).lower()
        if exc.status_code == 404 or "not present" in text or "non exist" in text:
            return []
        raise


def _md_table(headers: List[str], rows: List[List[str]]) -> List[str]:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) if c is not None else "" for c in r) + " |")
    return out


def build_report_md(meta: Dict[str, Any], targets, invalid,
                    scope_results: List[Dict[str, Any]]) -> str:
    suppressed_count = sum(len(sr["suppressed"]) for sr in scope_results)
    L: List[str] = ["# Panorama IP-to-rule membership report", ""]
    L += _md_table(["", ""], [
        ["Target", f"`{meta['target']}`"],
        ["Account", f"`{meta['username']}`"],
        ["IP list", f"`{meta['ip_list']}` ({len(targets)} searched)"],
        ["Match exclusions", f"{suppressed_count} matches suppressed"],
        ["Exclusions", f"`{meta['exclude_list'] or '(none)'}`"],
        ["Firewalls", "not contacted (Panorama config only)"],
        ["Ran at", meta["ran_at"]],
    ])
    L.append("")

    L.append("## 1. Rules matching the target IPs")
    rows = []
    for sr in scope_results:
        for r in sr["matched_rules"]:
            flags = []
            if r["disabled"]:
                flags.append("DISABLED")
            if r["any_sides"]:
                flags.append("any on " + "/".join(r["any_sides"]))
            for m in r["matches"]:
                via = f" via group {m['via']}" if m["via"] else ""
                rows.append([sr["scope"], sr["rulebase"], r["rule"], r["action"] or "",
                             ", ".join(flags), m["target"], m["side"],
                             f"{m['member']} = `{m['value']}`{via}"])
    L += _md_table(["Scope", "Rulebase", "Rule", "Action", "Flags", "Target",
                    "Side", "Matched through"], rows) if rows else ["(none)"]
    L.append("")

    L.append("## 2. Global any/any rules (match every IP; listed once)")
    rows = [[sr["scope"], sr["rulebase"], name]
            for sr in scope_results for name in sr["any_any_rules"]]
    L += _md_table(["Scope", "Rulebase", "Rule"], rows) if rows else ["(none)"]
    L.append("")

    L.append("## 3. Targets with no rule matches")
    matched_targets = {m["target"] for sr in scope_results
                       for r in sr["matched_rules"] for m in r["matches"]}
    rows = [[t["raw"]] for t in targets if t["raw"] not in matched_targets]
    L += _md_table(["Target"], rows) if rows else ["(none)"]
    L.append("")

    L.append("## 4. Suppressed matches (matching value equal to or broader "
             "than an exclusion entry)")
    rows = [[sr["scope"], sr["rulebase"], s["rule"], s["target"], s["side"],
             f"{s['member']} = `{s['value']}`" + (f" via group {s['via']}" if s["via"] else ""),
             f"`{s['excluded_by']}`"]
            for sr in scope_results for s in sr["suppressed"]]
    L += _md_table(["Scope", "Rulebase", "Rule", "Target", "Side",
                    "Matched through", "Excluded by"], rows) if rows else ["(none)"]
    L.append("")

    if invalid:
        L.append("## 5. Invalid input lines (skipped)")
        L += [f"- `{line}`" for line in invalid]
        L.append("")
    return "\n".join(L)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("USAGE:", 1)[1] if "USAGE:" in __doc__ else None)
    parser.add_argument("--ip-list", default=None,
                        help=f"Targets file (default: {LIST_ENV_VAR} in .env, then "
                             f"{DEFAULT_LIST_FILENAME} at repo root).")
    parser.add_argument("--exclude-file", default=None,
                        help=f"Exclusions file (default: {EXCLUDE_ENV_VAR} in .env, then "
                             f"{DEFAULT_EXCLUDE_FILENAME} at repo root; missing = none).")
    parser.add_argument("--host", default=None, help="Target Panorama hostname (overrides .env).")
    parser.add_argument("--device-groups", default=None,
                        help="Comma-separated device groups (default: all discovered).")
    parser.add_argument("--no-shared", action="store_true", help="Skip the shared rulebases.")
    parser.add_argument("--user-env", default=None,
                        help="Env var holding the username (e.g. agent_user).")
    parser.add_argument("--password-env", default=None,
                        help="Env var holding the password (e.g. agent_password).")
    parser.add_argument("--reports-dir", default=None,
                        help="Report output dir (default pan_reports/<host>/<TS>/ip_rule_matches).")
    parser.add_argument("--no-tls-verify", action="store_true",
                        help="Disable TLS certificate verification for this run.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show resolved lists and plan; no network calls.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = time.gmtime

    if args.no_tls_verify:
        os.environ["PANORAMA_TLS_VERIFY"] = "false"

    try:
        client = PanRestClient.from_env(user_env=args.user_env,
                                        password_env=args.password_env, host=args.host)
    except PanRestError as exc:
        log.error("%s", exc)
        return 2

    try:
        ip_path = resolve_list_path(args.ip_list, LIST_ENV_VAR, DEFAULT_LIST_FILENAME, True)
        exclude_path = resolve_list_path(args.exclude_file, EXCLUDE_ENV_VAR,
                                         DEFAULT_EXCLUDE_FILENAME, False)
    except FileNotFoundError as exc:
        log.error("List file not found: %s", exc)
        return 2

    targets, invalid = parse_ip_lines(ip_path.read_text(encoding="utf-8"))
    exclusions, invalid_excl = parse_ip_lines(
        exclude_path.read_text(encoding="utf-8")) if exclude_path else ([], [])
    invalid += [f"(exclusions) {x}" for x in invalid_excl]
    if not targets:
        log.error("No valid targets in %s", ip_path)
        return 2

    log.info("Target    : %s (account via %s)", client.env.url,
             args.user_env or "PANORAMA_* resolution")
    log.info("IP list   : %s (%d targets, %d invalid lines)",
             ip_path, len(targets), len(invalid))
    log.info("Exclusions: %s (%d entries; applied to MATCH VALUES, not targets)",
             exclude_path or "(none)", len(exclusions))
    if args.dry_run:
        for t in targets:
            log.info("  search  %s", t["raw"])
        for e in exclusions:
            log.info("  suppress matches via values covering %s", e["raw"])
        log.info("DRY RUN: no network calls, nothing written.")
        return 0

    try:
        all_dgs = client.list_device_groups()
        dgs = ([d.strip() for d in args.device_groups.split(",") if d.strip()]
               if args.device_groups else all_dgs)
        unknown = sorted(set(dgs) - set(all_dgs))
        if unknown:
            log.error("Unknown device groups: %s (available: %s)", unknown, all_dgs)
            return 2

        shared_addresses = client.list_addresses(location="shared")
        shared_groups = client.list_address_groups(location="shared")

        scope_results: List[Dict[str, Any]] = []

        def run_scope(scope: str, addresses, groups) -> None:
            for rulebase in ("pre", "post"):
                rules = pull_rules(client, scope, rulebase)
                res = match_rules(rules, addresses, groups, targets,
                                  scope=scope, rulebase=rulebase,
                                  match_exclusions=exclusions)
                scope_results.append(res)
                log.info("%s/%s: %d rules, %d matched, %d any/any, %d suppressed",
                         scope, rulebase, len(rules), len(res["matched_rules"]),
                         len(res["any_any_rules"]), len(res["suppressed"]))

        if not args.no_shared:
            run_scope("shared", shared_addresses, shared_groups)
        for dg in dgs:
            dg_addresses = client.list_addresses(device_group=dg)
            dg_groups = client.list_address_groups(device_group=dg)
            run_scope(dg, dg_addresses + shared_addresses, dg_groups + shared_groups)
    except PanRestError as exc:
        log.error("Pull failed: %s", exc)
        return 1

    meta = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "target": client.env.url,
        "username": client.username,
        "ip_list": str(ip_path),
        "exclude_list": str(exclude_path) if exclude_path else None,
        "read_only": True,
    }
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    reports_dir = (Path(args.reports_dir).expanduser().resolve() if args.reports_dir
                   else DEFAULT_REPORTS_BASE / client.env.hostname.split(".")[0] / ts
                   / "ip_rule_matches")
    reports_dir.mkdir(parents=True, exist_ok=True)

    totals = {
        "targets_searched": len(targets),
        "rules_matched": sum(len(sr["matched_rules"]) for sr in scope_results),
        "any_any_rules": sum(len(sr["any_any_rules"]) for sr in scope_results),
        "matches_suppressed": sum(len(sr["suppressed"]) for sr in scope_results),
    }
    report = {"meta": meta, "totals": totals, "targets": [t["raw"] for t in targets],
              "invalid_lines": invalid, "scopes": scope_results}
    (reports_dir / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    (reports_dir / "report.md").write_text(
        build_report_md(meta, targets, invalid, scope_results), encoding="utf-8")

    log.info("Totals  : %s", totals)
    log.info("Report  : %s", reports_dir / "report.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
