#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class ApiCfg:
    base_url: str
    auth: HTTPBasicAuth
    verify_tls: bool = False
    throttle_rps: float = 0.0
    timeout: int = 60


class Throttler:
    def __init__(self, rps: float):
        self.disabled = rps <= 0
        self.min_interval = 0.0 if self.disabled else 1.0 / rps
        self._last = 0.0

    def wait(self):
        if self.disabled:
            return
        now = time.monotonic()
        dt = now - self._last
        if dt < self.min_interval:
            time.sleep(self.min_interval - dt)
        self._last = time.monotonic()


def _build_base_url(host: str, mode: str) -> str:
    host = host.replace("https://", "").rstrip("/")
    if mode == "gm":
        return f"https://{host}/global-manager/api/v1/global-infra"
    if mode == "lm":
        return f"https://{host}/policy/api/v1/infra"
    raise ValueError("mode must be gm or lm")


def _request(
    method: str,
    cfg: ApiCfg,
    throttler: Throttler,
    path: str,
    payload: Optional[dict] = None,
) -> dict:
    url = cfg.base_url.rstrip("/") + path
    throttler.wait()
    r = requests.request(
        method=method,
        url=url,
        auth=cfg.auth,
        verify=cfg.verify_tls,
        timeout=cfg.timeout,
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload) if payload is not None else None,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:1000]}")
    return r.json() if r.text.strip() else {}


def _get_paginated(cfg: ApiCfg, throttler: Throttler, path: str) -> List[dict]:
    results: List[dict] = []
    cursor: Optional[str] = None

    while True:
        full_path = path
        if cursor:
            sep = "&" if "?" in full_path else "?"
            full_path = f"{full_path}{sep}cursor={cursor}"

        data = _request("GET", cfg, throttler, full_path)
        results.extend(data.get("results", []))

        cursor = data.get("cursor")
        if not cursor:
            break

    return results


def _policy_path(domain_id: str, policy_id: str) -> str:
    return f"/domains/{domain_id}/security-policies/{policy_id}"


def _rule_path(domain_id: str, policy_id: str, rule_id: str) -> str:
    return f"/domains/{domain_id}/security-policies/{policy_id}/rules/{rule_id}"


def _group_path(domain_id: str, group_id: str, mode: str) -> str:
    prefix = "global-infra" if mode == "gm" else "infra"
    return f"/{prefix}/domains/{domain_id}/groups/{group_id}"


def _dedupe_keep_order(values: List[str]) -> List[str]:
    seen = set()
    out = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _make_group_paths(
    mode: str,
    domain_id: str,
    group_prefix: str,
    start: int,
    end: int,
) -> List[str]:
    paths = []
    for i in range(start, end + 1):
        gid = f"{group_prefix}-grp-{i:05d}"
        paths.append(_group_path(domain_id, gid, mode))
    return paths


def main() -> None:
    p = argparse.ArgumentParser(
        description="Append existing groups to existing NSX rules."
    )
    p.add_argument("--mode", choices=["gm", "lm"], required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--domain-id", default="default")
    p.add_argument("--user", default=os.getenv("NSX_USER", ""))
    p.add_argument("--password", default=os.getenv("NSX_PASS", ""))
    p.add_argument("--verify-tls", action="store_true")
    p.add_argument("--throttle-rps", type=float, default=0.0)

    p.add_argument("--policy-prefix", default=None, help="Only modify policies with this prefix")
    p.add_argument("--rule-prefix", default=None, help="Only modify rules with this prefix")
    p.add_argument("--rule-id", default=None, help="Only modify a single exact rule ID")

    p.add_argument("--add-to", choices=["source", "destination", "both"], default="both")

    p.add_argument("--group-domain-id", default="default", help="Domain where the groups already exist")
    p.add_argument("--group-prefix", required=True, help="Existing group prefix, e.g. loadtest-gm1")
    p.add_argument("--group-start", type=int, required=True, help="First group number, e.g. 1")
    p.add_argument("--group-end", type=int, required=True, help="Last group number, e.g. 100")

    p.add_argument("--apply", action="store_true", help="Actually write changes")
    args = p.parse_args()

    if not args.user or not args.password:
        print("Missing creds. Set NSX_USER / NSX_PASS or pass --user / --password.", file=sys.stderr)
        sys.exit(2)

    if args.group_end < args.group_start:
        print("--group-end must be >= --group-start", file=sys.stderr)
        sys.exit(2)

    cfg = ApiCfg(
        base_url=_build_base_url(args.host, args.mode),
        auth=HTTPBasicAuth(args.user, args.password),
        verify_tls=args.verify_tls,
        throttle_rps=args.throttle_rps,
    )
    throttler = Throttler(cfg.throttle_rps)

    group_paths = _make_group_paths(
        mode=args.mode,
        domain_id=args.group_domain_id,
        group_prefix=args.group_prefix,
        start=args.group_start,
        end=args.group_end,
    )

    print(f"Base URL: {cfg.base_url}")
    print(f"Target rule domain: {args.domain_id}")
    print(f"Using {len(group_paths)} existing groups from domain '{args.group_domain_id}' with prefix '{args.group_prefix}'")

    policies = _get_paginated(cfg, throttler, f"/domains/{args.domain_id}/security-policies")
    if args.policy_prefix:
        policies = [p for p in policies if p.get("id", "").startswith(args.policy_prefix)]

    print(f"Policies matched: {len(policies)}")

    updated = 0
    inspected_rules = 0

    for pol in policies:
        pol_id = pol["id"]
        rules = _get_paginated(cfg, throttler, f"/domains/{args.domain_id}/security-policies/{pol_id}/rules")

        for rule in rules:
            rule_id = rule["id"]
            inspected_rules += 1

            if args.rule_id and rule_id != args.rule_id:
                continue
            if args.rule_prefix and not rule_id.startswith(args.rule_prefix):
                continue

            src = list(rule.get("source_groups", []))
            dst = list(rule.get("destination_groups", []))

            if args.add_to in ("source", "both"):
                src = _dedupe_keep_order(src + group_paths)

            if args.add_to in ("destination", "both"):
                dst = _dedupe_keep_order(dst + group_paths)

            changed = (src != rule.get("source_groups", [])) or (dst != rule.get("destination_groups", []))
            if not changed:
                continue

            rule["source_groups"] = src
            rule["destination_groups"] = dst

            path = _rule_path(args.domain_id, pol_id, rule_id)

            if args.apply:
                _request("PUT", cfg, throttler, path, rule)
                print(f"UPDATED {pol_id}/{rule_id}")
            else:
                print(f"WOULD UPDATE {pol_id}/{rule_id}")

            updated += 1

    print(f"Inspected rules: {inspected_rules}")
    print(f"Matched/updated rules: {updated}")
    print("Done." if args.apply else "Dry run only. Re-run with --apply to write changes.")


if __name__ == "__main__":
    main()