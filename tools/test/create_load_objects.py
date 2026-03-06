#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth


@dataclass
class ApiCfg:
    base_url: str
    auth: HTTPBasicAuth
    verify_tls: bool = False
    throttle_rps: float = 5.0  # hard-coded throttle
    timeout: int = 60


class Throttler:
    def __init__(self, rps: float):
        self.min_interval = 1.0 / max(rps, 0.0001)
        self._last = 0.0

    def wait(self):
        now = time.monotonic()
        dt = now - self._last
        if dt < self.min_interval:
            time.sleep(self.min_interval - dt)
        self._last = time.monotonic()


def _put(cfg: ApiCfg, throttler: Throttler, path: str, payload: dict) -> dict:
    url = cfg.base_url.rstrip("/") + path
    throttler.wait()
    r = requests.put(
        url,
        auth=cfg.auth,
        verify=cfg.verify_tls,
        timeout=cfg.timeout,
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
    )
    if r.status_code >= 400:
        raise RuntimeError(f"PUT {path} -> {r.status_code}: {r.text[:500]}")
    return r.json() if r.text.strip() else {}


def _build_base_url(host: str, mode: str) -> str:
    host = host.replace("https://", "").rstrip("/")
    if mode == "gm":
        # Global Manager live global-infra
        return f"https://{host}/global-manager/api/v1/global-infra"
    if mode == "lm":
        # Local Manager / policy API live infra
        return f"https://{host}/policy/api/v1/infra"
    raise ValueError("mode must be gm or lm")


def _group_path(mode: str, domain_id: str, group_id: str) -> str:
    if mode == "gm":
        return f"/domains/{domain_id}/groups/{group_id}"
    return f"/domains/{domain_id}/groups/{group_id}"


def _policy_path(domain_id: str, policy_id: str) -> str:
    return f"/domains/{domain_id}/security-policies/{policy_id}"


def _rule_path(domain_id: str, policy_id: str, rule_id: str) -> str:
    return f"/domains/{domain_id}/security-policies/{policy_id}/rules/{rule_id}"


def _make_group_payload(group_id: str, display_name: str, ips: List[str]) -> dict:
    # IPAddressExpression group (simple + deterministic)
    return {
        "resource_type": "Group",
        "id": group_id,
        "display_name": display_name,
        "expression": [
            {
                "resource_type": "IPAddressExpression",
                "ip_addresses": ips,
            }
        ],
    }


def _make_policy_payload(policy_id: str, display_name: str, category: str) -> dict:
    # Minimal SecurityPolicy. NSX will fill defaults.
    return {
        "resource_type": "SecurityPolicy",
        "id": policy_id,
        "display_name": display_name,
        "category": category,
        "stateful": True,
        "tcp_strict": True,
        "scope": ["ANY"],
    }


def _make_rule_payload(
    rule_id: str,
    display_name: str,
    seq: int,
    src_group_paths: List[str],
    dst_group_paths: List[str],
    services: Optional[List[str]] = None,
    action: str = "ALLOW",
) -> dict:
    return {
        "resource_type": "Rule",
        "id": rule_id,
        "display_name": display_name,
        "sequence_number": seq,
        "action": action,
        "direction": "IN_OUT",
        "ip_protocol": "IPV4_IPV6",
        "profiles": ["ANY"],
        "scope": ["ANY"],
        "disabled": False,
        "logged": False,
        "source_groups": src_group_paths,
        "destination_groups": dst_group_paths,
        "services": services or ["ANY"],
    }


def _generate_unique_ips(base_cidr: str, count: int, per_group: int) -> List[List[str]]:
    """
    Generates per_group IPs per group from base_cidr, sequentially.
    base_cidr should be big enough: e.g. 10.250.0.0/16 with lots of /32s.
    """
    net = ipaddress.ip_network(base_cidr, strict=False)
    # Use hosts() for /16 is fine; for very large networks this could be heavy.
    # We'll compute sequentially by integer offset instead.
    base_int = int(net.network_address)
    max_hosts = net.num_addresses

    needed = count * per_group
    if needed + 10 > max_hosts:
        raise ValueError(f"base_cidr {base_cidr} too small: need {needed} addresses, has {max_hosts}")

    groups: List[List[str]] = []
    cur = 10  # skip first few
    for _ in range(count):
        ips = []
        for _j in range(per_group):
            ip = ipaddress.ip_address(base_int + cur)
            ips.append(str(ip))
            cur += 1
        groups.append(ips)
    return groups


def main() -> None:
    p = argparse.ArgumentParser(description="Create bulk NSX Groups + Security Policies + Rules (LIVE).")
    p.add_argument("--mode", choices=["gm", "lm"], required=True, help="gm=Global Manager global-infra, lm=Local Manager infra")
    p.add_argument("--host", required=True, help="NSX host (e.g. nsx-gm1.lab.local)")
    p.add_argument("--domain-id", default="default", help="Domain ID (default: default)")
    p.add_argument("--user", default=os.getenv("NSX_USER", ""), help="Username (or set NSX_USER)")
    p.add_argument("--password", default=os.getenv("NSX_PASS", ""), help="Password (or set NSX_PASS)")
    p.add_argument("--verify-tls", action="store_true", help="Verify TLS certs (default off)")

    p.add_argument("--groups", type=int, required=True, help="X: number of groups to create")
    p.add_argument("--policies", type=int, required=True, help="Y: number of policies to create")
    p.add_argument("--rules-per-policy", type=int, required=True, help="Z: number of rules per policy")
    p.add_argument("--groups-per-side", type=int, required=True, help="ZZ: groups in each source and destination list")

    p.add_argument("--ips-per-group", type=int, default=1, help="How many IPs per group (default 1)")
    p.add_argument("--base-cidr", default="10.250.0.0/16", help="CIDR used to generate unique IPs (default 10.250.0.0/16)")
    p.add_argument("--category", default="Application", help="Policy category (default Application)")
    p.add_argument("--prefix", default="loadtest", help="Object ID/display_name prefix")
    p.add_argument("--seed", type=int, default=1337, help="Random seed for rule group selection")
    p.add_argument("--throttle-rps", type=float, default=5.0, help="Hard throttle (default 5 req/sec)")

    args = p.parse_args()

    if not args.user or not args.password:
        print("Missing creds. Provide --user/--password or set NSX_USER / NSX_PASS.", file=sys.stderr)
        sys.exit(2)

    if args.groups_per_side > args.groups:
        print("--groups-per-side cannot exceed --groups", file=sys.stderr)
        sys.exit(2)

    random.seed(args.seed)

    base_url = _build_base_url(args.host, args.mode)
    cfg = ApiCfg(
        base_url=base_url,
        auth=HTTPBasicAuth(args.user, args.password),
        verify_tls=args.verify_tls,
        throttle_rps=args.throttle_rps,
    )
    throttler = Throttler(cfg.throttle_rps)

    domain_id = args.domain_id

    # ---- Create Groups ----
    print(f"Base URL: {cfg.base_url}")
    print(f"Creating {args.groups} groups in domain '{domain_id}'...")

    ip_sets = _generate_unique_ips(args.base_cidr, args.groups, args.ips_per_group)

    group_ids: List[str] = []
    for i in range(1, args.groups + 1):
        gid = f"{args.prefix}-grp-{i:05d}"
        gname = gid
        payload = _make_group_payload(gid, gname, ip_sets[i - 1])
        _put(cfg, throttler, _group_path(args.mode, domain_id, gid), payload)
        group_ids.append(gid)

    # Precompute full group paths for rule references
    # IMPORTANT: Rules reference full paths (domain + id).
    group_paths = [f"/{'global-infra' if args.mode=='gm' else 'infra'}/domains/{domain_id}/groups/{gid}" for gid in group_ids]

    # ---- Create Policies + Rules ----
    print(f"Creating {args.policies} policies, {args.rules_per_policy} rules/policy...")
    total_rules = args.policies * args.rules_per_policy

    rule_count = 0
    for pidx in range(1, args.policies + 1):
        pol_id = f"{args.prefix}-pol-{pidx:04d}"
        pol_payload = _make_policy_payload(pol_id, pol_id, args.category)
        _put(cfg, throttler, _policy_path(domain_id, pol_id), pol_payload)

        for ridx in range(1, args.rules_per_policy + 1):
            rule_id = f"{args.prefix}-r-{pidx:04d}-{ridx:04d}"
            # choose ZZ distinct groups per side
            src = random.sample(group_paths, args.groups_per_side)
            dst = random.sample(group_paths, args.groups_per_side)

            seq = ridx * 10
            rule_payload = _make_rule_payload(
                rule_id=rule_id,
                display_name=rule_id,
                seq=seq,
                src_group_paths=src,
                dst_group_paths=dst,
                services=["ANY"],
                action="ALLOW",
            )
            _put(cfg, throttler, _rule_path(domain_id, pol_id, rule_id), rule_payload)

            rule_count += 1
            if rule_count % 50 == 0 or rule_count == total_rules:
                print(f"  rules created: {rule_count}/{total_rules}")

    print("Done.")
    print(f"Created/updated: groups={args.groups}, policies={args.policies}, rules={total_rules}")
    print("Note: re-running with same --prefix will update the same objects (idempotent PUT).")


if __name__ == "__main__":
    main()