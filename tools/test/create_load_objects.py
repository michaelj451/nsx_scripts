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
from typing import List, Optional

import requests
from requests.auth import HTTPBasicAuth


@dataclass
class ApiCfg:
    base_url: str
    auth: HTTPBasicAuth
    verify_tls: bool = False
    throttle_rps: float = 5.0
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
        print(f"ERROR on {path}: {r.status_code}", file=sys.stderr)
        raise RuntimeError(f"PUT {path} -> {r.status_code}: {r.text[:500]}")
    return r.json() if r.text.strip() else {}


def _build_base_url(host: str, mode: str) -> str:
    host = host.replace("https://", "").rstrip("/")
    if mode == "gm":
        return f"https://{host}/global-manager/api/v1/global-infra"
    if mode == "lm":
        return f"https://{host}/policy/api/v1/infra"
    raise ValueError("mode must be gm or lm")


def _group_path(mode: str, domain_id: str, group_id: str) -> str:
    return f"/domains/{domain_id}/groups/{group_id}"


def _policy_path(domain_id: str, policy_id: str) -> str:
    return f"/domains/{domain_id}/security-policies/{policy_id}"


def _rule_path(domain_id: str, policy_id: str, rule_id: str) -> str:
    return f"/domains/{domain_id}/security-policies/{policy_id}/rules/{rule_id}"


def _make_group_payload(group_id: str, display_name: str, ip_entries: List[str]) -> dict:
    return {
        "resource_type": "Group",
        "id": group_id,
        "display_name": display_name,
        "expression": [
            {
                "resource_type": "IPAddressExpression",
                "ip_addresses": ip_entries,
            }
        ],
    }


def _make_policy_payload(policy_id: str, display_name: str, category: str) -> dict:
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


def _align_up(value: int, block_size: int) -> int:
    if block_size <= 0:
        raise ValueError("block_size must be > 0")
    remainder = value % block_size
    return value if remainder == 0 else value + (block_size - remainder)


def _generate_group_ip_entries(
    base_cidr: str,
    group_count: int,
    subnets_per_group: int,
    subnet_prefix: int,
    ranges_per_group: int,
    range_width: int,
    singles_per_group: int = 0,
    start_offset: int = 10,
) -> List[List[str]]:
    """
    Generate per-group IPAddressExpression entries.

    Each group can contain:
      - N subnets (CIDR strings)
      - N ranges (start-end)
      - N single IPs

    Entries are generated sequentially from base_cidr without overlap.
    IPv4 only.
    """
    net = ipaddress.ip_network(base_cidr, strict=False)
    if net.version != 4:
        raise ValueError("This generator currently supports IPv4 only")

    if subnet_prefix < net.prefixlen:
        raise ValueError(
            f"subnet_prefix /{subnet_prefix} cannot be broader than base network /{net.prefixlen}"
        )
    if subnet_prefix > 32:
        raise ValueError("subnet_prefix must be <= 32")
    if range_width < 1:
        raise ValueError("range_width must be >= 1")
    if singles_per_group < 0:
        raise ValueError("singles_per_group must be >= 0")

    subnet_block_size = 2 ** (32 - subnet_prefix)
    base_int = int(net.network_address)
    net_end = int(net.broadcast_address)

    cursor = base_int + start_offset
    all_groups: List[List[str]] = []

    for _ in range(group_count):
        entries: List[str] = []

        # Subnets
        for _ in range(subnets_per_group):
            cursor = _align_up(cursor, subnet_block_size)
            subnet_net = ipaddress.ip_network(
                f"{ipaddress.ip_address(cursor)}/{subnet_prefix}",
                strict=False,
            )
            subnet_start = int(subnet_net.network_address)
            subnet_end = int(subnet_net.broadcast_address)

            if subnet_start < base_int or subnet_end > net_end:
                raise ValueError(
                    f"base_cidr {base_cidr} too small for requested subnet generation"
                )

            entries.append(str(subnet_net))
            cursor = subnet_end + 1

        # Ranges
        for _ in range(ranges_per_group):
            start_ip = ipaddress.ip_address(cursor)
            end_ip = ipaddress.ip_address(cursor + range_width - 1)

            if int(end_ip) > net_end:
                raise ValueError(
                    f"base_cidr {base_cidr} too small for requested range generation"
                )

            if range_width == 1:
                entries.append(str(start_ip))
            else:
                entries.append(f"{start_ip}-{end_ip}")
            cursor += range_width

        # Single IPs
        for _ in range(singles_per_group):
            ip = ipaddress.ip_address(cursor)
            if int(ip) > net_end:
                raise ValueError(
                    f"base_cidr {base_cidr} too small for requested single IP generation"
                )
            entries.append(str(ip))
            cursor += 1

        all_groups.append(entries)

    return all_groups


def main() -> None:
    p = argparse.ArgumentParser(
        description="Create bulk NSX Groups + Security Policies + Rules (LIVE)."
    )
    p.add_argument(
        "--mode",
        choices=["gm", "lm"],
        required=True,
        help="gm=Global Manager global-infra, lm=Local Manager infra",
    )
    p.add_argument("--host", required=True, help="NSX host (e.g. nsx-gm1.lab.local)")
    p.add_argument("--domain-id", default="default", help="Domain ID (default: default)")
    p.add_argument("--user", default=os.getenv("NSX_USER", ""), help="Username (or set NSX_USER)")
    p.add_argument("--password", default=os.getenv("NSX_PASS", ""), help="Password (or set NSX_PASS)")
    p.add_argument("--verify-tls", action="store_true", help="Verify TLS certs (default off)")

    p.add_argument("--groups", type=int, required=True, help="X: number of groups to create")
    p.add_argument("--policies", type=int, required=True, help="Y: number of policies to create")
    p.add_argument("--rules-per-policy", type=int, required=True, help="Z: number of rules per policy")
    p.add_argument("--groups-per-side", type=int, required=True, help="ZZ: groups in each source and destination list")

    p.add_argument("--subnets-per-group", type=int, default=5, help="Number of CIDR subnets per group (default 5)")
    p.add_argument("--subnet-prefix", type=int, default=30, help="Prefix length for generated subnets (default /30)")
    p.add_argument("--ranges-per-group", type=int, default=5, help="Number of IP ranges per group (default 5)")
    p.add_argument("--range-width", type=int, default=2, help="How many IPs in each range (default 2)")
    p.add_argument("--single-ips-per-group", type=int, default=0, help="Optional number of single IPs per group (default 0)")
    p.add_argument("--base-cidr", default="10.250.0.0/16", help="CIDR used to generate unique IP material (default 10.250.0.0/16)")

    p.add_argument("--category", default="Application", help="Policy category (default Application)")
    p.add_argument("--prefix", default="loadtest", help="Object ID/display_name prefix")
    p.add_argument("--seed", type=int, default=1337, help="Random seed for rule group selection")
    p.add_argument(
        "--throttle-rps",
        type=float,
        default=5.0,
        help="Throttle requests per second; use 0 to disable throttling",
    )

    args = p.parse_args()

    if not args.user or not args.password:
        print(
            "Missing creds. Provide --user/--password or set NSX_USER / NSX_PASS.",
            file=sys.stderr,
        )
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

    print(f"Base URL: {cfg.base_url}")
    print(
        f"Creating {args.groups} groups in domain '{domain_id}' "
        f"with {args.subnets_per_group} subnets/group, "
        f"{args.ranges_per_group} ranges/group, "
        f"{args.single_ips_per_group} single IPs/group..."
    )

    group_ip_entries = _generate_group_ip_entries(
        base_cidr=args.base_cidr,
        group_count=args.groups,
        subnets_per_group=args.subnets_per_group,
        subnet_prefix=args.subnet_prefix,
        ranges_per_group=args.ranges_per_group,
        range_width=args.range_width,
        singles_per_group=args.single_ips_per_group,
    )

    # ---- Create Groups ----
    group_ids: List[str] = []
    for i in range(1, args.groups + 1):
        gid = f"{args.prefix}-grp-{i:05d}"
        gname = gid
        payload = _make_group_payload(gid, gname, group_ip_entries[i - 1])
        _put(cfg, throttler, _group_path(args.mode, domain_id, gid), payload)
        group_ids.append(gid)

    # Rules reference full paths
    group_paths = [
        f"/{'global-infra' if args.mode == 'gm' else 'infra'}/domains/{domain_id}/groups/{gid}"
        for gid in group_ids
    ]

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
    print(
        "Per-group entries: "
        f"subnets={args.subnets_per_group}, "
        f"ranges={args.ranges_per_group}, "
        f"range_width={args.range_width}, "
        f"single_ips={args.single_ips_per_group}"
    )
    print("Note: re-running with same --prefix will update the same objects (idempotent PUT).")


if __name__ == "__main__":
    main()