#!/usr/bin/env python3
"""tools/test/create_tag_load_objects.py

Bulk loader for TAG-BASED groups, plus policies and rules that reference
them. Sibling to create_load_objects.py, which builds IPAddressExpression
groups; this one builds Condition expressions that match real VM tags, so
the created groups return actual VM members from
/domains/<d>/groups/<g>/members/virtual-machines.

That difference matters when the object under test is a membership report
(tools/reports/report_vms_in_rules.py): IP-only groups come back with zero
VM members, so they never exercise the member-resolution path at all.

WHAT IT CREATES
    N groups   : one Condition each, matching a (scope, tag) pair taken from
                 the VMs already on the manager, cycled round-robin.
    Y policies : Application category by default.
    Y*Z rules  : each with --groups-per-side groups on source and destination,
                 sampled from the created groups with a fixed --seed.

Idempotent: object IDs derive from --prefix, so re-running with the same
prefix updates the same objects rather than creating duplicates.

TAG DISCOVERY
    By default the script reads the manager's fabric VM inventory
    (/api/v1/fabric/virtual-machines) and collects every distinct
    (scope, tag) pair. Use --list-tags to see them without writing anything.
    Pass --tag "scope|tag" (repeatable) to skip discovery and supply pairs
    yourself; that is required in --mode gm, where a Global Manager has no
    fabric VM inventory.

    Groups cycle through the discovered pairs, so with 8 pairs and 4500
    groups you get ~562 groups per pair. Every group still costs one member
    API call in the report under test, which is what drives its runtime.

USAGE
    # See what tag material exists, write nothing
    python tools/test/create_tag_load_objects.py --mode lm \\
        --host nsx-lm2.lab.local --list-tags

    # 4500 tag groups + 80 policies x 25 rules
    python tools/test/create_tag_load_objects.py --mode lm \\
        --host nsx-lm2.lab.local \\
        --groups 4500 --policies 80 --rules-per-policy 25 \\
        --groups-per-side 4 --prefix tagload

    Credentials come from --user/--password or NSX_USER/NSX_PASS.
    Add --dry-run to print the plan and the first payloads, sending nothing.

CLEANUP
    tools/test/wipe_app_policies_then_groups.py removes policies then
    non-system groups. System-owned objects are always preserved.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import os
import random
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth

sys.path.insert(0, str(Path(__file__).resolve().parent))
import create_load_objects as clo  # noqa: E402

TagPair = Tuple[str, str]  # (scope, tag)


class SharedThrottler:
    """Thread-safe request pacing shared across workers.

    clo.Throttler keeps unsynchronised state, so it cannot be shared by a
    thread pool. This one holds a lock, and paces the run as a whole rather
    than per worker, so --throttle-rps means the same thing at any --workers.
    rps <= 0 disables pacing entirely.
    """
    def __init__(self, rps: float):
        self.min_interval = 0.0 if rps <= 0 else 1.0 / rps
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if not self.min_interval:
            return
        with self._lock:
            dt = time.monotonic() - self._last
            if dt < self.min_interval:
                time.sleep(self.min_interval - dt)
            self._last = time.monotonic()


# clo._put paces internally; hand it a disabled throttler and pace here
# instead, so pacing stays correct under concurrency.
_NOOP_THROTTLER = clo.Throttler(0)


def _is_already_exists(msg: str) -> bool:
    """NSX answers a PUT against an existing path with 400 / error_code
    500127 rather than updating it. The production client handles this the
    same way (put, then patch), which is what makes a re-run idempotent."""
    return "500127" in msg or "as it already exists" in msg


def _patch(cfg, path: str, payload: dict) -> dict:
    url = cfg.base_url.rstrip("/") + path
    r = requests.patch(
        url, auth=cfg.auth, verify=cfg.verify_tls, timeout=cfg.timeout,
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
    )
    if r.status_code >= 400:
        raise RuntimeError(f"PATCH {path} -> {r.status_code}: {r.text[:500]}")
    return r.json() if r.text.strip() else {}


def put_with_retry(cfg, throttler, path: str, payload: dict,
                   max_attempts: int = 5) -> dict:
    """clo._put, paced by a shared throttler and retrying 429/503.

    The sibling loader aborts the whole run on any 4xx/5xx. That is fine at
    its default 5 req/s, but unthrottled a single transient 429 would kill a
    multi-thousand-object build partway through.
    """
    attempt = 0
    while True:
        throttler.wait()
        try:
            return clo._put(cfg, _NOOP_THROTTLER, path, payload)
        except RuntimeError as exc:
            msg = str(exc)
            if _is_already_exists(msg):
                # Object is already there: update it in place so re-running
                # with the same --prefix is idempotent.
                throttler.wait()
                return _patch(cfg, path, payload)
            retryable = (" -> 429" in msg or " -> 503" in msg)
            attempt += 1
            if not retryable or attempt >= max_attempts:
                raise
            delay = min(0.5 * (2 ** attempt), 10.0)
            print(f"  throttled on {path} (attempt {attempt}/{max_attempts}); "
                  f"retrying in {delay:.1f}s", file=sys.stderr, flush=True)
            time.sleep(delay)


def run_pool(label: str, jobs, workers: int, total: int, every: int = 250):
    """Run put jobs, serially or across a thread pool, with progress.

    Any worker exception propagates once the pool drains.
    """
    done = 0
    lock = threading.Lock()
    t0 = time.monotonic()

    def tick():
        nonlocal done
        with lock:
            done += 1
            n = done
        if n % every == 0 or n == total:
            rate = n / max(time.monotonic() - t0, 0.001)
            eta = (total - n) / rate if rate else 0
            print(f"  ... {n}/{total} {label}  ({rate:.1f}/s, "
                  f"~{eta/60:.1f} min left)", flush=True)

    if workers <= 1:
        for job in jobs:
            job()
            tick()
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(job) for job in jobs]
        for f in concurrent.futures.as_completed(futures):
            f.result()
            tick()


# =============================================================================
# Tag discovery
# =============================================================================

def _fabric_vm_url(host: str) -> str:
    host = host.replace("https://", "").rstrip("/")
    return f"https://{host}/api/v1/fabric/virtual-machines"


def discover_tag_pairs(host: str, auth: HTTPBasicAuth, verify_tls: bool,
                       timeout: int = 60,
                       ) -> Tuple[List[TagPair], Dict[TagPair, int], int, int]:
    """Read fabric VMs and collect every distinct (scope, tag) pair.

    Returns (pairs_sorted, vm_count_per_pair, total_vms, tagged_vms).
    LM-only: a Global Manager has no fabric VM inventory.
    """
    url = _fabric_vm_url(host)
    counts: Dict[TagPair, int] = collections.Counter()
    total = tagged = 0
    cursor: Optional[str] = None
    while True:
        params = {"page_size": 1000}
        if cursor:
            params["cursor"] = cursor
        r = requests.get(url, auth=auth, verify=verify_tls, timeout=timeout,
                         params=params, headers={"Accept": "application/json"})
        if r.status_code >= 400:
            raise RuntimeError(
                f"GET {url} -> {r.status_code}: {r.text[:300]}. "
                f"Fabric VM inventory is Local Manager only; in --mode gm "
                f"supply pairs with --tag \"scope|tag\" instead."
            )
        doc = r.json()
        results = doc.get("results") or []
        for vm in results:
            total += 1
            tags = vm.get("tags") or []
            if tags:
                tagged += 1
            for t in tags:
                counts[((t.get("scope") or ""), (t.get("tag") or ""))] += 1
        cursor = doc.get("cursor")
        if not cursor or not results:
            break
    pairs = sorted(p for p in counts if p[1])  # a tag value is required
    return pairs, counts, total, tagged


def parse_tag_arg(raw: str) -> TagPair:
    """'scope|tag' -> (scope, tag). A bare value means an empty scope."""
    if "|" in raw:
        scope, tag = raw.split("|", 1)
        return scope.strip(), tag.strip()
    return "", raw.strip()


def condition_value(scope: str, tag: str) -> str:
    """NSX Condition value for a tag match: 'scope|tag', or just the tag
    when the scope is empty."""
    return f"{scope}|{tag}" if scope else tag


# =============================================================================
# Payloads
# =============================================================================

def make_tag_group_payload(group_id: str, display_name: str,
                           scope: str, tag: str) -> dict:
    return {
        "resource_type": "Group",
        "id": group_id,
        "display_name": display_name,
        "expression": [
            {
                "resource_type": "Condition",
                "member_type": "VirtualMachine",
                "key": "Tag",
                "operator": "EQUALS",
                "value": condition_value(scope, tag),
            }
        ],
    }


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(
        description="Create tag-based Groups (+ policies and rules) for load "
                    "testing membership reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--mode", choices=["gm", "lm"], required=True,
                   help="API surface: lm = /policy/api/v1/infra, "
                        "gm = /global-manager/api/v1/global-infra")
    p.add_argument("--host", required=True, help="NSX host (e.g. nsx-lm2.lab.local)")
    p.add_argument("--domain-id", default="default", help="Domain ID (default: default)")
    p.add_argument("--user", default=os.getenv("NSX_USER", ""),
                   help="Username (or set NSX_USER)")
    p.add_argument("--password", default=os.getenv("NSX_PASS", ""),
                   help="Password (or set NSX_PASS)")
    p.add_argument("--verify-tls", action="store_true",
                   help="Verify TLS certs (default off)")

    p.add_argument("--groups", type=int, default=0,
                   help="Number of tag-based groups to create")
    p.add_argument("--policies", type=int, default=0,
                   help="Number of security policies to create")
    p.add_argument("--rules-per-policy", type=int, default=0,
                   help="Rules per policy (uniform). Ignored when --rules-total is set.")
    p.add_argument("--rules-total", type=int, default=0, metavar="N",
                   help="Exact total rules to spread across --policies. Use when the "
                        "total does not divide evenly: the first (N %% policies) "
                        "policies get one extra rule each, so the total is exact.")
    p.add_argument("--groups-per-side", type=int, default=4,
                   help="Groups in each rule's source and destination list (default 4)")

    p.add_argument("--tag", action="append", default=[], metavar="SCOPE|TAG",
                   help="Tag pair to use, repeatable. Skips discovery. "
                        "A bare value means an empty scope. Required in --mode gm.")
    p.add_argument("--list-tags", action="store_true",
                   help="Print the discovered tag pairs and exit without writing.")

    p.add_argument("--category", default="Application", help="Policy category (default Application)")
    p.add_argument("--prefix", default="tagload", help="Object ID/display_name prefix")
    p.add_argument("--seed", type=int, default=1337, help="Random seed for rule group selection")
    p.add_argument("--throttle-rps", type=float, default=5.0,
                   help="Requests per second across the whole run; "
                        "0 disables throttling (default 5)")
    p.add_argument("--workers", type=int, default=5, metavar="N",
                   help="Concurrent PUT workers (default 5). NSX write latency "
                        "is ~400ms per object, so a serial run tops out near "
                        "2.5 objects/s regardless of --throttle-rps; raising "
                        "this is the only way to go faster. 5 stays under the "
                        "HTTP session pool of 10, so no connections are "
                        "discarded. Use 1 for strictly one-at-a-time.")
    p.add_argument("--skip-groups", action="store_true",
                   help="Do not create groups (reuse existing ones with this prefix for rules)")
    p.add_argument("--skip-rules", action="store_true",
                   help="Create groups only; no policies or rules")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the plan and sample payloads; send nothing.")
    args = p.parse_args()

    if not args.user or not args.password:
        p.error("credentials required: --user/--password or NSX_USER/NSX_PASS")

    auth = HTTPBasicAuth(args.user, args.password)

    # ---- tag pairs ----
    if args.tag:
        pairs = [parse_tag_arg(t) for t in args.tag]
        pairs = [(s, t) for s, t in pairs if t]
        source = "--tag"
        if not pairs:
            p.error("no usable --tag values (a tag value is required)")
    else:
        if args.mode == "gm":
            p.error("--mode gm has no fabric VM inventory to discover tags from; "
                    "pass --tag \"scope|tag\" (repeatable)")
        print(f"Discovering VM tags on {args.host} ...")
        pairs, counts, total_vms, tagged_vms = discover_tag_pairs(
            args.host, auth, args.verify_tls)
        source = "fabric VM inventory"
        print(f"  VMs: {total_vms} ({tagged_vms} tagged)")
        print(f"  Distinct (scope, tag) pairs: {len(pairs)}")
        for s, t in pairs:
            print(f"    scope={s!r:12} tag={t!r:18} on {counts[(s, t)]} VM-tag(s)"
                  f"   -> condition value {condition_value(s, t)!r}")
        if not pairs:
            print("No tagged VMs found; nothing to build tag groups from.",
                  file=sys.stderr)
            return 1

    if args.list_tags:
        return 0
    if args.groups <= 0 and not args.skip_groups:
        p.error("--groups is required (or pass --skip-groups to build rules only)")

    cfg = clo.ApiCfg(
        base_url=clo._build_base_url(args.host, args.mode),
        auth=auth,
        verify_tls=args.verify_tls,
        throttle_rps=args.throttle_rps,
    )
    throttler = SharedThrottler(args.throttle_rps)

    per_pair = (args.groups // len(pairs)) if pairs else 0
    print()
    print("=" * 66)
    print("TAG-BASED LOAD OBJECTS " + ("(DRY RUN)" if args.dry_run else ""))
    print("=" * 66)
    print(f"  Target        : {args.host}  ({args.mode}, domain={args.domain_id})")
    print(f"  Base URL      : {cfg.base_url}")
    print(f"  Tag pairs     : {len(pairs)} from {source}  (~{per_pair} groups each)")
    print(f"  Groups        : {args.groups}")
    if not args.skip_rules:
        if args.rules_total > 0:
            b, e = divmod(args.rules_total, max(args.policies, 1))
            shape = (f"{args.policies} policies, {args.rules_total} rules total "
                     f"({e} with {b+1}, {args.policies - e} with {b})")
        else:
            shape = (f"{args.policies} x {args.rules_per_policy} rules "
                     f"= {args.policies * args.rules_per_policy} rules")
        print(f"  Policies      : {shape}")
        print(f"  Groups/side   : {args.groups_per_side}")
    print(f"  Prefix        : {args.prefix}")
    print(f"  Throttle      : "
          + (f"{args.throttle_rps} req/s" if args.throttle_rps > 0 else "disabled"))
    print(f"  Workers       : {args.workers}")
    total_writes = (0 if args.skip_groups else args.groups)
    if not args.skip_rules:
        _b, _e = divmod(args.rules_total, max(args.policies, 1))
        _rules = args.rules_total if args.rules_total > 0 else args.policies * args.rules_per_policy
        total_writes += args.policies + _rules
    eta = (total_writes / args.throttle_rps) if args.throttle_rps > 0 else 0
    print(f"  Total PUTs    : {total_writes}"
          + (f"   (~{eta/60:.1f} min at {args.throttle_rps} req/s)" if eta else ""))
    print("=" * 66)

    group_paths: List[str] = []
    infra_root = "/global-infra" if args.mode == "gm" else "/infra"

    # ---- groups ----
    group_jobs = []
    for i in range(args.groups):
        gid = f"{args.prefix}-grp-{i:05d}"
        scope, tag = pairs[i % len(pairs)]
        group_paths.append(f"{infra_root}/domains/{args.domain_id}/groups/{gid}")
        if args.skip_groups:
            continue
        payload = make_tag_group_payload(
            gid, f"{args.prefix} tag group {i:05d} [{condition_value(scope, tag)}]",
            scope, tag)
        path = clo._group_path(args.mode, args.domain_id, gid)
        if args.dry_run:
            if i < 2:
                print(f"\nPUT {path}\n{json.dumps(payload, indent=2)}")
            continue
        group_jobs.append(
            lambda pa=path, pl=payload: put_with_retry(cfg, throttler, pa, pl))
    if group_jobs:
        run_pool("groups", group_jobs, args.workers, len(group_jobs))
        print(f"Groups done: {len(group_jobs)}", flush=True)

    # ---- policies + rules ----
    # Per-policy rule counts. --rules-total spreads a remainder so the total
    # is exact; otherwise every policy gets --rules-per-policy.
    if args.rules_total > 0 and args.policies > 0:
        base, extra = divmod(args.rules_total, args.policies)
        per_policy = [base + (1 if y < extra else 0) for y in range(args.policies)]
    else:
        per_policy = [args.rules_per_policy] * max(args.policies, 0)
    planned_rules = sum(per_policy)

    if args.skip_rules or args.policies <= 0 or planned_rules <= 0:
        print("Skipping policies/rules.")
    else:
        if args.groups_per_side > len(group_paths):
            p.error(f"--groups-per-side {args.groups_per_side} exceeds the "
                    f"{len(group_paths)} group(s) available")
        rng = random.Random(args.seed)
        policy_jobs, rule_jobs = [], []
        for y in range(args.policies):
            pid = f"{args.prefix}-pol-{y:04d}"
            ppath = clo._policy_path(args.domain_id, pid)
            pol = clo._make_policy_payload(
                pid, f"{args.prefix} policy {y:04d}", args.category)
            if args.dry_run:
                if y < 1:
                    print(f"\nPUT {ppath}\n{json.dumps(pol, indent=2)}")
            else:
                policy_jobs.append(
                    lambda pa=ppath, pl=pol: put_with_retry(cfg, throttler, pa, pl))
            for z in range(per_policy[y]):
                rid = f"{args.prefix}-rule-{y:04d}-{z:04d}"
                src = rng.sample(group_paths, args.groups_per_side)
                dst = rng.sample(group_paths, args.groups_per_side)
                rule = clo._make_rule_payload(
                    rid, f"{args.prefix} rule {y:04d}/{z:04d}",
                    seq=(z + 1) * 10, src_group_paths=src, dst_group_paths=dst,
                )
                rpath = clo._rule_path(args.domain_id, pid, rid)
                if args.dry_run:
                    if y == 0 and z < 1:
                        print(f"\nPUT {rpath}\n{json.dumps(rule, indent=2)}")
                    continue
                rule_jobs.append(
                    lambda pa=rpath, pl=rule: put_with_retry(cfg, throttler, pa, pl))
        # Policies must all exist before any rule is PUT underneath them.
        if policy_jobs:
            run_pool("policies", policy_jobs, args.workers, len(policy_jobs),
                     every=10)
        if rule_jobs:
            run_pool("rules", rule_jobs, args.workers, len(rule_jobs))
        if not args.dry_run:
            print(f"Policies done: {len(policy_jobs)}   "
                  f"Rules done: {len(rule_jobs)}", flush=True)

    referenced = len({g for g in group_paths})
    print()
    print("Created objects carry the prefix "
          f"{args.prefix!r}. To remove them:")
    print(f"  python tools/test/wipe_app_policies_then_groups.py "
          f"--host {args.host}"
          + ("" if args.mode == "lm" else " --federation-global"))
    if not args.skip_rules and args.policies and args.rules_per_policy:
        print(f"\nRule-referenced groups will be a subset of the {referenced} "
              f"created; the membership report logs the exact count.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
