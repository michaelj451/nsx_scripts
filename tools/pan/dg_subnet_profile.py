#!/usr/bin/env python3
"""tools/pan/dg_subnet_profile.py

Profile the address space each Device Group's rulebase actually talks about,
bucketed to /24 (configurable), and report the top N subnets per DG.

USE CASE:
    "A request lands on my desk: allow 10.50.5.10 -> 172.16.9.20 tcp/443.
    Which Device Group owns that conversation?"

    This tool answers the standing half of that question: it builds a
    DG <-> subnet ownership map from the existing rule population, so you
    have a cheat sheet of which DG is the natural home for which address
    space. The per-request half is --lookup (below), which consults the
    FULL index rather than the printed top N.

WHAT IT COUNTS:
    For every enabled rule in a DG's own rulebases (pre + post), every
    source and destination address reference is resolved to concrete
    networks (address objects, nested static groups and literal CIDRs) and
    rolled up to its containing /24. A rule is counted once per bucket per
    side, so the numbers read as "how many rules in this DG touch this /24",
    not "how many object references".

    Address space WIDER than the bucket mask (a /16 in a rule, say) is
    expanded into its constituent /24s when that is at most --expand-limit
    buckets (default 16, i.e. /20 and narrower); anything wider is kept as a
    single aggregate row, flagged with '*', so one 0.0.0.0/0 object cannot
    flood the table.

    'any' contributes no positional signal and is counted separately.
    FQDN objects and Dynamic Address Groups cannot be resolved offline;
    they are tallied as unresolved and reported per DG.

The bucketing itself lives in app/palo/pan_dg_subnets.py, shared with the
SSDD Toolkit web UI (which resolves the same model from its REST snapshot
instead of an XML export). This module is the offline-XML front end.

MODES:
    (default)   Profile every DG, print the top N /24s each.
    --lookup    Additionally answer "which DGs cover these IPs", ranked by
                rule count, using every bucket in the index.

CAVEATS:
    * Rule population is a PROXY for placement, not the truth. The truth is
      routing and zone/interface layout: a DG only enforces a flow its
      firewalls actually see. Use this to shortlist, then confirm with
      app/palo/pan_rule_placement.py (routing-table based) or the zone map.
    * check_policy_match's parser keys address objects by NAME across all
      scopes, so a name defined in two DGs collapses to the last one parsed.
      Rare in practice, but it can misattribute a bucket.

READ-ONLY, FILE-DRIVEN. No network calls, no credentials, no writes
anywhere customer-side. Same production safety properties as
check_policy_match.py and recommend_dg.py.

USAGE:
    python tools/pan/dg_subnet_profile.py \\
        --config tools/pan/configs/<customer>-<ts>.xml

    python tools/pan/dg_subnet_profile.py --config <cfg> --top 20
    python tools/pan/dg_subnet_profile.py --config <cfg> --mask 16
    python tools/pan/dg_subnet_profile.py --config <cfg> \\
        --lookup 10.50.5.10 --lookup 172.16.9.20
    python tools/pan/dg_subnet_profile.py --config <cfg> --include-inherited

    --json suppresses human output. --no-disk skips the audit write to
    $PANO_REPORTS_DIR/dg_subnet_profile/<UTC_TS>/.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_policy_match as cpm  # noqa: E402

from palo.pan_dg_subnets import (  # noqa: E402
    DGProfile, SideResolution, SubnetProfiler, interval_from_network,
    lookup_ip, profile_to_dict, share_pct,
)

log = logging.getLogger(__name__)


def _rule_id(rule: cpm.SecurityRule) -> str:
    return f"{rule.rulebase_path}#{rule.position}:{rule.name}"


class _AddressResolver:
    """resolve_address with a cache. The same object/group is referenced by
    hundreds of rules in a real config; resolving it once matters on a 25MB
    export."""

    def __init__(self, config: cpm.PanoramaConfig):
        self.config = config
        self._cache: Dict[str, Tuple[List[Any], List[str]]] = {}

    def resolve(self, name: str) -> Tuple[List[Any], List[str]]:
        hit = self._cache.get(name)
        if hit is None:
            hit = self.config.resolve_address(name)
            self._cache[name] = hit
        return hit


def _resolve_side(names: List[str], resolver: _AddressResolver) -> SideResolution:
    """One rule side's address names -> the engine's SideResolution."""
    if "any" in names:
        return SideResolution(is_any=True)
    res = SideResolution()
    for name in names:
        nets, caveats = resolver.resolve(name)
        res.caveats.extend(caveats)
        for net in nets:
            res.items.append((name, interval_from_network(net)))
    return res


def profile_rulebase(rules:       List[cpm.SecurityRule],
                     label:       str,
                     prof:        DGProfile,
                     resolver:    _AddressResolver,
                     profiler:    SubnetProfiler,
                     rule_filter: List[str]) -> None:
    """Fold one rulebase into the DG profile."""
    prof.rulebases.append(label)
    for rule in rules:
        if rule.disabled:
            prof.rules_skipped += 1
            continue
        if rule_filter and cpm._rule_matches_filter(rule.name, rule_filter):
            prof.rules_skipped += 1
            continue
        profiler.fold_rule(prof, _rule_id(rule),
                           _resolve_side(rule.source_addresses, resolver),
                           _resolve_side(rule.destination_addresses, resolver))


def build_profiles(config:           cpm.PanoramaConfig,
                   profiler:         SubnetProfiler,
                   rule_filter:      List[str],
                   include_inherited: bool) -> Dict[str, DGProfile]:
    resolver = _AddressResolver(config)
    profiles: Dict[str, DGProfile] = {}

    for dg_name, dg in sorted(config.device_groups.items()):
        prof = DGProfile(dg=dg_name, parent=dg.parent)
        scan: List[Tuple[List[cpm.SecurityRule], str]] = [
            (dg.pre_rulebase, f"{dg_name}/pre-rulebase"),
            (dg.post_rulebase, f"{dg_name}/post-rulebase"),
        ]
        if include_inherited:
            # Ancestors, nearest first; shared last. Attributed to this DG
            # because these rules DO apply to its firewalls.
            for anc in config.ancestor_chain(dg_name)[1:]:
                a = config.device_groups[anc]
                scan.append((a.pre_rulebase, f"{anc}/pre-rulebase (inherited)"))
                scan.append((a.post_rulebase, f"{anc}/post-rulebase (inherited)"))
            scan.append((config.shared_pre_rules, "shared/pre-rulebase (inherited)"))
            scan.append((config.shared_post_rules, "shared/post-rulebase (inherited)"))

        for rules, label in scan:
            profile_rulebase(rules, label, prof, resolver, profiler, rule_filter)
        profiles[dg_name] = prof

    # Shared is not a device group, but "the flow already lives in shared
    # policy" is a real answer, so profile it as a pseudo-DG.
    shared = DGProfile(dg="shared", parent=None)
    for rules, label in ((config.shared_pre_rules, "shared/pre-rulebase"),
                         (config.shared_post_rules, "shared/post-rulebase")):
        profile_rulebase(rules, label, shared, resolver, profiler, rule_filter)
    profiles["shared"] = shared
    return profiles


# =============================================================================
# Rendering
# =============================================================================

_pct = share_pct


def format_text(profiles: Dict[str, DGProfile],
                top: int,
                v4_prefix: int,
                v6_prefix: int,
                lookups: List[Dict[str, Any]],
                meta: Dict[str, Any]) -> str:
    out: List[str] = []
    w = out.append
    w("=" * 78)
    w(f"DEVICE GROUP SUBNET PROFILE  (IPv4 /{v4_prefix}, IPv6 /{v6_prefix} buckets)")
    w("=" * 78)
    w(f"config          : {meta['config']}")
    w(f"generated (UTC) : {meta['generated_utc']}")
    w(f"scope           : {meta['scope']}")
    w(f"device groups   : {meta['dg_count']}")
    w("")

    for dg in sorted(profiles):
        prof = profiles[dg]
        ranked = prof.ranked()
        if not prof.rules_scanned and not ranked:
            continue
        w("-" * 78)
        parent = f"  parent: {prof.parent}" if prof.parent else ""
        w(f"DEVICE GROUP: {dg}{parent}")
        w(f"  rulebases scanned  : {', '.join(prof.rulebases) or 'none'}")
        w(f"  enabled rules      : {prof.rules_scanned}"
          f"   (skipped disabled/filtered: {prof.rules_skipped})")
        w(f"  specific source    : {prof.specific_src_rules}"
          f"   any-source: {prof.any_src_rules}")
        w(f"  specific dest      : {prof.specific_dst_rules}"
          f"   any-dest:   {prof.any_dst_rules}")
        w(f"  distinct subnets   : {len(ranked)}")
        if not ranked:
            w("  (no resolvable addresses in this DG's rules)")
            w("")
            continue

        shown = ranked if top <= 0 else ranked[:top]
        addressed = len(prof.addressed_rules)
        covered = len(set().union(*[b.src_rules | b.dst_rules for b in shown]))
        w(f"  top {len(shown)} cover      : {covered}/{addressed} address-bearing "
          f"rules ({_pct(covered, addressed)}%)")
        w("")
        w("   rank  subnet                  rules    src    dst  share  objects")
        for i, b in enumerate(shown, 1):
            flag = "*" if b.aggregate else " "
            objs = ", ".join(sorted(b.objects)[:3])
            if len(b.objects) > 3:
                objs += f", +{len(b.objects) - 3}"
            w(f"   {i:>4}  {b.key + flag:<23} {b.total_rules:>5}  "
              f"{len(b.src_rules):>5}  {len(b.dst_rules):>5}  "
              f"{_pct(b.total_rules, addressed):>5}  {objs[:40]}")
        if any(b.aggregate for b in shown):
            w("   * aggregate: the rule used a prefix wider than the bucket mask "
              "and was too large to expand")
        if prof.unresolved:
            w("")
            w("  unresolved offline (FQDN / dynamic groups / dangling refs):")
            for c, n in sorted(prof.unresolved.items(), key=lambda kv: -kv[1])[:5]:
                w(f"    {n:>5}x  {c}")
        w("")

    if lookups:
        w("=" * 78)
        w("LOOKUP")
        w("=" * 78)
        for lk in lookups:
            w(f"{lk['ip']}")
            if not lk["matches"]:
                w("  no device group has a rule referencing this address space.")
                w("  -> nothing to inherit from; decide by routing/zone, then")
                w("     shared/post-rulebase is the usual catch-all home.")
                w("")
                continue
            for m in lk["matches"][:10]:
                agg = " (aggregate)" if m["aggregate"] else ""
                w(f"  {m['dg']:<24} {m['subnet']}{agg}")
                w(f"  {'':<24} {m['rules']} rules "
                  f"(src {m['src_rules']}, dst {m['dst_rules']}), "
                  f"rank {m['rank_in_dg']} of {m['dg_bucket_count']}")
                if m["sample_objects"]:
                    w(f"  {'':<24} objects: {', '.join(m['sample_objects'])}")
            w("")
        w("Placement from rule population is a shortlist, not a verdict.")
        w("Confirm with routing (app/palo/pan_rule_placement.py) or the zone map.")

    return "\n".join(out)


def profiles_to_json(profiles: Dict[str, DGProfile], top: int) -> Dict[str, Any]:
    return {dg: profile_to_dict(prof, top=top) for dg, prof in profiles.items()}


def write_csv(path: Path, profiles: Dict[str, DGProfile], top: int) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        wr = csv.writer(fh)
        wr.writerow(["device_group", "parent", "rank", "subnet", "aggregate",
                     "rules", "src_rules", "dst_rules", "share_pct",
                     "dg_address_bearing_rules", "dg_distinct_subnets",
                     "sample_objects"])
        for dg in sorted(profiles):
            prof = profiles[dg]
            ranked = prof.ranked()
            addressed = len(prof.addressed_rules)
            for i, b in enumerate(ranked if top <= 0 else ranked[:top], 1):
                wr.writerow([dg, prof.parent or "", i, b.key,
                             "yes" if b.aggregate else "no",
                             b.total_rules, len(b.src_rules), len(b.dst_rules),
                             _pct(b.total_rules, addressed),
                             addressed, len(ranked),
                             "; ".join(sorted(b.objects)[:5])])


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--config", required=True,
                   help="Path to the Panorama running-config XML file")
    p.add_argument("--top", type=int, default=10,
                   help="Subnets to list per device group. 0 = all. Default 10.")
    p.add_argument("--mask", type=int, default=24,
                   help="IPv4 bucket mask. Default 24.")
    p.add_argument("--v6-mask", type=int, default=64,
                   help="IPv6 bucket mask. Default 64.")
    p.add_argument("--expand-limit", type=int, default=16,
                   help="A rule prefix wider than the bucket mask is expanded "
                        "into its constituent buckets when there are at most "
                        "this many; wider prefixes stay as one aggregate row. "
                        "Default 16 (expands /20 and narrower at /24). "
                        "0 = never expand.")
    p.add_argument("--include-inherited", action="store_true",
                   help="Also fold ancestor-DG and shared rules into each DG's "
                        "profile. Default is DG-local rulebases only, which is "
                        "what tells you where a NEW rule belongs.")
    p.add_argument("--lookup", action="append", default=[], metavar="IP",
                   help="Report which DGs cover this IP, using the full index. "
                        "Repeatable.")
    p.add_argument("--json", action="store_true",
                   help="Suppress human-readable output; print JSON only.")
    p.add_argument("--output-dir", default=None,
                   help="Override the report root. Default is "
                        "$PANO_REPORTS_DIR/dg_subnet_profile/<UTC_TS>/.")
    p.add_argument("--no-disk", action="store_true",
                   help="Suppress the on-disk report (stdout only).")
    p.add_argument("--rule-filter", default=None,
                   help="Path to a rule-filter file (substring keywords). "
                        "Default: tools/pan/rule_filter.txt if present.")
    p.add_argument("--skip-rule", action="append", default=[], metavar="KEYWORD",
                   help="Additional inline filter keyword. Repeatable.")
    p.add_argument("--no-filter", action="store_true",
                   help="Disable rule filtering for this run.")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )

    if not 0 < args.mask <= 32:
        log.error("--mask must be 1..32, got %s", args.mask)
        return 2
    if not 0 < args.v6_mask <= 128:
        log.error("--v6-mask must be 1..128, got %s", args.v6_mask)
        return 2

    cfg_path = Path(args.config).expanduser()
    if not cfg_path.exists():
        log.error("Config not found: %s", cfg_path)
        return 2

    try:
        rule_filter, filter_source = cpm._load_rule_filter(
            explicit_path=(Path(args.rule_filter) if args.rule_filter else None),
            inline_keywords=args.skip_rule,
            disabled=args.no_filter,
        )
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 2
    if rule_filter:
        log.info("Rule filter active: %d keyword(s)%s", len(rule_filter),
                 f" from {filter_source}" if filter_source else "")

    log.info("Parsing %s", cfg_path)
    config = cpm.PanoramaConfig(cfg_path)

    profiler = SubnetProfiler(v4_prefix=args.mask, v6_prefix=args.v6_mask,
                              expand_limit=args.expand_limit)
    profiles = build_profiles(config, profiler, rule_filter,
                              args.include_inherited)

    lookups: List[Dict[str, Any]] = []
    for ip_text in args.lookup:
        try:
            lookups.append(lookup_ip(ip_text, profiles))
        except ValueError:
            log.error("Not an IP address: %r", ip_text)
            return 2

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = {
        "config": str(cfg_path),
        "generated_utc": generated,
        "scope": ("DG-local rulebases + inherited ancestor/shared"
                  if args.include_inherited else "DG-local rulebases (pre + post)"),
        "v4_mask": args.mask,
        "v6_mask": args.v6_mask,
        "expand_limit": args.expand_limit,
        "top": args.top,
        "dg_count": len(config.device_groups),
        "rule_filter_keywords": rule_filter,
    }

    payload = {
        "meta": meta,
        "device_groups": profiles_to_json(profiles, args.top),
        "lookups": lookups,
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(format_text(profiles, args.top, args.mask, args.v6_mask,
                          lookups, meta))

    if not args.no_disk:
        root = (Path(args.output_dir) if args.output_dir
                else cpm._resolve_default_output_dir() / "dg_subnet_profile")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_dir = root if args.output_dir else root / stamp
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "profile.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8")
        write_csv(out_dir / "top_subnets.csv", profiles, args.top)
        (out_dir / "profile.txt").write_text(
            format_text(profiles, args.top, args.mask, args.v6_mask,
                        lookups, meta), encoding="utf-8")
        log.info("Report written to %s", out_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
