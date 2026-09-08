#!/usr/bin/env python3
"""app/palo/pan_dg_subnets.py

Pure engine for "which address space does each device group's rulebase
actually talk about", bucketed to /24 (configurable).

Everything here is computation over INTERVALS: {"version", "lo", "hi",
"label"} with inclusive integer bounds, the same currency pan_ip_rules.py
uses. Resolving a rule's address members down to intervals is the caller's
job, which is what lets the two front ends share this code:

  * tools/pan/dg_subnet_profile.py resolves from an offline Panorama XML
    export (check_policy_match.PanoramaConfig).
  * tools/pan/ssdd_toolkit_web.py resolves from the REST snapshot the web
    toolkit already holds (pan_ip_rules.expand_group).

Interval arithmetic rather than ipaddress networks is deliberate: an
address object can be an ip-range, and a range is not a network. Rolling
[lo, hi] onto bucket boundaries handles hosts, subnets and ranges through
one path.

WHAT THE NUMBERS MEAN:
    A rule is counted once per bucket per side, so a bucket's count reads
    as "how many rules in this DG touch this /24", not "how many object
    references point into it".

    An interval spanning more buckets than `expand_limit` is kept as a
    single aggregate row labelled with the interval as written, so one
    0.0.0.0/0 object cannot flood the table with 16 million rows.

    'any' carries no positional signal and is counted separately, never
    bucketed.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

Interval = Dict[str, Any]        # {"version", "lo", "hi", "label"}

DEFAULT_V4_PREFIX = 24
DEFAULT_V6_PREFIX = 64
DEFAULT_EXPAND_LIMIT = 16


# =============================================================================
# Intervals
# =============================================================================

def interval_from_network(net: Any, label: Optional[str] = None) -> Interval:
    """An ipaddress network -> interval."""
    return {"version": net.version,
            "lo": int(net.network_address),
            "hi": int(net.broadcast_address),
            "label": label or str(net)}


def interval_from_text(text: str) -> Optional[Interval]:
    """A host, CIDR or 'a-b' range string -> interval, or None when the
    token is not an address (an FQDN, a keyword, a wildcard)."""
    text = (text or "").strip()
    if not text:
        return None
    if "-" in text and "/" not in text:
        a_text, _, b_text = text.partition("-")
        try:
            a = ipaddress.ip_address(a_text.strip())
            b = ipaddress.ip_address(b_text.strip())
        except ValueError:
            return None
        if a.version != b.version or int(a) > int(b):
            return None
        return {"version": a.version, "lo": int(a), "hi": int(b), "label": text}
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    return interval_from_network(net, label=text)


# =============================================================================
# Bucketing
# =============================================================================

def buckets_for_interval(iv: Interval,
                         v4_prefix: int = DEFAULT_V4_PREFIX,
                         v6_prefix: int = DEFAULT_V6_PREFIX,
                         expand_limit: int = DEFAULT_EXPAND_LIMIT,
                         ) -> List[Tuple[str, int, int, bool]]:
    """Roll one interval onto bucket boundaries.

    Returns [(key, lo, hi, is_aggregate), ...]:
      * an interval landing in one bucket -> that bucket.
      * an interval spanning at most `expand_limit` buckets -> each of them.
      * anything wider -> a single aggregate row keyed by the interval's own
        label, carrying the interval's real bounds so lookups still hit it.
    """
    bits = 32 if iv["version"] == 4 else 128
    plen = v4_prefix if iv["version"] == 4 else v6_prefix
    size = 1 << (bits - plen)
    first = iv["lo"] // size
    last = iv["hi"] // size
    count = last - first + 1

    if count <= max(expand_limit, 1):
        out = []
        for i in range(first, last + 1):
            base = i * size
            key = f"{ipaddress.ip_address(base)}/{plen}"
            out.append((key, base, base + size - 1, False))
        return out
    return [(iv["label"], iv["lo"], iv["hi"], True)]


# =============================================================================
# Model
# =============================================================================

@dataclass
class Bucket:
    """One subnet bucket within one device group."""
    key:       str
    version:   int
    lo:        int
    hi:        int
    aggregate: bool = False
    src_rules: Set[str] = field(default_factory=set)
    dst_rules: Set[str] = field(default_factory=set)
    objects:   Set[str] = field(default_factory=set)

    @property
    def total_rules(self) -> int:
        return len(self.src_rules | self.dst_rules)

    def covers(self, version: int, value: int) -> bool:
        return self.version == version and self.lo <= value <= self.hi


@dataclass
class SideResolution:
    """One side (source or destination) of one rule, already resolved.

    is_any        the side is 'any' (no positional signal)
    items         [(contributing object/literal name, interval)]
    caveats       what could not be resolved (FQDN, dynamic groups, dangling)
    """
    is_any:  bool = False
    items:   List[Tuple[str, Interval]] = field(default_factory=list)
    caveats: List[str] = field(default_factory=list)


@dataclass
class DGProfile:
    dg:                 str
    parent:             Optional[str] = None
    rulebases:          List[str] = field(default_factory=list)
    rules_scanned:      int = 0
    rules_skipped:      int = 0
    any_src_rules:      int = 0
    any_dst_rules:      int = 0
    specific_src_rules: int = 0
    specific_dst_rules: int = 0
    addressed_rules:    Set[str] = field(default_factory=set)
    unresolved:         Dict[str, int] = field(default_factory=dict)
    buckets:            Dict[str, Bucket] = field(default_factory=dict)

    def ranked(self) -> List[Bucket]:
        """Buckets by rule count, descending. Stable on ties (src count,
        then key) so report output does not shuffle between runs."""
        return sorted(self.buckets.values(),
                      key=lambda b: (-b.total_rules, -len(b.src_rules), b.key))

    @property
    def address_bearing_rules(self) -> int:
        return len(self.addressed_rules)


# =============================================================================
# Profiler
# =============================================================================

@dataclass
class SubnetProfiler:
    v4_prefix:    int = DEFAULT_V4_PREFIX
    v6_prefix:    int = DEFAULT_V6_PREFIX
    expand_limit: int = DEFAULT_EXPAND_LIMIT

    def fold_rule(self, prof: DGProfile, rule_id: str,
                  src: SideResolution, dst: SideResolution) -> None:
        """Fold one enabled rule's resolved sides into the profile."""
        prof.rules_scanned += 1
        for side, res in (("src", src), ("dst", dst)):
            for c in res.caveats:
                prof.unresolved[c] = prof.unresolved.get(c, 0) + 1
            if res.is_any:
                if side == "src":
                    prof.any_src_rules += 1
                else:
                    prof.any_dst_rules += 1
                continue
            landed = False
            for name, iv in res.items:
                for key, lo, hi, agg in buckets_for_interval(
                        iv, self.v4_prefix, self.v6_prefix, self.expand_limit):
                    b = prof.buckets.get(key)
                    if b is None:
                        b = Bucket(key=key, version=iv["version"], lo=lo, hi=hi,
                                   aggregate=agg)
                        prof.buckets[key] = b
                    (b.src_rules if side == "src" else b.dst_rules).add(rule_id)
                    b.objects.add(name)
                    landed = True
            if landed:
                prof.addressed_rules.add(rule_id)
                if side == "src":
                    prof.specific_src_rules += 1
                else:
                    prof.specific_dst_rules += 1


# =============================================================================
# Lookup
# =============================================================================

def lookup_ip(ip_text: str, profiles: Dict[str, DGProfile],
              max_per_dg: int = 3) -> Dict[str, Any]:
    """Every DG bucket covering `ip_text`, ranked.

    Deliberately consults the FULL index rather than each DG's top N: the
    /24 on a given request is frequently in a DG's long tail, and that is
    still the right DG. Specific buckets outrank aggregates, since a DG
    that names the /24 outright is a stronger signal than one that happens
    to carry a supernet.
    """
    ip = ipaddress.ip_address(ip_text)
    value, version = int(ip), ip.version
    hits: List[Dict[str, Any]] = []
    for dg, prof in profiles.items():
        ranked = prof.ranked()
        found = 0
        for rank, b in enumerate(ranked, 1):
            if not b.covers(version, value):
                continue
            hits.append({
                "dg": dg,
                "subnet": b.key,
                "aggregate": b.aggregate,
                "rules": b.total_rules,
                "src_rules": len(b.src_rules),
                "dst_rules": len(b.dst_rules),
                "rank_in_dg": rank,
                "dg_bucket_count": len(ranked),
                "sample_objects": sorted(b.objects)[:5],
            })
            found += 1
            if found >= max_per_dg:
                break
    hits.sort(key=lambda h: (h["aggregate"], -h["rules"], h["dg"]))
    return {"ip": ip_text, "matches": hits}


def share_pct(n: int, d: int) -> float:
    return round(100.0 * n / d, 1) if d else 0.0


def profile_to_dict(prof: DGProfile, top: int = 10,
                    include_all: bool = True) -> Dict[str, Any]:
    """Serializable view of one DG profile."""
    ranked = prof.ranked()
    addressed = prof.address_bearing_rules
    out: Dict[str, Any] = {
        "parent": prof.parent,
        "rulebases": prof.rulebases,
        "rules_scanned": prof.rules_scanned,
        "rules_skipped": prof.rules_skipped,
        "specific_src_rules": prof.specific_src_rules,
        "specific_dst_rules": prof.specific_dst_rules,
        "any_src_rules": prof.any_src_rules,
        "any_dst_rules": prof.any_dst_rules,
        "address_bearing_rules": addressed,
        "distinct_subnets": len(ranked),
        "unresolved": prof.unresolved,
        "top": [{
            "rank": i + 1,
            "subnet": b.key,
            "aggregate": b.aggregate,
            "rules": b.total_rules,
            "src_rules": len(b.src_rules),
            "dst_rules": len(b.dst_rules),
            "share_pct": share_pct(b.total_rules, addressed),
            "sample_objects": sorted(b.objects)[:5],
        } for i, b in enumerate(ranked if top <= 0 else ranked[:top])],
    }
    if include_all:
        out["all_subnets"] = [{
            "subnet": b.key, "aggregate": b.aggregate, "rules": b.total_rules,
            "src_rules": len(b.src_rules), "dst_rules": len(b.dst_rules),
        } for b in ranked]
    return out
