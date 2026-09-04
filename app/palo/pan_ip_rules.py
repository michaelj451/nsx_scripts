#!/usr/bin/env python3
"""app/palo/pan_ip_rules.py

Pure matching engine for "which Panorama security rules touch these IPs".
The Palo Alto counterpart of the NSX report_vms_in_rules.py idea, IP-driven:
given target IPs/subnets, find every rule whose source or destination
covers any of them, whether the coverage comes from

  - an address object member (host / subnet / range value),
  - an address-group member (static members expanded recursively, nested
    groups followed, cycles tolerated), or
  - a literal IP/CIDR/range token typed straight into the rule.

Exclusions: a target that is FULLY CONTAINED in any exclusion entry is
dropped before matching (partial overlaps are kept and the entry noted).

Everything here is pure computation over REST entries; pulling data and
writing reports is the CLI's job (tools/pan/report_ips_in_rules.py).
FQDN objects and dynamic groups never match (reported as unresolvable
coverage the caller may surface). IPv6 targets are supported; version
mismatches simply never match.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from palo.pan_group_remap import _RANGE_RE, address_value  # same REST shapes


class PanIpRulesError(RuntimeError):
    pass


# =============================================================================
# Input parsing
# =============================================================================

def parse_ip_entry(raw: str) -> Optional[Dict[str, Any]]:
    """One target/exclusion token -> interval entry, or None when invalid.

    Accepts a bare IP (/32 or /128), a CIDR subnet, or a range like
    10.1.1.5-10.1.1.20. Entries are {"raw", "kind", "version", "lo", "hi"}
    where lo/hi are inclusive integer bounds, so hosts, subnets, and ranges
    all match through the same interval arithmetic.
    """
    raw = raw.strip()
    if not raw:
        return None
    m = _RANGE_RE.match(raw)
    if m:
        try:
            a = ipaddress.ip_address(m.group(1))
            b = ipaddress.ip_address(m.group(2))
        except ValueError:
            return None
        if a.version != b.version or int(a) > int(b):
            return None
        return {"raw": raw, "kind": "range", "version": a.version,
                "lo": int(a), "hi": int(b)}
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    kind = "host" if net.prefixlen == net.max_prefixlen else "subnet"
    return {"raw": raw, "kind": kind, "version": net.version,
            "lo": int(net.network_address), "hi": int(net.broadcast_address)}


def parse_ip_lines(text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse a targets/exclusions file: one IP, subnet, or range per line
    (bare IP read as /32, /128 for IPv6), inline # comments stripped.

    Returns (entries, invalid_lines); entries are parse_ip_entry() dicts.
    """
    entries: List[Dict[str, Any]] = []
    invalid: List[str] = []
    for line in text.splitlines():
        raw = line.split("#", 1)[0].strip()
        if not raw:
            continue
        entry = parse_ip_entry(raw)
        if entry:
            entries.append(entry)
        else:
            invalid.append(raw)
    return entries, invalid


def _contains(outer: Dict[str, Any], inner: Dict[str, Any]) -> bool:
    return (outer["version"] == inner["version"]
            and outer["lo"] <= inner["lo"] and outer["hi"] >= inner["hi"])


def _overlaps(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    return (a["version"] == b["version"]
            and a["lo"] <= b["hi"] and b["lo"] <= a["hi"])


def apply_exclusions(
    targets: List[Dict[str, Any]],
    exclusions: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split targets into (kept, excluded). A target is excluded when it is
    fully contained in any exclusion entry; the matching entry is recorded.
    A partial overlap keeps the target but notes the overlapping entry."""
    kept: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []
    for t in targets:
        container = next((e for e in exclusions if _contains(e, t)), None)
        if container:
            excluded.append({**t, "excluded_by": container["raw"]})
            continue
        overlaps = [e["raw"] for e in exclusions if _overlaps(e, t)]
        kept.append({**t, "partial_exclusions": overlaps} if overlaps else t)
    return kept, excluded


# =============================================================================
# Token coverage
# =============================================================================

def token_covers(target: Dict[str, Any], token: str) -> bool:
    """True when an address value token (host, CIDR, or range text) overlaps
    the target entry (a parse_ip_entry() dict). Non-IP tokens (fqdn,
    keywords) never match."""
    entry = parse_ip_entry(token)
    if entry is None:
        return False
    return _overlaps(entry, target)


# =============================================================================
# Group expansion
# =============================================================================

def expand_group(
    name: str,
    groups_by_name: Dict[str, Dict[str, Any]],
    addr_by_name: Dict[str, Dict[str, str]],
    _seen: Optional[frozenset] = None,
) -> List[Dict[str, str]]:
    """Flatten a static address group to [{member, value, via}] where `via`
    is the nesting chain ("outer > inner"). Dynamic groups contribute
    nothing (no live member evaluation here). Cycles are tolerated."""
    seen = _seen or frozenset()
    if name in seen:
        return []
    g = groups_by_name.get(name)
    if g is None:
        return []
    out: List[Dict[str, str]] = []
    members = (g.get("static") or {}).get("member") or []
    if isinstance(members, str):
        members = [members]
    for m in members:
        if m in addr_by_name:
            out.append({"member": m, "value": addr_by_name[m]["value"],
                        "kind": addr_by_name[m]["kind"], "via": name})
        elif m in groups_by_name:
            for hit in expand_group(m, groups_by_name, addr_by_name,
                                    seen | frozenset([name])):
                out.append({**hit, "via": f"{name} > {hit['via']}"})
        else:
            try:
                ipaddress.ip_network(m, strict=False)
                out.append({"member": m, "value": m, "kind": "literal", "via": name})
            except ValueError:
                continue
    return out


# =============================================================================
# Rule matching
# =============================================================================

def match_rules(
    rules: List[Dict[str, Any]],
    addresses: List[Dict[str, Any]],
    groups: List[Dict[str, Any]],
    targets: List[Dict[str, Any]],
    *,
    scope: str,
    rulebase: str,
) -> Dict[str, Any]:
    """Match every rule's source/destination against the targets.

    Returns {"scope", "rulebase", "matched_rules": [...], "any_any_rules":
    [names]}. Each matched rule dict:
      {"rule", "action", "disabled", "matches": [
        {"target", "side", "member", "value", "via"}  # via "" = direct member
      ], "any_sides": ["source"...]}
    A rule with any on BOTH sides goes to any_any_rules (it matches every
    IP; listing per-target adds noise). A rule with any on ONE side is
    reported when the other side matches, with the any side noted.
    """
    addr_by_name: Dict[str, Dict[str, str]] = {}
    for a in addresses:
        av = address_value(a)
        if a.get("@name") and av:
            addr_by_name[a["@name"]] = av
    groups_by_name = {g["@name"]: g for g in groups if g.get("@name")}
    expansion_cache: Dict[str, List[Dict[str, str]]] = {}

    matched_rules: List[Dict[str, Any]] = []
    any_any: List[str] = []

    for rule in rules:
        rname = rule.get("@name", "?")
        sides: Dict[str, List[str]] = {}
        for side in ("source", "destination"):
            members = (rule.get(side) or {}).get("member") or []
            if isinstance(members, str):
                members = [members]
            sides[side] = members

        if all(ms == ["any"] for ms in sides.values()):
            any_any.append(rname)
            continue

        matches: List[Dict[str, Any]] = []
        any_sides = [s for s, ms in sides.items() if ms == ["any"]]

        for side, members in sides.items():
            if members == ["any"]:
                continue
            for m in members:
                candidates: List[Dict[str, str]]
                if m in addr_by_name:
                    av = addr_by_name[m]
                    candidates = [{"member": m, "value": av["value"],
                                   "kind": av["kind"], "via": ""}]
                elif m in groups_by_name:
                    if m not in expansion_cache:
                        expansion_cache[m] = expand_group(m, groups_by_name, addr_by_name)
                    candidates = expansion_cache[m]
                else:
                    candidates = [{"member": m, "value": m, "kind": "literal", "via": ""}]
                for c in candidates:
                    if c["kind"] == "fqdn":
                        continue
                    for t in targets:
                        if token_covers(t, c["value"]):
                            matches.append({"target": t["raw"], "side": side,
                                            "member": c["member"], "value": c["value"],
                                            "via": c["via"]})
        if matches:
            matched_rules.append({
                "rule": rname, "scope": scope, "rulebase": rulebase,
                "action": rule.get("action"),
                "disabled": rule.get("disabled") == "yes",
                "matches": matches,
                "any_sides": any_sides,
            })

    return {"scope": scope, "rulebase": rulebase,
            "matched_rules": matched_rules, "any_any_rules": any_any}
