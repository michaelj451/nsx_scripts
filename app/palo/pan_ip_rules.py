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

# =============================================================================
# Flow matching (src -> dst [port] against a rule evaluation chain)
# =============================================================================

# PAN-OS built-in service objects, present even when not in the pulled config.
PREDEFINED_SERVICES = {
    "service-http": {"protocol": {"tcp": {"port": "80,8080"}}},
    "service-https": {"protocol": {"tcp": {"port": "443"}}},
}


def parse_port_spec(text: str) -> Optional[Dict[str, Any]]:
    """'443' or 'tcp/443' or 'udp/53' -> {"proto": None|'tcp'|'udp',
    "port": int}. Empty -> None. Raises ValueError on garbage."""
    text = (text or "").strip().lower()
    if not text:
        return None
    proto = None
    if "/" in text:
        proto, _, text = text.partition("/")
        if proto not in ("tcp", "udp"):
            raise ValueError(f"Protocol must be tcp or udp, got {proto!r}")
    if not text.isdigit() or not (0 < int(text) < 65536):
        raise ValueError(f"Port must be 1-65535, got {text!r}")
    return {"proto": proto, "port": int(text)}


def _service_port_ranges(entry: Dict[str, Any]):
    for proto in ("tcp", "udp"):
        spec = (entry.get("protocol") or {}).get(proto) or {}
        for token in str(spec.get("port") or "").split(","):
            token = token.strip()
            if not token:
                continue
            lo, _, hi = token.partition("-")
            try:
                yield proto, int(lo), int(hi or lo)
            except ValueError:
                continue


def service_covers(port_spec: Dict[str, Any], entry: Dict[str, Any]) -> bool:
    for proto, lo, hi in _service_port_ranges(entry):
        if (port_spec["proto"] is None or port_spec["proto"] == proto) \
                and lo <= port_spec["port"] <= hi:
            return True
    return False


def _rule_service_coverage(
    members: List[str],
    port_spec: Optional[Dict[str, Any]],
    svc_by_name: Dict[str, Dict[str, Any]],
    svcgrp_by_name: Dict[str, List[str]],
) -> Optional[str]:
    """How the rule's service list covers the port (a description), or None
    when it does not. No port given -> always covered."""
    if port_spec is None:
        return "(no port given)"
    def walk(names: List[str], seen: frozenset) -> Optional[str]:
        for m in names:
            if m in ("any", "application-default"):
                return m
            entry = svc_by_name.get(m) or (
                {"@name": m, **PREDEFINED_SERVICES[m]} if m in PREDEFINED_SERVICES else None)
            if entry and service_covers(port_spec, entry):
                return m
            if m in svcgrp_by_name and m not in seen:
                hit = walk(svcgrp_by_name[m], seen | frozenset([m]))
                if hit:
                    return f"{hit} (in group {m})"
        return None
    return walk(members or ["any"], frozenset())


def _side_coverage(
    members: List[str],
    target: Optional[Dict[str, Any]],
    addr_by_name: Dict[str, Dict[str, str]],
    groups_by_name: Dict[str, Dict[str, Any]],
    expansion_cache: Dict[str, List[Dict[str, str]]],
) -> Optional[str]:
    """How a rule side covers the target entry (description), or None. A
    side is covered by 'any', by an object/literal whose value covers the
    target, or by a group member that does. No target -> pass."""
    if target is None:
        return "(not specified)"
    if members == ["any"]:
        return "any"
    for m in members:
        if m in addr_by_name:
            if token_covers(target, addr_by_name[m]["value"]):
                return f"{m} = {addr_by_name[m]['value']}"
        elif m in groups_by_name:
            if m not in expansion_cache:
                expansion_cache[m] = expand_group(m, groups_by_name, addr_by_name)
            for c in expansion_cache[m]:
                if c["kind"] != "fqdn" and token_covers(target, c["value"]):
                    return f"{c['member']} = {c['value']} via group {c['via']}"
        elif token_covers(target, m):
            return f"literal {m}"
    return None


def match_flow(
    chain: List[Dict[str, Any]],
    addresses: List[Dict[str, Any]],
    groups: List[Dict[str, Any]],
    services: List[Dict[str, Any]],
    service_groups: List[Dict[str, Any]],
    *,
    src: Optional[str] = None,
    dst: Optional[str] = None,
    port_spec: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Evaluate a flow against an ordered rule chain.

    chain: [{"scope", "rulebase", "rule": <rule entry>}] in evaluation order
    (shared pre, DG pre, DG post, shared post). src/dst are IP/subnet/range
    strings, both optional but the caller enforces at least one. Returns the
    matching rules in order, each with how every given criterion was covered.
    The first entry is what the firewall would actually apply.
    """
    if src is None and dst is None:
        raise ValueError("At least one of source and destination is required.")
    src_t = parse_ip_entry(src) if src else None
    dst_t = parse_ip_entry(dst) if dst else None
    if src and src_t is None:
        raise ValueError(f"Source is not an IP/subnet/range: {src!r}")
    if dst and dst_t is None:
        raise ValueError(f"Destination is not an IP/subnet/range: {dst!r}")

    addr_by_name = {a["@name"]: address_value(a) for a in addresses
                    if a.get("@name") and address_value(a)}
    groups_by_name = {g["@name"]: g for g in groups if g.get("@name")}
    svc_by_name = {s["@name"]: s for s in services if s.get("@name")}
    svcgrp_by_name = {}
    for g in service_groups:
        members = (g.get("members") or g.get("static") or {}).get("member") or []
        svcgrp_by_name[g.get("@name")] = [members] if isinstance(members, str) else members
    cache: Dict[str, List[Dict[str, str]]] = {}

    out: List[Dict[str, Any]] = []
    for item in chain:
        rule = item["rule"]
        def side(name):
            m = (rule.get(name) or {}).get("member") or []
            return [m] if isinstance(m, str) else m
        src_via = _side_coverage(side("source"), src_t, addr_by_name, groups_by_name, cache)
        if src_via is None:
            continue
        dst_via = _side_coverage(side("destination"), dst_t, addr_by_name, groups_by_name, cache)
        if dst_via is None:
            continue
        svc_via = _rule_service_coverage(side("service"), port_spec,
                                         svc_by_name, svcgrp_by_name)
        if svc_via is None:
            continue
        out.append({
            "scope": item["scope"], "rulebase": item["rulebase"],
            "rule": rule.get("@name", "?"), "action": rule.get("action"),
            "disabled": rule.get("disabled") == "yes",
            "src_via": src_via, "dst_via": dst_via, "service_via": svc_via,
        })
    return out


def _suppressed_by(cand: Optional[Dict[str, Any]],
                   exclusions: List[Dict[str, Any]]) -> Optional[str]:
    """The exclusion entry (raw text) that suppresses a match through this
    candidate value: suppression applies when the candidate's coverage is
    EQUAL TO OR BROADER THAN the entry (an aggregate at least that big).
    Narrower, more specific values are never suppressed."""
    if cand is None:
        return None
    for e in exclusions:
        if (e["version"] == cand["version"]
                and cand["lo"] <= e["lo"] and cand["hi"] >= e["hi"]):
            return e["raw"]
    return None


def match_rules(
    rules: List[Dict[str, Any]],
    addresses: List[Dict[str, Any]],
    groups: List[Dict[str, Any]],
    targets: List[Dict[str, Any]],
    *,
    scope: str,
    rulebase: str,
    match_exclusions: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Match every rule's source/destination against the targets.

    Returns {"scope", "rulebase", "matched_rules": [...], "any_any_rules":
    [names], "suppressed": [...]}. Each matched rule dict:
      {"rule", "action", "disabled", "matches": [
        {"target", "side", "member", "value", "via"}  # via "" = direct member
      ], "any_sides": ["source"...]}
    A rule with any on BOTH sides goes to any_any_rules (it matches every
    IP; listing per-target adds noise). A rule with any on ONE side is
    reported when the other side matches, with the any side noted.

    match_exclusions (parse_ip_lines entries) filter MATCH RESULTS: a match
    whose matching value is equal to or broader than an exclusion entry is
    moved to "suppressed" (with the entry that did it) instead of counting.
    """
    match_exclusions = match_exclusions or []
    addr_by_name: Dict[str, Dict[str, str]] = {}
    for a in addresses:
        av = address_value(a)
        if a.get("@name") and av:
            addr_by_name[a["@name"]] = av
    groups_by_name = {g["@name"]: g for g in groups if g.get("@name")}
    expansion_cache: Dict[str, List[Dict[str, str]]] = {}

    matched_rules: List[Dict[str, Any]] = []
    any_any: List[str] = []
    suppressed: List[Dict[str, Any]] = []

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
                    cand_entry = parse_ip_entry(c["value"])
                    excl = _suppressed_by(cand_entry, match_exclusions)
                    for t in targets:
                        if token_covers(t, c["value"]):
                            hit = {"target": t["raw"], "side": side,
                                   "member": c["member"], "value": c["value"],
                                   "via": c["via"]}
                            if excl:
                                suppressed.append({**hit, "rule": rname,
                                                   "excluded_by": excl})
                            else:
                                matches.append(hit)
        if matches:
            matched_rules.append({
                "rule": rname, "scope": scope, "rulebase": rulebase,
                "action": rule.get("action"),
                "disabled": rule.get("disabled") == "yes",
                "matches": matches,
                "any_sides": any_sides,
            })

    return {"scope": scope, "rulebase": rulebase,
            "matched_rules": matched_rules, "any_any_rules": any_any,
            "suppressed": suppressed}
