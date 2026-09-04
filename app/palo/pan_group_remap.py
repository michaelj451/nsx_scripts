#!/usr/bin/env python3
"""app/palo/pan_group_remap.py

CSV-driven IP remap analysis for Panorama address groups. The Palo Alto
counterpart of app/nsx/nsx_object_functions/nsx_group_remap.py: same CSV
format (old_subnet,new_subnet headers), same longest-prefix-first matching,
same offset-preserving remap arithmetic, same range/IPv6 policy (ranges and
IPv6 are analyzed and reported but never remapped; decision 2026-08-26).

The remap primitives (SubnetMap, read_csv_mappings, remap_token,
classify_token, analyze_range_token) deliberately mirror the NSX module
line for line. They are duplicated rather than imported because the NSX
module configures nsx_logs logging at import time and the shared-core
refactor is deferred; tests/test_pan_group_remap.py contains parity tests
that run both implementations against the same inputs so the two cannot
drift silently.

Where NSX groups carry literal IPs in IPAddressExpression.ip_addresses,
Panorama groups carry NAMES of address objects. So the PAN analysis is:
resolve each static member to its address object's value, remap the value,
and report whether an object with the mapped value already exists (reuse)
or would have to be created. Everything here is pure computation; pulling
the data and writing reports is the CLI's job
(tools/pan/pan_group_remap_report.py).
"""
from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

_RANGE_RE = re.compile(r"^\s*([0-9a-fA-F\.:]+)\s*-\s*([0-9a-fA-F\.:]+)\s*$")


class PanRemapError(RuntimeError):
    pass


# =============================================================================
# CSV mapping model (parity with nsx_group_remap)
# =============================================================================

@dataclass(frozen=True)
class SubnetMap:
    old: ipaddress._BaseNetwork
    new: ipaddress._BaseNetwork


def read_csv_mappings(csv_path: Path) -> List[SubnetMap]:
    required = {"old_subnet", "new_subnet"}
    maps: List[SubnetMap] = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise PanRemapError("CSV has no headers.")
        missing = required - set(h.strip() for h in reader.fieldnames)
        if missing:
            raise PanRemapError(f"CSV missing required headers: {sorted(missing)}")
        for row in reader:
            old_s = (row.get("old_subnet") or "").strip()
            new_s = (row.get("new_subnet") or "").strip()
            if not old_s or not new_s:
                continue
            old_net = ipaddress.ip_network(old_s, strict=False)
            new_net = ipaddress.ip_network(new_s, strict=False)
            if old_net.version != new_net.version:
                raise PanRemapError(f"IP version mismatch: {old_net} -> {new_net}")
            maps.append(SubnetMap(old=old_net, new=new_net))
    maps.sort(key=lambda m: (m.old.version, -m.old.prefixlen))
    return maps


# =============================================================================
# Token classification and remapping (parity with nsx_group_remap)
# =============================================================================

def classify_token(s: str) -> str:
    """'ip_range', 'subnet', or 'ip_address' (same rules as the NSX module)."""
    if _RANGE_RE.match(s):
        return "ip_range"
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
            if net.prefixlen < net.max_prefixlen:
                return "subnet"
        except ValueError:
            pass
    return "ip_address"


def _find_mapping_for_ip(ip: ipaddress._BaseAddress, maps: List[SubnetMap]) -> Optional[SubnetMap]:
    for m in maps:
        if ip.version == m.old.version and ip in m.old:
            return m
    return None


def _remap_ip(ip: ipaddress._BaseAddress, m: SubnetMap) -> ipaddress._BaseAddress:
    offset = int(ip) - int(m.old.network_address)
    return ipaddress.ip_address(int(m.new.network_address) + offset)


def remap_token(token: str, maps: List[SubnetMap]) -> str:
    """Remap one host/CIDR/range token; unmapped tokens come back unchanged."""
    token = str(token).strip()
    if not token:
        return token

    mrange = _RANGE_RE.match(token)
    if mrange:
        a = ipaddress.ip_address(mrange.group(1))
        b = ipaddress.ip_address(mrange.group(2))
        ma = _find_mapping_for_ip(a, maps)
        mb = _find_mapping_for_ip(b, maps)
        if ma and mb and ma.old == mb.old:
            return f"{_remap_ip(a, ma)}-{_remap_ip(b, ma)}"
        return token

    try:
        net = ipaddress.ip_network(token, strict=False)
        for m in maps:
            if net.version != m.old.version:
                # Guard the NSX engine lacks: subnet_of raises TypeError on a
                # version mismatch. Never remapped either way.
                continue
            if net == m.old:
                return str(m.new)
            if net.subnet_of(m.old):
                offset = int(net.network_address) - int(m.old.network_address)
                new_base = ipaddress.ip_address(int(m.new.network_address) + offset)
                return str(ipaddress.ip_network(f"{new_base}/{net.prefixlen}", strict=False))
        return token
    except ValueError:
        pass

    try:
        ip = ipaddress.ip_address(token)
        m = _find_mapping_for_ip(ip, maps)
        if not m:
            return token
        return str(_remap_ip(ip, m))
    except ValueError:
        return token


def analyze_range_token(token: str, maps: List[SubnetMap]) -> Dict[str, Any]:
    """Same statuses as the NSX module: mapped / no_change - overlaps /
    no_change - no_mapping."""
    mrange = _RANGE_RE.match(token)
    if not mrange:
        return {}
    a = ipaddress.ip_address(mrange.group(1))
    b = ipaddress.ip_address(mrange.group(2))
    ma = _find_mapping_for_ip(a, maps)
    mb = _find_mapping_for_ip(b, maps)
    if ma and mb and ma.old == mb.old:
        return {"proposed_change": f"{_remap_ip(a, ma)}-{_remap_ip(b, ma)}", "status": "mapped"}
    if ma and mb and ma.old != mb.old:
        return {"proposed_change": None, "status": "no_change - overlaps"}
    return {"proposed_change": None, "status": "no_change - no_mapping"}


# =============================================================================
# PAN address / group resolution
# =============================================================================

def address_value(entry: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """{'kind': 'ip-netmask'|'ip-range'|'fqdn', 'value': text} for a REST
    address entry, or None for shapes we do not analyze (wildcards)."""
    for kind in ("ip-netmask", "ip-range", "fqdn"):
        v = entry.get(kind)
        if isinstance(v, str) and v.strip():
            return {"kind": kind, "value": v.strip()}
    return None


def suggest_object_name(old_name: str, old_value: str, new_value: str) -> str:
    """Name for a would-be created object. When the old object follows the
    value-derived naming this lab uses (h-10.1.1.1, n-10.1.1.0-24), derive
    the new name the same way; otherwise append the mapped value."""
    def flat(v: str) -> str:
        return v.replace("/", "-")
    if flat(old_value) in old_name:
        return old_name.replace(flat(old_value), flat(new_value))
    return f"{old_name}--{flat(new_value)}"


def analyze_groups(
    groups: List[Dict[str, Any]],
    addresses: List[Dict[str, Any]],
    maps: List[SubnetMap],
    *,
    scope: str,
) -> Dict[str, Any]:
    """Analyze one scope (shared or one device group).

    `groups` and `addresses` are REST entries visible in that scope (for a
    DG pass shared + the DG's own objects so member resolution matches what
    Panorama itself sees; flat DG hierarchy assumed).

    Returns {"scope", "groups": [per-group dicts], "values_seen": [...]}
    where each per-group dict carries would_add / already_remapped /
    ranges / never_remapped / unresolved lists.
    """
    name_to_addr: Dict[str, Dict[str, Any]] = {}
    value_to_names: Dict[str, List[str]] = {}
    for a in addresses:
        name = a.get("@name")
        av = address_value(a)
        if not name or not av:
            continue
        name_to_addr[name] = av
        value_to_names.setdefault(av["value"], []).append(name)

    group_names = {g.get("@name") for g in groups}
    out_groups: List[Dict[str, Any]] = []
    values_seen: List[str] = []

    for g in groups:
        gname = g.get("@name", "?")
        result: Dict[str, Any] = {
            "group": gname,
            "scope": scope,
            "would_add": [],
            "already_remapped": [],
            "ranges": [],
            "never_remapped": [],
            "unresolved": [],
            "nested_groups": [],
        }
        if "dynamic" in g:
            result["never_remapped"].append({
                "member": None, "value": g.get("dynamic", {}).get("filter", ""),
                "reason": "dynamic_group",
            })
            out_groups.append(result)
            continue

        members = (g.get("static") or {}).get("member") or []
        if isinstance(members, str):
            members = [members]

        member_values: Dict[str, str] = {}   # member name -> value text
        for m in members:
            if m in name_to_addr:
                member_values[m] = name_to_addr[m]["value"]

        for m in members:
            if m in name_to_addr:
                av = name_to_addr[m]
                value = av["value"]
                values_seen.append(value)
                if av["kind"] == "fqdn":
                    result["never_remapped"].append({"member": m, "value": value, "reason": "fqdn"})
                    continue
                if ":" in value:
                    result["never_remapped"].append({"member": m, "value": value, "reason": "ipv6"})
                    continue
                if av["kind"] == "ip-range":
                    analysis = analyze_range_token(value, maps)
                    result["ranges"].append({"member": m, "range": value,
                                             "proposed_change": analysis.get("proposed_change"),
                                             "status": analysis.get("status", "unknown")})
                    continue
                mapped = remap_token(value, maps)
                # The engine returns a bare host as x.x.x.x/32 (a bare IP
                # parses as a /32 network). PAN ip-netmask values are usually
                # bare, so keep the mapped value in the source's form.
                if "/" not in value and mapped.endswith("/32"):
                    mapped = mapped[: -len("/32")]
                if mapped == value:
                    continue
                # Already remapped when another member of this group carries
                # the mapped value.
                partner = next((n for n, v in member_values.items() if v == mapped), None)
                if partner:
                    result["already_remapped"].append({
                        "member": m, "value": value,
                        "mapped_member": partner, "mapped_value": mapped,
                    })
                    continue
                existing = value_to_names.get(mapped, [])
                result["would_add"].append({
                    "member": m, "value": value, "mapped_value": mapped,
                    "existing_object": existing[0] if existing else None,
                    "suggested_name": None if existing else suggest_object_name(m, value, mapped),
                })
            elif m in group_names:
                result["nested_groups"].append(m)
            else:
                result["unresolved"].append(m)
        out_groups.append(result)

    return {"scope": scope, "groups": out_groups, "values_seen": values_seen}


def looks_like_ip_token(s: str) -> bool:
    """True for a host, CIDR, or range literal (parity with the NSX helper)."""
    if not s:
        return False
    if _RANGE_RE.match(s):
        return True
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def analyze_rules(
    rules: List[Dict[str, Any]],
    addresses: List[Dict[str, Any]],
    groups: List[Dict[str, Any]],
    maps: List[SubnetMap],
    *,
    scope: str,
    rulebase: str,
) -> Dict[str, Any]:
    """Analyze security rule source/destination members in one scope.

    Members can be address object NAMES, address group names (covered by the
    group analysis; recorded as group_refs), or literal IP/CIDR/range tokens.
    Same additive semantics as the group analysis: report what a remap would
    add next to each mapped member, never a removal.

    Returns {"scope", "rulebase", "rules": [per-rule dicts], "values_seen"}.
    """
    name_to_addr: Dict[str, Dict[str, Any]] = {}
    value_to_names: Dict[str, List[str]] = {}
    for a in addresses:
        name = a.get("@name")
        av = address_value(a)
        if not name or not av:
            continue
        name_to_addr[name] = av
        value_to_names.setdefault(av["value"], []).append(name)
    group_names = {g.get("@name") for g in groups}

    out_rules: List[Dict[str, Any]] = []
    values_seen: List[str] = []

    for rule in rules:
        rname = rule.get("@name", "?")
        result: Dict[str, Any] = {
            "rule": rname, "scope": scope, "rulebase": rulebase,
            "would_add": [], "already_remapped": [], "ranges": [],
            "never_remapped": [], "group_refs": [], "unresolved": [],
        }
        for side in ("source", "destination"):
            members = (rule.get(side) or {}).get("member") or []
            if isinstance(members, str):
                members = [members]

            side_values: Dict[str, str] = {}   # member -> value (objects and literals)
            for m in members:
                if m in name_to_addr:
                    side_values[m] = name_to_addr[m]["value"]
                elif looks_like_ip_token(m):
                    side_values[m] = m

            for m in members:
                if m == "any":
                    continue
                kind = None
                if m in name_to_addr:
                    av = name_to_addr[m]
                    value, kind = av["value"], "object"
                    if av["kind"] == "fqdn":
                        result["never_remapped"].append({"side": side, "member": m,
                                                         "value": value, "reason": "fqdn"})
                        continue
                    if av["kind"] == "ip-range":
                        values_seen.append(value)
                        analysis = analyze_range_token(value, maps)
                        result["ranges"].append({"side": side, "member": m, "range": value,
                                                 "proposed_change": analysis.get("proposed_change"),
                                                 "status": analysis.get("status", "unknown")})
                        continue
                elif m in group_names:
                    result["group_refs"].append({"side": side, "group": m})
                    continue
                elif looks_like_ip_token(m):
                    value, kind = m, "literal"
                    if _RANGE_RE.match(m):
                        values_seen.append(value)
                        analysis = analyze_range_token(value, maps)
                        result["ranges"].append({"side": side, "member": m, "range": value,
                                                 "proposed_change": analysis.get("proposed_change"),
                                                 "status": analysis.get("status", "unknown")})
                        continue
                else:
                    result["unresolved"].append({"side": side, "member": m})
                    continue

                values_seen.append(value)
                if ":" in value:
                    result["never_remapped"].append({"side": side, "member": m,
                                                     "value": value, "reason": "ipv6"})
                    continue
                mapped = remap_token(value, maps)
                if "/" not in value and mapped.endswith("/32"):
                    mapped = mapped[: -len("/32")]
                if mapped == value:
                    continue
                partner = next((n for n, v in side_values.items()
                                if v == mapped and n != m), None)
                if partner:
                    result["already_remapped"].append({
                        "side": side, "member": m, "value": value,
                        "mapped_member": partner, "mapped_value": mapped,
                    })
                    continue
                existing = value_to_names.get(mapped, [])
                result["would_add"].append({
                    "side": side, "member": m, "kind": kind,
                    "value": value, "mapped_value": mapped,
                    "existing_object": existing[0] if existing else None,
                    "suggested_name": (None if (existing or kind == "literal")
                                       else suggest_object_name(m, value, mapped)),
                })
        if any(result[k] for k in ("would_add", "already_remapped", "ranges",
                                   "never_remapped", "group_refs", "unresolved")):
            out_rules.append(result)

    return {"scope": scope, "rulebase": rulebase, "rules": out_rules,
            "values_seen": values_seen}


def aggregate_report_items(
    scopes: List[Dict[str, Any]],
    rule_scopes: List[Dict[str, Any]],
    name_locations: Dict[str, str],
) -> Dict[str, Any]:
    """Deduplicate analysis output into ACTIONABLE items.

    A shared address object referenced by thirty rules is ONE object action
    (performed where the object is defined, per name_locations, which comes
    from the REST entries' @location); the referencing rules and groups are
    collapsed into a reference summary. Literal IPs in rules stay one item
    per rule/side because each is a distinct rule edit. Ranges and
    never-remapped values are likewise deduped by member with reference
    lists.
    """
    object_actions: Dict[tuple, Dict[str, Any]] = {}
    literal_adds: List[Dict[str, Any]] = []
    ranges: Dict[tuple, Dict[str, Any]] = {}
    never: Dict[tuple, Dict[str, Any]] = {}

    def obj_ref(item_key: tuple, item: Dict[str, Any], ref: Dict[str, Any]) -> None:
        a = object_actions.setdefault(item_key, {
            "member": item["member"],
            "location": name_locations.get(item["member"], "?"),
            "value": item["value"],
            "mapped_value": item["mapped_value"],
            "existing_object": item.get("existing_object"),
            "suggested_name": item.get("suggested_name"),
            "refs": [],
        })
        a["refs"].append(ref)

    def simple_ref(bucket: Dict[tuple, Dict[str, Any]], key: tuple,
                   base: Dict[str, Any], ref: Dict[str, Any]) -> None:
        e = bucket.setdefault(key, {**base, "refs": []})
        e["refs"].append(ref)

    for s in scopes:
        for g in s["groups"]:
            ref = {"kind": "group", "scope": s["scope"], "name": g["group"]}
            for i in g["would_add"]:
                obj_ref((i["member"], i["value"], i["mapped_value"]), i, ref)
            for i in g["ranges"]:
                simple_ref(ranges, (i["member"], i["range"]),
                           {"member": i["member"], "range": i["range"],
                            "location": name_locations.get(i["member"], "?"),
                            "proposed_change": i["proposed_change"], "status": i["status"]}, ref)
            for i in g["never_remapped"]:
                simple_ref(never, (i.get("member"), i["value"], i["reason"]),
                           {"member": i.get("member"), "value": i["value"],
                            "reason": i["reason"]}, ref)

    for rs in rule_scopes:
        for r in rs["rules"]:
            for i in r["would_add"]:
                ref = {"kind": "rule", "scope": rs["scope"], "rulebase": rs["rulebase"],
                       "name": r["rule"], "side": i["side"]}
                if i["kind"] == "literal":
                    literal_adds.append({**i, "rule": r["rule"], "scope": rs["scope"],
                                         "rulebase": rs["rulebase"]})
                else:
                    obj_ref((i["member"], i["value"], i["mapped_value"]), i, ref)
            for i in r["ranges"]:
                ref = {"kind": "rule", "scope": rs["scope"], "rulebase": rs["rulebase"],
                       "name": r["rule"], "side": i["side"]}
                loc = name_locations.get(i["member"]) or (
                    "(rule literal)" if i["member"] == i["range"] else "?")
                simple_ref(ranges, (i["member"], i["range"]),
                           {"member": i["member"], "range": i["range"], "location": loc,
                            "proposed_change": i["proposed_change"], "status": i["status"]}, ref)
            for i in r["never_remapped"]:
                ref = {"kind": "rule", "scope": rs["scope"], "rulebase": rs["rulebase"],
                       "name": r["rule"], "side": i["side"]}
                simple_ref(never, (i["member"], i["value"], i["reason"]),
                           {"member": i["member"], "value": i["value"],
                            "reason": i["reason"]}, ref)

    return {
        "object_actions": sorted(object_actions.values(),
                                 key=lambda a: (a["location"], a["member"])),
        "literal_adds": literal_adds,
        "ranges": sorted(ranges.values(), key=lambda a: (a["location"], a["member"])),
        "never_remapped": sorted(never.values(),
                                 key=lambda a: (str(a["member"]), a["value"])),
    }


def summarize_refs(refs: List[Dict[str, Any]]) -> str:
    """'2 groups (dg-4-group [dg-4], ...); rules: shared/pre 16, dg-3/pre 4'"""
    groups = [r for r in refs if r["kind"] == "group"]
    rules = [r for r in refs if r["kind"] == "rule"]
    parts = []
    if groups:
        names = ", ".join(f"{r['name']} [{r['scope']}]" for r in groups)
        parts.append(f"{len(groups)} group{'s' if len(groups) != 1 else ''} ({names})")
    if rules:
        counts: Dict[str, int] = {}
        for r in rules:
            key = f"{r['scope']}/{r['rulebase']}"
            counts[key] = counts.get(key, 0) + 1
        detail = ", ".join(f"{k} {v}" for k, v in counts.items())
        parts.append(f"{len(rules)} rule ref{'s' if len(rules) != 1 else ''} ({detail})")
    return "; ".join(parts) if parts else "0 references"


def flatten_updates(agg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The per-target work list: for every group and every rule side, which
    member(s) an additive remap would add there and why. Built from the
    aggregated object actions (the new member is the reused or would-be
    created object) plus the literal adds. One row per target; a target
    referencing several remapped objects gets all its additions in one row.
    """
    buckets: Dict[tuple, Dict[str, Any]] = {}

    def add(kind: str, scope: str, rulebase: Optional[str], name: str,
            side: Optional[str], new_member: str, because: str) -> None:
        key = (kind, scope, rulebase or "", name, side or "")
        b = buckets.setdefault(key, {"kind": kind, "scope": scope,
                                     "rulebase": rulebase, "name": name,
                                     "side": side, "adds": []})
        entry = {"add": new_member, "for": because}
        if entry not in b["adds"]:
            b["adds"].append(entry)

    for a in agg["object_actions"]:
        new_member = a["existing_object"] or a["suggested_name"]
        for ref in a["refs"]:
            add(ref["kind"], ref["scope"], ref.get("rulebase"), ref["name"],
                ref.get("side"), new_member, a["member"])
    for i in agg["literal_adds"]:
        add("rule", i["scope"], i["rulebase"], i["rule"], i["side"],
            i["mapped_value"], f"literal {i['value']}")

    def sort_key(b: Dict[str, Any]):
        return (0 if b["kind"] == "group" else 1,
                0 if b["scope"] == "shared" else 1, b["scope"],
                0 if b["rulebase"] == "pre" else 1,
                b["name"], b["side"] or "")

    return sorted(buckets.values(), key=sort_key)


def csv_coverage(maps: List[SubnetMap], values_seen: List[str]) -> List[Dict[str, Any]]:
    """Per CSV row: how many distinct seen values fall inside old_subnet."""
    out = []
    for m in maps:
        hits = set()
        for v in set(values_seen):
            try:
                if "/" in v:
                    net = ipaddress.ip_network(v, strict=False)
                    if net.version == m.old.version and net.subnet_of(m.old):
                        hits.add(v)
                elif _RANGE_RE.match(v):
                    a, b = (ipaddress.ip_address(x) for x in _RANGE_RE.match(v).groups())
                    if a.version == m.old.version and a in m.old and b in m.old:
                        hits.add(v)
                else:
                    ip = ipaddress.ip_address(v)
                    if ip.version == m.old.version and ip in m.old:
                        hits.add(v)
            except ValueError:
                continue
        out.append({"old_subnet": str(m.old), "new_subnet": str(m.new),
                    "matches": len(hits), "values": sorted(hits)})
    return out
