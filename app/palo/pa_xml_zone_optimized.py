#!/usr/bin/env python3
"""
Usage:
  python pa_xml_zone.py --config running-config.xml --csv ip_map.txt --dg dg_zone.txt --out modified-config.xml --changelog changelog.json [--resolve-fqdn]

Drop-in replacement focused on speed:
- Builds indexes ONCE (addresses, rules, groups, member references)
- Avoids repeated .findall('.//...') scans per CSV row
- Updates the indexes incrementally as it creates objects / adds members
"""
from __future__ import annotations

import argparse
import bisect
import csv
import ipaddress
import json
import socket
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Iterable


# ---------- Utilities ----------
def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entry_name(elem: Optional[ET.Element]) -> Optional[str]:
    if elem is None:
        return None
    return elem.attrib.get("name")


def underscored(s: str) -> str:
    return s.replace(".", "_").replace("/", "_").replace(":", "_")


def gen_default_name_for_ip(ip_text: str) -> str:
    return f"svb_m1_{underscored(ip_text)}"


def find_shared_address_parent(root: ET.Element) -> ET.Element:
    """Return <shared>/<address> parent or create one."""
    candidate = root.find(".//shared/address")
    if candidate is not None:
        return candidate
    any_addr = root.find(".//address")
    if any_addr is not None:
        return any_addr
    cfg = root.find("devices") or root
    shared = cfg.find("shared")
    if shared is None:
        shared = ET.SubElement(cfg, "shared")
    address = shared.find("address")
    if address is None:
        address = ET.SubElement(shared, "address")
    return address


# ---------- Parsing helpers ----------
_RANGE_SEPS = [" - ", "-", ",", " "]


def parse_range_text(s: str) -> Optional[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]]:
    s = s.strip()
    for sep in _RANGE_SEPS:
        if sep in s:
            parts = [p.strip() for p in s.split(sep) if p.strip()]
            if len(parts) >= 2:
                try:
                    start = ipaddress.ip_address(parts[0])
                    end = ipaddress.ip_address(parts[-1])
                    return (start, end)
                except Exception:
                    return None
    return None


def normalize_ip_kind(ip_text: str) -> Tuple[str, object]:
    """
    Returns (kind, parsed)
      kind: 'net' | 'host' | 'range' | 'raw'
      parsed: ip_network | ip_address | (start,end) | raw_str
    """
    ip_text = (ip_text or "").strip()
    if not ip_text:
        return ("raw", "")
    rg = parse_range_text(ip_text)
    if rg is not None:
        return ("range", rg)
    try:
        if "/" in ip_text:
            return ("net", ipaddress.ip_network(ip_text, strict=False))
        return ("host", ipaddress.ip_address(ip_text))
    except Exception:
        return ("raw", ip_text)


def ip_int(addr: ipaddress._BaseAddress) -> int:
    return int(addr)


# ---------- Context / Indexes ----------
@dataclass(frozen=True)
class MemberLoc:
    parent: ET.Element          # rule entry or group entry
    section_tag: str            # 'source','destination','static'
    dg_name: str                # device-group name or 'shared'
    is_group: bool              # group vs rule


@dataclass
class RangeRec:
    start_i: int
    end_i: int
    obj_name: str
    text: str                   # original text (for changelog)
    entry_elem: ET.Element


@dataclass
class Context:
    root: ET.Element

    # Address object indexes
    name_to_entry: Dict[str, ET.Element]
    host_to_obj: Dict[str, str]                               # "1.2.3.4" -> obj_name
    net_to_obj: Dict[ipaddress._BaseNetwork, str]             # ip_network -> obj_name
    raw_to_obj: Dict[str, str]                                # raw literal -> obj_name
    ranges_v4: List[RangeRec]                                 # sorted by start_i
    ranges_v6: List[RangeRec]                                 # sorted by start_i

    # Rules/groups
    dg_rule_map: List[Tuple[ET.Element, str]]                 # (rule_elem, dg_name)
    groups: List[ET.Element]                                  # address-group/entry elems

    # Member references index: member text -> list of locations where it appears
    member_index: Dict[str, List[MemberLoc]]

    # Literal-IP members (from rules/groups) for fast range search
    literal_ips_v4: List[Tuple[int, str]]                     # sorted by int
    literal_ips_v6: List[Tuple[int, str]]                     # sorted by int

    # fqdn address objects (entry_elem, fqdn_text)
    fqdn_entries: List[Tuple[ET.Element, str]]


def build_context(root: ET.Element) -> Context:
    # Collect address entries once
    name_to_entry: Dict[str, ET.Element] = {}
    host_to_obj: Dict[str, str] = {}
    net_to_obj: Dict[ipaddress._BaseNetwork, str] = {}
    raw_to_obj: Dict[str, str] = {}
    ranges_v4: List[RangeRec] = []
    ranges_v6: List[RangeRec] = []
    fqdn_entries: List[Tuple[ET.Element, str]] = []

    for e in root.findall(".//address/entry"):
        nm = entry_name(e)
        if not nm:
            continue
        name_to_entry[nm] = e

        ipnm = e.find("ip-netmask")
        if ipnm is not None and ipnm.text and ipnm.text.strip():
            txt = ipnm.text.strip()
            kind, parsed = normalize_ip_kind(txt)
            if kind == "host":
                host_to_obj[str(parsed)] = nm
            elif kind == "net":
                net_to_obj[parsed] = nm
            elif kind == "raw":
                raw_to_obj[txt] = nm

        ipr = e.find("ip-range")
        if ipr is not None and ipr.text and ipr.text.strip():
            txt = ipr.text.strip()
            kind, parsed = normalize_ip_kind(txt)
            if kind == "range":
                s, t = parsed  # type: ignore[misc]
                rec = RangeRec(ip_int(s), ip_int(t), nm, txt, e)
                (ranges_v4 if s.version == 4 else ranges_v6).append(rec)
            else:
                raw_to_obj[txt] = nm

        fq = e.find("fqdn")
        if fq is not None and fq.text and fq.text.strip():
            fqdn_entries.append((e, fq.text.strip()))

    ranges_v4.sort(key=lambda r: r.start_i)
    ranges_v6.sort(key=lambda r: r.start_i)

    # Build list of rules grouped by device-group (once)
    dg_rule_map: List[Tuple[ET.Element, str]] = []
    seen_rule_ids = set()

    for dg in root.findall(".//devices/entry/device-group/entry"):
        dg_name = dg.attrib.get("name")
        if not dg_name:
            continue

        # pre-rulebase security
        for r in dg.findall(".//pre-rulebase//security//rules/entry"):
            rid = id(r)
            if rid not in seen_rule_ids:
                dg_rule_map.append((r, dg_name))
                seen_rule_ids.add(rid)

        # post-rulebase application-override
        for r in dg.findall(".//post-rulebase//application-override//rules/entry"):
            rid = id(r)
            if rid not in seen_rule_ids:
                dg_rule_map.append((r, dg_name))
                seen_rule_ids.add(rid)

        # conservative: any security rules under this dg
        for r in dg.findall(".//security//rules/entry"):
            rid = id(r)
            if rid not in seen_rule_ids:
                dg_rule_map.append((r, dg_name))
                seen_rule_ids.add(rid)

    # shared/global rules
    for path in [
        ".//shared//pre-rulebase//security//rules/entry",
        ".//shared//post-rulebase//security//rules/entry",
        ".//shared//post-rulebase//application-override//rules/entry",
    ]:
        for r in root.findall(path):
            rid = id(r)
            if rid not in seen_rule_ids:
                dg_rule_map.append((r, "shared"))
                seen_rule_ids.add(rid)

    groups = root.findall(".//address-group/entry")

    # Build member_index once
    member_index: Dict[str, List[MemberLoc]] = {}

    def index_members(parent: ET.Element, section_tag: str, dg_name: str, is_group: bool) -> None:
        sec = parent.find(section_tag)
        if sec is None:
            return
        for m in sec.findall("member"):
            if not (m.text and m.text.strip()):
                continue
            txt = m.text.strip()
            member_index.setdefault(txt, []).append(MemberLoc(parent, section_tag, dg_name, is_group))

    for r, dg_name in dg_rule_map:
        index_members(r, "source", dg_name, is_group=False)
        index_members(r, "destination", dg_name, is_group=False)

    for g in groups:
        index_members(g, "static", dg_name="(group)", is_group=True)

    # Build literal IP lists for quick range matching in member_index keys
    literal_ips_v4: List[Tuple[int, str]] = []
    literal_ips_v6: List[Tuple[int, str]] = []
    for txt in member_index.keys():
        try:
            ip_obj = ipaddress.ip_address(txt)
            pair = (ip_int(ip_obj), txt)
            (literal_ips_v4 if ip_obj.version == 4 else literal_ips_v6).append(pair)
        except Exception:
            continue
    literal_ips_v4.sort(key=lambda x: x[0])
    literal_ips_v6.sort(key=lambda x: x[0])

    return Context(
        root=root,
        name_to_entry=name_to_entry,
        host_to_obj=host_to_obj,
        net_to_obj=net_to_obj,
        raw_to_obj=raw_to_obj,
        ranges_v4=ranges_v4,
        ranges_v6=ranges_v6,
        dg_rule_map=dg_rule_map,
        groups=groups,
        member_index=member_index,
        literal_ips_v4=literal_ips_v4,
        literal_ips_v6=literal_ips_v6,
        fqdn_entries=fqdn_entries,
    )


# ---------- Fast lookup helpers ----------
def find_range_containing(ctx: Context, host: ipaddress._BaseAddress) -> Optional[Tuple[ET.Element, str, str]]:
    """Return (entry_elem, match_type, match_text) if host is contained in any known range."""
    ranges = ctx.ranges_v4 if host.version == 4 else ctx.ranges_v6
    if not ranges:
        return None
    h = ip_int(host)
    starts = [r.start_i for r in ranges]
    i = bisect.bisect_right(starts, h) - 1
    # scan backward a bit (ranges may overlap / same start)
    for j in range(i, max(-1, i - 32), -1):
        if j < 0:
            break
        rr = ranges[j]
        if rr.start_i <= h <= rr.end_i:
            return (rr.entry_elem, "range_contains", rr.text)
        if rr.start_i < 0 or rr.start_i > h:
            continue
        # if this range starts way before but doesn't contain, keep scanning a bit
    return None


def find_existing_object_for_ip(ctx: Context, ip_text: str) -> Tuple[Optional[ET.Element], Optional[str], Optional[str]]:
    """
    Returns (entry_elem, match_type, match_text) or (None,None,None)
      match_type: exact_net, exact_host, exact_range, range_contains, raw_match
    """
    kind, parsed = normalize_ip_kind(ip_text)
    if kind == "host":
        host = parsed  # type: ignore[assignment]
        nm = ctx.host_to_obj.get(str(host))
        if nm:
            return (ctx.name_to_entry.get(nm), "exact_host", str(host))
        cont = find_range_containing(ctx, host)  # type: ignore[arg-type]
        if cont:
            return cont
        return (None, None, None)

    if kind == "net":
        net = parsed  # type: ignore[assignment]
        nm = ctx.net_to_obj.get(net)
        if nm:
            return (ctx.name_to_entry.get(nm), "exact_net", str(net))
        return (None, None, None)

    if kind == "range":
        s, t = parsed  # type: ignore[misc]
        ranges = ctx.ranges_v4 if s.version == 4 else ctx.ranges_v6
        for rr in ranges:
            if rr.start_i == ip_int(s) and rr.end_i == ip_int(t):
                return (rr.entry_elem, "exact_range", rr.text)
        return (None, None, None)

    # raw
    raw = str(parsed)
    nm = ctx.raw_to_obj.get(raw)
    if nm:
        return (ctx.name_to_entry.get(nm), "raw_match", raw)
    return (None, None, None)


def name_conflict_exists(ctx: Context, preferred_name: str) -> Optional[ET.Element]:
    return ctx.name_to_entry.get(preferred_name)


def create_address_object(ctx: Context, ip_text: str, preferred_name: str, description: Optional[str] = None, tags: Optional[str] = None) -> ET.Element:
    parent = find_shared_address_parent(ctx.root)

    name = preferred_name
    base = name
    i = 0
    while name in ctx.name_to_entry:
        i += 1
        name = f"{base}_auto{i}"

    e = ET.SubElement(parent, "entry", {"name": name})

    kind, parsed = normalize_ip_kind(ip_text)
    if kind == "net" or kind == "host":
        ipnm = ET.SubElement(e, "ip-netmask")
        ipnm.text = ip_text
    elif kind == "range":
        ipr = ET.SubElement(e, "ip-range")
        ipr.text = ip_text
    else:
        # keep original behavior: raw goes into ip-netmask
        ipnm = ET.SubElement(e, "ip-netmask")
        ipnm.text = ip_text

    if description:
        d = ET.SubElement(e, "description")
        d.text = description
    if tags:
        tag_elem = ET.SubElement(e, "tag")
        for t in [x.strip() for x in tags.split(",") if x.strip()]:
            ET.SubElement(tag_elem, "member").text = t

    # update indexes
    ctx.name_to_entry[name] = e
    if kind == "host":
        ctx.host_to_obj[str(parsed)] = name  # type: ignore[arg-type]
    elif kind == "net":
        ctx.net_to_obj[parsed] = name  # type: ignore[index]
    elif kind == "range":
        s, t = parsed  # type: ignore[misc]
        rec = RangeRec(ip_int(s), ip_int(t), name, ip_text.strip(), e)
        if s.version == 4:
            ctx.ranges_v4.append(rec)
            ctx.ranges_v4.sort(key=lambda r: r.start_i)
        else:
            ctx.ranges_v6.append(rec)
            ctx.ranges_v6.sort(key=lambda r: r.start_i)
    else:
        ctx.raw_to_obj[ip_text.strip()] = name

    return e


def ensure_object_and_reuse_if_present(
    ctx: Context,
    ip_text: str,
    preferred_name: Optional[str],
    description: Optional[str],
    tags: Optional[str],
    changelog: list,
    based_on: Optional[str] = None,
) -> str:
    existing_entry, match_type, match_text = find_existing_object_for_ip(ctx, ip_text)
    if existing_entry is not None:
        name = entry_name(existing_entry) or ""
        changelog.append(
            {
                "timestamp": ts(),
                "action": "reuse_existing_object",
                "ip": ip_text,
                "existing_object": name,
                "match_type": match_type,
                "match_text": match_text,
                "based_on": based_on,
            }
        )
        return name

    if preferred_name:
        conflict = name_conflict_exists(ctx, preferred_name)
        if conflict is None:
            create_address_object(ctx, ip_text, preferred_name, description, tags)
            changelog.append({"timestamp": ts(), "action": "create_object", "ip": ip_text, "name": preferred_name, "based_on": based_on})
            return preferred_name
        else:
            # name exists; if it already matches this ip_text, reuse it; otherwise create auto-suffixed
            existing_ipvals = [n.text.strip() for n in conflict.findall("ip-netmask") if n.text and n.text.strip()]
            existing_ipranges = [n.text.strip() for n in conflict.findall("ip-range") if n.text and n.text.strip()]
            if ip_text in existing_ipvals or ip_text in existing_ipranges:
                changelog.append(
                    {
                        "timestamp": ts(),
                        "action": "reuse_existing_object_by_name_match",
                        "ip": ip_text,
                        "existing_object": preferred_name,
                        "based_on": based_on,
                    }
                )
                return preferred_name

            new_e = create_address_object(ctx, ip_text, preferred_name, description, tags)
            new_name = entry_name(new_e) or preferred_name
            changelog.append(
                {
                    "timestamp": ts(),
                    "action": "create_object_name_conflict",
                    "requested_name": preferred_name,
                    "created_name": new_name,
                    "ip": ip_text,
                    "based_on": based_on,
                }
            )
            return new_name

    default_name = gen_default_name_for_ip(ip_text)
    new_e = create_address_object(ctx, ip_text, default_name, description, tags)
    nm = entry_name(new_e) or default_name
    changelog.append({"timestamp": ts(), "action": "create_object", "ip": ip_text, "name": nm, "based_on": based_on})
    return nm


# ---------- Rule/group update helpers ----------
def update_zone_if_needed(rule_elem: ET.Element, dg_name: str, dg_zone_map: Dict[str, str], changelog: list, sections: List[str]) -> None:
    if dg_name not in dg_zone_map:
        return
    zone_to_add = dg_zone_map[dg_name]
    for section_tag in sections:
        sec = rule_elem.find(section_tag)
        if sec is None:
            sec = ET.SubElement(rule_elem, section_tag)
        existing = [m.text for m in sec.findall("member") if m.text]
        if zone_to_add not in existing:
            ET.SubElement(sec, "member").text = zone_to_add
            changelog.append(
                {
                    "timestamp": ts(),
                    "action": "update_zone",
                    "rule": entry_name(rule_elem),
                    "device_group": dg_name,
                    "section": section_tag,
                    "added_zone": zone_to_add,
                }
            )


def ensure_object_for_literal(ctx: Context, literal_val: str, changelog: list) -> None:
    # Create object for literal IP if no object exists; keep original behavior: ensure exists, but don't add it.
    _ = ensure_object_and_reuse_if_present(ctx, literal_val, None, None, None, changelog, based_on=f"literal_{literal_val}")


def add_members_and_index(ctx: Context, sec: ET.Element, parent: ET.Element, section_tag: str, dg_name: str, is_group: bool, to_add: Iterable[str]) -> List[str]:
    existing = [m.text for m in sec.findall("member") if m.text]
    added: List[str] = []
    for a in dict.fromkeys([x for x in to_add if x]):  # stable unique
        if a not in existing:
            ET.SubElement(sec, "member").text = a
            existing.append(a)
            added.append(a)
            ctx.member_index.setdefault(a, []).append(MemberLoc(parent, section_tag, dg_name, is_group))
    return added


def update_locations_for_match(
    ctx: Context,
    dg_zone_map: Dict[str, str],
    match_literal: str,
    match_obj_name: Optional[str],
    new_names: List[str],
    changelog: list,
    context: Optional[str] = None,
) -> Tuple[bool, bool]:
    """
    Find every location where match_literal OR match_obj_name appears (via member_index),
    then add new_names to that same section.
    Returns (any_source_updated, any_dest_updated) for zone injection.
    """
    locs: List[MemberLoc] = []
    if match_literal in ctx.member_index:
        locs.extend(ctx.member_index[match_literal])
    if match_obj_name and match_obj_name in ctx.member_index:
        locs.extend(ctx.member_index[match_obj_name])

    any_source = False
    any_dest = False

    # De-dupe locations (same parent/section/dg/is_group)
    seen = set()
    for loc in locs:
        key = (id(loc.parent), loc.section_tag, loc.dg_name, loc.is_group)
        if key in seen:
            continue
        seen.add(key)

        sec = loc.parent.find(loc.section_tag)
        if sec is None:
            continue

        before = [m.text for m in sec.findall("member") if m.text]
        added = add_members_and_index(ctx, sec, loc.parent, loc.section_tag, loc.dg_name, loc.is_group, new_names)
        after = [m.text for m in sec.findall("member") if m.text]

        if not added:
            continue

        if loc.is_group:
            action = "add_group_member"
            keyname = "group"
        else:
            action = "add_member"
            keyname = "rule"
            if loc.section_tag == "source":
                any_source = True
            if loc.section_tag == "destination":
                any_dest = True

        changelog.append(
            {
                "timestamp": ts(),
                "action": action,
                keyname: entry_name(loc.parent),
                "section": loc.section_tag,
                "added": added,
                "before": before,
                "after": after,
                "context": context,
            }
        )

        # zone injection for rules
        if not loc.is_group:
            sections: List[str] = []
            if loc.section_tag == "source":
                sections.append("from")
            if loc.section_tag == "destination":
                sections.append("to")
            if sections and loc.dg_name in dg_zone_map:
                update_zone_if_needed(loc.parent, loc.dg_name, dg_zone_map, changelog, sections)

    return any_source, any_dest


# ---------- FQDN resolution ----------
def resolve_fqdn(fqdn: str, changelog: list) -> List[str]:
    try:
        ips: List[str] = []
        for res in socket.getaddrinfo(fqdn, None):
            ip = res[4][0]
            if ip not in ips:
                ips.append(ip)
        changelog.append({"timestamp": ts(), "action": "fqdn_resolution", "fqdn": fqdn, "ips": ips})
        return ips
    except Exception as e:
        changelog.append({"timestamp": ts(), "action": "fqdn_resolution_failed", "fqdn": fqdn, "error": str(e)})
        return []


# ---------- Matching helpers (fast) ----------
def ips_in_network_from_literal_list(net: ipaddress._BaseNetwork, literal_list: List[Tuple[int, str]]) -> List[str]:
    start = int(net.network_address)
    end = int(net.broadcast_address) if hasattr(net, "broadcast_address") else int(net[-1])  # IPv6 ok with [-1]
    left = bisect.bisect_left(literal_list, (start, ""))
    right = bisect.bisect_right(literal_list, (end, "\uffff"))
    return [s for _, s in literal_list[left:right]]


def process_row(
    ctx: Context,
    dg_zone_map: Dict[str, str],
    search_ip_text: str,
    new_ip_text: str,
    preferred_name: Optional[str],
    tags: Optional[str],
    description: Optional[str],
    changelog: list,
    resolve_fqdn_flag: bool = False,
) -> None:
    search_ip_text = search_ip_text.strip()
    new_ip_text = new_ip_text.strip()

    s_kind, s_parsed = normalize_ip_kind(search_ip_text)
    n_kind, n_parsed = normalize_ip_kind(new_ip_text)

    # version sanity when both are valid IP constructs
    def get_version(kind: str, parsed: object) -> Optional[int]:
        if kind == "host":
            return parsed.version  # type: ignore[attr-defined]
        if kind == "net":
            return parsed.version  # type: ignore[attr-defined]
        if kind == "range":
            return parsed[0].version  # type: ignore[index]
        return None

    sv = get_version(s_kind, s_parsed)
    nv = get_version(n_kind, n_parsed)
    if sv is not None and nv is not None and sv != nv:
        changelog.append(
            {
                "timestamp": ts(),
                "action": "version_mismatch",
                "search_ip": search_ip_text,
                "new_ip": new_ip_text,
                "search_version": sv,
                "new_version": nv,
            }
        )
        return

    # If new_ip is network/range, ensure object exists once
    new_container_name: Optional[str] = None
    if n_kind in ("net", "range"):
        new_container_name = ensure_object_and_reuse_if_present(
            ctx, new_ip_text, preferred_name, description, tags, changelog, based_on=f"{search_ip_text}->{new_ip_text}"
        )

    # Find existing object name for search net/range if present
    search_obj_name: Optional[str] = None
    if s_kind == "net":
        search_obj_name = ctx.net_to_obj.get(s_parsed)  # type: ignore[arg-type]
    elif s_kind == "range":
        s0, s1 = s_parsed  # type: ignore[misc]
        rr_list = ctx.ranges_v4 if s0.version == 4 else ctx.ranges_v6
        for rr in rr_list:
            if rr.start_i == ip_int(s0) and rr.end_i == ip_int(s1):
                search_obj_name = rr.obj_name
                break

    # Determine matched hosts (address objects + literal members)
    matched_host_strs: set[str] = set()

    if s_kind == "net":
        net = s_parsed  # type: ignore[assignment]
        # from address objects
        for ip_str in ctx.host_to_obj.keys():
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj in net:
                    matched_host_strs.add(ip_str)
            except Exception:
                continue
        # from literal members (fast via bisect)
        ll = ctx.literal_ips_v4 if net.version == 4 else ctx.literal_ips_v6
        for ip_str in ips_in_network_from_literal_list(net, ll):
            matched_host_strs.add(ip_str)

        # fqdn resolve optional (still potentially expensive)
        if resolve_fqdn_flag and ctx.fqdn_entries:
            for entry_elem, fqdn in ctx.fqdn_entries:
                ips = resolve_fqdn(fqdn, changelog)
                if not ips:
                    changelog.append({"timestamp": ts(), "action": "fqdn_reference_unresolved", "fqdn": fqdn, "object": entry_name(entry_elem)})
                    continue
                for ipstr in ips:
                    try:
                        ip_obj = ipaddress.ip_address(ipstr)
                        if ip_obj in net:
                            matched_host_strs.add(ipstr)
                            # treat fqdn object as host object for mapping lookups
                            ename = entry_name(entry_elem)
                            if ename:
                                ctx.host_to_obj[ipstr] = ename
                    except Exception:
                        continue

    elif s_kind == "host":
        host = s_parsed  # type: ignore[assignment]
        matched_host_strs.add(str(host))
    else:
        # search is range or raw: host-level match list is hard/undefined; we rely on network/range-level update below.
        matched_host_strs = set()

    # ---- Process each matched host ----
    # sort by int to keep stable, original-ish behavior
    def sort_key(ip_str: str) -> int:
        try:
            return int(ipaddress.ip_address(ip_str))
        except Exception:
            return 0

    for host_str in sorted(matched_host_strs, key=sort_key):
        # compute mapped ip for host
        mapped_ip = new_ip_text
        if s_kind == "net" and n_kind == "net":
            s_net = s_parsed  # type: ignore[assignment]
            n_net = n_parsed  # type: ignore[assignment]
            try:
                host_ip = ipaddress.ip_address(host_str)
                offset = int(host_ip) - int(s_net.network_address)
                mapped_ip = str(ipaddress.ip_address(int(n_net.network_address) + offset))
            except Exception:
                mapped_ip = new_ip_text

        used_obj_name = ensure_object_and_reuse_if_present(
            ctx, mapped_ip, preferred_name, description, tags, changelog, based_on=f"{host_str}->{mapped_ip}"
        )
        orig_obj_name = ctx.host_to_obj.get(host_str)

        # Update rules/groups where host literal OR orig object name appears
        update_locations_for_match(
            ctx,
            dg_zone_map,
            match_literal=host_str,
            match_obj_name=orig_obj_name,
            new_names=[used_obj_name],
            changelog=changelog,
            context=f"mapped_from_{host_str}_based_on_{orig_obj_name or 'literal'}",
        )

    # ---- Network/Range-level mapping: add mapped network/range object to rules/groups referencing original net/range ----
    if s_kind in ("net", "range") and new_container_name:
        # ensure object for literal if rules reference the literal CIDR/range string
        # (original behavior only ensured object for host literal; keeping it light here)
        update_locations_for_match(
            ctx,
            dg_zone_map,
            match_literal=search_ip_text,
            match_obj_name=search_obj_name,
            new_names=[new_container_name],
            changelog=changelog,
            context=f"network_mapping_{search_ip_text}->{new_ip_text}",
        )

    # ---- For host search, handle containing networks/ranges in address objects ----
    if s_kind == "host" and n_kind in ("host", "net", "range"):
        try:
            search_host = s_parsed  # type: ignore[assignment]
            new_host = n_parsed if n_kind == "host" else None
        except Exception:
            search_host = None
            new_host = None

        if search_host is not None and new_host is not None:
            # find containers that contain search_host (nets + ranges from address objects)
            containing: List[Tuple[str, str]] = []  # (container_text, container_obj_name)
            for net, objn in ctx.net_to_obj.items():
                try:
                    if search_host in net:
                        containing.append((str(net), objn))
                except Exception:
                    continue

            rr_list = ctx.ranges_v4 if search_host.version == 4 else ctx.ranges_v6
            for rr in rr_list:
                if rr.start_i <= ip_int(search_host) <= rr.end_i:
                    containing.append((rr.text, rr.obj_name))

            # derive mapped containers and update references
            used_obj_name = ensure_object_and_reuse_if_present(
                ctx, str(new_host), preferred_name, description, tags, changelog, based_on=f"{search_ip_text}->{new_ip_text}"
            )

            for cont_text, cont_obj_name in containing:
                c_kind, c_parsed = normalize_ip_kind(cont_text)
                mapped_cont_name: Optional[str] = None

                if c_kind == "net":
                    cont_net = c_parsed  # type: ignore[assignment]
                    offset = int(search_host) - int(cont_net.network_address)
                    new_cont_addr_int = int(new_host) - offset
                    new_cont_net_str = f"{ipaddress.ip_address(new_cont_addr_int)}/{cont_net.prefixlen}"
                    mapped_cont_name = ensure_object_and_reuse_if_present(
                        ctx,
                        new_cont_net_str,
                        preferred_name,
                        description,
                        tags,
                        changelog,
                        based_on=f"derived_net_from_{search_ip_text}_in_{cont_text}",
                    )
                elif c_kind == "range":
                    s0, t0 = c_parsed  # type: ignore[misc]
                    host_offset = int(search_host) - int(s0)
                    new_s_int = int(new_host) - host_offset
                    range_size = int(t0) - int(s0)
                    new_t_int = new_s_int + range_size
                    new_range_str = f"{ipaddress.ip_address(new_s_int)} - {ipaddress.ip_address(new_t_int)}"
                    mapped_cont_name = ensure_object_and_reuse_if_present(
                        ctx,
                        new_range_str,
                        preferred_name,
                        description,
                        tags,
                        changelog,
                        based_on=f"derived_range_from_{search_ip_text}_in_{cont_text}",
                    )

                if not mapped_cont_name:
                    continue

                update_locations_for_match(
                    ctx,
                    dg_zone_map,
                    match_literal=cont_text,
                    match_obj_name=cont_obj_name,
                    new_names=[mapped_cont_name, used_obj_name],
                    changelog=changelog,
                    context=f"containing_mapping_{search_ip_text}_in_{cont_text}->{new_ip_text}",
                )

    changelog.append(
        {
            "timestamp": ts(),
            "action": "processed_csv_row",
            "search_ip": search_ip_text,
            "new_ip": new_ip_text,
            "preferred_name": preferred_name,
        }
    )


# ---------- Main ----------
def load_dg_zone_map(path: str) -> Dict[str, str]:
    dg_zone_map: Dict[str, str] = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    dg, zone = line.split(":", 1)
                    dg_zone_map[dg.strip()] = zone.strip()
                else:
                    parts = line.split()
                    if len(parts) == 2:
                        dg_zone_map[parts[0].strip()] = parts[1].strip()
    except FileNotFoundError:
        print(f"Warning: dg mapping file {path} not found — zone injection skipped.")
    except Exception as e:
        print("Warning: failed parsing dg mapping file:", e)
    return dg_zone_map


def main() -> None:
    parser = argparse.ArgumentParser(description="Palo Alto XML IP mapping with zone injection (fast indexed)")
    parser.add_argument("--config", default="running-config.xml")
    parser.add_argument("--csv", default="ip_map.txt")
    parser.add_argument("--dg", default="dg_zone.txt", help="Device-group to zone mapping file (dg: zone)")
    parser.add_argument("--out", default="modified-config.xml")
    parser.add_argument("--changelog", default="changelog.json")
    parser.add_argument("--resolve-fqdn", action="store_true", help="Resolve fqdn address objects via DNS")
    args = parser.parse_args()

    try:
        tree = ET.parse(args.config)
        root = tree.getroot()
    except Exception as e:
        print("Failed to parse config:", e)
        sys.exit(1)

    dg_zone_map = load_dg_zone_map(args.dg)
    changelog: List[dict] = []

    # Build indexes ONCE
    ctx = build_context(root)

    # Process CSV rows
    with open(args.csv, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            search_ip = (row.get("Search_ip") or row.get("search_ip") or row.get("search IP") or "").strip()
            new_ip = (row.get("new_ip") or row.get("New_ip") or row.get("new IP") or "").strip()
            preferred = (row.get("new_object_name") or row.get("Object_name") or row.get("new_object") or "").strip() or None
            tags = (row.get("tags") or row.get("tag") or "").strip() or None
            desc = (row.get("description") or row.get("desc") or "").strip() or None

            if not search_ip or not new_ip:
                changelog.append({"timestamp": ts(), "action": "skipped_row_missing_required", "row": row})
                continue

            changelog.append({"timestamp": ts(), "action": "processing_row", "search_ip": search_ip, "new_ip": new_ip, "preferred_name": preferred})
            process_row(ctx, dg_zone_map, search_ip, new_ip, preferred, tags, desc, changelog, resolve_fqdn_flag=args.resolve_fqdn)

    tree.write(args.out, encoding="utf-8", xml_declaration=True)
    with open(args.changelog, "w") as cfh:
        json.dump(changelog, cfh, indent=2)

    print(f"Modified config written to {args.out}")
    print(f"Changelog written to {args.changelog}")


if __name__ == "__main__":
    main()