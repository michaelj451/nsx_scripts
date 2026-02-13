#!/usr/bin/env python3
"""
Usage:
  python pa_xml_zone.py --config running-config.xml --csv ip_map.csv --dg dg_zone.txt \
    --out modified-config.xml --changelog changelog.jsonl

What it does:
- Containment-based IP remap (host/range/subnet inside a larger mapped subnet).
- Additive only: never removes existing members from rules.
- Adds mapped IPs to ALL security rules found in:
    * /config/shared/pre-rulebase/security/rules
    * /config/devices/entry/device-group/entry/.../pre-rulebase/security/rules
- Adds zones ONLY to device-group rules (not shared/global):
    If a DG rule gets any mapped IP added, add that DG's zone to the rule's <from> and <to>
    (unless 'any' is present, in which case we do not modify the zone list).
- Creates any needed address objects under /config/shared/address.

Input formats:
- CSV header expected: search_ip,new_ip,new_object_name,tags,desc
  * search_ip: CIDR only (e.g., 4.2.0.0/16, 10.4.1.0/24)
  * new_ip: CIDR only (same prefixlen recommended)
  * new_object_name optional (if empty, script generates svb_m1_* name)

- DG mapping file format (one per line):
    dg-3: zone-3-new
    dg-4: zone-4-new
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def underscored(s: str) -> str:
    return s.replace(".", "_").replace("/", "_").replace(":", "_").replace("-", "_")

def gen_default_name_for_value(value_text: str) -> str:
    # value_text is like "10.1.2.0/24" or "4.4.2.2" or "10.4.2.5-10.4.2.20"
    return f"svb_m1_{underscored(value_text)}"

def is_ip_literal_member(text: str) -> bool:
    # Supports:
    #   - single IP: "1.2.3.4"
    #   - CIDR: "1.2.3.0/24"
    #   - range: "1.2.3.4-1.2.3.10"
    # Rejects object names like "h-10.1.1.1" or "test-address-4.2.2.2"
    # (those are handled as object refs if present in address book)
    if not text or not isinstance(text, str):
        return False
    t = text.strip()
    # quick cheap checks
    if any(c.isalpha() for c in t):
        return False
    # now parse
    try:
        if "-" in t and "/" not in t:
            a, b = t.split("-", 1)
            ipaddress.ip_address(a.strip())
            ipaddress.ip_address(b.strip())
            return True
        if "/" in t:
            ipaddress.ip_network(t, strict=False)
            return True
        ipaddress.ip_address(t)
        return True
    except Exception:
        return False

@dataclass(frozen=True)
class MapRow:
    search_net: ipaddress._BaseNetwork
    new_net: ipaddress._BaseNetwork
    new_object_name: Optional[str]
    desc: Optional[str]

def parse_dg_zone_map(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise SystemExit(f"Bad DG map line (expected 'dg: zone'): {raw}")
        dg, zone = line.split(":", 1)
        dg = dg.strip()
        zone = zone.strip()
        if dg and zone:
            out[dg] = zone
    return out

def parse_ip_map_csv(path: Path) -> List[MapRow]:
    rows: List[MapRow] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"search_ip", "new_ip"}
        if not reader.fieldnames or not required.issubset(set(h.strip() for h in reader.fieldnames)):
            raise SystemExit(f"CSV must have headers including: {sorted(required)}. Got: {reader.fieldnames}")
        for r in reader:
            search_ip = (r.get("search_ip") or "").strip()
            new_ip = (r.get("new_ip") or "").strip()
            if not search_ip or not new_ip:
                continue
            try:
                s_net = ipaddress.ip_network(search_ip, strict=False)
                n_net = ipaddress.ip_network(new_ip, strict=False)
            except Exception as e:
                raise SystemExit(f"Bad CIDR in CSV row: search_ip={search_ip!r}, new_ip={new_ip!r}: {e}") from e
            if s_net.version != n_net.version:
                raise SystemExit(f"IP version mismatch: {s_net} -> {n_net}")
            new_obj = (r.get("new_object_name") or "").strip() or None
            desc = (r.get("desc") or "").strip() or None
            rows.append(MapRow(search_net=s_net, new_net=n_net, new_object_name=new_obj, desc=desc))
    # Prefer more specific matches first (longer prefix)
    rows.sort(key=lambda x: x.search_net.prefixlen, reverse=True)
    return rows


# --------------------------------------------------------------------------------------
# Mapping logic (containment-based)
# --------------------------------------------------------------------------------------

MappedValue = Tuple[str, str]  # (kind, new_value_text) where kind in {"ip","cidr","range"}

def map_ip(ip: ipaddress._BaseAddress, m: MapRow) -> Optional[ipaddress._BaseAddress]:
    if ip not in m.search_net:
        return None
    offset = int(ip) - int(m.search_net.network_address)
    candidate = int(m.new_net.network_address) + offset
    new_ip = ipaddress.ip_address(candidate)
    if new_ip not in m.new_net:
        # This would be weird, but protect anyway.
        return None
    return new_ip

def map_cidr(net: ipaddress._BaseNetwork, m: MapRow) -> Optional[ipaddress._BaseNetwork]:
    # only map if this subnet is fully inside the search subnet
    if net.network_address not in m.search_net:
        return None
    # ensure whole net contained:
    if net.broadcast_address not in m.search_net:
        return None

    # We preserve prefixlen. This is the typical expectation for 1:1 remaps.
    # If your search/new prefixlens differ, this still "tries" but may not match what you want.
    offset = int(net.network_address) - int(m.search_net.network_address)
    new_net_addr_int = int(m.new_net.network_address) + offset
    new_net_addr = ipaddress.ip_address(new_net_addr_int)
    # Build new network with same prefixlen
    try:
        new_net = ipaddress.ip_network(f"{new_net_addr}/{net.prefixlen}", strict=False)
    except Exception:
        return None
    # Ensure contained within new supernet
    if new_net.network_address not in m.new_net or new_net.broadcast_address not in m.new_net:
        return None
    return new_net

def map_range(start: ipaddress._BaseAddress, end: ipaddress._BaseAddress, m: MapRow) -> Optional[Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]]:
    # Only map if entire range is inside search net
    if start not in m.search_net or end not in m.search_net:
        return None
    ns = map_ip(start, m)
    ne = map_ip(end, m)
    if not ns or not ne:
        return None
    # keep ordering
    if int(ns) > int(ne):
        ns, ne = ne, ns
    return ns, ne

def map_value_text(value_text: str, mappings: List[MapRow]) -> Optional[Tuple[MapRow, MappedValue]]:
    """
    value_text is a literal: "4.2.2.2" or "4.2.0.0/16" or "10.4.1.5-10.4.1.20"
    Returns (maprow_used, ("ip"/"cidr"/"range", new_value_text))
    """
    t = value_text.strip()

    # range
    if "-" in t and "/" not in t:
        a, b = t.split("-", 1)
        try:
            start = ipaddress.ip_address(a.strip())
            end = ipaddress.ip_address(b.strip())
        except Exception:
            return None
        # Ensure start<=end for containment check
        if int(start) > int(end):
            start, end = end, start
        for m in mappings:
            if start.version != m.search_net.version:
                continue
            mapped = map_range(start, end, m)
            if mapped:
                ns, ne = mapped
                return m, ("range", f"{ns}-{ne}")
        return None

    # cidr
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except Exception:
            return None
        for m in mappings:
            if net.version != m.search_net.version:
                continue
            mapped = map_cidr(net, m)
            if mapped:
                return m, ("cidr", str(mapped))
        return None

    # single ip
    try:
        ip = ipaddress.ip_address(t)
    except Exception:
        return None
    for m in mappings:
        if ip.version != m.search_net.version:
            continue
        mapped = map_ip(ip, m)
        if mapped:
            return m, ("ip", str(mapped))
    return None


# --------------------------------------------------------------------------------------
# XML helpers
# --------------------------------------------------------------------------------------

def find_or_create(parent: ET.Element, tag: str) -> ET.Element:
    child = parent.find(tag)
    if child is None:
        child = ET.SubElement(parent, tag)
    return child

def ensure_member_list(parent: ET.Element, tag: str) -> ET.Element:
    # parent/<tag>/<member>...
    node = parent.find(tag)
    if node is None:
        node = ET.SubElement(parent, tag)
    return node

def get_members(node: Optional[ET.Element]) -> List[str]:
    if node is None:
        return []
    return [m.text.strip() for m in node.findall("member") if m.text and m.text.strip()]

def has_member(node: Optional[ET.Element], value: str) -> bool:
    return value in set(get_members(node))

def add_member(node: ET.Element, value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if has_member(node, value):
        return False
    m = ET.SubElement(node, "member")
    m.text = value
    return True

def get_entry_by_name(parent: ET.Element, name: str) -> Optional[ET.Element]:
    for e in parent.findall("entry"):
        if e.get("name") == name:
            return e
    return None

def ensure_shared_address_entry(root: ET.Element, name: str, kind: str, value_text: str, desc: Optional[str]) -> ET.Element:
    """
    Ensures /config/shared/address/entry[@name=name] exists with correct value.
    kind: ip|cidr|range (stored as ip-netmask for ip/cidr, ip-range for range)
    """
    shared = root.find("./shared")
    if shared is None:
        shared = ET.SubElement(root, "shared")
    addr = shared.find("./address")
    if addr is None:
        addr = ET.SubElement(shared, "address")

    entry = get_entry_by_name(addr, name)
    if entry is None:
        entry = ET.SubElement(addr, "entry", {"name": name})

    # Set value
    if kind == "range":
        # remove ip-netmask if present
        for n in entry.findall("ip-netmask"):
            entry.remove(n)
        node = entry.find("ip-range")
        if node is None:
            node = ET.SubElement(entry, "ip-range")
        node.text = value_text
    else:
        for n in entry.findall("ip-range"):
            entry.remove(n)
        node = entry.find("ip-netmask")
        if node is None:
            node = ET.SubElement(entry, "ip-netmask")
        node.text = value_text

    if desc:
        d = entry.find("description")
        if d is None:
            d = ET.SubElement(entry, "description")
        d.text = desc

    return entry

def build_address_book(root: ET.Element) -> Dict[str, Tuple[str, str]]:
    """
    name -> (kind, value_text) from /config/shared/address and also device-group address stores if present.
    """
    out: Dict[str, Tuple[str, str]] = {}

    # shared
    for e in root.findall("./shared/address/entry"):
        name = e.get("name")
        if not name:
            continue
        ipn = e.findtext("ip-netmask")
        ipr = e.findtext("ip-range")
        if ipr and ipr.strip():
            out[name] = ("range", ipr.strip())
        elif ipn and ipn.strip():
            # could be ip or cidr; we treat it as literal text and let mapper parse
            out[name] = ("ip_or_cidr", ipn.strip())

    # device-group local address (optional)
    for dg in root.findall("./devices/entry/device-group/entry"):
        for e in dg.findall("./address/entry"):
            name = e.get("name")
            if not name:
                continue
            ipn = e.findtext("ip-netmask")
            ipr = e.findtext("ip-range")
            if ipr and ipr.strip():
                out[name] = ("range", ipr.strip())
            elif ipn and ipn.strip():
                out[name] = ("ip_or_cidr", ipn.strip())

    return out


# --------------------------------------------------------------------------------------
# Core rule processing
# --------------------------------------------------------------------------------------

@dataclass
class Change:
    time: str
    scope: str                # "shared" or "device-group"
    dg: Optional[str]         # device-group name if applicable
    rule: str
    field: str                # "source"/"destination"/"from"/"to"
    added: List[str]
    reason: str

def iter_security_rules_shared(root: ET.Element) -> Iterable[ET.Element]:
    yield from root.findall("./shared/pre-rulebase/security/rules/entry")

def iter_security_rules_device_groups(root: ET.Element) -> Iterable[Tuple[str, ET.Element]]:
    for dg_entry in root.findall("./devices/entry/device-group/entry"):
        dg_name = dg_entry.get("name") or ""
        for rule in dg_entry.findall("./pre-rulebase/security/rules/entry"):
            yield dg_name, rule

def process_member_list(
    root: ET.Element,
    rule: ET.Element,
    list_tag: str,                       # "source" or "destination"
    mappings: List[MapRow],
    addr_book: Dict[str, Tuple[str, str]],
    changes: List[Change],
    scope: str,
    dg_name: Optional[str],
) -> bool:
    """
    Adds mapped members (address object names) to rule/<list_tag>.
    Returns True if any addition occurred.
    """
    any_added = False
    node = ensure_member_list(rule, list_tag)
    existing_members = get_members(node)

    # We'll compute additions based on each existing member.
    for mem in existing_members:
        mem = mem.strip()
        if not mem or mem == "any":
            continue

        # Determine underlying value text:
        value_text: Optional[str] = None
        if is_ip_literal_member(mem):
            value_text = mem
        elif mem in addr_book:
            kind, val = addr_book[mem]
            value_text = val
        else:
            # unknown object name; skip
            continue

        mapped = map_value_text(value_text, mappings)
        if not mapped:
            continue

        used_map, (kind, new_value_text) = mapped

        # Determine object name to add (use CSV name only if mapping row provided it AND it's a clean fit for literals)
        # If CSV new_object_name is present, that is typically meant for the whole mapped network, but we are mapping
        # contained items (host/range/subnet). So we generate a deterministic name from the mapped value.
        obj_name = gen_default_name_for_value(new_value_text)

        # Ensure shared address object exists
        ensure_shared_address_entry(root, obj_name, "range" if kind == "range" else "ip", new_value_text, used_map.desc)

        # Add object name into the rule list (additive)
        if add_member(node, obj_name):
            any_added = True
            changes.append(Change(
                time=ts(),
                scope=scope,
                dg=dg_name,
                rule=rule.get("name", "<unnamed>"),
                field=list_tag,
                added=[obj_name],
                reason=f"mapped {mem} ({value_text}) via {used_map.search_net} -> {used_map.new_net} to {new_value_text}",
            ))

    return any_added

def add_zone_to_rule_if_needed(
    rule: ET.Element,
    zone: str,
    field_tag: str,               # "from" or "to"
) -> bool:
    """
    Add zone to rule/<from|to> if:
    - field exists (created if missing)
    - does NOT contain 'any'
    - zone not already present
    """
    node = ensure_member_list(rule, field_tag)
    members = get_members(node)
    if "any" in members:
        return False
    return add_member(node, zone)

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Input Panorama/PAN-OS XML config")
    ap.add_argument("--csv", required=True, help="CSV mapping file: search_ip,new_ip,...")
    ap.add_argument("--dg", required=True, help="Device-group to zone mapping file (dg: zone)")
    ap.add_argument("--out", required=True, help="Output XML file")
    ap.add_argument("--changelog", required=True, help="Output changelog JSONL file")
    args = ap.parse_args()

    config_path = Path(args.config)
    csv_path = Path(args.csv)
    dg_path = Path(args.dg)
    out_path = Path(args.out)
    changes_path = Path(args.changelog)

    tree = ET.parse(str(config_path))
    root = tree.getroot()

    mappings = parse_ip_map_csv(csv_path)
    dg_zone = parse_dg_zone_map(dg_path)

    addr_book = build_address_book(root)
    changes: List[Change] = []

    # -------------------------
    # Shared rules: add mapped IPs ONLY (no zone changes here)
    # -------------------------
    for rule in iter_security_rules_shared(root):
        # update address book view each rule? not necessary; we create new shared entries with deterministic names
        process_member_list(root, rule, "source", mappings, addr_book, changes, scope="shared", dg_name=None)
        process_member_list(root, rule, "destination", mappings, addr_book, changes, scope="shared", dg_name=None)

    # refresh addr book so newly created shared objects can be recognized if referenced later
    addr_book = build_address_book(root)

    # -------------------------
    # Device-group rules: add mapped IPs + add zone if rule changed
    # -------------------------
    for dg_name, rule in iter_security_rules_device_groups(root):
        changed = False
        changed |= process_member_list(root, rule, "source", mappings, addr_book, changes, scope="device-group", dg_name=dg_name)
        changed |= process_member_list(root, rule, "destination", mappings, addr_book, changes, scope="device-group", dg_name=dg_name)

        # Only if we actually added mapped IPs to THIS RULE, add DG zone (additive)
        if changed:
            zone = dg_zone.get(dg_name)
            if zone:
                added_any = False
                if add_zone_to_rule_if_needed(rule, zone, "from"):
                    added_any = True
                    changes.append(Change(time=ts(), scope="device-group", dg=dg_name, rule=rule.get("name","<unnamed>"),
                                          field="from", added=[zone], reason="added DG zone because mapped IPs were added to rule"))
                if add_zone_to_rule_if_needed(rule, zone, "to"):
                    added_any = True
                    changes.append(Change(time=ts(), scope="device-group", dg=dg_name, rule=rule.get("name","<unnamed>"),
                                          field="to", added=[zone], reason="added DG zone because mapped IPs were added to rule"))
                # If 'any' existed, we do nothing (by design, to avoid removing/rewriting).
                _ = added_any

    # Write outputs
    tree.write(str(out_path), encoding="utf-8", xml_declaration=True)

    with changes_path.open("w", encoding="utf-8") as f:
        for c in changes:
            f.write(json.dumps(c.__dict__, ensure_ascii=False) + "\n")

    print(f"Wrote: {out_path}")
    print(f"Wrote changelog: {changes_path} ({len(changes)} changes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())