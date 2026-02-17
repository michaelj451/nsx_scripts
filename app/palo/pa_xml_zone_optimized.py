#!/usr/bin/env python3
"""
pa_xml_zone.py

Usage:
  python pa_xml_zone.py --config running-config.xml --csv ip_map.csv --dg dg_zone.txt \
    --out modified-config.xml --changelog changelog.jsonl

What it does (additive-only):
- Containment-based IP remap (host/subnet inside a larger mapped subnet).
- Adds mapped IPs to ALL security rules found in:
    * /config/shared/pre-rulebase/security/rules
    * /config/shared/post-rulebase/security/rules
    * /config/devices/entry/device-group/entry/.../pre-rulebase/security/rules
    * /config/devices/entry/device-group/entry/.../post-rulebase/security/rules
- Adds zones ONLY to device-group rules (not shared/global):
    If a DG rule gets any mapped IP added, add that DG's zone to the rule's <from> and <to>
    (unless 'any' is present, in which case we do not modify the zone list).
- Creates any needed *address objects* under /config/shared/address.
- ALSO updates *address-groups* (static groups only):
    * /config/shared/address-group/entry/.../static/member
    * /config/devices/entry/device-group/entry/.../address-group/entry/.../static/member

Important notes / assumptions:
- This script updates STATIC address-groups only. Dynamic groups (with <dynamic>) are skipped.
- IP RANGES ARE IGNORED everywhere:
    - literal members like "10.1.1.1-10.1.1.10" are skipped
    - address objects with <ip-range> are skipped
- For address-group members that are:
    - literal IP/CIDR: we map them directly
    - address-object name: we look up its ip-netmask in the address book and map that
    - address-group name: we do NOT expand nested groups here (to avoid surprise explosion).
      If you need nested expansion, we can add it safely (with loop detection) later.
- Additive-only: we never remove anything, only add new mapped object members.

Input formats:
- CSV header expected: search_ip,new_ip,new_object_name,tags,desc
  * search_ip: CIDR only (e.g., 4.2.0.0/16, 10.4.1.0/24)
  * new_ip: CIDR only (same prefixlen recommended)
  * new_object_name optional (currently not used for contained items; deterministic names used)

- DG mapping file format (one per line):
    dg-3: zone-3-new
    dg-4: zone-4-new
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def underscored(s: str) -> str:
    return s.replace(".", "_").replace("/", "_").replace(":", "_").replace("-", "_")

def gen_default_name_for_value(value_text: str) -> str:
    # value_text is like "10.1.2.0/24" or "4.4.2.2"
    return f"svb_m2_{underscored(value_text)}"

def is_ip_literal_member(text: str) -> bool:
    """
    Supports (RANGES intentionally ignored):
      - single IP: "1.2.3.4"
      - CIDR: "1.2.3.0/24"
    Rejects:
      - ranges: "1.2.3.4-1.2.3.10"
      - object names like "h-10.1.1.1" or "test-address-4.2.2.2"
    """
    if not text or not isinstance(text, str):
        return False
    t = text.strip()
    if any(c.isalpha() for c in t):
        return False
    # ignore ranges
    if "-" in t and "/" not in t:
        return False
    try:
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

MappedValue = Tuple[str, str]  # (kind, new_value_text) where kind in {"ip","cidr"}

def map_ip(ip: ipaddress._BaseAddress, m: MapRow) -> Optional[ipaddress._BaseAddress]:
    if ip not in m.search_net:
        return None
    offset = int(ip) - int(m.search_net.network_address)
    candidate = int(m.new_net.network_address) + offset
    new_ip = ipaddress.ip_address(candidate)
    if new_ip not in m.new_net:
        return None
    return new_ip

def map_cidr(net: ipaddress._BaseNetwork, m: MapRow) -> Optional[ipaddress._BaseNetwork]:
    # only map if this subnet is fully inside the search subnet
    if net.network_address not in m.search_net:
        return None
    if net.broadcast_address not in m.search_net:
        return None

    offset = int(net.network_address) - int(m.search_net.network_address)
    new_net_addr_int = int(m.new_net.network_address) + offset
    new_net_addr = ipaddress.ip_address(new_net_addr_int)

    try:
        new_net = ipaddress.ip_network(f"{new_net_addr}/{net.prefixlen}", strict=False)
    except Exception:
        return None

    if new_net.network_address not in m.new_net or new_net.broadcast_address not in m.new_net:
        return None
    return new_net

def map_value_text(value_text: str, mappings: List[MapRow]) -> Optional[Tuple[MapRow, MappedValue]]:
    """
    value_text is a literal: "4.2.2.2" or "4.2.0.0/16"
    RANGES are intentionally ignored.
    Returns (maprow_used, ("ip"/"cidr", new_value_text))
    """
    t = value_text.strip()

    # ignore ranges
    if "-" in t and "/" not in t:
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

def ensure_member_list(parent: ET.Element, tag: str) -> ET.Element:
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
    kind: ip|cidr (stored as ip-netmask)
    NOTE: RANGES are ignored by caller; we do not create ip-range objects here.
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

    # force ip-netmask representation
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
    name -> (kind, value_text) from:
      - /config/shared/address
      - /config/devices/entry/device-group/entry/.../address

    NOTE: address objects with <ip-range> are included as kind="range" so callers can SKIP them.
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
            out[name] = ("ip_or_cidr", ipn.strip())

    # device-group local address
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
# Change logging
# --------------------------------------------------------------------------------------

@dataclass
class Change:
    time: str
    scope: str                # "shared" or "device-group"
    dg: Optional[str]         # device-group name if applicable
    target: str               # rule name or address-group name
    field: str                # "source"/"destination"/"from"/"to"/"static"
    added: List[str]
    reason: str
    rulebase: Optional[str] = None   # "pre", "post", or None (non-rule changes)


# --------------------------------------------------------------------------------------
# Iterators for rules and groups
# --------------------------------------------------------------------------------------

def iter_security_rules_shared(root: ET.Element) -> Iterable[ET.Element]:
    yield from root.findall("./shared/pre-rulebase/security/rules/entry")

def iter_security_rules_shared_post(root: ET.Element) -> Iterable[ET.Element]:
    yield from root.findall("./shared/post-rulebase/security/rules/entry")

def iter_security_rules_device_groups(root: ET.Element) -> Iterable[Tuple[str, ET.Element]]:
    for dg_entry in root.findall("./devices/entry/device-group/entry"):
        dg_name = dg_entry.get("name") or ""
        for rule in dg_entry.findall("./pre-rulebase/security/rules/entry"):
            yield dg_name, rule

def iter_security_rules_device_groups_post(root: ET.Element) -> Iterable[Tuple[str, ET.Element]]:
    for dg_entry in root.findall("./devices/entry/device-group/entry"):
        dg_name = dg_entry.get("name") or ""
        for rule in dg_entry.findall("./post-rulebase/security/rules/entry"):
            yield dg_name, rule

def iter_address_groups_shared(root: ET.Element) -> Iterable[ET.Element]:
    yield from root.findall("./shared/address-group/entry")

def iter_address_groups_device_groups(root: ET.Element) -> Iterable[Tuple[str, ET.Element]]:
    for dg_entry in root.findall("./devices/entry/device-group/entry"):
        dg_name = dg_entry.get("name") or ""
        for grp in dg_entry.findall("./address-group/entry"):
            yield dg_name, grp


# --------------------------------------------------------------------------------------
# Core processing: rules
# --------------------------------------------------------------------------------------

def process_rule_member_list(
    root: ET.Element,
    rule: ET.Element,
    list_tag: str,                       # "source" or "destination"
    mappings: List[MapRow],
    addr_book: Dict[str, Tuple[str, str]],
    changes: List[Change],
    scope: str,
    dg_name: Optional[str],
    rulebase: str,                       # "pre" or "post"
) -> bool:
    """
    Adds mapped members (address object names) to rule/<list_tag>.
    Returns True if any addition occurred.

    NOTE: IP ranges are ignored (literal ranges and ip-range address objects).
    """
    any_added = False
    node = ensure_member_list(rule, list_tag)
    existing_members = get_members(node)

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
            if kind == "range":
                continue  # ignore ip-range address objects
            value_text = val
        else:
            # unknown object name (often: address-group). We skip here by design.
            continue

        mapped = map_value_text(value_text, mappings)
        if not mapped:
            continue

        used_map, (kind, new_value_text) = mapped

        obj_name = gen_default_name_for_value(new_value_text)

        # Ensure shared address object exists (ip-netmask only)
        ensure_shared_address_entry(
            root,
            obj_name,
            "ip",
            new_value_text,
            used_map.desc
        )

        if add_member(node, obj_name):
            any_added = True
            changes.append(Change(
                time=ts(),
                scope=scope,
                dg=dg_name,
                target=rule.get("name", "<unnamed-rule>"),
                field=list_tag,
                added=[obj_name],
                reason=f"rule {list_tag}: mapped {mem} ({value_text}) via {used_map.search_net} -> {used_map.new_net} to {new_value_text}",
                rulebase=rulebase,
            ))

    return any_added

def add_zone_to_rule_if_needed(rule: ET.Element, zone: str, field_tag: str) -> bool:
    """
    Add zone to rule/<from|to> if:
    - does NOT contain 'any'
    - zone not already present
    """
    node = ensure_member_list(rule, field_tag)
    members = get_members(node)
    if "any" in members:
        return False
    return add_member(node, zone)


# --------------------------------------------------------------------------------------
# Core processing: address-groups
# --------------------------------------------------------------------------------------

def _get_static_member_node(group_entry: ET.Element) -> Optional[ET.Element]:
    """
    Returns the <static> node if present, else None.
    If <dynamic> present (or no <static>), we do not modify.
    """
    if group_entry.find("dynamic") is not None:
        return None
    static = group_entry.find("static")
    return static

def process_address_group_static_members(
    root: ET.Element,
    group_entry: ET.Element,
    mappings: List[MapRow],
    addr_book: Dict[str, Tuple[str, str]],
    changes: List[Change],
    scope: str,
    dg_name: Optional[str],
) -> bool:
    """
    For an address-group entry, look at ./static/member values and add mapped *address object names*.

    Member cases:
    - literal ip/cidr: map directly
    - address object name: look up its ip-netmask in addr_book and map that
    - address-group name or unknown: skip (no nested expansion here)

    NOTE: IP ranges are ignored (literal ranges and ip-range address objects).
    """
    static = _get_static_member_node(group_entry)
    if static is None:
        return False  # dynamic or no static; skip

    existing = get_members(static)
    any_added = False

    for mem in existing:
        mem = mem.strip()
        if not mem or mem == "any":
            continue

        value_text: Optional[str] = None
        if is_ip_literal_member(mem):
            value_text = mem
        elif mem in addr_book:
            kind, val = addr_book[mem]
            if kind == "range":
                continue  # ignore ip-range address objects
            value_text = val
        else:
            # could be a nested group name or unknown token; skip
            continue

        mapped = map_value_text(value_text, mappings)
        if not mapped:
            continue

        used_map, (kind, new_value_text) = mapped
        obj_name = gen_default_name_for_value(new_value_text)

        ensure_shared_address_entry(
            root,
            obj_name,
            "ip",
            new_value_text,
            used_map.desc
        )

        if add_member(static, obj_name):
            any_added = True
            changes.append(Change(
                time=ts(),
                scope=scope,
                dg=dg_name,
                target=group_entry.get("name", "<unnamed-address-group>"),
                field="static",
                added=[obj_name],
                reason=f"address-group static: mapped {mem} ({value_text}) via {used_map.search_net} -> {used_map.new_net} to {new_value_text}",
                # rulebase left as None intentionally
            ))

    return any_added


# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Input Panorama/PAN-OS XML config")
    ap.add_argument("--csv", required=True, help="CSV mapping file: search_ip,new_ip,...")
    ap.add_argument("--dg", required=True, help="Device-group to zone mapping file (dg: zone)")
    ap.add_argument("--out", required=True, help="Output XML file")
    ap.add_argument("--changelog", required=True, help="Output changelog JSONL file ('.jsonl' will be appended if missing)")
    args = ap.parse_args()

    config_path = Path(args.config)
    csv_path = Path(args.csv)
    dg_path = Path(args.dg)
    out_path = Path(args.out)

    # Always append ".jsonl" if it doesn't already end with it
    changes_path = Path(args.changelog)
    if not str(changes_path).lower().endswith(".jsonl"):
        changes_path = Path(str(changes_path) + ".jsonl")

    tree = ET.parse(str(config_path))
    root = tree.getroot()

    mappings = parse_ip_map_csv(csv_path)
    dg_zone = parse_dg_zone_map(dg_path)

    addr_book = build_address_book(root)
    changes: List[Change] = []

    # -------------------------
    # Address-groups first
    # -------------------------

    # Shared address-groups
    for grp in iter_address_groups_shared(root):
        process_address_group_static_members(
            root, grp, mappings, addr_book, changes,
            scope="shared", dg_name=None
        )

    # DG address-groups
    for dg_name, grp in iter_address_groups_device_groups(root):
        process_address_group_static_members(
            root, grp, mappings, addr_book, changes,
            scope="device-group", dg_name=dg_name
        )

    # Refresh address book so newly created shared objects are recognized later
    addr_book = build_address_book(root)

    # -------------------------
    # Shared rules (pre): add mapped IPs ONLY (no zone changes here)
    # -------------------------
    for rule in iter_security_rules_shared(root):
        process_rule_member_list(root, rule, "source", mappings, addr_book, changes, scope="shared", dg_name=None, rulebase="pre")
        process_rule_member_list(root, rule, "destination", mappings, addr_book, changes, scope="shared", dg_name=None, rulebase="pre")

    # -------------------------
    # Shared rules (post): add mapped IPs ONLY (no zone changes here)
    # -------------------------
    for rule in iter_security_rules_shared_post(root):
        process_rule_member_list(root, rule, "source", mappings, addr_book, changes, scope="shared", dg_name=None, rulebase="post")
        process_rule_member_list(root, rule, "destination", mappings, addr_book, changes, scope="shared", dg_name=None, rulebase="post")

    # refresh addr book (not strictly needed, but harmless)
    addr_book = build_address_book(root)

    # -------------------------
    # Device-group rules (pre): add mapped IPs + add zone if rule changed
    # -------------------------
    for dg_name, rule in iter_security_rules_device_groups(root):
        changed = False
        changed |= process_rule_member_list(root, rule, "source", mappings, addr_book, changes, scope="device-group", dg_name=dg_name, rulebase="pre")
        changed |= process_rule_member_list(root, rule, "destination", mappings, addr_book, changes, scope="device-group", dg_name=dg_name, rulebase="pre")

        if changed:
            zone = dg_zone.get(dg_name)
            if zone:
                if add_zone_to_rule_if_needed(rule, zone, "from"):
                    changes.append(Change(
                        time=ts(), scope="device-group", dg=dg_name,
                        target=rule.get("name", "<unnamed-rule>"),
                        field="from", added=[zone],
                        reason="added DG zone because mapped IPs were added to rule",
                        rulebase="pre",
                    ))
                if add_zone_to_rule_if_needed(rule, zone, "to"):
                    changes.append(Change(
                        time=ts(), scope="device-group", dg=dg_name,
                        target=rule.get("name", "<unnamed-rule>"),
                        field="to", added=[zone],
                        reason="added DG zone because mapped IPs were added to rule",
                        rulebase="pre",
                    ))

    # -------------------------
    # Device-group rules (post): add mapped IPs + add zone if rule changed
    # -------------------------
    for dg_name, rule in iter_security_rules_device_groups_post(root):
        changed = False
        changed |= process_rule_member_list(root, rule, "source", mappings, addr_book, changes, scope="device-group", dg_name=dg_name, rulebase="post")
        changed |= process_rule_member_list(root, rule, "destination", mappings, addr_book, changes, scope="device-group", dg_name=dg_name, rulebase="post")

        if changed:
            zone = dg_zone.get(dg_name)
            if zone:
                if add_zone_to_rule_if_needed(rule, zone, "from"):
                    changes.append(Change(
                        time=ts(), scope="device-group", dg=dg_name,
                        target=rule.get("name", "<unnamed-rule>"),
                        field="from", added=[zone],
                        reason="added DG zone because mapped IPs were added to rule",
                        rulebase="post",
                    ))
                if add_zone_to_rule_if_needed(rule, zone, "to"):
                    changes.append(Change(
                        time=ts(), scope="device-group", dg=dg_name,
                        target=rule.get("name", "<unnamed-rule>"),
                        field="to", added=[zone],
                        reason="added DG zone because mapped IPs were added to rule",
                        rulebase="post",
                    ))

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