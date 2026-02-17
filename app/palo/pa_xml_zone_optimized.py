#!/usr/bin/env python3
"""
pa_xml_zone.py

Usage:
  python pa_xml_zone.py --config running-config.xml --csv ip_map.csv --dg dg_zone.txt \
    --out modified-config.xml --changelog changelog.jsonl

Behavior (additive-only):
- Containment-based IP remap for single IPs + CIDRs.
- IGNORES IP ranges everywhere:
    - literal "a-b" members are skipped
    - address objects with <ip-range> are skipped
- Updates security rules in:
    * shared pre-rulebase + post-rulebase
    * device-group pre-rulebase + post-rulebase
- If a DG rule changes (mapped members added), add that DG's zone to <from> and <to>
  unless 'any' is present.
- Ensures new mapped address objects are created under /config/shared/address
- Updates STATIC address-groups in:
    * /config/shared/address-group/entry/.../static/member
    * /config/devices/entry/device-group/entry/.../address-group/entry/.../static/member
- Changelog JSONL includes rulebase ("pre"/"post") for rule changes.
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
    # NOTE: svb_m2_ prefix
    return f"svb_m2_{underscored(value_text)}"

def is_ip_literal_member(text: str) -> bool:
    """
    Supports:
      - single IP: "1.2.3.4"
      - CIDR: "1.2.3.0/24"
    Rejects/ignores:
      - ranges: "1.2.3.4-1.2.3.10"
      - object names (anything with letters)
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


# --------------------------------------------------------------------------------------
# Input parsing
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class MapRow:
    search_net: ipaddress._BaseNetwork
    new_net: ipaddress._BaseNetwork
    desc: Optional[str]

def parse_ip_map_csv(path: Path) -> List[MapRow]:
    rows: List[MapRow] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"search_ip", "new_ip"}
        if not reader.fieldnames or not required.issubset({h.strip() for h in reader.fieldnames}):
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
            desc = (r.get("desc") or "").strip() or None
            rows.append(MapRow(search_net=s_net, new_net=n_net, desc=desc))

    # prefer more-specific search nets first
    rows.sort(key=lambda x: x.search_net.prefixlen, reverse=True)
    return rows

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


# --------------------------------------------------------------------------------------
# Mapping logic (containment-based, ranges ignored)
# --------------------------------------------------------------------------------------

def map_value_text(value_text: str, mappings: List[MapRow]) -> Optional[Tuple[MapRow, str]]:
    """
    value_text:
      - IP:   "4.2.2.2"
      - CIDR: "4.2.0.0/16"
    Ranges ignored.
    Returns (maprow_used, new_value_text)
    """
    t = value_text.strip()

    # ignore ranges
    if "-" in t and "/" not in t:
        return None

    # CIDR
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except Exception:
            return None
        for m in mappings:
            if net.version != m.search_net.version:
                continue
            # full containment
            if net.network_address in m.search_net and net.broadcast_address in m.search_net:
                offset = int(net.network_address) - int(m.search_net.network_address)
                new_addr_int = int(m.new_net.network_address) + offset
                new_addr = ipaddress.ip_address(new_addr_int)
                try:
                    new_net = ipaddress.ip_network(f"{new_addr}/{net.prefixlen}", strict=False)
                except Exception:
                    continue
                if new_net.network_address in m.new_net and new_net.broadcast_address in m.new_net:
                    return m, str(new_net)
        return None

    # single IP
    try:
        ip = ipaddress.ip_address(t)
    except Exception:
        return None
    for m in mappings:
        if ip.version != m.search_net.version:
            continue
        if ip in m.search_net:
            offset = int(ip) - int(m.search_net.network_address)
            new_ip_int = int(m.new_net.network_address) + offset
            new_ip = ipaddress.ip_address(new_ip_int)
            if new_ip in m.new_net:
                return m, str(new_ip)
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

def add_member(node: ET.Element, value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if value in set(get_members(node)):
        return False
    m = ET.SubElement(node, "member")
    m.text = value
    m.tail = "\n"  # readability: line feed after each added member
    return True

def get_entry_by_name(parent: ET.Element, name: str) -> Optional[ET.Element]:
    for e in parent.findall("entry"):
        if e.get("name") == name:
            return e
    return None

def ensure_shared_address_entry(root: ET.Element, name: str, value_text: str, desc: Optional[str]) -> Tuple[ET.Element, bool]:
    """
    Ensure /config/shared/address/entry[@name=name] exists with ip-netmask=value_text.
    Returns (entry, created_bool).
    """
    shared = root.find("./shared")
    if shared is None:
        shared = ET.SubElement(root, "shared")

    addr = shared.find("./address")
    if addr is None:
        addr = ET.SubElement(shared, "address")

    entry = get_entry_by_name(addr, name)
    created = False
    if entry is None:
        entry = ET.SubElement(addr, "entry", {"name": name})
        entry.tail = "\n"  # readability: line feed after newly created entry
        created = True

    # force ip-netmask (ranges are not created in this script)
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

    return entry, created

def build_address_book(root: ET.Element) -> Dict[str, Tuple[str, str]]:
    """
    name -> (kind, value_text)
      kind: "ip_or_cidr" or "range"
    Includes:
      - shared address objects
      - DG local address objects
    """
    out: Dict[str, Tuple[str, str]] = {}

    # shared
    for e in root.findall("./shared/address/entry"):
        name = e.get("name")
        if not name:
            continue
        ipn = (e.findtext("ip-netmask") or "").strip()
        ipr = (e.findtext("ip-range") or "").strip()
        if ipr:
            out[name] = ("range", ipr)
        elif ipn:
            out[name] = ("ip_or_cidr", ipn)

    # device-groups local address objects
    for dg in root.findall("./devices/entry/device-group/entry"):
        for e in dg.findall("./address/entry"):
            name = e.get("name")
            if not name:
                continue
            ipn = (e.findtext("ip-netmask") or "").strip()
            ipr = (e.findtext("ip-range") or "").strip()
            if ipr:
                out[name] = ("range", ipr)
            elif ipn:
                out[name] = ("ip_or_cidr", ipn)

    return out


# --------------------------------------------------------------------------------------
# Change logging
# --------------------------------------------------------------------------------------

@dataclass
class Change:
    time: str
    scope: str                # "shared" or "device-group"
    dg: Optional[str]         # DG name if applicable
    target: str               # rule name or address-group name
    field: str                # "source"/"destination"/"from"/"to"/"static"
    added: List[str]
    reason: str
    rulebase: Optional[str] = None   # "pre"/"post" for rules, None for groups


# --------------------------------------------------------------------------------------
# Iterators
# --------------------------------------------------------------------------------------

def iter_security_rules_shared_pre(root: ET.Element) -> Iterable[ET.Element]:
    yield from root.findall("./shared/pre-rulebase/security/rules/entry")

def iter_security_rules_shared_post(root: ET.Element) -> Iterable[ET.Element]:
    yield from root.findall("./shared/post-rulebase/security/rules/entry")

def iter_security_rules_dg_pre(root: ET.Element) -> Iterable[Tuple[str, ET.Element]]:
    for dg_entry in root.findall("./devices/entry/device-group/entry"):
        dg_name = dg_entry.get("name") or ""
        for rule in dg_entry.findall("./pre-rulebase/security/rules/entry"):
            yield dg_name, rule

def iter_security_rules_dg_post(root: ET.Element) -> Iterable[Tuple[str, ET.Element]]:
    for dg_entry in root.findall("./devices/entry/device-group/entry"):
        dg_name = dg_entry.get("name") or ""
        for rule in dg_entry.findall("./post-rulebase/security/rules/entry"):
            yield dg_name, rule

def iter_address_groups_shared(root: ET.Element) -> Iterable[ET.Element]:
    yield from root.findall("./shared/address-group/entry")

def iter_address_groups_dg(root: ET.Element) -> Iterable[Tuple[str, ET.Element]]:
    for dg_entry in root.findall("./devices/entry/device-group/entry"):
        dg_name = dg_entry.get("name") or ""
        for grp in dg_entry.findall("./address-group/entry"):
            yield dg_name, grp


# --------------------------------------------------------------------------------------
# Address-group processing (static only, ranges ignored)
# --------------------------------------------------------------------------------------

def _get_static_node(group_entry: ET.Element) -> Optional[ET.Element]:
    if group_entry.find("dynamic") is not None:
        return None
    return group_entry.find("static")

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
    For ./static/member, add mapped address-object names (created under shared/address).
    Member cases:
      - literal IP/CIDR: map directly
      - address-object name: look up its ip-netmask in addr_book and map that
      - range literals and ip-range objects are ignored
      - unknown / nested group names: skipped
    """
    static = _get_static_node(group_entry)
    if static is None:
        return False

    any_added = False
    existing = get_members(static)

    for mem in existing:
        mem = mem.strip()
        if not mem or mem == "any":
            continue

        source_type: Optional[str] = None
        value_text: Optional[str] = None

        if is_ip_literal_member(mem):
            value_text = mem
            source_type = "literal"
        elif mem in addr_book:
            kind, val = addr_book[mem]
            if kind == "range":
                continue
            value_text = val
            source_type = "address-object"
        else:
            continue  # skip unknown / nested groups

        mapped = map_value_text(value_text, mappings)
        if not mapped:
            continue

        used_map, new_value_text = mapped
        obj_name = gen_default_name_for_value(new_value_text)

        _, created = ensure_shared_address_entry(root, obj_name, new_value_text, used_map.desc)

        if add_member(static, obj_name):
            any_added = True
            changes.append(Change(
                time=ts(),
                scope=scope,
                dg=dg_name,
                target=group_entry.get("name", "<unnamed-address-group>"),
                field="static",
                added=[obj_name],
                reason=(
                    f"address-group static: mapped {mem} ({value_text}) "
                    f"[source={source_type}] -> {new_value_text} "
                    f"[object_created={created}]"
                ),
                rulebase=None,
            ))

    return any_added


# --------------------------------------------------------------------------------------
# Rule processing (ranges ignored)
# --------------------------------------------------------------------------------------

def process_rule_member_list(
    root: ET.Element,
    rule: ET.Element,
    list_tag: str,  # "source" or "destination"
    mappings: List[MapRow],
    addr_book: Dict[str, Tuple[str, str]],
    changes: List[Change],
    scope: str,
    dg_name: Optional[str],
    rulebase: str,  # "pre" or "post"
) -> bool:
    """
    Adds mapped members (address object names) to rule/<list_tag>.
    Returns True if any addition occurred.
    """
    any_added = False
    node = ensure_member_list(rule, list_tag)
    existing_members = get_members(node)

    for mem in existing_members:
        mem = mem.strip()
        if not mem or mem == "any":
            continue

        source_type: Optional[str] = None
        value_text: Optional[str] = None

        if is_ip_literal_member(mem):
            value_text = mem
            source_type = "literal"
        elif mem in addr_book:
            kind, val = addr_book[mem]
            if kind == "range":
                continue
            value_text = val
            source_type = "address-object"
        else:
            continue  # unknown token (often address-group) is skipped by design

        mapped = map_value_text(value_text, mappings)
        if not mapped:
            continue

        used_map, new_value_text = mapped
        obj_name = gen_default_name_for_value(new_value_text)

        _, created = ensure_shared_address_entry(root, obj_name, new_value_text, used_map.desc)

        if add_member(node, obj_name):
            any_added = True
            changes.append(Change(
                time=ts(),
                scope=scope,
                dg=dg_name,
                target=rule.get("name", "<unnamed-rule>"),
                field=list_tag,
                added=[obj_name],
                reason=(
                    f"rule {list_tag}: mapped {mem} ({value_text}) "
                    f"[source={source_type}] -> {new_value_text} "
                    f"[object_created={created}]"
                ),
                rulebase=rulebase,
            ))

    return any_added

def add_zone_to_rule_if_needed(rule: ET.Element, zone: str, field_tag: str) -> bool:
    node = ensure_member_list(rule, field_tag)
    members = get_members(node)
    if "any" in members:
        return False
    return add_member(node, zone)


# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Input Panorama/PAN-OS XML config")
    ap.add_argument("--csv", required=True, help="CSV mapping file: search_ip,new_ip,...")
    ap.add_argument("--dg", required=True, help="Device-group to zone mapping file (dg: zone)")
    ap.add_argument("--out", required=True, help="Output XML file")
    ap.add_argument("--changelog", required=True, help="Output changelog JSONL file ('.jsonl' appended if missing)")
    args = ap.parse_args()

    config_path = Path(args.config)
    csv_path = Path(args.csv)
    dg_path = Path(args.dg)
    out_path = Path(args.out)

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
    # Address-groups first (shared + DG)
    # -------------------------
    for grp in iter_address_groups_shared(root):
        process_address_group_static_members(root, grp, mappings, addr_book, changes, scope="shared", dg_name=None)

    for dg_name, grp in iter_address_groups_dg(root):
        process_address_group_static_members(root, grp, mappings, addr_book, changes, scope="device-group", dg_name=dg_name)

    # refresh address book in case we created new shared objects
    addr_book = build_address_book(root)

    # -------------------------
    # Shared rules: pre + post
    # -------------------------
    for rule in iter_security_rules_shared_pre(root):
        process_rule_member_list(root, rule, "source", mappings, addr_book, changes, scope="shared", dg_name=None, rulebase="pre")
        process_rule_member_list(root, rule, "destination", mappings, addr_book, changes, scope="shared", dg_name=None, rulebase="pre")

    for rule in iter_security_rules_shared_post(root):
        process_rule_member_list(root, rule, "source", mappings, addr_book, changes, scope="shared", dg_name=None, rulebase="post")
        process_rule_member_list(root, rule, "destination", mappings, addr_book, changes, scope="shared", dg_name=None, rulebase="post")

    # refresh address book again (harmless)
    addr_book = build_address_book(root)

    # -------------------------
    # Device-group rules: pre + post (plus zone add if changed)
    # -------------------------
    for dg_name, rule in iter_security_rules_dg_pre(root):
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

    for dg_name, rule in iter_security_rules_dg_post(root):
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

    # Pretty-print indentation for readability
    ET.indent(tree, space="  ")

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