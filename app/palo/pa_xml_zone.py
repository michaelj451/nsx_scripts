#!/usr/bin/env python3
"""
Usage:
  python pa_xml_zone.py --config running-config.xml --csv ip_map.txt --dg dg_zone.txt --out modified-config.xml --changelog changelog.json [--resolve-fqdn]

MINIMAL CHANGE: Skip anything with IP ranges.
- Skip CSV rows where search_ip or new_ip looks like an IP range
- Skip ip-range address objects during collection/matching
- Skip literal range members found in rules/groups
- Skip "containing range" derived mapping
"""
from __future__ import annotations
import argparse
import csv
import ipaddress
import json
import socket
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional

# ---------- Utilities ----------
def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def entry_name(elem: ET.Element) -> Optional[str]:
    if elem is None:
        return None
    return elem.attrib.get('name')

def underscored(s: str) -> str:
    return s.replace('.', '_').replace('/', '_').replace(':', '_')

def gen_default_name_for_ip(ip_text: str) -> str:
    return f"svb_m2_{underscored(ip_text)}"

def is_ip_range_text(txt: str) -> bool:
    """
    Minimal heuristic: treat anything containing '-' as a range.
    Safe for our use: we want to SKIP ranges even if formatting is odd.
    """
    if not txt:
        return False
    return '-' in txt.strip()

def find_shared_address_parent(root: ET.Element) -> ET.Element:
    """Return <shared>/<address> parent or create one."""
    candidate = root.find('.//shared/address')
    if candidate is not None:
        return candidate
    any_addr = root.find('.//address')
    if any_addr is not None:
        return any_addr
    cfg = root.find('devices') or root
    shared = cfg.find('shared')
    if shared is None:
        shared = ET.SubElement(cfg, 'shared')
    address = shared.find('address')
    if address is None:
        address = ET.SubElement(shared, 'address')
    return address

# ---------- Address collection & matching ----------
def collect_address_entries(root: ET.Element) -> List[Tuple[ET.Element, List[dict]]]:
    """
    Return list of (entry_elem, ipvals) where ipvals is list of dicts:
      { 'type': 'net'|'host'|'range'|'raw'|'fqdn', 'value': obj, 'text': original_text }

    MINIMAL CHANGE: skip ip-range values entirely.
    """
    out = []
    # search all address/entry nodes anywhere
    for e in root.findall('.//address/entry'):
        ipvals = []
        ipnm = e.find('ip-netmask')
        if ipnm is not None and ipnm.text and ipnm.text.strip():
            txt = ipnm.text.strip()
            try:
                if '/' in txt:
                    ipvals.append({'type': 'net', 'value': ipaddress.ip_network(txt, strict=False), 'text': txt})
                else:
                    ipvals.append({'type': 'host', 'value': ipaddress.ip_address(txt), 'text': txt})
            except Exception:
                ipvals.append({'type': 'raw', 'value': txt, 'text': txt})

        ipr = e.find('ip-range')
        if ipr is not None and ipr.text and ipr.text.strip():
            # MINIMAL CHANGE: skip ranges
            pass

        fq = e.find('fqdn')
        if fq is not None and fq.text and fq.text.strip():
            ipvals.append({'type': 'fqdn', 'value': fq.text.strip(), 'text': fq.text.strip()})
        if ipvals:
            out.append((e, ipvals))
    return out

def find_existing_object_for_ip(root: ET.Element, ip_text: str) -> Tuple[Optional[ET.Element], Optional[str], Optional[str]]:
    """
    Find an existing address object for ip_text.
    Returns (entry_elem, match_type, match_text) or (None, None, None)

    MINIMAL CHANGE: if ip_text is a range, skip lookup.
    """
    if is_ip_range_text(ip_text):
        return (None, None, None)

    is_net = False
    is_range = False
    target_net = None
    target_host = None
    target_range = None

    # Check for range format first
    found_range = False
    for sep in [' - ', '-', ',', ' ']:
        if sep in ip_text:
            parts = [p.strip() for p in ip_text.split(sep) if p.strip()]
            if len(parts) >= 2:
                try:
                    s = ipaddress.ip_address(parts[0])
                    t = ipaddress.ip_address(parts[1])
                    target_range = (s, t)
                    is_range = True
                    found_range = True
                    break
                except Exception:
                    pass

    if not found_range:
        try:
            if '/' in ip_text:
                target_net = ipaddress.ip_network(ip_text, strict=False)
                is_net = True
            else:
                target_host = ipaddress.ip_address(ip_text)
                is_net = False
        except Exception:
            pass

    # MINIMAL CHANGE: ranges are skipped entirely, so this lookup only handles host/net/raw.
    if is_net or target_host is not None:
        entries = collect_address_entries(root)
        for e, ipvals in entries:
            for iv in ipvals:
                t = iv['type']
                v = iv['value']
                txt = iv['text']
                if is_net and t == 'net' and v == target_net:
                    return (e, 'exact_net', txt)
                if (not is_net) and target_host is not None and t == 'host' and v == target_host:
                    return (e, 'exact_host', txt)
                if t == 'raw' and txt == ip_text:
                    return (e, 'raw_match', txt)

    return (None, None, None)

# ---------- object creation & reuse ----------
def name_conflict_exists(root: ET.Element, preferred_name: str) -> Optional[ET.Element]:
    for e in root.findall('.//address/entry'):
        if entry_name(e) == preferred_name:
            return e
    return None

def create_address_object(root: ET.Element, ip_text: str, preferred_name: str, description: Optional[str]=None, tags: Optional[str]=None) -> ET.Element:
    """
    MINIMAL CHANGE: refuse to create ranges.
    """
    if is_ip_range_text(ip_text):
        raise ValueError(f"Refusing to create ip-range object (range skipping enabled): {ip_text}")

    parent = find_shared_address_parent(root)
    name = preferred_name
    base = name
    i = 0
    while True:
        if not name_conflict_exists(root, name):
            break
        i += 1
        name = f"{base}_auto{i}"
    e = ET.SubElement(parent, 'entry', {'name': name})
    if '/' in ip_text:
        ipnm = ET.SubElement(e, 'ip-netmask')
        ipnm.text = ip_text
    else:
        ipnm = ET.SubElement(e, 'ip-netmask')
        ipnm.text = ip_text
    if description:
        d = ET.SubElement(e, 'description')
        d.text = description
    if tags:
        tag_elem = ET.SubElement(e, 'tag')
        for t in [x.strip() for x in tags.split(',') if x.strip()]:
            ET.SubElement(tag_elem, 'member').text = t
    return e

def ensure_object_and_reuse_if_present(root: ET.Element, ip_text: str, preferred_name: Optional[str], description: Optional[str], tags: Optional[str], changelog: list, based_on: Optional[str]=None) -> Optional[str]:
    """
    MINIMAL CHANGE: if ip_text is a range, log+skip.
    """
    if is_ip_range_text(ip_text):
        changelog.append({'timestamp': ts(), 'action': 'skipped_range_value', 'ip': ip_text, 'based_on': based_on})
        return None

    existing_entry, match_type, match_text = find_existing_object_for_ip(root, ip_text)
    if existing_entry is not None:
        name = entry_name(existing_entry)
        changelog.append({'timestamp': ts(), 'action': 'reuse_existing_object', 'ip': ip_text,
                          'existing_object': name, 'match_type': match_type, 'match_text': match_text,
                          'based_on': based_on})
        return name

    if preferred_name:
        conflict = name_conflict_exists(root, preferred_name)
        if conflict is None:
            create_address_object(root, ip_text, preferred_name, description, tags)
            changelog.append({'timestamp': ts(), 'action': 'create_object', 'ip': ip_text, 'name': preferred_name, 'based_on': based_on})
            return preferred_name
        else:
            existing_ipvals = [ipnm.text.strip() for ipnm in conflict.findall('ip-netmask') if ipnm.text and ipnm.text.strip()]
            # NOTE: ranges skipped, so only ip-netmask compare
            if ip_text in existing_ipvals:
                changelog.append({'timestamp': ts(), 'action': 'reuse_existing_object_by_name_match', 'ip': ip_text, 'existing_object': preferred_name, 'based_on': based_on})
                return preferred_name
            new_e = create_address_object(root, ip_text, preferred_name, description, tags)
            new_name = entry_name(new_e)
            changelog.append({'timestamp': ts(), 'action': 'create_object_name_conflict', 'requested_name': preferred_name, 'created_name': new_name, 'ip': ip_text, 'based_on': based_on})
            return new_name

    default_name = gen_default_name_for_ip(ip_text)
    new_e = create_address_object(root, ip_text, default_name, description, tags)
    changelog.append({'timestamp': ts(), 'action': 'create_object', 'ip': ip_text, 'name': entry_name(new_e), 'based_on': based_on})
    return entry_name(new_e)

# ---------- rule & group helpers ----------
def update_section(root: ET.Element, parent: ET.Element, section_tag: str, literal_val: str, obj_name: Optional[str], new_names: List[str], changelog: list, context: Optional[str]=None, is_group: bool=False) -> bool:
    """
    MINIMAL CHANGE: if literal_val is a range, do nothing.
    Also, filter out None new_names (since ensure_object... can skip).
    """
    if is_ip_range_text(literal_val):
        return False

    sec = parent.find(section_tag)
    if sec is None:
        return False
    to_add: List[str] = []
    matched = False
    for m in sec.findall('member'):
        m_text = m.text.strip() if m.text else ''
        if m_text == literal_val:
            matched = True
            if obj_name is None:
                ensure_object_and_reuse_if_present(root, literal_val, None, None, None, changelog, based_on=f"literal_{literal_val}")
        if obj_name and m_text == obj_name:
            matched = True
        if matched:
            to_add.extend([n for n in new_names if n])
            break
    if to_add:
        before = [m.text for m in sec.findall('member') if m.text]
        existing = [m.text for m in sec.findall('member') if m.text]
        added_items = []
        for a in dict.fromkeys(to_add):
            if a not in existing:
                ET.SubElement(sec, 'member').text = a
                added_items.append(a)
        after = [m.text for m in sec.findall('member') if m.text]
        if is_group:
            action = 'add_group_member'
            key = 'group'
        else:
            action = 'add_member'
            key = 'rule'
        changelog.append({'timestamp': ts(), 'action': action, key: entry_name(parent),
                          'section': section_tag, 'added': added_items, 'before': before, 'after': after, 'context': context})
        return True
    return False

def update_zone_if_needed(rule_elem: ET.Element, dg_name: str, dg_zone_map: Dict[str, str], changelog: list, sections: List[str]):
    """Ensure mapped zone for device-group is in specified <from> and/or <to> of rule"""
    if dg_name not in dg_zone_map:
        return
    zone_to_add = dg_zone_map[dg_name]
    for section_tag in sections:
        sec = rule_elem.find(section_tag)
        if sec is None:
            sec = ET.SubElement(rule_elem, section_tag)
        existing = [m.text for m in sec.findall('member') if m.text]
        if zone_to_add not in existing:
            ET.SubElement(sec, 'member').text = zone_to_add
            changelog.append({'timestamp': ts(), 'action': 'update_zone',
                              'rule': entry_name(rule_elem),
                              'device_group': dg_name,
                              'section': section_tag,
                              'added_zone': zone_to_add})

# ---------- FQDN resolution ----------
def resolve_fqdn(fqdn: str, changelog: list) -> List[str]:
    try:
        ips = []
        for res in socket.getaddrinfo(fqdn, None):
            ip = res[4][0]
            if ip not in ips:
                ips.append(ip)
        changelog.append({'timestamp': ts(), 'action': 'fqdn_resolution', 'fqdn': fqdn, 'ips': ips})
        return ips
    except Exception as e:
        changelog.append({'timestamp': ts(), 'action': 'fqdn_resolution_failed', 'fqdn': fqdn, 'error': str(e)})
        return []

# ---------- CSV row processing ----------
def process_row(root: ET.Element, dg_zone_map: Dict[str,str], search_ip_text: str, new_ip_text: str, preferred_name: Optional[str], tags: Optional[str], description: Optional[str], changelog: list, resolve_fqdn_flag: bool=False):
    """
    MINIMAL CHANGE: Skip any row where search_ip or new_ip is a range.
    """
    if is_ip_range_text(search_ip_text) or is_ip_range_text(new_ip_text):
        changelog.append({'timestamp': ts(), 'action': 'skipped_row_range', 'search_ip': search_ip_text, 'new_ip': new_ip_text})
        return

    try:
        is_search_net = '/' in search_ip_text
        is_search_range = not is_search_net and any(sep in search_ip_text for sep in [' - ', '-', ',', ' '])
        is_new_net = '/' in new_ip_text
        is_new_range = not is_new_net and any(sep in new_ip_text for sep in [' - ', '-', ',', ' '])
        # MINIMAL CHANGE: ranges are skipped above, but keep vars for minimal diff
        search_net = ipaddress.ip_network(search_ip_text, strict=False) if is_search_net else None
        new_net = ipaddress.ip_network(new_ip_text, strict=False) if is_new_net else None
        search_host = ipaddress.ip_address(search_ip_text) if not is_search_net and not is_search_range else None
        new_host = ipaddress.ip_address(new_ip_text) if not is_new_net and not is_new_range else None

        # MINIMAL CHANGE: simplify version detection (no range path)
        search_version = search_net.version if is_search_net else search_host.version
        new_version = new_net.version if is_new_net else new_host.version

    except Exception as e:
        changelog.append({'timestamp': ts(), 'action': 'invalid_row', 'search_ip': search_ip_text, 'new_ip': new_ip_text, 'error': str(e)})
        return

    if search_version != new_version:
        changelog.append({'timestamp': ts(), 'action': 'version_mismatch', 'search_ip': search_ip_text, 'new_ip': new_ip_text, 'search_version': search_version, 'new_version': new_version})
        return

    entries = collect_address_entries(root)
    host_to_obj: Dict[str,str] = {}
    fqdn_entries: List[Tuple[ET.Element,str]] = []
    for e, ipvals in entries:
        for iv in ipvals:
            if iv['type'] == 'host':
                host_to_obj[str(iv['value'])] = entry_name(e)
            elif iv['type'] == 'fqdn':
                fqdn_entries.append((e, iv['value']))

    # Build list of rules grouped by device-group (so we can inject zones correctly)
    dg_rule_map: List[Tuple[ET.Element, str]] = []  # (rule_elem, dg_name)
    for dg in root.findall('.//devices/entry/device-group/entry'):
        dg_name = dg.attrib.get('name')
        if not dg_name:
            continue
        for r in dg.findall('.//pre-rulebase//security//rules/entry'):
            dg_rule_map.append((r, dg_name))
        for r in dg.findall('.//post-rulebase//application-override//rules/entry'):
            dg_rule_map.append((r, dg_name))
        for r in dg.findall('.//security//rules/entry'):
            if (r, dg_name) not in dg_rule_map:
                dg_rule_map.append((r, dg_name))

    for r in root.findall('.//shared//pre-rulebase//security//rules/entry'):
        dg_rule_map.append((r, 'shared'))
    for r in root.findall('.//shared//post-rulebase//security//rules/entry'):
        dg_rule_map.append((r, 'shared'))
    for r in root.findall('.//shared//post-rulebase//application-override//rules/entry'):
        dg_rule_map.append((r, 'shared'))

    groups = root.findall('.//address-group/entry')

    # If new_ip is a network/range, ensure object exists (reuse if found)
    new_net_name = None
    if is_new_net or is_new_range:
        new_net_name = ensure_object_and_reuse_if_present(root, new_ip_text, preferred_name, description, tags, changelog, based_on=f"{search_ip_text}->{new_ip_text}")

    # Find search network/range object name if exists
    search_obj_name = None
    if is_search_net or is_search_range:
        for e, ipvals in entries:
            for iv in ipvals:
                if (is_search_net and iv['type'] == 'net' and iv['value'] == search_net):
                    search_obj_name = entry_name(e)
                    break
            if search_obj_name:
                break

    matched_hosts = set()

    # (A) hosts that exist as address objects that belong to the search_net or equal the search_host
    for ip_str, obj_name in host_to_obj.items():
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_search_net and ip_obj in search_net:
                matched_hosts.add(ip_obj)
            elif not is_search_net and not is_search_range and ip_obj == search_host:
                matched_hosts.add(ip_obj)
        except Exception:
            continue

    # (B) literal IPs in rules (search across collected rules)
    for r_elem, dgname in dg_rule_map:
        for side in ('source', 'destination'):
            sec = r_elem.find(side)
            if sec is None:
                continue
            for m in sec.findall('member'):
                if not (m.text and m.text.strip()):
                    continue
                txt = m.text.strip()
                # MINIMAL CHANGE: skip literal ranges in rules
                if is_ip_range_text(txt):
                    continue
                try:
                    ip_obj = ipaddress.ip_address(txt)
                    if is_search_net and ip_obj in search_net:
                        matched_hosts.add(ip_obj)
                    elif not is_search_net and not is_search_range and ip_obj == search_host:
                        matched_hosts.add(ip_obj)
                except Exception:
                    pass

    # FQDN resolution if requested
    if resolve_fqdn_flag:
        for entry_elem, fqdn in fqdn_entries:
            ips = resolve_fqdn(fqdn, changelog)
            if not ips:
                changelog.append({'timestamp': ts(), 'action': 'fqdn_reference_unresolved', 'fqdn': fqdn, 'object': entry_name(entry_elem)})
            else:
                for ipstr in ips:
                    if is_ip_range_text(ipstr):
                        continue
                    try:
                        ip_obj = ipaddress.ip_address(ipstr)
                        if is_search_net and ip_obj in search_net:
                            matched_hosts.add(ip_obj)
                            host_to_obj[ipstr] = entry_name(entry_elem)
                        elif not is_search_net and not is_search_range and ip_obj == search_host:
                            matched_hosts.add(ip_obj)
                            host_to_obj[ipstr] = entry_name(entry_elem)
                    except Exception:
                        pass

    # ---- Process each matched host ----
    used_obj_name: Optional[str] = None
    for host_ip in sorted(matched_hosts, key=lambda x: int(x)):
        host_str = str(host_ip)
        mapped_ip = new_ip_text  # default for host-to-host
        if is_search_net and is_new_net:
            offset = int(host_ip) - int(search_net.network_address)
            mapped_ip = str(ipaddress.ip_address(int(new_net.network_address) + offset))

        used_obj_name = ensure_object_and_reuse_if_present(root, mapped_ip, preferred_name, description, tags, changelog, based_on=f"{host_str}->{mapped_ip}")
        if not used_obj_name:
            continue

        orig_obj_name = host_to_obj.get(host_str)
        new_names = [used_obj_name]

        for r_elem, dg_name in dg_rule_map:
            updated_source = update_section(root, r_elem, 'source', host_str, orig_obj_name, new_names, changelog, context=f"mapped_from_{host_str}_based_on_{orig_obj_name or 'literal'}")
            updated_dest = update_section(root, r_elem, 'destination', host_str, orig_obj_name, new_names, changelog, context=f"mapped_from_{host_str}_based_on_{orig_obj_name or 'literal'}")
            sections = []
            if updated_source:
                sections.append('from')
            if updated_dest:
                sections.append('to')
            if sections and dg_name in dg_zone_map:
                update_zone_if_needed(r_elem, dg_name, dg_zone_map, changelog, sections)

        for g in groups:
            update_section(root, g, 'static', host_str, orig_obj_name, new_names, changelog, context=f"mapped_from_{host_str}_based_on_{orig_obj_name or 'literal'}", is_group=True)

    # ---- Network-level mapping: add mapped network object to rules/groups referencing original network (literal/object) ----
    if (is_search_net or is_search_range) and new_net_name:
        search_net_str = search_ip_text
        new_names = [new_net_name]
        for r_elem, dg_name in dg_rule_map:
            updated_source = update_section(root, r_elem, 'source', search_net_str, search_obj_name, new_names, changelog, context=f"network_mapping_{search_ip_text}->{new_ip_text}")
            updated_dest = update_section(root, r_elem, 'destination', search_net_str, search_obj_name, new_names, changelog, context=f"network_mapping_{search_ip_text}->{new_ip_text}")
            sections = []
            if updated_source:
                sections.append('from')
            if updated_dest:
                sections.append('to')
            if sections and dg_name in dg_zone_map:
                update_zone_if_needed(r_elem, dg_name, dg_zone_map, changelog, sections)
        for g in groups:
            update_section(root, g, 'static', search_net_str, search_obj_name, new_names, changelog, context=f"network_mapping_{search_ip_text}->{new_ip_text}", is_group=True)

    # ---- For host search, handle containing networks only (MINIMAL CHANGE: skip containing ranges) ----
    if not is_search_net and not is_search_range and search_host is not None:
        containing_containers = []
        for e, ipvals in entries:
            for iv in ipvals:
                if iv['type'] == 'net' and search_host in iv['value']:
                    containing_containers.append((e, iv, 'net'))
                # MINIMAL CHANGE: no 'range' path here anymore

        for cont_e, cont_iv, cont_type in containing_containers:
            # cont_type is always 'net' now
            offset = int(search_host) - int(cont_iv['value'].network_address)
            new_cont_addr_int = int(new_host) - offset
            new_cont_net_str = f"{ipaddress.ip_address(new_cont_addr_int)}/{cont_iv['value'].prefixlen}"
            mapped_cont_name = ensure_object_and_reuse_if_present(root, new_cont_net_str, preferred_name, description, tags, changelog, based_on=f"derived_net_from_{search_ip_text}_in_{cont_iv['text']}")
            if not mapped_cont_name:
                continue

            cont_str = cont_iv['text']
            cont_obj_name = entry_name(cont_e)
            cont_new_names = [mapped_cont_name, used_obj_name] if used_obj_name else [mapped_cont_name]
            for r_elem, dg_name in dg_rule_map:
                updated_source = update_section(root, r_elem, 'source', cont_str, cont_obj_name, cont_new_names, changelog, context=f"containing_mapping_{search_ip_text}_in_{cont_str}->{new_ip_text}")
                updated_dest = update_section(root, r_elem, 'destination', cont_str, cont_obj_name, cont_new_names, changelog, context=f"containing_mapping_{search_ip_text}_in_{cont_str}->{new_ip_text}")
                sections = []
                if updated_source:
                    sections.append('from')
                if updated_dest:
                    sections.append('to')
                if sections and dg_name in dg_zone_map:
                    update_zone_if_needed(r_elem, dg_name, dg_zone_map, changelog, sections)
            for g in groups:
                update_section(root, g, 'static', cont_str, cont_obj_name, cont_new_names, changelog, context=f"containing_mapping_{search_ip_text}_in_{cont_str}->{new_ip_text}", is_group=True)

    changelog.append({'timestamp': ts(), 'action': 'processed_csv_row', 'search_ip': search_ip_text, 'new_ip': new_ip_text, 'preferred_name': preferred_name})

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="Palo Alto XML IP mapping with zone injection")
    parser.add_argument('--config', default='running-config.xml')
    parser.add_argument('--csv', default='ip_map.txt')
    parser.add_argument('--dg', default='dg_zone.txt', help='Device-group to zone mapping file (dg: zone)')
    parser.add_argument('--out', default='modified-config.xml')
    parser.add_argument('--changelog', default='changelog.json')
    parser.add_argument('--resolve-fqdn', action='store_true', help='Resolve fqdn address objects via DNS')
    args = parser.parse_args()

    try:
        tree = ET.parse(args.config)
        root = tree.getroot()
    except Exception as e:
        print("Failed to parse config:", e)
        sys.exit(1)

    # load dg_zone map (device-group -> zone)
    dg_zone_map: Dict[str,str] = {}
    try:
        with open(args.dg) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    dg, zone = line.split(':', 1)
                    dg_zone_map[dg.strip()] = zone.strip()
                else:
                    parts = line.split()
                    if len(parts) == 2:
                        dg_zone_map[parts[0].strip()] = parts[1].strip()
    except FileNotFoundError:
        print(f"Warning: dg mapping file {args.dg} not found — zone injection skipped.")
    except Exception as e:
        print("Warning: failed parsing dg mapping file:", e)

    changelog: List[dict] = []

    # Process CSV rows
    with open(args.csv, newline='') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            search_ip = (row.get('Search_ip') or row.get('search_ip') or row.get('search IP') or '').strip()
            new_ip = (row.get('new_ip') or row.get('New_ip') or row.get('new IP') or '').strip()
            preferred = (row.get('new_object_name') or row.get('Object_name') or row.get('new_object') or '').strip() or None
            tags = (row.get('tags') or row.get('tag') or '').strip() or None
            desc = (row.get('description') or row.get('desc') or '').strip() or None

            if not search_ip or not new_ip:
                changelog.append({'timestamp': ts(), 'action': 'skipped_row_missing_required', 'row': row})
                continue

            # MINIMAL CHANGE: skip rows with ranges
            if is_ip_range_text(search_ip) or is_ip_range_text(new_ip):
                changelog.append({'timestamp': ts(), 'action': 'skipped_row_range', 'search_ip': search_ip, 'new_ip': new_ip, 'row': row})
                continue

            changelog.append({'timestamp': ts(), 'action': 'processing_row', 'search_ip': search_ip, 'new_ip': new_ip, 'preferred_name': preferred})
            process_row(root, dg_zone_map, search_ip, new_ip, preferred, tags, desc, changelog, resolve_fqdn_flag=args.resolve_fqdn)

    # write outputs
    tree.write(args.out, encoding='utf-8', xml_declaration=True)
    with open(args.changelog, 'w') as cfh:
        json.dump(changelog, cfh, indent=2)

    print(f"Modified config written to {args.out}")
    print(f"Changelog written to {args.changelog}")

if __name__ == '__main__':
    main()