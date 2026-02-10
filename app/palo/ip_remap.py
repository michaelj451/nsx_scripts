#!/usr/bin/env python3
"""
pa_xml_r_o_dedup_final_without_zones_fqdn.py

Features:
 - Deduplication & preferred-name handling
 - Adds mapped objects into rules and groups
 - Timezone-aware timestamps in changelog
 - Bulk CSV processing
 - (NEW) Remap ip-range address objects when mapping net->net (CIDR->CIDR)
"""
from __future__ import annotations
import argparse
import csv
import ipaddress
import json
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

def find_shared_address_parent(root: ET.Element) -> ET.Element:
    """Return <shared>/<address> parent or create one."""
    candidate = root.find('.//shared/address')
    if candidate is not None:
        return candidate
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
    """
    out = []
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
            txt = ipr.text.strip()
            found = False
            for sep in [' - ', '-', ',', ' ']:
                if sep in txt:
                    parts = [p.strip() for p in txt.split(sep) if p.strip()]
                    if len(parts) >= 2:
                        try:
                            s = ipaddress.ip_address(parts[0])
                            t = ipaddress.ip_address(parts[1])
                            ipvals.append({'type': 'range', 'value': (s, t), 'text': txt})
                            found = True
                            break
                        except Exception:
                            pass
            if not found:
                ipvals.append({'type': 'raw', 'value': txt, 'text': txt})
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
    match_type: exact_net, exact_host, exact_range, raw_match
    """
    try:
        if '/' in ip_text:
            target_net = ipaddress.ip_network(ip_text, strict=False)
            is_net = True
            is_range = False
            target_host = None
            target_range = None
        elif '-' in ip_text or ' ' in ip_text:
            parts = ip_text.replace(' - ', '-').split('-')
            if len(parts) == 2:
                s = ipaddress.ip_address(parts[0].strip())
                t = ipaddress.ip_address(parts[1].strip())
                target_range = (s, t)
                is_range = True
                is_net = False
                target_host = None
            else:
                target_host = ipaddress.ip_address(ip_text)
                is_net = False
                is_range = False
                target_range = None
        else:
            target_host = ipaddress.ip_address(ip_text)
            is_net = False
            is_range = False
            target_range = None
    except Exception:
        return (None, None, None)

    entries = collect_address_entries(root)
    for e, ipvals in entries:
        for iv in ipvals:
            t = iv['type']
            if t == 'net' and is_net and iv['value'] == target_net:
                return (e, 'exact_net', iv['text'])
            if t == 'host' and not is_net and not is_range and iv['value'] == target_host:
                return (e, 'exact_host', iv['text'])
            if t == 'range' and is_range and iv['value'] == target_range:
                return (e, 'exact_range', iv['text'])
            if t == 'raw' and iv['text'] == ip_text:
                return (e, 'raw_match', iv['text'])
    return (None, None, None)

# ---------- object creation & reuse ----------
def name_conflict_exists(root: ET.Element, preferred_name: str) -> Optional[ET.Element]:
    for e in root.findall('.//address/entry'):
        if entry_name(e) == preferred_name:
            return e
    return None

def create_address_object(root: ET.Element, ip_text: str, preferred_name: str, description: Optional[str]=None, tags: Optional[str]=None) -> ET.Element:
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
    elif '-' in ip_text or ' ' in ip_text:
        ipr = ET.SubElement(e, 'ip-range')
        ipr.text = ip_text
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

def ensure_object_and_reuse_if_present(
    root: ET.Element,
    ip_text: str,
    preferred_name: Optional[str],
    description: Optional[str],
    tags: Optional[str],
    changelog: list,
    based_on: Optional[str]=None
) -> str:
    existing_entry, match_type, match_text = find_existing_object_for_ip(root, ip_text)
    if existing_entry is not None:
        name = entry_name(existing_entry)
        changelog.append({
            'timestamp': ts(),
            'action': 'reuse_existing_object',
            'ip': ip_text,
            'existing_object': name,
            'match_type': match_type,
            'match_text': match_text,
            'based_on': based_on
        })
        return name

    if preferred_name:
        conflict = name_conflict_exists(root, preferred_name)
        if conflict is None:
            create_address_object(root, ip_text, preferred_name, description, tags)
            changelog.append({'timestamp': ts(), 'action': 'create_object', 'ip': ip_text, 'name': preferred_name, 'based_on': based_on})
            return preferred_name
        else:
            existing_ipvals = [ipnm.text.strip() for ipnm in conflict.findall('ip-netmask') if ipnm.text and ipnm.text.strip()]
            existing_ranges = [ipr.text.strip() for ipr in conflict.findall('ip-range') if ipr.text and ipr.text.strip()]
            if ip_text in existing_ipvals or ip_text in existing_ranges:
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
def update_section(
    root: ET.Element,
    parent: ET.Element,
    section_tag: str,
    literal_val: str,
    obj_name: Optional[str],
    new_name: str,
    changelog: list,
    context: Optional[str]=None,
    is_group: bool=False
) -> bool:
    """
    parent is the rule element or group element.
    - If literal_val is present, transform literal -> object (ensure object exists) and also add new_name
    - If obj_name present and found among members, add new_name
    - Avoid duplicates.
    """
    sec = parent.find(section_tag)
    if sec is None:
        return False
    to_remove: List[ET.Element] = []
    to_add: List[str] = []
    for m in list(sec.findall('member')):
        if m.text == literal_val:
            to_remove.append(m)
            if obj_name is None:
                obj_name = ensure_object_and_reuse_if_present(root, literal_val, None, None, None, changelog, based_on=f"literal_{literal_val}")
            to_add.append(obj_name)
            to_add.append(new_name)
        elif obj_name and m.text == obj_name:
            to_add.append(new_name)

    if to_remove or to_add:
        before = [m.text for m in sec.findall('member') if m.text]
        for rem in to_remove:
            sec.remove(rem)

        existing = [m.text for m in sec.findall('member') if m.text]
        for a in dict.fromkeys(to_add):  # preserve order, remove dups
            if a not in existing:
                ET.SubElement(sec, 'member').text = a

        after = [m.text for m in sec.findall('member') if m.text]
        if is_group:
            action = 'update_group'
            key = 'group'
        else:
            action = 'update_rule'
            key = 'rule'
        changelog.append({
            'timestamp': ts(),
            'action': action,
            key: entry_name(parent),
            'section': section_tag,
            'removed': [r.text for r in to_remove],
            'added': list(dict.fromkeys(to_add)),
            'before': before,
            'after': after,
            'context': context
        })
        return True
    return False

# ---------- CSV row processing ----------
def process_row(
    root: ET.Element,
    search_ip_text: str,
    new_ip_text: str,
    preferred_name: Optional[str],
    tags: Optional[str],
    description: Optional[str],
    changelog: list
):
    """
    - search_ip_text may be host, range, or network (CIDR)
    - new_ip_text may be host, range, or network (CIDR)
    - preferred_name optional (for created objects)
    """
    try:
        is_search_net = '/' in search_ip_text
        is_search_range = '-' in search_ip_text or ' ' in search_ip_text
        is_new_net = '/' in new_ip_text
        is_new_range = '-' in new_ip_text or ' ' in new_ip_text

        search_net = ipaddress.ip_network(search_ip_text, strict=False) if is_search_net else None
        search_range_start = None
        search_range_end = None
        if is_search_range:
            parts = search_ip_text.replace(' - ', '-').split('-')
            search_range_start = ipaddress.ip_address(parts[0].strip())
            search_range_end = ipaddress.ip_address(parts[1].strip())

        new_net = ipaddress.ip_network(new_ip_text, strict=False) if is_new_net else None
        new_range_start = None
        new_range_end = None
        if is_new_range:
            parts = new_ip_text.replace(' - ', '-').split('-')
            new_range_start = ipaddress.ip_address(parts[0].strip())
            new_range_end = ipaddress.ip_address(parts[1].strip())

        search_host = ipaddress.ip_address(search_ip_text) if not is_search_net and not is_search_range else None
        new_host = ipaddress.ip_address(new_ip_text) if not is_new_net and not is_new_range else None
    except Exception as e:
        changelog.append({'timestamp': ts(), 'action': 'invalid_row', 'search_ip': search_ip_text, 'new_ip': new_ip_text, 'error': str(e)})
        return

    search_version = search_net.version if is_search_net else search_range_start.version if is_search_range else search_host.version
    new_version = new_net.version if is_new_net else new_range_start.version if is_new_range else new_host.version
    if search_version != new_version:
        changelog.append({
            'timestamp': ts(),
            'action': 'version_mismatch',
            'search_ip': search_ip_text,
            'new_ip': new_ip_text,
            'search_version': search_version,
            'new_version': new_version
        })
        return

    entries = collect_address_entries(root)

    # Map host IP -> object name for existing host objects
    host_to_obj: Dict[str, str] = {}
    for e, ipvals in entries:
        for iv in ipvals:
            if iv['type'] == 'host':
                host_to_obj[str(iv['value'])] = entry_name(e)

    # Build flat list of rules
    rules_elems: List[ET.Element] = []
    for dg in root.findall('.//devices/entry/device-group/entry'):
        for r in dg.findall('.//pre-rulebase//security//rules/entry'):
            rules_elems.append(r)
        for r in dg.findall('.//pre-rulebase//application-override//rules/entry'):
            rules_elems.append(r)
        for r in dg.findall('.//post-rulebase//security//rules/entry'):
            rules_elems.append(r)
        for r in dg.findall('.//post-rulebase//application-override//rules/entry'):
            rules_elems.append(r)
        for r in dg.findall('.//security//rules/entry'):
            if r not in rules_elems:
                rules_elems.append(r)
        for r in dg.findall('.//application-override//rules/entry'):
            if r not in rules_elems:
                rules_elems.append(r)

    for r in root.findall('.//shared//pre-rulebase//security//rules/entry'):
        rules_elems.append(r)
    for r in root.findall('.//shared//post-rulebase//security//rules/entry'):
        rules_elems.append(r)
    for r in root.findall('.//shared//pre-rulebase//application-override//rules/entry'):
        rules_elems.append(r)
    for r in root.findall('.//shared//post-rulebase//application-override//rules/entry'):
        rules_elems.append(r)

    groups = root.findall('.//address-group/entry')

    # If new_ip is a network or range, ensure network/range object exists (reuse if found)
    new_container_name = None
    if is_new_net or is_new_range:
        new_container_name = ensure_object_and_reuse_if_present(
            root,
            new_ip_text,
            preferred_name,
            description,
            tags,
            changelog,
            based_on=f"{search_ip_text}->{new_ip_text}"
        )

    # Find search network/range object name if exists
    search_obj_name = None
    if is_search_net:
        for e, ipvals in entries:
            for iv in ipvals:
                if iv['type'] == 'net' and iv['value'] == search_net:
                    search_obj_name = entry_name(e)
                    break
            if search_obj_name:
                break
    elif is_search_range:
        for e, ipvals in entries:
            for iv in ipvals:
                if iv['type'] == 'range' and iv['value'] == (search_range_start, search_range_end):
                    search_obj_name = entry_name(e)
                    break
            if search_obj_name:
                break

    # Determine matched hosts
    matched_hosts = set()

    # 1) Host objects in config that fall in the search container (net/range/host)
    for ip_str, obj_name in host_to_obj.items():
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_search_net and ip_obj in search_net:
                matched_hosts.add(ip_obj)
            elif is_search_range and search_range_start <= ip_obj <= search_range_end:
                matched_hosts.add(ip_obj)
            elif not is_search_net and not is_search_range and ip_obj == search_host:
                matched_hosts.add(ip_obj)
        except Exception:
            continue

    # 2) Literal IPs in rules that fall in the search container
    for r_elem in rules_elems:
        for side in ('source', 'destination'):
            sec = r_elem.find(side)
            if sec is None:
                continue
            for m in sec.findall('member'):
                if not (m.text and m.text.strip()):
                    continue
                txt = m.text.strip()
                try:
                    ip_obj = ipaddress.ip_address(txt)
                    if is_search_net and ip_obj in search_net:
                        matched_hosts.add(ip_obj)
                    elif is_search_range and search_range_start <= ip_obj <= search_range_end:
                        matched_hosts.add(ip_obj)
                    elif not is_search_net and not is_search_range and ip_obj == search_host:
                        matched_hosts.add(ip_obj)
                except Exception:
                    pass

    # Process each matched host
    for host_ip in sorted(matched_hosts, key=lambda x: int(x)):
        host_str = str(host_ip)

        if is_search_net and is_new_net:
            offset = int(host_ip) - int(search_net.network_address)
            mapped_ip = str(ipaddress.ip_address(int(new_net.network_address) + offset))
        elif is_search_range and is_new_range:
            offset = int(host_ip) - int(search_range_start)
            mapped_ip = str(ipaddress.ip_address(int(new_range_start) + offset))
        elif not is_new_net and not is_new_range:
            mapped_ip = new_ip_text
        else:
            mapped_ip = new_ip_text

        # Use default name for hosts unless a preferred name is provided
        host_preferred_name = preferred_name if preferred_name else gen_default_name_for_ip(mapped_ip)
        used_obj_name = ensure_object_and_reuse_if_present(
            root,
            mapped_ip,
            host_preferred_name,
            description,
            tags,
            changelog,
            based_on=f"{host_str}->{mapped_ip}"
        )

        orig_obj_name = host_to_obj.get(host_str)

        for r_elem in rules_elems:
            update_section(
                root, r_elem, 'source',
                host_str, orig_obj_name, used_obj_name,
                changelog,
                context=f"mapped_from_{host_str}_based_on_{orig_obj_name or 'literal'}"
            )
            update_section(
                root, r_elem, 'destination',
                host_str, orig_obj_name, used_obj_name,
                changelog,
                context=f"mapped_from_{host_str}_based_on_{orig_obj_name or 'literal'}"
            )

        for g in groups:
            update_section(
                root, g, 'static',
                host_str, orig_obj_name, used_obj_name,
                changelog,
                context=f"mapped_from_{host_str}_based_on_{orig_obj_name or 'literal'}",
                is_group=True
            )

    # (NEW) Remap ip-range address objects when mapping net->net.
    # We only remap ranges that are fully contained in the search subnet (safe behavior).
    if is_search_net and is_new_net:
        for e, ipvals in entries:
            for iv in ipvals:
                if iv['type'] != 'range':
                    continue

                rs, rt = iv['value']  # start/end as ipaddress objects
                old_range_text = iv['text']
                old_range_obj = entry_name(e)

                # only handle ranges fully inside the search_net
                if not (rs in search_net and rt in search_net):
                    changelog.append({
                        'timestamp': ts(),
                        'action': 'skip_range_not_fully_in_search_net',
                        'range': old_range_text,
                        'range_object': old_range_obj,
                        'search_net': str(search_net),
                        'new_net': str(new_net),
                    })
                    continue

                start_off = int(rs) - int(search_net.network_address)
                end_off = int(rt) - int(search_net.network_address)

                new_rs = ipaddress.ip_address(int(new_net.network_address) + start_off)
                new_rt = ipaddress.ip_address(int(new_net.network_address) + end_off)
                new_range_text = f"{new_rs}-{new_rt}"

                new_range_obj = ensure_object_and_reuse_if_present(
                    root,
                    new_range_text,
                    preferred_name=None,  # let it generate svb_m2_... for ranges
                    description=description,
                    tags=tags,
                    changelog=changelog,
                    based_on=f"range_in_{search_ip_text}->{new_ip_text}:{old_range_text}"
                )

                for r_elem in rules_elems:
                    update_section(
                        root, r_elem, 'source',
                        old_range_text, old_range_obj, new_range_obj,
                        changelog,
                        context=f"range_mapping_{old_range_text}->{new_range_text}"
                    )
                    update_section(
                        root, r_elem, 'destination',
                        old_range_text, old_range_obj, new_range_obj,
                        changelog,
                        context=f"range_mapping_{old_range_text}->{new_range_text}"
                    )

                for g in groups:
                    update_section(
                        root, g, 'static',
                        old_range_text, old_range_obj, new_range_obj,
                        changelog,
                        context=f"range_mapping_{old_range_text}->{new_range_text}",
                        is_group=True
                    )

                changelog.append({
                    'timestamp': ts(),
                    'action': 'range_remapped',
                    'search_net': str(search_net),
                    'new_net': str(new_net),
                    'old_range': old_range_text,
                    'old_range_object': old_range_obj,
                    'new_range': new_range_text,
                    'new_range_object': new_range_obj,
                })

    # Container-level mapping: add mapped network/range object to rules/groups
    if (is_search_net or is_search_range) and new_container_name:
        search_container_str = search_ip_text
        for r_elem in rules_elems:
            update_section(
                root, r_elem, 'source',
                search_container_str, search_obj_name, new_container_name,
                changelog,
                context=f"container_mapping_{search_ip_text}->{new_ip_text}"
            )
            update_section(
                root, r_elem, 'destination',
                search_container_str, search_obj_name, new_container_name,
                changelog,
                context=f"container_mapping_{search_ip_text}->{new_ip_text}"
            )
        for g in groups:
            update_section(
                root, g, 'static',
                search_container_str, search_obj_name, new_container_name,
                changelog,
                context=f"container_mapping_{search_ip_text}->{new_ip_text}",
                is_group=True
            )

    changelog.append({
        'timestamp': ts(),
        'action': 'processed_csv_row',
        'search_ip': search_ip_text,
        'new_ip': new_ip_text,
        'preferred_name': preferred_name
    })

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="Palo Alto XML IP mapping without zone injection or FQDN resolution")
    parser.add_argument('--config', default='running-config.xml')
    parser.add_argument('--csv', default='ip_map.txt')
    parser.add_argument('--out', default='modified-config.xml')
    parser.add_argument('--changelog', default='changelog.json')
    args = parser.parse_args()

    try:
        tree = ET.parse(args.config)
        root = tree.getroot()
    except Exception as e:
        print("Failed to parse config:", e)
        sys.exit(1)

    changelog: List[dict] = []

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

            changelog.append({'timestamp': ts(), 'action': 'processing_row', 'search_ip': search_ip, 'new_ip': new_ip, 'preferred_name': preferred})
            process_row(root, search_ip, new_ip, preferred, tags, desc, changelog)

    tree.write(args.out, encoding='utf-8', xml_declaration=True)
    with open(args.changelog, 'w') as cfh:
        json.dump(changelog, cfh, indent=2)

    print(f"Modified config written to {args.out}")
    print(f"Changelog written to {args.changelog}")

if __name__ == '__main__':
    main()