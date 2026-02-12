#!/usr/bin/env python3
"""
Usage:
  python pa_xml_zone.py --config running-config.xml --csv ip_map.txt --dg dg_zone.txt --out modified-config.xml --changelog changelog.json

CSV format (header required):
  search_ip,new_ip,new_object_name,tags,desc

Example:
  10.1.1.0/24,10.1.2.0/24,,,something1
  10.2.1.0/24,10.2.2.0/24,,,something2
  10.3.1.0/24,10.3.2.0/24,,,something
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
from typing import Dict, List, Optional, Tuple, Iterable


# -------------------------
# Helpers
# -------------------------

def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def underscored(s: str) -> str:
    return s.replace('.', '_').replace('/', '_').replace(':', '_').replace('-', '_')


def gen_default_name_for_value(value: str) -> str:
    # Keep your original naming vibe but safe for PA object names.
    return f"svb_m1_{underscored(value)}"


def entry_name(elem: Optional[ET.Element]) -> Optional[str]:
    if elem is None:
        return None
    return elem.attrib.get("name")


def ensure_child(parent: ET.Element, tag: str) -> ET.Element:
    c = parent.find(tag)
    if c is None:
        c = ET.SubElement(parent, tag)
    return c


def pretty_indent(elem: ET.Element, level: int = 0) -> None:
    # ElementTree doesn't preserve original formatting.
    # This makes the output readable; Panorama does not care about whitespace.
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        for child in elem:
            pretty_indent(child, level + 1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if not elem.tail or not elem.tail.strip():
            elem.tail = i


# -------------------------
# Mapping model
# -------------------------

@dataclass(frozen=True)
class CsvMapRow:
    old: ipaddress.IPv4Network | ipaddress.IPv6Network
    new: ipaddress.IPv4Network | ipaddress.IPv6Network
    new_object_name: Optional[str]
    tags: Optional[str]
    desc: Optional[str]


class SubnetMapper:
    """
    Maps any IP / subnet / range that is *contained within* one of the old networks
    to the corresponding value in the new network by preserving host offsets.

    Key behavior:
      - Most specific old subnet wins (sort by prefixlen desc)
      - Ranges are ONLY mapped if both endpoints are inside the same mapped old subnet
    """

    def __init__(self, rows: List[CsvMapRow]) -> None:
        # most-specific-first avoids accidental matches when you have nested mappings
        self.rows = sorted(rows, key=lambda r: r.old.prefixlen, reverse=True)

    def find_row_for_ip(self, ip: ipaddress._BaseAddress) -> Optional[CsvMapRow]:
        for r in self.rows:
            if ip.version != r.old.version:
                continue
            if ip in r.old:
                return r
        return None

    def find_row_for_net(self, net: ipaddress._BaseNetwork) -> Optional[CsvMapRow]:
        # containment: only if this net is fully inside the mapping old net
        for r in self.rows:
            if net.version != r.old.version:
                continue
            if net.subnet_of(r.old):
                return r
        return None

    def map_ip(self, ip: ipaddress._BaseAddress) -> Optional[Tuple[CsvMapRow, ipaddress._BaseAddress]]:
        r = self.find_row_for_ip(ip)
        if not r:
            return None
        # offset within old -> same offset within new
        offset = int(ip) - int(r.old.network_address)
        mapped = ipaddress.ip_address(int(r.new.network_address) + offset)
        # safety: must land inside r.new
        if mapped not in r.new:
            return None
        return r, mapped

    def map_network(self, net: ipaddress._BaseNetwork) -> Optional[Tuple[CsvMapRow, ipaddress._BaseNetwork]]:
        r = self.find_row_for_net(net)
        if not r:
            return None
        # preserve the *network address offset* and keep prefixlen the same
        offset = int(net.network_address) - int(r.old.network_address)
        new_net_addr = ipaddress.ip_address(int(r.new.network_address) + offset)
        mapped = ipaddress.ip_network(f"{new_net_addr}/{net.prefixlen}", strict=False)
        # safety: must remain inside r.new
        if not mapped.subnet_of(r.new):
            return None
        return r, mapped

    def map_range(self, start: ipaddress._BaseAddress, end: ipaddress._BaseAddress) -> Optional[Tuple[CsvMapRow, ipaddress._BaseAddress, ipaddress._BaseAddress]]:
        # FIX: range only maps if BOTH endpoints are inside the SAME old subnet mapping
        r1 = self.find_row_for_ip(start)
        r2 = self.find_row_for_ip(end)
        if not r1 or not r2 or r1.old != r2.old:
            return None
        m1 = self.map_ip(start)
        m2 = self.map_ip(end)
        if not m1 or not m2:
            return None
        _, ms = m1
        _, me = m2
        if int(ms) > int(me):
            ms, me = me, ms
        return r1, ms, me


# -------------------------
# Parsing CSV
# -------------------------

def read_csv_mappings(path: str) -> List[CsvMapRow]:
    rows: List[CsvMapRow] = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        required = {"search_ip", "new_ip"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise SystemExit(f"CSV must include headers: {sorted(required)} (got: {reader.fieldnames})")

        for i, row in enumerate(reader, start=2):
            search_ip = (row.get("search_ip") or "").strip()
            new_ip = (row.get("new_ip") or "").strip()
            if not search_ip or not new_ip:
                continue

            try:
                old_net = ipaddress.ip_network(search_ip, strict=False)
                new_net = ipaddress.ip_network(new_ip, strict=False)
            except ValueError as e:
                raise SystemExit(f"CSV line {i}: invalid network: {e}") from e

            if old_net.version != new_net.version:
                raise SystemExit(f"CSV line {i}: IP version mismatch: {old_net} -> {new_net}")

            new_object_name = (row.get("new_object_name") or "").strip() or None
            tags = (row.get("tags") or "").strip() or None
            desc = (row.get("desc") or "").strip() or None

            rows.append(CsvMapRow(old=old_net, new=new_net, new_object_name=new_object_name, tags=tags, desc=desc))
    return rows


def read_dg_list(path: str) -> List[str]:
    # Your file name might say dg_zone.txt but it’s a list; we’ll treat it as “device groups to process”.
    dgs: List[str] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            dgs.append(line)
    return dgs


# -------------------------
# Panorama XML traversal
# -------------------------

@dataclass
class Scope:
    scope_name: str   # "shared" or "dg:<name>"
    root_elem: ET.Element          # the element within which we update rules
    address_elem: ET.Element       # the <address> container we add objects into


def find_scopes(cfg: ET.Element, device_groups: List[str]) -> List[Scope]:
    scopes: List[Scope] = []

    shared = cfg.find("./shared")
    if shared is not None:
        addr = ensure_child(shared, "address")
        scopes.append(Scope(scope_name="shared", root_elem=shared, address_elem=addr))

    # Device groups live under /config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DG']
    localhost = cfg.find("./devices/entry[@name='localhost.localdomain']")
    if localhost is None:
        return scopes

    dg_root = localhost.find("./device-group")
    if dg_root is None:
        return scopes

    for dg_name in device_groups:
        dg_entry = dg_root.find(f"./entry[@name='{dg_name}']")
        if dg_entry is None:
            # Ignore missing DGs silently (keeps it drop-in friendly)
            continue
        addr = ensure_child(dg_entry, "address")
        scopes.append(Scope(scope_name=f"dg:{dg_name}", root_elem=dg_entry, address_elem=addr))

    return scopes


def index_address_objects(address_elem: ET.Element) -> Dict[str, ET.Element]:
    out: Dict[str, ET.Element] = {}
    for e in address_elem.findall("./entry"):
        n = entry_name(e)
        if n:
            out[n] = e
    return out


def iter_rule_member_lists(scope_root: ET.Element) -> Iterable[Tuple[str, ET.Element]]:
    """
    Yield (path_hint, member_parent_elem) for <source> and <destination> blocks.

    We target Security rules under:
      - shared/pre-rulebase/security/rules/entry
      - <dg>/pre-rulebase/security/rules/entry
    (You can extend later for post-rulebase/nat/etc if needed.)
    """
    for rule in scope_root.findall(".//pre-rulebase/security/rules/entry"):
        rname = rule.attrib.get("name", "")
        src = rule.find("./source")
        dst = rule.find("./destination")
        if src is not None:
            yield f"{rname}:source", src
        if dst is not None:
            yield f"{rname}:destination", dst


# -------------------------
# Address value parsing / creation
# -------------------------

def parse_ip_netmask_text(text: str) -> Tuple[str, ipaddress._BaseAddress | ipaddress._BaseNetwork]:
    """
    Palo Alto stores host and subnet both in <ip-netmask>.

    - If it contains '/', treat as network (e.g. 10.1.1.0/24)
    - Else treat as host IP (e.g. 10.1.1.1)
    """
    t = text.strip()
    if "/" in t:
        return "network", ipaddress.ip_network(t, strict=False)
    return "host", ipaddress.ip_address(t)


def parse_ip_range_text(text: str) -> Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]:
    t = text.strip()
    if "-" not in t:
        raise ValueError(f"Invalid ip-range (missing '-'): {t}")
    a, b = [p.strip() for p in t.split("-", 1)]
    return ipaddress.ip_address(a), ipaddress.ip_address(b)


def build_address_entry(name: str, kind: str, value: str, desc: Optional[str]) -> ET.Element:
    e = ET.Element("entry", {"name": name})
    child = ET.SubElement(e, kind)
    child.text = value
    if desc:
        d = ET.SubElement(e, "description")
        d.text = desc
    return e


# -------------------------
# Main conversion logic
# -------------------------

def convert_scope(scope: Scope, mapper: SubnetMapper, changes: List[dict]) -> None:
    addr_index = index_address_objects(scope.address_elem)

    def ensure_object(name: str, kind: str, value: str, desc: Optional[str], src_obj: Optional[str]) -> None:
        if name in addr_index:
            return
        new_entry = build_address_entry(name, kind, value, desc)
        scope.address_elem.append(new_entry)
        addr_index[name] = new_entry
        changes.append({
            "ts": ts(),
            "scope": scope.scope_name,
            "action": "add_address_object",
            "name": name,
            "kind": kind,
            "value": value,
            "desc": desc,
            "source_object": src_obj,
        })

    def mapped_name_for(row: CsvMapRow, value_str: str) -> str:
        # If CSV explicitly provides new_object_name, use it ONLY for the “base mapping object”
        # (i.e., when value_str exactly equals row.new for networks).
        # Otherwise derive from the new value string.
        if row.new_object_name and value_str == str(row.new):
            return row.new_object_name
        return gen_default_name_for_value(value_str)

    # 1) Walk existing address objects and pre-create mapped objects for anything inside mapped subnets
    for entry in list(scope.address_elem.findall("./entry")):
        obj_name = entry_name(entry)
        if not obj_name:
            continue

        ipnet = entry.find("./ip-netmask")
        iprng = entry.find("./ip-range")

        if ipnet is not None and ipnet.text:
            try:
                which, parsed = parse_ip_netmask_text(ipnet.text)
            except ValueError:
                continue

            if which == "host":
                mapped = mapper.map_ip(parsed)  # type: ignore[arg-type]
                if not mapped:
                    continue
                row, new_ip = mapped
                new_value = str(new_ip)
                new_name = mapped_name_for(row, new_value)
                ensure_object(new_name, "ip-netmask", new_value, row.desc, obj_name)

            else:
                mapped = mapper.map_network(parsed)  # type: ignore[arg-type]
                if not mapped:
                    continue
                row, new_net = mapped
                new_value = str(new_net)
                new_name = mapped_name_for(row, new_value)
                ensure_object(new_name, "ip-netmask", new_value, row.desc, obj_name)

        elif iprng is not None and iprng.text:
            # Range mapping (bugfix: only map if both endpoints in SAME old subnet mapping)
            try:
                start, end = parse_ip_range_text(iprng.text)
            except ValueError:
                continue
            mapped = mapper.map_range(start, end)
            if not mapped:
                continue
            row, new_start, new_end = mapped
            new_value = f"{new_start}-{new_end}"
            new_name = mapped_name_for(row, new_value)
            ensure_object(new_name, "ip-range", new_value, row.desc, obj_name)

    # 2) Update rules: for every referenced object that is “inside mapping”, add the mapped object name.
    #    We do this by looking up the referenced address object, reading its value, mapping it, and adding member.
    for hint, member_parent in iter_rule_member_lists(scope.root_elem):
        members = member_parent.findall("./member")
        if not members:
            continue

        existing_names = [m.text.strip() for m in members if m.text and m.text.strip()]
        existing_set = set(existing_names)

        for old_ref in list(existing_names):
            src_entry = addr_index.get(old_ref)
            if src_entry is None:
                continue

            ipnet = src_entry.find("./ip-netmask")
            iprng = src_entry.find("./ip-range")

            new_ref: Optional[str] = None
            if ipnet is not None and ipnet.text:
                try:
                    which, parsed = parse_ip_netmask_text(ipnet.text)
                except ValueError:
                    continue

                if which == "host":
                    mapped = mapper.map_ip(parsed)  # type: ignore[arg-type]
                    if mapped:
                        row, new_ip = mapped
                        new_value = str(new_ip)
                        new_ref = mapped_name_for(row, new_value)
                        ensure_object(new_ref, "ip-netmask", new_value, row.desc, old_ref)

                else:
                    mapped = mapper.map_network(parsed)  # type: ignore[arg-type]
                    if mapped:
                        row, new_net = mapped
                        new_value = str(new_net)
                        new_ref = mapped_name_for(row, new_value)
                        ensure_object(new_ref, "ip-netmask", new_value, row.desc, old_ref)

            elif iprng is not None and iprng.text:
                try:
                    start, end = parse_ip_range_text(iprng.text)
                except ValueError:
                    continue
                mapped = mapper.map_range(start, end)
                if mapped:
                    row, new_start, new_end = mapped
                    new_value = f"{new_start}-{new_end}"
                    new_ref = mapped_name_for(row, new_value)
                    ensure_object(new_ref, "ip-range", new_value, row.desc, old_ref)

            if new_ref and new_ref not in existing_set:
                ET.SubElement(member_parent, "member").text = new_ref
                existing_set.add(new_ref)
                changes.append({
                    "ts": ts(),
                    "scope": scope.scope_name,
                    "action": "add_rule_member",
                    "rule_field": hint,
                    "added_member": new_ref,
                    "because_of": old_ref,
                })


def write_changelog(path: str, changes: List[dict]) -> None:
    p = Path(path)
    if p.suffix.lower() == ".jsonl":
        with p.open("w", encoding="utf-8") as f:
            for obj in changes:
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    else:
        with p.open("w", encoding="utf-8") as f:
            json.dump(changes, f, indent=2, ensure_ascii=False)


# -------------------------
# CLI
# -------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Input Panorama running-config.xml")
    ap.add_argument("--csv", required=True, help="CSV mapping file")
    ap.add_argument("--dg", required=True, help="Text file listing device-group names (one per line)")
    ap.add_argument("--out", required=True, help="Output modified XML file")
    ap.add_argument("--changelog", required=True, help="Changelog file (.json or .jsonl)")

    args = ap.parse_args(argv)

    rows = read_csv_mappings(args.csv)
    mapper = SubnetMapper(rows)

    device_groups = read_dg_list(args.dg)

    tree = ET.parse(args.config)
    cfg = tree.getroot()

    scopes = find_scopes(cfg, device_groups)

    changes: List[dict] = []
    for s in scopes:
        convert_scope(s, mapper, changes)

    # Pretty output (Panorama does not care about whitespace, but humans do)
    pretty_indent(cfg)

    tree.write(args.out, encoding="utf-8", xml_declaration=True)
    write_changelog(args.changelog, changes)

    print(f"Wrote: {args.out}")
    print(f"Changelog: {args.changelog} ({len(changes)} changes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())