#!/usr/bin/env python3
"""
Usage:
  python pa_xml_zone_optimized.py --config running-config.xml --csv ip_map.txt --out modified-config.xml --dg dg_zone.txt --changelog changelog.jsonl

CSV format (header required):
  search_ip,new_ip,new_object_name,tags,desc

dg_zone.txt format (one per line; comments allowed):
  dg-3: zone-3
  dg-3,zone-3
  dg-3 zone-3
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


# -------------------------
# Helpers
# -------------------------

def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def underscored(s: str) -> str:
    return s.replace(".", "_").replace("/", "_").replace(":", "_").replace("-", "_")


def gen_default_name_for_value(value: str) -> str:
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
    Maps any IP / subnet / range that is contained within one of the old networks
    to the corresponding value in the new network by preserving host offsets.

    - Most specific old subnet wins (sort by prefixlen desc)
    - Ranges only map if both endpoints are inside the SAME mapped old subnet
    """

    def __init__(self, rows: List[CsvMapRow]) -> None:
        self.rows = sorted(rows, key=lambda r: r.old.prefixlen, reverse=True)

    def find_row_for_ip(self, ip: ipaddress._BaseAddress) -> Optional[CsvMapRow]:
        for r in self.rows:
            if ip.version != r.old.version:
                continue
            if ip in r.old:
                return r
        return None

    def find_row_for_net(self, net: ipaddress._BaseNetwork) -> Optional[CsvMapRow]:
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
        offset = int(ip) - int(r.old.network_address)
        mapped = ipaddress.ip_address(int(r.new.network_address) + offset)
        if mapped not in r.new:
            return None
        return r, mapped

    def map_network(self, net: ipaddress._BaseNetwork) -> Optional[Tuple[CsvMapRow, ipaddress._BaseNetwork]]:
        r = self.find_row_for_net(net)
        if not r:
            return None
        offset = int(net.network_address) - int(r.old.network_address)
        new_net_addr = ipaddress.ip_address(int(r.new.network_address) + offset)
        mapped = ipaddress.ip_network(f"{new_net_addr}/{net.prefixlen}", strict=False)
        if not mapped.subnet_of(r.new):
            return None
        return r, mapped

    def map_range(
        self,
        start: ipaddress._BaseAddress,
        end: ipaddress._BaseAddress,
    ) -> Optional[Tuple[CsvMapRow, ipaddress._BaseAddress, ipaddress._BaseAddress]]:
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


# -------------------------
# DG -> Zone mapping
# -------------------------

def read_dg_zone_map(path: str) -> dict[str, str]:
    """
    Reads a dg->zone mapping file.

    Supported lines:
      dg-3: zone-3
      dg-3,zone-3
      dg-3 zone-3

    Ignores blanks and comments (# ...).
    """
    mapping: dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if ":" in line:
                dg, zone = line.split(":", 1)
            elif "," in line:
                dg, zone = line.split(",", 1)
            else:
                parts = line.split()
                if len(parts) != 2:
                    raise ValueError(f"Bad dg->zone line: {raw!r}")
                dg, zone = parts

            dg = dg.strip()
            zone = zone.strip()
            if not dg or not zone:
                raise ValueError(f"Bad dg->zone line: {raw!r}")

            mapping[dg] = zone

    return mapping


# -------------------------
# Address value parsing / creation
# -------------------------

_RANGE_RE = re.compile(r"^\s*([0-9a-fA-F\.:]+)\s*-\s*([0-9a-fA-F\.:]+)\s*$")


def parse_ip_netmask_text(text: str) -> Tuple[str, ipaddress._BaseAddress | ipaddress._BaseNetwork]:
    t = text.strip()
    if "/" in t:
        return "network", ipaddress.ip_network(t, strict=False)
    return "host", ipaddress.ip_address(t)


def parse_ip_range_text(text: str) -> Tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]:
    m = _RANGE_RE.match(text.strip())
    if not m:
        raise ValueError(f"Invalid ip-range: {text!r}")
    return ipaddress.ip_address(m.group(1)), ipaddress.ip_address(m.group(2))


def classify_literal_member(text: str) -> Optional[Tuple[str, object]]:
    """
    Return ("host", ip), ("network", net), ("range", (start,end)) if the member text is a raw literal.
    Otherwise return None.
    """
    t = (text or "").strip()
    if not t:
        return None

    if "-" in t:
        try:
            a, b = parse_ip_range_text(t)
            return "range", (a, b)
        except ValueError:
            return None

    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
            return "network", net
        except ValueError:
            return None

    try:
        ip = ipaddress.ip_address(t)
        return "host", ip
    except ValueError:
        return None


def build_address_entry(name: str, kind: str, value: str, desc: Optional[str]) -> ET.Element:
    e = ET.Element("entry", {"name": name})
    child = ET.SubElement(e, kind)
    child.text = value
    if desc:
        d = ET.SubElement(e, "description")
        d.text = desc
    return e


def index_address_objects(address_elem: ET.Element) -> Dict[str, ET.Element]:
    out: Dict[str, ET.Element] = {}
    for e in address_elem.findall("./entry"):
        n = entry_name(e)
        if n:
            out[n] = e
    return out


# -------------------------
# Rule iteration (shared + DG, pre + post)
# -------------------------

def iter_security_rule_entries(root: ET.Element):
    """
    Yield tuples:
      (scope, dg_name, dg_entry, rule_entry)

    scope:
      - "shared"
      - "device-group"
    dg_name:
      - None for shared
      - DG name for device-group
    dg_entry:
      - None for shared
      - The DG <entry> element for DG
    """
    # Shared pre/post security rules
    for rule in root.findall("./shared/pre-rulebase/security/rules/entry"):
        yield ("shared", None, None, rule)
    for rule in root.findall("./shared/post-rulebase/security/rules/entry"):
        yield ("shared", None, None, rule)

    # Device-group pre/post security rules
    for dg in root.findall("./devices/entry/device-group/entry"):
        dg_name = dg.attrib.get("name")
        if not dg_name:
            continue

        for rule in dg.findall("./pre-rulebase/security/rules/entry"):
            yield ("device-group", dg_name, dg, rule)
        for rule in dg.findall("./post-rulebase/security/rules/entry"):
            yield ("device-group", dg_name, dg, rule)


# -------------------------
# Zone injection (DG only)
# -------------------------

def ensure_zone_members(rule: ET.Element, zone: str) -> bool:
    """
    For DG rules:
      - If <from>/<to> is missing -> create it with zone
      - If it contains 'any' -> remove 'any' and set zone
      - Ensure zone is present
    Returns True if modified.
    """
    changed = False

    def fix(tag: str) -> None:
        nonlocal changed
        node = rule.find(tag)
        if node is None:
            node = ET.SubElement(rule, tag)
            ET.SubElement(node, "member").text = zone
            changed = True
            return

        members = [m for m in node.findall("member")]
        texts = [m.text.strip() for m in members if m.text and m.text.strip()]

        # remove 'any' if present
        any_members = [m for m in members if (m.text or "").strip() == "any"]
        if any_members:
            for m in any_members:
                node.remove(m)
            changed = True
            texts = [t for t in texts if t != "any"]

        if zone not in texts:
            ET.SubElement(node, "member").text = zone
            changed = True

    fix("from")
    fix("to")
    return changed


# -------------------------
# Conversion logic per scope (shared and DG)
# -------------------------

def ensure_address_container_for_scope(root: ET.Element, scope: str, dg_entry: Optional[ET.Element]) -> ET.Element:
    if scope == "shared":
        shared = root.find("./shared")
        if shared is None:
            shared = ET.SubElement(root, "shared")
        return ensure_child(shared, "address")
    else:
        assert dg_entry is not None
        return ensure_child(dg_entry, "address")


def mapped_name_for(row: CsvMapRow, value_str: str) -> str:
    if row.new_object_name and value_str == str(row.new):
        return row.new_object_name
    return gen_default_name_for_value(value_str)


def ensure_object(
    address_elem: ET.Element,
    addr_index: Dict[str, ET.Element],
    changes: List[dict],
    scope_name: str,
    name: str,
    kind: str,
    value: str,
    desc: Optional[str],
    source_object: Optional[str],
) -> None:
    if name in addr_index:
        return
    new_entry = build_address_entry(name, kind, value, desc)
    address_elem.append(new_entry)
    addr_index[name] = new_entry
    changes.append({
        "ts": ts(),
        "scope": scope_name,
        "action": "add_address_object",
        "name": name,
        "kind": kind,
        "value": value,
        "desc": desc,
        "source_object": source_object,
    })


def map_or_create_from_literal(
    mapper: SubnetMapper,
    literal_kind: str,
    literal_obj: object,
    default_desc: Optional[str],
) -> Tuple[str, str, Optional[str]]:
    """
    Given a literal (host/net/range), return (addr_kind, addr_value, desc) to create/use.
    If it maps, use mapped value & CSV desc.
    Otherwise, use original literal value & default_desc.
    """
    if literal_kind == "host":
        ip = literal_obj  # type: ignore[assignment]
        mapped = mapper.map_ip(ip)  # type: ignore[arg-type]
        if mapped:
            row, new_ip = mapped
            return "ip-netmask", str(new_ip), row.desc
        return "ip-netmask", str(ip), default_desc

    if literal_kind == "network":
        net = literal_obj  # type: ignore[assignment]
        mapped = mapper.map_network(net)  # type: ignore[arg-type]
        if mapped:
            row, new_net = mapped
            return "ip-netmask", str(new_net), row.desc
        return "ip-netmask", str(net), default_desc

    # range
    start, end = literal_obj  # type: ignore[misc]
    mapped = mapper.map_range(start, end)
    if mapped:
        row, ns, ne = mapped
        return "ip-range", f"{ns}-{ne}", row.desc
    return "ip-range", f"{start}-{end}", default_desc


def process_rule_members(
    root: ET.Element,
    scope: str,
    dg_name: Optional[str],
    dg_entry: Optional[ET.Element],
    mapper: SubnetMapper,
    changes: List[dict],
    rule: ET.Element,
) -> Tuple[bool, bool]:
    """
    Update a rule's <source> and <destination> members:
      - For object references: if referenced object maps -> add mapped object reference
      - For raw literals in rules: create object (mapped if possible) and REPLACE literal with object name

    Returns (changed_src, changed_dst).
    """
    address_elem = ensure_address_container_for_scope(root, scope, dg_entry)
    addr_index = index_address_objects(address_elem)
    scope_name = "shared" if scope == "shared" else f"dg:{dg_name}"

    changed_src = False
    changed_dst = False

    def handle_block(block_tag: str) -> bool:
        nonlocal addr_index
        block = rule.find(block_tag)
        if block is None:
            return False

        members = block.findall("member")
        if not members:
            return False

        existing_texts = [(m.text or "").strip() for m in members]
        existing_set = set([t for t in existing_texts if t])

        modified = False

        # pass 1: convert raw literals to objects (replace member text)
        for m in members:
            txt = (m.text or "").strip()
            if not txt:
                continue

            lit = classify_literal_member(txt)
            if not lit:
                continue

            lit_kind, lit_obj = lit
            addr_kind, addr_value, desc = map_or_create_from_literal(mapper, lit_kind, lit_obj, default_desc=None)
            obj_name = gen_default_name_for_value(addr_value)

            ensure_object(
                address_elem=address_elem,
                addr_index=addr_index,
                changes=changes,
                scope_name=scope_name,
                name=obj_name,
                kind=addr_kind,
                value=addr_value,
                desc=desc,
                source_object=None,
            )

            if txt != obj_name:
                m.text = obj_name
                modified = True
                changes.append({
                    "ts": ts(),
                    "scope": scope_name,
                    "action": "replace_literal_with_object",
                    "rule": rule.attrib.get("name"),
                    "field": block_tag,
                    "literal": txt,
                    "object": obj_name,
                    "value": addr_value,
                })

        # refresh after replacements
        members = block.findall("member")
        existing_texts = [(m.text or "").strip() for m in members]
        existing_set = set([t for t in existing_texts if t])

        # pass 2: for existing object references, if object maps -> add mapped object member
        for ref in list(existing_set):
            src_entry = addr_index.get(ref)
            if src_entry is None:
                continue

            ipnet = src_entry.find("./ip-netmask")
            iprng = src_entry.find("./ip-range")

            new_ref: Optional[str] = None
            new_kind: Optional[str] = None
            new_value: Optional[str] = None
            new_desc: Optional[str] = None

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
                        new_desc = row.desc
                        new_ref = mapped_name_for(row, new_value)
                        new_kind = "ip-netmask"
                else:
                    mapped = mapper.map_network(parsed)  # type: ignore[arg-type]
                    if mapped:
                        row, new_net = mapped
                        new_value = str(new_net)
                        new_desc = row.desc
                        new_ref = mapped_name_for(row, new_value)
                        new_kind = "ip-netmask"

            elif iprng is not None and iprng.text:
                try:
                    start, end = parse_ip_range_text(iprng.text)
                except ValueError:
                    continue
                mapped = mapper.map_range(start, end)
                if mapped:
                    row, ns, ne = mapped
                    new_value = f"{ns}-{ne}"
                    new_desc = row.desc
                    new_ref = mapped_name_for(row, new_value)
                    new_kind = "ip-range"

            if new_ref and new_ref not in existing_set and new_kind and new_value:
                ensure_object(
                    address_elem=address_elem,
                    addr_index=addr_index,
                    changes=changes,
                    scope_name=scope_name,
                    name=new_ref,
                    kind=new_kind,
                    value=new_value,
                    desc=new_desc,
                    source_object=ref,
                )
                ET.SubElement(block, "member").text = new_ref
                existing_set.add(new_ref)
                modified = True
                changes.append({
                    "ts": ts(),
                    "scope": scope_name,
                    "action": "add_rule_member",
                    "rule": rule.attrib.get("name"),
                    "field": block_tag,
                    "added_member": new_ref,
                    "because_of": ref,
                })

        return modified

    if handle_block("source"):
        changed_src = True
    if handle_block("destination"):
        changed_dst = True

    return changed_src, changed_dst


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
# Main
# -------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Input Panorama running-config.xml")
    ap.add_argument("--csv", required=True, help="CSV mapping file")
    ap.add_argument("--dg", required=True, help="Device Group to Zone mapping file (dg: zone)")
    ap.add_argument("--out", required=True, help="Output modified XML file")
    ap.add_argument("--changelog", required=True, help="Changelog file (.json or .jsonl)")

    args = ap.parse_args(argv)

    mapper = SubnetMapper(read_csv_mappings(args.csv))
    dg_to_zone = read_dg_zone_map(args.dg)

    tree = ET.parse(args.config)
    cfg = tree.getroot()

    changes: List[dict] = []

    for scope, dg_name, dg_entry, rule in iter_security_rule_entries(cfg):
        # Always do address processing (shared + DG)
        changed_src, changed_dst = process_rule_members(
            root=cfg,
            scope=scope,
            dg_name=dg_name,
            dg_entry=dg_entry,
            mapper=mapper,
            changes=changes,
            rule=rule,
        )

        # Zone injection:
        # - ONLY for device-group rules
        # - ONLY if DG is mapped in dg_zone.txt
        if scope == "device-group" and dg_name and dg_name in dg_to_zone:
            zone = dg_to_zone[dg_name]
            z_changed = ensure_zone_members(rule, zone)
            if z_changed:
                changes.append({
                    "ts": ts(),
                    "scope": f"dg:{dg_name}",
                    "action": "ensure_zones",
                    "rule": rule.attrib.get("name"),
                    "zone": zone,
                })

        # Shared rules: never touch zones (by design)

    pretty_indent(cfg)
    tree.write(args.out, encoding="utf-8", xml_declaration=True)
    write_changelog(args.changelog, changes)

    print(f"Wrote: {args.out}")
    print(f"Changelog: {args.changelog} ({len(changes)} changes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())