#!/usr/bin/env python3
"""
pa_xml_zone_optimized.py

Usage:
  python pa_xml_zone_optimized.py --config running-config.xml --csv ip_map.csv --dg dg_zone.txt --out modified-config.xml --changelog changelog.json

CSV format (header required):
  search_ip,new_ip,new_object_name,tags,desc

DG->Zone mapping file (--dg) supports lines like:
  dg-3: zone-3
  dg-3,zone-3
  dg-3 zone-3
Comments (# ...) and blanks ignored.

Key behavior:
  - Updates SHARED + selected DEVICE-GROUP pre-rulebase security rules
  - Adds mapped address objects and adds mapped members into source/destination lists
  - If a DG rule changed src/dst, injects zone into <from>/<to>
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
from typing import Dict, Iterable, List, Optional, Set, Tuple


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
    - Ranges map ONLY if both endpoints are inside the SAME mapped old subnet
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
# Parsing files
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


def read_dg_zone_map(path: str) -> dict[str, str]:
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
# Panorama XML traversal
# -------------------------

@dataclass
class Scope:
    scope_name: str         # "shared" or "dg:<name>"
    root_elem: ET.Element
    address_elem: ET.Element


def find_dg_entries(cfg: ET.Element) -> List[ET.Element]:
    dgs = cfg.findall("./devices/entry[@name='localhost.localdomain']/device-group/entry")
    if not dgs:
        dgs = cfg.findall("./devices/entry/device-group/entry")
    return dgs


def build_scopes(cfg: ET.Element, dg_filter: Set[str]) -> List[Scope]:
    scopes: List[Scope] = []

    shared = cfg.find("./shared")
    if shared is not None:
        scopes.append(Scope("shared", shared, ensure_child(shared, "address")))

    for dg in find_dg_entries(cfg):
        dg_name = dg.attrib.get("name")
        if not dg_name or dg_name not in dg_filter:
            continue
        scopes.append(Scope(f"dg:{dg_name}", dg, ensure_child(dg, "address")))

    return scopes


def index_address_objects(address_elem: ET.Element) -> Dict[str, ET.Element]:
    out: Dict[str, ET.Element] = {}
    for e in address_elem.findall("./entry"):
        n = entry_name(e)
        if n:
            out[n] = e
    return out


def iter_rule_member_lists(scope_root: ET.Element) -> Iterable[Tuple[str, ET.Element]]:
    for rule in scope_root.findall(".//pre-rulebase/security/rules/entry"):
        rname = rule.attrib.get("name", "")
        src = rule.find("./source")
        dst = rule.find("./destination")
        if src is not None:
            yield f"{rname}:source", src
        if dst is not None:
            yield f"{rname}:destination", dst


def iter_security_rule_entries(root: ET.Element, device_groups: Optional[Set[str]] = None):
    for rule in root.findall("./shared/pre-rulebase/security/rules/entry"):
        yield ("shared", None, rule)

    for dg in find_dg_entries(root):
        dg_name = dg.attrib.get("name")
        if not dg_name:
            continue
        if device_groups is not None and dg_name not in device_groups:
            continue
        for rule in dg.findall("./pre-rulebase/security/rules/entry"):
            yield ("device-group", dg_name, rule)


def inject_zones_if_needed(
    rule: ET.Element,
    dg_name: str | None,
    dg_to_zone: dict[str, str],
    changed_src: bool,
    changed_dst: bool,
) -> None:
    if not dg_name:
        return
    zone = dg_to_zone.get(dg_name)
    if not zone:
        return

    def ensure_member(parent_tag: str, member_value: str) -> None:
        node = rule.find(parent_tag)
        if node is None:
            node = ET.SubElement(rule, parent_tag)
        members = [m.text for m in node.findall("member")]
        if member_value not in members:
            ET.SubElement(node, "member").text = member_value

    if changed_src:
        ensure_member("from", zone)
    if changed_dst:
        ensure_member("to", zone)


# -------------------------
# Address value parsing / creation
# -------------------------

def parse_ip_netmask_text(text: str) -> Tuple[str, ipaddress._BaseAddress | ipaddress._BaseNetwork]:
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

def convert_scope(
    scope: Scope,
    mapper: SubnetMapper,
    changes: List[dict],
    shared_addr_elem: Optional[ET.Element],
) -> None:
    """
    FIX: DG scopes often reference SHARED address objects.
    So for lookups we use: local_index + shared_index (fallback).
    For creating new objects, we create them in the scope where the original object was found;
    if the original was only in shared, we create new object in shared (safe + avoids empty DG address containers).
    """
    local_index = index_address_objects(scope.address_elem)
    shared_index = index_address_objects(shared_addr_elem) if shared_addr_elem is not None else {}

    def lookup_addr(name: str) -> Tuple[Optional[ET.Element], str]:
        if name in local_index:
            return local_index[name], "local"
        if name in shared_index:
            return shared_index[name], "shared"
        return None, "missing"

    def ensure_object_in(target: str, name: str, kind: str, value: str, desc: Optional[str], src_obj: Optional[str]) -> None:
        if target == "local":
            idx = local_index
            addr_elem = scope.address_elem
            scope_name = scope.scope_name
        else:
            idx = shared_index
            if shared_addr_elem is None:
                return
            addr_elem = shared_addr_elem
            scope_name = "shared"

        if name in idx:
            return

        new_entry = build_address_entry(name, kind, value, desc)
        addr_elem.append(new_entry)
        idx[name] = new_entry
        changes.append({
            "ts": ts(),
            "scope": scope_name,
            "action": "add_address_object",
            "name": name,
            "kind": kind,
            "value": value,
            "desc": desc,
            "source_object": src_obj,
        })

    def mapped_name_for(row: CsvMapRow, value_str: str) -> str:
        if row.new_object_name and value_str == str(row.new):
            return row.new_object_name
        return gen_default_name_for_value(value_str)

    # 1) Pre-create mapped objects from LOCAL objects (and shared if we are in shared scope)
    #    This is mostly for convenience; the rule-driven phase will also ensure objects.
    seed_elems: List[Tuple[ET.Element, str]] = [(e, "local") for e in scope.address_elem.findall("./entry")]
    if scope.scope_name == "shared" and shared_addr_elem is not None:
        seed_elems = [(e, "shared") for e in shared_addr_elem.findall("./entry")]

    for entry, origin in seed_elems:
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
                ensure_object_in(origin, new_name, "ip-netmask", new_value, row.desc, obj_name)
            else:
                mapped = mapper.map_network(parsed)  # type: ignore[arg-type]
                if not mapped:
                    continue
                row, new_net = mapped
                new_value = str(new_net)
                new_name = mapped_name_for(row, new_value)
                ensure_object_in(origin, new_name, "ip-netmask", new_value, row.desc, obj_name)

        elif iprng is not None and iprng.text:
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
            ensure_object_in(origin, new_name, "ip-range", new_value, row.desc, obj_name)

    # 2) Update rules: add mapped members (this is what drives changed_src/dst)
    for hint, member_parent in iter_rule_member_lists(scope.root_elem):
        members = member_parent.findall("./member")
        if not members:
            continue

        existing_names = [m.text.strip() for m in members if m.text and m.text.strip()]
        existing_set = set(existing_names)

        for old_ref in list(existing_names):
            src_entry, origin = lookup_addr(old_ref)
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
                        ensure_object_in(origin, new_ref, "ip-netmask", new_value, row.desc, old_ref)
                else:
                    mapped = mapper.map_network(parsed)  # type: ignore[arg-type]
                    if mapped:
                        row, new_net = mapped
                        new_value = str(new_net)
                        new_ref = mapped_name_for(row, new_value)
                        ensure_object_in(origin, new_ref, "ip-netmask", new_value, row.desc, old_ref)

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
                    ensure_object_in(origin, new_ref, "ip-range", new_value, row.desc, old_ref)

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
# CLI / main
# -------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Input Panorama running-config.xml")
    ap.add_argument("--csv", required=True, help="CSV mapping file")
    ap.add_argument("--dg", required=True, help="Device Group to Zone mapping file (dg: zone per line)")
    ap.add_argument("--out", required=True, help="Output modified XML file")
    ap.add_argument("--changelog", required=True, help="Changelog file (.json or .jsonl)")
    args = ap.parse_args(argv)

    rows = read_csv_mappings(args.csv)
    mapper = SubnetMapper(rows)
    dg_to_zone = read_dg_zone_map(args.dg)
    dg_filter = set(dg_to_zone.keys())

    tree = ET.parse(args.config)
    cfg = tree.getroot()

    shared_elem = cfg.find("./shared")
    shared_addr_elem = ensure_child(shared_elem, "address") if shared_elem is not None else None

    changes: List[dict] = []

    scopes = build_scopes(cfg, dg_filter)
    for scope in scopes:
        convert_scope(scope, mapper, changes, shared_addr_elem)

    # Determine which DG rules changed (src/dst) from changes list
    touched: Dict[Tuple[str, str], Dict[str, bool]] = {}
    for ch in changes:
        if ch.get("action") != "add_rule_member":
            continue
        scope_name = ch.get("scope")
        rule_field = ch.get("rule_field")
        if not isinstance(scope_name, str) or not scope_name.startswith("dg:"):
            continue
        if not isinstance(rule_field, str) or ":" not in rule_field:
            continue

        dg_name = scope_name.split(":", 1)[1]
        rule_name, which = rule_field.rsplit(":", 1)
        key = (dg_name, rule_name)
        flags = touched.setdefault(key, {"src": False, "dst": False})
        if which == "source":
            flags["src"] = True
        elif which == "destination":
            flags["dst"] = True

    # Inject zones only where rules were modified
    for scope, dg_name, rule in iter_security_rule_entries(cfg, device_groups=dg_filter):
        if scope != "device-group" or not dg_name:
            continue
        rule_name = rule.attrib.get("name", "")
        flags = touched.get((dg_name, rule_name))
        if not flags:
            continue
        inject_zones_if_needed(
            rule=rule,
            dg_name=dg_name,
            dg_to_zone=dg_to_zone,
            changed_src=flags["src"],
            changed_dst=flags["dst"],
        )

    pretty_indent(cfg)
    tree.write(args.out, encoding="utf-8", xml_declaration=True)
    write_changelog(args.changelog, changes)

    print(f"Wrote: {args.out}")
    print(f"Changelog: {args.changelog} ({len(changes)} changes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())