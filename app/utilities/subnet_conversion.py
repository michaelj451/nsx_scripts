#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Tuple

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e


@dataclass(frozen=True)
class SubnetMap:
    old: ipaddress._BaseNetwork
    new: ipaddress._BaseNetwork
    vlan: str | None = None
    description: str | None = None


def load_groups(path: Path) -> Any:
    """
    Loads YAML/JSON. Returns whatever the file contains (list/dict).
    Common shapes supported:
      - list of group dicts
      - dict with key 'results' containing list of group dicts
      - dict keyed by group name -> group dict
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".json"}:
        return json.loads(text)
    if path.suffix.lower() in {".yml", ".yaml"}:
        return yaml.safe_load(text)
    raise SystemExit(f"Unsupported input extension: {path.suffix} (use .yaml/.yml/.json)")


def write_output(path: Path, obj: Any) -> None:
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(obj, indent=2, sort_keys=False), encoding="utf-8")
        return
    if path.suffix.lower() in {".yml", ".yaml"}:
        path.write_text(yaml.safe_dump(obj, sort_keys=False), encoding="utf-8")
        return
    raise SystemExit(f"Unsupported output extension: {path.suffix} (use .yaml/.yml/.json)")


def read_csv_mappings(csv_path: Path) -> list[SubnetMap]:
    required = {"old_subnet", "new_subnet", "vlan", "description"}
    maps: list[SubnetMap] = []

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit("CSV has no headers.")
        missing = required - set(h.strip() for h in reader.fieldnames)
        if missing:
            raise SystemExit(f"CSV missing required headers: {sorted(missing)}")

        for row in reader:
            old_s = (row.get("old_subnet") or "").strip()
            new_s = (row.get("new_subnet") or "").strip()
            if not old_s or not new_s:
                continue

            old_net = ipaddress.ip_network(old_s, strict=False)
            new_net = ipaddress.ip_network(new_s, strict=False)

            # Keep it sane: v4->v4 and v6->v6 only
            if old_net.version != new_net.version:
                raise SystemExit(f"IP version mismatch: {old_net} -> {new_net}")

            maps.append(
                SubnetMap(
                    old=old_net,
                    new=new_net,
                    vlan=(row.get("vlan") or "").strip() or None,
                    description=(row.get("description") or "").strip() or None,
                )
            )

    # Prefer more specific old_subnets first to avoid “big net eats small net” problems
    maps.sort(key=lambda m: (m.old.version, -m.old.prefixlen))
    return maps

def looks_like_ip_or_cidr(s: str) -> bool:
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


def remap_ip_or_cidr(token: str, maps: list[SubnetMap]) -> str:
    """
    If token is an IP or CIDR and falls under any old subnet mapping, remap it to the new subnet
    preserving host offset. Otherwise return token unchanged.
    """
    # First: exact CIDR replacement if token is a network and equals old subnet
    try:
        net = ipaddress.ip_network(token, strict=False)
        for m in maps:
            if net == m.old:
                return str(m.new)
        # Remap a CIDR that is fully inside old subnet
        for m in maps:
            if net.version != m.old.version:
                continue
            if net.subnet_of(m.old):
                # preserve prefixlen, shift base address by offset
                old_base = int(net.network_address)
                old_root = int(m.old.network_address)
                new_root = int(m.new.network_address)
                offset = old_base - old_root
                new_base_ip = ipaddress.ip_address(new_root + offset)
                new_net = ipaddress.ip_network(f"{new_base_ip}/{net.prefixlen}", strict=False)
                return str(new_net)
        return token
    except ValueError:
        pass

    # IP address remap
    try:
        ip = ipaddress.ip_address(token)
        for m in maps:
            if ip.version != m.old.version:
                continue
            if ip in m.old:
                old_root = int(m.old.network_address)
                new_root = int(m.new.network_address)
                offset = int(ip) - old_root
                new_ip = ipaddress.ip_address(new_root + offset)
                return str(new_ip)
        return token
    except ValueError:
        return token


def deep_remap(obj: Any, maps: list[SubnetMap]) -> Any:
    """
    Recursively walk dict/list/scalars and remap any scalar strings that look like IP/CIDR.
    """
    if isinstance(obj, dict):
        return {k: deep_remap(v, maps) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deep_remap(v, maps) for v in obj]
    if isinstance(obj, str) and looks_like_ip_or_cidr(obj.strip()):
        return remap_ip_or_cidr(obj.strip(), maps)
    return obj


def pick_group(groups: Iterable[dict[str, Any]], name: str) -> dict[str, Any]:
    """
    Picks one group by matching common name keys.
    """
    candidates = []
    for g in groups:
        gn = (
            (g.get("display_name") or "")
            or (g.get("name") or "")
            or (g.get("id") or "")
        )
        if gn == name:
            return g
        if name.lower() in str(gn).lower():
            candidates.append(g)

    if len(candidates) == 1:
        return candidates[0]

    # If exact not found and substring ambiguous, fail loudly with options.
    known = []
    for g in groups:
        known.append((g.get("display_name") or g.get("name") or g.get("id") or "<unnamed>"))
    raise SystemExit(
        f"Group '{name}' not found uniquely.\n"
        f"- Exact match failed\n"
        f"- Substring matches: {len(candidates)}\n"
        f"Available group names (sample up to 50): {known[:50]}"
    )


def append_new_to_group_name(group: dict[str, Any]) -> None:
    """
    Appends 'new' to the group name/display_name without getting cute.
    """
    if "display_name" in group and isinstance(group["display_name"], str):
        group["display_name"] = f"{group['display_name']} new"
        return
    if "name" in group and isinstance(group["name"], str):
        group["name"] = f"{group['name']} new"
        return
    # fallback: do nothing if no name fields found

def find_groups_container(doc: Any) -> Tuple[Any, list[dict]]:
    """
    Return (container, groups_list).

    Supported shapes:
      A) [ {...}, {...} ]
      B) { "results": [ {...}, ... ] }
      C) { "groups":  [ {...}, ... ] }
      D) { "objects": { "groups": [ {...}, ... ] } }
      E) { "<domain>": { "groups": [ {...}, ... ] }, ... }   (or values contain groups)
      F) { "<name>": {...}, ... }  (dict keyed by group name -> group dict)
    """
    # A) list of groups
    if isinstance(doc, list):
        if all(isinstance(x, dict) for x in doc):
            return doc, doc

    # dict shapes
    if isinstance(doc, dict):
        # B) results
        if isinstance(doc.get("results"), list) and all(isinstance(x, dict) for x in doc["results"]):
            return doc, doc["results"]

        # C) groups at top level
        if isinstance(doc.get("groups"), list) and all(isinstance(x, dict) for x in doc["groups"]):
            return doc, doc["groups"]

        # D) objects.groups
        obj = doc.get("objects")
        if isinstance(obj, dict) and isinstance(obj.get("groups"), list) and all(isinstance(x, dict) for x in obj["groups"]):
            return obj, obj["groups"]

        # E) nested per-domain/per-manager wrappers
        # look for any dict value that contains a 'groups' list
        for v in doc.values():
            if isinstance(v, dict) and isinstance(v.get("groups"), list) and all(isinstance(x, dict) for x in v["groups"]):
                return v, v["groups"]

        # F) keyed dict of group objects
        if doc and all(isinstance(v, dict) for v in doc.values()):
            # avoid false positives like {"meta": {...}, "data": {...}}
            # If at least one entry looks like a group (has display_name/name/path/expression), accept.
            def looks_like_group(g: dict) -> bool:
                keys = set(g.keys())
                return bool(keys & {"display_name", "name", "path", "expression", "id"})
            values = list(doc.values())
            if any(looks_like_group(v) for v in values):
                return doc, values

    raise SystemExit(
        "Unrecognized groups document shape. "
        "Expected list, {results:[...]}, {groups:[...]}, {objects:{groups:[...]}}, "
        "or nested dict containing groups."
    )