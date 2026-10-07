"""app/multisite/pan_mirror.py

Mirror NSX groups onto a Panorama device group EXACTLY: same group type, same
membership, same tags (Mike, 2026-10-04). Pure: NSX data in, Panorama object
plan out, with the exact REST API payload each object would be written as.
The XML API is not used (Mike, 2026-10-05): writes go through the Panorama
REST API (Objects/Tags, Objects/Addresses, Objects/AddressGroups).

HOW EACH NSX PIECE MAPS

  NSX                                   Panorama (objects in shared by default,
                                        see MirrorOptions.object_location)
  VM (with IP)                          address object NAMED BY ITS HOSTNAME
                                        (NSX `hostname` tag), carrying ALL of
                                        the VM's NSX tags
  IPAddressExpression entry             address object NAMED BY THE ADDRESS
                                        (10.6.0.50, 10.6.1.0_24, a-b range)
  NSX tag scope|value                   tag "<scope>.<value>" (format option)
  Tag-only group (conditions, AND/OR,   DYNAMIC address group, same name,
    nested conditions)                  filter on the same tags, same AND/OR
  IP-only group                         STATIC address group of the address objects
  Group of groups (PathExpression)      STATIC address group of those groups
  ExternalIDExpression (VMs by id)      STATIC address group of those VMs' objects
  Mixed group (tags OR addresses OR     STATIC group holding a helper dynamic
    groups)                             group "<name>-tags" plus the rest; a
                                        Panorama group cannot be both kinds

  Not representable, reported as findings: segment paths, conditions other
  than VirtualMachine Tag EQUALS, MAC addresses, empty groups.

Panorama shares ONE namespace for address objects and address groups in a
scope, so every name is checked against both.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

NAME_MAX = 63
TAG_MAX = 127


@dataclass
class MirrorOptions:
    device_group: str = "dg-5"
    hostname_scope: str = "hostname"
    tag_format: str = "{scope}.{value}"      # a tag with an empty scope is just "{value}"
    vm_types: Tuple[str, ...] = ("REGULAR",)
    include_system: bool = False
    # Where address objects, address groups, services and service groups are
    # created: "shared" (Mike, 2026-10-06: usable by every device group) or
    # "device-group" on Panorama; "vsys" when writing directly to a firewall
    # (Mike, 2026-10-06: direct to palo5). Rules go to device_group, or to the
    # firewall's vsys.
    object_location: str = "shared"
    vsys: str = "vsys1"


def safe_name(text: str, max_len: int = NAME_MAX) -> str:
    """Panorama object name: letters, digits, '.', '_', '-', space; at most
    max_len characters, longer names keep a hash suffix so they never collide."""
    s = re.sub(r"[^A-Za-z0-9._ -]+", "_", (text or "").strip())
    s = re.sub(r"_+", "_", s).strip(" ") or "unnamed"
    if len(s) <= max_len:
        return s
    h = hashlib.md5(s.encode("utf-8")).hexdigest()[:7]
    return f"{s[:max_len - 8]}_{h}"


def tag_name(scope: str, value: str, fmt: str) -> str:
    scope, value = (scope or "").strip(), (value or "").strip()
    raw = fmt.format(scope=scope, value=value) if scope else value
    return safe_name(raw, TAG_MAX)


def ip_object(token: str) -> Optional[Dict[str, str]]:
    """An address entry -> {name, type, value}, named by the address itself."""
    t = (token or "").strip()
    if "-" in t and "/" not in t:
        a, b = (x.strip() for x in t.split("-", 1))
        try:
            ipaddress.ip_address(a), ipaddress.ip_address(b)
        except ValueError:
            return None
        return {"name": safe_name(f"{a}-{b}"), "type": "ip-range", "value": f"{a}-{b}"}
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return None
    if net.num_addresses == 1:
        return {"name": safe_name(str(net.network_address)), "type": "ip-netmask",
                "value": f"{net.network_address}/{net.prefixlen}"}
    return {"name": safe_name(f"{net.network_address}_{net.prefixlen}"), "type": "ip-netmask",
            "value": str(net)}


def _usable_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_link_local or a.is_loopback or a.is_unspecified)


def _parse_tag_value(value: str) -> Tuple[str, str]:
    """NSX condition value is "scope|tag" (scope first); "|tag" or "tag" has no scope."""
    if "|" in (value or ""):
        scope, tag = value.split("|", 1)
        return scope.strip(), tag.strip()
    return "", (value or "").strip()


# ---------------------------------------------------------------------------
# Expression -> parts
# ---------------------------------------------------------------------------

class _Parts:
    def __init__(self) -> None:
        self.filter_terms: List[str] = []      # alternating: term, op, term ...
        self.ips: List[str] = []
        self.group_paths: List[str] = []
        self.ext_ids: List[str] = []
        self.unsupported: List[str] = []
        self.tags_used: List[Tuple[str, str]] = []


def _condition_term(e: Dict[str, Any], opts: MirrorOptions, parts: _Parts) -> Optional[str]:
    if (e.get("member_type") != "VirtualMachine" or e.get("key") != "Tag"
            or e.get("operator") != "EQUALS"):
        parts.unsupported.append(f"condition {e.get('member_type')}.{e.get('key')} "
                                 f"{e.get('operator')} {e.get('value')!r}")
        return None
    scope, tag = _parse_tag_value(e.get("value", ""))
    if not tag:
        parts.unsupported.append(f"tag condition with no tag value ({e.get('value')!r}): "
                                 f"matches any tag in scope {scope!r}, no Panorama equivalent")
        return None
    parts.tags_used.append((scope, tag))
    return f"'{tag_name(scope, tag, opts.tag_format)}'"


def _nested_filter(exprs: Sequence[Dict[str, Any]], opts: MirrorOptions, parts: _Parts) -> Optional[str]:
    """A NestedExpression that holds only conditions -> one parenthesized filter."""
    out: List[str] = []
    for e in exprs or []:
        rt = e.get("resource_type")
        if rt == "Condition":
            t = _condition_term(e, opts, parts)
            if t is None:
                return None
            out.append(t)
        elif rt == "ConjunctionOperator":
            out.append(e.get("conjunction_operator", "OR").lower())
        elif rt == "NestedExpression":
            inner = _nested_filter(e.get("expressions"), opts, parts)
            if inner is None:
                return None
            out.append(inner)
        else:
            parts.unsupported.append(f"{rt} inside a nested expression")
            return None
    return "(" + " ".join(out) + ")" if out else None


def split_expression(expr: Sequence[Dict[str, Any]], opts: MirrorOptions) -> _Parts:
    parts = _Parts()
    pending_op: Optional[str] = None
    for e in expr or []:
        rt = e.get("resource_type")
        if rt == "ConjunctionOperator":
            pending_op = e.get("conjunction_operator", "OR").lower()
            continue
        term: Optional[str] = None
        if rt == "Condition":
            term = _condition_term(e, opts, parts)
        elif rt == "NestedExpression":
            term = _nested_filter(e.get("expressions"), opts, parts)
        elif rt == "IPAddressExpression":
            parts.ips.extend(e.get("ip_addresses") or [])
        elif rt == "PathExpression":
            for p in e.get("paths") or []:
                (parts.group_paths if "/groups/" in p else parts.unsupported).append(
                    p if "/groups/" in p else f"path member {p} (not a group)")
        elif rt == "ExternalIDExpression":
            parts.ext_ids.extend(e.get("external_ids") or [])
        else:
            parts.unsupported.append(f"{rt}")
        if term is not None:
            if parts.filter_terms:
                parts.filter_terms.append(pending_op or "or")
            parts.filter_terms.append(term)
        elif rt not in ("Condition", "NestedExpression") and pending_op == "and":
            parts.unsupported.append(f"AND joining a {rt} (NSX allows only OR across member kinds)")
        pending_op = None
    return parts


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

def _group_path(g: Dict[str, Any]) -> str:
    return g.get("path") or f"/infra/domains/default/groups/{g.get('id')}"


def build_mirror(groups: List[Dict[str, Any]], vms: List[Dict[str, Any]],
                 opts: Optional[MirrorOptions] = None,
                 only: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """`only`: NSX group display names or ids to mirror (plus every group they
    nest, so the plan is complete). None mirrors every non-system group."""
    opts = opts or MirrorOptions()
    findings: List[Dict[str, Any]] = []
    by_path = {_group_path(g): g for g in groups}
    by_key = {}
    for g in groups:
        by_key[g.get("display_name")] = g
        by_key[g.get("id")] = g

    if only is None:
        chosen = [g for g in groups if opts.include_system or not g.get("_system_owned")]
    else:
        chosen, queue, seen = [], [], set()
        for k in only:
            if k not in by_key:
                findings.append({"severity": "error", "code": "group_not_found", "group": k,
                                 "detail": "no NSX group with that name or id"})
            else:
                queue.append(by_key[k])
        while queue:
            g = queue.pop(0)
            if _group_path(g) in seen:
                continue
            seen.add(_group_path(g))
            chosen.append(g)
            for p in split_expression(g.get("expression"), opts).group_paths:
                if p in by_path:
                    queue.append(by_path[p])

    # ---- VMs: hostname-named objects carrying every NSX tag ---------------
    vm_by_ext: Dict[str, Dict[str, Any]] = {}
    for vm in vms:
        if vm.get("type") in opts.vm_types and vm.get("external_id"):
            vm_by_ext[vm["external_id"]] = vm

    group_plans: List[Dict[str, Any]] = []
    tags_used: Set[Tuple[str, str]] = set()
    ip_tokens: List[str] = []
    ext_needed: Set[str] = set()
    for g in chosen:
        gname = safe_name(g.get("display_name") or g.get("id"))
        parts = split_expression(g.get("expression"), opts)
        tags_used |= set(parts.tags_used)
        for u in parts.unsupported:
            findings.append({"severity": "warning", "code": "not_mirrored", "group": gname,
                             "detail": f"left out on Panorama: {u}"})
        flt = " ".join(parts.filter_terms) if parts.filter_terms else ""
        if flt and " and " in flt and " or " in f" {flt} ".replace("(", " ").replace(")", " "):
            pass  # nested parentheses carry NSX's grouping; flat mixes are rare and kept as written
        members: List[str] = []
        ip_objs = [o for o in (ip_object(t) for t in parts.ips) if o]
        for t in parts.ips:
            if ip_object(t) is None:
                findings.append({"severity": "warning", "code": "bad_address", "group": gname,
                                 "detail": f"address {t!r} is not an IP, CIDR or range"})
        ip_tokens.extend(parts.ips)
        members += [o["name"] for o in ip_objs]
        for p in parts.group_paths:
            ref = by_path.get(p)
            if ref is None:
                findings.append({"severity": "error", "code": "nested_group_missing", "group": gname,
                                 "detail": f"nests {p}, which NSX does not return"})
            else:
                members.append(safe_name(ref.get("display_name") or ref.get("id")))
        ext_needed |= set(parts.ext_ids)
        members_vm_ext = list(parts.ext_ids)

        kinds = [bool(flt), bool(ip_objs or parts.group_paths or parts.ext_ids)]
        entry: Dict[str, Any] = {"name": gname, "nsx_group": g.get("display_name"),
                                 "nsx_path": _group_path(g), "helper_for": None}
        if flt and not kinds[1]:
            entry.update(kind="dynamic", filter=flt)
            group_plans.append(entry)
        elif kinds[1] or flt:
            if flt:
                helper = safe_name(f"{gname}-tags")
                group_plans.append({"name": helper, "kind": "dynamic", "filter": flt,
                                    "nsx_group": g.get("display_name"), "nsx_path": _group_path(g),
                                    "helper_for": gname})
                members.insert(0, helper)
                findings.append({"severity": "info", "code": "mixed_group", "group": gname,
                                 "detail": f"tags and addresses in one NSX group: Panorama gets static "
                                           f"group {gname} holding dynamic group {helper}"})
            entry.update(kind="static", members=members, members_vm_ext=members_vm_ext)
            group_plans.append(entry)
        else:
            findings.append({"severity": "warning", "code": "empty_group", "group": gname,
                             "detail": "nothing Panorama can represent (empty, or only unsupported "
                                       "members); no Panorama group is created"})
        if parts.unsupported and (flt or kinds[1]):
            entry["partial"] = True

    # VMs relevant to the chosen groups: any VM carrying a tag a filter uses,
    # or named by an ExternalIDExpression.
    def vm_tags(vm):
        return {(t.get("scope") or "", t.get("tag") or "") for t in vm.get("tags") or []}

    addresses: List[Dict[str, Any]] = []
    vm_obj_name: Dict[str, str] = {}
    # Frozen before the loop: whether a VM is included must not depend on the
    # order VMs are visited (tags_used grows below with each VM's own tags).
    filter_tags = frozenset(tags_used)
    for ext, vm in sorted(vm_by_ext.items(), key=lambda kv: kv[1].get("display_name") or kv[0]):
        if not (vm_tags(vm) & filter_tags) and ext not in ext_needed:
            continue
        name = vm.get("display_name") or ext
        host = next((t.get("tag") for t in vm.get("tags") or []
                     if t.get("scope") == opts.hostname_scope and t.get("tag")), None)
        if not host:
            findings.append({"severity": "error", "code": "vm_missing_hostname", "vm": name,
                             "detail": f"no NSX tag with scope {opts.hostname_scope!r}; every VM must "
                                       f"have one, so no object is created"})
            continue
        ips = sorted(ip for ip in vm.get("ips") or [] if _usable_ip(ip))
        if not ips:
            findings.append({"severity": "warning", "code": "vm_without_ip", "vm": name,
                             "detail": "no IP from NSX (powered off or no VIF): no object, so "
                                       "dynamic groups cannot match it yet"})
            continue
        if len(ips) > 1:
            findings.append({"severity": "info", "code": "vm_multiple_ips", "vm": name,
                             "detail": f"{len(ips)} IPs: objects {host}, {host}-2 ..."})
        tags = sorted({tag_name(s, v, opts.tag_format) for s, v in vm_tags(vm) if v})
        for i, ip in enumerate(ips):
            obj_name = safe_name(host if i == 0 else f"{host}-{i + 1}")
            o = ip_object(ip)
            addresses.append({"name": obj_name, "type": o["type"], "value": o["value"],
                              "tags": tags, "description": f"NSX VM {name}", "source": "vm"})
            vm_obj_name.setdefault(ext, obj_name)
        tags_used |= {(s, v) for s, v in vm_tags(vm) if v}

    for gp in group_plans:
        for ext in gp.pop("members_vm_ext", []) or []:
            if ext in vm_obj_name:
                gp["members"].append(vm_obj_name[ext])
            else:
                findings.append({"severity": "warning", "code": "vm_member_not_mirrored",
                                 "group": gp["name"], "detail": f"VM {ext} has no object (see VM findings)"})

    seen_ip: Set[str] = set()
    for t in ip_tokens:
        o = ip_object(t)
        if o and o["name"] not in seen_ip:
            seen_ip.add(o["name"])
            addresses.append({**o, "tags": [], "description": "NSX group address entry",
                              "source": "address"})

    tags = sorted({tag_name(s, v, opts.tag_format) for s, v in tags_used})
    tag_objs = [{"name": t} for t in tags]

    # One namespace for addresses and address groups in a scope.
    owners: Dict[str, Dict[str, Any]] = {}
    for kind, items in (("address", addresses), ("address-group", group_plans)):
        for it in items:
            prev = owners.get(it["name"])
            if prev is None:
                owners[it["name"]] = {"kind": kind, "item": it}
            elif kind == "address" and prev["kind"] == "address" and prev["item"].get("value") == it.get("value"):
                continue
            else:
                findings.append({"severity": "error", "code": "name_clash", "object": it["name"],
                                 "detail": f"{prev['kind']} and {kind} would share the name {it['name']!r}"})
    for gp in group_plans:
        if gp["kind"] == "static" and not gp["members"]:
            findings.append({"severity": "error", "code": "static_group_empty", "group": gp["name"],
                             "detail": "a Panorama static group needs at least one member"})

    plan = {"device_group": opts.device_group, "options": opts.__dict__.copy(),
            "tags": tag_objs, "addresses": addresses, "address_groups": _order_groups(group_plans),
            "findings": findings}
    plan["writes"] = rest_writes(plan)
    plan["counts"] = {"tags": len(tag_objs), "addresses": len(addresses),
                      "dynamic_groups": sum(g["kind"] == "dynamic" for g in group_plans),
                      "static_groups": sum(g["kind"] == "static" for g in group_plans),
                      "errors": sum(f["severity"] == "error" for f in findings),
                      "warnings": sum(f["severity"] == "warning" for f in findings)}
    return plan


def _order_groups(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Members before the groups that hold them (dynamic first, then static
    groups in dependency order)."""
    names = {g["name"] for g in groups}
    done: Set[str] = set()
    out: List[Dict[str, Any]] = []
    pending = list(groups)
    while pending:
        progressed = False
        for g in list(pending):
            deps = [m for m in g.get("members", []) if m in names]
            if all(d in done for d in deps):
                out.append(g)
                done.add(g["name"])
                pending.remove(g)
                progressed = True
        if not progressed:          # a cycle: emit the rest as is; NSX forbids cycles anyway
            out.extend(pending)
            break
    return out


# ---------------------------------------------------------------------------
# Exact REST writes (Panorama REST API, one POST per object)
# ---------------------------------------------------------------------------

RESOURCE = {"tag": "Objects/Tags", "address": "Objects/Addresses",
            "address-group": "Objects/AddressGroups"}


def object_location(plan: Dict[str, Any]) -> str:
    """"shared" or "device-group" for the plan's objects (plans written before
    2026-10-06 carry no option: device group)."""
    return (plan.get("options") or {}).get("object_location") or "device-group"


def rest_writes(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every object as {kind, name, resource, location, device_group, entry}, in
    creation order: tags, addresses, then groups with members before holders.
    `entry` is the exact JSON body element for POST <resource>?location=shared
    &name=<name> (or location=device-group&device-group=<dg>&name=<name>)."""
    dg = plan["device_group"]
    loc = object_location(plan)
    vsys = (plan.get("options") or {}).get("vsys") or "vsys1"
    out: List[Dict[str, Any]] = []

    def add(kind: str, entry: Dict[str, Any]) -> None:
        out.append({"kind": kind, "name": entry["@name"], "resource": RESOURCE[kind],
                    "location": loc, "device_group": dg, "vsys": vsys, "entry": entry})

    for t in plan["tags"]:
        add("tag", {"@name": t["name"], "comments": "mirrored from NSX"})
    for a in plan["addresses"]:
        e: Dict[str, Any] = {"@name": a["name"], a["type"]: a["value"]}
        if a["tags"]:
            e["tag"] = {"member": list(a["tags"])}
        e["description"] = a["description"]
        add("address", e)
    for g in plan["address_groups"]:
        e = {"@name": g["name"]}
        if g["kind"] == "dynamic":
            e["dynamic"] = {"filter": g["filter"]}
        else:
            e["static"] = {"member": list(g["members"])}
        e["description"] = g.get("description") or (
            f"helper for {g['helper_for']} (NSX {g['nsx_group']})" if g.get("helper_for")
            else f"NSX group {g['nsx_group']}")
        add("address-group", e)
    return out


# ---------------------------------------------------------------------------
# Siblings only (Mike, 2026-10-05): the Palo gets the IP groups the
# workflows create and add to rules, with the same names as on NSX.
# ---------------------------------------------------------------------------

def _vm_ip_index(vms: List[Dict[str, Any]], opts: MirrorOptions) -> Tuple[Dict[str, List[Tuple[str, str]]], List[Dict[str, Any]]]:
    """Current VM address -> [(hostname, vm display name)], for VMs that carry
    the hostname tag. VMs without one are reported (every VM must have it)."""
    index: Dict[str, List[Tuple[str, str]]] = {}
    findings: List[Dict[str, Any]] = []
    for vm in vms:
        if vm.get("type") not in opts.vm_types:
            continue
        name = vm.get("display_name") or vm.get("external_id")
        host = next((t.get("tag") for t in vm.get("tags") or []
                     if t.get("scope") == opts.hostname_scope and t.get("tag")), None)
        ips = [ip for ip in vm.get("ips") or [] if _usable_ip(ip)]
        if not host:
            if ips:
                findings.append({"severity": "warning", "code": "vm_missing_hostname", "vm": name,
                                 "detail": f"no NSX tag with scope {opts.hostname_scope!r}; its addresses "
                                           f"are named by IP only"})
            continue
        for ip in ips:
            index.setdefault(str(ipaddress.ip_address(ip)), []).append((host, name))
    return index, findings


def build_sibling_mirror(bundles: List[Dict[str, Any]], vms: List[Dict[str, Any]],
                         opts: Optional[MirrorOptions] = None) -> Dict[str, Any]:
    """Static address groups for the sibling groups of one or more NSX sibling
    bundles (each {"path", "sibling_map"} from build_sibling_groups).

    Group name: the NSX sibling's display name (<group>_np_ips, _avs_ips, ...).
    Address object name (Mike, 2026-10-05): "<hostname>-<address>-<suffix>",
    e.g. ax2001-10.6.0.101-np_ips, where the hostname is the VM that owns the
    address (for a mapped address, the VM that owns the SOURCE address it was
    mapped from) and the suffix is the bundle's sibling suffix without its
    leading underscore. An address with no VM behind it (a subnet, a range, a
    hand-typed IP) is "<address>-<suffix>", e.g. 10.7.1.0_24-avs_ips. No
    tags, no dynamic groups. The same sibling from two bundles must hold the same
    members, else it is an error.
    """
    opts = opts or MirrorOptions()
    index, findings = _vm_ip_index(vms, opts)
    addresses: Dict[str, Dict[str, Any]] = {}
    groups: Dict[str, Dict[str, Any]] = {}

    def host_of(src: str) -> Optional[Tuple[str, str]]:
        try:
            net = ipaddress.ip_network(src.strip(), strict=False)
        except ValueError:
            return None
        if net.num_addresses != 1:
            return None
        owners = index.get(str(net.network_address), [])
        if len(owners) > 1:
            findings.append({"severity": "warning", "code": "address_shared_by_vms", "object": src,
                             "detail": f"{src} is the address of {len(owners)} VMs "
                                       f"({', '.join(n for _, n in owners)}); named by IP only"})
            return None
        return owners[0] if owners else None

    def add_address(addr: str, src: str, group: str, suffix: str) -> Optional[str]:
        o = ip_object(addr)
        if o is None:
            findings.append({"severity": "warning", "code": "bad_address", "group": group,
                             "detail": f"{addr!r} is not an IP, CIDR or range; left out"})
            return None
        owner = host_of(src) if o["type"] == "ip-netmask" and o["value"].endswith(("/32", "/128")) else None
        if owner:
            name = safe_name(f"{owner[0]}-{o['name']}{suffix}")
            desc = f"NSX VM {owner[1]}" + (f" (mapped from {src})" if src != addr else "")
        else:
            name, desc = safe_name(f"{o['name']}{suffix}"), (
                f"NSX sibling address (mapped from {src})" if src != addr else "NSX sibling address")
        prev = addresses.get(name)
        if prev and prev["value"] != o["value"]:
            findings.append({"severity": "error", "code": "name_clash", "object": name,
                             "detail": f"{prev['value']} and {o['value']} would share the name {name!r}"})
            return None
        addresses.setdefault(name, {"name": name, "type": o["type"], "value": o["value"],
                                    "tags": [], "description": desc, "source": "sibling"})
        return name

    for b in bundles:
        smap = b["sibling_map"]
        appendix = smap.get("appendix") or ""
        suffix = f"-{appendix.lstrip('_')}" if appendix else ""
        for row in smap.get("map", []):
            gname = safe_name(row.get("sibling_display_name") or row.get("sibling_id"))
            members: List[str] = []
            mapped = row.get("ips_sibling_mapped")
            if mapped is None:                       # source-address view (WF-C build)
                pairs = [(ip, [ip]) for ip in row.get("ips_source") or []]
            else:                                    # mapped view (WF-D build)
                pairs = [(src, list(dst or [])) for src, dst in row.get("ip_pairs") or []]
                flat = {d for _, ds in pairs for d in ds}
                if flat != set(mapped):
                    findings.append({"severity": "error", "code": "bundle_inconsistent", "group": gname,
                                     "detail": "ip_pairs and ips_sibling_mapped disagree in the bundle"})
            for src, dsts in pairs:
                for d in dsts:
                    n = add_address(d, src, gname, suffix)
                    if n and n not in members:
                        members.append(n)
            entry = {"name": gname, "kind": "static", "members": members,
                     "nsx_group": row.get("sibling_display_name"),
                     "nsx_original": row.get("original_display_name"),
                     "view": appendix, "bundle": b.get("path"), "helper_for": None}
            prev = groups.get(gname)
            if prev is None:
                groups[gname] = entry
            elif sorted(prev["members"]) != sorted(members):
                findings.append({"severity": "error", "code": "sibling_differs_between_bundles",
                                 "group": gname, "detail": f"{prev['bundle']} and {b.get('path')} hold "
                                                           f"different members for {gname}"})
        if not smap.get("map"):
            findings.append({"severity": "warning", "code": "bundle_empty", "object": b.get("path"),
                             "detail": "the bundle has no sibling groups"})

    plan_groups = []
    for g in groups.values():
        if not g["members"]:
            findings.append({"severity": "warning", "code": "empty_group", "group": g["name"],
                             "detail": "no addresses; a Panorama static group needs a member, so it is skipped"})
        else:
            plan_groups.append(g)
    plan = {"device_group": opts.device_group, "options": opts.__dict__.copy(), "mode": "siblings",
            "tags": [], "addresses": list(addresses.values()), "address_groups": plan_groups,
            "findings": findings}
    plan["writes"] = rest_writes(plan)
    plan["counts"] = {"tags": 0, "addresses": len(addresses), "dynamic_groups": 0,
                      "static_groups": len(plan_groups),
                      "named_by_hostname": sum(1 for a in addresses.values() if a["description"].startswith("NSX VM")),
                      "errors": sum(f["severity"] == "error" for f in findings),
                      "warnings": sum(f["severity"] == "warning" for f in findings)}
    return plan
