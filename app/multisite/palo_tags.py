"""app/multisite/palo_tags.py

Palo Alto tag plan for the firewall between the NSX managers (dg-5).

Groups on the Palo are DYNAMIC address groups that match tags, instead of
static IP lists, so a VM's objects carry who it is and the groups follow:

  * Every VM IP becomes an address object tagged with the VM's HOSTNAME and
    its ASL_ID (every VM has one).
  * An NSX group with at most `threshold` member VMs (default 10) becomes a
    dynamic group matching its members' hostname tags:
        'hostname_ax2001' or 'hostname_0e02'
  * A group with MORE than `threshold` members gets its own SECURITY_GROUP
    tag, added to every member VM's objects, and the dynamic group matches
    that one tag:
        'security_group_web-tier'
  * Addresses in a group that belong to no known VM (hand-typed IPs and
    subnets, or a VM whose address the snapshot could not attribute) become
    static address objects tagged with the group's security_group tag, and
    that tag is OR'd into the group's filter. Nothing a rule matched today is
    dropped on the Palo.
  * With a multi-site map, each VM address is ALSO pre-staged at its mapped
    address for every site, with the same tags, so the dynamic group keeps
    matching the VM wherever it lands.

Input is a VM rule snapshot (tools/nsx/capture_vm_rule_data.py): it holds
the VMs (IPs, NSX tags), each group's evaluated members and IPs, and the
rules. Only groups that rules reference are planned unless all_groups=True.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from common import ipspan
from common.subnet_map import SiteMap

PAN_NAME_MAX = 63


@dataclass
class TagOptions:
    threshold: int = 10
    hostname_scope: str = "hostname"          # NSX tag scope; every VM must carry it
    asl_scope: str = "asl_id"
    vm_types: Tuple[str, ...] = ("REGULAR",)
    hostname_fmt: str = "hostname_{value}"
    asl_fmt: str = "asl_id_{value}"
    sg_fmt: str = "security_group_{group}"
    all_groups: bool = False


def pan_name(text: str, max_len: int = PAN_NAME_MAX) -> str:
    """A Panorama object or tag name: letters, digits, '.', '_', '-', space;
    at most 63 characters (longer names keep a hash suffix, never collide)."""
    s = re.sub(r"[^A-Za-z0-9._ -]+", "_", (text or "").strip())
    s = re.sub(r"_+", "_", s).strip("_ ") or "unnamed"
    if len(s) <= max_len:
        return s
    h = hashlib.md5(s.encode("utf-8")).hexdigest()[:7]
    return f"{s[:max_len - 8]}_{h}"


def _tag_value(vm: Dict[str, Any], scope: str) -> Optional[str]:
    for t in vm.get("tags") or []:
        if (t.get("scope") or "") == scope and (t.get("tag") or "").strip():
            return t["tag"].strip()
    return None


def _hostname(vm: Dict[str, Any], scope: str) -> Optional[str]:
    """The VM's hostname, from its NSX tag only. There is deliberately no
    fallback to the VM name or guest hostname: every VM must carry the tag
    (Mike, 2026-10-04), and a missing one is a blocking error."""
    return _tag_value(vm, scope)


def referenced_group_paths(snapshot: Dict[str, Any]) -> Dict[str, List[str]]:
    """group path -> display names of the enabled, non-default rules using it."""
    out: Dict[str, List[str]] = {}
    for r in snapshot.get("rules") or []:
        if r.get("disabled") or r.get("is_default"):
            continue
        for side in ("source_groups", "destination_groups"):
            for p in r.get(side) or []:
                if p and p != "ANY":
                    out.setdefault(p, [])
                    name = r.get("display_name") or r.get("id")
                    if name not in out[p]:
                        out[p].append(name)
    return out


def build_tag_plan(snapshot: Dict[str, Any], opts: TagOptions,
                   site_map: Optional[SiteMap] = None,
                   sites: Sequence[str] = ()) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    vms = {v.get("external_id"): v for v in snapshot.get("vms") or [] if v.get("external_id")}
    groups_by_path = snapshot.get("groups_by_path") or {}
    members = snapshot.get("group_to_members") or {}
    group_ips = snapshot.get("group_ips") or {}
    refs = referenced_group_paths(snapshot)
    paths = sorted(groups_by_path) if opts.all_groups else sorted(p for p in refs if p in groups_by_path)
    for p in sorted(set(refs) - set(groups_by_path)):
        findings.append({"severity": "error", "code": "rule_group_not_in_snapshot", "group": p,
                         "detail": "a rule references a group the snapshot does not hold"})

    # A loose group address that is exactly some known VM's IP is that VM:
    # the group's tag goes on the VM's object instead of a second object.
    ip_owner: Dict[ipspan.Span, str] = {}
    for vid, vm in vms.items():
        if vm.get("type") in opts.vm_types:
            for ip in vm.get("ips") or []:
                s = ipspan.try_span(ip)
                if s:
                    ip_owner.setdefault(s, vid)

    # ---- per-group membership and strategy ---------------------------------
    plan_groups: List[Dict[str, Any]] = []
    vm_sg_tags: Dict[str, Set[str]] = {}
    static_tags: Dict[ipspan.Span, Set[str]] = {}
    static_groups: Dict[ipspan.Span, Set[str]] = {}
    used_vms: Set[str] = set()
    for path in paths:
        meta = groups_by_path[path]
        gname = meta.get("display_name") or meta.get("id") or path.rsplit("/", 1)[-1]
        member_ids = [m for m in members.get(path) or [] if m in vms]
        vm_members = [m for m in member_ids if vms[m].get("type") in opts.vm_types]
        skipped_types = sorted({vms[m].get("type") for m in member_ids} - set(opts.vm_types))
        sg_tag = pan_name(opts.sg_fmt.format(group=gname), 127)
        strategy = "security_group" if len(vm_members) > opts.threshold else "hostname"

        # Group entries are kept exactly as NSX holds them (host, CIDR or
        # range). An entry is "loose" unless a member VM's own address
        # already covers it; a subnet is never split around a member VM.
        vm_union = ipspan.merge(s for m in vm_members for ip in vms[m].get("ips") or []
                                if (s := ipspan.try_span(ip)))
        unattributed: List[ipspan.Span] = []
        for ip in group_ips.get(path) or []:
            s = ipspan.try_span(ip)
            if s is None or any(ipspan.contains(u, s) for u in vm_union) or s in unattributed:
                continue
            unattributed.append(s)

        terms: List[str] = []
        no_hostname: List[str] = []
        if strategy == "security_group":
            for m in vm_members:
                vm_sg_tags.setdefault(m, set()).add(sg_tag)
            terms.append(sg_tag)
        else:
            for m in vm_members:
                h = _hostname(vms[m], opts.hostname_scope)
                if h:
                    terms.append(pan_name(opts.hostname_fmt.format(value=h), 127))
                else:
                    no_hostname.append(vms[m].get("display_name") or m)
        if no_hostname:
            findings.append({"severity": "error", "code": "group_member_without_hostname",
                             "group": gname, "detail": (
                                 f"{len(no_hostname)} member VM(s) have no hostname, so the "
                                 f"hostname filter leaves them out: {', '.join(no_hostname)}")})
        if unattributed:
            if sg_tag not in terms:
                terms.append(sg_tag)
            for s in unattributed:
                owner = ip_owner.get(s)
                if owner:
                    vm_sg_tags.setdefault(owner, set()).add(sg_tag)
                    used_vms.add(owner)
                else:
                    static_tags.setdefault(s, set()).add(sg_tag)
                    static_groups.setdefault(s, set()).add(gname)
        used_vms.update(vm_members)

        asl_ids = sorted({a for m in vm_members if (a := _tag_value(vms[m], opts.asl_scope))})
        entry = {
            "name": pan_name(gname), "nsx_group": gname, "nsx_path": path,
            "strategy": strategy, "member_vms": len(vm_members),
            "static_addresses": [ipspan.fmt(s) for s in unattributed],
            "asl_ids": asl_ids, "referenced_by_rules": refs.get(path, []),
            "filter": " or ".join(f"'{t}'" for t in dict.fromkeys(terms)),
            "skipped_member_types": skipped_types,
        }
        if not terms:
            entry["filter"] = ""
            findings.append({"severity": "warning", "code": "group_matches_nothing", "group": gname,
                             "detail": "no member VMs with a hostname and no addresses; the "
                                       "dynamic group would be empty"})
        plan_groups.append(entry)

    # ---- per-VM checks and address objects ---------------------------------
    host_owner: Dict[str, str] = {}
    objects: List[Dict[str, Any]] = []
    for m in sorted(used_vms, key=lambda x: vms[x].get("display_name") or x):
        vm = vms[m]
        name = vm.get("display_name") or m
        host = _hostname(vm, opts.hostname_scope)
        asl = _tag_value(vm, opts.asl_scope)
        if not asl:
            findings.append({"severity": "error", "code": "vm_missing_asl_id", "vm": name,
                             "detail": f"no NSX tag with scope {opts.asl_scope!r}; every VM must have one"})
        if not host:
            findings.append({"severity": "error", "code": "vm_missing_hostname", "vm": name,
                             "detail": f"no NSX tag with scope {opts.hostname_scope!r}; every VM must "
                                       f"have one (run the hostname tagging workflow)"})
        elif host in host_owner and host_owner[host] != name:
            findings.append({"severity": "error", "code": "duplicate_hostname", "vm": name,
                             "detail": f"hostname {host!r} is also on {host_owner[host]}; a hostname "
                                       f"tag would match both VMs"})
        else:
            host_owner[host] = name
        ips = [ip for ip in vm.get("ips") or [] if ipspan.try_span(ip)]
        if not ips:
            findings.append({"severity": "warning", "code": "vm_without_ip", "vm": name,
                             "detail": "no IP in the snapshot (powered off or no VIF); nothing "
                                       "to tag on the Palo until it has one"})
            continue
        tags = [t for t in (
            pan_name(opts.hostname_fmt.format(value=host), 127) if host else None,
            pan_name(opts.asl_fmt.format(value=asl), 127) if asl else None) if t]
        tags += sorted(vm_sg_tags.get(m, ()))
        for ip in ips:
            objects.append(_obj(f"{host or name}-{ip}", ip, tags, name, None))
            for site in sites:
                mapped = site_map.map_value(site, ip) if site_map else None
                if mapped:
                    objects.append(_obj(f"{host or name}-{mapped}", mapped, tags, name, site))
                elif site_map:
                    findings.append({"severity": "warning", "code": "vm_ip_unmapped", "vm": name,
                                     "site": site, "detail": f"{ip} has no mapping for {site}; "
                                     f"nothing is pre-staged there"})

    # One object per loose address, carrying every group tag it needs. Ranges
    # stay ip-range objects and are NOT pre-staged at other sites: ranges are
    # never remapped anywhere in this toolkit.
    for span in sorted(static_tags):
        tags = sorted(static_tags[span])
        val = ipspan.fmt(span)
        in_groups = sorted(static_groups[span])
        objects.append(_obj(f"addr-{val}", val, tags, None, None, groups=in_groups))
        if "-" in val:
            if site_map and sites:
                findings.append({"severity": "warning", "code": "range_not_prestaged",
                                 "object": val, "detail": (
                                     f"range {val} (in {', '.join(in_groups)}) is not pre-staged "
                                     f"at {', '.join(sites)}: ranges are never remapped")})
            continue
        for site in sites:
            mapped = site_map.map_value(site, val) if site_map else None
            if mapped:
                objects.append(_obj(f"addr-{mapped}", mapped, tags, None, site, groups=in_groups))

    # Same name means same value (names are built from the value), so those
    # merge. Same name with a different value would be a real clash.
    merged: Dict[str, Dict[str, Any]] = {}
    for o in objects:
        prev = merged.get(o["name"])
        if prev is None:
            merged[o["name"]] = o
            continue
        if prev["value"] != o["value"]:
            findings.append({"severity": "error", "code": "duplicate_object_name",
                             "object": o["name"], "detail": (
                                 f"{prev['value']} and {o['value']} would share one name")})
            continue
        prev["tags"] = sorted(set(prev["tags"]) | set(o["tags"]))
        prev["sites"] = sorted(set(prev["sites"]) | set(o["sites"]))
        if o.get("loose_in_groups"):
            prev["loose_in_groups"] = sorted(set(prev.get("loose_in_groups") or [])
                                             | set(o["loose_in_groups"]))
        prev["vm"] = prev["vm"] or o["vm"]
    objects = list(merged.values())

    # ---- inventory ---------------------------------------------------------
    tag_use: Dict[str, int] = {}
    for o in objects:
        for t in o["tags"]:
            tag_use[t] = tag_use.get(t, 0) + 1
    max_tags = max((len(o["tags"]) for o in objects), default=0)
    return {
        "options": {"threshold": opts.threshold, "hostname_scope": opts.hostname_scope,
                    "asl_scope": opts.asl_scope, "vm_types": list(opts.vm_types),
                    "formats": {"hostname": opts.hostname_fmt, "asl_id": opts.asl_fmt,
                                "security_group": opts.sg_fmt},
                    "all_groups": opts.all_groups, "sites_prestaged": list(sites)},
        "dynamic_groups": plan_groups,
        "address_objects": objects,
        "tags": [{"name": t, "objects": c} for t, c in sorted(tag_use.items())],
        "findings": findings,
        "counts": {"groups": len(plan_groups),
                   "groups_hostname": sum(g["strategy"] == "hostname" for g in plan_groups),
                   "groups_security_group": sum(g["strategy"] == "security_group" for g in plan_groups),
                   "vms": len(used_vms), "address_objects": len(objects), "tags": len(tag_use),
                   "max_tags_on_one_object": max_tags,
                   "errors": sum(f["severity"] == "error" for f in findings),
                   "warnings": sum(f["severity"] == "warning" for f in findings)},
    }


def _obj(name: str, value: str, tags: List[str], vm: Optional[str], site: Optional[str],
         groups: Optional[List[str]] = None) -> Dict[str, Any]:
    kind = "ip-range" if "-" in value else "ip-netmask"
    v = value if "/" in value or "-" in value else f"{value}/32"
    o = {"name": pan_name(name), "type": kind, "value": v, "tags": sorted(tags), "vm": vm,
         "sites": [site or "source"]}
    if groups is not None:
        o["loose_in_groups"] = groups
    return o
