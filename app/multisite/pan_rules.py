"""app/multisite/pan_rules.py

Palo Alto security rules mirrored from NSX DFW rules (Palo track P3). Pure:
NSX policies, rules, groups and services plus the NSX sibling bundles in, a
Panorama plan out (objects, services, rules, the exact REST payload of each,
findings). No network calls.

Decisions (Mike, 2026-10-06):
  - Target: a device group's pre-rulebase (lab: pano4 dg-5), candidate
    config only; the push and revert are the existing nsx_pan_mirror ones.
  - ALL SIBLING VIEWS: an NSX group on a rule side becomes every sibling of
    that group across the bundles given (<g>_np_ips holds its current lm1
    addresses, <g>_avs_ips the lm2 addresses, <g>_lm3_ips the lm3 ones), so
    the rule matches a VM before and after it moves. A rule on one manager
    names only one view; copying that alone would allow only traffic that
    never crosses the firewall.
  - A group with no source-view sibling: an IP-only NSX group is mirrored as
    itself (static group, same name, its own addresses); a group of groups
    is replaced by its members, each expanded the same way. Segments, empty
    tag groups and other members Panorama cannot match are reported and
    left out, so a Palo rule can be narrower than NSX, never wider. A side
    left with nothing skips the rule; it never becomes "any".
  - Zones: any/any for the lab (options, so a later zone map can fill them).
  - Objects (addresses, address groups, services, service groups) are created
    in `shared` by default (Mike, 2026-10-06), rules in the device group;
    MirrorOptions.object_location switches the objects to the device group.

HOW AN NSX RULE MAPS

  NSX                                 Panorama (device-group pre-rulebase)
  rule display name                   rule name (63 characters max, hash suffix)
  source / destination group          every sibling of the group, plus its current
                                      addresses when no source-view sibling holds them
  ANY                                 any
  sources_excluded / ..._excluded     negate-source / negate-destination
  TCP/UDP port-set service            service object named after the NSX service
                                      (one per protocol: <svc>-tcp, <svc>-udp, in a
                                      service group named after the NSX service)
  nested service                      flattened into its parent
  ICMP service                        a second rule "<name>-icmp" with App-IDs
                                      (icmp, ping, ipv6-icmp), service application-default
  ANY service                         application any, service any
  ALLOW / DROP / REJECT               allow / drop / reset-both
  disabled                            disabled yes
  (options, not from NSX)             security profile group or individual profiles
                                      on allow rules; log forwarding profile on all
  context profile                     rule skipped (leaving it out would widen the rule)
  applied-to, direction, logging      not represented (the rule targets every firewall
                                      in the device group)

Rule order: NSX evaluation order (category, policy sequence, rule sequence).
A REST create appends to the bottom of the rulebase, so the push keeps it.
RuleOptions.rulebase picks the device group's pre-rulebase (default) or
post-rulebase. Panorama rule names are unique across both, so the same NSX
rule in both needs RuleOptions.name_suffix on one of them.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from multisite.pan_mirror import (MirrorOptions, _vm_ip_index, build_sibling_mirror, ip_object,
                                  object_location, rest_writes, safe_name)

# Layer 3 DFW categories in NSX evaluation order. Ethernet (layer 2) is not
# mirrored: a Panorama security rule is layer 3.
CATEGORY_ORDER = ["Emergency", "Infrastructure", "Environment", "Application"]
ACTIONS = {"ALLOW": "allow", "DROP": "drop", "REJECT": "reset-both"}
RESOURCE = {"service": "Objects/Services", "service-group": "Objects/ServiceGroups"}
RULEBASE = {"pre": "Policies/SecurityPreRules", "post": "Policies/SecurityPostRules"}


@dataclass
class RuleOptions:
    zone_from: str = "any"
    zone_to: str = "any"
    rulebase: str = "pre"                      # "pre" or "post" (device-group rulebase)
    only_rules: Optional[List[str]] = None     # NSX rule display names or ids; None = all
    name_suffix: str = ""                      # appended to every Panorama rule name
    # Mike, 2026-10-06: rules can carry a security profile and a logging
    # profile. These name EXISTING Panorama objects (never created here).
    # Security profiles apply to allow rules only; logging to every rule.
    profile_group: Optional[str] = None        # security profile group
    profiles: Optional[Dict[str, str]] = None  # or individual profiles: {type: name}, see PROFILE_TYPES
    log_setting: Optional[str] = None          # log forwarding profile


# Individual security profile types (the rule's profile-setting keys) and the
# REST resource that holds each kind of referenced profile.
PROFILE_TYPES = {"virus": "Objects/AntivirusSecurityProfiles",
                 "spyware": "Objects/AntiSpywareSecurityProfiles",
                 "vulnerability": "Objects/VulnerabilityProtectionSecurityProfiles",
                 "url-filtering": "Objects/URLFilteringSecurityProfiles",
                 "file-blocking": "Objects/FileBlockingSecurityProfiles",
                 "wildfire-analysis": "Objects/WildFireAnalysisSecurityProfiles",
                 "data-filtering": "Objects/DataFilteringSecurityProfiles"}
PROFILE_GROUP_RESOURCE = "Objects/SecurityProfileGroups"
LOG_PROFILE_RESOURCE = "Objects/LogForwardingProfiles"
PREDEFINED_PROFILES = {"default", "strict"}   # built in, never listed by the REST API


def profile_refs(options: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """Existing Panorama objects a rule plan references: [(label, resource, name)].
    Built-in profiles (default, strict) are left out: they cannot be looked up."""
    out: List[Tuple[str, str, str]] = []
    if options.get("profile_group"):
        out.append(("security profile group", PROFILE_GROUP_RESOURCE, options["profile_group"]))
    for t, n in (options.get("profiles") or {}).items():
        if n not in PREDEFINED_PROFILES:
            out.append((f"{t} profile", PROFILE_TYPES[t], n))
    if options.get("log_setting"):
        out.append(("log forwarding profile", LOG_PROFILE_RESOURCE, options["log_setting"]))
    return out


def _last(path: str) -> str:
    return (path or "").rstrip("/").rsplit("/", 1)[-1]


def group_kind(g: Dict[str, Any]) -> str:
    """ip_only | nested | ip_nested | segment | tag | empty | other."""
    kinds: Set[str] = set()
    for e in g.get("expression") or []:
        rt = e.get("resource_type")
        if rt == "ConjunctionOperator":
            continue
        if rt == "IPAddressExpression":
            kinds.add("ip" if e.get("ip_addresses") else "empty")
        elif rt == "PathExpression":
            for p in e.get("paths") or []:
                kinds.add("group" if "/groups/" in p else "segment")
        elif rt in ("Condition", "NestedExpression", "ExternalIDExpression"):
            kinds.add("tag")
        else:
            kinds.add("other")
    kinds.discard("empty")
    if not kinds:
        return "empty"
    if "tag" in kinds:
        return "tag"
    if kinds == {"ip"}:
        return "ip_only"
    if kinds == {"group"}:
        return "nested"
    if kinds == {"ip", "group"}:
        return "ip_nested"
    if "segment" in kinds:
        return "segment"
    return "other"


def _group_ips(g: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for e in g.get("expression") or []:
        if e.get("resource_type") == "IPAddressExpression":
            out += [x for x in e.get("ip_addresses") or [] if x not in out]
    return out


def _group_member_ids(g: Dict[str, Any]) -> List[str]:
    return [_last(p) for e in g.get("expression") or [] if e.get("resource_type") == "PathExpression"
            for p in e.get("paths") or [] if "/groups/" in p]


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

def _icmp_apps(entry: Dict[str, Any]) -> List[str]:
    if entry.get("protocol") == "ICMPv6":
        return ["ipv6-icmp"]
    t = entry.get("icmp_type")
    if t is None:
        return ["icmp", "ping"]
    return ["ping"] if t in (0, 8) else ["icmp"]


def flatten_service(sid: str, services: Dict[str, Dict[str, Any]],
                    seen: Optional[Set[str]] = None) -> Tuple[List[Tuple[str, str, str]], List[str], List[str]]:
    """An NSX service -> (port entries [(proto, dst ports, src ports)], ICMP App-IDs,
    unsupported entry descriptions). Nested services are followed."""
    seen = set() if seen is None else seen
    ports: List[Tuple[str, str, str]] = []
    apps: List[str] = []
    bad: List[str] = []
    if sid in seen:
        return ports, apps, bad
    seen.add(sid)
    svc = services.get(sid)
    if svc is None:
        return ports, apps, [f"service {sid} not found on NSX"]
    for e in svc.get("service_entries") or []:
        rt = e.get("resource_type")
        if rt == "L4PortSetServiceEntry" and e.get("l4_protocol") in ("TCP", "UDP"):
            dst = ",".join(str(p) for p in e.get("destination_ports") or []) or "0-65535"
            src = ",".join(str(p) for p in e.get("source_ports") or [])
            ports.append((e["l4_protocol"].lower(), dst, src))
        elif rt == "ICMPTypeServiceEntry":
            apps += [a for a in _icmp_apps(e) if a not in apps]
        elif rt == "NestedServiceServiceEntry":
            p, a, b = flatten_service(_last(e.get("nested_service_path", "")), services, seen)
            ports += p
            apps += [x for x in a if x not in apps]
            bad += b
        else:
            bad.append(f"{svc.get('display_name') or sid}: {rt} {e.get('l4_protocol') or e.get('protocol') or ''}".strip())
    return ports, apps, bad


def _merge_ports(ports: List[Tuple[str, str, str]]) -> List[Tuple[str, str, str]]:
    """One (proto, src) pair -> one Panorama service with the ports joined."""
    merged: Dict[Tuple[str, str], List[str]] = {}
    for proto, dst, src in ports:
        lst = merged.setdefault((proto, src), [])
        for p in dst.split(","):
            if p not in lst:
                lst.append(p)
    return [(proto, ",".join(dst), src) for (proto, src), dst in merged.items()]


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

def _ordered_rules(policies: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    # NSX's default sections (default-layer3-section, ANY to ANY) are not customer rules.
    pols = [p for p in policies if p.get("category") in CATEGORY_ORDER
            and not p.get("_system_owned") and not p.get("is_default")]
    pols.sort(key=lambda p: (CATEGORY_ORDER.index(p["category"]), p.get("sequence_number", 0), p.get("id", "")))
    out = []
    for p in pols:
        for r in sorted(p.get("rules") or [], key=lambda r: (r.get("sequence_number", 0), r.get("id", ""))):
            if not r.get("_system_owned"):
                out.append((p, r))
    return out


def build_rule_mirror(policies: List[Dict[str, Any]], groups: List[Dict[str, Any]],
                      services: List[Dict[str, Any]], bundles: List[Dict[str, Any]],
                      vms: List[Dict[str, Any]], opts: Optional[MirrorOptions] = None,
                      ropts: Optional[RuleOptions] = None) -> Dict[str, Any]:
    """`policies`: NSX security policies, each with its rules under "rules"."""
    opts = opts or MirrorOptions()
    ropts = ropts or RuleOptions()
    if ropts.profile_group and ropts.profiles:
        raise ValueError("a rule takes a security profile group OR individual profiles, not both")
    bad_types = sorted(set(ropts.profiles or {}) - set(PROFILE_TYPES))
    if bad_types:
        raise ValueError(f"unknown security profile type(s) {bad_types}; known: {sorted(PROFILE_TYPES)}")
    if ropts.rulebase not in RULEBASE:
        raise ValueError(f"rulebase must be one of {sorted(RULEBASE)}")
    base = build_sibling_mirror(bundles, vms, opts)
    findings: List[Dict[str, Any]] = list(base["findings"])
    in_plan = {g["name"] for g in base["address_groups"]}

    # Sibling index: NSX group id -> [(Panorama group name, source view?)].
    sibs: Dict[str, List[Tuple[str, bool]]] = {}
    sibling_to_orig: Dict[str, str] = {}
    source_views = 0
    for b in bundles:
        rows = b["sibling_map"].get("map") or []
        is_source = all(r.get("ips_sibling_mapped") is None for r in rows)
        source_views += is_source
        for r in rows:
            sibling_to_orig[r.get("sibling_id")] = r.get("original_id")
            name = safe_name(r.get("sibling_display_name") or r.get("sibling_id"))
            if name in in_plan and (name, is_source) not in sibs.get(r.get("original_id"), []):
                sibs.setdefault(r.get("original_id"), []).append((name, is_source))
    if not source_views:
        findings.append({"severity": "error", "code": "no_source_view", "object": "bundles",
                         "detail": "no source-view bundle (Workflow C, <group>_np_ips): groups' current "
                                   "addresses would be missing, so VMs that have not moved would not match"})

    gby = {g["id"]: g for g in groups}
    sby = {s["id"]: s for s in services}
    index, _ = _vm_ip_index(vms, opts)

    # Mirrored IP-only groups (same name as on NSX) and their addresses.
    mirror_groups: Dict[str, Dict[str, Any]] = {}
    mirror_addrs: Dict[str, Dict[str, Any]] = {}

    def mirror_address(addr: str, gname: str) -> Optional[str]:
        o = ip_object(addr)
        if o is None:
            findings.append({"severity": "warning", "code": "bad_address", "group": gname,
                             "detail": f"{addr!r} is not an IP, CIDR or range; left out"})
            return None
        owner = None
        if o["type"] == "ip-netmask" and o["value"].endswith(("/32", "/128")):
            owners = index.get(str(ipaddress.ip_network(o["value"]).network_address), [])
            owner = owners[0] if len(owners) == 1 else None
        name = safe_name(f"{owner[0]}-{o['name']}") if owner else o["name"]
        prev = mirror_addrs.get(name)
        if prev and prev["value"] != o["value"]:
            findings.append({"severity": "error", "code": "name_clash", "object": name,
                             "detail": f"{prev['value']} and {o['value']} would share the name {name!r}"})
            return None
        mirror_addrs.setdefault(name, {"name": name, "type": o["type"], "value": o["value"], "tags": [],
                                       "description": f"NSX VM {owner[1]}" if owner else "NSX group address",
                                       "source": "group"})
        return name

    def mirror_group(g: Dict[str, Any]) -> Optional[str]:
        gname = safe_name(g.get("display_name") or g["id"])
        if gname not in mirror_groups:
            members = [n for n in (mirror_address(a, gname) for a in _group_ips(g)) if n]
            members = list(dict.fromkeys(members))
            if not members:
                return None
            mirror_groups[gname] = {"name": gname, "kind": "static", "members": members,
                                    "nsx_group": g.get("display_name"), "nsx_original": g.get("display_name"),
                                    "view": "group", "helper_for": None}
        return gname

    def expand(gid: str, seen: Set[str], dropped: List[str]) -> List[str]:
        """Panorama members for one NSX group: all its siblings, plus its current
        addresses when no source-view sibling holds them."""
        if gid in seen:
            return []
        seen = seen | {gid}
        out = [n for n, _ in sibs.get(gid, [])]
        if any(src for _, src in sibs.get(gid, [])):
            return out
        g = gby.get(gid)
        if g is None:
            dropped.append(f"{gid} (not on NSX)")
            return out
        kind = group_kind(g)
        label = g.get("display_name") or gid
        if kind in ("ip_only", "ip_nested"):
            n = mirror_group(g)
            out += [n] if n else []
        if kind in ("nested", "ip_nested"):
            for m in _group_member_ids(g):
                out += [x for x in expand(m, seen, dropped) if x not in out]
        if kind == "tag":
            if not out:
                dropped.append(f"{label} (tag group with no sibling: no members on the source manager)")
            else:
                dropped.append(f"{label} (current addresses: no source-view sibling)")
        elif kind == "segment":
            dropped.append(f"{label} (segment member)")
        elif kind in ("empty", "other"):
            dropped.append(f"{label} ({kind} group)")
        return out

    rules_out: List[Dict[str, Any]] = []
    svc_objs: Dict[str, Dict[str, Any]] = {}
    svc_groups: Dict[str, Dict[str, Any]] = {}
    svc_ref: Dict[str, Tuple[Optional[str], List[str], List[str]]] = {}
    used_names: Set[str] = set()
    report: List[Dict[str, Any]] = []
    ordered = _ordered_rules(policies)
    if ropts.only_rules:
        wanted = set(ropts.only_rules)
        found = {k for _, r in ordered for k in (r.get("display_name"), r.get("id")) if k in wanted}
        for k in sorted(wanted - found):
            findings.append({"severity": "error", "code": "rule_not_found", "object": k,
                             "detail": "no NSX rule with that name or id (default sections are never mirrored)"})
        ordered = [(p, r) for p, r in ordered if r.get("display_name") in wanted or r.get("id") in wanted]

    def service_ref(sid: str) -> Tuple[Optional[str], List[str], List[str]]:
        """NSX service id -> (Panorama service or group name or None, App-IDs, unsupported)."""
        if sid in svc_ref:
            return svc_ref[sid]
        ports, apps, bad = flatten_service(sid, sby)
        ports = _merge_ports(ports)
        sname = safe_name((sby.get(sid) or {}).get("display_name") or sid)
        ref: Optional[str] = None
        if len(ports) == 1:
            ref = sname
            names = [sname]
        else:
            names = [safe_name(f"{sname}-{p}" + (f"-{i}" if sum(q == p for q, _, _ in ports) > 1 else ""))
                     for i, (p, _, _) in enumerate(ports)]
            if ports:
                ref = sname
                svc_groups[sname] = {"name": sname, "members": names, "nsx_service": sid}
        for n, (proto, dst, src) in zip(names, ports):
            body = {"port": dst}
            if src:
                body["source-port"] = src
            prev = svc_objs.get(n)
            if prev and prev["protocol"] != {proto: body}:
                findings.append({"severity": "error", "code": "service_name_clash", "object": n,
                                 "detail": f"two NSX services would share the Panorama service name {n!r}"})
            svc_objs.setdefault(n, {"name": n, "protocol": {proto: body}, "nsx_service": sid})
        svc_ref[sid] = (ref, apps, bad)
        return svc_ref[sid]

    def rule_name(base_name: str, policy_id: str) -> str:
        n = safe_name(base_name)
        if n in used_names:
            n = safe_name(f"{base_name}-{policy_id}")
        used_names.add(n)
        return n

    def side(refs: List[str], dropped: List[str]) -> Tuple[List[str], bool]:
        """-> (Panorama members, NSX side was ANY)."""
        if not refs or "ANY" in refs:
            return ["any"], True
        seen_orig: List[str] = []
        out: List[str] = []
        for r in refs:
            if not r.startswith("/"):
                # NSX rules may hold literal addresses (IP, CIDR, range) beside group paths.
                n = mirror_address(r, "rule literal")
                if n and n not in out:
                    out.append(n)
                continue
            gid = sibling_to_orig.get(_last(r), _last(r))
            if gid not in seen_orig:
                seen_orig.append(gid)
        for gid in seen_orig:
            out += [x for x in expand(gid, set(), dropped) if x not in out]
        return out, False

    in_scope = 0
    for pol, r in ordered:
        nsx_refs = [_last(x) for x in (r.get("source_groups") or []) + (r.get("destination_groups") or [])
                    if x.startswith("/")]
        touched = any(sibs.get(sibling_to_orig.get(g, g)) for g in nsx_refs)
        if not touched:
            continue
        in_scope += 1
        label = f"{pol.get('display_name') or pol['id']} / {r.get('display_name') or r['id']}"
        row = {"nsx_policy": pol.get("display_name") or pol["id"], "nsx_rule": r.get("display_name") or r["id"],
               "nsx_action": r.get("action"), "pan_rules": [], "dropped": [], "skipped": None}
        report.append(row)

        def skip(why: str) -> None:
            row["skipped"] = why
            findings.append({"severity": "warning", "code": "rule_skipped", "object": label, "detail": why})

        action = ACTIONS.get(r.get("action"))
        if action is None:
            skip(f"action {r.get('action')} has no Panorama equivalent")
            continue
        profiles = [p for p in r.get("profiles") or [] if p != "ANY"]
        if profiles:
            skip(f"context profile(s) {', '.join(_last(p) for p in profiles)}: leaving them out would widen the rule")
            continue
        dropped: List[str] = []
        src, src_any = side(r.get("source_groups") or [], dropped)
        dst, dst_any = side(r.get("destination_groups") or [], dropped)
        row["dropped"] = list(dict.fromkeys(dropped))
        if not src or not dst:
            skip(f"{'source' if not src else 'destination'} has nothing Panorama can match "
                 f"({'; '.join(row['dropped']) or 'no members'})")
            continue
        if row["dropped"]:
            findings.append({"severity": "warning", "code": "rule_narrower", "object": label,
                             "detail": "left out: " + "; ".join(row["dropped"])})

        svc_paths = r.get("services") or ["ANY"]
        port_refs: List[str] = []
        apps: List[str] = []
        svc_any = "ANY" in svc_paths
        if r.get("service_entries"):
            findings.append({"severity": "warning", "code": "inline_services_not_mirrored", "object": label,
                             "detail": "the rule's own service entries are left out"})
        if not svc_any:
            for p in svc_paths:
                ref, a, bad = service_ref(_last(p))
                if ref and ref not in port_refs:
                    port_refs.append(ref)
                apps += [x for x in a if x not in apps]
                for b in bad:
                    findings.append({"severity": "warning", "code": "service_not_mirrored", "object": label,
                                     "detail": f"left out: {b}"})
            if not port_refs and not apps:
                skip("no service Panorama can match")
                continue

        common = {"from": {"member": [ropts.zone_from]}, "to": {"member": [ropts.zone_to]},
                  "source": {"member": src}, "destination": {"member": dst},
                  "source-user": {"member": ["any"]}, "category": {"member": ["any"]}}
        flags = {"action": action, "disabled": "yes" if r.get("disabled") else "no"}
        if action == "allow":   # security profiles inspect allowed traffic only
            if ropts.profile_group:
                flags["profile-setting"] = {"group": {"member": [ropts.profile_group]}}
            elif ropts.profiles:
                flags["profile-setting"] = {"profiles": {t: {"member": [n]} for t, n in ropts.profiles.items()}}
        if ropts.log_setting:
            flags["log-setting"] = ropts.log_setting
        if r.get("sources_excluded") and not src_any:
            flags["negate-source"] = "yes"
        if r.get("destinations_excluded") and not dst_any:
            flags["negate-destination"] = "yes"
        desc = f"NSX {label}"[:1023]
        variants: List[Tuple[str, List[str], List[str]]] = []
        if svc_any:
            variants.append(("", ["any"], ["any"]))
        if port_refs:
            variants.append(("", ["any"], port_refs))
        if apps:
            variants.append(("-icmp" if port_refs else "", apps, ["application-default"]))
        base_name = r.get("display_name") or r["id"]
        for suffix, app_list, svc_list in variants:
            name = rule_name(base_name + suffix + ropts.name_suffix, pol["id"])
            entry = {"@name": name, **common, "application": {"member": app_list},
                     "service": {"member": svc_list}, **flags, "description": desc}
            rules_out.append({"name": name, "entry": entry, "nsx_policy": row["nsx_policy"],
                              "nsx_rule": row["nsx_rule"]})
            row["pan_rules"].append(name)

    # One namespace for addresses and address groups: mirrored originals must
    # not reuse a sibling plan name for something else.
    addresses = list(base["addresses"])
    names = {a["name"]: a for a in addresses}
    for a in mirror_addrs.values():
        prev = names.get(a["name"])
        if prev is None:
            addresses.append(a)
            names[a["name"]] = a
        elif prev["value"] != a["value"]:
            findings.append({"severity": "error", "code": "name_clash", "object": a["name"],
                             "detail": f"{prev['value']} and {a['value']} would share the name {a['name']!r}"})
    group_names = {g["name"] for g in base["address_groups"]}
    for g in mirror_groups.values():
        if g["name"] in group_names or g["name"] in names:
            findings.append({"severity": "error", "code": "name_clash", "object": g["name"],
                             "detail": "a mirrored NSX group would reuse an existing plan name"})
    plan = {"device_group": opts.device_group, "options": {**opts.__dict__, **ropts.__dict__}, "mode": "rules",
            "tags": [], "addresses": addresses,
            "address_groups": base["address_groups"] + list(mirror_groups.values()),
            "services": list(svc_objs.values()), "service_groups": list(svc_groups.values()),
            "rules": rules_out, "rule_report": report, "findings": findings}
    plan["writes"] = rest_writes(plan) + service_rule_writes(plan)
    plan["counts"] = {
        "nsx_rules": len(ordered), "nsx_rules_in_scope": in_scope,
        "nsx_rules_skipped": sum(1 for x in report if x["skipped"]),
        "pan_rules": len(rules_out), "addresses": len(addresses),
        "sibling_groups": len(base["address_groups"]), "mirrored_groups": len(mirror_groups),
        "static_groups": len(plan["address_groups"]), "dynamic_groups": 0, "tags": 0,
        "services": len(svc_objs), "service_groups": len(svc_groups),
        "named_by_hostname": sum(1 for a in addresses if a["description"].startswith("NSX VM")),
        "errors": sum(f["severity"] == "error" for f in findings),
        "warnings": sum(f["severity"] == "warning" for f in findings)}
    return plan


def service_rule_writes(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Services, then service groups, then rules (in NSX order), each as
    {kind, name, resource, location, device_group, entry} like rest_writes."""
    dg = plan["device_group"]
    loc = object_location(plan)
    out: List[Dict[str, Any]] = []
    for s in plan["services"]:
        out.append({"kind": "service", "name": s["name"], "resource": RESOURCE["service"], "location": loc,
                    "device_group": dg, "entry": {"@name": s["name"], "protocol": s["protocol"],
                                                  "description": f"NSX service {s['nsx_service']}"}})
    for g in plan["service_groups"]:
        out.append({"kind": "service-group", "name": g["name"], "resource": RESOURCE["service-group"],
                    "location": loc, "device_group": dg,
                    "entry": {"@name": g["name"], "members": {"member": list(g["members"])}}})
    rule_resource = RULEBASE[(plan.get("options") or {}).get("rulebase") or "pre"]
    for r in plan["rules"]:   # rules always live in the device group
        out.append({"kind": "security-rule", "name": r["name"], "resource": rule_resource,
                    "location": "device-group", "device_group": dg, "entry": r["entry"]})
    return out
