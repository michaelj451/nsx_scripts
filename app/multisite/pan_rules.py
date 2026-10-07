"""app/multisite/pan_rules.py

Palo Alto security rules mirrored from NSX DFW rules (Palo track P3). Pure:
NSX policies, rules, groups and services plus the NSX sibling bundles in, a
Panorama plan out (objects, services, rules, the exact REST payload of each,
findings). No network calls.

Decisions (Mike, 2026-10-06):
  - Target: a device group's pre-rulebase (lab: pano4 dg-5), candidate
    config only; the push and revert are the existing nsx_pan_mirror ones.
  - ONE GROUP PER NSX GROUP, named with the NSX sibling convention
    "<group>_np_ips" (RuleOptions.group_suffix, OBJECT_APPENDIX in .env),
    holding the group's addresses at EVERY site: the members of all its
    siblings across the bundles (<g>_np_ips current lm1 addresses, <g>_avs_ips
    lm2, <g>_lm3_ips lm3), so the rule matches a VM before and after it
    moves. A rule on one manager names only one view; copying that alone would
    allow only traffic that never crosses the firewall. The per-view sibling
    groups are not created on Panorama; the address object names keep the
    view (ax2001-10.7.0.101-avs_ips), so the site stays visible in the group.
  - A group with no source-view sibling: an IP-only NSX group adds its own
    addresses; a group of groups adds its members' addresses, each expanded
    the same way. Segments, empty tag groups and other members Panorama
    cannot match are reported and left out, so a Palo rule can be narrower
    than NSX, never wider. A side left with nothing skips the rule; it never
    becomes "any".
  - Zones: any/any for the lab (options, so a later zone map can fill them).
  - Objects (addresses, address groups, services, service groups) are created
    in `shared` by default (Mike, 2026-10-06), rules in the device group;
    MirrorOptions.object_location switches the objects to the device group.

HOW AN NSX RULE MAPS

  NSX                                 Panorama (device-group pre-rulebase)
  rule display name                   rule name (63 characters max, hash suffix)
  source / destination group          one static group "<group>_np_ips" with the
                                      group's addresses from every view
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
# "pre"/"post": a Panorama device group's rulebases. "local": a firewall's own
# rulebase, when writing directly to the firewall (MirrorOptions.object_location
# "vsys").
RULEBASE = {"pre": "Policies/SecurityPreRules", "post": "Policies/SecurityPostRules",
            "local": "Policies/SecurityRules"}


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
    # Mike, 2026-10-06: one Panorama group per NSX group, named with the NSX
    # sibling convention "<group>_np_ips" (OBJECT_APPENDIX), holding every site.
    group_suffix: str = "_np_ips"


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


# NSX ALG service entries become plain port services (Mike, 2026-10-06: use
# ports as much as possible). Protocol per ALG; ports from the entry, else the
# well-known default.
ALG_PORTS = {"FTP": ("tcp", "21"), "TFTP": ("udp", "69"), "ORACLE_TNS": ("tcp", "1521"),
             "SUN_RPC_TCP": ("tcp", "111"), "SUN_RPC_UDP": ("udp", "111"),
             "MS_RPC_TCP": ("tcp", "135"), "MS_RPC_UDP": ("udp", "135"),
             "NBNS_BROADCAST": ("udp", "137"), "NBDG_BROADCAST": ("udp", "138")}


def port_entry(e: Dict[str, Any]) -> Optional[Tuple[str, str, str, Optional[str]]]:
    """An NSX service entry with a port form -> (proto, dst ports, src ports,
    ALG note or None); None for any other entry type."""
    rt = e.get("resource_type")
    src = ",".join(str(p) for p in e.get("source_ports") or [])
    if rt == "L4PortSetServiceEntry" and e.get("l4_protocol") in ("TCP", "UDP"):
        dst = ",".join(str(p) for p in e.get("destination_ports") or []) or "0-65535"
        return e["l4_protocol"].lower(), dst, src, None
    if rt == "ALGTypeServiceEntry" and e.get("alg") in ALG_PORTS:
        proto, default = ALG_PORTS[e["alg"]]
        dst = ",".join(str(p) for p in e.get("destination_ports") or []) or default
        return proto, dst, src, f"ALG {e['alg']} as {proto}/{dst}"
    return None


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


def _profile_summary(pid: str, ctx: Dict[str, Dict[str, Any]]) -> str:
    """An NSX context profile as "<id>: APP_ID a, b; DOMAIN_NAME c"."""
    p = ctx.get(pid)
    if p is None:
        return f"{pid} (definition not read)"
    attrs = "; ".join(f"{a.get('key')} {', '.join(str(v) for v in a.get('value') or [])}"
                      for a in p.get("attributes") or [])
    return f"{p.get('display_name') or pid}: {attrs or 'no attributes'}"


def build_rule_mirror(policies: List[Dict[str, Any]], groups: List[Dict[str, Any]],
                      services: List[Dict[str, Any]], bundles: List[Dict[str, Any]],
                      vms: List[Dict[str, Any]], opts: Optional[MirrorOptions] = None,
                      ropts: Optional[RuleOptions] = None,
                      context_profiles: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """`policies`: NSX security policies, each with its rules under "rules".
    `context_profiles`: NSX context profiles, to name the App-IDs a rule uses."""
    opts = opts or MirrorOptions()
    ropts = ropts or RuleOptions()
    if ropts.profile_group and ropts.profiles:
        raise ValueError("a rule takes a security profile group OR individual profiles, not both")
    bad_types = sorted(set(ropts.profiles or {}) - set(PROFILE_TYPES))
    if bad_types:
        raise ValueError(f"unknown security profile type(s) {bad_types}; known: {sorted(PROFILE_TYPES)}")
    if ropts.rulebase not in RULEBASE:
        raise ValueError(f"rulebase must be one of {sorted(RULEBASE)}")
    if (ropts.rulebase == "local") != (opts.object_location == "vsys"):
        raise ValueError("a firewall target needs rulebase 'local' with objects in 'vsys', and only then")
    base = build_sibling_mirror(bundles, vms, opts)
    findings: List[Dict[str, Any]] = list(base["findings"])
    # The per-view sibling plan supplies the address objects; its groups are
    # not pushed. Their members are folded into one group per NSX group.
    sib_members = {g["name"]: g["members"] for g in base["address_groups"]}
    in_plan = set(sib_members)
    views = [b["sibling_map"].get("appendix") or "" for b in bundles]

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

    # One Panorama group per NSX group a rule uses, and the addresses of IP-only
    # NSX groups (their current addresses have no source-view sibling).
    combined: Dict[str, Dict[str, Any]] = {}
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

    def expand(gid: str, seen: Set[str], dropped: List[str]) -> List[str]:
        """Address objects for one NSX group: those of all its siblings, plus its
        current addresses when no source-view sibling holds them."""
        if gid in seen:
            return []
        seen = seen | {gid}
        out: List[str] = []
        for n, _ in sibs.get(gid, []):
            out += [a for a in sib_members[n] if a not in out]
        if any(src for _, src in sibs.get(gid, [])):
            return out
        g = gby.get(gid)
        if g is None:
            dropped.append(f"{gid} (not on NSX)")
            return out
        kind = group_kind(g)
        label = g.get("display_name") or gid
        if kind in ("ip_only", "ip_nested"):
            for a in _group_ips(g):
                n = mirror_address(a, label)
                if n and n not in out:
                    out.append(n)
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
    svc_ref: Dict[str, Tuple[Optional[str], List[str], List[str], List[str]]] = {}
    # Mike, 2026-10-06: ports wherever possible; every place an App-ID is
    # involved (NSX context profiles, ICMP, ALGs, no port form) is listed here.
    app_review: List[Dict[str, Any]] = []
    ctx = {p["id"]: p for p in context_profiles or []}
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

    def service_ref(sid: str, stack: Tuple[str, ...] = ()) -> Tuple[Optional[str], List[str], List[str], List[str]]:
        """NSX service id -> (Panorama service or service group name or None,
        App-IDs, entries with no port form, ALG entries mapped to ports).

        Mirrors the NSX service exactly (Mike, 2026-10-06): a service with one
        port entry is one Panorama service of the same name; a service with
        several entries, or one nesting other services, is a service group of
        the same name whose members are one service per port entry
        (<svc>-tcp, <svc>-udp, ...) and the nested services' own objects.
        ICMP has no port form, so it contributes App-IDs instead."""
        if sid in svc_ref:
            return svc_ref[sid]
        svc = sby.get(sid)
        if svc is None or sid in stack:
            return None, [], [f"service {sid} not found on NSX" if svc is None else f"service {sid} nests itself"], []
        label = svc.get("display_name") or sid
        sname = safe_name(label)
        entries = svc.get("service_entries") or []
        protos = [pe[0] for pe in (port_entry(e) for e in entries) if pe]
        members: List[str] = []
        apps: List[str] = []
        bad: List[str] = []
        algs: List[str] = []
        for e in entries:
            pe = port_entry(e)
            rt = e.get("resource_type")
            if pe:
                proto, dst, src, alg = pe
                n = sname if len(entries) == 1 else safe_name(
                    f"{sname}-{proto}" + (f"-{len([m for m in members if m.startswith(f'{sname}-{proto}')]) + 1}"
                                          if protos.count(proto) > 1 else ""))
                body = {"port": dst}
                if src:
                    body["source-port"] = src
                prev = svc_objs.get(n)
                if prev and prev["protocol"] != {proto: body}:
                    findings.append({"severity": "error", "code": "service_name_clash", "object": n,
                                     "detail": f"two NSX services would share the Panorama service name {n!r}"})
                svc_objs.setdefault(n, {"name": n, "protocol": {proto: body}, "nsx_service": sid})
                members.append(n)
                if alg:
                    algs.append(f"{label}: {alg}")
            elif rt == "ICMPTypeServiceEntry":
                apps += [a for a in _icmp_apps(e) if a not in apps]
            elif rt == "NestedServiceServiceEntry":
                ref, a, b, g = service_ref(_last(e.get("nested_service_path", "")), stack + (sid,))
                if ref and ref not in members:
                    members.append(ref)
                apps += [x for x in a if x not in apps]
                bad += b
                algs += g
            else:
                detail = e.get("alg") or e.get("l4_protocol") or e.get("protocol") or e.get("protocol_number") or ""
                bad.append(f"{label}: {rt} {detail}".strip())
        ref: Optional[str] = None
        if members == [sname]:                        # one port entry: the service itself
            ref = sname
        elif members:
            ref = sname
            if sname in svc_objs:
                findings.append({"severity": "error", "code": "service_name_clash", "object": sname,
                                 "detail": "a service and a service group would share this name"})
            svc_groups[sname] = {"name": sname, "members": members, "nsx_service": sid}
        svc_ref[sid] = (ref, apps, bad, algs)
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
            n = combined_group(gid, dropped)
            if n and n not in out:
                out.append(n)
        return out, False

    def combined_group(gid: str, dropped: List[str]) -> Optional[str]:
        """The one Panorama group for NSX group `gid`: "<NSX display name><suffix>",
        holding the group's addresses at every site (all bundles' views)."""
        g = gby.get(gid) or {}
        display = g.get("display_name") or next(
            (r.get("original_display_name") for b in bundles for r in b["sibling_map"].get("map") or []
             if r.get("original_id") == gid), gid)
        name = safe_name(f"{display}{ropts.group_suffix}")
        if name not in combined:
            members = expand(gid, set(), dropped)
            if not members:
                return None
            combined[name] = {"name": name, "kind": "static", "members": members, "nsx_group": display,
                              "nsx_original": display, "view": "all", "helper_for": None,
                              "description": f"NSX group {display}: its addresses at every site "
                                             f"({', '.join(v for v in views if v)} views)"}
        return name

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
            app_review.append({"kind": "nsx_app_id", "nsx_policy": row["nsx_policy"], "nsx_rule": row["nsx_rule"],
                               "nsx": "; ".join(_profile_summary(_last(p), ctx) for p in profiles),
                               "palo": "rule skipped (ports alone would allow every application on them)"})
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
                ref, a, bad, algs = service_ref(_last(p))
                if ref and ref not in port_refs:
                    port_refs.append(ref)
                apps += [x for x in a if x not in apps]
                for b in bad:
                    findings.append({"severity": "warning", "code": "service_not_mirrored", "object": label,
                                     "detail": f"left out: {b}"})
                    app_review.append({"kind": "no_port_form", "nsx_policy": row["nsx_policy"],
                                       "nsx_rule": row["nsx_rule"], "nsx": b,
                                       "palo": "left out (would need an App-ID)"})
                for g in algs:
                    app_review.append({"kind": "alg_ports", "nsx_policy": row["nsx_policy"],
                                       "nsx_rule": row["nsx_rule"], "nsx": g,
                                       "palo": f"port service {ref}"})
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
            if app_list is apps:
                app_review.append({"kind": "icmp_app_id", "nsx_policy": row["nsx_policy"],
                                   "nsx_rule": row["nsx_rule"], "nsx": "ICMP service (no ports exist for ICMP)",
                                   "palo": f"rule {name}: App-ID {', '.join(apps)}, service application-default"})

    # Only the address objects the plan's groups and rules use are pushed. One
    # namespace for addresses and address groups: no name may mean two things.
    pool = {a["name"]: a for a in base["addresses"]}
    for a in mirror_addrs.values():
        prev = pool.get(a["name"])
        if prev is None:
            pool[a["name"]] = a
        elif prev["value"] != a["value"]:
            findings.append({"severity": "error", "code": "name_clash", "object": a["name"],
                             "detail": f"{prev['value']} and {a['value']} would share the name {a['name']!r}"})
    used: List[str] = []
    for g in combined.values():
        used += [m for m in g["members"] if m not in used]
    for r in rules_out:
        for side_name in ("source", "destination"):
            used += [m for m in r["entry"][side_name]["member"] if m in pool and m not in used]
    addresses = [pool[n] for n in used]
    for g in combined.values():
        if g["name"] in pool:
            findings.append({"severity": "error", "code": "name_clash", "object": g["name"],
                             "detail": "an address object and an address group would share this name"})
    plan = {"device_group": opts.device_group, "options": {**opts.__dict__, **ropts.__dict__}, "mode": "rules",
            "tags": [], "addresses": addresses, "address_groups": list(combined.values()),
            "services": list(svc_objs.values()), "service_groups": list(svc_groups.values()),
            "rules": rules_out, "rule_report": report, "app_id_review": app_review, "findings": findings}
    plan["writes"] = rest_writes(plan) + service_rule_writes(plan)
    plan["counts"] = {
        "nsx_rules": len(ordered), "nsx_rules_in_scope": in_scope,
        "nsx_rules_skipped": sum(1 for x in report if x["skipped"]),
        "pan_rules": len(rules_out), "addresses": len(addresses),
        "address_groups": len(combined),
        "static_groups": len(plan["address_groups"]), "dynamic_groups": 0, "tags": 0,
        "services": len(svc_objs), "service_groups": len(svc_groups),
        "named_by_hostname": sum(1 for a in addresses if a["description"].startswith("NSX VM")),
        "errors": sum(f["severity"] == "error" for f in findings),
        "warnings": sum(f["severity"] == "warning" for f in findings),
        "app_id_review": len(app_review),
        "nsx_rules_with_app_id": sum(1 for x in app_review if x["kind"] == "nsx_app_id")}
    return plan


def service_rule_writes(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Services, then service groups, then rules (in NSX order), each as
    {kind, name, resource, location, device_group, entry} like rest_writes."""
    dg = plan["device_group"]
    loc = object_location(plan)
    o = plan.get("options") or {}
    vsys = o.get("vsys") or "vsys1"
    out: List[Dict[str, Any]] = []
    for s in plan["services"]:
        out.append({"kind": "service", "name": s["name"], "resource": RESOURCE["service"], "location": loc,
                    "device_group": dg, "vsys": vsys, "entry": {"@name": s["name"], "protocol": s["protocol"],
                                                                "description": f"NSX service {s['nsx_service']}"}})
    for g in plan["service_groups"]:
        out.append({"kind": "service-group", "name": g["name"], "resource": RESOURCE["service-group"],
                    "location": loc, "device_group": dg, "vsys": vsys,
                    "entry": {"@name": g["name"], "members": {"member": list(g["members"])}}})
    rulebase = o.get("rulebase") or "pre"
    # Rules live in the device group on Panorama, in the vsys on a firewall.
    rule_loc = "vsys" if rulebase == "local" else "device-group"
    for r in plan["rules"]:
        out.append({"kind": "security-rule", "name": r["name"], "resource": RULEBASE[rulebase],
                    "location": rule_loc, "device_group": dg, "vsys": vsys, "entry": r["entry"]})
    return out
