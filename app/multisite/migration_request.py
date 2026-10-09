"""app/multisite/migration_request.py

Logic for the migration request workflow (Mike, 2026-10-07). No NSX or
Panorama calls happen here: tools/multisite/migration_request.py does the
captures, runs the existing tools and calls these functions.

THE WORKFLOW

  1. A request names the servers to migrate and the destination manager.
     A server is given as a VM name, an IP address, or "name,ip[,ip]".
  2. The request report lists the servers, every NSX rule they use, what
     Workflow A copies to the destination, the Workflow C siblings there,
     the Workflow D siblings and rule amendments on the source, and exactly
     what is created on Palo Alto.
  3. The request is reviewed and approved.
  4. At the change window a fresh capture rebuilds everything from the same
     inputs. Changes on the source since the request went through their own
     approval, so they are taken as they are and listed. A change to the
     request's own servers stops the run.

SCOPE

  Workflow A: the rules that touch the servers, their policies, and every
  group and service those rules need (nested ones included, policy-level
  applied-to included).
  Workflow C: an IP-only sibling for every group in that bundle, holding the
  source's current addresses (unchanged Workflow C behaviour on a subset).
  Workflow D (Mike, 2026-10-07): only the groups the servers are members of,
  and the rules those groups are in. Each D sibling holds only the
  requested servers' addresses, mapped through the destination's subnet map.
"""
from __future__ import annotations

import copy
import difflib
import hashlib
import ipaddress
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from common.fileio import read_yaml, write_yaml
from common.md import align_markdown_tables, md_escape, md_table
from nsx.push_skip import content_key

SCHEMA = "nsx-migration-request/1"
DEFAULT_SECTION_IDS = frozenset({"default-layer2-section", "default-layer3-section"})
CATEGORY_ORDER = ("Ethernet", "Emergency", "Infrastructure", "Environment", "Application")
# Fields whose group references a rule is matched on.
RULE_REF_FIELDS = ("source_groups", "destination_groups", "scope")
# Fields amend-refs adds siblings to (it leaves scope alone unless asked).
AMEND_FIELDS = ("source_groups", "destination_groups")

Entry = Tuple[str, Optional[List[str]]]


# ---------------------------------------------------------------------------
# Input: VM names and/or IP addresses
# ---------------------------------------------------------------------------

def as_ip(text: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        return None


def parse_list_lines(lines: Iterable[str]) -> Tuple[List[Entry], List[str]]:
    """One server per line: `name`, `ip`, or `name,ip[,ip...]`. Blank lines
    and `#` comments are ignored. Returns (entries, warnings)."""
    entries: List[Entry] = []
    warnings: List[str] = []
    for lineno, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = [p.strip() for p in s.split(",")]
        name = parts[0]
        if not name:
            warnings.append(f"line {lineno}: no name before the first comma, skipped")
            continue
        ips: List[str] = []
        for tok in (p for p in parts[1:] if p):
            ip = as_ip(tok)
            if ip:
                ips.append(ip)
            else:
                warnings.append(f"line {lineno}: {tok!r} is not an IP address, ignored")
        entries.append((name, ips or None))
    return entries, warnings


def parse_tokens(values: Sequence[str]) -> List[Entry]:
    """--servers "web01,10.6.0.101": every comma-separated token is its own
    entry (use a list file for `name,ip`)."""
    out: List[Entry] = []
    for raw in values or []:
        for tok in str(raw).split(","):
            t = tok.strip()
            if t:
                out.append((t, None))
    return out


def merge_entries(entries: Sequence[Entry], vms: Sequence[Dict[str, Any]]
                  ) -> Tuple[List[Entry], Dict[str, Dict[str, Any]]]:
    """Resolve every entry to the name the server lookup should use.

    An IP that exactly one VM owns becomes that VM, so a request given only
    an address still finds the VM and every group the VM is in. Entries that
    land on the same VM are merged (a VM listed by name and by IP is one
    server). Returns (entries for the lookup, notes keyed by the lookup name
    in lower case: requested_as, ambiguous owners)."""
    names_lower = {(vm.get("display_name") or "").lower() for vm in vms}
    owners: Dict[str, Set[str]] = {}
    for vm in vms:
        for ip in vm.get("ips") or []:
            owners.setdefault(ip, set()).add(vm.get("display_name") or "?")
    merged: Dict[str, Dict[str, Any]] = {}
    for raw, ips in entries:
        name, extra = raw, list(ips or [])
        note: Dict[str, Any] = {}
        ip = as_ip(raw)
        if ip and raw.lower() not in names_lower:
            own = sorted(owners.get(ip, ()))
            if len(own) == 1:
                name, extra = own[0], sorted(set(extra) | {ip})
                note["found_by_ip"] = ip
            elif len(own) > 1:
                note["ambiguous"] = own
        key = name.lower()
        slot = merged.setdefault(key, {"name": name, "ips": None, "requested_as": [], "notes": {}})
        slot["requested_as"].append(raw)
        if extra:
            slot["ips"] = sorted(set(slot["ips"] or []) | set(extra))
        slot["notes"].update(note)
    out = [(m["name"], m["ips"]) for m in merged.values()]
    notes = {k: {"requested_as": m["requested_as"], **m["notes"]} for k, m in merged.items()}
    return out, notes


def suggest_names(name: str, vms: Sequence[Dict[str, Any]], limit: int = 3) -> List[str]:
    """VM names that contain `name`, else the closest spellings."""
    names = sorted({vm.get("display_name") or "" for vm in vms} - {""})
    low = name.lower()
    hits = [n for n in names if low in n.lower()]
    if not hits:
        parts = [t for t in re.split(r"[^a-z0-9]+", low) if t]
        hits = [n for n in names if parts and all(t in n.lower() for t in parts)]
    if hits:
        return hits[:limit]
    return difflib.get_close_matches(name, names, n=limit, cutoff=0.5)


# ---------------------------------------------------------------------------
# The source capture (capture_nsx_state.py --output-dir), read from disk
# ---------------------------------------------------------------------------

@dataclass
class CaptureView:
    host: str
    domain: str
    root: Path
    policies: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    policy_files: Dict[str, Path] = field(default_factory=dict)
    rules: Dict[Tuple[str, str], Dict[str, Any]] = field(default_factory=dict)
    rule_files: Dict[Tuple[str, str], Path] = field(default_factory=dict)
    groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    group_files: Dict[str, Path] = field(default_factory=dict)
    additive: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    additive_files: Dict[str, Path] = field(default_factory=dict)
    services: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    service_files: Dict[str, Path] = field(default_factory=dict)


def _yaml_objects(directory: Path) -> Iterable[Tuple[Path, Dict[str, Any]]]:
    if not directory.is_dir():
        return
    for f in sorted(directory.glob("*.yaml")):
        if f.name in ("index.yaml", "rules_order.yaml"):
            continue
        obj = read_yaml(f)
        if isinstance(obj, dict) and obj.get("id"):
            yield f, obj


def load_capture(capture: Path, host: str, domain: str = "default") -> CaptureView:
    root = capture / "nsx_export" / host / "domains" / domain
    if not root.is_dir():
        raise FileNotFoundError(f"No captured domain at {root}")
    cap = CaptureView(host=host, domain=domain, root=capture)
    pol_root = root / "security-policies"
    for poldir in sorted(d for d in pol_root.iterdir() if d.is_dir()) if pol_root.is_dir() else []:
        pf = poldir / "policy.yaml"
        if not pf.is_file():
            continue
        pol = read_yaml(pf)
        pid = pol.get("id") if isinstance(pol, dict) else None
        if not pid:
            continue
        cap.policies[pid] = pol
        cap.policy_files[pid] = pf
        for rf, rule in _yaml_objects(poldir / "rules"):
            cap.rules[(pid, rule["id"])] = rule
            cap.rule_files[(pid, rule["id"])] = rf
    for f, g in _yaml_objects(root / "groups"):
        if g.get("path"):
            cap.groups[g["path"]] = g
            cap.group_files[g["path"]] = f
    for f, g in _yaml_objects(capture / "groups_additive" / "domains" / domain / "groups"):
        if g.get("path"):
            cap.additive[g["path"]] = g
            cap.additive_files[g["path"]] = f
    for f, s in _yaml_objects(root / "services"):
        if s.get("path"):
            cap.services[s["path"]] = s
            cap.service_files[s["path"]] = f
    return cap


def is_default_policy(policy: Dict[str, Any]) -> bool:
    return bool(policy.get("is_default")) or policy.get("id") in DEFAULT_SECTION_IDS


def rule_order_key(policy: Dict[str, Any], rule: Dict[str, Any]) -> Tuple[Any, ...]:
    cat = policy.get("category")
    return (CATEGORY_ORDER.index(cat) if cat in CATEGORY_ORDER else len(CATEGORY_ORDER),
            policy.get("sequence_number", 0), policy.get("id", ""),
            rule.get("sequence_number", 0), rule.get("id", ""))


# ---------------------------------------------------------------------------
# Servers and rules
# ---------------------------------------------------------------------------

def _rule_counts(hits: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for h in hits:
        for ext in h["info"]["by_side"]:
            out[ext] = out.get(ext, 0) + 1
    return out


def server_rows(entries: Sequence[Entry], notes: Dict[str, Dict[str, Any]],
                analysis: Dict[str, Any], data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One row per requested server, in request order. `analysis` is
    report_vms_in_rules.analyze() over `data` (the VM-rule snapshot)."""
    resolved = {k.lower(): v for k, v in analysis["resolved"].items()}
    vm_by_ext = {vm.get("external_id"): vm for vm in data["vms"]}
    gbp = data["groups_by_path"]
    counts = _rule_counts(analysis["hits"])
    rows: List[Dict[str, Any]] = []
    for name, _ips in entries:
        key = name.lower()
        note = notes.get(key, {})
        meta = resolved.get(key)
        row: Dict[str, Any] = {"key": key, "requested_as": note.get("requested_as", [name]),
                               "vm": None, "external_id": None, "ips": [], "power_state": None,
                               "found_by_ip": note.get("found_by_ip"), "groups": [],
                               "group_paths": [], "rules": 0, "status": "ok", "problems": [],
                               "suggestions": []}
        if meta is None:
            if note.get("ambiguous"):
                row["status"] = "ambiguous"
                row["problems"].append("address held by more than one VM: "
                                       + ", ".join(note["ambiguous"]))
            else:
                row["status"] = "not_found"
                row["problems"].append("no VM with this name on the source")
                row["suggestions"] = suggest_names(name, data["vms"])
            rows.append(row)
            continue
        ext = meta["external_id"]
        vm = vm_by_ext.get(ext) or {}
        kind = meta.get("kind")
        row.update(external_id=ext, ips=list(meta.get("ips") or []),
                   kind={"NSX": "vm", "NSX+ip": "vm", "IP": "ip", "planned": "planned"}.get(kind, kind),
                   power_state=vm.get("power_state"))
        if kind in ("NSX", "NSX+ip"):
            row["vm"] = meta.get("display_name")
        elif kind == "IP":
            owners = meta.get("owner_vms") or []
            if note.get("ambiguous") or len(owners) > 1:
                row["status"] = "ambiguous"
                row["problems"].append("address held by more than one VM: "
                                       + ", ".join(note.get("ambiguous") or owners))
            else:
                row["problems"].append("no VM owns this address on the source (powered off, or "
                                       "not a VM): matched by address only")
        else:
            row["problems"].append("not a VM on the source: matched by the given addresses only")
        paths = sorted(analysis["vm_to_groups"].get(ext) or ())
        row["group_paths"] = paths
        row["groups"] = [(gbp.get(p) or {}).get("display_name") or p.rsplit("/", 1)[-1] for p in paths]
        row["rules"] = counts.get(ext, 0)
        if not row["ips"]:
            row["problems"].append("no IP address known (a powered-off VM reports none): "
                                   "add it to the request as name,ip")
        rows.append(row)
    return rows


def select_rules(hits: Sequence[Dict[str, Any]], cap: CaptureView,
                 include_default_sections: bool = False
                 ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """The rules to copy: every rule the server lookup found, as captured.
    Returns (selected in NSX evaluation order, excluded with a reason)."""
    selected: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []
    for h in hits:
        r = h["rule"]
        pid, rid = r.get("_policy_id"), r.get("id")
        names = h.get("ext_id_to_name") or {}
        matched = [{"server": names.get(ext, ext), "sides": list(sides)}
                   for ext, sides in sorted(h["info"]["by_side"].items(),
                                            key=lambda kv: str(names.get(kv[0], kv[0])))]
        base = {"key": f"{pid}/{rid}", "policy_id": pid, "rule_id": rid,
                "policy_name": r.get("_policy_display") or pid,
                "rule_name": r.get("display_name") or rid, "matched": matched}
        reason = None
        pol = cap.policies.get(pid)
        if (r.get("_domain_id") or "default") != cap.domain:
            reason = f"domain {r.get('_domain_id')} is not captured (only {cap.domain})"
        elif pol is None:
            reason = "policy missing from the source capture (captures out of step: re-run)"
        elif is_default_policy(pol) and not include_default_sections:
            reason = "NSX default section (never copied)"
        elif (pid, rid) not in cap.rules:
            reason = "rule missing from the source capture (captures out of step: re-run)"
        if reason:
            excluded.append({**base, "reason": reason,
                             "error": "out of step" in reason})
            continue
        rule = cap.rules[(pid, rid)]
        info = h["info"]
        selected.append({
            **base, "category": pol.get("category"),
            "order": list(rule_order_key(pol, rule)),
            "action": rule.get("action"), "disabled": bool(rule.get("disabled")),
            "direction": rule.get("direction"),
            "source_groups": list(rule.get("source_groups") or []),
            "destination_groups": list(rule.get("destination_groups") or []),
            "scope": list(rule.get("scope") or []),
            "services": list(rule.get("services") or []),
            "profiles": [p for p in rule.get("profiles") or [] if p not in ("ANY", "any")],
            "global": bool(info.get("any_src") and info.get("any_dst")),
        })
    selected.sort(key=lambda s: s["order"])
    return selected, excluded


# ---------------------------------------------------------------------------
# Dependencies of the selected rules
# ---------------------------------------------------------------------------

def _is_ref(v: Any) -> bool:
    return isinstance(v, str) and v.startswith("/")


def is_group_path(p: str) -> bool:
    return "/domains/" in p and "/groups/" in p


def expression_paths(expr: Any) -> List[str]:
    """Every PathExpression path at any depth (NestedExpression included)."""
    out: List[str] = []
    for e in expr or []:
        if not isinstance(e, dict):
            continue
        if e.get("resource_type") == "PathExpression":
            out.extend(p for p in e.get("paths") or [] if isinstance(p, str))
        elif e.get("resource_type") == "NestedExpression":
            out.extend(expression_paths(e.get("expressions")))
    return out


def nested_service_paths(service: Dict[str, Any]) -> List[str]:
    """NSX nests services as NestedServiceServiceEntry.nested_service_path."""
    return [e["nested_service_path"] for e in service.get("service_entries") or []
            if isinstance(e, dict) and e.get("resource_type") == "NestedServiceServiceEntry"
            and _is_ref(e.get("nested_service_path"))]


def dependency_closure(cap: CaptureView, selected: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    group_refs: Set[str] = set()
    service_refs: Set[str] = set()
    profiles: Set[str] = set()
    for s in selected:
        rule = cap.rules[(s["policy_id"], s["rule_id"])]
        for f in RULE_REF_FIELDS:
            group_refs.update(v for v in rule.get(f) or [] if _is_ref(v))
        service_refs.update(v for v in rule.get("services") or [] if _is_ref(v))
        profiles.update(v for v in rule.get("profiles") or [] if _is_ref(v))
    for pid in {s["policy_id"] for s in selected}:
        group_refs.update(v for v in cap.policies[pid].get("scope") or [] if _is_ref(v))

    groups: Set[str] = set()
    unresolved_groups: Set[str] = set()
    segments: Set[str] = set()
    pending = sorted(group_refs)
    while pending:
        p = pending.pop()
        if p in groups or p in unresolved_groups:
            continue
        g = cap.groups.get(p)
        if g is None:
            unresolved_groups.add(p)
            continue
        groups.add(p)
        for q in expression_paths(g.get("expression")):
            if is_group_path(q):
                pending.append(q)
            else:
                segments.add(q)

    services: Set[str] = set()
    builtin: Set[str] = set()
    pending = sorted(service_refs)
    while pending:
        p = pending.pop()
        if p in services or p in builtin:
            continue
        s = cap.services.get(p)
        if s is None:
            builtin.add(p)
            continue
        services.add(p)
        pending.extend(nested_service_paths(s))
    return {"groups": sorted(groups), "services": sorted(services),
            "unresolved_groups": sorted(unresolved_groups),
            "builtin_services": sorted(builtin), "segment_paths": sorted(segments),
            "context_profiles": sorted(profiles)}


# ---------------------------------------------------------------------------
# Bundles
# ---------------------------------------------------------------------------

def write_bundle(out: Path, cap: CaptureView, selected: Sequence[Dict[str, Any]],
                 clo: Dict[str, Any]) -> Dict[str, Any]:
    """Write the Workflow A bundle in the push tools' layout, plus the kept
    groups' captured-IP copies (c_input/) that Workflow C builds from:

      services/services/*.yaml        groups/groups/*.yaml
      policies/security-policies/<slug>/policy.yaml
      rules/security-policies/<slug>/{policy.yaml, rules/*.yaml}
      c_input/*.yaml
    """
    svc_dir = out / "services" / "services"
    grp_dir = out / "groups" / "groups"
    pol_root = out / "policies" / "security-policies"
    rul_root = out / "rules" / "security-policies"
    c_in = out / "c_input"
    for d in (svc_dir, grp_dir, pol_root, rul_root, c_in):
        d.mkdir(parents=True, exist_ok=True)
    for p in clo["services"]:
        shutil.copy2(cap.service_files[p], svc_dir / cap.service_files[p].name)
    no_additive: List[str] = []
    for p in clo["groups"]:
        shutil.copy2(cap.group_files[p], grp_dir / cap.group_files[p].name)
        src = cap.additive_files.get(p)
        if src is None:
            no_additive.append(p)
            src = cap.group_files[p]
        shutil.copy2(src, c_in / src.name)
    by_policy: Dict[str, List[Dict[str, Any]]] = {}
    for s in selected:
        by_policy.setdefault(s["policy_id"], []).append(s)
    for pid, rules in by_policy.items():
        pf = cap.policy_files[pid]
        slug = pf.parent.name
        order = {"policy": pid, "rules": [s["rule_id"] for s in rules]}
        for root in (pol_root, rul_root):
            (root / slug).mkdir(parents=True, exist_ok=True)
            shutil.copy2(pf, root / slug / "policy.yaml")
            write_yaml(root / slug / "rules_order.yaml", order)
        for s in rules:
            rf = cap.rule_files[(pid, s["rule_id"])]
            doc = read_yaml(rf)
            # The rules push reads the parent policy from this field (the
            # capture's own flat-export step injects it the same way).
            doc["_parent_policy_id"] = pid
            write_yaml(rul_root / slug / "rules" / rf.name, doc)
    return {"policies": len(by_policy), "rules": len(selected), "groups": len(clo["groups"]),
            "services": len(clo["services"]), "groups_without_captured_ips": no_additive}


def ip_covered(ip: str, entries: Iterable[str]) -> bool:
    """True when `ip` equals, or lies inside, one of the group's address
    entries (address, CIDR, or a-b range)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for e in entries:
        e = str(e).strip()
        try:
            if "/" in e:
                if a in ipaddress.ip_network(e, strict=False):
                    return True
            elif "-" in e:
                lo, hi = (ipaddress.ip_address(x.strip()) for x in e.split("-", 1))
                if lo.version == a.version and lo <= a <= hi:
                    return True
            elif a == ipaddress.ip_address(e):
                return True
        except (ValueError, TypeError):
            continue
    return False


def amendable_groups(cap: CaptureView) -> Set[str]:
    """Group paths named in source/destination of a customer rule on the source."""
    out: Set[str] = set()
    for (pid, _rid), rule in cap.rules.items():
        if is_default_policy(cap.policies.get(pid) or {}):
            continue
        for f in AMEND_FIELDS:
            out.update(v for v in rule.get(f) or [] if _is_ref(v))
    return out


def d_scope(servers: Sequence[Dict[str, Any]], data: Dict[str, Any], cap: CaptureView
            ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    """Workflow D scope (Mike, 2026-10-07): the groups the servers are
    members of that sit in a rule, each holding only those servers'
    addresses. Returns ({group path: {id, name, servers: {server: [ips]}}},
    groups left out with the reason)."""
    used = amendable_groups(cap)
    members = data.get("group_to_members") or {}
    group_ips = data.get("group_ips") or {}
    scope: Dict[str, Dict[str, Any]] = {}
    left_out: Dict[str, Dict[str, Any]] = {}
    for row in servers:
        if row["status"] != "ok" or not row.get("external_id"):
            continue
        label = row["vm"] or row["key"]
        for path in row["group_paths"]:
            g = cap.groups.get(path)
            name = (g or {}).get("display_name") or path.rsplit("/", 1)[-1]
            if g is None:
                left_out[path] = {"group": name, "reason": "not in the captured domain"}
                continue
            if path not in used:
                left_out[path] = {"group": name, "reason": "not in any rule's source or destination"}
                continue
            ips = [ip for ip in row["ips"] if ip_covered(ip, group_ips.get(path) or ())]
            if not ips and row["external_id"] in set(members.get(path) or ()):
                ips = list(row["ips"])
            slot = scope.setdefault(path, {"id": g["id"], "name": name, "servers": {}})
            slot["servers"][label] = sorted(set(slot["servers"].get(label, [])) | set(ips))
    return scope, sorted(left_out.values(), key=lambda x: x["group"])


def _strip_ip_expressions(expr: Any) -> List[Any]:
    out: List[Any] = []
    for e in expr or []:
        if isinstance(e, dict) and e.get("resource_type") == "IPAddressExpression":
            continue
        if isinstance(e, dict) and e.get("resource_type") == "NestedExpression":
            e = {**e, "expressions": _strip_ip_expressions(e.get("expressions"))}
        out.append(e)
    return out


def write_d_input(out: Path, cap: CaptureView, scope: Dict[str, Dict[str, Any]]) -> int:
    """One file per D group for build_sibling_groups.py: the group's
    definition with its address lists replaced by the requested servers'
    addresses. Conditions and paths stay, so the builder's own rules (skip a
    segment-based group) apply unchanged."""
    out.mkdir(parents=True, exist_ok=True)
    n = 0
    for path, slot in sorted(scope.items()):
        g = copy.deepcopy(cap.groups[path])
        ips = sorted({ip for v in slot["servers"].values() for ip in v})
        g["expression"] = _strip_ip_expressions(g.get("expression")) + (
            [{"resource_type": "IPAddressExpression", "ip_addresses": ips}] if ips else [])
        write_yaml(out / cap.group_files[path].name, g)
        n += 1
    return n


# ---------------------------------------------------------------------------
# Rule amendments (what amend-refs adds), computed from the capture
# ---------------------------------------------------------------------------

def sibling_pairs(sibling_map: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {r["original_id"]: r for r in (sibling_map or {}).get("map") or []}


def amendments(rules: Iterable[Tuple[Dict[str, Any], Dict[str, Any]]],
               sibling_map: Dict[str, Any]) -> List[Dict[str, Any]]:
    """(policy, rule) pairs -> one row per rule that gains a sibling."""
    pairs = sibling_pairs(sibling_map)
    out: List[Dict[str, Any]] = []
    for pol, rule in rules:
        adds = []
        for f in AMEND_FIELDS:
            current = [v for v in rule.get(f) or [] if _is_ref(v)]
            ids = {v.rsplit("/", 1)[-1] for v in current}
            for v in current:
                row = pairs.get(v.rsplit("/", 1)[-1])
                if row and row["sibling_id"] not in ids:
                    adds.append({"field": f, "original": row.get("original_display_name") or row["original_id"],
                                 "sibling": row["sibling_id"]})
        if adds:
            out.append({"key": f"{pol.get('id')}/{rule.get('id')}",
                        "policy_name": pol.get("display_name") or pol.get("id"),
                        "rule_name": rule.get("display_name") or rule.get("id"), "adds": adds})
    return out


def source_rules(cap: CaptureView) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    pairs = [(cap.policies[pid], r) for (pid, _), r in cap.rules.items()
             if not is_default_policy(cap.policies[pid])]
    return sorted(pairs, key=lambda pr: rule_order_key(*pr))


def selected_rules(cap: CaptureView, selected: Sequence[Dict[str, Any]]
                   ) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    return [(cap.policies[s["policy_id"]], cap.rules[(s["policy_id"], s["rule_id"])]) for s in selected]


# ---------------------------------------------------------------------------
# Fingerprints, comparison and the gate
# ---------------------------------------------------------------------------

def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                     default=str).encode("utf-8")).hexdigest()


def build_model(rec: Dict[str, Any], cap: CaptureView, clo: Dict[str, Any],
                c_map: Dict[str, Any], d_map: Dict[str, Any],
                palo_plan: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Everything the request would change, as content fingerprints. Two
    models are equal exactly when the same objects would be pushed."""
    ck = lambda o: hashlib.sha256(content_key(o).encode("utf-8")).hexdigest()[:16]  # noqa: E731
    servers = {r["key"]: {"status": r["status"], "vm": r["vm"], "external_id": r["external_id"],
                          "ips": sorted(r["ips"]), "new_ips": r.get("new_ips") or {}}
               for r in rec["servers"]}
    model = {
        "servers": servers,
        "rules": {s["key"]: ck(cap.rules[(s["policy_id"], s["rule_id"])]) for s in rec["rules"]},
        "policies": {pid: ck(cap.policies[pid]) for pid in sorted({s["policy_id"] for s in rec["rules"]})},
        "groups": {cap.groups[p]["id"]: ck(cap.groups[p]) for p in clo["groups"]},
        "services": {cap.services[p]["id"]: ck(cap.services[p]) for p in clo["services"]},
        "c_siblings": {r["sibling_id"]: sorted(r.get("ips_source") or []) for r in c_map.get("map") or []},
        "d_siblings": {r["sibling_id"]: sorted(r.get("ips_sibling_mapped") or []) for r in d_map.get("map") or []},
        "c_amend": sorted(f"{a['key']} {x['field']} +{x['sibling']}" for a in rec["c_amend"] for x in a["adds"]),
        "d_amend": sorted(f"{a['key']} {x['field']} +{x['sibling']}" for a in rec["d_amend"] for x in a["adds"]),
        "palo": ({f"{w['kind']}/{w['name']}": _digest(w.get("entry"))[:16] for w in palo_plan.get("writes") or []}
                 if palo_plan else {}),
    }
    model["digest"] = _digest({k: v for k, v in model.items() if k != "digest"})
    return model


def compare_models(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Dict[str, List[str]]]:
    out: Dict[str, Dict[str, List[str]]] = {}
    for cat in sorted(set(old) | set(new)):
        if cat == "digest":
            continue
        a, b = old.get(cat), new.get(cat)
        if isinstance(a, list) or isinstance(b, list):
            sa, sb = set(a or []), set(b or [])
            d = {"added": sorted(sb - sa), "removed": sorted(sa - sb), "changed": []}
        else:
            a, b = a or {}, b or {}
            d = {"added": sorted(set(b) - set(a)), "removed": sorted(set(a) - set(b)),
                 "changed": sorted(k for k in set(a) & set(b) if a[k] != b[k])}
        if any(d.values()):
            out[cat] = d
    return out


def server_gate(old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    """The run stops when one of the request's own servers changed: that is
    the one thing no other approval covers (Mike, 2026-10-07)."""
    problems: List[str] = []
    a, b = old.get("servers") or {}, new.get("servers") or {}
    for key in sorted(set(a) | set(b)):
        x, y = a.get(key), b.get(key)
        if x is None or y is None:
            problems.append(f"{key}: {'added to' if x is None else 'missing from'} the request")
            continue
        if x["status"] != y["status"]:
            problems.append(f"{key}: status was {x['status']}, now {y['status']}")
        if x["external_id"] != y["external_id"]:
            problems.append(f"{key}: resolves to a different VM ({x['vm']} then, {y['vm']} now)")
        if x["ips"] != y["ips"]:
            problems.append(f"{key}: addresses were {', '.join(x['ips']) or 'none'}, "
                            f"now {', '.join(y['ips']) or 'none'}")
        if x.get("new_ips") != y.get("new_ips"):
            problems.append(f"{key}: new addresses at the destination changed")
    return problems


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def _gname(path: str, gbp: Dict[str, Any]) -> str:
    """Group display name from {path: name} or {path: {display_name}}."""
    v = gbp.get(path)
    if isinstance(v, dict):
        v = v.get("display_name")
    return v or path.rsplit("/", 1)[-1]


def _side(refs: Sequence[str], gbp: Dict[str, Dict[str, Any]]) -> str:
    names = [_gname(r, gbp) if _is_ref(r) else str(r) for r in refs or []]
    return ", ".join(names) if names else "ANY"


def _services(refs: Sequence[str]) -> str:
    names = [r.rsplit("/", 1)[-1] if _is_ref(r) else str(r) for r in refs or []]
    return ", ".join(names) if names else "ANY"


def preview_counts(rows: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    """Classify push dry-run rows: new / update / unchanged / skipped / failed."""
    c = {"new": 0, "update": 0, "unchanged": 0, "skipped": 0, "failed": 0}
    for r in rows:
        st = str(r.get("status") or "")
        if st.startswith("failed"):
            c["failed"] += 1
        elif st in ("skipped_unchanged", "skipped_no_change", "no_change"):
            c["unchanged"] += 1
        elif st == "dry_run":
            c["update" if r.get("exists_on_target") or r.get("refs_added_total") else "new"] += 1
        else:
            c["skipped"] += 1
    return c


def counts_text(c: Optional[Dict[str, int]], new: str = "new", update: str = "update") -> str:
    if not c:
        return "not previewed"
    parts = [f"{c.get('new', 0)} {new}", f"{c.get('update', 0)} {update}",
             f"{c.get('unchanged', 0)} already identical"]
    if c.get("failed"):
        parts.append(f"**{c['failed']} failed**")
    return ", ".join(parts)


def _palo_existing_gaps(push_doc: Dict[str, Any], plan: Dict[str, Any]) -> List[List[str]]:
    """Address groups already on Panorama that miss planned members. The push
    never edits an existing object, so these members are NOT added by it."""
    planned = {w["name"]: w["entry"] for w in plan.get("writes") or [] if w.get("kind") == "address-group"}
    out = []
    for r in push_doc.get("results") or []:
        if r.get("kind") != "address-group" or not r.get("differs"):
            continue
        want = ((planned.get(r["name"]) or {}).get("static") or {}).get("member") or []
        have = ((r.get("existing") or {}).get("static") or {}).get("member") or []
        have = [have] if isinstance(have, str) else have
        missing = sorted(set(want) - set(have))
        if missing:
            out.append([r["name"], str(len(missing)), ", ".join(missing)])
    return out


def render_request_md(rec: Dict[str, Any], previews: Optional[Dict[str, Any]] = None,
                      title: str = "Migration request") -> str:
    """The approver's report: servers first, then every change per system."""
    previews = previews or {}
    inp = rec["inputs"]
    gbp = rec.get("group_names") or {}
    src, dst = inp["source_host"], inp["destination_host"]
    L: List[str] = [f"# {title}: {inp.get('name') or rec['request_id']}", ""]
    L += [f"Servers moving from **{src}** to **{dst}**. Request `{rec['request_id']}`, built "
          f"{rec['created_at']} from a capture of {src} taken {rec['captured_at']}.", ""]
    srcs = inp.get("server_sources") or []
    if srcs:
        L += ["Server list: " + "; ".join(
            f"`{x['file']}` ({x['entries']} entries, sha256 {x['sha256'][:12]})" if "file" in x
            else f"{x['command_line']} from the command line" for x in srcs) + ".", ""]
    if rec.get("approval"):
        a = rec["approval"]
        L += [f"Status: **approved** by {a.get('approved_by') or 'unknown'} under change "
              f"{a.get('change_ref') or 'none'} at {a.get('approved_at')}.", ""]
    else:
        L += ["Status: **awaiting approval**.", ""]
    if rec.get("errors"):
        L += ["**Errors (must be resolved before approval):**", ""] + [f"- {e}" for e in rec["errors"]] + [""]
    s = rec["summary"]
    L += md_table(["servers requested", "found", "need attention", "NSX rules to copy", "groups", "services",
                   "C siblings", "D siblings", "source rules amended", "Palo objects"],
                  [[s["servers"], s["servers_ok"], s["servers_attention"], s["rules"], s["groups"],
                    s["services"], s["c_siblings"], s["d_siblings"], s["d_rules_amended"],
                    s["palo_writes"]]], ["r"] * 10)
    L += ["", "## Servers", ""]
    L += md_table(["#", "requested as", "VM", "addresses", f"new address at {dst}", "groups", "rules", "status"],
                  [[i, ", ".join(r["requested_as"]), r["vm"] or "-", ", ".join(r["ips"]) or "-",
                    ", ".join(f"{k} to {', '.join(v) or 'unmapped'}" for k, v in (r.get("new_ips") or {}).items())
                    or "-", len(r["groups"]), r["rules"],
                    "ok" if r["status"] == "ok" and not r["problems"] else
                    "; ".join([r["status"]] * (r["status"] != "ok") + r["problems"]
                              + ([f"did you mean {', '.join(r['suggestions'])}?"] if r["suggestions"] else []))]
                   for i, r in enumerate(rec["servers"], 1)], ["r", "l", "l", "l", "l", "r", "r", "l"])
    L += ["", "Groups each server is in:", ""]
    L += md_table(["server", "groups"], [[r["vm"] or r["key"], ", ".join(r["groups"]) or "none"]
                                         for r in rec["servers"] if r["status"] == "ok"])

    L += ["", "## Firewall rules these servers use", "",
          "Every NSX rule on the source whose source, destination or applied-to contains a requested "
          "server, in NSX evaluation order. These are the rules copied to the destination. A rule "
          "applies to every member of its groups, not only the requested servers.", ""]
    L += md_table(["#", "policy", "rule", "action", "source", "destination", "services", "applied to",
                   "servers (side)"],
                  [[i, x["policy_name"], x["rule_name"] + (" (disabled)" if x["disabled"] else "")
                    + (" [ANY to ANY]" if x["global"] else ""), x["action"], _side(x["source_groups"], gbp),
                    _side(x["destination_groups"], gbp), _services(x["services"]), _side(x["scope"], gbp),
                    "; ".join(f"{m['server']} ({'/'.join(m['sides'])})" for m in x["matched"])]
                   for i, x in enumerate(rec["rules"], 1)], ["r"] + ["l"] * 8)
    if rec["excluded_rules"]:
        L += ["", "Rules the servers touch that are NOT copied:", ""]
        L += md_table(["policy", "rule", "why"], [[x["policy_name"], x["rule_name"], x["reason"]]
                                                 for x in rec["excluded_rules"]])

    a_prev = previews.get("a") or {}
    L += ["", f"## Workflow A: objects copied to {dst}", ""]
    rows = []
    for kind in ("services", "groups", "policies", "rules"):
        c = (a_prev.get(kind) or {})
        rows.append([kind, rec["summary"][kind] if kind in rec["summary"] else len(rec["bundle"].get(kind) or []),
                     c.get("new", "-"), c.get("update", "-"), c.get("unchanged", "-"), c.get("failed", "-")])
    L += md_table(["kind", "in bundle", "new", "update", "already identical", "failed"], rows,
                  ["l", "r", "r", "r", "r", "r"])
    if not a_prev:
        L += ["", "Destination not previewed: run `preview --part a` for new / update / identical."]
    L += ["", "Groups: " + (", ".join(sorted(_gname(p, gbp) for p in rec["closure"]["groups"])) or "none") + ".",
          "", "Services: " + (", ".join(sorted(p.rsplit('/', 1)[-1] for p in rec["closure"]["services"]))
                              or "none") + "."]
    if rec["closure"]["builtin_services"]:
        L += ["", "Built-in NSX services the rules use (already on every manager, not copied): "
              + ", ".join(p.rsplit("/", 1)[-1] for p in rec["closure"]["builtin_services"]) + "."]
    if rec["closure"]["segment_paths"]:
        L += ["", "Segment references inside groups are stripped on the destination (segment ids differ "
              "per manager): " + ", ".join(p.rsplit("/", 1)[-1] for p in rec["closure"]["segment_paths"]) + "."]
    if rec["closure"]["context_profiles"]:
        L += ["", "Context profiles the rules use (not copied by any push tool; must exist on the destination): "
              + ", ".join(p.rsplit("/", 1)[-1] for p in rec["closure"]["context_profiles"]) + "."]
    if rec["closure"]["unresolved_groups"]:
        L += ["", "**Group references not found in the capture:** "
              + ", ".join(rec["closure"]["unresolved_groups"]) + "."]

    L += ["", f"## Workflow C: sibling groups on {dst}", "",
          f"IP-only `{inp['c_appendix']}` siblings holding the source's current addresses, so the copied rules "
          "still match servers that have not moved yet.", ""]
    c_rows = rec["c_siblings"]
    L += (md_table(["sibling", "original group", "addresses"],
                   [[r["sibling_id"], r["original"], ", ".join(r["ips"])] for r in c_rows]) if c_rows else ["None."])
    c_prev = (previews.get("c") or {}).get("siblings")
    if c_prev:
        L += ["", f"Dry run against {dst}: {counts_text(c_prev)}."]
    L += ["", "Rules on the destination that gain a sibling:", ""]
    L += (md_table(["policy", "rule", "adds"],
                   [[a["policy_name"], a["rule_name"], ", ".join(f"{x['sibling']} ({x['field'].split('_')[0]})"
                                                               for x in a["adds"])] for a in rec["c_amend"]])
          if rec["c_amend"] else ["None."])

    d_prev = previews.get("d") or {}
    L += ["", f"## Workflow D: changes on {src}", "",
          f"`{inp['d_appendix']}` siblings for the groups the servers are in that a rule uses, holding only "
          f"the requested servers' new addresses (map `{inp['subnet_map']}`). The rules those groups are in "
          "gain the sibling.", ""]
    by_sib: Dict[str, Dict[str, Any]] = {}
    for r in rec["d_siblings"]:
        slot = by_sib.setdefault(r["sibling_id"], {"original": r["original"], "addrs": []})
        slot["addrs"].append(f"{r['mapped_ip'] or 'unmapped'} ({r['server']})")
    L += (md_table(["sibling", "original group", f"addresses at {dst} (server)"],
                   [[k, v["original"], ", ".join(v["addrs"])] for k, v in by_sib.items()])
          if by_sib else ["None."])
    if rec["d_no_sibling"]:
        L += ["", "Groups with no D sibling:", ""]
        L += md_table(["group", "why"], [[x["group"], x["reason"]] for x in rec["d_no_sibling"]])
    L += ["", f"Rules on {src} that gain a sibling:", ""]
    L += (md_table(["policy", "rule", "adds"],
                   [[a["policy_name"], a["rule_name"], ", ".join(f"{x['sibling']} ({x['field'].split('_')[0]})"
                                                               for x in a["adds"])] for a in rec["d_amend"]])
          if rec["d_amend"] else ["None."])
    if d_prev:
        am = d_prev.get("amend") or {}
        L += ["", f"Dry run against {src}: siblings {counts_text(d_prev.get('siblings'))}; "
                  f"{am.get('update', 0)} rules would gain a sibling, {am.get('unchanged', 0)} rules unchanged"
                  + (f", **{am['failed']} failed**" if am.get("failed") else "") + "."]

    L += ["", "## Palo Alto", ""]
    palo = rec.get("palo") or {}
    if not palo:
        L += ["Not planned for this request."]
    else:
        L += [f"Panorama device group **{palo['device_group']}**, objects in `{palo['object_location']}`, "
              f"{palo['rulebase']}-rulebase. Full plan: `{palo['plan_md']}`.", ""]
        pc = palo["counts"]
        L += md_table(["Panorama rules", "address groups", "addresses", "services", "service groups",
                       "NSX rules not mirrored", "errors", "warnings"],
                      [[pc["pan_rules"], pc["address_groups"], pc["addresses"], pc["services"],
                        pc["service_groups"], pc["nsx_rules_skipped"], pc["errors"], pc["warnings"]]], ["r"] * 8)
        pp = previews.get("palo")
        if pp:
            L += ["", f"Checked against {pp.get('panorama')} at {pp.get('created_at')}:", ""]
            L += md_table(["to create", "already there, identical", "already there, different", "failed"],
                          [[pp["summary"].get("would_create", 0), pp["summary"].get("exists_unchanged", 0)
                            - pp["summary"].get("exists_differs", 0), pp["summary"].get("exists_differs", 0),
                            pp["summary"].get("failed", 0)]], ["r"] * 4)
            gaps = pp.get("member_gaps") or []
            if gaps:
                L += ["", "**Address groups already on Panorama that lack members.** The push never edits an "
                      "existing object, so these members must be added by hand:", ""]
                L += md_table(["address group", "missing", "members to add"], gaps, ["l", "r", "l"])
            kinds: Dict[str, int] = {}
            for w in pp.get("would_create") or []:
                kinds[w["kind"]] = kinds.get(w["kind"], 0) + 1
            if kinds:
                L += ["", "To create, by kind (every name is in the dry-run report "
                      f"`{pp.get('report')}`):", ""]
                L += md_table(["kind", "to create"], [[k, n] for k, n in sorted(kinds.items())], ["l", "r"])
        else:
            L += ["", "Panorama not checked yet: run `preview --part palo` for what already exists."]
        if palo.get("groups"):
            L += ["", "Address groups (one per NSX group, holding its addresses at every site):", ""]
            L += md_table(["address group", "NSX group", "addresses"],
                          [[g["name"], g["nsx"], g["members"]] for g in palo["groups"]], ["l", "l", "r"])
        L += ["", "Rules, in push order:", ""]
        L += md_table(["#", "rule", "action", "source", "destination", "service", "from NSX"],
                      [[i, r["name"], r["action"], r["source"], r["destination"], r["service"], r["nsx"]]
                       for i, r in enumerate(palo["rules"], 1)], ["r"] + ["l"] * 6)
        if palo["skipped"]:
            L += ["", "NSX rules not mirrored to Palo, or narrowed:", ""]
            L += md_table(["NSX policy / rule", "outcome"], palo["skipped"])
        other = [f for f in palo["findings"] if f[1] not in ("rule_narrower", "rule_skipped")]
        if other:
            L += ["", "Other Palo findings:", ""]
            L += md_table(["severity", "code", "where", "detail"], other)

    if rec.get("warnings"):
        L += ["", "## Warnings", ""] + [f"- {w}" for w in rec["warnings"]]
    L += ["", "## Files", "", f"- Request record: `{rec['paths']['record']}`",
          f"- Workflow A bundle: `{rec['paths']['bundle']}`",
          f"- Workflow C siblings: `{rec['paths']['c']}`", f"- Workflow D siblings: `{rec['paths']['d']}`"]
    if palo:
        L += [f"- Palo plan: `{palo['plan_md']}`"]
    L += [f"- Fingerprint: `{rec['model']['digest']}`", ""]
    return align_markdown_tables("\n".join(L)) + "\n"


def render_delta_md(run: Dict[str, Any], delta: Dict[str, Dict[str, List[str]]],
                    gate_problems: Sequence[str], strict: bool) -> str:
    L = [f"# Changes since approval: request {run['request_id']}", "",
         f"Rebuilt {run['created_at']} from a capture of {run['source_host']} taken {run['captured_at']}. "
         f"Approved fingerprint `{run['approved_digest']}`, now `{run['digest']}`.", ""]
    if gate_problems:
        L += ["**STOPPED.** The request's own servers changed. Raise a new request "
              "(nothing here was pushed):", ""] + [f"- {p}" for p in gate_problems] + [""]
    elif strict and delta:
        L += ["**STOPPED (--strict).** Something changed since approval; re-approve before pushing.", ""]
    elif delta:
        L += ["Proceeding. The changes below happened on the source after the request; they went through "
              "their own approval and are pushed as they are now.", ""]
    else:
        L += ["No change since approval: exactly the approved request will be pushed.", ""]
    labels = {"servers": "Servers", "rules": "NSX rules", "policies": "Policies", "groups": "Groups",
              "services": "Services", "c_siblings": "Workflow C siblings", "d_siblings": "Workflow D siblings",
              "c_amend": "Destination rule amendments", "d_amend": "Source rule amendments",
              "palo": "Palo Alto objects"}
    for cat, d in delta.items():
        L += [f"## {labels.get(cat, cat)}", ""]
        L += md_table(["change", "items"], [[k, ", ".join(md_escape(x) for x in v)] for k, v in d.items() if v])
        L += [""]
    return align_markdown_tables("\n".join(L)) + "\n"
