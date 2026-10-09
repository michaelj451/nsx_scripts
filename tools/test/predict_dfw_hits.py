#!/usr/bin/env python3
"""tools/test/predict_dfw_hits.py

Predict which DFW rule a flow hits on an NSX Local Manager, offline, so a
traffic plan can be checked before any traffic is sent.

Lab test tool only. It models NSX first-match evaluation at each VM vNIC the
flow crosses (source VM outbound, destination VM inbound):
  - category order Emergency, Infrastructure, Environment, Application
    (Ethernet is L2 and skipped), then policy sequence, then rule sequence;
  - disabled rules skipped; sources_excluded / destinations_excluded honoured;
  - Applied To: a rule is on a vNIC when its scope (or its policy's scope)
    is ANY or holds that VM as a member. Groups holding only IPs place the
    rule on no vNIC, which is how NSX treats them;
  - group addresses are the group's EFFECTIVE IPs as NSX reports them (what
    the DFW enforces, stale realized bindings included), not a rebuild from
    tags.
Rules and services come from the flat exports of capture_nsx_state.py. Group
membership comes from a live snapshot (read-only GETs) or a saved one.

USAGE:
    # Check every flow of a traffic plan (exit 1 if any flow would hit a rule
    # other than its `expect`, or more than one rule)
    python tools/test/predict_dfw_hits.py --source nsx-lm2 \\
        --plan tools/test/traffic_plans/lm2_hit_subset.yaml

    # Search: for every rule, one flow from the plan's hosts that hits only it,
    # and the rules no flow can reach
    python tools/test/predict_dfw_hits.py --source nsx-lm2 \\
        --plan tools/test/traffic_plans/lm2_hit_subset.yaml --search \\
        --extra-dst 10.21.250.10,10.21.4.10,8.8.8.8

    # Reuse a saved snapshot instead of querying NSX
    python tools/test/predict_dfw_hits.py --source nsx-lm2 --snapshot <file> --plan <plan>

OUTPUT:
    $NSX_LOG_DIR/dfw_predict/<host>/<UTC_TS>/live_groups.json  (live snapshots)
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.nsx_constants import resolve_manager         # noqa: E402

CATEGORIES = ["Ethernet", "Emergency", "Infrastructure", "Environment", "Application"]
BUILTIN_SERVICES = {
    "SSH": [("TCP", "22")], "HTTP": [("TCP", "80")], "HTTPS": [("TCP", "443")],
    "ICMP-ALL": [("ICMP", None)], "DHCP-Client": [("UDP", "68")],
    "DHCP-Server": [("UDP", "67")],
}
SEARCH_SERVICES = [("ICMP", None), ("TCP", "22"), ("TCP", "80"), ("TCP", "443"),
                   ("TCP", "8443"), ("TCP", "9005"), ("UDP", "53"), ("UDP", "514"),
                   ("UDP", "67"), ("UDP", "68"), ("TCP", "50"), ("UDP", "51")]


def _leaf(path: str) -> str:
    return path.rsplit("/", 1)[-1]


# =============================================================================
# Snapshot
# =============================================================================

def take_snapshot(alias: str) -> Dict[str, Any]:
    """Read-only: every group's effective IPs and VM members, every VM's IPv4s."""
    from nsx.nsx_policy_client import NsxPolicyClient
    c = NsxPolicyClient(nsxmanager=resolve_manager(alias), federation_global=False)
    snap: Dict[str, Any] = {"host": resolve_manager(alias),
                            "taken_at": datetime.now(timezone.utc).isoformat(),
                            "groups": {}, "vms": {}}
    for g in c.list_groups(domain_id="default"):
        gid = g["id"]
        snap["groups"][gid] = {
            "ips": sorted(c.get_group_effective_ips(gid, "default")),
            "vms": sorted(v.get("display_name") for v in c.list_policy_group_member_vms(gid, "default")),
        }
    names = {vm["external_id"]: vm["display_name"] for vm in c.list_virtual_machines()}
    for vif in c.list_vm_vifs():
        name = names.get(vif.get("owner_vm_id"))
        if not name:
            continue
        for info in vif.get("ip_address_info") or []:
            snap["vms"].setdefault(name, []).extend(
                ip for ip in info.get("ip_addresses") or [] if ":" not in ip)
    return snap


# =============================================================================
# Model
# =============================================================================

class Model:
    def __init__(self, host: str, snap: Dict[str, Any]):
        self.groups = snap["groups"]
        self.ip_to_vms: Dict[str, List[str]] = {}
        for vm, ips in snap["vms"].items():
            for ip in ips:
                self.ip_to_vms.setdefault(ip, []).append(vm)
        self.services: Dict[str, Dict[str, Any]] = {}
        for f in Path(f"nsx_services_export/{host}/services").rglob("*.yaml"):
            s = yaml.safe_load(f.read_text(encoding="utf-8"))
            self.services[s["id"]] = s
        rules_root = Path(f"nsx_rules_export/{host}/security-policies")
        if not rules_root.is_dir():
            raise SystemExit(f"no flat rule export at {rules_root}; run capture_nsx_state.py first")
        policies = {}
        for p in rules_root.rglob("policy.yaml"):
            d = yaml.safe_load(p.read_text(encoding="utf-8"))
            policies[d["id"]] = d
        self.rules: List[Tuple[Tuple[int, int, int], Dict[str, Any], Dict[str, Any]]] = []
        self.all_rule_ids: List[str] = []
        for f in rules_root.rglob("rules/*.yaml"):
            r = yaml.safe_load(f.read_text(encoding="utf-8"))
            pol = policies[_leaf(r["parent_path"])]
            cat = pol.get("category")
            if cat == "Ethernet":
                continue
            self.all_rule_ids.append(r["id"])
            if r.get("disabled"):
                continue
            key = (CATEGORIES.index(cat), pol.get("sequence_number", 0), r.get("sequence_number", 0))
            self.rules.append((key, pol, r))
        self.rules.sort(key=lambda t: t[0])

    def _entries(self, sid: str, seen: Tuple[str, ...] = ()) -> List[Tuple[str, Optional[str]]]:
        if sid in BUILTIN_SERVICES:
            return BUILTIN_SERVICES[sid]
        out: List[Tuple[str, Optional[str]]] = []
        for e in (self.services.get(sid) or {}).get("service_entries") or []:
            t = e.get("resource_type")
            if t == "L4PortSetServiceEntry":
                out += [(e["l4_protocol"].upper(), p) for p in e.get("destination_ports") or []]
            elif t == "ICMPTypeServiceEntry":
                out.append(("ICMP", e.get("icmp_type")))
            elif t == "NestedServiceServiceEntry":
                n = _leaf(e["nested_service_path"])
                if n not in seen:
                    out += self._entries(n, seen + (n,))
        return out

    def _service_match(self, services: Optional[List[str]], proto: str, port: Optional[str]) -> bool:
        if not services or services == ["ANY"]:
            return True
        for sp in services:
            for p, ports in self._entries(_leaf(sp)):
                if p == "ICMP" and proto == "ICMP":
                    return True
                if p == proto and ports and port is not None:
                    lo, _, hi = ports.partition("-")
                    if int(lo) <= int(port) <= int(hi or lo):
                        return True
        return False

    @staticmethod
    def _ip_in(ip: str, entries: Sequence[str]) -> bool:
        a = ipaddress.ip_address(ip)
        for e in entries:
            if ":" in e:
                continue
            if "-" in e:
                lo, hi = e.split("-")
                if ipaddress.ip_address(lo) <= a <= ipaddress.ip_address(hi):
                    return True
            elif a in ipaddress.ip_network(e, strict=False):
                return True
        return False

    def _group_match(self, paths: Optional[List[str]], ip: str) -> bool:
        if not paths or paths == ["ANY"]:
            return True
        return any(self._ip_in(ip, self.groups.get(_leaf(p), {}).get("ips", [])) for p in paths)

    def _on_vnic(self, scope: Optional[List[str]], vm: str) -> bool:
        if not scope or scope == ["ANY"]:
            return True
        return any(vm in self.groups.get(_leaf(p), {}).get("vms", []) for p in scope)

    def first_match(self, vm: str, src: str, dst: str, proto: str, port: Optional[str]) -> str:
        for _, pol, r in self.rules:
            scope = r.get("scope") if r.get("scope") not in (None, ["ANY"]) else pol.get("scope")
            if not self._on_vnic(scope, vm):
                continue
            if self._group_match(r.get("source_groups"), src) == bool(r.get("sources_excluded")):
                continue
            if self._group_match(r.get("destination_groups"), dst) == bool(r.get("destinations_excluded")):
                continue
            if self._service_match(r.get("services"), proto, port):
                return r["id"]
        return "(no rule)"

    def evaluate(self, src: str, dst: str, proto: str, port: Optional[str]) -> Tuple[List[str], List[str]]:
        """Rules hit at the source VM's vNIC(s) and at the destination VM's vNIC(s)."""
        return ([self.first_match(vm, src, dst, proto, port) for vm in self.ip_to_vms.get(src, [])],
                [self.first_match(vm, src, dst, proto, port) for vm in self.ip_to_vms.get(dst, [])])


# =============================================================================
# Plans
# =============================================================================

def host_ips(plan: Dict[str, Any]) -> Dict[str, str]:
    ips = {}
    for alias, h in (plan.get("hosts") or {}).items():
        if h.get("ip"):
            ips[alias] = h["ip"]
        elif "@" in str(h.get("ssh", "")):
            ips[alias] = h["ssh"].split("@", 1)[1]
    return ips


def flow_points(f: Dict[str, Any]) -> List[Tuple[str, str, Optional[str]]]:
    a = f["action"]
    if a == "ping":
        return [(f["dst"], "ICMP", None)]
    if a in ("tcp", "iperf3"):
        return [(f["dst"], "TCP", str(f["port"]))]
    if a == "udp":
        return [(f["dst"], "UDP", str(f["port"]))]
    if a == "dns":
        return [(f["server"], "UDP", "53")]
    if a == "scan":
        lo, hi = (int(x) for x in str(f["ports"]).split("-"))
        return [(f["dst"], "TCP", str(p)) for p in range(lo, hi + 1)]
    if a in ("http", "download"):
        u = urlparse(f["url"])
        return [(u.hostname, "TCP", str(u.port or (443 if u.scheme == "https" else 80)))]
    raise SystemExit(f"flow {f.get('id')}: unknown action {a!r}")


def check_plan(model: Model, plan: Dict[str, Any]) -> int:
    ips = host_ips(plan)
    bad = 0
    for f in plan.get("flows") or []:
        src = ips.get(f["from"])
        if not src:
            print(f"BAD {f['id']}: host {f['from']!r} has no ip (add ip: to hosts)")
            bad += 1
            continue
        got: Set[str] = set()
        for dst, proto, port in flow_points(f):
            s, d = model.evaluate(src, dst, proto, port)
            got |= set(s + d)
        ok = got == {f["expect"]}
        bad += not ok
        print(f"{'OK ' if ok else 'BAD'} {f['id']:<24} expect={f['expect']:<24} predicted={sorted(got) or ['(no VM on path)']}")
    for rid in plan.get("cold") or []:
        if rid not in model.all_rule_ids:
            print(f"BAD cold rule {rid!r} does not exist on this manager")
            bad += 1
    print(f"{bad} problem(s)")
    return 1 if bad else 0


def search(model: Model, plan: Dict[str, Any], extra_dst: List[str]) -> None:
    ips = host_ips(plan)
    vm_ips = sorted(model.ip_to_vms)
    dsts = sorted(set(vm_ips) | set(extra_dst))
    found: Dict[str, Tuple[bool, str, List[str], List[str]]] = {}
    for alias, src in sorted(ips.items()):
        for dst in dsts:
            if dst == src:
                continue
            for proto, port in SEARCH_SERVICES:
                s, d = model.evaluate(src, dst, proto, port)
                hits = s + d
                for rid in set(hits):
                    clean = all(h == rid for h in hits)
                    label = f"{alias} -> {dst} {proto}/{port or '-'}"
                    prev = found.get(rid)
                    if prev is None or (clean and not prev[0]):
                        found[rid] = (clean, label, s, d)
    for _, pol, r in model.rules:
        rid = r["id"]
        if rid in found:
            clean, label, s, d = found[rid]
            print(f"{'clean' if clean else 'MIXED'}  {rid[:40]:<40} {label:<40} src={s or '-'} dst={d or '-'}")
    disabled = sorted(set(model.all_rule_ids) - {r['id'] for _, _, r in model.rules})
    dead = [r["id"] for _, _, r in model.rules if r["id"] not in found]
    print(f"No flow from these hosts reaches: {dead + [d + ' (disabled)' for d in disabled]}")


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--source", required=True, help="NSX manager alias whose rules are modelled")
    p.add_argument("--plan", type=Path, required=True, help="traffic plan YAML (hosts + flows)")
    p.add_argument("--snapshot", type=Path, help="saved live_groups.json (default: take one now)")
    p.add_argument("--search", action="store_true", help="find a flow for every rule instead of checking the plan")
    p.add_argument("--extra-dst", default="", help="comma-separated extra destination IPs for --search")
    args = p.parse_args()
    logging.disable(logging.CRITICAL)

    host = resolve_manager(args.source)
    if not host:
        raise SystemExit(f"cannot resolve {args.source!r}")
    if args.snapshot:
        snap = json.loads(args.snapshot.read_text(encoding="utf-8"))
    else:
        snap = take_snapshot(args.source)
        out = (Path(os.environ.get("NSX_LOG_DIR", "nsx_logs")) / "dfw_predict" / host
               / datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"))
        out.mkdir(parents=True, exist_ok=True)
        (out / "live_groups.json").write_text(json.dumps(snap, indent=1), encoding="utf-8")
        print(f"Snapshot: {out / 'live_groups.json'}")
    plan = yaml.safe_load(args.plan.read_text(encoding="utf-8")) or {}
    model = Model(host, snap)
    if args.search:
        search(model, plan, [x.strip() for x in args.extra_dst.split(",") if x.strip()])
        return 0
    return check_plan(model, plan)


if __name__ == "__main__":
    sys.exit(main())
