#!/usr/bin/env python3
"""app/palo/pan_rule_placement.py

Pure engine for "which device group should a new src -> dst rule go in".

Data model: per device group, the ROUTING TABLE of its firewall(s) (from
`show routing route`, proxied through Panorama). The recommendation logic:

  1. "Most likely" placement anchors on specificity, per side: the DG(s)
     whose best route to the SOURCE is the most specific anywhere, plus
     the DG(s) whose best route to the DESTINATION is the most specific
     anywhere. When src anchors to firewall A and dst anchors to firewall
     B, BOTH are recommended: the flow plausibly crosses both, and each
     needs the rule.
  2. A default route (prefix 0) never anchors: a firewall that reaches an
     endpoint only via its default route is transit at best, so it is not
     recommended unless nothing better exists anywhere.
  3. Connected routes beat static, static beat dynamic, at equal prefix
     length.
  4. Owning an endpoint is enough to be recommended; a missing route to
     the FAR endpoint on that firewall is reported as a caution, not a
     disqualifier (the rule belongs there once routing is in place, and
     partial RIB visibility should not hide the placement).

Everything here is pure computation over parsed route entries; pulling the
tables is the caller's job.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional

KIND_ORDER = {"connected": 3, "static": 2, "dynamic": 1}


class PanPlacementError(RuntimeError):
    pass


def parse_route_entry(e: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One `show routing route` result entry -> normalized route, or None
    for entries we cannot use (no destination, unparseable)."""
    dest = (e.get("destination") or "").strip()
    flags = (e.get("flags") or "").replace("~", " ").split()
    if not dest:
        return None
    try:
        net = ipaddress.ip_network(dest, strict=False)
    except ValueError:
        return None
    kind = "connected" if "C" in flags else ("static" if "S" in flags else "dynamic")
    return {
        "destination": dest,
        "version": net.version,
        "lo": int(net.network_address),
        "hi": int(net.broadcast_address),
        "prefixlen": net.prefixlen,
        "kind": kind,
        "active": "A" in flags,
        "interface": (e.get("interface") or "").strip(),
        "nexthop": (e.get("nexthop") or "").strip(),
        "virtual_router": (e.get("virtual-router") or "").strip(),
    }


def parse_routes(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for e in entries:
        r = parse_route_entry(e)
        if r:
            out.append(r)
    return out


def best_route(ip_text: str, routes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Longest-prefix active route for the IP; connected > static > dynamic
    on equal prefix. None when no active route covers it (not even default)."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise PanPlacementError(f"Not an IP address: {ip_text!r}") from exc
    best = None
    for r in routes:
        if not r["active"] or r["version"] != ip.version:
            continue
        if not (r["lo"] <= int(ip) <= r["hi"]):
            continue
        if best is None or (r["prefixlen"], KIND_ORDER[r["kind"]]) > \
                (best["prefixlen"], KIND_ORDER[best["kind"]]):
            best = r
    return best


def _route_phrase(r: Optional[Dict[str, Any]]) -> str:
    if r is None:
        return "no route"
    where = f" on {r['interface']}" if r["interface"] else ""
    via = f" via {r['nexthop']}" if r["nexthop"] and r["kind"] != "connected" else ""
    if r["prefixlen"] == 0:
        return f"default route only{via}"
    return f"{r['kind']} {r['destination']}{where}{via}"


def recommend_placement(
    src_ip: str,
    dst_ip: str,
    dg_tables: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """dg_tables: {dg_name: {"device": hostname, "routes": [parsed routes]}}.

    Returns {"recommended": [...], "considered": [...], "note": str|None}.
    Each recommended entry carries the reasons; considered lists every DG
    with its src/dst route summary and why it was or was not chosen.
    """
    evaluated = []
    for dg, info in sorted(dg_tables.items()):
        src_r = best_route(src_ip, info["routes"])
        dst_r = best_route(dst_ip, info["routes"])
        evaluated.append({
            "dg": dg,
            "device": info.get("device", "?"),
            "src_route": src_r, "dst_route": dst_r,
            "src_pref": src_r["prefixlen"] if src_r else -1,
            "dst_pref": dst_r["prefixlen"] if dst_r else -1,
        })

    max_src = max((e["src_pref"] for e in evaluated), default=-1)
    max_dst = max((e["dst_pref"] for e in evaluated), default=-1)

    recommended = []
    for e in evaluated:
        reasons = []
        # Anchor only on non-default specificity (prefix > 0).
        if e["src_pref"] == max_src and max_src > 0:
            reasons.append(f"most specific route to source: {_route_phrase(e['src_route'])}")
        if e["dst_pref"] == max_dst and max_dst > 0:
            reasons.append(f"most specific route to destination: {_route_phrase(e['dst_route'])}")
        if reasons:
            # Say how (or whether) the non-anchoring side is reachable.
            if e["src_pref"] != max_src or max_src <= 0:
                reasons.append(
                    f"source reachable: {_route_phrase(e['src_route'])}" if e["src_route"]
                    else "caution: this firewall has NO route to the source; the rule "
                         "only matters once routing exists")
            if e["dst_pref"] != max_dst or max_dst <= 0:
                reasons.append(
                    f"destination reachable: {_route_phrase(e['dst_route'])}" if e["dst_route"]
                    else "caution: this firewall has NO route to the destination; the "
                         "rule only matters once routing exists")
            recommended.append({"dg": e["dg"], "device": e["device"],
                                "score": max(e["src_pref"], 0) + max(e["dst_pref"], 0),
                                "reasons": reasons})
    recommended.sort(key=lambda r: (-r["score"], r["dg"]))

    note = None
    if not recommended:
        if max_src <= 0 and max_dst <= 0:
            note = ("No firewall has a specific route to either endpoint "
                    "(default routes at best); the flow may be outside every "
                    "firewall's routed space, or routing data is missing.")

    considered = [{
        "dg": e["dg"], "device": e["device"],
        "src": _route_phrase(e["src_route"]),
        "dst": _route_phrase(e["dst_route"]),
        "verdict": ("recommended" if any(r["dg"] == e["dg"] for r in recommended)
                    else "another firewall owns the endpoints more specifically"),
    } for e in evaluated]

    return {"recommended": recommended, "considered": considered, "note": note}
