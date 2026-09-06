#!/usr/bin/env python3
"""tools/pan/ssdd_toolkit_web.py

SSDD Toolkit: local web hub for the Panorama tools. Serves on 127.0.0.1:

    /             SSDD Toolkit hub (links to the tool pages)
    /ip-search    IP-to-rule search: pull a config snapshot, then search
                  IPs / subnets / ranges against it (two buttons)
    /group-remap  CSV group remap dry run: pick a CSV from data/, run the
                  same analysis as tools/pan/pan_group_remap_report.py,
                  browse past reports
    /remap-pivot  Same CSV remap dry-run data, pivoted: one row per
                  group/rule with Source (adds) and Destination (adds) as
                  parallel columns. Shares run history with /group-remap.

Read-only against Panorama, stdlib HTTP server only, binds loopback only
(no auth; it never listens beyond 127.0.0.1). Managed firewalls are never
contacted. All runs land in the same pan_reports/ and pan_capture/ trees
the CLI tools use, so web and CLI runs share one history.

USAGE:
    # Simplest: reads agent_user / agent_password from .env by default.
    python tools/pan/ssdd_toolkit_web.py --no-tls-verify
    # then open http://127.0.0.1:8765

    # Override the .env var names if your account uses different keys:
    python tools/pan/ssdd_toolkit_web.py \
        --user-env some_other_user --password-env some_other_pw --no-tls-verify

(tools/pan/ip_rule_search_web.py now delegates here.)
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

import xml.etree.ElementTree as ET  # noqa: E402

import requests  # noqa: E402
import urllib3  # noqa: E402

from palo.pan_env import resolve_panorama_env  # noqa: E402
from palo.pan_group_remap import read_csv_mappings, summarize_refs  # noqa: E402
from palo.pan_ip_rules import (  # noqa: E402
    match_flow, match_rules, parse_ip_lines, parse_port_spec,
)
from palo.pan_rest_client import PanRestClient, PanRestError  # noqa: E402
from palo.pan_rule_placement import (  # noqa: E402
    PanPlacementError, parse_routes, recommend_placement,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("ssdd_toolkit_web")

DEFAULT_PORT = 8765
REPO_EXCLUDE_FILE = REPO_ROOT / "pan_ip_rule_exclude.txt"
DATA_DIR = REPO_ROOT / "data"
RUN_ID_RE = re.compile(r"^\d{8}_\d{6}$")

CONFIG: Dict[str, Any] = {}


def _load_remap_module():
    """The group remap CLI, loaded as a module so run_report() is shared."""
    spec = importlib.util.spec_from_file_location(
        "pan_group_remap_report", Path(__file__).parent / "pan_group_remap_report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


REMAP = _load_remap_module()


def fresh_client() -> PanRestClient:
    return PanRestClient.from_env(user_env=CONFIG["user_env"],
                                  password_env=CONFIG["password_env"],
                                  host=CONFIG["host"])


# =============================================================================
# IP search: snapshot + search (see /ip-search)
# =============================================================================

SNAPSHOT: Dict[str, Any] = {}


def snapshot_file() -> Path:
    return REPO_ROOT / "pan_capture" / CONFIG["display_host"].split(".")[0] / "web_snapshot.json"


def _pull_scope(client: PanRestClient, resource: str, scope: str) -> List[Dict[str, Any]]:
    try:
        if scope == "shared":
            return client.entries(resource, location="shared")
        return client.entries(resource, device_group=scope)
    except PanRestError as exc:
        text = str(exc).lower()
        if exc.status_code == 404 or "not present" in text or "non exist" in text:
            return []
        raise


def _pull_scope_rules(client: PanRestClient, scope: str, rulebase: str) -> List[Dict[str, Any]]:
    return _pull_scope(client, f"Policies/Security{rulebase.capitalize()}Rules", scope)


def pull_snapshot() -> Dict[str, Any]:
    client = fresh_client()
    dgs = client.list_device_groups()
    shared_addresses = client.list_addresses(location="shared")
    shared_groups = client.list_address_groups(location="shared")
    shared_services = _pull_scope(client, "Objects/Services", "shared")
    shared_svc_groups = _pull_scope(client, "Objects/ServiceGroups", "shared")

    scopes: List[Dict[str, Any]] = [{
        "scope": "shared",
        "addresses": shared_addresses, "groups": shared_groups,
        "services": shared_services, "service_groups": shared_svc_groups,
        "rules": {rb: _pull_scope_rules(client, "shared", rb) for rb in ("pre", "post")},
    }]
    for dg in dgs:
        scopes.append({
            "scope": dg,
            "addresses": client.list_addresses(device_group=dg) + shared_addresses,
            "groups": client.list_address_groups(device_group=dg) + shared_groups,
            "services": _pull_scope(client, "Objects/Services", dg) + shared_services,
            "service_groups": (_pull_scope(client, "Objects/ServiceGroups", dg)
                               + shared_svc_groups),
            "rules": {rb: _pull_scope_rules(client, dg, rb) for rb in ("pre", "post")},
        })

    snap = {
        "meta": {"pulled_at": datetime.now(timezone.utc).isoformat(),
                 "target": client.env.url, "username": client.username,
                 "device_groups": dgs},
        "scopes": scopes,
    }
    SNAPSHOT.clear()
    SNAPSHOT.update(snap)
    f = snapshot_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(snap, indent=2) + "\n", encoding="utf-8")
    log.info("Snapshot pulled: %d device groups (saved %s)", len(dgs), f)
    return snapshot_status()


def load_persisted_snapshot() -> None:
    f = snapshot_file()
    if f.exists():
        try:
            SNAPSHOT.update(json.loads(f.read_text(encoding="utf-8")))
            log.info("Loaded persisted snapshot from %s (pulled_at %s)",
                     f, SNAPSHOT["meta"]["pulled_at"])
        except (ValueError, KeyError):
            log.warning("Ignoring unreadable snapshot file %s", f)


def snapshot_status() -> Dict[str, Any]:
    if not SNAPSHOT:
        return {"present": False}
    return {"present": True, **SNAPSHOT["meta"],
            "rule_counts": {s["scope"]: {rb: len(s["rules"][rb]) for rb in ("pre", "post")}
                            for s in SNAPSHOT["scopes"]}}


def _parse_service_filter(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    proto = (payload.get("service_proto") or "").strip().lower() or None
    ports_text = (payload.get("service_ports") or "").strip()
    if proto and proto not in ("tcp", "udp"):
        raise ValueError(f"Service protocol must be tcp or udp, got {proto!r}")
    if not ports_text:
        if proto:
            raise ValueError("A protocol was chosen but no ports were given.")
        return None
    ports = []
    for token in ports_text.split(","):
        token = token.strip()
        if not token:
            continue
        if not token.isdigit() or not (0 < int(token) < 65536):
            raise ValueError(f"Ports must be 1-65535, comma separated; got {token!r}")
        ports.append(int(token))
    if not ports:
        return None
    return {"proto": proto, "ports": ports}


def run_search(payload: Dict[str, Any], plus: bool = False) -> Dict[str, Any]:
    if not SNAPSHOT:
        raise ValueError("No configuration snapshot yet. Pull the config first.")
    service_filter = _parse_service_filter(payload)
    if service_filter and SNAPSHOT["scopes"] and "services" not in SNAPSHOT["scopes"][0]:
        raise ValueError("This snapshot predates service filtering (no services); "
                         "pull the config again.")

    targets_text = payload.get("targets", "")
    exclusions_text = payload.get("exclusions", "")
    use_repo_exclusions = bool(payload.get("use_repo_exclusions", True))

    targets, invalid = parse_ip_lines(targets_text)
    exclusions, invalid_excl = parse_ip_lines(exclusions_text)
    if use_repo_exclusions and REPO_EXCLUDE_FILE.exists():
        repo_excl, repo_invalid = parse_ip_lines(REPO_EXCLUDE_FILE.read_text(encoding="utf-8"))
        exclusions += repo_excl
        invalid_excl += repo_invalid
    invalid += [f"(exclusions) {x}" for x in invalid_excl]
    if not targets:
        raise ValueError("No valid targets given (IPs, subnets, or ranges, one per line).")

    all_dgs = SNAPSHOT["meta"]["device_groups"]
    wanted = [d.strip() for d in (payload.get("device_groups") or "").split(",") if d.strip()]
    unknown = sorted(set(wanted) - set(all_dgs))
    if unknown:
        raise ValueError(f"Unknown device groups: {unknown} (available: {all_dgs})")
    keep = set(wanted or all_dgs) | ({"shared"} if payload.get("include_shared", True) else set())

    scope_results: List[Dict[str, Any]] = []
    for s in SNAPSHOT["scopes"]:
        if s["scope"] not in keep:
            continue
        for rulebase in ("pre", "post"):
            scope_results.append(match_rules(s["rules"][rulebase], s["addresses"],
                                             s["groups"], targets,
                                             scope=s["scope"], rulebase=rulebase,
                                             match_exclusions=exclusions,
                                             service_filter=service_filter,
                                             services=s.get("services", []),
                                             service_groups=s.get("service_groups", [])))

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    result = {
        "run_id": run_id,
        "meta": {
            "ran_at": datetime.now(timezone.utc).isoformat(),
            "target": SNAPSHOT["meta"]["target"],
            "username": SNAPSHOT["meta"]["username"],
            "snapshot_pulled_at": SNAPSHOT["meta"]["pulled_at"],
            "device_groups": sorted(keep - {"shared"}),
            "read_only": True,
            "firewalls_contacted": False,
        },
        "inputs": {"targets": targets_text, "exclusions": exclusions_text,
                   "use_repo_exclusions": use_repo_exclusions,
                   "repo_exclude_file": str(REPO_EXCLUDE_FILE) if use_repo_exclusions else None,
                   "device_groups": payload.get("device_groups") or "",
                   "service_proto": payload.get("service_proto") or "",
                   "service_ports": payload.get("service_ports") or ""},
        "service_filter": service_filter,
        "totals": {
            "targets_searched": len(targets),
            "rules_matched": sum(len(sr["matched_rules"]) for sr in scope_results),
            "any_any_rules": sum(len(sr["any_any_rules"]) for sr in scope_results),
            "matches_suppressed": sum(len(sr["suppressed"]) for sr in scope_results),
        },
        "targets": [t["raw"] for t in targets],
        "invalid_lines": invalid,
        "scopes": scope_results,
    }
    run_dir = search_runs_dir(plus)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / f"{run_id}.json").write_text(json.dumps(result, indent=2) + "\n",
                                            encoding="utf-8")
    log.info("Search%s %s: %d targets, %d matches against snapshot %s",
             "+" if plus else "", run_id, len(targets),
             result["totals"]["rules_matched"], SNAPSHOT["meta"]["pulled_at"])
    return result


def search_runs_dir(plus: bool = False) -> Path:
    name = "web_rule_search_plus" if plus else "web_ip_search"
    return REPO_ROOT / "pan_reports" / CONFIG["display_host"].split(".")[0] / name


def list_search_runs(plus: bool = False) -> List[Dict[str, Any]]:
    d = search_runs_dir(plus)
    if not d.exists():
        return []
    out = []
    for f in sorted(d.glob("*.json"), reverse=True)[:50]:
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
            out.append({"run_id": r["run_id"], "ran_at": r["meta"]["ran_at"],
                        "totals": r["totals"], "targets": r["targets"][:8],
                        "service": ((r.get("inputs", {}).get("service_proto") or "")
                                    + " " + (r.get("inputs", {}).get("service_ports") or "")).strip()})
        except (ValueError, KeyError):
            continue
    return out


def load_search_run(run_id: str, plus: bool = False) -> Dict[str, Any] | None:
    if not RUN_ID_RE.match(run_id):
        return None
    f = search_runs_dir(plus) / f"{run_id}.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None


# =============================================================================
# Group remap (see /group-remap)
# =============================================================================

def list_csvs() -> List[Dict[str, Any]]:
    out = []
    for f in sorted(DATA_DIR.glob("*.csv")):
        try:
            rows = len(read_csv_mappings(f))
        except Exception:
            rows = None
        out.append({"name": f.name, "rows": rows})
    return out


def _flatten_already_remapped(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Walk scopes + rule_scopes in report.json and pull the already_remapped
    entries into the same shape as `updates` (one row per group/rule side).
    Returns [{scope, type, name, side, items}]. `items` is a printable
    'member -> mapped_member (for value)' summary."""
    out: List[Dict[str, Any]] = []
    # Groups: per-scope, per-group. No `side` on group already_remapped.
    for s in report.get("scopes") or []:
        scope = s.get("scope") or ""
        for g in s.get("groups") or []:
            items = g.get("already_remapped") or []
            if not items:
                continue
            summary = "; ".join(
                f"{i.get('mapped_member')} (for {i.get('value')})" for i in items
            )
            out.append({
                "scope": scope, "type": "group",
                "name": g.get("name") or "", "side": "",
                "items": summary,
            })
    # Rules: per-scope+rulebase, per-rule, split by side.
    for rs in report.get("rule_scopes") or []:
        scope = rs.get("scope") or ""
        rulebase = rs.get("rulebase") or ""
        for r in rs.get("rules") or []:
            by_side: Dict[str, List[str]] = {}
            for i in r.get("already_remapped") or []:
                side = (i.get("side") or "").lower()
                if side not in ("source", "destination"):
                    continue
                by_side.setdefault(side, []).append(
                    f"{i.get('mapped_member')} (for {i.get('value')})"
                )
            for side, entries in by_side.items():
                out.append({
                    "scope": scope, "type": f"{rulebase}-rule",
                    "name": r.get("name") or "", "side": side,
                    "items": "; ".join(entries),
                })
    return out


def condense_remap(report: Dict[str, Any], run_ts: str) -> Dict[str, Any]:
    """report.json -> the view the page renders."""
    agg = report["actions"]
    return {
        "run_ts": run_ts,
        "meta": report["meta"],
        "totals": report["totals"],
        "object_actions": [{
            "member": a["member"], "location": a["location"],
            "value": a["value"], "mapped_value": a["mapped_value"],
            "action": (f"reuse {a['existing_object']}" if a["existing_object"]
                       else f"create {a['suggested_name']}"),
            "refs": summarize_refs(a["refs"]),
            "refs_count": len(a["refs"]),
            "refs_groups": sum(1 for r in a["refs"] if r.get("kind") == "group"),
            "refs_rules": sum(1 for r in a["refs"] if r.get("kind") == "rule"),
        } for a in agg["object_actions"]],
        "updates": [{
            "scope": u["scope"],
            "type": "group" if u["kind"] == "group" else f"{u['rulebase']}-rule",
            "name": u["name"], "side": u["side"] or "",
            "adds": "; ".join(f"{a['add']} (for {a['for']})" for a in u["adds"]),
            # Distinct add-item kinds present in this update row. "literal"
            # means the rule has a bare IP/CIDR/range that maps; "object"
            # means the rule/group directly references a named address object
            # whose value maps. Group updates are always "object" (groups can
            # only hold members, never literals).
            "kinds": sorted({
                "literal" if str(a.get("for", "")).startswith("literal ") else "object"
                for a in u["adds"]
            }),
        } for u in report["updates"]],
        "already": _flatten_already_remapped(report),
        "coverage": report["csv_coverage"],
    }


def run_remap(payload: Dict[str, Any]) -> Dict[str, Any]:
    csv_name = (payload.get("csv") or "").strip()
    csv_path = (DATA_DIR / csv_name).resolve()
    if csv_path.parent != DATA_DIR.resolve() or not csv_path.exists():
        raise ValueError(f"CSV must be a file in data/ (got {csv_name!r}).")
    maps = read_csv_mappings(csv_path)

    client = fresh_client()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    host_short = client.env.hostname.split(".")[0]
    capture_dir = REPO_ROOT / "pan_capture" / host_short / ts
    reports_dir = REPO_ROOT / "pan_reports" / host_short / ts / "group_remap_dryrun"
    report = REMAP.run_report(client, maps, csv_path=csv_path, capture_dir=capture_dir,
                              reports_dir=reports_dir,
                              device_groups=payload.get("device_groups") or None)
    log.info("Remap dry run %s: %s", ts, report["totals"])
    return condense_remap(report, ts)


def list_remap_runs() -> List[Dict[str, Any]]:
    base = REPO_ROOT / "pan_reports" / CONFIG["display_host"].split(".")[0]
    if not base.exists():
        return []
    out = []
    for d in sorted(base.iterdir(), reverse=True):
        f = d / "group_remap_dryrun" / "report.json"
        if not (RUN_ID_RE.match(d.name) and f.exists()):
            continue
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
            out.append({"run_ts": d.name, "ran_at": r["meta"]["ran_at"],
                        "csv": Path(r["meta"]["csv"]).name, "totals": r["totals"]})
        except (ValueError, KeyError):
            continue
        if len(out) >= 30:
            break
    return out


def load_remap_run(run_ts: str) -> Dict[str, Any] | None:
    if not RUN_ID_RE.match(run_ts):
        return None
    f = (REPO_ROOT / "pan_reports" / CONFIG["display_host"].split(".")[0]
         / run_ts / "group_remap_dryrun" / "report.json")
    if not f.exists():
        return None
    return condense_remap(json.loads(f.read_text(encoding="utf-8")), run_ts)


# =============================================================================
# Flow match (see /flow-search): evaluate a flow against the rule chains
# =============================================================================

def run_flow(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not SNAPSHOT:
        raise ValueError("No configuration snapshot yet. Pull the config first.")
    if SNAPSHOT["scopes"] and "services" not in SNAPSHOT["scopes"][0]:
        raise ValueError("This snapshot predates flow search (no services); "
                         "pull the config again.")

    src = (payload.get("src") or "").strip() or None
    dst = (payload.get("dst") or "").strip() or None
    if not src and not dst:
        raise ValueError("Fill in at least one of source and destination IP.")
    port_spec = parse_port_spec(payload.get("port") or "")

    scope_by_name = {s["scope"]: s for s in SNAPSHOT["scopes"]}
    shared = scope_by_name.get("shared")
    dgs = SNAPSHOT["meta"]["device_groups"]

    per_dg: List[Dict[str, Any]] = []
    for dg in dgs:
        s = scope_by_name.get(dg)
        if s is None:
            continue
        chain = []
        if shared:
            chain += [{"scope": "shared", "rulebase": "pre", "rule": r}
                      for r in shared["rules"]["pre"]]
        chain += [{"scope": dg, "rulebase": "pre", "rule": r} for r in s["rules"]["pre"]]
        chain += [{"scope": dg, "rulebase": "post", "rule": r} for r in s["rules"]["post"]]
        if shared:
            chain += [{"scope": "shared", "rulebase": "post", "rule": r}
                      for r in shared["rules"]["post"]]
        matches = match_flow(chain, s["addresses"], s["groups"],
                             s["services"], s["service_groups"],
                             src=src, dst=dst, port_spec=port_spec)
        per_dg.append({"dg": dg, "matches": matches,
                       "first_match": matches[0] if matches else None})

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = {"run_id": run_id, "src": src, "dst": dst,
           "port": payload.get("port") or "",
           "meta": {"ran_at": datetime.now(timezone.utc).isoformat(),
                    "snapshot_pulled_at": SNAPSHOT["meta"]["pulled_at"],
                    "target": SNAPSHOT["meta"]["target"]},
           "per_dg": per_dg}
    d = flow_runs_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{run_id}.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    log.info("Flow %s: %s -> %s port=%s : first matches %s", run_id, src, dst,
             payload.get("port") or "-",
             {p["dg"]: (p["first_match"] or {}).get("rule") for p in per_dg})
    return out


def flow_runs_dir() -> Path:
    return REPO_ROOT / "pan_reports" / CONFIG["display_host"].split(".")[0] / "web_flow_search"


def list_flow_runs() -> List[Dict[str, Any]]:
    d = flow_runs_dir()
    if not d.exists():
        return []
    out = []
    for f in sorted(d.glob("*.json"), reverse=True)[:50]:
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
            out.append({"run_id": r["run_id"], "ran_at": r["meta"]["ran_at"],
                        "src": r["src"], "dst": r["dst"], "port": r["port"],
                        "first": {p["dg"]: (p["first_match"] or {}).get("rule")
                                  for p in r["per_dg"]}})
        except (ValueError, KeyError):
            continue
    return out


def load_flow_run(run_id: str) -> Dict[str, Any] | None:
    if not RUN_ID_RE.match(run_id):
        return None
    f = flow_runs_dir() / f"{run_id}.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None


# =============================================================================
# Rule placement (see /rule-placement): routing tables via Panorama proxy
# =============================================================================

TOPOLOGY: Dict[str, Any] = {}


def topology_file() -> Path:
    return REPO_ROOT / "pan_capture" / CONFIG["display_host"].split(".")[0] / "web_topology.json"


def _admin_session():
    """Admin XML API session (op commands are denied to the agent account).
    Uses PANORAMA_API_KEY when stored, else keygen from the admin
    username/password in .env."""
    env = resolve_panorama_env()
    s = requests.Session()
    s.verify = env.verify
    key = env.api_key
    if not key:
        r = s.get(f"{env.url}/api/",
                  params={"type": "keygen", "user": env.username, "password": env.password},
                  timeout=60)
        key = ET.fromstring(r.text).findtext("./result/key")
        if not key:
            raise PanRestError("Admin keygen failed (needed for routing-table ops).")
    return s, env.url, key


def _admin_op(s, url: str, key: str, cmd: str, target: str | None = None) -> ET.Element:
    params = {"type": "op", "cmd": cmd, "key": key}
    if target:
        params["target"] = target
    r = s.get(f"{url}/api/", params=params, timeout=90)
    root = ET.fromstring(r.text)
    if root.get("status") != "success":
        msg = "; ".join(l.text for l in root.iter("line") if l.text) or r.text[:200]
        raise PanRestError(f"op failed{' on ' + target if target else ''}: {msg}",
                           status_code=r.status_code)
    return root


def pull_topology() -> Dict[str, Any]:
    """DG -> firewall routing tables: DG membership via REST (agent account),
    `show routing route` per connected firewall via Panorama proxy (admin)."""
    client = fresh_client()
    dg_serials: Dict[str, List[str]] = {}
    for e in client.entries("Panorama/DeviceGroups"):
        devs = e.get("devices", {}).get("entry", [])
        devs = [devs] if isinstance(devs, dict) else devs
        dg_serials[e["@name"]] = [d.get("@name") for d in devs if d.get("@name")]

    s, url, key = _admin_session()
    root = _admin_op(s, url, key, "<show><devices><connected></connected></devices></show>")
    dev_info: Dict[str, Dict[str, str]] = {}
    for e in root.findall(".//devices/entry"):
        serial = e.findtext("serial")
        if serial:
            dev_info[serial] = {"hostname": e.findtext("hostname") or serial,
                                "connected": e.findtext("connected") or "?"}

    tables: Dict[str, Any] = {}
    warnings: List[str] = []
    for dg, serials in sorted(dg_serials.items()):
        if not serials:
            warnings.append(f"{dg}: no devices in the device group")
            continue
        for serial in serials:
            info = dev_info.get(serial)
            hostname = info["hostname"] if info else serial
            if not info:
                warnings.append(f"{dg}: device {serial} not connected; no routing table")
                continue
            try:
                r = _admin_op(s, url, key,
                              "<show><routing><route></route></routing></show>", serial)
            except PanRestError as exc:
                warnings.append(f"{dg}/{hostname}: routing pull failed: {exc}")
                continue
            entries = [{c.tag: (c.text or "") for c in e}
                       for e in r.findall(".//result/entry")]
            routes = parse_routes(entries)
            tables[dg] = {"device": hostname, "serial": serial, "routes": routes}
            log.info("topology %s/%s: %d routes", dg, hostname, len(routes))

    topo = {"meta": {"pulled_at": datetime.now(timezone.utc).isoformat(),
                     "target": CONFIG["display_target"]},
            "tables": tables, "warnings": warnings}
    TOPOLOGY.clear()
    TOPOLOGY.update(topo)
    f = topology_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(topo, indent=2) + "\n", encoding="utf-8")
    return topology_status()


def load_persisted_topology() -> None:
    f = topology_file()
    if f.exists():
        try:
            TOPOLOGY.update(json.loads(f.read_text(encoding="utf-8")))
            log.info("Loaded persisted topology from %s (pulled_at %s)",
                     f, TOPOLOGY["meta"]["pulled_at"])
        except (ValueError, KeyError):
            log.warning("Ignoring unreadable topology file %s", f)


def topology_status() -> Dict[str, Any]:
    if not TOPOLOGY:
        return {"present": False}
    return {"present": True, "pulled_at": TOPOLOGY["meta"]["pulled_at"],
            "warnings": TOPOLOGY.get("warnings", []),
            "tables": {dg: {"device": t["device"], "routes": len(t["routes"])}
                       for dg, t in TOPOLOGY.get("tables", {}).items()}}


def run_placement(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not TOPOLOGY or not TOPOLOGY.get("tables"):
        raise ValueError("No routing topology yet. Pull routing tables first.")
    src = (payload.get("src") or "").strip()
    dst = (payload.get("dst") or "").strip()
    try:
        result = recommend_placement(src, dst, TOPOLOGY["tables"])
    except PanPlacementError as exc:
        raise ValueError(str(exc)) from exc
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = {"run_id": run_id, "src": src, "dst": dst,
           "meta": {"ran_at": datetime.now(timezone.utc).isoformat(),
                    "topology_pulled_at": TOPOLOGY["meta"]["pulled_at"],
                    "target": TOPOLOGY["meta"]["target"]},
           **result}
    d = placement_runs_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{run_id}.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    log.info("Placement %s: %s -> %s = %s", run_id, src, dst,
             [r["dg"] for r in out["recommended"]] or "none")
    return out


def placement_runs_dir() -> Path:
    return REPO_ROOT / "pan_reports" / CONFIG["display_host"].split(".")[0] / "web_rule_placement"


def list_placement_runs() -> List[Dict[str, Any]]:
    d = placement_runs_dir()
    if not d.exists():
        return []
    out = []
    for f in sorted(d.glob("*.json"), reverse=True)[:50]:
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
            out.append({"run_id": r["run_id"], "ran_at": r["meta"]["ran_at"],
                        "src": r["src"], "dst": r["dst"],
                        "recommended": [x["dg"] for x in r["recommended"]]})
        except (ValueError, KeyError):
            continue
    return out


def load_placement_run(run_id: str) -> Dict[str, Any] | None:
    if not RUN_ID_RE.match(run_id):
        return None
    f = placement_runs_dir() / f"{run_id}.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None


# =============================================================================
# Run deletion (per-report delete buttons and clear-all)
# =============================================================================

def delete_runs(kind: str, run_id: str | None) -> Dict[str, Any]:
    """Delete one saved run (run_id given) or all of them (run_id None) for
    one tool's history. Only removes files this toolkit's naming scheme
    owns, under pan_reports/<host>/."""
    import shutil
    host = CONFIG["display_host"].split(".")[0]
    deleted = 0
    if kind in ("search", "searchplus", "placement", "flow"):
        d = {"search": search_runs_dir,
             "searchplus": lambda: search_runs_dir(True),
             "placement": placement_runs_dir,
             "flow": flow_runs_dir}[kind]()
        files = ([d / f"{run_id}.json"] if run_id else list(d.glob("*.json"))) if d.exists() else []
        for f in files:
            if RUN_ID_RE.match(f.stem) and f.exists():
                f.unlink()
                deleted += 1
    elif kind == "remap":
        base = REPO_ROOT / "pan_reports" / host
        dirs = ([base / run_id] if run_id else
                [p for p in base.iterdir() if RUN_ID_RE.match(p.name)]) if base.exists() else []
        for p in dirs:
            report_dir = p / "group_remap_dryrun"
            if RUN_ID_RE.match(p.name) and report_dir.exists():
                shutil.rmtree(report_dir)
                deleted += 1
                if not any(p.iterdir()):
                    p.rmdir()
    else:
        raise ValueError(f"Unknown history kind {kind!r}")
    log.info("Deleted %d %s run(s)%s", deleted, kind, f" ({run_id})" if run_id else " (all)")
    return {"deleted": deleted}


# =============================================================================
# Pages
# =============================================================================

SHELL_CSS = """
:root { color-scheme: light dark;
  --bg:#f6f7f9; --panel:#ffffff; --ink:#1a2330; --muted:#5b6878;
  --line:#dde3ea; --accent:#0e7490; --accent-ink:#ffffff; --bad:#b4232a; }
@media (prefers-color-scheme: dark) { :root {
  --bg:#12161c; --panel:#1a2029; --ink:#e6ebf2; --muted:#8fa0b3;
  --line:#2a3442; --accent:#22a3bf; --accent-ink:#0b1015; --bad:#ef6a70; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
  font:14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; }
header { padding:12px 22px; border-bottom:1px solid var(--line);
  display:flex; align-items:baseline; gap:18px; flex-wrap:wrap; }
header h1 { font-size:17px; margin:0; }
header h1 a { color:inherit; text-decoration:none; }
header nav a { color:var(--accent); text-decoration:none; margin-right:14px;
  font-size:13px; font-weight:600; }
header nav a.here { color:var(--muted); }
header .sub { color:var(--muted); font-size:12.5px; margin-left:auto; }
.panel { background:var(--panel); border:1px solid var(--line);
  border-radius:8px; padding:14px; }
label { display:block; font-weight:600; margin:10px 0 4px; font-size:13px; }
label:first-child { margin-top:0; }
textarea, input[type=text], select { width:100%; background:var(--bg); color:var(--ink);
  border:1px solid var(--line); border-radius:6px; padding:8px;
  font:12.5px/1.5 ui-monospace, Menlo, monospace; }
textarea { resize:vertical; }
.hint { color:var(--muted); font-size:12px; margin:2px 0 0; }
.row { display:flex; align-items:center; gap:8px; margin-top:10px; font-size:13px; }
button { margin-top:14px; width:100%; padding:9px; border:0; border-radius:6px;
  background:var(--accent); color:var(--accent-ink); font-weight:700;
  font-size:14px; cursor:pointer; }
button:disabled { opacity:.5; cursor:not-allowed; }
button.secondary { background:transparent; color:var(--accent);
  border:1.5px solid var(--accent); }
.snap { margin-top:8px; font-size:12px; color:var(--muted);
  border-left:3px solid var(--line); padding-left:8px; }
.snap.ok { border-left-color:var(--accent); }
.err { color:var(--bad); font-size:13px; margin-top:10px; white-space:pre-wrap; }
.chips { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px; }
.chip { background:var(--panel); border:1px solid var(--line); border-radius:8px;
  padding:8px 14px; }
.chip b { font-size:19px; display:block; }
.chip span { color:var(--muted); font-size:12px; }
h2 { font-size:14px; margin:20px 0 8px; }
table { border-collapse:collapse; width:100%; background:var(--panel);
  border:1px solid var(--line); border-radius:8px; overflow:hidden; font-size:12.5px; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); }
th { background:color-mix(in srgb, var(--panel) 60%, var(--bg)); font-size:12px; }
tr:last-child td { border-bottom:0; }
td code, li code { font:12px ui-monospace, Menlo, monospace; }
.flag { color:var(--bad); font-weight:600; }
.none { color:var(--muted); font-style:italic; }
.tblwrap { overflow-x:auto; }
.runs { list-style:none; margin:6px 0 0; padding:0; }
.runs li { padding:7px 26px 7px 8px; border:1px solid var(--line); border-radius:6px;
  margin-bottom:6px; cursor:pointer; font-size:12.5px; position:relative; }
.runs li:hover { border-color:var(--accent); }
.runs .when { color:var(--muted); font-size:11.5px; }
.runs .del { position:absolute; top:5px; right:5px; color:var(--muted);
  font:700 13px/1 sans-serif; padding:2px 6px; border-radius:4px; }
.runs .del:hover { color:var(--accent-ink); background:var(--bad); }
.clearlink { float:right; color:var(--bad); font-size:11px;
  text-decoration:none; font-weight:600; }
.reco { border:1.5px solid var(--accent); border-radius:8px; padding:10px 14px;
  margin-bottom:10px; background:var(--panel); }
.reco b { font-size:15px; }
.reco ul { margin:6px 0 0; padding-left:18px; }
.readonly { font-size:11.5px; color:var(--muted); margin-top:12px; }
.layout { display:grid; grid-template-columns:300px 1fr; gap:18px;
  padding:18px 22px; max-width:1500px; }
@media (max-width: 900px){ .layout { grid-template-columns:1fr; } }
"""

HELPERS_JS = """
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"]/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function table(headers, rows) {
  if (!rows.length) return '<p class="none">(none)</p>';
  return '<div class="tblwrap"><table><tr>' +
    headers.map(h => `<th>${esc(h)}</th>`).join("") + "</tr>" +
    rows.map(r => "<tr>" + r.map(c => `<td>${c}</td>`).join("") + "</tr>").join("") +
    "</table></div>";
}
function wireHistory(kind, refresh) {
  for (const del of $("runs").querySelectorAll(".del"))
    del.onclick = async ev => {
      ev.stopPropagation();
      await fetch("/api/runs/delete", {method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({kind, id: del.dataset.del})});
      refresh();
    };
  const clear = $("clear-runs");
  if (clear) clear.onclick = async ev => {
    ev.preventDefault();
    if (!confirm("Delete ALL saved runs for this tool?")) return;
    await fetch("/api/runs/delete", {method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({kind})});
    refresh();
  };
}
"""


def shell(title: str, here: str, body: str, script: str) -> str:
    nav = "".join(
        f'<a href="{path}"{" class=here" if here == path else ""}>{name}</a>'
        for path, name in (("/", "SSDD Toolkit"), ("/ip-search", "IP Rule Search"),
                           ("/rule-search", "Rule Search+"),
                           ("/group-remap", "Group Remap"),
                           ("/remap-pivot", "Remap Pivot"),
                           ("/flow-search", "Flow Match"),
                           ("/rule-placement", "Rule Placement")))
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>{SHELL_CSS}</style></head>
<body>
<header><h1><a href="/">SSDD Toolkit</a></h1><nav>{nav}</nav>
<span class="sub" id="server-info"></span></header>
{body}
<script>{HELPERS_JS}
fetch("/api/info").then(r => r.json()).then(i => {{
  const el = $("server-info");
  if (el) el.textContent = `${{i.target}} as ${{i.username_source}} (read-only)`;
  if (window.onInfo) window.onInfo(i); }});
{script}</script>
</body></html>"""


HUB_BODY = """
<div class="layout" style="grid-template-columns:1fr 1fr; max-width:1000px;">
  <a class="panel" href="/ip-search" style="text-decoration:none;color:inherit">
    <h2 style="margin-top:0">IP Rule Search</h2>
    <p class="hint">Pull a Panorama config snapshot, then search IPs, subnets,
      and ranges against every rulebase (shared + device-group pre/post).
      Exclusion lists, run history, instant re-search against the snapshot.</p>
  </a>
  <a class="panel" href="/group-remap" style="text-decoration:none;color:inherit">
    <h2 style="margin-top:0">Group Remap Dry Run</h2>
    <p class="hint">Run a subnet-remap CSV against address groups and rules;
      see the deduplicated object actions and exactly what gets added where.
      Report-only: nothing is ever pushed.</p>
  </a>
  <a class="panel" href="/remap-pivot" style="text-decoration:none;color:inherit">
    <h2 style="margin-top:0">Remap Pivot (Source vs Destination)</h2>
    <p class="hint">Same CSV remap dry run, presented one row per group/rule
      with Source (adds) and Destination (adds) as parallel columns. Easier
      to scan when a single rule gets adds on both sides.</p>
  </a>
  <a class="panel" href="/rule-search" style="text-decoration:none;color:inherit">
    <h2 style="margin-top:0">Rule Search+</h2>
    <p class="hint">IP Rule Search with full rule context: every match also
      shows the rule's configured source, destination, and service, and an
      optional service filter (tcp/udp + comma-delimited ports) narrows
      results to rules covering those ports.</p>
  </a>
  <a class="panel" href="/flow-search" style="text-decoration:none;color:inherit">
    <h2 style="margin-top:0">Flow Match</h2>
    <p class="hint">Source and/or destination IP plus an optional port, checked
      against each device group's full evaluation chain (shared pre, DG pre,
      DG post, shared post). Shows every matching rule and highlights the one
      that would actually apply.</p>
  </a>
  <a class="panel" href="/rule-placement" style="text-decoration:none;color:inherit">
    <h2 style="margin-top:0">Rule Placement</h2>
    <p class="hint">Source IP + destination IP in, the most likely device
      group(s) for a new rule out. Anchored on the firewalls' routing tables:
      the boxes that most specifically own each endpoint, not every possible
      location.</p>
  </a>
</div>
<p class="hint" style="padding:0 22px">Read-only against Panorama; firewalls
are never contacted. Runs are saved under pan_reports/ alongside the CLI
tools' output.</p>
"""

IP_SEARCH_BODY = """
<div class="layout">
  <div>
    <div class="panel">
      <label for="targets">Search targets</label>
      <textarea id="targets" rows="7" placeholder="10.1.1.5&#10;10.2.1.0/24&#10;10.1.1.5-10.1.1.20"></textarea>
      <p class="hint">IPs, subnets (CIDR), or ranges. One per line, # comments OK.</p>
      <label for="exclusions">Match exclusions (optional)</label>
      <textarea id="exclusions" rows="3" placeholder="10.0.0.0/8">10.0.0.0/8</textarea>
      <p class="hint">Suppresses MATCHES whose matching value is equal to or
        broader than an entry (e.g. rules matching only via a 10.0.0.0/8
        aggregate). Targets are never excluded.</p>
      <div class="row">
        <input type="checkbox" id="repo-excl" checked>
        <label for="repo-excl" style="margin:0;font-weight:400">also apply pan_ip_rule_exclude.txt</label>
      </div>
      <label for="dgs">Device groups (optional)</label>
      <input type="text" id="dgs" placeholder="all (or: dg-4,dg-5)">
      <button id="pull" class="secondary">Pull fresh config</button>
      <div class="snap" id="snap-status">No config snapshot yet. Pull first.</div>
      <button id="go" disabled>Search snapshot</button>
      <div class="err" id="error"></div>
      <div class="readonly">Read-only. Pull = fresh keygen + REST pull into a
        local snapshot; Search = matches the snapshot, no network.
        Firewalls are never contacted. Runs saved under pan_reports/.</div>
    </div>
    <div class="panel" style="margin-top:14px">
      <label style="margin-top:0">Previous runs
        <a href="#" id="clear-runs" class="clearlink">clear all</a></label>
      <ul id="runs" class="runs"></ul>
    </div>
  </div>
  <div id="results"><p class="none">No search yet.</p></div>
</div>
"""

IP_SEARCH_JS = """
function render(r) {
  const t = r.totals;
  const matchRows = [], anyRows = [];
  for (const sr of r.scopes) {
    for (const rule of sr.matched_rules) {
      const flags = [rule.disabled ? "DISABLED" : "",
                     rule.any_sides.length ? "any on " + rule.any_sides.join("/") : ""]
                    .filter(Boolean).join(", ");
      for (const m of rule.matches) {
        const via = m.via ? ` <span class="none">via group ${esc(m.via)}</span>` : "";
        matchRows.push([esc(sr.scope), esc(sr.rulebase), esc(rule.rule),
          esc(rule.action || ""), `<span class="flag">${esc(flags)}</span>`,
          `<code>${esc(m.target)}</code>`, esc(m.side),
          `${esc(m.member)} = <code>${esc(m.value)}</code>${via}`]);
      }
    }
    for (const name of sr.any_any_rules)
      anyRows.push([esc(sr.scope), esc(sr.rulebase), esc(name)]);
  }
  const matched = new Set();
  for (const sr of r.scopes) for (const rule of sr.matched_rules)
    for (const m of rule.matches) matched.add(m.target);
  const noMatch = r.targets.filter(x => !matched.has(x)).map(x => [`<code>${esc(x)}</code>`]);
  const suppRows = [];
  for (const sr of r.scopes)
    for (const s of (sr.suppressed || []))
      suppRows.push([esc(sr.scope), esc(sr.rulebase), esc(s.rule), `<code>${esc(s.target)}</code>`,
        esc(s.side), `${esc(s.member)} = <code>${esc(s.value)}</code>` +
          (s.via ? ` <span class="none">via group ${esc(s.via)}</span>` : ""),
        `<code>${esc(s.excluded_by)}</code>`]);
  const invRows = r.invalid_lines.map(x => [`<code>${esc(x)}</code>`]);

  $("results").innerHTML = `
    <div class="chips">
      <div class="chip"><b>${t.targets_searched}</b><span>targets searched</span></div>
      <div class="chip"><b>${t.rules_matched}</b><span>rule matches</span></div>
      <div class="chip"><b>${t.any_any_rules}</b><span>any/any rules</span></div>
      <div class="chip"><b>${t.matches_suppressed ?? 0}</b><span>matches suppressed</span></div>
    </div>
    <p class="hint">Run ${esc(r.run_id)} at ${esc(r.meta.ran_at)} against
      ${esc(r.meta.target)} as ${esc(r.meta.username)}
      (snapshot pulled ${esc(r.meta.snapshot_pulled_at || "n/a")})</p>
    <h2>Rules matching the targets</h2>
    ${table(["Scope","Rulebase","Rule","Action","Flags","Target","Side","Matched through"], matchRows)}
    <h2>Global any/any rules (match every IP)</h2>
    ${table(["Scope","Rulebase","Rule"], anyRows)}
    <h2>Targets with no matches</h2>${table(["Target"], noMatch)}
    <h2>Suppressed matches (value equal to or broader than an exclusion)</h2>
    ${table(["Scope","Rulebase","Rule","Target","Side","Matched through","Excluded by"], suppRows)}
    ${invRows.length ? "<h2>Invalid input lines</h2>" + table(["Line"], invRows) : ""}`;
}

function showSnapshot(s) {
  const el = $("snap-status");
  if (!s || !s.present) {
    el.className = "snap";
    el.textContent = "No config snapshot yet. Pull first.";
    $("go").disabled = true;
    return;
  }
  const rules = Object.values(s.rule_counts)
    .reduce((n, rc) => n + rc.pre + rc.post, 0);
  el.className = "snap ok";
  el.textContent = `Snapshot pulled ${s.pulled_at} : ` +
    `${s.device_groups.length} device groups, ${rules} rules.`;
  $("go").disabled = false;
}
window.onInfo = i => showSnapshot(i.snapshot);

async function refreshRuns() {
  const runs = await (await fetch("/api/runs")).json();
  $("runs").innerHTML = runs.length ? runs.map(r =>
    `<li data-id="${esc(r.run_id)}">
       <div><b>${r.totals.rules_matched}</b> matches, ${r.totals.targets_searched} targets
         ${r.totals.matches_suppressed ? `(${r.totals.matches_suppressed} suppressed)` : ""}</div>
       <div><code>${esc(r.targets.join(", "))}</code></div>
       <div class="when">${esc(r.ran_at)}</div>
       <span class="del" data-del="${esc(r.run_id)}" title="delete this run">&#215;</span></li>`).join("")
    : '<li class="none" style="cursor:default">none yet</li>';
  for (const li of $("runs").querySelectorAll("li[data-id]"))
    li.onclick = async () => {
      const run = await (await fetch("/api/run?id=" + li.dataset.id)).json();
      if (!run.error) { render(run); fillInputs(run.inputs); }
    };
  wireHistory("search", refreshRuns);
}

function fillInputs(i) {
  if (!i) return;
  $("targets").value = i.targets || "";
  $("exclusions").value = i.exclusions || "";
  $("repo-excl").checked = !!i.use_repo_exclusions;
  $("dgs").value = i.device_groups || "";
}

$("pull").onclick = async () => {
  $("error").textContent = "";
  $("pull").disabled = true;
  $("pull").textContent = "Pulling from Panorama...";
  try {
    const data = await (await fetch("/api/pull", {method: "POST"})).json();
    if (data.error) $("error").textContent = data.error;
    else showSnapshot(data);
  } catch (e) { $("error").textContent = String(e); }
  $("pull").disabled = false;
  $("pull").textContent = "Pull fresh config";
};

$("go").onclick = async () => {
  $("error").textContent = "";
  $("go").disabled = true;
  $("go").textContent = "Searching snapshot...";
  try {
    const resp = await fetch("/api/search", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        targets: $("targets").value,
        exclusions: $("exclusions").value,
        use_repo_exclusions: $("repo-excl").checked,
        device_groups: $("dgs").value,
      })});
    const data = await resp.json();
    if (data.error) $("error").textContent = data.error;
    else { render(data); refreshRuns(); }
  } catch (e) { $("error").textContent = String(e); }
  $("go").disabled = false;
  $("go").textContent = "Search snapshot";
};
refreshRuns();
"""

REMAP_BODY = """
<div class="layout">
  <div>
    <div class="panel">
      <label for="csv">Remap CSV (from data/)</label>
      <select id="csv"></select>
      <p class="hint">Format: old_subnet,new_subnet. Longest prefix wins.</p>
      <label for="dgs">Device groups (optional)</label>
      <input type="text" id="dgs" placeholder="all (or: dg-4,dg-5)">
      <button id="run">Run dry-run report (pulls fresh)</button>
      <div class="err" id="error"></div>
      <div class="readonly">Report-only: analyzes what an additive remap WOULD
        do; nothing is pushed. Pulls fresh config each run. report.md and
        report.json land in pan_reports/ exactly like the CLI tool.</div>
    </div>
    <div class="panel" style="margin-top:14px">
      <label style="margin-top:0">Previous reports
        <a href="#" id="clear-runs" class="clearlink">clear all</a></label>
      <ul id="runs" class="runs"></ul>
    </div>
  </div>
  <div id="results"><p class="none">No report yet.</p></div>
</div>
"""

REMAP_JS = """
function render(r) {
  const t = r.totals;
  $("results").innerHTML = `
    <div class="chips">
      <div class="chip"><b>${t.object_actions}</b><span>object actions</span></div>
      <div class="chip"><b>${t.targets_updated}</b><span>groups/rules updated</span></div>
      <div class="chip"><b>${t.ranges}</b><span>ranges (report-only)</span></div>
      <div class="chip"><b>${t.csv_rows_unmatched}</b><span>CSV rows unmatched</span></div>
    </div>
    <p class="hint">Run ${esc(r.run_ts)} at ${esc(r.meta.ran_at)} against
      ${esc(r.meta.target)} as ${esc(r.meta.username)},
      CSV ${esc(r.meta.csv)} (${esc(r.meta.csv_rows)} rows)</p>
    <h2>Object actions (deduplicated; each object once, at its owning location)</h2>
    ${table(["Object","Defined in","Current value","Mapped value","Action","Referenced by"],
      r.object_actions.map(a => [esc(a.member), esc(a.location),
        `<code>${esc(a.value)}</code>`, `<code>${esc(a.mapped_value)}</code>`,
        esc(a.action), esc(a.refs)]))}
    <h2>What gets added where (per group and per rule)</h2>
    ${table(["Scope","Type","Group / Rule","Side","Adds"],
      r.updates.map(u => [esc(u.scope), esc(u.type), esc(u.name), esc(u.side), esc(u.adds)]))}
    <h2>CSV coverage</h2>
    ${table(["old_subnet","new_subnet","matches","matched values"],
      r.coverage.map(c => [`<code>${esc(c.old_subnet)}</code>`,
        `<code>${esc(c.new_subnet)}</code>`, c.matches,
        c.values.slice(0, 6).map(v => `<code>${esc(v)}</code>`).join(", ") +
          (c.values.length > 6 ? " ..." : "")]))}
    <p class="hint">Full report (already remapped, ranges, never remapped,
      unresolved) is in pan_reports/.../group_remap_dryrun/report.md</p>`;
}

async function refreshRuns() {
  const runs = await (await fetch("/api/remap/runs")).json();
  $("runs").innerHTML = runs.length ? runs.map(r =>
    `<li data-id="${esc(r.run_ts)}">
       <div><b>${r.totals.object_actions}</b> object actions,
         ${r.totals.targets_updated} targets <code>${esc(r.csv)}</code></div>
       <div class="when">${esc(r.ran_at)}</div>
       <span class="del" data-del="${esc(r.run_ts)}" title="delete this report">&#215;</span></li>`).join("")
    : '<li class="none" style="cursor:default">none yet</li>';
  for (const li of $("runs").querySelectorAll("li[data-id]"))
    li.onclick = async () => {
      const run = await (await fetch("/api/remap/run?id=" + li.dataset.id)).json();
      if (!run.error) render(run);
    };
  wireHistory("remap", refreshRuns);
}

fetch("/api/remap/csvs").then(r => r.json()).then(csvs => {
  $("csv").innerHTML = csvs.map(c =>
    `<option value="${esc(c.name)}">${esc(c.name)}${c.rows != null ? ` (${c.rows} rows)` : ""}</option>`
  ).join("") || "<option value=''>no CSVs in data/</option>"; });

$("run").onclick = async () => {
  $("error").textContent = "";
  $("run").disabled = true;
  $("run").textContent = "Pulling and analyzing...";
  try {
    const resp = await fetch("/api/remap/run", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({csv: $("csv").value, device_groups: $("dgs").value})});
    const data = await resp.json();
    if (data.error) $("error").textContent = data.error;
    else { render(data); refreshRuns(); }
  } catch (e) { $("error").textContent = String(e); }
  $("run").disabled = false;
  $("run").textContent = "Run dry-run report (pulls fresh)";
};
refreshRuns();
"""


REMAP_PIVOT_BODY = """
<div class="layout">
  <div>
    <div class="panel">
      <label for="csv">Remap CSV (from data/)</label>
      <select id="csv"></select>
      <p class="hint">Same input, same analysis as /group-remap. Pivoted view.</p>
      <label for="dgs">Device groups (optional)</label>
      <input type="text" id="dgs" placeholder="all (or: dg-4,dg-5)">
      <button id="run">Run dry-run report (pulls fresh)</button>
      <div class="err" id="error"></div>
      <div class="readonly">Report-only. Rows share history with /group-remap;
        a run started here is browsable there and vice versa.</div>
    </div>
    <div class="panel" style="margin-top:14px">
      <label style="margin-top:0">Previous reports
        <a href="#" id="clear-runs" class="clearlink">clear all</a></label>
      <ul id="runs" class="runs"></ul>
    </div>
  </div>
  <div id="results"><p class="none">No report yet.</p></div>
</div>
"""

REMAP_PIVOT_JS = """
function render(r) {
  // Pivot both r.updates and r.already by (scope, type, name). Each
  // rule/group becomes one row with four side-columns; blank if empty.
  const map = new Map();
  function ensure(key, u) {
    if (!map.has(key)) {
      map.set(key, {scope: u.scope, type: u.type, name: u.name,
                    src_add: "", dst_add: "",
                    src_already: "", dst_already: "",
                    _kinds: new Set()});
    }
    return map.get(key);
  }
  for (const u of r.updates || []) {
    const key = `${u.scope}||${u.type}||${u.name}`;
    const row = ensure(key, u);
    const side = String(u.side || "").toLowerCase();
    if (side === "source" || side === "src") row.src_add = u.adds || "";
    else if (side === "destination" || side === "dst") row.dst_add = u.adds || "";
    // group-scope updates carry side="" (no source/dest split for groups):
    // put those into src_add so they don't disappear.
    else if (u.type === "group") row.src_add = u.adds || row.src_add;
    for (const k of (u.kinds || [])) row._kinds.add(k);
  }
  for (const u of r.already || []) {
    const key = `${u.scope}||${u.type}||${u.name}`;
    const row = ensure(key, u);
    const side = String(u.side || "").toLowerCase();
    if (side === "source" || side === "src") row.src_already = u.items || "";
    else if (side === "destination" || side === "dst") row.dst_already = u.items || "";
    else if (u.type === "group") row.src_already = u.items || row.src_already;
  }
  // Sort: scope, type, name for stable output
  const pivoted = Array.from(map.values()).sort((a, b) =>
    (a.scope + a.type + a.name).localeCompare(b.scope + b.type + b.name));

  // Partition: one Groups bucket (all scopes together), and one bucket per
  // scope for rules. Keep insertion order determined by sort below.
  const groupRows = pivoted.filter(p => p.type === "group");
  const ruleRows  = pivoted.filter(p => p.type !== "group");
  const scopeOrder = (s) => (s === "shared" ? 0 : 1);
  const rulesByScope = new Map();
  for (const r of ruleRows) {
    if (!rulesByScope.has(r.scope)) rulesByScope.set(r.scope, []);
    rulesByScope.get(r.scope).push(r);
  }
  const scopes = Array.from(rulesByScope.keys()).sort((a, b) =>
    (scopeOrder(a) - scopeOrder(b)) || a.localeCompare(b));

  function whyOf(p) {
    // Groups are always by-object; skip the "object" label there and only
    // annotate rule rows (where literal vs object is meaningful).
    if (p.type === "group") return "";
    return Array.from(p._kinds || []).sort().join(", ");
  }

  function renderGroupsTable(rows) {
    if (!rows.length) return '<p class="none">(no group updates)</p>';
    return `
      <div class="tblwrap"><table style="table-layout:fixed;width:100%;">
        <colgroup>
          <col style="width:12%"><col style="width:26%">
          <col style="width:15.5%"><col style="width:15.5%">
          <col style="width:15.5%"><col style="width:15.5%">
        </colgroup>
        <tr>
          <th rowspan="2">Scope</th>
          <th rowspan="2">Group</th>
          <th colspan="2" style="text-align:center">Adds</th>
          <th colspan="2" style="text-align:center">Already mapped</th>
        </tr>
        <tr>
          <th>Source</th><th>Destination</th>
          <th>Source</th><th>Destination</th>
        </tr>
        ${rows.map(p => `<tr>
          <td>${esc(p.scope)}</td>
          <td style="word-break:break-word">${esc(p.name)}</td>
          <td style="word-break:break-word">${esc(p.src_add)}</td>
          <td style="word-break:break-word">${esc(p.dst_add)}</td>
          <td style="word-break:break-word;color:var(--muted)">${esc(p.src_already)}</td>
          <td style="word-break:break-word;color:var(--muted)">${esc(p.dst_already)}</td>
        </tr>`).join("")}
      </table></div>`;
  }

  function renderRulesTable(rows) {
    if (!rows.length) return '<p class="none">(no rule updates)</p>';
    return `
      <div class="tblwrap"><table style="table-layout:fixed;width:100%;">
        <colgroup>
          <col style="width:9%"><col style="width:23%"><col style="width:9%">
          <col style="width:14.75%"><col style="width:14.75%">
          <col style="width:14.75%"><col style="width:14.75%">
        </colgroup>
        <tr>
          <th rowspan="2">Rulebase</th>
          <th rowspan="2">Rule</th>
          <th rowspan="2" title="literal = rule has a bare IP/CIDR that maps; object = rule references an address object that maps">Why</th>
          <th colspan="2" style="text-align:center">Adds</th>
          <th colspan="2" style="text-align:center">Already mapped</th>
        </tr>
        <tr>
          <th>Source</th><th>Destination</th>
          <th>Source</th><th>Destination</th>
        </tr>
        ${rows.map(p => `<tr>
          <td>${esc(p.type.replace(/-rule$/, ""))}</td>
          <td style="word-break:break-word">${esc(p.name)}</td>
          <td>${esc(whyOf(p))}</td>
          <td style="word-break:break-word">${esc(p.src_add)}</td>
          <td style="word-break:break-word">${esc(p.dst_add)}</td>
          <td style="word-break:break-word;color:var(--muted)">${esc(p.src_already)}</td>
          <td style="word-break:break-word;color:var(--muted)">${esc(p.dst_already)}</td>
        </tr>`).join("")}
      </table></div>`;
  }

  const rulesSections = scopes.map(sc =>
    `<h3 style="margin-top:22px">Device group: ${esc(sc)} (${rulesByScope.get(sc).length} rule${rulesByScope.get(sc).length === 1 ? "" : "s"})</h3>
     ${renderRulesTable(rulesByScope.get(sc))}`).join("");

  // Root-cause view: which object actions drive the most downstream rows.
  // One "action" resolved usually knocks out many groups/rules at once, so
  // sorting by downstream ref count surfaces the biggest levers first.
  const rootActions = (r.object_actions || []).slice().sort(
    (a, b) => (b.refs_count || 0) - (a.refs_count || 0));
  const totalDownstream = rootActions.reduce((s, a) => s + (a.refs_count || 0), 0);

  function renderRootTable(rows) {
    if (!rows.length) return '<p class="none">(no object actions)</p>';
    return `
      <div class="tblwrap"><table style="table-layout:fixed;width:100%;">
        <colgroup>
          <col style="width:5%"><col style="width:18%"><col style="width:11%">
          <col style="width:11%"><col style="width:11%"><col style="width:20%">
          <col style="width:24%">
        </colgroup>
        <tr>
          <th>#</th>
          <th>Object</th>
          <th>Defined in</th>
          <th>Current value</th>
          <th>Mapped value</th>
          <th>Action</th>
          <th title="how many groups / rules downstream would be resolved by this single action">Downstream targets</th>
        </tr>
        ${rows.map((a, i) => `<tr>
          <td>${i + 1}</td>
          <td style="word-break:break-word"><code>${esc(a.member)}</code></td>
          <td>${esc(a.location)}</td>
          <td><code>${esc(a.value)}</code></td>
          <td><code>${esc(a.mapped_value)}</code></td>
          <td>${esc(a.action)}</td>
          <td style="word-break:break-word"><b>${a.refs_count}</b>
            (${a.refs_groups} group${a.refs_groups === 1 ? "" : "s"},
             ${a.refs_rules} rule${a.refs_rules === 1 ? "" : "s"}):
            <span style="color:var(--muted);font-size:12px">${esc(a.refs)}</span></td>
        </tr>`).join("")}
      </table></div>`;
  }

  const alreadyCount = (r.already || []).length;
  const t = r.totals;
  $("results").innerHTML = `
    <div class="chips">
      <div class="chip"><b>${t.object_actions}</b><span>object actions</span></div>
      <div class="chip"><b>${totalDownstream}</b><span>downstream group/rule refs</span></div>
      <div class="chip"><b>${groupRows.length}</b><span>groups touched</span></div>
      <div class="chip"><b>${ruleRows.length}</b><span>rule sides touched</span></div>
      <div class="chip"><b>${alreadyCount}</b><span>already-mapped rows</span></div>
      <div class="chip"><b>${t.ranges}</b><span>ranges (report-only)</span></div>
      <div class="chip"><b>${t.csv_rows_unmatched}</b><span>CSV rows unmatched</span></div>
    </div>
    <p class="hint">Run ${esc(r.run_ts)} at ${esc(r.meta.ran_at)} against
      ${esc(r.meta.target)} as ${esc(r.meta.username)},
      CSV ${esc(r.meta.csv)} (${esc(r.meta.csv_rows)} rows)</p>

    <h2 style="margin-top:14px">Root causes (${rootActions.length}
      object action${rootActions.length === 1 ? "" : "s"} would resolve
      ${totalDownstream} downstream ref${totalDownstream === 1 ? "" : "s"})</h2>
    <p class="hint">One "object action" is the single canonical change (create
      or reuse a partner object) that then propagates to every group/rule
      listed in Downstream targets. Sorted by downstream ref count so the
      biggest levers are on top.</p>
    ${renderRootTable(rootActions)}

    <h2 style="margin-top:22px">Groups (${groupRows.length})</h2>
    ${renderGroupsTable(groupRows)}

    <h2 style="margin-top:22px">Rules (${ruleRows.length}), grouped by device group</h2>
    ${rulesSections || '<p class="none">(no rule updates)</p>'}

    <p class="hint">Empty cell = nothing on that side. The two "Already mapped"
      columns show entries where a partner object with the mapped value already
      exists on this group/rule, so no add is needed. Full detail is in
      pan_reports/.../group_remap_dryrun/report.md; also see the un-pivoted
      view under <a href="/group-remap">Group Remap</a>.</p>`;
}

async function refreshRuns() {
  const runs = await (await fetch("/api/remap/runs")).json();
  $("runs").innerHTML = runs.length ? runs.map(r =>
    `<li data-id="${esc(r.run_ts)}">
       <div><b>${r.totals.object_actions}</b> object actions,
         ${r.totals.targets_updated} targets <code>${esc(r.csv)}</code></div>
       <div class="when">${esc(r.ran_at)}</div>
       <span class="del" data-del="${esc(r.run_ts)}" title="delete this report">&#215;</span></li>`).join("")
    : '<li class="none" style="cursor:default">none yet</li>';
  for (const li of $("runs").querySelectorAll("li[data-id]"))
    li.onclick = async () => {
      const run = await (await fetch("/api/remap/run?id=" + li.dataset.id)).json();
      if (!run.error) render(run);
    };
  wireHistory("remap", refreshRuns);
}

fetch("/api/remap/csvs").then(r => r.json()).then(csvs => {
  $("csv").innerHTML = csvs.map(c =>
    `<option value="${esc(c.name)}">${esc(c.name)}${c.rows != null ? ` (${c.rows} rows)` : ""}</option>`
  ).join("") || "<option value=''>no CSVs in data/</option>"; });

$("run").onclick = async () => {
  $("error").textContent = "";
  $("run").disabled = true;
  $("run").textContent = "Pulling and analyzing...";
  try {
    const resp = await fetch("/api/remap/run", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({csv: $("csv").value, device_groups: $("dgs").value})});
    const data = await resp.json();
    if (data.error) $("error").textContent = data.error;
    else { render(data); refreshRuns(); }
  } catch (e) { $("error").textContent = String(e); }
  $("run").disabled = false;
  $("run").textContent = "Run dry-run report (pulls fresh)";
};
refreshRuns();
"""


RULE_SEARCH_BODY = """
<div class="layout">
  <div>
    <div class="panel">
      <label for="targets">Search targets</label>
      <textarea id="targets" rows="6" placeholder="10.1.1.5&#10;10.2.1.0/24&#10;10.1.1.5-10.1.1.20"></textarea>
      <p class="hint">IPs, subnets (CIDR), or ranges. One per line, # comments OK.</p>
      <label for="svc-proto">Service protocol (optional)</label>
      <select id="svc-proto">
        <option value="">any protocol</option>
        <option value="tcp">tcp</option>
        <option value="udp">udp</option>
      </select>
      <label for="svc-ports">Service ports (optional, comma delimited)</label>
      <input type="text" id="svc-ports" placeholder="443,8080">
      <p class="hint">Keeps only rules whose service covers at least one of
        these ports.</p>
      <label for="exclusions">Match exclusions (optional)</label>
      <textarea id="exclusions" rows="2" placeholder="10.0.0.0/8">10.0.0.0/8</textarea>
      <div class="row">
        <input type="checkbox" id="repo-excl" checked>
        <label for="repo-excl" style="margin:0;font-weight:400">also apply pan_ip_rule_exclude.txt</label>
      </div>
      <label for="dgs">Device groups (optional)</label>
      <input type="text" id="dgs" placeholder="all (or: dg-4,dg-5)">
      <button id="pull" class="secondary">Pull fresh config</button>
      <div class="snap" id="snap-status">No config snapshot yet. Pull first.</div>
      <button id="go" disabled>Search snapshot</button>
      <div class="err" id="error"></div>
      <div class="readonly">Like IP Rule Search, plus each matched rule's full
        configured source / destination / service, and an optional service
        filter. Read-only, snapshot-based.</div>
    </div>
    <div class="panel" style="margin-top:14px">
      <label style="margin-top:0">Previous runs
        <a href="#" id="clear-runs" class="clearlink">clear all</a></label>
      <ul id="runs" class="runs"></ul>
    </div>
  </div>
  <div id="results"><p class="none">No search yet.</p></div>
</div>
"""

RULE_SEARCH_JS = """
const members = list => (list || []).map(m => `<code>${esc(m)}</code>`).join("<br>");

function render(r) {
  const t = r.totals;
  const matchRows = [], anyRows = [];
  for (const sr of r.scopes) {
    for (const rule of sr.matched_rules) {
      const flags = [rule.disabled ? "DISABLED" : "",
                     rule.any_sides.length ? "any on " + rule.any_sides.join("/") : ""]
                    .filter(Boolean).join(", ");
      const hits = rule.matches.map(m =>
        `<code>${esc(m.target)}</code> (${esc(m.side)}) via ${esc(m.member)}` +
        (m.via ? ` <span class="none">in group ${esc(m.via)}</span>` : "")).join("<br>");
      matchRows.push([esc(sr.scope), esc(sr.rulebase), esc(rule.rule),
        rule.action === "allow" ? esc(rule.action)
          : `<span class="flag">${esc(rule.action || "")}</span>`,
        `<span class="flag">${esc(flags)}</span>`, hits,
        members(rule.source_members), members(rule.destination_members),
        members(rule.service_members) +
          (rule.service_matched ? `<br><span class="none">filter: ${esc(rule.service_matched)}</span>` : "")]);
    }
    for (const name of sr.any_any_rules)
      anyRows.push([esc(sr.scope), esc(sr.rulebase), esc(name)]);
  }
  const matched = new Set();
  for (const sr of r.scopes) for (const rule of sr.matched_rules)
    for (const m of rule.matches) matched.add(m.target);
  const noMatch = r.targets.filter(x => !matched.has(x)).map(x => [`<code>${esc(x)}</code>`]);
  const suppRows = [];
  for (const sr of r.scopes)
    for (const s of (sr.suppressed || []))
      suppRows.push([esc(sr.scope), esc(sr.rulebase), esc(s.rule), `<code>${esc(s.target)}</code>`,
        `${esc(s.member)} = <code>${esc(s.value)}</code>`, `<code>${esc(s.excluded_by)}</code>`]);

  const filt = r.service_filter
    ? `, service ${r.service_filter.proto || "tcp|udp"}/${r.service_filter.ports.join(",")}` : "";
  $("results").innerHTML = `
    <div class="chips">
      <div class="chip"><b>${t.targets_searched}</b><span>targets searched</span></div>
      <div class="chip"><b>${t.rules_matched}</b><span>rule matches</span></div>
      <div class="chip"><b>${t.any_any_rules}</b><span>any/any rules</span></div>
      <div class="chip"><b>${t.matches_suppressed ?? 0}</b><span>matches suppressed</span></div>
    </div>
    <p class="hint">Run ${esc(r.run_id)} at ${esc(r.meta.ran_at)}${esc(filt)}
      (snapshot pulled ${esc(r.meta.snapshot_pulled_at || "n/a")})</p>
    <h2>Rules matching the targets (with configured source / destination / service)</h2>
    ${table(["Scope","Rulebase","Rule","Action","Flags","Target hits",
             "Source (configured)","Destination (configured)","Service (configured)"], matchRows)}
    <h2>Global any/any rules${r.service_filter ? " (passing the service filter)" : ""}</h2>
    ${table(["Scope","Rulebase","Rule"], anyRows)}
    <h2>Targets with no matches</h2>${table(["Target"], noMatch)}
    <h2>Suppressed matches</h2>
    ${table(["Scope","Rulebase","Rule","Target","Matched through","Excluded by"], suppRows)}`;
}

function showSnapshot(s) {
  const el = $("snap-status");
  if (!s || !s.present) {
    el.className = "snap";
    el.textContent = "No config snapshot yet. Pull first.";
    $("go").disabled = true;
    return;
  }
  const rules = Object.values(s.rule_counts)
    .reduce((n, rc) => n + rc.pre + rc.post, 0);
  el.className = "snap ok";
  el.textContent = `Snapshot pulled ${s.pulled_at} : ` +
    `${s.device_groups.length} device groups, ${rules} rules.`;
  $("go").disabled = false;
}
window.onInfo = i => showSnapshot(i.snapshot);

async function refreshRuns() {
  const runs = await (await fetch("/api/runs2")).json();
  $("runs").innerHTML = runs.length ? runs.map(r =>
    `<li data-id="${esc(r.run_id)}">
       <div><b>${r.totals.rules_matched}</b> matches, ${r.totals.targets_searched} targets
         ${r.service ? `svc ${esc(r.service)}` : ""}</div>
       <div><code>${esc(r.targets.join(", "))}</code></div>
       <div class="when">${esc(r.ran_at)}</div>
       <span class="del" data-del="${esc(r.run_id)}" title="delete this run">&#215;</span></li>`).join("")
    : '<li class="none" style="cursor:default">none yet</li>';
  for (const li of $("runs").querySelectorAll("li[data-id]"))
    li.onclick = async () => {
      const run = await (await fetch("/api/run2?id=" + li.dataset.id)).json();
      if (!run.error) { render(run); fillInputs(run.inputs); }
    };
  wireHistory("searchplus", refreshRuns);
}

function fillInputs(i) {
  if (!i) return;
  $("targets").value = i.targets || "";
  $("exclusions").value = i.exclusions || "";
  $("repo-excl").checked = !!i.use_repo_exclusions;
  $("dgs").value = i.device_groups || "";
  $("svc-proto").value = i.service_proto || "";
  $("svc-ports").value = i.service_ports || "";
}

$("pull").onclick = async () => {
  $("error").textContent = "";
  $("pull").disabled = true;
  $("pull").textContent = "Pulling from Panorama...";
  try {
    const data = await (await fetch("/api/pull", {method: "POST"})).json();
    if (data.error) $("error").textContent = data.error;
    else showSnapshot(data);
  } catch (e) { $("error").textContent = String(e); }
  $("pull").disabled = false;
  $("pull").textContent = "Pull fresh config";
};

$("go").onclick = async () => {
  $("error").textContent = "";
  $("go").disabled = true;
  $("go").textContent = "Searching snapshot...";
  try {
    const resp = await fetch("/api/search2", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        targets: $("targets").value,
        exclusions: $("exclusions").value,
        use_repo_exclusions: $("repo-excl").checked,
        device_groups: $("dgs").value,
        service_proto: $("svc-proto").value,
        service_ports: $("svc-ports").value,
      })});
    const data = await resp.json();
    if (data.error) $("error").textContent = data.error;
    else { render(data); refreshRuns(); }
  } catch (e) { $("error").textContent = String(e); }
  $("go").disabled = false;
  $("go").textContent = "Search snapshot";
};
refreshRuns();
"""

FLOW_BODY = """
<div class="layout">
  <div>
    <div class="panel">
      <label for="src">Source IP (optional)</label>
      <input type="text" id="src" placeholder="10.1.1.5">
      <label for="dst">Destination IP (optional)</label>
      <input type="text" id="dst" placeholder="10.2.1.9">
      <p class="hint">IP, subnet, or range. At least one of the two.</p>
      <label for="port">Port (optional)</label>
      <input type="text" id="port" placeholder="443 or tcp/443 or udp/53">
      <button id="pull" class="secondary">Pull fresh config</button>
      <div class="snap" id="snap-status">No config snapshot yet. Pull first.</div>
      <button id="go" disabled>Find matching rules</button>
      <div class="err" id="error"></div>
      <div class="readonly">Evaluates the flow against each device group's
        chain in firewall order: shared pre, DG pre, DG post, shared post.
        The first match per device group is what would actually apply.
        Snapshot-only; no network per lookup.</div>
    </div>
    <div class="panel" style="margin-top:14px">
      <label style="margin-top:0">Previous lookups
        <a href="#" id="clear-runs" class="clearlink">clear all</a></label>
      <ul id="runs" class="runs"></ul>
    </div>
  </div>
  <div id="results"><p class="none">No lookup yet.</p></div>
</div>
"""

FLOW_JS = """
function render(r) {
  const crit = [r.src ? `src <code>${esc(r.src)}</code>` : "",
                r.dst ? `dst <code>${esc(r.dst)}</code>` : "",
                r.port ? `port <code>${esc(r.port)}</code>` : ""]
               .filter(Boolean).join(", ");
  const sections = r.per_dg.map(p => {
    const first = p.first_match;
    const head = first
      ? `<div class="reco"><b>${esc(first.rule)}</b>
           <span class="${first.action === "allow" ? "" : "flag"}">${esc(first.action || "")}</span>
           <span class="none">first match: ${esc(first.scope)}/${esc(first.rulebase)}${first.disabled ? " DISABLED" : ""}</span>
           <ul><li>source: ${esc(first.src_via)}</li>
               <li>destination: ${esc(first.dst_via)}</li>
               <li>service: ${esc(first.service_via)}</li></ul></div>`
      : '<p class="none">no matching rule (flow would hit the implicit deny)</p>';
    const rows = p.matches.map((m, i) => [
      i === 0 ? "<b>1 (applies)</b>" : String(i + 1),
      esc(m.scope), esc(m.rulebase), esc(m.rule),
      m.action === "allow" ? esc(m.action) : `<span class="flag">${esc(m.action || "")}</span>`,
      m.disabled ? '<span class="flag">DISABLED</span>' : "",
      esc(m.src_via), esc(m.dst_via), esc(m.service_via)]);
    return `<h2>${esc(p.dg)}</h2>${head}
      ${p.matches.length > 1 ? table(
        ["#","Scope","Rulebase","Rule","Action","Flags","Source via","Destination via","Service via"],
        rows) : ""}`;
  }).join("");
  $("results").innerHTML = `
    <p class="hint">Lookup ${esc(r.run_id)}: ${crit}
      (snapshot pulled ${esc(r.meta.snapshot_pulled_at)})</p>
    ${sections || '<p class="none">no device groups in snapshot</p>'}`;
}

function showSnapshot(s) {
  const el = $("snap-status");
  if (!s || !s.present) {
    el.className = "snap";
    el.textContent = "No config snapshot yet. Pull first.";
    $("go").disabled = true;
    return;
  }
  const rules = Object.values(s.rule_counts)
    .reduce((n, rc) => n + rc.pre + rc.post, 0);
  el.className = "snap ok";
  el.textContent = `Snapshot pulled ${s.pulled_at} : ` +
    `${s.device_groups.length} device groups, ${rules} rules.`;
  $("go").disabled = false;
}
window.onInfo = i => showSnapshot(i.snapshot);

async function refreshRuns() {
  const runs = await (await fetch("/api/flow/runs")).json();
  $("runs").innerHTML = runs.length ? runs.map(r => {
    const firsts = Object.entries(r.first)
      .map(([dg, rule]) => `${dg}: ${rule || "no match"}`).join(", ");
    return `<li data-id="${esc(r.run_id)}">
       <div><code>${esc(r.src || "*")}</code> to <code>${esc(r.dst || "*")}</code>
         ${r.port ? `port ${esc(r.port)}` : ""}</div>
       <div class="when">${esc(firsts)}</div>
       <div class="when">${esc(r.ran_at)}</div>
       <span class="del" data-del="${esc(r.run_id)}" title="delete this lookup">&#215;</span></li>`;
  }).join("") : '<li class="none" style="cursor:default">none yet</li>';
  for (const li of $("runs").querySelectorAll("li[data-id]"))
    li.onclick = async () => {
      const run = await (await fetch("/api/flow/run?id=" + li.dataset.id)).json();
      if (!run.error) {
        render(run);
        $("src").value = run.src || ""; $("dst").value = run.dst || "";
        $("port").value = run.port || "";
      }
    };
  wireHistory("flow", refreshRuns);
}

$("pull").onclick = async () => {
  $("error").textContent = "";
  $("pull").disabled = true;
  $("pull").textContent = "Pulling from Panorama...";
  try {
    const data = await (await fetch("/api/pull", {method: "POST"})).json();
    if (data.error) $("error").textContent = data.error;
    else showSnapshot(data);
  } catch (e) { $("error").textContent = String(e); }
  $("pull").disabled = false;
  $("pull").textContent = "Pull fresh config";
};

$("go").onclick = async () => {
  $("error").textContent = "";
  $("go").disabled = true;
  try {
    const resp = await fetch("/api/flow/run", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({src: $("src").value, dst: $("dst").value,
                            port: $("port").value})});
    const data = await resp.json();
    if (data.error) $("error").textContent = data.error;
    else { render(data); refreshRuns(); }
  } catch (e) { $("error").textContent = String(e); }
  $("go").disabled = false;
};
refreshRuns();
"""

PLACEMENT_BODY = """
<div class="layout">
  <div>
    <div class="panel">
      <label for="src">Source IP</label>
      <input type="text" id="src" placeholder="10.3.1.5">
      <label for="dst">Destination IP</label>
      <input type="text" id="dst" placeholder="10.4.1.9">
      <button id="pull" class="secondary">Pull routing tables</button>
      <div class="snap" id="topo-status">No routing topology yet. Pull first.</div>
      <button id="go" disabled>Recommend placement</button>
      <div class="err" id="error"></div>
      <div class="readonly">Routing tables come from each connected firewall
        via Panorama's proxy (read-only op, admin credentials; the one place
        the toolkit touches firewall state). Recommendation = the device
        group(s) whose firewall most specifically routes each endpoint;
        default-route-only boxes are never recommended.</div>
    </div>
    <div class="panel" style="margin-top:14px">
      <label style="margin-top:0">Previous lookups
        <a href="#" id="clear-runs" class="clearlink">clear all</a></label>
      <ul id="runs" class="runs"></ul>
    </div>
  </div>
  <div id="results"><p class="none">No lookup yet.</p></div>
</div>
"""

PLACEMENT_JS = """
function render(r) {
  const recos = r.recommended.map(x => `
    <div class="reco"><b>${esc(x.dg)}</b>
      <span class="none">(${esc(x.device)})</span>
      <ul>${x.reasons.map(y => `<li>${esc(y)}</li>`).join("")}</ul></div>`).join("");
  $("results").innerHTML = `
    <p class="hint">Lookup ${esc(r.run_id)}: <code>${esc(r.src)}</code> to
      <code>${esc(r.dst)}</code> (topology pulled ${esc(r.meta.topology_pulled_at)})</p>
    <h2>Recommended placement</h2>
    ${recos || '<p class="none">(none)</p>'}
    ${r.note ? `<p class="err">${esc(r.note)}</p>` : ""}
    <h2>Every device group considered</h2>
    ${table(["Device group","Firewall","Route to source","Route to destination","Verdict"],
      r.considered.map(c => [esc(c.dg), esc(c.device), esc(c.src), esc(c.dst),
        c.verdict === "recommended" ? `<b>${esc(c.verdict)}</b>` : esc(c.verdict)]))}`;
}

function showTopo(s) {
  const el = $("topo-status");
  if (!s || !s.present) {
    el.className = "snap";
    el.textContent = "No routing topology yet. Pull first.";
    $("go").disabled = true;
    return;
  }
  const parts = Object.entries(s.tables)
    .map(([dg, t]) => `${dg}/${t.device} ${t.routes} routes`).join(", ");
  el.className = "snap ok";
  el.textContent = `Topology pulled ${s.pulled_at} : ${parts}.` +
    (s.warnings.length ? ` Warnings: ${s.warnings.join("; ")}` : "");
  $("go").disabled = false;
}
window.onInfo = i => showTopo(i.topology);

async function refreshRuns() {
  const runs = await (await fetch("/api/placement/runs")).json();
  $("runs").innerHTML = runs.length ? runs.map(r =>
    `<li data-id="${esc(r.run_id)}">
       <div><code>${esc(r.src)}</code> to <code>${esc(r.dst)}</code>
         : <b>${esc(r.recommended.join(", ") || "none")}</b></div>
       <div class="when">${esc(r.ran_at)}</div>
       <span class="del" data-del="${esc(r.run_id)}" title="delete this lookup">&#215;</span></li>`).join("")
    : '<li class="none" style="cursor:default">none yet</li>';
  for (const li of $("runs").querySelectorAll("li[data-id]"))
    li.onclick = async () => {
      const run = await (await fetch("/api/placement/run?id=" + li.dataset.id)).json();
      if (!run.error) { render(run); $("src").value = run.src; $("dst").value = run.dst; }
    };
  wireHistory("placement", refreshRuns);
}

$("pull").onclick = async () => {
  $("error").textContent = "";
  $("pull").disabled = true;
  $("pull").textContent = "Pulling routing tables...";
  try {
    const data = await (await fetch("/api/placement/pull", {method: "POST"})).json();
    if (data.error) $("error").textContent = data.error;
    else showTopo(data);
  } catch (e) { $("error").textContent = String(e); }
  $("pull").disabled = false;
  $("pull").textContent = "Pull routing tables";
};

$("go").onclick = async () => {
  $("error").textContent = "";
  $("go").disabled = true;
  try {
    const resp = await fetch("/api/placement/run", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({src: $("src").value, dst: $("dst").value})});
    const data = await resp.json();
    if (data.error) $("error").textContent = data.error;
    else { render(data); refreshRuns(); }
  } catch (e) { $("error").textContent = String(e); }
  $("go").disabled = false;
};
refreshRuns();
"""


# =============================================================================
# HTTP server
# =============================================================================

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.debug("%s " + fmt, self.address_string(), *args)

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def _page(self, title: str, here: str, body: str, script: str) -> None:
        self._send(200, shell(title, here, body, script).encode("utf-8"),
                   "text/html; charset=utf-8")

    def do_GET(self) -> None:
        if self.path == "/":
            self._page("SSDD Toolkit", "/", HUB_BODY, "")
        elif self.path.startswith("/ip-search"):
            self._page("SSDD Toolkit : IP Rule Search", "/ip-search",
                       IP_SEARCH_BODY, IP_SEARCH_JS)
        elif self.path.startswith("/remap-pivot"):
            self._page("SSDD Toolkit : Remap Pivot", "/remap-pivot",
                       REMAP_PIVOT_BODY, REMAP_PIVOT_JS)
        elif self.path.startswith("/group-remap"):
            self._page("SSDD Toolkit : Group Remap", "/group-remap",
                       REMAP_BODY, REMAP_JS)
        elif self.path.startswith("/rule-search"):
            self._page("SSDD Toolkit : Rule Search+", "/rule-search",
                       RULE_SEARCH_BODY, RULE_SEARCH_JS)
        elif self.path.startswith("/flow-search"):
            self._page("SSDD Toolkit : Flow Match", "/flow-search",
                       FLOW_BODY, FLOW_JS)
        elif self.path.startswith("/rule-placement"):
            self._page("SSDD Toolkit : Rule Placement", "/rule-placement",
                       PLACEMENT_BODY, PLACEMENT_JS)
        elif self.path == "/api/info":
            self._json({"target": CONFIG["display_target"],
                        "username_source": CONFIG["user_env"] or "PANORAMA_* resolution",
                        "snapshot": snapshot_status(),
                        "topology": topology_status()})
        elif self.path == "/api/runs":
            self._json(list_search_runs())
        elif self.path.startswith("/api/run?"):
            run_id = (self.path.split("id=", 1) + [""])[1].split("&")[0]
            run = load_search_run(run_id)
            self._json(run if run else {"error": f"run {run_id!r} not found"},
                       200 if run else 404)
        elif self.path == "/api/runs2":
            self._json(list_search_runs(plus=True))
        elif self.path.startswith("/api/run2?"):
            run_id = (self.path.split("id=", 1) + [""])[1].split("&")[0]
            run = load_search_run(run_id, plus=True)
            self._json(run if run else {"error": f"run {run_id!r} not found"},
                       200 if run else 404)
        elif self.path == "/api/flow/runs":
            self._json(list_flow_runs())
        elif self.path.startswith("/api/flow/run?"):
            run_id = (self.path.split("id=", 1) + [""])[1].split("&")[0]
            run = load_flow_run(run_id)
            self._json(run if run else {"error": f"run {run_id!r} not found"},
                       200 if run else 404)
        elif self.path == "/api/placement/runs":
            self._json(list_placement_runs())
        elif self.path.startswith("/api/placement/run?"):
            run_id = (self.path.split("id=", 1) + [""])[1].split("&")[0]
            run = load_placement_run(run_id)
            self._json(run if run else {"error": f"run {run_id!r} not found"},
                       200 if run else 404)
        elif self.path == "/api/remap/csvs":
            self._json(list_csvs())
        elif self.path == "/api/remap/runs":
            self._json(list_remap_runs())
        elif self.path.startswith("/api/remap/run?"):
            run_ts = (self.path.split("id=", 1) + [""])[1].split("&")[0]
            run = load_remap_run(run_ts)
            self._json(run if run else {"error": f"run {run_ts!r} not found"},
                       200 if run else 404)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/api/pull":
                self._json(pull_snapshot())
            elif self.path == "/api/search":
                self._json(run_search(payload))
            elif self.path == "/api/remap/run":
                self._json(run_remap(payload))
            elif self.path == "/api/search2":
                self._json(run_search(payload, plus=True))
            elif self.path == "/api/flow/run":
                self._json(run_flow(payload))
            elif self.path == "/api/placement/pull":
                self._json(pull_topology())
            elif self.path == "/api/placement/run":
                self._json(run_placement(payload))
            elif self.path == "/api/runs/delete":
                self._json(delete_runs(payload.get("kind", ""), payload.get("id")))
            else:
                self._json({"error": "not found"}, 404)
        except ValueError as exc:
            self._json({"error": str(exc)}, 400)
        except PanRestError as exc:
            self._json({"error": f"Panorama pull failed: {exc}"}, 502)
        except Exception as exc:  # keep the server alive on surprises
            log.exception("request failed")
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("USAGE:", 1)[1] if "USAGE:" in __doc__ else None)
    parser.add_argument("--host", default=None, help="Target Panorama hostname (overrides .env).")
    parser.add_argument("--user-env", default="agent_user",
                        help="Env var (in .env) holding the username (default: agent_user).")
    parser.add_argument("--password-env", default="agent_password",
                        help="Env var (in .env) holding the password (default: agent_password).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Listen port on 127.0.0.1 (default {DEFAULT_PORT}).")
    parser.add_argument("--no-tls-verify", action="store_true",
                        help="Disable TLS certificate verification toward Panorama.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = time.gmtime

    if args.no_tls_verify:
        os.environ["PANORAMA_TLS_VERIFY"] = "false"

    try:
        probe = PanRestClient.from_env(user_env=args.user_env,
                                       password_env=args.password_env, host=args.host)
    except PanRestError as exc:
        log.error("%s", exc)
        return 2
    CONFIG.update({
        "user_env": args.user_env, "password_env": args.password_env,
        "host": args.host, "display_host": probe.env.hostname,
        "display_target": probe.env.url,
    })
    load_persisted_snapshot()
    load_persisted_topology()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    log.info("SSDD Toolkit: http://127.0.0.1:%d (target %s, loopback only)",
             args.port, probe.env.url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
