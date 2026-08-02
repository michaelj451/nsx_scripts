#!/usr/bin/env python3
"""tools/nsx/capture_fabric_state.py

Read-only capture of an NSX manager's FABRIC + NETWORK state into a
timestamped bundle. Companion to capture_nsx_state.py, which handles DFW.

What's captured:

  nsx_fabric_capture/<host>/<UTC_TS>/
    manifest.json
    logs/
    fabric/
      compute-managers/*.json
      transport-nodes/*.json           (hosts + edges)
      edge-clusters/*.json
      transport-zones/*.json
      uplink-profiles/*.json           (a.k.a. host-switch-profiles)
      transport-node-profiles/*.json
      ip-pools/*.json                  (VTEP + service-insertion)
      ip-blocks/*.json                 (T0 uplinks etc.)
    network/
      tier-0s/<id>/
        gateway.json
        locale-services/<ls-id>/
          locale-service.json
          interfaces/*.json
          bgp.json                     (may be absent on T0 without BGP)
          bgp-neighbors/*.json
        static-routes/*.json
        nat/USER/*.json
      tier-1s/<id>/                    (same layout minus BGP)
      segments/*.json                  (with subnets, DHCP, connectivity)
      gateway-policies/                (edge firewall on T0/T1)
        <policy-id>/
          policy.json
          rules/*.json

Everything here uses GET-only calls. Zero writes to the manager.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time as _time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.cli_bootstrap import init_cli               # noqa: E402
from nsx.nsx_constants import resolve_manager, nsx_log_dir  # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient    # noqa: E402


log = logging.getLogger(__name__)
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2",
                       "nsx-lm3", "nsx-lm4", "nsx-lm5"]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def setup_logging(bundle_logs_dir: Path) -> Path:
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)
    bundle_logs_dir.mkdir(parents=True, exist_ok=True)

    logging.Formatter.converter = _time.gmtime
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter(
        "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S")
    for h in (logging.StreamHandler(),
              logging.FileHandler(bundle_logs_dir / f"capture_fabric_state_{RUN_TS}.log",
                                  encoding="utf-8"),
              logging.FileHandler(global_log_dir / f"capture_fabric_state_{RUN_TS}.log",
                                  encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    return bundle_logs_dir / f"capture_fabric_state_{RUN_TS}.log"


def _sanitize_filename(s: str) -> str:
    """NSX ids sometimes contain '/' or ':'. Replace with safe chars."""
    return s.replace("/", "_").replace(":", "_").replace(" ", "_")


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def _safe_get(c: NsxPolicyClient, path: str, params: Optional[Dict] = None) -> Optional[Dict]:
    try:
        return c._get(path, params=params or {})
    except Exception as e:
        # 404 is expected for optional sub-resources (bgp on non-BGP gateway etc.)
        msg = str(e)
        if "404" in msg:
            return None
        log.warning("  GET %s failed: %s", path, msg[:120])
        return None


# =============================================================================
# Fabric
# =============================================================================

def capture_fabric(c: NsxPolicyClient, out: Path) -> Dict[str, int]:
    counts: Dict[str, int] = {}

    def dump_list(label: str, api_path: str, subdir: str) -> int:
        r = _safe_get(c, api_path)
        items = (r or {}).get("results", []) or []
        d = out / subdir
        for it in items:
            iid = it.get("id") or it.get("unique_id") or "no-id"
            _write_json(d / f"{_sanitize_filename(iid)}.json", it)
        log.info("  fabric.%s: %d", label, len(items))
        counts[label] = len(items)
        return len(items)

    dump_list("compute-managers",       "/api/v1/fabric/compute-managers",  "fabric/compute-managers")
    dump_list("transport-nodes",        "/api/v1/transport-nodes",          "fabric/transport-nodes")
    dump_list("edge-clusters",          "/api/v1/edge-clusters",            "fabric/edge-clusters")
    dump_list("transport-zones",        "/api/v1/transport-zones",          "fabric/transport-zones")
    dump_list("uplink-profiles",        "/api/v1/host-switch-profiles",     "fabric/uplink-profiles")
    dump_list("transport-node-profiles","/api/v1/transport-node-profiles",  "fabric/transport-node-profiles")
    dump_list("ip-pools",               "/api/v1/pools/ip-pools",           "fabric/ip-pools")
    dump_list("ip-blocks",              "/api/v1/pools/ip-blocks",          "fabric/ip-blocks")

    # For each IP pool, also grab its subnets (allocations)
    pool_subnets = 0
    for pool_file in (out / "fabric/ip-pools").glob("*.json"):
        pid = json.loads(pool_file.read_text()).get("id")
        if not pid:
            continue
        sub = _safe_get(c, f"/api/v1/pools/ip-pools/{pid}/subnets")
        if sub and (sub.get("results") or []):
            _write_json(out / "fabric" / "ip-pools" / f"{_sanitize_filename(pid)}.subnets.json",
                        {"pool_id": pid, "subnets": sub.get("results")})
            pool_subnets += len(sub["results"])
    counts["ip-pool-subnets"] = pool_subnets
    log.info("  fabric.ip-pool-subnets: %d", pool_subnets)

    return counts


# =============================================================================
# Network (policy plane)
# =============================================================================

def _dump_gateway_subresources(c: NsxPolicyClient, kind: str, gw_id: str, gw_dir: Path,
                               with_bgp: bool) -> Dict[str, int]:
    """kind = 'tier-0s' or 'tier-1s'. Dumps locale-services, interfaces,
    optionally BGP, static routes, and USER NAT rules."""
    sub_counts: Dict[str, int] = {"locale_services": 0, "interfaces": 0,
                                   "bgp_neighbors": 0, "static_routes": 0,
                                   "nat_rules": 0}
    base = f"/policy/api/v1/infra/{kind}/{gw_id}"

    ls_r = _safe_get(c, f"{base}/locale-services")
    for ls in ((ls_r or {}).get("results") or []):
        ls_id = ls.get("id")
        ls_dir = gw_dir / "locale-services" / _sanitize_filename(ls_id or "no-id")
        _write_json(ls_dir / "locale-service.json", ls)
        sub_counts["locale_services"] += 1

        ifs = _safe_get(c, f"{base}/locale-services/{ls_id}/interfaces")
        for i in ((ifs or {}).get("results") or []):
            _write_json(ls_dir / "interfaces" / f"{_sanitize_filename(i.get('id') or 'no-id')}.json", i)
            sub_counts["interfaces"] += 1

        if with_bgp:
            bgp = _safe_get(c, f"{base}/locale-services/{ls_id}/bgp")
            if bgp:
                _write_json(ls_dir / "bgp.json", bgp)
                nbrs = _safe_get(c, f"{base}/locale-services/{ls_id}/bgp/neighbors")
                for n in ((nbrs or {}).get("results") or []):
                    _write_json(ls_dir / "bgp-neighbors" / f"{_sanitize_filename(n.get('id') or 'no-id')}.json", n)
                    sub_counts["bgp_neighbors"] += 1

    sr = _safe_get(c, f"{base}/static-routes")
    for r in ((sr or {}).get("results") or []):
        _write_json(gw_dir / "static-routes" / f"{_sanitize_filename(r.get('id') or 'no-id')}.json", r)
        sub_counts["static_routes"] += 1

    for section in ("USER", "INTERNAL", "DEFAULT"):
        nat = _safe_get(c, f"{base}/nat/{section}/nat-rules")
        for r in ((nat or {}).get("results") or []):
            _write_json(gw_dir / "nat" / section / f"{_sanitize_filename(r.get('id') or 'no-id')}.json", r)
            sub_counts["nat_rules"] += 1

    return sub_counts


def capture_network(c: NsxPolicyClient, out: Path) -> Dict[str, int]:
    counts: Dict[str, int] = {"tier-0s": 0, "tier-1s": 0, "segments": 0,
                              "gateway-policies": 0, "gateway-rules": 0}
    subtotals: Dict[str, int] = {}

    # Tier-0s
    t0s = _safe_get(c, "/policy/api/v1/infra/tier-0s")
    for t0 in ((t0s or {}).get("results") or []):
        t0_id = t0.get("id")
        d = out / "network" / "tier-0s" / _sanitize_filename(t0_id or "no-id")
        _write_json(d / "gateway.json", t0)
        counts["tier-0s"] += 1
        s = _dump_gateway_subresources(c, "tier-0s", t0_id, d, with_bgp=True)
        for k, v in s.items():
            subtotals[f"t0.{k}"] = subtotals.get(f"t0.{k}", 0) + v
    log.info("  network.tier-0s: %d", counts["tier-0s"])

    # Tier-1s
    t1s = _safe_get(c, "/policy/api/v1/infra/tier-1s")
    for t1 in ((t1s or {}).get("results") or []):
        t1_id = t1.get("id")
        d = out / "network" / "tier-1s" / _sanitize_filename(t1_id or "no-id")
        _write_json(d / "gateway.json", t1)
        counts["tier-1s"] += 1
        s = _dump_gateway_subresources(c, "tier-1s", t1_id, d, with_bgp=False)
        for k, v in s.items():
            subtotals[f"t1.{k}"] = subtotals.get(f"t1.{k}", 0) + v
    log.info("  network.tier-1s: %d", counts["tier-1s"])

    # Segments
    segs = _safe_get(c, "/policy/api/v1/infra/segments")
    for s in ((segs or {}).get("results") or []):
        sid = s.get("id")
        _write_json(out / "network" / "segments" / f"{_sanitize_filename(sid or 'no-id')}.json", s)
        counts["segments"] += 1
    log.info("  network.segments: %d", counts["segments"])

    # Gateway policies (edge firewall on T0/T1)
    gp = _safe_get(c, "/policy/api/v1/infra/domains/default/gateway-policies")
    for p in ((gp or {}).get("results") or []):
        pid = p.get("id")
        pdir = out / "network" / "gateway-policies" / _sanitize_filename(pid or "no-id")
        _write_json(pdir / "policy.json", p)
        counts["gateway-policies"] += 1
        rules = _safe_get(c, f"/policy/api/v1/infra/domains/default/gateway-policies/{pid}/rules")
        for r in ((rules or {}).get("results") or []):
            _write_json(pdir / "rules" / f"{_sanitize_filename(r.get('id') or 'no-id')}.json", r)
            counts["gateway-rules"] += 1
    log.info("  network.gateway-policies: %d  (rules: %d)",
             counts["gateway-policies"], counts["gateway-rules"])

    counts["subtotals"] = subtotals  # type: ignore[assignment]
    return counts


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--source", required=True, choices=NSX_MANAGER_CHOICES)
    p.add_argument("--output-base", default="nsx_fabric_capture",
                   help="Output root. Default: ./nsx_fabric_capture/")
    p.add_argument("--federation-global", action="store_true",
                   help="Set for GM sources.")
    args = p.parse_args()

    init_cli()
    host = resolve_manager(args.source)
    if not host:
        raise SystemExit(f"Cannot resolve alias {args.source}")

    out_dir = (Path(args.output_base).expanduser().resolve()
               / host / RUN_TS)
    logs_dir = out_dir / "logs"
    setup_logging(logs_dir)

    log.info("=" * 70)
    log.info("CAPTURE FABRIC + NETWORK STATE")
    log.info("  Source     : %s (%s)", args.source, host)
    log.info("  Output     : %s", out_dir)
    log.info("  Read-only  : GET-only, zero writes")
    log.info("=" * 70)

    c = NsxPolicyClient(nsxmanager=host, federation_global=args.federation_global)

    started = _time.time()
    log.info("[1/2] Fabric ...")
    fab_counts = capture_fabric(c, out_dir)
    log.info("[2/2] Network ...")
    net_counts = capture_network(c, out_dir)
    elapsed = _time.time() - started

    manifest = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source_alias": args.source,
        "source_host": host,
        "federation_global": args.federation_global,
        "elapsed_seconds": round(elapsed, 2),
        "counts": {"fabric": fab_counts, "network": net_counts},
        "output_dir": str(out_dir),
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    log.info("=" * 70)
    log.info("Manifest: %s", out_dir / "manifest.json")
    log.info("Elapsed:  %.1fs", elapsed)
    log.info("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
