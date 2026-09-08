#!/usr/bin/env python3
"""tools/pan/perf_test_panorama.py

Read-only performance test of a Panorama's XML API.

Everything this script sends is a read: keygen, operational "show" commands,
and config gets. Nothing is written to Panorama, no commits, no candidate
changes. It answers:

  - How fast is the network path (DNS, TCP connect, TLS handshake)?
  - How long does keygen take?
  - What is the latency profile (min/avg/p50/p95/max) of common op commands
    and config reads, over N iterations each?
  - How big and how slow is a full running-config pull?
  - How does the API behave under modest concurrency (throughput and
    per-request latency at 1/4/8 parallel workers)?
  - What did the Panorama's own CPU/load look like before and after
    (via "show system resources")?

Target selection:
  Default target and credentials come from .env (see app/palo/pan_env.py).
  --host overrides the target hostname; when it differs from the .env host,
  any stored PANORAMA_API_KEY is ignored (keys are per-device) and a fresh
  keygen runs against the override host with the .env username/password.

USAGE:
    # Dry run: show the test plan and target, no network calls to Panorama
    python tools/pan/perf_test_panorama.py --host pano2.lab.local --dry-run

    # Full run against pano2 (self-signed lab cert)
    python tools/pan/perf_test_panorama.py --host pano2.lab.local --no-tls-verify

    # Heavier sampling
    python tools/pan/perf_test_panorama.py --host pano2.lab.local --no-tls-verify \
        --iterations 25 --concurrency 1,4,8,16 --requests-per-level 40

Exit codes:
    0  all phases completed
    1  a phase failed (partial results are still reported)
    2  .env / arguments do not describe a usable target

A JSON report (no secrets; key fingerprint only) is written to
.pano_reports/perf_test_<host>_<UTC ts>.json unless --no-report is given.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import socket
import ssl
import statistics
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

import requests  # noqa: E402
import urllib3  # noqa: E402

from palo.pan_env import (  # noqa: E402
    API_KEY_VARS, HOST_VARS, PanoramaEnvError, load_repo_env, resolve_panorama_env,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("perf_test_panorama")

DEFAULT_REPORT_DIR = REPO_ROOT / ".pano_reports"
DEFAULT_ITERATIONS = 10
DEFAULT_CONFIG_PULLS = 3
DEFAULT_CONCURRENCY = "1,4,8"
DEFAULT_REQUESTS_PER_LEVEL = 24
REQUEST_TIMEOUT = 120

# Op commands timed in the sequential phase. All are reads.
OP_COMMANDS = [
    ("show_system_info", "<show><system><info></info></system></show>"),
    ("show_clock", "<show><clock></clock></show>"),
    ("show_devices_connected", "<show><devices><connected></connected></devices></show>"),
    ("show_devicegroups", "<show><devicegroups></devicegroups></show>"),
    ("show_templates", "<show><templates></templates></show>"),
]

# Config-read xpaths timed in the sequential phase.
CONFIG_READS = [
    ("get_device_groups", "/config/devices/entry[@name='localhost.localdomain']/device-group"),
    ("get_shared_address", "/config/shared/address"),
    ("get_shared_pre_rules", "/config/shared/pre-rulebase/security/rules"),
]

# Cheapest op command; used for the concurrency phase.
CONCURRENCY_CMD = "<show><clock></clock></show>"


# =============================================================================
# Helpers (pure)
# =============================================================================

def percentile(sorted_vals: List[float], pct: float) -> float:
    """Linear-interpolated percentile over an already-sorted list."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    rank = (pct / 100.0) * (len(sorted_vals) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (rank - lo)


def stats_ms(samples: List[float]) -> Dict[str, float]:
    """min/avg/p50/p95/max in milliseconds from a list of seconds."""
    if not samples:
        return {}
    vals = sorted(s * 1000.0 for s in samples)
    return {
        "count": len(vals),
        "min_ms": round(vals[0], 1),
        "avg_ms": round(statistics.fmean(vals), 1),
        "p50_ms": round(percentile(vals, 50), 1),
        "p95_ms": round(percentile(vals, 95), 1),
        "max_ms": round(vals[-1], 1),
    }


def fmt_stats(name: str, st: Dict[str, Any], extra: str = "") -> str:
    if not st:
        return f"  {name:<28} (no samples)"
    return (f"  {name:<28} n={st['count']:<3} min={st['min_ms']:>8.1f}  avg={st['avg_ms']:>8.1f}  "
            f"p50={st['p50_ms']:>8.1f}  p95={st['p95_ms']:>8.1f}  max={st['max_ms']:>8.1f} ms{extra}")


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n} B"


# =============================================================================
# Transport-level timing (no API key needed)
# =============================================================================

def time_transport(hostname: str, port: int, verify: bool, samples: int) -> Dict[str, Any]:
    dns, tcp, tls = [], [], []
    error: Optional[str] = None
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    for _ in range(samples):
        try:
            t0 = time.perf_counter()
            addr = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)[0][4]
            t1 = time.perf_counter()
            with socket.create_connection(addr, timeout=10) as sock:
                t2 = time.perf_counter()
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    t3 = time.perf_counter()
            dns.append(t1 - t0)
            tcp.append(t2 - t1)
            tls.append(t3 - t2)
        except OSError as exc:
            error = f"{type(exc).__name__}: {exc}"
            break
    out: Dict[str, Any] = {
        "dns_resolve": stats_ms(dns),
        "tcp_connect": stats_ms(tcp),
        "tls_handshake": stats_ms(tls),
    }
    if error:
        out["error"] = error
    return out


# =============================================================================
# API calls
# =============================================================================

class ApiError(RuntimeError):
    pass


def api_call(session: requests.Session, base_url: str, verify: bool,
             params: Dict[str, str]) -> ET.Element:
    """One XML API request. Returns the parsed <response> root; raises ApiError
    when HTTP or the XML status attribute reports failure."""
    r = session.get(f"{base_url}/api/", params=params, verify=verify, timeout=REQUEST_TIMEOUT)
    if r.status_code >= 400:
        raise ApiError(f"HTTP {r.status_code}: {r.text[:200]}")
    try:
        root = ET.fromstring(r.text)
    except ET.ParseError as exc:
        raise ApiError(f"non-XML response: {r.text[:200]}") from exc
    if root.get("status") != "success":
        msg = "; ".join(el.text for el in root.iter("line") if el.text) or r.text[:200]
        raise ApiError(f"pan status={root.get('status')} code={root.get('code')}: {msg}")
    root.set("_bytes", str(len(r.content)))
    return root


def keygen(base_url: str, username: str, password: str, verify: bool) -> tuple[str, float]:
    """(api_key, elapsed_seconds). A dedicated session so keygen timing is not
    polluted by an existing keep-alive connection."""
    t0 = time.perf_counter()
    with requests.Session() as s:
        root = api_call(s, base_url, verify,
                        {"type": "keygen", "user": username, "password": password})
    elapsed = time.perf_counter() - t0
    key = root.findtext("./result/key")
    if not key:
        raise ApiError("keygen returned no key")
    return key, elapsed


def timed(fn: Callable[[], ET.Element], iterations: int) -> tuple[List[float], List[int], Optional[str]]:
    """Run fn() `iterations` times. Returns (latencies_s, sizes_bytes, error)."""
    lat: List[float] = []
    sizes: List[int] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        try:
            root = fn()
        except (ApiError, requests.RequestException) as exc:
            return lat, sizes, f"{type(exc).__name__}: {exc}"
        lat.append(time.perf_counter() - t0)
        sizes.append(int(root.get("_bytes", "0")))
    return lat, sizes, None


# =============================================================================
# Phases
# =============================================================================

def phase_op_commands(base_url: str, key: str, verify: bool, iterations: int) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    with requests.Session() as s:
        for name, cmd in OP_COMMANDS:
            lat, sizes, err = timed(
                lambda: api_call(s, base_url, verify, {"type": "op", "cmd": cmd, "key": key}),
                iterations)
            entry: Dict[str, Any] = stats_ms(lat)
            if sizes:
                entry["resp_bytes_avg"] = int(statistics.fmean(sizes))
            if err:
                entry["error"] = err
            results[name] = entry
            line = fmt_stats(name, entry) if lat else f"  {name:<28} FAILED: {err}"
            log.info("%s", line)
    return results


def phase_config_reads(base_url: str, key: str, verify: bool, iterations: int) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    with requests.Session() as s:
        for name, xpath in CONFIG_READS:
            lat, sizes, err = timed(
                lambda: api_call(s, base_url, verify,
                                 {"type": "config", "action": "get", "xpath": xpath, "key": key}),
                iterations)
            entry: Dict[str, Any] = stats_ms(lat)
            if sizes:
                entry["resp_bytes_avg"] = int(statistics.fmean(sizes))
            if err:
                entry["error"] = err
            results[name] = entry
            extra = f"  ({human_bytes(entry['resp_bytes_avg'])})" if sizes else ""
            line = fmt_stats(name, entry, extra) if lat else f"  {name:<28} FAILED: {err}"
            log.info("%s", line)
    return results


def phase_full_config(base_url: str, key: str, verify: bool, pulls: int) -> Dict[str, Any]:
    with requests.Session() as s:
        lat, sizes, err = timed(
            lambda: api_call(s, base_url, verify,
                             {"type": "config", "action": "show", "xpath": "/config", "key": key}),
            pulls)
    entry: Dict[str, Any] = stats_ms(lat)
    if sizes:
        entry["resp_bytes_avg"] = int(statistics.fmean(sizes))
        entry["throughput_mbps_avg"] = round(
            (statistics.fmean(sizes) * 8 / 1_000_000) / statistics.fmean(lat), 2)
    if err:
        entry["error"] = err
    if lat:
        log.info("%s", fmt_stats("full_running_config", entry,
                                 f"  ({human_bytes(entry['resp_bytes_avg'])}, "
                                 f"{entry['throughput_mbps_avg']} Mbps)"))
    else:
        log.info("  full_running_config          FAILED: %s", err)
    return entry


def phase_concurrency(base_url: str, key: str, verify: bool,
                      levels: List[int], total_per_level: int) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    for workers in levels:
        lat: List[float] = []
        errors: List[str] = []

        def one() -> float:
            # A session per request: measures cost as independent clients see it.
            t0 = time.perf_counter()
            with requests.Session() as s:
                api_call(s, base_url, verify,
                         {"type": "op", "cmd": CONCURRENCY_CMD, "key": key})
            return time.perf_counter() - t0

        wall0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(one) for _ in range(total_per_level)]
            for f in as_completed(futures):
                try:
                    lat.append(f.result())
                except (ApiError, requests.RequestException) as exc:
                    errors.append(f"{type(exc).__name__}: {exc}")
        wall = time.perf_counter() - wall0

        entry: Dict[str, Any] = stats_ms(lat)
        entry["workers"] = workers
        entry["requests"] = total_per_level
        entry["errors"] = len(errors)
        entry["wall_s"] = round(wall, 2)
        entry["req_per_s"] = round(len(lat) / wall, 1) if wall > 0 else 0.0
        if errors:
            entry["first_error"] = errors[0]
        results[f"c{workers}"] = entry
        log.info("%s", fmt_stats(f"concurrency x{workers}", entry,
                                 f"  ({entry['req_per_s']} req/s, errors={len(errors)})"))
    return results


def snapshot_resources(base_url: str, key: str, verify: bool) -> Dict[str, Any]:
    """First lines of `show system resources` (a `top` snapshot): load average
    and CPU line, so the report shows what the Panorama itself was doing."""
    try:
        with requests.Session() as s:
            root = api_call(s, base_url, verify,
                            {"type": "op",
                             "cmd": "<show><system><resources></resources></system></show>",
                             "key": key})
        text = root.findtext("./result") or ""
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()][:5]
        return {"top_lines": lines}
    except (ApiError, requests.RequestException) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("USAGE:", 1)[1] if "USAGE:" in __doc__ else None)
    parser.add_argument("--host", default=None,
                        help="Target Panorama hostname (overrides .env). A stored API key is "
                             "ignored when this differs from the .env host.")
    parser.add_argument("--env-file", default=None, help="Path to the .env to load (default: <repo>/.env).")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                        help=f"Samples per op/config test (default {DEFAULT_ITERATIONS}).")
    parser.add_argument("--config-pulls", type=int, default=DEFAULT_CONFIG_PULLS,
                        help=f"Full running-config pulls (default {DEFAULT_CONFIG_PULLS}).")
    parser.add_argument("--concurrency", default=DEFAULT_CONCURRENCY,
                        help=f"Comma-separated worker counts (default {DEFAULT_CONCURRENCY}).")
    parser.add_argument("--requests-per-level", type=int, default=DEFAULT_REQUESTS_PER_LEVEL,
                        help=f"Requests per concurrency level (default {DEFAULT_REQUESTS_PER_LEVEL}).")
    parser.add_argument("--skip-full-config", action="store_true",
                        help="Skip the full running-config pull phase.")
    parser.add_argument("--no-tls-verify", action="store_true",
                        help="Disable TLS certificate verification for this run.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the resolved target and test plan; send nothing to Panorama.")
    parser.add_argument("--report-dir", default=None,
                        help=f"Where to write the JSON report (default: {DEFAULT_REPORT_DIR}).")
    parser.add_argument("--no-report", action="store_true", help="Do not write a JSON report.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = time.gmtime

    env_path = Path(args.env_file).expanduser().resolve() if args.env_file else (REPO_ROOT / ".env")
    load_repo_env(env_path)
    if args.no_tls_verify:
        os.environ["PANORAMA_TLS_VERIFY"] = "false"

    environ: Dict[str, str] = dict(os.environ)
    try:
        env_target = resolve_panorama_env(environ)
    except PanoramaEnvError as exc:
        log.error("%s", exc)
        return 2

    host_overridden = bool(args.host) and args.host.strip().lower() != env_target.hostname.lower()
    if args.host:
        for var in HOST_VARS:
            environ.pop(var, None)
        environ["PANORAMA_HOST"] = args.host.strip()
    if host_overridden:
        # Stored API keys belong to the .env Panorama; force keygen on the override.
        for var in API_KEY_VARS:
            environ.pop(var, None)

    try:
        target = resolve_panorama_env(environ)
    except PanoramaEnvError as exc:
        log.error("%s", exc)
        return 2

    levels = sorted({int(x) for x in args.concurrency.split(",") if x.strip()})
    if any(l < 1 or l > 32 for l in levels):
        log.error("Concurrency levels must be between 1 and 32.")
        return 2

    plan = [
        f"transport timing            : {args.iterations} samples (DNS, TCP, TLS)",
        "keygen                      : 1 call" if not target.has_api_key else "keygen                      : skipped (stored key)",
        f"op commands                 : {len(OP_COMMANDS)} commands x {args.iterations} iterations",
        f"config reads                : {len(CONFIG_READS)} xpaths x {args.iterations} iterations",
        ("full running-config pulls   : skipped" if args.skip_full_config
         else f"full running-config pulls   : {args.config_pulls}"),
        f"concurrency                 : levels {levels}, {args.requests_per_level} requests each",
        "resource snapshots          : before and after (show system resources)",
    ]
    log.info("Target      : %s (tls_verify=%s, auth=%s)", target.url, target.verify,
             "api_key" if target.has_api_key else "username_password")
    if host_overridden:
        log.info("Host override: .env points at %s; testing %s with fresh keygen",
                 env_target.hostname, target.hostname)
    log.info("Test plan (all read-only):")
    for line in plan:
        log.info("  %s", line)

    report: Dict[str, Any] = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "target": target.describe(),
        "host_overridden": host_overridden,
        "parameters": {
            "iterations": args.iterations,
            "config_pulls": 0 if args.skip_full_config else args.config_pulls,
            "concurrency_levels": levels,
            "requests_per_level": args.requests_per_level,
        },
        "plan": plan,
        "read_only": True,
    }

    if args.dry_run:
        log.info("DRY RUN: no requests sent to Panorama.")
        report["status"] = "dry_run"
        _write_report(args, target.hostname, report)
        return 0

    failed = False

    log.info("Phase 1/6: transport (DNS / TCP / TLS)")
    report["transport"] = time_transport(target.hostname, target.port, target.verify, args.iterations)
    for k in ("dns_resolve", "tcp_connect", "tls_handshake"):
        log.info("%s", fmt_stats(k, report["transport"].get(k, {})))
    if "error" in report["transport"]:
        log.error("Transport phase error: %s", report["transport"]["error"])
        failed = True

    log.info("Phase 2/6: authentication")
    try:
        if target.has_api_key:
            key = target.api_key
            report["auth"] = {"method": "stored_api_key"}
        else:
            key, kg = keygen(target.url, target.username, target.password, target.verify)
            report["auth"] = {"method": "keygen", "keygen_ms": round(kg * 1000, 1)}
            log.info("  keygen                       %.1f ms", kg * 1000)
        report["auth"]["api_key_fingerprint"] = hashlib.sha256(key.encode()).hexdigest()[:12]
    except (ApiError, requests.RequestException) as exc:
        log.error("Authentication failed: %s", exc)
        report["auth"] = {"error": str(exc)}
        report["status"] = "auth_failed"
        _write_report(args, target.hostname, report)
        return 1

    report["resources_before"] = snapshot_resources(target.url, key, target.verify)
    for ln in report["resources_before"].get("top_lines", [])[:2]:
        log.info("  before: %s", ln)

    log.info("Phase 3/6: op command latency (%d iterations each)", args.iterations)
    report["op_commands"] = phase_op_commands(target.url, key, target.verify, args.iterations)

    log.info("Phase 4/6: config read latency (%d iterations each)", args.iterations)
    report["config_reads"] = phase_config_reads(target.url, key, target.verify, args.iterations)

    if args.skip_full_config:
        log.info("Phase 5/6: full running-config pull: skipped")
    else:
        log.info("Phase 5/6: full running-config pull (%d pulls)", args.config_pulls)
        report["full_config"] = phase_full_config(target.url, key, target.verify, args.config_pulls)

    log.info("Phase 6/6: concurrency (levels %s, %d requests each)", levels, args.requests_per_level)
    report["concurrency"] = phase_concurrency(target.url, key, target.verify,
                                              levels, args.requests_per_level)

    report["resources_after"] = snapshot_resources(target.url, key, target.verify)
    for ln in report["resources_after"].get("top_lines", [])[:2]:
        log.info("  after:  %s", ln)

    for section in ("op_commands", "config_reads", "concurrency"):
        if any("error" in v for v in report.get(section, {}).values()):
            failed = True
    if "error" in report.get("full_config", {}):
        failed = True

    report["status"] = "completed_with_errors" if failed else "ok"
    _write_report(args, target.hostname, report)
    log.info("Status: %s", report["status"])
    return 1 if failed else 0


def _write_report(args: argparse.Namespace, hostname: str, report: Dict[str, Any]) -> None:
    if args.no_report:
        return
    out_dir = Path(args.report_dir).expanduser().resolve() if args.report_dir else DEFAULT_REPORT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"perf_test_{hostname.split('.')[0]}_{ts}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log.info("Report: %s", path)


if __name__ == "__main__":
    sys.exit(main())
