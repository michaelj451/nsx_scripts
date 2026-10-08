#!/usr/bin/env python3
"""tools/test/generate_lab_traffic.py

Generate lab traffic from a YAML flow plan so chosen DFW rules collect hits,
then check the rules-usage diff against the plan's expectations.

Lab test tool only. It never talks to NSX: traffic goes from the Mac, from
aidev, or from lab VMs over SSH (key auth; lm1/lm2 VMs through a jump host,
because their DFW drops SSH from the Mac). Hit counts are read separately
with tools/reports/report_rules_usage.py.

Three modes:
  (default)  list the plan: every flow, where it runs from, the command, and
             the rule it should hit. Sends nothing.
  --run      send the traffic and write a run record.
  --check    read a rules-usage diff.json (report run with --compare-to a
             report taken before the traffic) and grade it: every expected
             rule must have new hits, every rule under `cold:` must have none.

USAGE:
    P=tools/test/traffic_plans/lm1_hit_subset.yaml
    python tools/reports/report_rules_usage.py --target nsx-lm1          # before
    python tools/test/generate_lab_traffic.py --plan $P                  # list
    python tools/test/generate_lab_traffic.py --plan $P --run            # send
    # wait until the counters move (20-30 min on lm1), then:
    python tools/reports/report_rules_usage.py --target nsx-lm1 --compare-to <before dir>
    python tools/test/generate_lab_traffic.py --plan $P --check <after dir>/diff.json

PLAN FORMAT: see tools/test/traffic_plans/lm1_hit_subset.yaml. Actions:
    ping      dst, count
    tcp       dst, port, repeat        one connection attempt per repeat
    udp       dst, port, repeat        one datagram per repeat
    scan      dst, ports "lo-hi"       one connection attempt per port
    http      url, repeat              curl, body discarded
    download  url, repeat              curl, prints bytes received
    dns       server, name, repeat     dig, one try each
    iperf3    server (host alias), dst, port, seconds
                                       starts a one-shot iperf3 server on the
                                       server host, then runs the client

OUTPUT (with --run):
    $NSX_LOG_DIR/traffic_runs/<UTC_TS>/run.json   per-flow command, exit code,
                                                  output tail, start/end UTC
    $NSX_LOG_DIR/traffic_runs/<UTC_TS>/logs/
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

log = logging.getLogger(__name__)

SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=accept-new"]


# =============================================================================
# Plan
# =============================================================================

def load_plan(path: Path) -> Dict[str, Any]:
    plan = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    hosts = plan.get("hosts") or {}
    seen = set()
    for f in plan.get("flows") or []:
        fid = f.get("id")
        if not fid or fid in seen:
            raise SystemExit(f"flow id missing or duplicated: {fid!r}")
        seen.add(fid)
        if f.get("from") not in hosts:
            raise SystemExit(f"flow {fid}: unknown host {f.get('from')!r}")
        if f.get("action") == "iperf3" and f.get("server") not in hosts:
            raise SystemExit(f"flow {fid}: unknown iperf3 server {f.get('server')!r}")
        if not f.get("expect"):
            raise SystemExit(f"flow {fid}: no expect rule")
    return plan


def _loop(n: int, body: str) -> str:
    return f"i=0; while [ $i -lt {int(n)} ]; do {body}; i=$((i+1)); done"


def flow_command(f: Dict[str, Any], local: bool = False) -> str:
    """Shell command (POSIX sh) that runs on the flow's source host."""
    a = f["action"]
    q = shlex.quote
    # macOS nc ignores -w while connecting; -G sets its connect timeout.
    nc = "nc -G 2 -w 2" if local and sys.platform == "darwin" else "nc -w 2"
    if a == "ping":
        return f"ping -c {int(f.get('count', 3))} {q(f['dst'])}"
    if a == "tcp":
        return _loop(f.get("repeat", 1), f"{nc} -z {q(f['dst'])} {int(f['port'])}")
    if a == "udp":
        return _loop(f.get("repeat", 1),
                     f"printf traffic | {nc} -u {q(f['dst'])} {int(f['port'])}")
    if a == "scan":
        lo, hi = (int(x) for x in str(f["ports"]).split("-"))
        return f"{nc} -z {q(f['dst'])} {lo}-{hi}"
    if a == "http":
        return _loop(f.get("repeat", 1), f"curl -sk -o /dev/null -m 5 {q(f['url'])}")
    if a == "download":
        return _loop(f.get("repeat", 1),
                     f"curl -sk -o /dev/null -m 60 -w '%{{size_download}}\\n' {q(f['url'])}")
    if a == "dns":
        return _loop(f.get("repeat", 1),
                     f"dig +tries=1 +time=1 @{q(f['server'])} {q(f.get('name', 'lab.local'))}")
    if a == "iperf3":
        return (f"iperf3 -c {q(f['dst'])} -p {int(f['port'])} "
                f"-t {int(f.get('seconds', 5))} --connect-timeout 3000")
    raise SystemExit(f"flow {f.get('id')}: unknown action {a!r}")


def iperf3_server_command(f: Dict[str, Any]) -> str:
    # -1 serves one client then exits; -D detaches so the SSH session returns.
    return f"iperf3 -s -1 -D -p {int(f['port'])}"


def host_argv(host: Dict[str, Any], command: str) -> List[str]:
    if host.get("local"):
        return ["sh", "-c", command]
    argv = ["ssh", "-n", *SSH_OPTS]
    if host.get("jump"):
        argv += ["-J", host["jump"]]
    return argv + [host["ssh"], command]


# =============================================================================
# Run
# =============================================================================

def _run(argv: List[str], timeout: int) -> Tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or "") + (exc.stderr or "")
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        return 124, out + f"\n[timed out after {timeout}s]"


def _tail(text: str, lines: int = 6) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def run_plan(plan: Dict[str, Any], only: Optional[set]) -> List[Dict[str, Any]]:
    hosts = plan["hosts"]
    records = []
    for f in plan["flows"]:
        if only and f["id"] not in only:
            continue
        rec: Dict[str, Any] = {"id": f["id"], "from": f["from"], "action": f["action"],
                               "expect": f["expect"],
                               "started_at": datetime.now(timezone.utc).isoformat()}
        if f["action"] == "iperf3":
            scmd = iperf3_server_command(f)
            rc, out = _run(host_argv(hosts[f["server"]], scmd), timeout=30)
            rec["server_command"] = scmd
            rec["server_exit"] = rc
            if rc != 0:
                log.warning("  %s: iperf3 server on %s failed (exit %d): %s",
                            f["id"], f["server"], rc, _tail(out, 2))
        cmd = flow_command(f, local=bool(hosts[f["from"]].get("local")))
        timeout = 60 + 5 * int(f.get("repeat", 1)) + int(f.get("seconds", 0))
        rc, out = _run(host_argv(hosts[f["from"]], cmd), timeout=timeout)
        rec.update({"command": cmd, "exit": rc, "output_tail": _tail(out),
                    "finished_at": datetime.now(timezone.utc).isoformat()})
        # Exit codes are informational: a dropped or refused flow still hits
        # its rule, and nc/ping/dig return non-zero when nothing answers.
        log.info("  %-24s from %-6s exit=%-3d expect=%s", f["id"], f["from"], rc, f["expect"])
        records.append(rec)
    return records


# =============================================================================
# Check
# =============================================================================

def check(plan: Dict[str, Any], diff_path: Path) -> int:
    doc = json.loads(diff_path.read_text(encoding="utf-8"))
    delta: Dict[str, Optional[int]] = {}
    for t in doc.get("transitions") or []:
        d = t.get("hit_count_delta")
        delta[t["rule_id"]] = (delta.get(t["rule_id"]) or 0) + (d or 0)
    expected = sorted({f["expect"] for f in plan["flows"]})
    cold = sorted(set(plan.get("cold") or []))
    failures = 0
    print(f"Compared to: {doc.get('compared_to')}")
    print("Expected hits (delta must be > 0):")
    for rid in expected:
        d = delta.get(rid)
        ok = bool(d and d > 0)
        failures += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {rid:<34} delta={d}")
    print("Cold rules (delta must be 0):")
    for rid in cold:
        d = delta.get(rid)
        ok = not d
        failures += not ok
        print(f"  {'PASS' if ok else 'FAIL'}  {rid:<34} delta={d}")
    others = sorted(r for r, d in delta.items() if d and r not in expected and r not in cold)
    if others:
        print("Other rules with new hits (not in the plan):")
        for rid in others:
            print(f"  NOTE  {rid:<34} delta={delta[rid]}")
    print(f"Result: {'PASS' if failures == 0 else f'FAIL ({failures})'}")
    return 0 if failures == 0 else 1


# =============================================================================
# Main
# =============================================================================

def _setup_logging(log_dir: Optional[Path]) -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(message)s",
                            "%Y-%m-%dT%H:%M:%S")
    handlers: List[logging.Handler] = [logging.StreamHandler()]
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_dir / "generate_lab_traffic.log",
                                            encoding="utf-8"))
    for h in handlers:
        h.setFormatter(fmt)
        root.addHandler(h)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--plan", required=True, type=Path, help="YAML flow plan")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--run", action="store_true", help="send the traffic")
    mode.add_argument("--check", type=Path, metavar="DIFF_JSON",
                      help="grade a rules-usage diff.json against the plan")
    p.add_argument("--only", default="",
                   help="comma-separated flow ids to run (default: all)")
    p.add_argument("--output-base", type=Path, default=None,
                   help="run records root (default: $NSX_LOG_DIR/traffic_runs or "
                        "./nsx_logs/traffic_runs)")
    args = p.parse_args()

    plan = load_plan(args.plan)

    if args.check:
        _setup_logging(None)
        return check(plan, args.check)

    if not args.run:
        _setup_logging(None)
        print(f"Plan {args.plan} for {plan.get('manager')}: "
              f"{len(plan['flows'])} flows, {len(plan.get('cold') or [])} cold rules. "
              "Nothing sent (pass --run).")
        for f in plan["flows"]:
            print(f"  {f['id']:<24} from {f['from']:<6} expect {f['expect']}")
            if f["action"] == "iperf3":
                print(f"      on {f['server']}: {iperf3_server_command(f)}")
            print(f"      {flow_command(f, local=bool(plan['hosts'][f['from']].get('local')))}")
        print("Cold: " + ", ".join(plan.get("cold") or []))
        return 0

    base = args.output_base or Path(os.environ.get("NSX_LOG_DIR", "nsx_logs")) / "traffic_runs"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = base.expanduser().resolve() / ts
    _setup_logging(out_dir / "logs")
    only = {x.strip() for x in args.only.split(",") if x.strip()} or None
    log.info("Traffic run %s, plan %s (%s)", ts, args.plan, plan.get("manager"))
    started = datetime.now(timezone.utc).isoformat()
    records = run_plan(plan, only)
    run = {"plan": str(args.plan.resolve()), "manager": plan.get("manager"),
           "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
           "flows": records, "cold": plan.get("cold") or []}
    (out_dir / "run.json").write_text(json.dumps(run, indent=2), encoding="utf-8")
    log.info("Run record: %s", out_dir / "run.json")
    log.info("Next: wait for the counters to move, then report_rules_usage.py "
             "--compare-to <before report dir> and --check its diff.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
