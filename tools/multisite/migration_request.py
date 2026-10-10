#!/usr/bin/env python3
"""tools/multisite/migration_request.py

Migration requests: from a list of servers to an approved, repeatable change
on NSX (Workflows A, C and D) and Palo Alto (Mike, 2026-10-07).

  request   Build a request from a server list: captures the source
            (read-only), finds every NSX rule the servers use, builds the
            Workflow A bundle, the Workflow C and D siblings and the Palo
            plan, previews them (dry runs) and writes the approver's report.
  preview   Re-run the dry runs of one part (a, c, d, palo or all) and
            refresh the report. Read-only everywhere.
  approve   Record the approval (change reference, approver) against the
            request's fingerprint.
  refresh   At the change window: re-capture the source and rebuild from the
            approved request's own inputs, into runs/<UTC_TS>/. Changes on
            the source since approval are taken and listed (they went through
            their own approval); a change to the request's own servers stops
            the run. --strict stops on any change.
  run       One phase of a refreshed run: a, c, d2a, d3 or palo. Dry run by
            default; --apply writes; --verify checks; --rollback undoes.
  report    Re-render a request's or a run's report from its JSON.

Every NSX write goes through the existing push tools (services.py,
groups.py, policies.py, rules.py) with the same flags the workflow driver
uses; Palo writes go through tools/pan/nsx_pan_mirror.py push. Nothing here
writes to a manager directly, and nothing ever commits on Panorama.

Server list (--servers or --server-list): a VM name, an IP address, or
`name,ip[,ip]` per line. An IP that exactly one VM owns is resolved to that
VM. Docs: docs/multivendor/RUNBOOK_MIGRATION_REQUEST.md.

USAGE
    python tools/multisite/migration_request.py request --source nsx-lm1 \\
        --destination nsx-lm3 --device-group dg-4 --no-tls-verify \\
        --servers "ubuntu22-speedtest-10.6.0.101-ax2001,10.6.1.102"
    python tools/multisite/migration_request.py approve --request <dir> \\
        --change-ref CHG0001 --approved-by "Mike Ferguson"
    python tools/multisite/migration_request.py refresh --request <dir>
    python tools/multisite/migration_request.py run --run <dir>/runs/latest --phase a
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (REPO_ROOT / "app", REPO_ROOT / "tools" / "reports", REPO_ROOT / "tools" / "pan",
           REPO_ROOT / "tools" / "nsx"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from common.bundles import new_run_dir, update_latest            # noqa: E402
from common.fileio import read_json, sha256_file, write_json, write_text  # noqa: E402
from common.logs import setup_logging                             # noqa: E402
from common.paths import repo_relative                            # noqa: E402
from common.timeutil import run_ts, utc_now_iso                   # noqa: E402
from multisite import migration_request as mr                     # noqa: E402

log = logging.getLogger("migration_request")
PY = sys.executable
NSX_CHOICES = ["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5", "nsx-lm6"]
OUT_BASE = REPO_ROOT / "migration_requests"
# Tracked server list (Mike, 2026-10-08), read when no servers are given on the command line.
DEFAULT_SERVER_LIST = REPO_ROOT / "migration_request_servers.txt"
# Destination site (manager alias without "nsx-") -> Workflow D suffix and subnet
# map, as in docs/multivendor/RUNBOOK_MULTIVENDOR_ROLLOUT.md. Other destinations
# take --d-appendix and --subnet-map.
DEST_DEFAULTS = {"lm2": {"d_appendix": "_avs_ips", "subnet_map": "data/subnet_map_lm2.csv"},
                 "lm3": {"d_appendix": "_lm3_ips", "subnet_map": "data/subnet_map_lm3.csv"}}
PHASES = ("a", "c", "d2a", "d3", "palo")


class BuildError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def run_step(label: str, cmd: Sequence[Any], log_dir: Path) -> Dict[str, Any]:
    """Stream one existing tool's output to the terminal and its own log."""
    from nsx.streaming import stream_command
    log_dir.mkdir(parents=True, exist_ok=True)
    step_log = log_dir / f"{label}.log"
    cmd = [str(c) for c in cmd]
    log.info("STEP %s", label)
    log.info("  cmd: %s", " ".join(cmd))
    rc, _ = stream_command(cmd, REPO_ROOT, step_log)
    ok = rc == 0
    log.log(logging.INFO if ok else logging.ERROR, "  %s (rc=%d)  log: %s",
            "OK" if ok else "FAILED", rc, repo_relative(step_log))
    return {"label": label, "cmd": cmd, "rc": rc, "ok": ok, "log": repo_relative(step_log)}


def resolve(alias: str) -> str:
    from nsx.nsx_constants import resolve_manager
    host = resolve_manager(alias)
    if not host:
        raise SystemExit(f"Manager {alias} is not defined (set it in .env).")
    return host


def sib_dir(work: Path, wf: str, src_host: str) -> Path:
    return work / wf / "nsx_sibling_groups" / src_host


def amend_dir(work: Path, wf: str, host: str) -> Path:
    return work / wf / "rules_amend" / host


def load_server_entries(servers: Optional[List[str]], server_list: Optional[str],
                        default: Path = DEFAULT_SERVER_LIST):
    """The request's servers: --server-list and/or --servers as given; with
    neither, the tracked list at the repo root. Returns (entries, warnings,
    sources), each source recorded in request.json (a file with its sha256)."""
    entries: List[mr.Entry] = []
    warnings: List[str] = []
    sources: List[Dict[str, Any]] = []
    path = Path(server_list) if server_list else (None if servers else default)
    if path is not None:
        if not path.is_file():
            raise SystemExit(f"Server list not found: {path}")
        e, w = mr.parse_list_lines(path.read_text(encoding="utf-8").splitlines())
        entries += e
        warnings += [f"{path.name}: {x}" for x in w]
        sources.append({"file": repo_relative(path), "sha256": sha256_file(path), "entries": len(e)})
    if servers:
        tokens = mr.parse_tokens(servers)
        entries += tokens
        sources.append({"command_line": len(tokens)})
    if not entries:
        raise SystemExit(f"No servers given: add them to {repo_relative(default)} (one per line), "
                         "or pass --servers / --server-list.")
    return entries, warnings, sources


def _setting(cli: Optional[str], env_var: str) -> Optional[str]:
    """Command line > .env. "none" on the command line switches it off."""
    if cli is not None:
        return None if cli.strip().lower() == "none" else cli.strip()
    return (os.environ.get(env_var) or "").strip() or None


def _load_record(path: Path, name: str) -> Dict[str, Any]:
    f = path / name
    if not f.is_file():
        raise SystemExit(f"{f} not found.")
    return read_json(f)


# ---------------------------------------------------------------------------
# Build: capture, select, bundle, siblings, Palo plan (shared by request and refresh)
# ---------------------------------------------------------------------------

def build(work: Path, inputs: Dict[str, Any]) -> Dict[str, Any]:
    """Everything a request (or a run) consists of, written under `work`.
    Read-only against the source manager."""
    from nsx.captured_source import validate_capture
    from nsx.vm_rule_data import load_snapshot
    from report_vms_in_rules import analyze

    src, src_host, dom = inputs["source"], inputs["source_host"], inputs["domain_id"]
    logs = work / "logs" / "build"
    errors: List[str] = []
    warnings: List[str] = []

    # 1-2. Two read-only captures of the source, back to back, inside `work`.
    cap_dir = work / "source" / "capture"
    if not run_step("1_capture_source", [PY, "tools/nsx/capture_nsx_state.py", "--source", src,
                                         "--live-query", "--domain-id", dom, "--output-dir", cap_dir,
                                         "--no-flat-exports"], logs)["ok"]:
        raise BuildError("source capture failed; see its log")
    cap_manifest = validate_capture(cap_dir, src_host, dom)
    vm_root = work / "source" / "vm_rules"
    cmd = [PY, "tools/nsx/capture_vm_rule_data.py", "--source", src, "--output-root", vm_root]
    if inputs.get("rate_limit") is not None:
        cmd += ["--rate-limit", inputs["rate_limit"]]
    if not run_step("2_capture_vm_rules", cmd, logs)["ok"]:
        raise BuildError("VM-rule snapshot incomplete; see its log")
    data = load_snapshot(vm_root / src_host)
    cap = mr.load_capture(cap_dir, src_host, dom)

    # 3. Servers and the rules they use.
    entries = [(n, ips) for n, ips in inputs["entries"]]
    merged, notes = mr.merge_entries(entries, data["vms"])
    analysis = analyze(data, merged)
    servers = mr.server_rows(merged, notes, analysis, data)
    ok_ext = {r["external_id"] for r in servers if r["status"] == "ok" and r["external_id"]}
    hits = []
    for h in analysis["hits"]:
        by_side = {e: s for e, s in h["info"]["by_side"].items() if e in ok_ext}
        if by_side:
            hits.append({**h, "info": {**h["info"], "by_side": by_side}})
    selected, excluded = mr.select_rules(hits, cap, inputs["include_default_sections"])
    errors += [f"{x['policy_name']} / {x['rule_name']}: {x['reason']}" for x in excluded if x.get("error")]

    # 4. Workflow A bundle (+ the captured-IP copies Workflow C builds from).
    clo = mr.dependency_closure(cap, selected)
    if clo["unresolved_groups"]:
        errors.append("group references not in the capture: " + ", ".join(clo["unresolved_groups"]))
    bundle = mr.write_bundle(work / "bundle", cap, selected, clo)

    # 5. Workflow C siblings (unchanged builder, source addresses).
    c_sib = sib_dir(work, "c", src_host)
    if not run_step("5_build_c_siblings", [PY, "tools/nsx/build_sibling_groups.py",
                                           "--groups-dir", work / "bundle" / "c_input", "--label", src_host,
                                           "--output-base", work / "c", "--appendix", inputs["c_appendix"],
                                           "--domain-id", dom], logs)["ok"]:
        raise BuildError("Workflow C sibling build failed; see its log")
    c_map = read_json(c_sib / "sibling_map.json")

    # 6. Workflow D: the servers' groups that sit in a rule, servers' addresses only.
    scope, left_out = mr.d_scope(servers, data, cap)
    mr.write_d_input(work / "bundle" / "d_input", cap, scope)
    d_sib = sib_dir(work, "d", src_host)
    if not run_step("6_build_d_siblings", [PY, "tools/nsx/build_sibling_groups.py",
                                           "--groups-dir", work / "bundle" / "d_input", "--label", src_host,
                                           "--output-base", work / "d", "--appendix", inputs["d_appendix"],
                                           "--csv-remap", REPO_ROOT / inputs["subnet_map"],
                                           "--skip-segment-groups", "--domain-id", dom], logs)["ok"]:
        raise BuildError("Workflow D sibling build failed; see its log")
    d_map = read_json(d_sib / "sibling_map.json")

    # New addresses per server, through the same loader the D build uses.
    from nsx_group_ip_remap_offline import _load_mapping_csv
    table, _invalid = _load_mapping_csv(REPO_ROOT / inputs["subnet_map"], bidirectional=False)
    for r in servers:
        if r["status"] == "ok":
            r["new_ips"] = {ip: list(table.map_token(ip)[0] or []) for ip in r["ips"]}
            unmapped = [ip for ip, m in r["new_ips"].items() if not m]
            if unmapped:
                r["problems"].append(f"not covered by {inputs['subnet_map']}: " + ", ".join(unmapped))

    by_id = {s["id"]: (p, s) for p, s in scope.items()}
    d_rows = []
    for row in d_map.get("map") or []:
        _path, slot = by_id.get(row["original_id"], (None, {"servers": {}}))
        pairs = {p[0]: p[1] for p in row.get("ip_pairs") or []}
        for server, ips in sorted(slot["servers"].items()):
            for ip in ips:
                d_rows.append({"sibling_id": row["sibling_id"],
                               "original": row.get("original_display_name") or row["original_id"],
                               "server": server, "source_ip": ip, "mapped_ip": ", ".join(pairs.get(ip) or [])})
    d_no = list(left_out) + [{"group": x.get("original_display_name") or x["original_id"], "reason": x["reason"]}
                             for x in d_map.get("no_sibling") or []]

    c_rows = [{"sibling_id": r["sibling_id"], "original": r.get("original_display_name") or r["original_id"],
               "ips": r.get("ips_source") or []} for r in c_map.get("map") or []]
    c_amend = mr.amendments(mr.selected_rules(cap, selected), c_map)
    d_amend = mr.amendments(mr.source_rules(cap), d_map)

    # 7. Palo plan, from the same capture.
    palo, plan = None, None
    if inputs["palo"]["enabled"]:
        palo, plan = build_palo(work, inputs, cap, selected, data, c_sib, c_map, d_sib, d_map, logs)
        if plan["counts"]["errors"]:
            errors.append(f"Palo plan has {plan['counts']['errors']} error(s); see {palo['plan_md']}")

    gnames = {p: g.get("display_name") or g.get("id") for p, g in data["groups_by_path"].items()}
    gnames.update({p: g.get("display_name") or g.get("id") for p, g in cap.groups.items()})
    rec: Dict[str, Any] = {
        "schema": mr.SCHEMA, "request_id": inputs["request_id"], "created_at": utc_now_iso(),
        "captured_at": cap_manifest.get("captured_at"), "snapshot_at": data.get("collected_at"),
        "inputs": inputs, "servers": servers, "rules": selected, "excluded_rules": excluded,
        "closure": clo, "bundle": bundle, "c_siblings": c_rows, "c_amend": c_amend,
        "d_siblings": d_rows, "d_no_sibling": d_no, "d_amend": d_amend, "palo": palo,
        "group_names": gnames, "errors": errors, "warnings": warnings,
        "paths": {"record": repo_relative(work), "bundle": repo_relative(work / "bundle"),
                  "c": repo_relative(c_sib), "d": repo_relative(d_sib)},
    }
    attention = [r for r in servers if r["status"] != "ok" or r["problems"]]
    rec["summary"] = {"servers": len(servers), "servers_ok": len(servers) - len(attention),
                      "servers_attention": len(attention), "rules": len(selected),
                      "policies": bundle["policies"], "groups": bundle["groups"],
                      "services": bundle["services"], "c_siblings": len(c_rows),
                      "d_siblings": len(d_map.get("map") or []), "d_rules_amended": len(d_amend),
                      "palo_writes": len(plan["writes"]) if plan else 0}
    rec["model"] = mr.build_model(rec, cap, clo, c_map, d_map, plan)
    return rec


def build_palo(work: Path, inputs: Dict[str, Any], cap: mr.CaptureView, selected: List[Dict[str, Any]],
               data: Dict[str, Any], c_sib: Path, c_map: Dict[str, Any], d_sib: Path,
               d_map: Dict[str, Any], logs: Path):
    """The Palo plan for exactly the selected rules, built by the same mapping
    code as `nsx_pan_mirror.py plan-rules`, from the request's own capture.
    Built-in NSX services and context profiles are not in a capture, so they
    are read once (GET only) and saved beside the plan."""
    from multisite.pan_mirror import MirrorOptions
    from multisite.pan_rules import RuleOptions, build_rule_mirror
    from nsx.cli_bootstrap import init_cli
    from nsx.nsx_policy_client import NsxPolicyClient
    from nsx_pan_mirror import render_rules_md

    p = inputs["palo"]
    pdir = work / "palo"
    pdir.mkdir(parents=True, exist_ok=True)
    init_cli()
    client = NsxPolicyClient(inputs["source_host"])
    log.info("Reading all services and context profiles from %s (read-only) for the Palo plan",
             inputs["source_host"])
    services = client.list_services()
    ctx = client._get_all_results(client._policy_path("/context-profiles"))
    write_json(pdir / "nsx_services_all.json", services)
    write_json(pdir / "nsx_context_profiles.json", ctx)

    pol_ids: List[str] = []
    for s in selected:
        if s["policy_id"] not in pol_ids:
            pol_ids.append(s["policy_id"])
    # Only the selected rules go in, so a rule id shared by two policies can
    # never pull in the other one.
    policies = [{**cap.policies[pid], "rules": [cap.rules[(pid, s["rule_id"])] for s in selected
                                                if s["policy_id"] == pid]} for pid in pol_ids]
    bundles = [{"path": repo_relative(c_sib), "sibling_map": c_map},
               {"path": repo_relative(d_sib), "sibling_map": d_map}]
    opts = MirrorOptions(device_group=p["device_group"], object_location=p["object_location"])
    ropts = RuleOptions(zone_from=p["zone_from"], zone_to=p["zone_to"], rulebase=p["rulebase"],
                        profile_group=p["profile_group"], log_setting=p["log_setting"],
                        group_suffix=inputs["c_appendix"])
    plan = build_rule_mirror(policies, list(cap.groups.values()), services, bundles, data["vms"],
                             opts, ropts, context_profiles=ctx)
    meta = {"source": inputs["source_host"], "nsx_source": f"{inputs['source_host']} (request capture)",
            "vm_source": inputs["source_host"], "generated_at": utc_now_iso(),
            "bundles": [b["path"] for b in bundles]}
    plan["meta"] = meta
    write_json(pdir / "plan.json", plan)
    write_text(pdir / "plan.md", render_rules_md(plan, meta))

    def svc(e: Dict[str, Any]) -> str:
        apps = [a for a in e["application"]["member"] if a != "any"]
        return ", ".join(e["service"]["member"]) + (f" (apps: {', '.join(apps)})" if apps else "")

    summary = {
        "device_group": p["device_group"], "object_location": p["object_location"],
        "rulebase": p["rulebase"], "plan_md": repo_relative(pdir / "plan.md"), "counts": plan["counts"],
        "rules": [{"name": r["name"], "action": r["entry"]["action"]
                   + (" (disabled)" if r["entry"].get("disabled") == "yes" else ""),
                   "source": ", ".join(r["entry"]["source"]["member"]),
                   "destination": ", ".join(r["entry"]["destination"]["member"]),
                   "service": svc(r["entry"]), "nsx": f"{r['nsx_policy']} / {r['nsx_rule']}"}
                  for r in plan["rules"]],
        "skipped": [[f"{x['nsx_policy']} / {x['nsx_rule']}",
                     ("skipped: " + x["skipped"]) if x["skipped"] else "narrower: " + "; ".join(x["dropped"])]
                    for x in plan["rule_report"] if x["skipped"] or x["dropped"]],
        "findings": [[f["severity"], f["code"], f.get("group") or f.get("vm") or f.get("object") or "",
                      f["detail"]] for f in plan["findings"]],
        "groups": [{"name": g["name"], "nsx": g.get("nsx_original") or g.get("nsx_group") or "",
                    "members": len(g["members"])} for g in plan["address_groups"]],
    }
    return summary, plan


# ---------------------------------------------------------------------------
# Phase steps (the same commands tools/nsx/run_workflow.py runs, on these paths)
# ---------------------------------------------------------------------------

def phase_steps(work: Path, inputs: Dict[str, Any], phase: str, apply: bool) -> List[Dict[str, Any]]:
    a = ["--apply"] if apply else []
    src, dst = inputs["source"], inputs["destination"]
    src_host, dst_host = inputs["source_host"], inputs["destination_host"]
    b = work / "bundle"
    if phase == "a":
        return [
            {"label": "a1_services", "roots": [b / "services"],
             "cmd": [PY, "tools/nsx/services.py", "push", "--target", dst,
                     "--services-dir", b / "services" / "services"] + a},
            {"label": "a2_groups", "roots": [b / "groups"],
             "cmd": [PY, "tools/nsx/groups.py", "push", "--target", dst, "--groups-dir", b / "groups" / "groups",
                     "--segments-mode", "strip"] + a},
            {"label": "a3_policies", "roots": [b / "policies"],
             "cmd": [PY, "tools/nsx/policies.py", "push", "--target", dst,
                     "--policies-dir", b / "policies" / "security-policies"] + a},
            {"label": "a4_rules", "roots": [b / "rules"],
             "cmd": [PY, "tools/nsx/rules.py", "push", "--target", dst,
                     "--rules-dir", b / "rules" / "security-policies"] + a},
        ]
    if phase == "c":
        sib, amend = sib_dir(work, "c", src_host), amend_dir(work, "c", dst_host)
        return [
            {"label": "c3_siblings", "roots": [sib],
             "cmd": [PY, "tools/nsx/groups.py", "push", "--target", dst, "--groups-dir", sib / "groups",
                     "--skip-no-ip-change"] + a},
            {"label": "c5_amend_refs", "roots": [amend],
             "cmd": [PY, "tools/nsx/rules.py", "amend-refs", "--target", dst,
                     "--sibling-map", sib / "sibling_map.json", "--reports-dir", amend / "push_report"] + a},
        ]
    sib = sib_dir(work, "d", src_host)
    if phase == "d2a":
        return [{"label": "d2a_siblings", "roots": [sib],
                 "cmd": [PY, "tools/nsx/groups.py", "push", "--target", src, "--groups-dir", sib / "groups",
                         "--skip-no-ip-change"] + a}]
    if phase == "d3":
        amend = amend_dir(work, "d", src_host)
        return [{"label": "d3_amend_refs", "roots": [amend],
                 "cmd": [PY, "tools/nsx/rules.py", "amend-refs", "--target", src,
                         "--sibling-map", sib / "sibling_map.json", "--reports-dir", amend / "push_report"] + a}]
    raise ValueError(phase)


def rollback_steps(work: Path, inputs: Dict[str, Any], phase: str, apply: bool) -> List[Dict[str, Any]]:
    """Reverse order. --allow-delete where the push created objects, exactly
    as the workflow driver passes it."""
    a = ["--apply"] if apply else []
    src, dst = inputs["source"], inputs["destination"]
    b = work / "bundle"

    def groups_revert(target: str, reports: Path) -> List[Any]:
        return [PY, "tools/nsx/groups.py", "revert", "--target", target, "--reports-dir", reports,
                "--allow-delete"] + a

    def rules_revert(target: str, reports: Path) -> List[Any]:
        return [PY, "tools/nsx/rules.py", "revert", "--target", target, "--reports-dir", reports] + a

    if phase == "a":
        return [{"label": "a4_rules_revert", "cmd": rules_revert(dst, b / "rules" / "push_report")},
                {"label": "a3_policies_revert",
                 "cmd": [PY, "tools/nsx/policies.py", "revert", "--target", dst,
                         "--reports-dir", b / "policies" / "push_report"] + a},
                {"label": "a2_groups_revert", "cmd": groups_revert(dst, b / "groups" / "push_report")},
                {"label": "a1_services_revert",
                 "cmd": [PY, "tools/nsx/services.py", "revert", "--target", dst,
                         "--reports-dir", b / "services" / "push_report"] + a}]
    if phase == "c":
        return [{"label": "c5_amend_revert",
                 "cmd": rules_revert(dst, amend_dir(work, "c", inputs["destination_host"]) / "push_report")},
                {"label": "c3_siblings_revert",
                 "cmd": groups_revert(dst, sib_dir(work, "c", inputs["source_host"]) / "push_report")}]
    if phase == "d2a":
        return [{"label": "d2a_siblings_revert",
                 "cmd": groups_revert(src, sib_dir(work, "d", inputs["source_host"]) / "push_report")}]
    return [{"label": "d3_amend_revert",
             "cmd": rules_revert(src, amend_dir(work, "d", inputs["source_host"]) / "push_report")}]


def palo_flags(args: argparse.Namespace) -> List[str]:
    out: List[str] = []
    if getattr(args, "no_tls_verify", False):
        out.append("--no-tls-verify")
    if getattr(args, "palo_host", None):
        out += ["--host", args.palo_host]
    return out


def cli_flag(inputs: Dict[str, Any]) -> List[str]:
    """The request's --palo-cli choice, passed to the Palo push dry run."""
    return [] if (inputs.get("palo") or {}).get("cli_commands", True) else ["--no-cli-commands"]


def paste_files(work: Path, dry_manifest: Path, inputs: Dict[str, Any]) -> Dict[str, Any]:
    """Paths of the paste-ready CLI text a Palo dry run wrote, if it wrote any."""
    if not (inputs.get("palo") or {}).get("cli_commands", True):
        return {}
    stem = dry_manifest.name[:-len(".json")]
    dated = work / "palo" / f"{stem}_set_commands.txt"
    if not dated.is_file():
        return {}
    return {"set_commands": repo_relative(dated),
            "delete_commands": repo_relative(work / "palo" / f"{stem}_delete_commands.txt"),
            "set_commands_latest": repo_relative(work / "palo" / "pan_set_commands.txt")}


def newest(directory: Path, pattern: str) -> Optional[Path]:
    found = sorted(directory.glob(pattern))
    return found[-1] if found else None


# ---------------------------------------------------------------------------
# Previews (dry runs) for the request report
# ---------------------------------------------------------------------------

def _rows(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    doc = read_json(path)
    return doc if isinstance(doc, list) else (doc.get("rows") or [])


def run_previews(work: Path, rec: Dict[str, Any], parts: Sequence[str],
                 args: argparse.Namespace) -> Dict[str, Any]:
    inputs = rec["inputs"]
    pfile = work / "preview" / "previews.json"
    previews = read_json(pfile) if pfile.is_file() else {}
    logs = work / "logs" / f"preview_{run_ts()}"
    src_host = inputs["source_host"]
    for part in parts:
        if part == "a":
            recs = [run_step(s["label"], s["cmd"], logs) for s in phase_steps(work, inputs, "a", False)]
            b = work / "bundle"
            previews["a"] = {k: mr.preview_counts(_rows(b / k / "push_report" / f"{k}.json"))
                             for k in ("services", "groups", "policies", "rules")}
            previews["a"]["ok"] = all(r["ok"] for r in recs)
        elif part == "c":
            recs = [run_step(s["label"], s["cmd"], logs) for s in phase_steps(work, inputs, "c", False)[:1]]
            previews["c"] = {"siblings": mr.preview_counts(
                _rows(sib_dir(work, "c", src_host) / "push_report" / "groups.json")),
                "ok": all(r["ok"] for r in recs)}
        elif part == "d":
            recs = [run_step(s["label"], s["cmd"], logs)
                    for ph in ("d2a", "d3") for s in phase_steps(work, inputs, ph, False)]
            previews["d"] = {"siblings": mr.preview_counts(
                _rows(sib_dir(work, "d", src_host) / "push_report" / "groups.json")),
                "amend": mr.preview_counts(
                    _rows(amend_dir(work, "d", src_host) / "push_report" / "amend_refs.json")),
                "ok": all(r["ok"] for r in recs)}
        elif part == "palo" and rec.get("palo"):
            plan_path = work / "palo" / "plan.json"
            r = run_step("palo_push_dryrun", [PY, "tools/pan/nsx_pan_mirror.py", "push", "--plan", plan_path,
                                              "--allow-plan-errors"] + palo_flags(args)
                         + cli_flag(inputs), logs)
            doc_path = newest(work / "palo", "push_*_dryrun.json")
            if r["ok"] and doc_path:
                doc = read_json(doc_path)
                plan = read_json(plan_path)
                previews["palo"] = {"panorama": doc.get("panorama"), "created_at": doc.get("created_at"),
                                    "summary": doc.get("summary") or {}, "report": repo_relative(doc_path),
                                    "member_gaps": mr._palo_existing_gaps(doc, plan),
                                    "would_create": [{"kind": x["kind"], "name": x["name"]}
                                                     for x in doc.get("results") or []
                                                     if x.get("status") == "would_create"]}
                previews["palo"].update(paste_files(work, doc_path, inputs))
            else:
                previews["palo"] = None
                log.error("Palo preview failed (device group or profiles missing, or login); see %s", r["log"])
    write_json(pfile, previews)
    return previews


def render(work: Path, rec: Dict[str, Any], title: str, out_name: str) -> Path:
    pfile = work / "preview" / "previews.json"
    previews = read_json(pfile) if pfile.is_file() else {}
    approval = work / "approval.json"
    if approval.is_file() and "approval" not in rec:
        rec = {**rec, "approval": read_json(approval)}
    path = work / out_name
    write_text(path, mr.render_request_md(rec, previews, title=title))
    return path


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_request(args: argparse.Namespace) -> int:
    from palo.pan_env import load_repo_env
    load_repo_env()
    entries, warnings, sources = load_server_entries(args.servers, args.server_list)
    if args.source == args.destination:
        raise SystemExit("Source and destination are the same manager.")
    dflt = DEST_DEFAULTS.get(args.destination.replace("nsx-", "", 1), {})
    d_app = args.d_appendix or dflt.get("d_appendix")
    smap = args.subnet_map or dflt.get("subnet_map")
    if not d_app or not smap:
        raise SystemExit(f"No defaults for {args.destination}: pass --d-appendix and --subnet-map.")
    c_app = args.c_appendix or os.environ.get("OBJECT_APPENDIX") or "_np_ips"
    if c_app == d_app:
        raise SystemExit(f"The C and D suffixes must differ (both {c_app}).")
    smap_path = (REPO_ROOT / smap).resolve()
    if not smap_path.is_file():
        raise SystemExit(f"Subnet map not found: {smap}")
    if not args.no_palo and not args.device_group:
        raise SystemExit("Name the Panorama device group (--device-group dg-4), or pass --no-palo.")

    work = new_run_dir(OUT_BASE / f"{args.source}_to_{args.destination}")
    setup_logging("migration_request", work / "logs", run_ts=work.name)
    for w in warnings:
        log.warning("server list: %s", w)
    inputs = {
        "request_id": f"{args.source}_to_{args.destination}/{work.name}", "name": args.name,
        "source": args.source, "source_host": resolve(args.source),
        "destination": args.destination, "destination_host": resolve(args.destination),
        "domain_id": args.domain_id, "entries": [[n, ips] for n, ips in entries],
        "server_sources": sources,
        "include_default_sections": args.include_default_sections,
        "c_appendix": c_app, "d_appendix": d_app,
        "subnet_map": repo_relative(smap_path), "subnet_map_sha256": sha256_file(smap_path),
        "rate_limit": args.rate_limit,
        "palo": {"enabled": not args.no_palo, "device_group": args.device_group,
                 "object_location": args.object_location, "rulebase": args.rulebase,
                 "zone_from": args.zone_from, "zone_to": args.zone_to,
                 "profile_group": _setting(args.profile_group, "PANORAMA_SECURITY_PROFILE_GROUP"),
                 "log_setting": _setting(args.log_setting, "PANORAMA_LOG_FORWARDING_PROFILE"),
                 "cli_commands": args.palo_cli},
    }
    write_text(work / "servers.txt", "".join(f"{n}{',' + ','.join(ips) if ips else ''}\n" for n, ips in entries))
    log.info("=" * 70)
    log.info("MIGRATION REQUEST %s", inputs["request_id"])
    log.info("  %s -> %s, %d server entr%s, Palo %s", args.source, args.destination, len(entries),
             "y" if len(entries) == 1 else "ies", args.device_group if not args.no_palo else "off")
    log.info("=" * 70)
    try:
        rec = build(work, inputs)
    except BuildError as exc:
        log.error("Request not built: %s", exc)
        return 1
    rec["warnings"] = warnings + rec["warnings"]
    write_json(work / "request.json", rec)
    if not args.no_preview:
        parts = ["a", "c", "d"] + (["palo"] if rec.get("palo") else [])
        run_previews(work, rec, parts, args)
    path = render(work, rec, "Migration request", "request.md")
    update_latest(work.parent, work)
    log.info("Request: %s", repo_relative(path))
    pp = (read_json(work / "preview" / "previews.json") if (work / "preview" / "previews.json").is_file()
          else {}).get("palo") or {}
    if pp.get("set_commands"):
        log.info("Palo Alto paste file from the dry run (%d missing object(s)): %s",
                 (pp.get("summary") or {}).get("would_create", 0), pp["set_commands"])
    log.info("Fingerprint: %s", rec["model"]["digest"])
    for e in rec["errors"]:
        log.error("  %s", e)
    print(path)
    return 1 if rec["errors"] else 0


def _request_dir(path: str) -> Path:
    p = Path(path).resolve()
    if p.name == "latest":
        p = p.resolve()
    if not (p / "request.json").is_file():
        raise SystemExit(f"{p} is not a request directory (no request.json).")
    return p


def cmd_preview(args: argparse.Namespace) -> int:
    from palo.pan_env import load_repo_env
    load_repo_env()
    work = _request_dir(args.request)
    setup_logging("migration_request_preview", work / "logs", run_ts=run_ts())
    rec = read_json(work / "request.json")
    parts = ["a", "c", "d", "palo"] if args.part == "all" else [args.part]
    run_previews(work, rec, parts, args)
    path = render(work, rec, "Migration request", "request.md")
    print(path)
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    work = _request_dir(args.request)
    rec = read_json(work / "request.json")
    if rec["errors"] and not args.accept_errors:
        for e in rec["errors"]:
            log.error("  %s", e)
        log.error("The request has errors; fix and re-request, or pass --accept-errors.")
        return 2
    approval = {"request_id": rec["request_id"], "digest": rec["model"]["digest"],
                "change_ref": args.change_ref, "approved_by": args.approved_by,
                "approved_at": utc_now_iso(), "accepted_errors": rec["errors"] if args.accept_errors else []}
    write_json(work / "approval.json", approval)
    render(work, rec, "Migration request", "request.md")
    log.info("Approved %s under %s by %s (fingerprint %s)", rec["request_id"], args.change_ref,
             args.approved_by, approval["digest"])
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    from palo.pan_env import load_repo_env
    load_repo_env()
    req = _request_dir(args.request)
    rec = read_json(req / "request.json")
    approval_path = req / "approval.json"
    if not approval_path.is_file():
        raise SystemExit("The request is not approved yet (run `approve`).")
    approval = read_json(approval_path)
    if approval.get("digest") != rec["model"]["digest"]:
        raise SystemExit("request.json changed after approval (fingerprint differs); re-approve.")
    work = new_run_dir(req / "runs")
    setup_logging("migration_request_refresh", work / "logs", run_ts=work.name)
    inputs = dict(rec["inputs"])
    problems: List[str] = []
    smap = REPO_ROOT / inputs["subnet_map"]
    if not smap.is_file() or sha256_file(smap) != inputs["subnet_map_sha256"]:
        problems.append(f"subnet map {inputs['subnet_map']} changed since approval")
    try:
        new = build(work, inputs)
    except BuildError as exc:
        log.error("Run not built: %s", exc)
        return 1
    new["approval"] = approval
    write_json(work / "request.json", new)
    delta = mr.compare_models(rec["model"], new["model"])
    problems += mr.server_gate(rec["model"], new["model"])
    blocked = bool(problems) or (args.strict and bool(delta)) or bool(new["errors"])
    run = {"request_id": rec["request_id"], "request_dir": repo_relative(req), "created_at": new["created_at"],
           "captured_at": new["captured_at"], "source_host": inputs["source_host"],
           "approved_digest": rec["model"]["digest"], "digest": new["model"]["digest"],
           "approval": approval, "strict": args.strict, "delta": delta,
           "gate": {"passed": not blocked, "problems": problems, "errors": new["errors"]}}
    write_json(work / "run.json", run)
    write_text(work / "delta.md", mr.render_delta_md(run, delta, problems + new["errors"], args.strict))
    render(work, new, "Implementation plan", "implementation.md")
    update_latest(work.parent, work)
    log.info("Run: %s", repo_relative(work))
    log.info("Changes since approval: %s", ", ".join(f"{k} ({sum(map(len, v.values()))})"
                                                      for k, v in delta.items()) or "none")
    if blocked:
        for p in problems + new["errors"]:
            log.error("  %s", p)
        log.error("STOPPED: see %s. Nothing will be pushed from this run.", repo_relative(work / "delta.md"))
        print(work / "delta.md")
        return 2
    log.info("Gate passed. Next: run --run %s --phase a (dry run)", repo_relative(work))
    print(work / "delta.md")
    return 0


def _run_dir(path: str) -> Path:
    p = Path(path).resolve()
    if not (p / "run.json").is_file():
        raise SystemExit(f"{p} is not a run directory (no run.json); create one with `refresh`.")
    return p


def _bundle_presence(work: Path, inputs: Dict[str, Any], out_dir: Path) -> Dict[str, Any]:
    """Read-only: every object of the bundle exists on the destination."""
    from nsx.cli_bootstrap import init_cli
    from nsx.nsx_policy_client import NsxPolicyClient
    from common.fileio import read_yaml
    init_cli()
    client = NsxPolicyClient(inputs["destination_host"])
    dom = inputs["domain_id"]
    b = work / "bundle"
    have_services = {s["id"] for s in client.list_services()}
    have_groups = {g["id"] for g in client.list_groups(domain_id=dom)}
    have_policies = {p["id"] for p in client.list_security_policies(domain_id=dom)}
    missing: Dict[str, List[str]] = {"services": [], "groups": [], "policies": [], "rules": []}
    for f in sorted((b / "services" / "services").glob("*.yaml")):
        sid = read_yaml(f)["id"]
        if sid not in have_services:
            missing["services"].append(sid)
    for f in sorted((b / "groups" / "groups").glob("*.yaml")):
        gid = read_yaml(f)["id"]
        if gid not in have_groups:
            missing["groups"].append(gid)
    rules_have: Dict[str, set] = {}
    for pdir in sorted(d for d in (b / "rules" / "security-policies").iterdir() if d.is_dir()):
        pid = read_yaml(pdir / "policy.yaml")["id"]
        if pid not in have_policies:
            missing["policies"].append(pid)
            continue
        if pid not in rules_have:
            rules_have[pid] = {r["id"] for r in client.list_security_rules(pid, domain_id=dom)}
        for f in sorted((pdir / "rules").glob("*.yaml")):
            rid = read_yaml(f)["id"]
            if rid not in rules_have[pid]:
                missing["rules"].append(f"{pid}/{rid}")
    doc = {"checked_at": utc_now_iso(), "destination": inputs["destination_host"], "missing": missing,
           "ok": not any(missing.values())}
    write_json(out_dir / "bundle_presence.json", doc)
    log.info("Bundle presence on %s: %s", inputs["destination_host"],
             "every object present" if doc["ok"] else
             "; ".join(f"{k} missing: {', '.join(v)}" for k, v in missing.items() if v))
    return doc


def cmd_run(args: argparse.Namespace) -> int:
    from palo.pan_env import load_repo_env
    load_repo_env()
    work = _run_dir(args.run)
    run = read_json(work / "run.json")
    rec = read_json(work / "request.json")
    inputs = rec["inputs"]
    if args.verify and args.rollback:
        raise SystemExit("--verify and --rollback are separate actions.")
    action = "verify" if args.verify else ("rollback" if args.rollback else "push")
    mode = "verify" if args.verify else ("apply" if args.apply else "dryrun")
    if args.rollback:
        mode = f"rollback_{mode}"
    if action == "push" and args.apply and not run["gate"]["passed"]:
        log.error("This run did not pass the approval gate (%s); nothing is pushed.",
                  repo_relative(work / "delta.md"))
        return 2
    if args.phase == "palo" and not rec.get("palo"):
        raise SystemExit("This request has no Palo plan (it was built with --no-palo).")
    ts = run_ts()
    logs = work / "logs" / f"{ts}_{args.phase}_{mode}"
    setup_logging("migration_request_run", logs, run_ts=ts)
    out_dir = work / "report" / args.phase / mode
    out_dir.mkdir(parents=True, exist_ok=True)
    state_path = work / "phases.json"
    state = read_json(state_path) if state_path.is_file() else {}
    since = utc_now_iso()[:19]
    log.info("=" * 70)
    log.info("RUN %s  phase %s  %s", rec["request_id"], args.phase, mode.upper())
    log.info("  %s -> %s   run dir %s", inputs["source"], inputs["destination"], repo_relative(work))
    log.info("=" * 70)
    order = {"c": "a", "d3": "d2a"}
    if action == "push" and args.apply and args.phase in order and \
            not (state.get(order[args.phase]) or {}).get("apply_ok"):
        log.warning("Phase %s has not been applied in this run yet; %s normally follows it.",
                    order[args.phase], args.phase)

    records: List[Dict[str, Any]] = []
    roots: List[Path] = []
    if args.phase == "palo":
        plan = work / "palo" / "plan.json"
        if action == "rollback":
            manifest = newest(work / "palo", "push_*_apply.json")
            if manifest is None:
                raise SystemExit("No Palo apply in this run to roll back.")
            cmd = [PY, "tools/pan/nsx_pan_mirror.py", "revert", "--manifest", manifest] + palo_flags(args)
            records.append(run_step("palo_revert", cmd + (["--apply"] if args.apply else []), logs))
        else:
            cmd = [PY, "tools/pan/nsx_pan_mirror.py", "push", "--plan", plan] + palo_flags(args) + cli_flag(inputs)
            if args.allow_plan_errors:
                cmd.append("--allow-plan-errors")
            apply = args.apply and action == "push"
            records.append(run_step("palo_push" if apply else "palo_push_dryrun",
                                    cmd + (["--apply"] if apply else []), logs))
            doc_path = newest(work / "palo", f"push_*_{'apply' if apply else 'dryrun'}.json")
            if doc_path is not None:
                doc = read_json(doc_path)
                if not apply:
                    pf = paste_files(work, doc_path, inputs)
                    if pf:
                        log.info("Palo Alto paste file from this dry run (%d missing object(s)): %s",
                                 (doc.get("summary") or {}).get("would_create", 0), pf["set_commands"])
                gaps = mr._palo_existing_gaps(doc, read_json(plan))
                for g in gaps:
                    log.warning("Address group %s already on Panorama lacks %s member(s): %s "
                                "(the push never edits an existing object; add them by hand)", *g)
                if action == "verify":
                    left = (doc.get("summary") or {}).get("would_create", 0)
                    ok = not left and not gaps
                    log.log(logging.INFO if ok else logging.ERROR, "Palo verify: %s",
                            "every planned object is on Panorama" if ok else
                            f"{left} object(s) still missing, {len(gaps)} group(s) lacking members")
                    records[-1]["ok"] = records[-1]["ok"] and ok
    else:
        if action == "verify":
            steps = verify_steps(work, inputs, args.phase, out_dir)
        elif action == "rollback":
            steps = rollback_steps(work, inputs, args.phase, args.apply)
        else:
            steps = phase_steps(work, inputs, args.phase, args.apply)
        for st in steps:
            if st.get("inproc"):
                doc = _bundle_presence(work, inputs, out_dir)
                records.append({"label": st["label"], "ok": doc["ok"], "rc": 0 if doc["ok"] else 1})
                continue
            rec_step = run_step(st["label"], st["cmd"], logs)
            records.append(rec_step)
            roots += st.get("roots") or []
            if rec_step["rc"] == 130:
                log.warning("Operator stopped %s; remaining steps will not run.", st["label"])
                break
            if not rec_step["ok"]:
                log.error("Stopping: %s failed.", st["label"])
                break
        wf = "a" if args.phase == "a" else ("c" if args.phase == "c" else "d")
        label = f"{args.phase.upper()} {mode.upper()}: {inputs['source']} to {inputs['destination']}"
        if action == "push":
            cmd = [PY, "tools/nsx/report_avs_run.py", "--out-dir", out_dir, "--since", since,
                   "--workflow", wf, "--label", f"Request {rec['request_id']} {label}"]
            for r in dict.fromkeys(roots):
                cmd += ["--report-root", r]
            run_step("report", cmd, logs)
        elif action == "rollback":
            cmd = [PY, "tools/nsx/report_rollback.py", "--out-dir", out_dir, "--since", since,
                   "--label", f"Request {rec['request_id']} {label}"]
            for st in steps:
                c = [str(x) for x in st["cmd"]]
                if "--reports-dir" in c:
                    cmd += ["--report-root", c[c.index("--reports-dir") + 1]]
            run_step("report", cmd, logs)

    ok = bool(records) and all(r["ok"] for r in records)
    slot = state.setdefault(args.phase, {})
    slot[mode] = {"at": utc_now_iso(), "ok": ok}
    if mode == "apply":
        slot["apply_ok"] = ok
    if mode == "rollback_apply" and ok:
        slot["apply_ok"] = False
    write_json(state_path, state)
    write_json(logs / "manifest.json", {"request_id": rec["request_id"], "phase": args.phase, "action": action,
                                        "mode": mode, "steps": records, "report_dir": repo_relative(out_dir),
                                        "ok": ok})
    log.info("=" * 70)
    log.info("Phase %s %s: %s. Report: %s", args.phase, mode, "OK" if ok else "FAILED",
             repo_relative(out_dir))
    if action == "push" and not args.apply and ok:
        log.info("Dry run only. Re-run with --apply to write.")
    return 0 if ok else 1


def verify_steps(work: Path, inputs: Dict[str, Any], phase: str, out_dir: Path) -> List[Dict[str, Any]]:
    src, dst = inputs["source"], inputs["destination"]
    cap = work / "source" / "capture"
    if phase in ("a", "c"):
        cmd = [PY, "tools/nsx/verify_avs_run.py", "--source", src, "--target", dst, "--report-dir", out_dir,
               "--domain-id", inputs["domain_id"], "--source-capture", cap, "--skip-object-parity"]
        steps = []
        if phase == "a":
            steps.append({"label": "a_bundle_presence", "inproc": True})
        else:
            cmd += ["--sibling-map", sib_dir(work, "c", inputs["source_host"]) / "sibling_map.json"]
        return steps + [{"label": f"{phase}_verify", "cmd": cmd}]
    sib = sib_dir(work, "d", inputs["source_host"])
    base = newest(sib / "push_report" / "baselines", "*_target_baseline.json")
    if base is None:
        raise SystemExit("No d2a apply baseline in this run yet; apply d2a first.")
    return [{"label": f"{phase}_validate",
             "cmd": [PY, "tools/nsx/validate_wf_d.py", "--target", src, "--baseline", base,
                     "--sibling-map", sib / "sibling_map.json", "--output-base", out_dir]}]


def cmd_report(args: argparse.Namespace) -> int:
    p = Path(args.dir).resolve()
    if (p / "run.json").is_file():
        rec = read_json(p / "request.json")
        run = read_json(p / "run.json")
        write_text(p / "delta.md", mr.render_delta_md(run, run["delta"],
                                                       run["gate"]["problems"] + run["gate"]["errors"],
                                                       run["strict"]))
        print(render(p, rec, "Implementation plan", "implementation.md"))
    else:
        p = _request_dir(args.dir)
        print(render(p, read_json(p / "request.json"), "Migration request", "request.md"))
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n\n", 1)[1])
    sub = p.add_subparsers(dest="cmd", required=True)

    def palo_conn(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--no-tls-verify", action="store_true",
                        help="Panorama with the PAN-OS default self-signed certificate (lab).")
        sp.add_argument("--palo-host", default=None, help="Panorama host override (default: .env).")

    rq = sub.add_parser("request", help="Build a request from a server list (read-only).")
    rq.add_argument("--source", required=True, choices=NSX_CHOICES)
    rq.add_argument("--destination", required=True, choices=NSX_CHOICES)
    rq.add_argument("--servers", action="append", metavar="LIST",
                    help="Comma-separated VM names and/or IP addresses; each token is one server. Repeatable.")
    rq.add_argument("--server-list", metavar="FILE",
                    help="One server per line: name, ip, or name,ip[,ip]. # comments allowed. "
                         f"Default when neither this nor --servers is given: {DEFAULT_SERVER_LIST.name} "
                         "(tracked, at the repo root).")
    rq.add_argument("--name", default=None, help="Short label shown in the report title.")
    rq.add_argument("--domain-id", default="default")
    rq.add_argument("--include-default-sections", action="store_true",
                    help="Also copy rules in NSX's default sections (off: they exist on every manager).")
    rq.add_argument("--c-appendix", default=None, help="Workflow C suffix (default OBJECT_APPENDIX, _np_ips).")
    rq.add_argument("--d-appendix", default=None,
                    help="Workflow D suffix (default _avs_ips for nsx-lm2, _lm3_ips for nsx-lm3).")
    rq.add_argument("--subnet-map", default=None,
                    help="Subnet map for D (default data/subnet_map_lm2.csv or data/subnet_map_lm3.csv).")
    rq.add_argument("--device-group", default=None, help="Panorama device group, e.g. dg-4 (required with Palo).")
    rq.add_argument("--object-location", choices=["shared", "device-group"], default="shared")
    rq.add_argument("--rulebase", choices=["pre", "post"], default="pre")
    rq.add_argument("--zone-from", default="any")
    rq.add_argument("--zone-to", default="any")
    rq.add_argument("--profile-group", default=None,
                    help="Security profile group on allow rules (default .env; 'none' for none).")
    rq.add_argument("--log-setting", default=None,
                    help="Log forwarding profile (default .env; 'none' for none).")
    rq.add_argument("--no-palo", action="store_true", help="NSX only: no Palo plan.")
    rq.add_argument("--palo-cli", action=argparse.BooleanOptionalAction, default=True,
                    help="The Palo dry run also writes paste-ready PAN-OS CLI text for exactly the objects it "
                         "finds missing (palo/pan_set_commands.txt, pan_delete_commands.txt, plus dated copies "
                         "beside each dry-run report). On by default; --no-palo-cli leaves it out. A refresh "
                         "and its run --phase palo dry runs keep the request's choice.")
    rq.add_argument("--no-preview", action="store_true",
                    help="Skip the dry runs (offline report; run `preview` later).")
    rq.add_argument("--rate-limit", type=float, default=None, metavar="RPS",
                    help="NSX requests per second for the VM-rule snapshot.")
    palo_conn(rq)
    rq.set_defaults(func=cmd_request)

    pv = sub.add_parser("preview", help="Dry runs for one part, then refresh the report (read-only).")
    pv.add_argument("--request", required=True)
    pv.add_argument("--part", choices=["a", "c", "d", "palo", "all"], default="all")
    palo_conn(pv)
    pv.set_defaults(func=cmd_preview)

    ap = sub.add_parser("approve", help="Record the approval against the request's fingerprint.")
    ap.add_argument("--request", required=True)
    ap.add_argument("--change-ref", required=True)
    ap.add_argument("--approved-by", required=True)
    ap.add_argument("--accept-errors", action="store_true", help="Approve although the request lists errors.")
    ap.set_defaults(func=cmd_approve)

    rf = sub.add_parser("refresh", help="Re-capture and rebuild an approved request into runs/<UTC_TS>/.")
    rf.add_argument("--request", required=True)
    rf.add_argument("--strict", action="store_true", help="Stop on ANY change since approval.")
    rf.set_defaults(func=cmd_refresh)

    rn = sub.add_parser("run", help="One phase of a refreshed run (dry run unless --apply).")
    rn.add_argument("--run", required=True, help="A run directory (<request>/runs/<UTC_TS> or runs/latest).")
    rn.add_argument("--phase", required=True, choices=PHASES)
    rn.add_argument("--apply", action="store_true")
    rn.add_argument("--verify", action="store_true")
    rn.add_argument("--rollback", action="store_true")
    rn.add_argument("--allow-plan-errors", action="store_true", help="Palo: push although the plan has errors.")
    palo_conn(rn)
    rn.set_defaults(func=cmd_run)

    rp = sub.add_parser("report", help="Re-render the report of a request or run directory.")
    rp.add_argument("--dir", required=True)
    rp.set_defaults(func=cmd_report)

    args = p.parse_args(argv)
    if args.cmd in ("approve", "report"):
        setup_logging("migration_request", None)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
