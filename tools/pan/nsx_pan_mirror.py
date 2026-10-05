#!/usr/bin/env python3
"""tools/pan/nsx_pan_mirror.py

Mirror NSX groups onto a Panorama device group exactly (same group type,
membership and tags). Three separate commands; nothing here ever commits.

  plan     READ-ONLY against NSX. Pulls the source manager's groups, VMs and
           VM IPs, and writes the Panorama object plan (tags, address objects
           named by VM hostname or by IP address, dynamic and static address
           groups) plus the exact REST payload for every object.
  push     Against Panorama CANDIDATE config, through the REST API only (the
           XML API is not used). Dry run by default: checks which
           objects already exist and lists what it would create. --apply
           creates only the missing ones, in dependency order, and records
           exactly what it created. An object that already exists is never
           modified. Never commits: you review and commit in Panorama.
  revert   Deletes only the objects a push manifest says it created, newest
           first, and only while they still exist. Dry run by default.

Mapping rules: app/multisite/pan_mirror.py.

USAGE
    # 1. plan (NSX read-only); --groups limits it to a few groups + what they nest
    python tools/pan/nsx_pan_mirror.py plan --source nsx-lm1 \\
        --groups seed-tag-net-10-6-0,ip-address-group,seed-nested-web

    # 2. push: dry run, then apply (logs in as agent_user from .env)
    python tools/pan/nsx_pan_mirror.py push --plan <run>/plan.json
    python tools/pan/nsx_pan_mirror.py push --plan <run>/plan.json --apply

    # 3. undo exactly what that apply created
    python tools/pan/nsx_pan_mirror.py revert --manifest <run>/push_<ts>_apply.json --apply

OUTPUT
    pan_mirror_runs/<nsx-host>/<UTC_TS>/  plan.json  plan.md  push_*.json  revert_*.json
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from common.bundles import new_run_dir, update_latest            # noqa: E402
from common.fileio import read_json, write_json, write_text       # noqa: E402
from common.logs import setup_logging                             # noqa: E402
from common.md import align_markdown_tables, md_table             # noqa: E402
from common.paths import repo_relative                            # noqa: E402
from common.timeutil import run_ts, utc_now_iso                   # noqa: E402
from multisite.pan_mirror import MirrorOptions, build_mirror      # noqa: E402

log = logging.getLogger("nsx_pan_mirror")
OUT_BASE = REPO_ROOT / "pan_mirror_runs"
NSX_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5", "nsx-lm6"]


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------

def render_plan_md(plan: Dict[str, Any], meta: Dict[str, Any]) -> str:
    c = plan["counts"]
    L = [f"# NSX to Panorama mirror plan: {meta['source']} to {plan['device_group']}", "",
         f"Generated {meta['generated_at']}. Read-only: NSX was read, Panorama was not contacted.", "",
         "Objects are named by VM hostname (VM address objects) or by IP address (address "
         "entries), carry the VMs' NSX tags, and keep each NSX group's type.", ""]
    L += md_table(["tags", "addresses", "dynamic groups", "static groups", "errors", "warnings"],
                  [[c["tags"], c["addresses"], c["dynamic_groups"], c["static_groups"],
                    c["errors"], c["warnings"]]], ["r"] * 6)
    L += ["", "## Address groups", ""]
    L += md_table(["name", "kind", "filter / members", "NSX group"],
                  [[g["name"], g["kind"] + (" (helper)" if g.get("helper_for") else "")
                    + (" (partial)" if g.get("partial") else ""),
                    f"`{g['filter']}`" if g["kind"] == "dynamic" else ", ".join(g["members"]),
                    g["nsx_group"]] for g in plan["address_groups"]])
    L += ["", "## Address objects", ""]
    L += md_table(["name", "type", "value", "tags", "from"],
                  [[a["name"], a["type"], a["value"], ", ".join(a["tags"]), a["description"]]
                   for a in plan["addresses"]])
    L += ["", "## Tags", "", ", ".join(f"`{t['name']}`" for t in plan["tags"]) or "none", "",
          "## Findings", ""]
    L += (md_table(["severity", "code", "where", "detail"],
                   [[f["severity"], f["code"], f.get("group") or f.get("vm") or f.get("object") or "",
                     f["detail"]] for f in plan["findings"]]) if plan["findings"] else ["None."])
    return align_markdown_tables("\n".join(L)) + "\n"


def cmd_plan(args: argparse.Namespace) -> int:
    from nsx.cli_bootstrap import init_cli
    from nsx.nsx_constants import resolve_manager
    from nsx.nsx_policy_client import NsxPolicyClient
    from nsx.vm_rule_data import attach_vm_ips
    init_cli()
    host = resolve_manager(args.source)
    if not host:
        log.error("Manager not defined for %s (set it in .env).", args.source)
        return 2
    run_dir = new_run_dir(Path(args.output_base) / host)
    # init_cli() already logs to the console; add only the run log file here.
    setup_logging("nsx_pan_mirror_plan", run_dir / "logs", run_ts=run_dir.name, console=False)
    log.info("Reading %s (read-only): groups, VMs, VIF IPs", host)
    client = NsxPolicyClient(host)
    groups = client.list_groups(domain_id=args.domain_id)
    vms = client.list_virtual_machines()
    attach_vm_ips(client, vms)
    write_json(run_dir / "nsx_source.json", {"groups": groups, "vms": vms})

    only = [g.strip() for g in args.groups.split(",") if g.strip()] if args.groups else None
    opts = MirrorOptions(device_group=args.device_group, hostname_scope=args.hostname_scope,
                         tag_format=args.tag_format)
    plan = build_mirror(groups, vms, opts, only=only)
    meta = {"source": args.source, "source_host": host, "generated_at": utc_now_iso(),
            "groups_requested": only, "domain_id": args.domain_id}
    plan["meta"] = meta
    write_json(run_dir / "plan.json", plan)
    write_text(run_dir / "plan.md", render_plan_md(plan, meta))
    update_latest(run_dir.parent, run_dir)
    log.info("Plan: %s", plan["counts"])
    print(run_dir / "plan.md")
    return 1 if plan["counts"]["errors"] else 0


# ---------------------------------------------------------------------------
# Panorama REST session (the XML API is not used for config)
# ---------------------------------------------------------------------------

class RestSession:
    """get / create / delete one object through the Panorama REST API.

    Login reuses palo.pan_rest_client.PanRestClient, whose keygen is the only
    call to /api/ (a REST key has to come from keygen) and which never lets a
    network error carry the keygen URL, and so the password, into a message.
    """

    def __init__(self, client: Any):
        self.c = client
        self.base_url = client.env.url
        self.api = f"{client.env.url}/restapi/{client.rest_version}"

    def _req(self, method: str, resource: str, params: Dict[str, str],
             body: Optional[Dict[str, Any]] = None):
        import requests
        try:
            return self.c.session.request(method, f"{self.api}/{resource}", params=params,
                                          headers={"X-PAN-KEY": self.c.api_key}, json=body,
                                          timeout=60)
        except requests.RequestException as exc:
            raise RuntimeError(f"Cannot reach {self.base_url} ({type(exc).__name__})") from None

    @staticmethod
    def _why(r) -> str:
        try:
            j = r.json()
        except ValueError:
            return r.text[:200]
        causes = []
        for d in j.get("details") or []:
            for c in (d.get("causes") or []) if isinstance(d, dict) else []:
                causes.append(c.get("description", ""))
        return f"{j.get('message', '')} {'; '.join(causes)}".strip()[:300]

    @staticmethod
    def _params(w: Dict[str, Any]) -> Dict[str, str]:
        return {"location": "device-group", "device-group": w["device_group"], "name": w["name"]}

    def exists(self, w: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        r = self._req("GET", w["resource"], self._params(w))
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise RuntimeError(f"read {w['kind']} {w['name']}: HTTP {r.status_code} {self._why(r)}")
        entries = (r.json().get("result") or {}).get("entry") or []
        return entries[0] if entries else None

    def create(self, w: Dict[str, Any]) -> None:
        r = self._req("POST", w["resource"], self._params(w), {"entry": w["entry"]})
        if r.status_code >= 300:
            raise RuntimeError(f"create {w['kind']} {w['name']}: HTTP {r.status_code} {self._why(r)}")

    def delete(self, w: Dict[str, Any]) -> None:
        r = self._req("DELETE", w["resource"], self._params(w))
        if r.status_code >= 300:
            raise RuntimeError(f"delete {w['kind']} {w['name']}: HTTP {r.status_code} {self._why(r)}")

    def device_group_exists(self, device_group: str) -> bool:
        r = self._req("GET", "Panorama/DeviceGroups", {"name": device_group})
        if r.status_code == 404:
            return False
        if r.status_code != 200:
            raise RuntimeError(f"read device group {device_group}: HTTP {r.status_code} {self._why(r)}")
        return bool((r.json().get("result") or {}).get("entry"))


def open_session(user_env: str, password_env: str, host: Optional[str],
                 no_tls_verify: bool = False) -> RestSession:
    from palo.pan_env import load_repo_env
    from palo.pan_rest_client import PanRestClient, PanRestError
    load_repo_env()
    if no_tls_verify:
        # Lab Panoramas present PAN-OS's default self-signed certificate, whose
        # name never matches the host (docs/pan/RUNBOOK_PAN_LAB.md).
        os.environ["PANORAMA_TLS_VERIFY"] = "false"
    try:
        client = PanRestClient.from_env(user_env=user_env, password_env=password_env,
                                        host=host, load_env=False)
        _ = client.api_key                      # log in now, not mid-push
    except PanRestError as exc:
        raise SystemExit(f"Panorama login failed: {exc}") from None
    log.info("Logged in to %s as %s (REST %s, tls_verify=%s)", client.env.url,
             os.environ.get(user_env), client.rest_version, client.env.verify)
    return RestSession(client)


# ---------------------------------------------------------------------------
# push / revert (session-agnostic, so they can be tested with a fake)
# ---------------------------------------------------------------------------

def device_group_exists(session: Any, device_group: str) -> bool:
    """Checked before any write: refuse to write into a device group that is
    not there rather than find out object by object."""
    return session.device_group_exists(device_group)


def _row(w: Dict[str, Any]) -> Dict[str, Any]:
    return {"kind": w["kind"], "name": w["name"], "resource": w["resource"],
            "device_group": w["device_group"]}


def push_writes(session: Any, writes: List[Dict[str, Any]], apply: bool) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for w in writes:
        row = _row(w)
        try:
            existing = session.exists(w)
        except RuntimeError as exc:
            row.update(status="failed", error=str(exc))
            results.append(row)
            log.error("STOP: %s", exc)
            break
        if existing is not None:
            row.update(status="exists_unchanged", existing=existing)
            log.info("  exists, left unchanged: %s %s", w["kind"], w["name"])
        elif not apply:
            row.update(status="would_create", entry=w["entry"])
            log.info("  would create: %s %s", w["kind"], w["name"])
        else:
            try:
                session.create(w)
            except RuntimeError as exc:
                row.update(status="failed", error=str(exc), entry=w["entry"])
                results.append(row)
                log.error("STOP: %s", exc)
                break
            row.update(status="created", entry=w["entry"])
            log.info("  created: %s %s", w["kind"], w["name"])
        results.append(row)
    return results


def revert_created(session: Any, results: List[Dict[str, Any]], apply: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in reversed([r for r in results if r.get("status") == "created"]):
        rec = _row(row)
        try:
            if session.exists(row) is None:
                rec["status"] = "already_gone"
            elif not apply:
                rec["status"] = "would_delete"
            else:
                session.delete(row)
                rec["status"] = "deleted"
        except RuntimeError as exc:
            rec.update(status="failed", error=str(exc))
            out.append(rec)
            log.error("STOP: %s", exc)
            break
        log.info("  %s: %s %s", rec["status"], row["kind"], row["name"])
        out.append(rec)
    return out


def _summary(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in rows:
        out[r["status"]] = out.get(r["status"], 0) + 1
    return out


def cmd_push(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan).resolve()
    plan = read_json(plan_path)
    run_dir = plan_path.parent
    ts = run_ts()
    setup_logging("nsx_pan_mirror_push", run_dir / "logs", run_ts=ts)
    if plan["counts"]["errors"] and not args.allow_plan_errors:
        log.error("The plan has %d error(s); fix them or pass --allow-plan-errors.", plan["counts"]["errors"])
        return 2
    log.info("%s %d object(s) into device group %s (candidate config; never commits)",
             "APPLY:" if args.apply else "DRY RUN:", len(plan["writes"]), plan["device_group"])
    session = open_session(args.user_env, args.password_env, args.host, args.no_tls_verify)
    if not device_group_exists(session, plan["device_group"]):
        log.error("Device group %r does not exist on %s; nothing sent (a set would create it).",
                  plan["device_group"], session.base_url)
        return 2
    rows = push_writes(session, plan["writes"], args.apply)
    mode = "apply" if args.apply else "dryrun"
    doc = {"created_at": utc_now_iso(), "mode": mode, "plan": str(plan_path),
           "device_group": plan["device_group"], "panorama": session.base_url,
           "committed": False, "summary": _summary(rows), "results": rows}
    path = run_dir / f"push_{ts}_{mode}.json"
    write_json(path, doc)
    log.info("Summary: %s", doc["summary"])
    log.info("Manifest: %s", repo_relative(path))
    if args.apply and doc["summary"].get("created"):
        log.info("Nothing is committed. Review in Panorama; undo with: "
                 "python tools/pan/nsx_pan_mirror.py revert --manifest %s --apply", repo_relative(path))
    print(path)
    return 1 if doc["summary"].get("failed") else 0


def cmd_revert(args: argparse.Namespace) -> int:
    mpath = Path(args.manifest).resolve()
    manifest = read_json(mpath)
    if manifest.get("mode") != "apply":
        log.error("Revert needs an APPLY manifest (this one is %r).", manifest.get("mode"))
        return 2
    ts = run_ts()
    setup_logging("nsx_pan_mirror_revert", mpath.parent / "logs", run_ts=ts)
    session = open_session(args.user_env, args.password_env, args.host, args.no_tls_verify)
    rows = revert_created(session, manifest["results"], args.apply)
    mode = "apply" if args.apply else "dryrun"
    doc = {"created_at": utc_now_iso(), "mode": mode, "source_manifest": str(mpath),
           "committed": False, "summary": _summary(rows), "results": rows}
    path = mpath.parent / f"revert_{ts}_{mode}.json"
    write_json(path, doc)
    log.info("Summary: %s  Manifest: %s", doc["summary"], repo_relative(path))
    print(path)
    return 1 if doc["summary"].get("failed") else 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n\n", 1)[1])
    sub = p.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("plan", help="Read NSX and write the Panorama object plan (read-only).")
    pl.add_argument("--source", required=True, choices=NSX_CHOICES)
    pl.add_argument("--domain-id", default="default")
    pl.add_argument("--groups", help="Comma-separated NSX group names or ids (plus what they nest).")
    pl.add_argument("--device-group", default="dg-5")
    pl.add_argument("--hostname-scope", default="hostname")
    pl.add_argument("--tag-format", default="{scope}.{value}",
                    help="Panorama tag name for an NSX scope|value tag (default {scope}.{value}).")
    pl.add_argument("--output-base", default=str(OUT_BASE))
    for name, hlp in (("push", "Create the plan's missing objects in candidate config (dry run default)."),
                      ("revert", "Delete exactly what a push apply created (dry run default).")):
        sp = sub.add_parser(name, help=hlp)
        if name == "push":
            sp.add_argument("--plan", required=True)
            sp.add_argument("--allow-plan-errors", action="store_true",
                            help="Push even though the plan reported errors (those objects are absent).")
        else:
            sp.add_argument("--manifest", required=True)
        sp.add_argument("--apply", action="store_true")
        sp.add_argument("--user-env", default="agent_user")
        sp.add_argument("--password-env", default="agent_password")
        sp.add_argument("--host", default=None, help="Panorama host override (default from .env).")
        sp.add_argument("--no-tls-verify", action="store_true",
                        help="Skip TLS verification (lab Panoramas with the default self-signed certificate).")
    args = p.parse_args(argv)
    return {"plan": cmd_plan, "push": cmd_push, "revert": cmd_revert}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
