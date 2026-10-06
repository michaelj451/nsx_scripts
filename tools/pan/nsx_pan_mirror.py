#!/usr/bin/env python3
"""tools/pan/nsx_pan_mirror.py

Mirror the NSX sibling IP groups, and the NSX rules that use them, onto a
Panorama device group. Separate commands; nothing here ever commits.

  plan     Reads the sibling bundle(s) an NSX step built (the IP groups the
           workflows create and add to rules: <group>_np_ips, _avs_ips,
           _lm3_ips) and, read-only, the source manager's VM hostnames. Writes
           the Panorama plan: one static address group per sibling, same name
           as on NSX, of address objects named <hostname>-<address>-<suffix>
           (or <address>-<suffix> when no VM owns the address), plus the exact
           REST payload for every object. Objects go to shared by default
           (--object-location), rules to --device-group. No Panorama call.
  plan-rules
           The same objects, plus a security rule (pre-rulebase by default,
           --rulebase post for the post-rulebase) for every NSX
           rule that uses a group with a sibling (Palo track P3). Each NSX
           group on a rule becomes ALL its siblings across the bundles given,
           plus the IP-only NSX group itself when no source-view bundle holds
           its current addresses. Reads NSX policies, rules, groups and
           services from the source manager (read-only). Mapping rules:
           app/multisite/pan_rules.py. No Panorama call.
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
    # 1. plan from the sibling bundle(s) of the NSX steps (VM lookup is read-only)
    python tools/pan/nsx_pan_mirror.py plan \\
        --bundle nsx_avs_runs/rollout/nsx-lm1_avs_ips --bundle nsx_avs_runs/rollout/nsx-lm1_lm3_ips

    # 1b. or objects AND rules, from every sibling view (NSX reads are read-only)
    python tools/pan/nsx_pan_mirror.py plan-rules \\
        --bundle nsx_avs_runs/nsx-lm1_to_nsx-lm3 \\
        --bundle nsx_avs_runs/rollout/nsx-lm1_avs_ips --bundle nsx_avs_runs/rollout/nsx-lm1_lm3_ips

    # 2. push: dry run, then apply (logs in as agent_user from .env)
    python tools/pan/nsx_pan_mirror.py push --plan <run>/plan.json
    python tools/pan/nsx_pan_mirror.py push --plan <run>/plan.json --apply

    # 3. undo exactly what that apply created
    python tools/pan/nsx_pan_mirror.py revert --manifest <run>/push_<ts>_apply.json --apply

    # 4. re-render the report of any push or revert manifest (each already writes one)
    python tools/pan/nsx_pan_mirror.py report --manifest <run>/push_<ts>_apply.json

OUTPUT
    pan_mirror_runs/<nsx-host>/<UTC_TS>/  plan.json  plan.md  push_*.json + .md  revert_*.json + .md
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from common.bundles import new_run_dir, update_latest            # noqa: E402
from common.fileio import read_json, write_json, write_text       # noqa: E402
from common.logs import setup_logging                             # noqa: E402
from common.md import align_markdown_tables, md_table             # noqa: E402
from common.paths import repo_relative                            # noqa: E402
from common.timeutil import run_ts, utc_now_iso                   # noqa: E402
from multisite.pan_mirror import MirrorOptions, build_sibling_mirror  # noqa: E402
from multisite.pan_rules import RuleOptions, build_rule_mirror       # noqa: E402

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
    if plan.get("mode") == "siblings":
        L[-2] = ("Sibling groups only: one static address group per NSX sibling, same name as on NSX. "
                 "Address objects are named <hostname>-<address>-<suffix>, or <address>-<suffix> when no "
                 "VM with a live address owns it (a powered-off VM reports no address).")
        L += md_table(["sibling groups", "addresses", "named by hostname", "errors", "warnings"],
                      [[c["static_groups"], c["addresses"], c.get("named_by_hostname", 0),
                        c["errors"], c["warnings"]]], ["r"] * 5)
    else:
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


def _resolve_bundle(path: str) -> Path:
    """A run dir, a nsx_sibling_groups/<host> dir, or a sibling_map.json."""
    p = Path(path).resolve()
    if p.is_file():
        return p.parent
    if (p / "sibling_map.json").is_file():
        return p
    found = sorted(p.glob("nsx_sibling_groups/*/sibling_map.json"))
    if len(found) == 1:
        return found[0].parent
    raise SystemExit(f"No single sibling bundle under {p} (found {len(found)}); pass the bundle folder.")


def _load_bundles(paths: List[str]) -> List[Dict[str, Any]]:
    bundles = []
    for b in paths:
        d = _resolve_bundle(b)
        bundles.append({"path": repo_relative(d), "sibling_map": read_json(d / "sibling_map.json")})
    return bundles


def _log_bundles(bundles: List[Dict[str, Any]]) -> None:
    for b in bundles:
        sm = b["sibling_map"]
        log.info("Bundle %s: %d sibling group(s), suffix %s, from %s", b["path"], len(sm.get("map", [])),
                 sm.get("appendix"), sm.get("source_host"))


def _nsx_client(alias: Optional[str], default_host: str):
    """Read-only NSX client for `alias` (a manager alias) or `default_host`."""
    from nsx.cli_bootstrap import init_cli
    from nsx.nsx_constants import resolve_manager
    from nsx.nsx_policy_client import NsxPolicyClient
    init_cli()
    host = resolve_manager(alias) if alias else default_host
    return (NsxPolicyClient(host), host) if host else (None, None)


def _read_vms(client: Any, run_dir: Path) -> List[Dict[str, Any]]:
    # Read-only: VM hostname tags and VIF addresses, to name objects
    # <hostname>-<address>-<suffix>.
    from nsx.vm_rule_data import attach_vm_ips
    vms = client.list_virtual_machines()
    attach_vm_ips(client, vms)
    write_json(run_dir / "nsx_vms.json", vms)
    return vms


ENV_DEVICE_GROUP = "PANORAMA_DEVICE_GROUP"
ENV_PROFILE_GROUP = "PANORAMA_SECURITY_PROFILE_GROUP"
ENV_LOG_SETTING = "PANORAMA_LOG_FORWARDING_PROFILE"


def _setting(cli: Optional[str], env_var: str, default: Optional[str] = None) -> Optional[str]:
    """Command line > .env > default. "none" on the command line switches it off."""
    if cli is not None:
        return None if cli.strip().lower() == "none" else cli.strip()
    return (os.environ.get(env_var) or "").strip() or default


def _resolve_env_settings(args: argparse.Namespace) -> None:
    """Fill the device group (and, for plan-rules, the profiles) from .env
    (Mike, 2026-10-06) where the command line did not set them."""
    from palo.pan_env import load_repo_env
    load_repo_env()
    args.device_group = _setting(args.device_group, ENV_DEVICE_GROUP, "dg-5")
    if hasattr(args, "log_setting"):
        args.log_setting = _setting(args.log_setting, ENV_LOG_SETTING)
        if args.profile and args.profile_group is None:
            args.profile_group = None   # individual --profile flags replace the .env group
        else:
            args.profile_group = _setting(args.profile_group, ENV_PROFILE_GROUP)


def cmd_plan(args: argparse.Namespace) -> int:
    _resolve_env_settings(args)
    bundles = _load_bundles(args.bundle)
    source_host = bundles[0]["sibling_map"].get("source_host") or "unknown-source"
    run_dir = new_run_dir(Path(args.output_base) / source_host)
    setup_logging("nsx_pan_mirror_plan", run_dir / "logs", run_ts=run_dir.name)
    _log_bundles(bundles)

    vms: List[Dict[str, Any]] = []
    vm_host = None
    if not args.no_vm_lookup:
        client, vm_host = _nsx_client(args.vm_source, source_host)
        if client is None:
            log.error("Manager not defined for %s (set it in .env).", args.vm_source)
            return 2
        log.info("Reading VMs from %s (read-only) for hostnames", vm_host)
        vms = _read_vms(client, run_dir)

    opts = MirrorOptions(device_group=args.device_group, hostname_scope=args.hostname_scope,
                         object_location=args.object_location)
    plan = build_sibling_mirror(bundles, vms, opts)
    meta = {"source": source_host, "vm_source": vm_host, "generated_at": utc_now_iso(),
            "bundles": [b["path"] for b in bundles]}
    plan["meta"] = meta
    write_json(run_dir / "plan.json", plan)
    write_text(run_dir / "plan.md", render_plan_md(plan, meta))
    update_latest(run_dir.parent, run_dir)
    log.info("Plan: %s", plan["counts"])
    print(run_dir / "plan.md")
    return 1 if plan["counts"]["errors"] else 0


# ---------------------------------------------------------------------------
# plan-rules (Palo track P3)
# ---------------------------------------------------------------------------

def render_rules_md(plan: Dict[str, Any], meta: Dict[str, Any]) -> str:
    c = plan["counts"]
    o = plan["options"]
    rb = f"{o.get('rulebase', 'pre')}-rulebase"
    prof = (f"profile group `{o['profile_group']}`" if o.get("profile_group") else
            ", ".join(f"{t} `{n}`" for t, n in (o.get("profiles") or {}).items()) or "none")
    L = [f"# NSX to Panorama rule plan: {meta['source']} to {plan['device_group']} {rb}", "",
         f"Generated {meta['generated_at']}. Read-only: NSX was read, Panorama was not contacted.", "",
         "One Panorama rule per NSX rule that uses a group with a sibling (plus `<name>-icmp` when the "
         "rule also allows ICMP). Each NSX group becomes all its siblings across the bundles, plus the "
         "IP-only NSX group itself when no source-view bundle holds its current addresses. Zones "
         f"`{plan['options']['zone_from']}` to `{plan['options']['zone_to']}`. A push appends the rules to "
         f"the bottom of the {rb} in NSX order.", "",
         f"Security profiles (allow rules): {prof}. Log forwarding profile: "
         f"{'`' + o['log_setting'] + '`' if o.get('log_setting') else 'none'}."
         + (f" Rule name suffix `{o['name_suffix']}`." if o.get("name_suffix") else "")
         + (f" Only NSX rules: {', '.join(o['only_rules'])}." if o.get("only_rules") else ""), "",
         "Bundles: " + ", ".join(f"`{b}`" for b in meta["bundles"]), ""]
    L += md_table(["NSX rules", "in scope", "skipped", "Panorama rules", "sibling groups", "mirrored groups",
                   "addresses", "services", "service groups", "errors", "warnings"],
                  [[c["nsx_rules"], c["nsx_rules_in_scope"], c["nsx_rules_skipped"], c["pan_rules"],
                    c["sibling_groups"], c["mirrored_groups"], c["addresses"], c["services"],
                    c["service_groups"], c["errors"], c["warnings"]]], ["r"] * 11)
    L += ["", "## Rules (in push order)", ""]
    L += md_table(["#", "rule", "action", "source", "destination", "application", "service", "NSX policy / rule"],
                  [[i, r["name"], r["entry"]["action"] + (" (disabled)" if r["entry"]["disabled"] == "yes" else ""),
                    ("NOT " if r["entry"].get("negate-source") == "yes" else "")
                    + ", ".join(r["entry"]["source"]["member"]),
                    ("NOT " if r["entry"].get("negate-destination") == "yes" else "")
                    + ", ".join(r["entry"]["destination"]["member"]),
                    ", ".join(r["entry"]["application"]["member"]), ", ".join(r["entry"]["service"]["member"]),
                    f"{r['nsx_policy']} / {r['nsx_rule']}"] for i, r in enumerate(plan["rules"], 1)],
                  ["r", "l", "l", "l", "l", "l", "l", "l"])
    odd = [x for x in plan["rule_report"] if x["skipped"] or x["dropped"]]
    L += ["", "## NSX rules skipped or narrowed", ""]
    L += (md_table(["NSX policy / rule", "outcome", "left out"],
                   [[f"{x['nsx_policy']} / {x['nsx_rule']}", "skipped: " + x["skipped"] if x["skipped"]
                     else "narrower than NSX", "; ".join(x["dropped"])] for x in odd]) if odd else ["None."])
    L += ["", "## Services", ""]
    L += (md_table(["name", "protocol", "ports", "source ports", "NSX service"],
                   [[s["name"], p, b["port"], b.get("source-port", ""), s["nsx_service"]]
                    for s in plan["services"] for p, b in s["protocol"].items()]) if plan["services"] else ["None."])
    if plan["service_groups"]:
        L += ["", "Service groups:", ""]
        L += md_table(["name", "members", "NSX service"],
                      [[g["name"], ", ".join(g["members"]), g["nsx_service"]] for g in plan["service_groups"]])
    L += ["", "## Address groups", ""]
    L += md_table(["name", "kind", "members", "from"],
                  [[g["name"], "mirrored NSX group" if g.get("view") == "group" else f"sibling ({g.get('view')})",
                    ", ".join(g["members"]), g.get("nsx_original") or g.get("nsx_group") or ""]
                   for g in plan["address_groups"]])
    L += ["", "## Address objects", ""]
    L += md_table(["name", "type", "value", "from"],
                  [[a["name"], a["type"], a["value"], a["description"]] for a in plan["addresses"]])
    L += ["", "## Findings", ""]
    L += (md_table(["severity", "code", "where", "detail"],
                   [[f["severity"], f["code"], f.get("group") or f.get("vm") or f.get("object") or "",
                     f["detail"]] for f in plan["findings"]]) if plan["findings"] else ["None."])
    return align_markdown_tables("\n".join(L)) + "\n"


def cmd_plan_rules(args: argparse.Namespace) -> int:
    _resolve_env_settings(args)
    bundles = _load_bundles(args.bundle)
    hosts = {b["sibling_map"].get("source_host") for b in bundles}
    if len(hosts) != 1:
        raise SystemExit(f"Bundles come from different source managers: {sorted(map(str, hosts))}")
    source_host = hosts.pop() or "unknown-source"
    run_dir = new_run_dir(Path(args.output_base) / source_host)
    setup_logging("nsx_pan_mirror_plan_rules", run_dir / "logs", run_ts=run_dir.name)
    _log_bundles(bundles)

    client, nsx_host = _nsx_client(args.nsx_source, source_host)
    if client is None:
        log.error("Manager not defined for %s (set it in .env).", args.nsx_source)
        return 2
    log.info("Reading policies, rules, groups and services from %s (read-only)", nsx_host)
    policies = client.list_security_policies()
    for p in policies:
        p["rules"] = client.list_security_rules(p["id"])
    groups = client.list_groups()
    services = client.list_services()
    write_json(run_dir / "nsx_policies.json", policies)
    write_json(run_dir / "nsx_groups.json", groups)
    write_json(run_dir / "nsx_services.json", services)

    vms: List[Dict[str, Any]] = []
    vm_host = None
    if not args.no_vm_lookup:
        vm_client, vm_host = (client, nsx_host) if not args.vm_source else _nsx_client(args.vm_source, source_host)
        if vm_client is None:
            log.error("Manager not defined for %s (set it in .env).", args.vm_source)
            return 2
        log.info("Reading VMs from %s (read-only) for hostnames", vm_host)
        vms = _read_vms(vm_client, run_dir)

    opts = MirrorOptions(device_group=args.device_group, hostname_scope=args.hostname_scope,
                         object_location=args.object_location)
    profiles = {}
    for p in args.profile or []:
        t, _, n = p.partition("=")
        if not n:
            raise SystemExit(f"--profile takes TYPE=NAME, got {p!r}")
        profiles[t.strip()] = n.strip()
    try:
        suffix = args.rule_suffix.strip()
        if suffix and suffix[0] not in "-_":
            suffix = f"-{suffix}"
        ropts = RuleOptions(zone_from=args.zone_from, zone_to=args.zone_to, rulebase=args.rulebase,
                            only_rules=args.nsx_rule or None, name_suffix=suffix,
                            profile_group=args.profile_group, profiles=profiles or None,
                            log_setting=args.log_setting)
        plan = build_rule_mirror(policies, groups, services, bundles, vms, opts, ropts)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    meta = {"source": source_host, "nsx_source": nsx_host, "vm_source": vm_host,
            "generated_at": utc_now_iso(), "bundles": [b["path"] for b in bundles]}
    plan["meta"] = meta
    write_json(run_dir / "plan.json", plan)
    write_text(run_dir / "plan.md", render_rules_md(plan, meta))
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
        # Manifests written before 2026-10-06 carry no location: device group.
        if w.get("location", "device-group") == "shared":
            return {"location": "shared", "name": w["name"]}
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

    def named_exists(self, resource: str, name: str, device_group: str) -> Optional[str]:
        """Where an existing object `name` is visible to the device group:
        "shared", "device-group", or None. Read-only."""
        for params in ({"location": "shared", "name": name},
                       {"location": "device-group", "device-group": device_group, "name": name}):
            r = self._req("GET", resource, params)
            if r.status_code == 200 and (r.json().get("result") or {}).get("entry"):
                return params["location"]
            if r.status_code not in (200, 404):
                raise RuntimeError(f"read {resource} {name}: HTTP {r.status_code} {self._why(r)}")
        return None

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


def missing_profiles(session: Any, plan: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Security / log forwarding profiles the plan's rules name that Panorama
    does not have. Checked before any write; built-in profiles are skipped."""
    from multisite.pan_rules import profile_refs
    out = []
    for label, resource, name in profile_refs(plan.get("options") or {}):
        where = session.named_exists(resource, name, plan["device_group"])
        if where is None:
            out.append((label, name))
        else:
            log.info("Found %s %s in %s", label, name, where)
    return out


def _row(w: Dict[str, Any]) -> Dict[str, Any]:
    return {"kind": w["kind"], "name": w["name"], "resource": w["resource"],
            "location": w.get("location", "device-group"), "device_group": w["device_group"]}


def _norm(v: Any) -> Any:
    if isinstance(v, dict):
        if set(v) == {"member"}:
            m = v["member"]
            return sorted(m if isinstance(m, list) else [m])
        return {k: _norm(x) for k, x in v.items()}
    return v


def differs(entry: Dict[str, Any], existing: Dict[str, Any]) -> List[str]:
    """Top-level fields of the planned entry that the existing object does not
    match (member lists compared as sets; description and fields Panorama adds
    are ignored). Empty = the existing object already is the planned one."""
    out = []
    for k, v in entry.items():
        if k in ("@name", "description"):
            continue
        if _norm(v) != _norm(existing.get(k)):
            out.append(k)
    return out


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
            diff = differs(w["entry"], existing)
            if diff:
                # Never modified either way; flagged so a same-named object with
                # other content is not mistaken for the planned one.
                row["differs"] = diff
                log.warning("  exists with DIFFERENT %s, left unchanged: %s %s",
                            ", ".join(diff), w["kind"], w["name"])
            else:
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


# ---------------------------------------------------------------------------
# Reports: a markdown report beside every push / revert manifest
# ---------------------------------------------------------------------------

def _detail(row: Dict[str, Any]) -> str:
    """One-line content summary of a planned or existing object."""
    e = row.get("entry") or row.get("existing") or {}
    k = row["kind"]
    mem = lambda f: ", ".join((e.get(f) or {}).get("member") or [])  # noqa: E731
    if k == "address":
        return next((f"{t} {e[t]}" for t in ("ip-netmask", "ip-range", "fqdn") if t in e), "")
    if k == "address-group":
        if "static" in e:
            return f"static, {len((e['static'] or {}).get('member') or [])} member(s)"
        if "dynamic" in e:
            return f"dynamic: {(e['dynamic'] or {}).get('filter', '')}"
    if k == "service":
        return "; ".join(f"{p} {b.get('port', '')}" for p, b in (e.get("protocol") or {}).items())
    if k == "service-group":
        return f"{len((e.get('members') or {}).get('member') or [])} member(s)"
    if k == "security-rule":
        ps = e.get("profile-setting") or {}
        prof = (f"; profile group {', '.join(ps['group']['member'])}" if "group" in ps else
                "; profiles " + ", ".join(f"{t} {', '.join(v['member'])}" for t, v in ps["profiles"].items())
                if "profiles" in ps else "")
        rb = "post" if row.get("resource", "").endswith("PostRules") else "pre"
        return (f"[{rb}] {e.get('action', '')}: {mem('source')} to {mem('destination')}; "
                f"service {mem('service')}; application {mem('application')}{prof}"
                + (f"; log {e['log-setting']}" if e.get("log-setting") else ""))
    return ""


def _kind_table(rows: List[Dict[str, Any]], statuses: List[str], flag: Optional[str] = None) -> List[str]:
    kinds = list(dict.fromkeys(r["kind"] for r in rows))
    cols = statuses + ([flag] if flag else [])

    def count(k: Optional[str], s: str) -> int:
        sel = [r for r in rows if k is None or r["kind"] == k]
        return sum(1 for r in sel if (r.get(s) if s == flag else r["status"] == s))

    body = [[k] + [count(k, s) for s in cols] for k in kinds]
    body.append(["total"] + [count(None, s) for s in cols])
    return md_table(["kind"] + cols, body, ["l"] + ["r"] * len(cols))


def render_push_md(doc: Dict[str, Any]) -> str:
    rows = doc["results"]
    apply = doc["mode"] == "apply"
    planned = doc.get("planned", len(rows))
    L = [f"# Panorama push report ({'APPLY' if apply else 'DRY RUN'}): device group "
         f"{doc['device_group']} on {doc['panorama']}", "",
         f"Generated {doc['created_at']}. Plan `{repo_relative(doc['plan'])}`. "
         f"{len(rows)} of {planned} planned object(s) checked. Candidate configuration only: "
         f"nothing is committed.", ""]
    if not apply:
        L += ["Dry run: Panorama was only read. `would_create` is what an apply would create; "
              "`exists_unchanged` is already there and is never modified.", ""]
    L += _kind_table(rows, ["would_create", "created", "exists_unchanged", "failed"], "differs")
    failed = [r for r in rows if r["status"] == "failed"]
    if failed:
        L += ["", f"## Failed: the push stopped here, {planned - len(rows)} later object(s) not sent", ""]
        L += md_table(["kind", "name", "error"], [[r["kind"], r["name"], r.get("error", "")] for r in failed])
    diffs = [r for r in rows if r.get("differs")]
    if diffs:
        L += ["", "## Already on Panorama with different content (left unchanged)", ""]
        L += md_table(["kind", "name", "differs in", "on Panorama now"],
                      [[r["kind"], r["name"], ", ".join(r["differs"]),
                        _detail({"kind": r["kind"], "entry": r.get("existing")})] for r in diffs])
    L += ["", "## Objects (in push order)", ""]
    L += md_table(["#", "kind", "location", "name", "status", "content"],
                  [[i, r["kind"], r.get("location", "device-group"), r["name"], r["status"], _detail(r)]
                   for i, r in enumerate(rows, 1)], ["r", "l", "l", "l", "l", "l"])
    if apply and any(r["status"] == "created" for r in rows):
        L += ["", "## Undo", "", "Deletes exactly the objects this apply created, newest first (dry run, then `--apply`):", "",
              "```bash", f"python tools/pan/nsx_pan_mirror.py revert --manifest {repo_relative(doc['manifest'])} "
              f"--no-tls-verify", "```"]
    return align_markdown_tables("\n".join(L)) + "\n"


def render_revert_md(doc: Dict[str, Any]) -> str:
    rows = doc["results"]
    apply = doc["mode"] == "apply"
    L = [f"# Panorama revert report ({'APPLY' if apply else 'DRY RUN'})", "",
         f"Generated {doc['created_at']}. Undoes push manifest `{repo_relative(doc['source_manifest'])}`. "
         f"Only objects that push created are touched, newest first. Nothing is committed.", ""]
    L += _kind_table(rows, ["would_delete", "deleted", "already_gone", "failed"])
    failed = [r for r in rows if r["status"] == "failed"]
    if failed:
        L += ["", "## Failed: the revert stopped here", ""]
        L += md_table(["kind", "name", "error"], [[r["kind"], r["name"], r.get("error", "")] for r in failed])
    L += ["", "## Objects (in delete order)", ""]
    L += md_table(["#", "kind", "location", "name", "status"],
                  [[i, r["kind"], r.get("location", "device-group"), r["name"], r["status"]]
                   for i, r in enumerate(rows, 1)], ["r", "l", "l", "l", "l"])
    return align_markdown_tables("\n".join(L)) + "\n"


def write_report(doc: Dict[str, Any], manifest_path: Path) -> Path:
    doc = {**doc, "manifest": str(manifest_path)}
    text = render_revert_md(doc) if "source_manifest" in doc else render_push_md(doc)
    path = manifest_path.with_suffix(".md")
    write_text(path, text)
    return path


def cmd_report(args: argparse.Namespace) -> int:
    mpath = Path(args.manifest).resolve()
    path = write_report(read_json(mpath), mpath)
    print(path)
    return 0


def cmd_push(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan).resolve()
    plan = read_json(plan_path)
    run_dir = plan_path.parent
    ts = run_ts()
    setup_logging("nsx_pan_mirror_push", run_dir / "logs", run_ts=ts)
    if plan["counts"]["errors"] and not args.allow_plan_errors:
        log.error("The plan has %d error(s); fix them or pass --allow-plan-errors.", plan["counts"]["errors"])
        return 2
    by_loc = {}
    for w in plan["writes"]:
        by_loc[w.get("location", "device-group")] = by_loc.get(w.get("location", "device-group"), 0) + 1
    log.info("%s %d object(s): %s; device group %s (candidate config; never commits)",
             "APPLY:" if args.apply else "DRY RUN:", len(plan["writes"]),
             ", ".join(f"{n} in {loc}" for loc, n in sorted(by_loc.items())), plan["device_group"])
    session = open_session(args.user_env, args.password_env, args.host, args.no_tls_verify)
    if not device_group_exists(session, plan["device_group"]):
        log.error("Device group %r does not exist on %s; nothing sent (a set would create it).",
                  plan["device_group"], session.base_url)
        return 2
    missing = missing_profiles(session, plan)
    if missing:
        for label, name in missing:
            log.error("The plan's %s %r is not on %s (shared or %s); nothing sent.", label, name,
                      session.base_url, plan["device_group"])
        return 2
    rows = push_writes(session, plan["writes"], args.apply)
    mode = "apply" if args.apply else "dryrun"
    doc = {"created_at": utc_now_iso(), "mode": mode, "plan": str(plan_path),
           "device_group": plan["device_group"], "panorama": session.base_url,
           "committed": False, "planned": len(plan["writes"]), "summary": _summary(rows), "results": rows}
    n_diff = sum(1 for r in rows if r.get("differs"))
    if n_diff:
        doc["summary"]["exists_differs"] = n_diff
    path = run_dir / f"push_{ts}_{mode}.json"
    write_json(path, doc)
    log.info("Summary: %s", doc["summary"])
    log.info("Manifest: %s  Report: %s", repo_relative(path), repo_relative(write_report(doc, path)))
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
    log.info("Summary: %s  Manifest: %s  Report: %s", doc["summary"], repo_relative(path),
             repo_relative(write_report(doc, path)))
    print(path)
    return 1 if doc["summary"].get("failed") else 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n\n", 1)[1])
    sub = p.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("plan", help="Plan the Panorama objects for NSX sibling bundles (no Panorama call).")
    pl.add_argument("--bundle", action="append", required=True,
                    help="Sibling bundle of an NSX step (run dir, nsx_sibling_groups/<host> dir or "
                         "sibling_map.json). Repeat for several steps.")
    pl.add_argument("--vm-source", choices=NSX_CHOICES,
                    help="Manager to read VM hostnames from (default: the bundle's source host).")
    pl.add_argument("--no-vm-lookup", action="store_true",
                    help="Skip the VM lookup: every object is named <address>-<suffix>.")
    pl.add_argument("--device-group", help="Device group (default: PANORAMA_DEVICE_GROUP in .env, else dg-5).")
    pl.add_argument("--hostname-scope", default="hostname")
    pl.add_argument("--object-location", choices=["shared", "device-group"], default="shared",
                    help="Where address objects and groups are created (default shared).")
    pl.add_argument("--output-base", default=str(OUT_BASE))
    pr = sub.add_parser("plan-rules", help="Plan the objects AND the pre-rulebase rules for the NSX rules "
                                           "that use sibling groups (no Panorama call).")
    pr.add_argument("--bundle", action="append", required=True,
                    help="Sibling bundle of an NSX step. Repeat for every view (_np_ips, _avs_ips, _lm3_ips): "
                         "each NSX group on a rule becomes all its siblings.")
    pr.add_argument("--nsx-source", choices=NSX_CHOICES,
                    help="Manager to read rules, groups and services from (default: the bundles' source host).")
    pr.add_argument("--vm-source", choices=NSX_CHOICES,
                    help="Manager to read VM hostnames from (default: the NSX source).")
    pr.add_argument("--no-vm-lookup", action="store_true",
                    help="Skip the VM lookup: every object is named by its address.")
    pr.add_argument("--device-group", help="Device group (default: PANORAMA_DEVICE_GROUP in .env, else dg-5).")
    pr.add_argument("--hostname-scope", default="hostname")
    pr.add_argument("--object-location", choices=["shared", "device-group"], default="shared",
                    help="Where address objects, address groups, services and service groups are created "
                         "(default shared). Rules always go to --device-group.")
    pr.add_argument("--zone-from", default="any", help="Source zone of every rule (default any).")
    pr.add_argument("--zone-to", default="any", help="Destination zone of every rule (default any).")
    pr.add_argument("--rulebase", choices=["pre", "post"], default="pre",
                    help="Device-group rulebase the rules go to (default pre). Names are unique across "
                         "pre and post: use --rule-suffix to put rules already in one into the other.")
    pr.add_argument("--nsx-rule", action="append",
                    help="Only this NSX rule (display name or id). Repeat for several; default all.")
    pr.add_argument("--rule-suffix", default="",
                    help="Appended to every Panorama rule name after a hyphen: --rule-suffix post gives "
                         "<rule>-post.")
    pr.add_argument("--profile-group",
                    help="Existing security profile group set on every allow rule (default: "
                         "PANORAMA_SECURITY_PROFILE_GROUP in .env; 'none' = no profile).")
    pr.add_argument("--profile", action="append", metavar="TYPE=NAME",
                    help="Existing individual security profile on every allow rule, instead of a group. "
                         "TYPE: virus, spyware, vulnerability, url-filtering, file-blocking, "
                         "wildfire-analysis, data-filtering. Repeat per type.")
    pr.add_argument("--log-setting", help="Existing log forwarding profile set on every rule (default: "
                                          "PANORAMA_LOG_FORWARDING_PROFILE in .env; 'none' = no profile).")
    pr.add_argument("--output-base", default=str(OUT_BASE))
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
    rp = sub.add_parser("report", help="Write the markdown report for an existing push or revert manifest "
                                       "(push and revert already write one; this re-renders it).")
    rp.add_argument("--manifest", required=True, help="push_<ts>_<mode>.json or revert_<ts>_<mode>.json")
    args = p.parse_args(argv)
    return {"plan": cmd_plan, "plan-rules": cmd_plan_rules, "push": cmd_push,
            "revert": cmd_revert, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
