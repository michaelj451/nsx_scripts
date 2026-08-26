#!/usr/bin/env python3
"""
tools/reports/report_vms_in_rules.py

Rule-centric membership report. Given a list of VM display names, this
tool finds every DFW rule that touches any of those VMs and emits a
markdown + JSON report grouped BY RULE.

For each VM in the input list, we determine every group it is a live
member of (all sources: tag, path, segment, IP) by hitting the NSX
`/policy/api/v1/infra/domains/<d>/groups/<g>/members/virtual-machines`
endpoint per group. We then walk every policy + rule and, for each rule,
check whether any target VM is:

  - in a group referenced by the rule's source_groups
  - in a group referenced by the rule's destination_groups
  - in a group referenced by the rule's scope (applied_to)

Rules that touch at least one target VM go into the report. Rules with
ANY on both source AND destination (global rules) are included and
labelled so they stand out.

Read-only: strict GETs, no writes.

Usage:
  python tools/reports/report_vms_in_rules.py \\
    --manager nsx-lm1 \\
    [--vm-list vm_rule_report_targets.txt] \\
    [--output-dir nsx_logs/reports/vm_rule_membership/nsx-lm1.lab.local] \\
    [--overwrite] \\
    [--federation-global]

The --vm-list file is one VM display name per line; blank lines and
lines starting with `#` are ignored. Matching is case-insensitive.
Precedence for the list path: --vm-list > VM_RULE_REPORT_LIST (.env)
> auto-discovered vm_rule_report_targets.txt at repo root.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_log_dir, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.md_utils import align_markdown_tables

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
DEFAULT_LIST_FILENAME = "vm_rule_report_targets.txt"
ANY_TOKEN = "ANY"


# ---------- setup ----------

def setup_logging(tool: str) -> Path:
    log_dir = Path(nsx_log_dir).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = (log_dir / f"vm_rule_membership_{RUN_TS}.log").resolve()
    log_file.touch(exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter(
        "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S",
    )
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(ch)
    root.addHandler(fh)
    log.info("Logging to %s", log_file)
    return log_file


# ---------- VM-list loader ----------

def load_vm_names(explicit_path: Optional[str]) -> Tuple[List[str], Path]:
    """
    Load the VM display-name list. Returns (names, source_path).
    Precedence:
      1. explicit --vm-list
      2. VM_RULE_REPORT_LIST env var
      3. auto-discovered REPO_ROOT/vm_rule_report_targets.txt
    Blank lines and `#` comments are ignored. Order + duplicates preserved.
    """
    explicit = (explicit_path or "").strip()
    envvar = (os.getenv("VM_RULE_REPORT_LIST") or "").strip()
    source: Optional[str] = None
    fp: Optional[Path] = None

    if explicit:
        fp = Path(os.path.expandvars(explicit)).expanduser()
        source = "--vm-list"
    elif envvar:
        fp = Path(os.path.expandvars(envvar)).expanduser()
        source = "VM_RULE_REPORT_LIST"
    else:
        default_fp = REPO_ROOT / DEFAULT_LIST_FILENAME
        if default_fp.exists():
            fp = default_fp
            source = f"default ({DEFAULT_LIST_FILENAME} at repo root)"

    if fp is None:
        raise SystemExit(
            "No VM list provided. Pass --vm-list <path>, set "
            "VM_RULE_REPORT_LIST in .env, or create "
            f"{DEFAULT_LIST_FILENAME} at the repo root."
        )
    if not fp.exists():
        raise SystemExit(f"VM list file not found ({source}): {fp}")

    names: List[str] = []
    for line in fp.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        names.append(s)
    log.info("Loaded %d VM name(s) from %s (%s)", len(names), fp, source)
    return names, fp


# ---------- helpers ----------

def _looks_any(g: Any) -> bool:
    if not isinstance(g, str):
        return False
    s = g.strip().upper()
    return s in ("ANY", "*")


def _group_paths(refs: Optional[List[Any]]) -> List[str]:
    """Return only the /infra/... group path entries from a rule's source_groups
    / destination_groups / scope. ANY-like entries are filtered out (the caller
    handles ANY semantics separately)."""
    out: List[str] = []
    for r in refs or []:
        if isinstance(r, str) and r.startswith("/") and not _looks_any(r):
            out.append(r)
    return out


def _has_any(refs: Optional[List[Any]]) -> bool:
    for r in refs or []:
        if _looks_any(r):
            return True
    return False


def _md_esc(s: Any) -> str:
    """Escape pipes in markdown-cell content."""
    return str(s).replace("|", "\\|") if s is not None else ""


# ---------- data pull ----------

def build_vm_index(vms: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Return (by_name_lower, by_ext_id)."""
    by_name: Dict[str, Dict[str, Any]] = {}
    by_ext: Dict[str, Dict[str, Any]] = {}
    for vm in vms:
        ext = vm.get("external_id") or vm.get("id")
        name = vm.get("display_name") or vm.get("name") or ""
        if ext:
            by_ext[ext] = vm
        if name:
            by_name[name.lower()] = vm
    return by_name, by_ext


def pull_groups_with_members(
    client: NsxPolicyClient,
    domain_ids: List[str],
    site_clients_for_members: Optional[Dict[str, NsxPolicyClient]] = None,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Set[str]]]:
    """
    For every group in every domain, fetch live VM members via
    /members/virtual-machines. Returns:
      groups_by_path: group_path -> {id, display_name, domain_id, member_count}
      group_to_members: group_path -> set(external_id)

    If `site_clients_for_members` is provided (GM federation mode), member
    lookups fan out to EACH site's LM (using federation_global=True clients)
    and are UNIONed per group, because a GM's /members endpoint returns 400
    without an enforcement point. Otherwise the single `client` is used.

    Errors on a single group are logged and skipped (empty member set).
    """
    groups_by_path: Dict[str, Dict[str, Any]] = {}
    group_to_members: Dict[str, Set[str]] = {}

    for domain_id in domain_ids:
        try:
            groups = client.list_groups(domain_id=domain_id)
        except Exception as exc:
            log.error("list_groups(%s) failed: %s", domain_id, exc)
            continue
        log.info("Domain %s: %d group(s)", domain_id, len(groups))

        for i, g in enumerate(groups, start=1):
            gpath = g.get("path")
            gid = g.get("id")
            gname = g.get("display_name") or gid or "(unnamed)"
            if not gpath or not gid:
                continue
            groups_by_path[gpath] = {
                "id": gid,
                "display_name": gname,
                "domain_id": domain_id,
                "path": gpath,
            }
            ext_ids: Set[str] = set()
            if site_clients_for_members:
                # Federated: union members across sites
                for site_id, site_client in site_clients_for_members.items():
                    try:
                        members = site_client.list_policy_group_member_vms(
                            group_id=gid, domain_id=domain_id
                        )
                    except Exception as exc:
                        log.warning(
                            "site=%s group=%s/%s member-fetch failed: %s",
                            site_id, domain_id, gid, exc,
                        )
                        continue
                    for m in members:
                        mid = NsxPolicyClient._extract_vm_id_from_member(m)
                        if mid:
                            ext_ids.add(mid)
            else:
                try:
                    members = client.list_policy_group_member_vms(
                        group_id=gid, domain_id=domain_id
                    )
                except Exception as exc:
                    log.warning(
                        "list_policy_group_member_vms(%s/%s) failed: %s",
                        domain_id, gid, exc,
                    )
                    members = []
                for m in members:
                    mid = NsxPolicyClient._extract_vm_id_from_member(m)
                    if mid:
                        ext_ids.add(mid)
            group_to_members[gpath] = ext_ids
            groups_by_path[gpath]["member_count"] = len(ext_ids)
            if i % 25 == 0:
                log.info("  ... %d/%d group members fetched in domain %s",
                         i, len(groups), domain_id)
    log.info("Groups indexed: %d across %d domain(s)",
             len(groups_by_path), len(domain_ids))
    return groups_by_path, group_to_members


def discover_federation_sites(gm_client: NsxPolicyClient) -> List[Dict[str, Any]]:
    """
    Return a list of federated sites known to this GM. Each entry is the
    raw dict from GET /global-manager/api/v1/global-infra/sites. Empty list
    if the endpoint fails.
    """
    try:
        r = gm_client._get(gm_client.POLICY_ROOT + "/sites")
    except Exception as exc:
        log.error("Federation site discovery failed: %s", exc)
        return []
    sites = r.get("results") or []
    log.info("Federation sites discovered: %d", len(sites))
    return sites


def build_site_clients_for_federation(
    sites: List[Dict[str, Any]],
) -> Tuple[Dict[str, NsxPolicyClient], Dict[str, NsxPolicyClient], Dict[str, str]]:
    """
    For each federation site, build:
      - site_fabric_clients: federation_global=False, for fabric VM inventory
      - site_fed_clients:    federation_global=True,  for federated group members
      - site_display:        site_id -> display_name (for reporting)
    Sites that fail to connect are skipped with a WARN.
    """
    site_fabric: Dict[str, NsxPolicyClient] = {}
    site_fed: Dict[str, NsxPolicyClient] = {}
    site_display: Dict[str, str] = {}
    for s in sites:
        sid = s.get("id")
        if not sid:
            continue
        display = s.get("display_name") or sid
        site_display[sid] = display
        try:
            site_fabric[sid] = NsxPolicyClient(nsxmanager=sid,
                                                federation_global=False)
            site_fed[sid] = NsxPolicyClient(nsxmanager=sid,
                                             federation_global=True)
            log.info("  federation site ready: %s (%s)", sid, display)
        except Exception as exc:
            log.warning("  cannot connect to site %s (%s): %s",
                        sid, display, str(exc)[:120])
    return site_fabric, site_fed, site_display


def build_vm_to_groups(
    group_to_members: Dict[str, Set[str]],
) -> Dict[str, Set[str]]:
    """Reverse index: ext_id -> set(group_paths)."""
    out: Dict[str, Set[str]] = {}
    for gpath, members in group_to_members.items():
        for ext in members:
            out.setdefault(ext, set()).add(gpath)
    return out


def pull_all_rules(
    client: NsxPolicyClient,
    domain_ids: List[str],
) -> List[Dict[str, Any]]:
    """Return a flat list of rule dicts, each augmented with:
      _policy_id, _policy_display, _policy_path, _domain_id, _category.
    Rules preserve their NSX evaluation order.
    """
    all_rules: List[Dict[str, Any]] = []
    for domain_id in domain_ids:
        try:
            policies = client.list_security_policies(domain_id=domain_id)
        except Exception as exc:
            log.error("list_security_policies(%s) failed: %s", domain_id, exc)
            continue
        log.info("Domain %s: %d policy/-ies", domain_id, len(policies))
        for pol in policies:
            pol_id = pol.get("id")
            pol_path = pol.get("path")
            pol_name = pol.get("display_name") or pol_id
            pol_cat = pol.get("category") or ""
            if not pol_id or not pol_path:
                continue
            try:
                rules = client.list_security_rules(
                    security_policy_id=pol_id, domain_id=domain_id,
                )
            except Exception as exc:
                log.warning(
                    "list_security_rules(%s/%s) failed: %s",
                    domain_id, pol_id, exc,
                )
                continue
            for r in rules:
                r["_policy_id"] = pol_id
                r["_policy_path"] = pol_path
                r["_policy_display"] = pol_name
                r["_domain_id"] = domain_id
                r["_category"] = pol_cat
                all_rules.append(r)
    log.info("Rules indexed: %d", len(all_rules))
    return all_rules


# ---------- correlation ----------

def rule_touches_targets(
    rule: Dict[str, Any],
    target_ext_ids: Set[str],
    vm_to_groups: Dict[str, Set[str]],
) -> Dict[str, Any]:
    """
    Determine which target VMs this rule touches and on which sides.
    Returns {"touched": bool, "by_side": {ext_id: [sides]}, "any_src": bool,
             "any_dst": bool, "any_scope": bool, "src_groups": [...],
             "dst_groups": [...], "scope_groups": [...]}
    """
    src_paths = set(_group_paths(rule.get("source_groups")))
    dst_paths = set(_group_paths(rule.get("destination_groups")))
    scope_paths = set(_group_paths(rule.get("scope")))
    any_src = _has_any(rule.get("source_groups"))
    any_dst = _has_any(rule.get("destination_groups"))
    any_scope = _has_any(rule.get("scope"))
    # If source_groups/destination_groups is empty AND has no ANY, we treat as
    # ANY (some rules omit the field entirely to mean "any").
    if not src_paths and not any_src:
        any_src = True
    if not dst_paths and not any_dst:
        any_dst = True
    if not scope_paths and not any_scope:
        any_scope = True

    by_side: Dict[str, List[str]] = {}
    for ext in target_ext_ids:
        vm_groups = vm_to_groups.get(ext) or set()
        sides: List[str] = []
        # A VM matches a side if (ANY on that side) OR (it's a member of a group listed there).
        # But we don't want to over-flag: for reporting purposes, we tag by
        # concrete-match sides first, and fall back to "any-*" annotations only
        # if no concrete matches exist on any side.
        if src_paths and (vm_groups & src_paths):
            sides.append("Src")
        if dst_paths and (vm_groups & dst_paths):
            sides.append("Dst")
        if scope_paths and (vm_groups & scope_paths):
            sides.append("Scope")
        if sides:
            by_side[ext] = sides
        else:
            # No concrete group match; only ANY on all sides could make it hit.
            # If src+dst+scope are ALL any/empty, this is a global rule and
            # every VM is touched.
            if any_src and any_dst and any_scope:
                by_side[ext] = ["ANY"]

    return {
        "touched": bool(by_side),
        "by_side": by_side,
        "any_src": any_src,
        "any_dst": any_dst,
        "any_scope": any_scope,
        "src_groups": sorted(src_paths),
        "dst_groups": sorted(dst_paths),
        "scope_groups": sorted(scope_paths),
    }


# ---------- rendering ----------

def _fmt_group_list(paths: List[str], any_flag: bool,
                    groups_by_path: Dict[str, Dict[str, Any]]) -> str:
    parts: List[str] = []
    if any_flag:
        parts.append("**ANY**")
    for p in paths:
        gname = (groups_by_path.get(p) or {}).get("display_name") or p.split("/")[-1]
        parts.append(_md_esc(gname))
    if not parts:
        parts.append("(none)")
    return ", ".join(parts)


def _fmt_service_list(services: Optional[List[Any]]) -> str:
    if not services:
        return "ANY"
    out: List[str] = []
    for s in services:
        if isinstance(s, str):
            out.append(s.split("/")[-1] if s.startswith("/") else s)
    return ", ".join(out) if out else "ANY"


def render_markdown(
    manager_host: str,
    ran_at: str,
    vm_names_input: List[str],
    resolved: Dict[str, Dict[str, Any]],
    not_found: List[str],
    duplicate_names: List[str],
    hits: List[Dict[str, Any]],
    groups_by_path: Dict[str, Dict[str, Any]],
    total_rules: int,
    federation_mode: str = "lm",
    site_display: Optional[Dict[str, str]] = None,
) -> str:
    site_display = site_display or {}
    show_site_col = federation_mode == "gm" and bool(site_display)
    lines: List[str] = []
    lines.append(f"# VM Rule Membership Report - {manager_host}\n")
    lines.append(f"- **Ran at**: {ran_at}")
    lines.append(f"- **Manager**: {manager_host}")
    lines.append(f"- **Mode**: {'GM federation (multi-site aggregated)' if federation_mode == 'gm' else 'LM (single site)'}")
    if show_site_col:
        lines.append(
            f"- **Federated sites**: {len(site_display)} "
            f"({', '.join(sorted(site_display.values()))})"
        )
    lines.append(f"- **VMs requested**: {len(vm_names_input)}")
    lines.append(f"- **VMs matched on NSX**: {len(resolved)}")
    lines.append(f"- **Names not found**: {len(not_found)}")
    if duplicate_names:
        lines.append(f"- **Duplicate/ambiguous input names**: {len(duplicate_names)}")
    lines.append(f"- **Rules scanned**: {total_rules}")
    lines.append(f"- **Rules hitting at least one requested VM**: {len(hits)}")
    lines.append("")

    # -------- resolved VMs --------
    lines.append(f"## Requested VMs matched ({len(resolved)})\n")
    if not resolved:
        lines.append("_No requested VM names matched a live VM on NSX._\n")
    else:
        if show_site_col:
            lines.append("| # | VM name | Site | External ID | Groups | Rules hit |")
            lines.append("|---:|---|---|---|---:|---:|")
        else:
            lines.append("| # | VM name | External ID | Groups | Rules hit |")
            lines.append("|---:|---|---|---:|---:|")
        for i, (name, meta) in enumerate(resolved.items(), start=1):
            if show_site_col:
                site = site_display.get(meta.get("site_id") or "", "-")
                lines.append(
                    f"| {i} | {_md_esc(meta.get('display_name'))} | "
                    f"{_md_esc(site)} | "
                    f"`{_md_esc((meta.get('external_id') or '')[:20])}...` | "
                    f"{meta.get('group_count', 0)} | "
                    f"{meta.get('rule_hit_count', 0)} |"
                )
            else:
                lines.append(
                    f"| {i} | {_md_esc(meta.get('display_name'))} | "
                    f"`{_md_esc((meta.get('external_id') or '')[:20])}...` | "
                    f"{meta.get('group_count', 0)} | "
                    f"{meta.get('rule_hit_count', 0)} |"
                )
        lines.append("")

    if not_found:
        lines.append(f"## Requested names NOT found on NSX ({len(not_found)})\n")
        lines.append("| # | Requested name |")
        lines.append("|---:|---|")
        for i, n in enumerate(not_found, start=1):
            lines.append(f"| {i} | {_md_esc(n)} |")
        lines.append("")

    if duplicate_names:
        lines.append(f"## Duplicate names in input ({len(duplicate_names)})\n")
        for n in duplicate_names:
            lines.append(f"- {_md_esc(n)}")
        lines.append("")

    # -------- matched VMs with zero rules --------
    zero_rule_vms = [name for name, m in resolved.items()
                     if m.get("rule_hit_count", 0) == 0]
    if zero_rule_vms:
        lines.append(f"## Matched VMs NOT in any rule ({len(zero_rule_vms)})\n")
        for n in zero_rule_vms:
            lines.append(f"- {_md_esc(n)}")
        lines.append("")

    # -------- per-rule sections (the main event) --------
    lines.append(f"## Rules hitting the requested VMs ({len(hits)})\n")
    if not hits:
        lines.append("_None of the matched VMs are referenced by any rule "
                     "(directly or via group membership)._\n")
    for i, h in enumerate(hits, start=1):
        r = h["rule"]
        info = h["info"]
        global_flag = " **[GLOBAL - ANY-src AND ANY-dst]**" if (info["any_src"] and info["any_dst"]) else ""
        disabled = " _(disabled)_" if r.get("disabled") else ""
        lines.append(
            f"### {i}. `{_md_esc(r.get('_policy_display'))}` "
            f"› **{_md_esc(r.get('display_name'))}** "
            f"[{_md_esc(r.get('action') or '?')}]"
            f"{global_flag}{disabled}\n"
        )
        lines.append(
            f"- Policy: `{_md_esc(r.get('_policy_display'))}` "
            f"({_md_esc(r.get('_category') or 'no-category')})"
        )
        lines.append(f"- Rule ID: `{_md_esc(r.get('id'))}`")
        lines.append(f"- Direction: {_md_esc(r.get('direction') or 'IN_OUT')}   "
                     f"IP protocol: {_md_esc(r.get('ip_protocol') or 'IPV4_IPV6')}")
        lines.append(f"- Source: {_fmt_group_list(info['src_groups'], info['any_src'], groups_by_path)}")
        lines.append(f"- Destination: {_fmt_group_list(info['dst_groups'], info['any_dst'], groups_by_path)}")
        lines.append(f"- Applied To (scope): {_fmt_group_list(info['scope_groups'], info['any_scope'], groups_by_path)}")
        lines.append(f"- Services: {_md_esc(_fmt_service_list(r.get('services')))}")
        lines.append("")
        lines.append("| VM | Hit as |")
        lines.append("|---|---|")
        for ext, sides in sorted(
            info["by_side"].items(),
            key=lambda kv: (h["ext_id_to_name"].get(kv[0], kv[0]).lower()),
        ):
            name = h["ext_id_to_name"].get(ext, ext[:12] + "...")
            lines.append(f"| {_md_esc(name)} | {', '.join(sides)} |")
        lines.append("")
    return align_markdown_tables("\n".join(lines))


# ---------- main ----------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rule-centric membership report for a list of VM names."
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3",
                 "nsx-lm4", "nsx-lm5"],
        required=True,
    )
    parser.add_argument(
        "--vm-list", default=None,
        help="Path to a VM display-name list (one name per line, `#` "
             "comments allowed). Case-insensitive match. Precedence: this "
             "flag > VM_RULE_REPORT_LIST (.env) > auto-discovered "
             f"{DEFAULT_LIST_FILENAME} at repo root.",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help=("Root output dir. Default: "
              "<NSX_LOG_DIR>/reports/vm_rule_membership/<manager-host>. "
              "Each run writes a fresh timestamped subdir inside."),
    )
    parser.add_argument(
        "--overwrite", action="store_true",
        help="Delete the timestamped run dir if it already exists.",
    )
    parser.add_argument(
        "--federation-global", action="store_true",
        help="Query the federated /global-infra/ view (use with GM sources).",
    )
    args = parser.parse_args()

    init_cli()
    setup_logging("vm_rule_membership")

    manager_host = resolve_manager(args.manager)
    if not manager_host:
        raise SystemExit(f"Manager not defined for {args.manager}.")

    names_input, list_path = load_vm_names(args.vm_list)
    if not names_input:
        raise SystemExit(f"No VM names loaded (file: {list_path})")

    log.info("Target manager: %s (federation_global=%s)",
             manager_host, args.federation_global)
    client = NsxPolicyClient(nsxmanager=manager_host,
                             federation_global=args.federation_global)

    # ---- pull VMs (and figure out federation topology) ----
    is_gm_federation = (
        args.federation_global and "/global-manager/" in client.POLICY_ROOT
    )
    vm_ext_to_site: Dict[str, str] = {}
    site_display: Dict[str, str] = {}
    site_fabric_clients: Dict[str, NsxPolicyClient] = {}
    site_fed_clients: Dict[str, NsxPolicyClient] = {}

    if is_gm_federation:
        log.info("Detected GM federation mode. Discovering sites.")
        sites = discover_federation_sites(client)
        if not sites:
            raise SystemExit(
                "GM federation mode: no sites discovered. Cannot fetch VM "
                "inventory without at least one site."
            )
        site_fabric_clients, site_fed_clients, site_display = (
            build_site_clients_for_federation(sites)
        )
        if not site_fabric_clients:
            raise SystemExit(
                "GM federation mode: no site LMs reachable. Check .env "
                "hostnames and network connectivity, then retry."
            )
        vms: List[Dict[str, Any]] = []
        for sid, fab_c in site_fabric_clients.items():
            try:
                site_vms = fab_c.list_virtual_machines()
            except Exception as exc:
                log.warning("Site %s (%s): list_virtual_machines failed: %s",
                            sid, site_display.get(sid, sid), exc)
                continue
            for vm in site_vms:
                ext = vm.get("external_id") or vm.get("id")
                if ext:
                    vm_ext_to_site[ext] = sid
            vms.extend(site_vms)
            log.info("Site %s (%s): %d VM(s) pulled",
                     sid, site_display.get(sid, sid), len(site_vms))
    elif args.federation_global:
        # Federation on an LM: unusual but not fatal. Fabric API still LM-only.
        log.info("federation_global=True on an LM (not a GM). "
                 "Fetching fabric VMs from this LM.")
        # LM fabric requires federation_global=False on the client; make a
        # dedicated one just for this call.
        _fab_client = NsxPolicyClient(nsxmanager=manager_host,
                                       federation_global=False)
        vms = _fab_client.list_virtual_machines()
    else:
        log.info("Fetching virtual machines from %s", manager_host)
        vms = client.list_virtual_machines()

    by_name, by_ext = build_vm_index(vms)
    log.info("VMs indexed: %d (by-name unique keys=%d)", len(vms), len(by_name))

    # ---- resolve target names ----
    resolved: Dict[str, Dict[str, Any]] = {}  # display_name -> {external_id, display_name, ...}
    not_found: List[str] = []
    duplicate_names: List[str] = []
    seen: Set[str] = set()
    for raw in names_input:
        key = raw.strip().lower()
        if not key:
            continue
        if key in seen:
            duplicate_names.append(raw)
            continue
        seen.add(key)
        vm = by_name.get(key)
        if not vm:
            not_found.append(raw)
            continue
        ext = vm.get("external_id") or vm.get("id")
        display = vm.get("display_name") or raw
        if not ext:
            not_found.append(raw)
            continue
        resolved[display] = {
            "external_id": ext,
            "display_name": display,
            "tags": vm.get("tags") or [],
            "site_id": vm_ext_to_site.get(ext),
        }
    log.info(
        "Requested %d name(s): resolved=%d, not_found=%d, duplicates=%d",
        len(names_input), len(resolved), len(not_found), len(duplicate_names),
    )

    target_ext_ids: Set[str] = {m["external_id"] for m in resolved.values()}
    ext_id_to_name: Dict[str, str] = {m["external_id"]: m["display_name"]
                                       for m in resolved.values()}

    # ---- pull domains, groups + members, rules ----
    try:
        domains = client.list_domains()
    except Exception as exc:
        raise SystemExit(f"list_domains failed: {exc}")
    domain_ids = [d.get("id") for d in domains if d.get("id")]
    if not domain_ids:
        raise SystemExit("No domains returned from NSX.")
    log.info("Domains: %s", ", ".join(domain_ids))

    groups_by_path, group_to_members = pull_groups_with_members(
        client,
        domain_ids,
        site_clients_for_members=site_fed_clients if is_gm_federation else None,
    )
    vm_to_groups = build_vm_to_groups(group_to_members)

    # Attach per-VM group counts to the resolved dict for the summary table
    for meta in resolved.values():
        meta["group_count"] = len(vm_to_groups.get(meta["external_id"]) or set())
        meta["rule_hit_count"] = 0  # filled in after rule walk

    all_rules = pull_all_rules(client, domain_ids)

    # ---- walk rules, find hits ----
    hits: List[Dict[str, Any]] = []
    for rule in all_rules:
        info = rule_touches_targets(rule, target_ext_ids, vm_to_groups)
        if not info["touched"]:
            continue
        hits.append({
            "rule": rule,
            "info": info,
            "ext_id_to_name": ext_id_to_name,
        })
        for ext in info["by_side"]:
            meta = next((m for m in resolved.values()
                         if m["external_id"] == ext), None)
            if meta is not None:
                meta["rule_hit_count"] = meta.get("rule_hit_count", 0) + 1
    log.info("Rules touching >= 1 requested VM: %d / %d", len(hits), len(all_rules))

    # ---- output dir ----
    if args.output_dir:
        base_out = Path(args.output_dir).expanduser().resolve()
    else:
        base_out = (
            Path(nsx_log_dir).expanduser().resolve()
            / "reports" / "vm_rule_membership" / manager_host
        )
    out_dir = base_out / RUN_TS
    if out_dir.exists():
        if not args.overwrite:
            raise SystemExit(
                f"Output dir already exists: {out_dir} (pass --overwrite)"
            )
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- render + write ----
    ran_at = datetime.now(timezone.utc).isoformat()
    md_text = render_markdown(
        manager_host=manager_host,
        ran_at=ran_at,
        vm_names_input=names_input,
        resolved=resolved,
        not_found=not_found,
        duplicate_names=duplicate_names,
        hits=hits,
        groups_by_path=groups_by_path,
        total_rules=len(all_rules),
        federation_mode=("gm" if is_gm_federation else "lm"),
        site_display=site_display,
    )
    md_path = out_dir / "report.md"
    md_path.write_text(md_text, encoding="utf-8")
    log.info("Markdown report: %s", md_path)

    json_doc = {
        "manager": args.manager,
        "manager_host": manager_host,
        "ran_at": ran_at,
        "vm_list_source": str(list_path),
        "vm_names_input": names_input,
        "federation_mode": "gm" if is_gm_federation else "lm",
        "federation_sites": [
            {"site_id": sid, "display_name": name}
            for sid, name in sorted(site_display.items())
        ],
        "counts": {
            "requested": len(names_input),
            "resolved": len(resolved),
            "not_found": len(not_found),
            "duplicates": len(duplicate_names),
            "domains": len(domain_ids),
            "groups": len(groups_by_path),
            "rules_total": len(all_rules),
            "rules_hitting_targets": len(hits),
        },
        "resolved": [
            {**meta, "external_id_full": meta["external_id"]}
            for meta in resolved.values()
        ],
        "not_found": not_found,
        "duplicates": duplicate_names,
        "rules": [
            {
                "policy_display": h["rule"].get("_policy_display"),
                "policy_id": h["rule"].get("_policy_id"),
                "domain_id": h["rule"].get("_domain_id"),
                "category": h["rule"].get("_category"),
                "rule_id": h["rule"].get("id"),
                "rule_display": h["rule"].get("display_name"),
                "action": h["rule"].get("action"),
                "direction": h["rule"].get("direction"),
                "disabled": bool(h["rule"].get("disabled")),
                "source_groups": h["info"]["src_groups"],
                "destination_groups": h["info"]["dst_groups"],
                "scope_groups": h["info"]["scope_groups"],
                "any_source": h["info"]["any_src"],
                "any_destination": h["info"]["any_dst"],
                "any_scope": h["info"]["any_scope"],
                "services": h["rule"].get("services"),
                "hits": [
                    {
                        "external_id": ext,
                        "display_name": ext_id_to_name.get(ext),
                        "sides": sides,
                    }
                    for ext, sides in h["info"]["by_side"].items()
                ],
            }
            for h in hits
        ],
    }
    json_path = out_dir / "report.json"
    json_path.write_text(
        json.dumps(json_doc, indent=2, sort_keys=True), encoding="utf-8",
    )
    log.info("JSON report:     %s", json_path)

    print(json.dumps({
        "manager": manager_host,
        "requested": len(names_input),
        "resolved": len(resolved),
        "not_found": len(not_found),
        "duplicates": len(duplicate_names),
        "groups_indexed": len(groups_by_path),
        "rules_scanned": len(all_rules),
        "rules_hitting_targets": len(hits),
        "output_dir": str(out_dir),
        "markdown": str(md_path),
        "json": str(json_path),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
