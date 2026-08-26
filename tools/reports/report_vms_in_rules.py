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
import ipaddress
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

def load_vm_names(
    explicit_path: Optional[str],
) -> Tuple[List[Tuple[str, Optional[List[str]]]], Path]:
    """
    Load the VM target list. Returns (entries, source_path) where each entry
    is (name, ips_or_None):
      - ips=None  -> name-only entry, NSX will be queried to resolve it
      - ips=list  -> planned/external entry: use these IPs directly, skip NSX lookup

    File format per non-blank, non-comment line:
      <name>                       # NSX lookup
      <name>,<ip>                  # planned VM with one IP
      <name>,<ip1>,<ip2>,...       # planned VM with multiple IPs

    Precedence for the list path:
      1. explicit --vm-list
      2. VM_RULE_REPORT_LIST env var
      3. auto-discovered REPO_ROOT/vm_rule_report_targets.txt
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

    entries: List[Tuple[str, Optional[List[str]]]] = []
    for lineno, line in enumerate(fp.read_text(encoding="utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = [p.strip() for p in s.split(",")]
        if not parts[0]:
            log.warning("Line %d: blank name, skipping: %r", lineno, line)
            continue
        name = parts[0]
        ip_tokens = [p for p in parts[1:] if p]
        if not ip_tokens:
            entries.append((name, None))
            continue
        valid_ips: List[str] = []
        for tok in ip_tokens:
            try:
                ipaddress.ip_address(tok)
                valid_ips.append(tok)
            except ValueError:
                log.warning(
                    "Line %d: %r has invalid IP %r; ignoring that token.",
                    lineno, name, tok,
                )
        if not valid_ips:
            log.warning(
                "Line %d: %r had IP tokens but none parsed; treating as name-only.",
                lineno, name,
            )
            entries.append((name, None))
        else:
            entries.append((name, valid_ips))
    n_named = sum(1 for _, ips in entries if ips is None)
    n_planned = sum(1 for _, ips in entries if ips is not None)
    log.info(
        "Loaded %d entry/-ies from %s (%s): name-only=%d, planned-with-ip=%d",
        len(entries), fp, source, n_named, n_planned,
    )
    return entries, fp


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


def _short(s: Any, maxlen: int = 40) -> str:
    """Truncate long strings with a trailing ellipsis so a single very long
    rule / group name can't blow up the whole table's column widths."""
    if s is None:
        return ""
    text = str(s)
    if len(text) <= maxlen:
        return text
    # Reserve 3 chars for the ellipsis
    return text[: max(1, maxlen - 3)] + "..."


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


def pull_group_ip_memberships(
    client: NsxPolicyClient,
    groups_by_path: Dict[str, Dict[str, Any]],
    site_clients_for_members: Optional[Dict[str, NsxPolicyClient]] = None,
) -> Dict[str, Set[str]]:
    """
    For each group, fetch /members/ip-addresses (returns every IP or CIDR the
    group evaluates to, including from IP-only expressions). Returns
    group_path -> set(ip_or_cidr strings). Errors per group are logged and
    the group ends up with an empty set.

    In GM federation mode, per-site clients are unioned.
    """
    result: Dict[str, Set[str]] = {}
    for gpath, meta in groups_by_path.items():
        domain_id = meta["domain_id"]
        gid = meta["id"]
        ips: Set[str] = set()
        if site_clients_for_members:
            iter_clients = site_clients_for_members.items()
        else:
            iter_clients = [("(single)", client)]
        for label, cli in iter_clients:
            try:
                path = cli._policy_path(
                    f"/domains/{cli._q(domain_id)}/groups/{cli._q(gid)}/members/ip-addresses"
                )
                r = cli._get(path)
            except Exception as exc:
                log.warning("group=%s/%s (%s): /members/ip-addresses failed: %s",
                            domain_id, gid, label, exc)
                continue
            for ip in (r.get("results") or []):
                if isinstance(ip, str) and ip.strip():
                    ips.add(ip.strip())
        result[gpath] = ips
    total_ips = sum(len(v) for v in result.values())
    log.info("Group IP memberships fetched: %d total IP/CIDR entries across %d group(s)",
             total_ips, len(result))
    return result


def _parse_ip_or_cidr(s: str) -> Optional[Tuple[str, Any]]:
    """Return ('addr', ip_address) or ('net', ip_network) or None if unparseable."""
    try:
        if "/" in s:
            return ("net", ipaddress.ip_network(s, strict=False))
        return ("addr", ipaddress.ip_address(s))
    except (ValueError, TypeError):
        return None


def match_vm_ips_to_groups(
    vm_ips: Dict[str, List[str]],
    group_ips: Dict[str, Set[str]],
) -> Dict[str, Set[str]]:
    """Given ext_id -> [vm ip strings] and group_path -> {group ip/cidr strings},
    return ext_id -> set(group_paths) where the VM's IPs are covered by the
    group's IP entries. Handles IPv4 + IPv6. CIDR containment respected."""
    parsed_groups: Dict[str, List[Tuple[str, Any]]] = {}
    for gpath, ips in group_ips.items():
        parsed: List[Tuple[str, Any]] = []
        for s in ips:
            entry = _parse_ip_or_cidr(s)
            if entry is not None:
                parsed.append(entry)
        parsed_groups[gpath] = parsed

    out: Dict[str, Set[str]] = {}
    for ext_id, ip_list in vm_ips.items():
        vm_addrs = []
        for s in ip_list:
            try:
                vm_addrs.append(ipaddress.ip_address(s))
            except (ValueError, TypeError):
                continue
        if not vm_addrs:
            continue
        matched: Set[str] = set()
        for gpath, entries in parsed_groups.items():
            hit = False
            for kind, val in entries:
                if kind == "addr":
                    if any(a == val for a in vm_addrs):
                        hit = True
                        break
                else:  # net
                    if any(a in val for a in vm_addrs):
                        hit = True
                        break
            if hit:
                matched.add(gpath)
        if matched:
            out[ext_id] = matched
    return out


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
                    groups_by_path: Dict[str, Dict[str, Any]],
                    per_name_maxlen: int = 30) -> str:
    parts: List[str] = []
    if any_flag:
        parts.append("**ANY**")
    for p in paths:
        gname = (groups_by_path.get(p) or {}).get("display_name") or p.split("/")[-1]
        parts.append(_md_esc(_short(gname, per_name_maxlen)))
    if not parts:
        parts.append("(none)")
    return ", ".join(parts)


def _fmt_group_list_for_vm(
    paths: List[str],
    any_flag: bool,
    groups_by_path: Dict[str, Dict[str, Any]],
    vm_groups: Set[str],
    per_name_maxlen: int = 30,
) -> str:
    """VM-scoped version: only shows groups from `paths` that this VM is
    actually a member of, so the Src/Dst cell describes THIS VM's match
    (not the rule's full group list).

    - If the side is ANY on the rule, show 'ANY'.
    - If the VM isn't a member of any group on this side, show '-'.
    - Otherwise show the intersection.
    """
    if any_flag:
        return "**ANY**"
    matched = [p for p in paths if p in vm_groups]
    if not matched:
        return "-"
    parts: List[str] = []
    for p in matched:
        gname = (groups_by_path.get(p) or {}).get("display_name") or p.split("/")[-1]
        parts.append(_md_esc(_short(gname, per_name_maxlen)))
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
    vm_to_groups: Dict[str, Set[str]],
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
    n_nsx = sum(1 for m in resolved.values() if m.get("kind") == "NSX")
    n_nsx_ip = sum(1 for m in resolved.values() if m.get("kind") == "NSX+ip")
    n_planned = sum(1 for m in resolved.values() if m.get("kind") == "planned")
    lines.append(f"- **Entries requested**: {len(vm_names_input)}")
    lines.append(
        f"- **Resolved**: {len(resolved)}   "
        f"(NSX={n_nsx}, NSX+explicit-IPs={n_nsx_ip}, planned={n_planned})"
    )
    lines.append(f"- **Names not found (name-only entries, no NSX match)**: {len(not_found)}")
    if duplicate_names:
        lines.append(f"- **Duplicate/ambiguous input names**: {len(duplicate_names)}")
    lines.append(f"- **Rules scanned**: {total_rules}")
    lines.append(f"- **Rules hitting at least one requested VM**: {len(hits)}")
    lines.append("")

    # -------- resolved VMs --------
    lines.append(f"## Requested VMs matched ({len(resolved)})\n")
    if not resolved:
        lines.append("_No requested VM names resolved (either not found on NSX and no IPs supplied)._\n")
    else:
        if show_site_col:
            lines.append("| # | VM name | Kind | Site | IPs | Groups | Rules hit |")
            lines.append("|---:|---|---|---|---|---:|---:|")
        else:
            lines.append("| # | VM name | Kind | IPs | Groups | Rules hit |")
            lines.append("|---:|---|---|---|---:|---:|")
        for i, (name, meta) in enumerate(resolved.items(), start=1):
            kind = meta.get("kind", "NSX")
            ips = meta.get("ips") or []
            ips_cell = _md_esc(_short(", ".join(ips) if ips else "-", 50))
            if show_site_col:
                site = site_display.get(meta.get("site_id") or "", "-")
                lines.append(
                    f"| {i} | {_md_esc(meta.get('display_name'))} | "
                    f"{kind} | "
                    f"{_md_esc(site)} | "
                    f"{ips_cell} | "
                    f"{meta.get('group_count', 0)} | "
                    f"{meta.get('rule_hit_count', 0)} |"
                )
            else:
                lines.append(
                    f"| {i} | {_md_esc(meta.get('display_name'))} | "
                    f"{kind} | "
                    f"{ips_cell} | "
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

    # -------- per-VM rule tables (the main event) --------
    # Build: ext_id -> [(rule_dict, info_dict, sides_list), ...] preserving
    # NSX rule order (already the order in `hits`).
    per_vm: Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any], List[str]]]] = {}
    for h in hits:
        for ext_id, sides in h["info"]["by_side"].items():
            per_vm.setdefault(ext_id, []).append((h["rule"], h["info"], sides))

    lines.append(f"## Rules per VM\n")
    if not resolved:
        lines.append("_No matched VMs to report on._\n")
    for name, meta in resolved.items():
        ext = meta["external_id"]
        rules_for_vm = per_vm.get(ext, [])
        n = len(rules_for_vm)
        header = f"### {_md_esc(name)}   `{n} rule{'s' if n != 1 else ''}`"
        if show_site_col:
            site = site_display.get(meta.get("site_id") or "", "-")
            header += f"   _(site: {_md_esc(site)})_"
        lines.append(header + "\n")
        if not rules_for_vm:
            lines.append("_Not referenced by any rule._\n")
            continue
        lines.append("| # | Policy | Rule | Action | Source | Destination | Hit as |")
        lines.append("|---:|---|---|---|---|---|---|")
        vm_groups = vm_to_groups.get(ext, set())
        for i, (r, info, sides) in enumerate(rules_for_vm, start=1):
            global_flag = " *(global)*" if (info["any_src"] and info["any_dst"]) else ""
            disabled = " *(disabled)*" if r.get("disabled") else ""
            action = (r.get("action") or "?").upper()
            lines.append(
                f"| {i} | "
                f"{_md_esc(_short(r.get('_policy_display'), 30))} | "
                f"{_md_esc(_short(r.get('display_name'), 40))}{disabled} | "
                f"{action}{global_flag} | "
                f"{_fmt_group_list_for_vm(info['src_groups'], info['any_src'], groups_by_path, vm_groups)} | "
                f"{_fmt_group_list_for_vm(info['dst_groups'], info['any_dst'], groups_by_path, vm_groups)} | "
                f"{', '.join(sides)} |"
            )
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

    # ---- resolve target entries ----
    # Each input entry is (name, ips_or_None):
    #   ips is None    -> name-only, look up on NSX
    #   ips is a list  -> planned/IP-only; skip NSX lookup, use given IPs
    resolved: Dict[str, Dict[str, Any]] = {}  # display_name -> meta
    not_found: List[str] = []
    duplicate_names: List[str] = []
    seen: Set[str] = set()
    vm_ips: Dict[str, List[str]] = {}   # ext_id (or synthetic) -> [ip strings]
    for raw_name, raw_ips in names_input:
        key = raw_name.strip().lower()
        if not key:
            continue
        if key in seen:
            duplicate_names.append(raw_name)
            continue
        seen.add(key)
        explicit_ips = list(raw_ips) if raw_ips else []

        vm = by_name.get(key)
        if vm:
            # NSX-matched: auto-fetch IPs from fabric dict, union with explicit
            ext = vm.get("external_id") or vm.get("id")
            display = vm.get("display_name") or raw_name
            if not ext:
                # Rare: NSX returned a VM but no id. Fall back to planned if
                # we have explicit IPs, else not_found.
                if explicit_ips:
                    synth_ext = f"planned:{raw_name}"
                    resolved[raw_name] = {
                        "external_id": synth_ext,
                        "display_name": raw_name,
                        "kind": "planned",
                        "tags": [],
                        "site_id": None,
                        "ips": explicit_ips,
                    }
                    vm_ips[synth_ext] = explicit_ips
                else:
                    not_found.append(raw_name)
                continue
            auto_ips = sorted(NsxPolicyClient._collect_ips_recursive(vm))
            merged_ips = sorted(set(auto_ips) | set(explicit_ips))
            resolved[display] = {
                "external_id": ext,
                "display_name": display,
                "kind": "NSX+ip" if explicit_ips else "NSX",
                "tags": vm.get("tags") or [],
                "site_id": vm_ext_to_site.get(ext),
                "ips": merged_ips,
                "explicit_ips": explicit_ips,
                "auto_ips": auto_ips,
            }
            vm_ips[ext] = merged_ips
            continue

        # Name NOT on NSX. If explicit IPs supplied, treat as planned/IP-only.
        if explicit_ips:
            synth_ext = f"planned:{raw_name}"
            resolved[raw_name] = {
                "external_id": synth_ext,
                "display_name": raw_name,
                "kind": "planned",
                "tags": [],
                "site_id": None,
                "ips": explicit_ips,
                "explicit_ips": explicit_ips,
                "auto_ips": [],
            }
            vm_ips[synth_ext] = explicit_ips
        else:
            not_found.append(raw_name)
    log.info(
        "Requested %d entry/-ies: resolved=%d, not_found=%d, duplicates=%d",
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

    # ---- augment memberships by IP ----
    # Groups can include IP addresses / CIDRs (either as their only members or
    # mixed with tag/segment/path). NSX evaluates DFW rules against packet IPs,
    # so a VM whose IP falls inside a group's IP set is effectively a member
    # for rule-matching purposes. Fetch /members/ip-addresses per group and
    # add matches into vm_to_groups.
    group_ips = pull_group_ip_memberships(
        client,
        groups_by_path,
        site_clients_for_members=site_fed_clients if is_gm_federation else None,
    )
    ip_based_matches = match_vm_ips_to_groups(vm_ips, group_ips)
    for ext, gps in ip_based_matches.items():
        vm_to_groups.setdefault(ext, set()).update(gps)
    log.info("IP-based membership added: %d VM(s) matched %d additional group(s)",
             len(ip_based_matches), sum(len(v) for v in ip_based_matches.values()))

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
    input_names_only = [n for (n, _ips) in names_input]
    md_text = render_markdown(
        manager_host=manager_host,
        ran_at=ran_at,
        vm_names_input=input_names_only,
        resolved=resolved,
        not_found=not_found,
        duplicate_names=duplicate_names,
        hits=hits,
        groups_by_path=groups_by_path,
        total_rules=len(all_rules),
        vm_to_groups=vm_to_groups,
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
        "vm_entries_input": [
            {"name": n, "planned_ips": ips} for (n, ips) in names_input
        ],
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
