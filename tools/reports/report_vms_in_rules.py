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
from nsx.report_paths import report_run_dir, reports_root

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


def _load_members_cache(path: Path, minutes: int, referenced: Set[str]):
    """Load the on-disk member cache when fresh AND it covers every
    rule-referenced group. Returns (groups_by_path, group_to_members,
    member_meta, group_ips) or None."""
    if minutes <= 0 or not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        age_min = (datetime.now(timezone.utc)
                   - datetime.fromisoformat(data["ts"])).total_seconds() / 60.0
        if age_min > minutes:
            log.info("Member cache is %.1f min old (> %d): refetching.", age_min, minutes)
            return None
        cached_keys = set(data["group_to_members"].keys())
        missing = {x for x in referenced if x not in cached_keys}
        if missing:
            log.info("Member cache lacks %d rule-referenced group(s): refetching.", len(missing))
            return None
        return (
            data["groups_by_path"],
            {k: set(v) for k, v in data["group_to_members"].items()},
            data["member_meta"],
            {k: set(v) for k, v in data["group_ips"].items()},
        )
    except Exception as exc:
        log.warning("Member cache unreadable (%s): refetching.", exc)
        return None


def _save_members_cache(path: Path, groups_by_path, group_to_members,
                        member_meta, group_ips) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "groups_by_path": groups_by_path,
            "group_to_members": {k: sorted(v) for k, v in group_to_members.items()},
            "member_meta": member_meta,
            "group_ips": {k: sorted(v) for k, v in group_ips.items()},
        }, sort_keys=True), encoding="utf-8")
        log.info("Member cache saved: %s", path)
    except Exception as exc:
        log.warning("Member cache save failed: %s", exc)


def pull_groups_with_members(
    client: NsxPolicyClient,
    domain_ids: List[str],
    gm_site_eps: Optional[Dict[str, str]] = None,
    only_paths: Optional[Set[str]] = None,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Set[str]], Dict[str, Dict[str, Any]]]:
    """
    For every group in every domain, fetch live VM members via
    /members/virtual-machines. Returns:
      groups_by_path: group_path -> {id, display_name, domain_id, member_count}
      group_to_members: group_path -> set(external_id)
      member_meta: external_id -> {display_name, site_id, tags} harvested from
        the member objects themselves (the GM-only VM universe).

    If `gm_site_eps` is provided (GM federation mode: site_id -> enforcement
    point path), member lookups go THROUGH THE GM with an
    `enforcement_point_path` query parameter, one call per site per group, and
    are UNIONed. No direct LM connections are made: a bare GM /members call
    returns 400, but the enforcement-point form is proxied by the GM to each
    site. Otherwise the single `client` is queried directly (LM mode).

    Errors on a single group are logged and skipped (empty member set).
    """
    groups_by_path: Dict[str, Dict[str, Any]] = {}
    group_to_members: Dict[str, Set[str]] = {}
    member_meta: Dict[str, Dict[str, Any]] = {}
    site_fail_counts: Dict[str, int] = {}
    site_first_error: Dict[str, str] = {}
    benign_skips = 0   # cross-site NOT_FOUND: group not realized at that site
    api_calls = 0
    pruned = 0

    def _eps_for_domain(domain_id: str) -> Dict[str, str]:
        """Location-scoped domains (domain id == a site id) exist only at
        their own site; querying other sites' enforcement points is a
        guaranteed NOT_FOUND. Global domains fan out to every site."""
        if gm_site_eps and domain_id in gm_site_eps:
            return {domain_id: gm_site_eps[domain_id]}
        return gm_site_eps or {}

    def _is_not_found(exc: Exception) -> bool:
        s = str(exc)
        return "could not be found" in s.lower() or "NOT_FOUND" in s or " 600]" in s

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
            if only_paths is not None and gpath not in only_paths:
                # No rule references this group: its membership cannot affect
                # the report. Indexed for display, members not fetched.
                group_to_members[gpath] = set()
                groups_by_path[gpath]["member_count"] = 0
                groups_by_path[gpath]["members_fetched"] = False
                pruned += 1
                continue
            groups_by_path[gpath]["members_fetched"] = True
            ext_ids: Set[str] = set()
            members_path = client._policy_path(
                f"/domains/{client._q(domain_id)}/groups/{client._q(gid)}"
                "/members/virtual-machines"
            )
            if gm_site_eps:
                # Federated: GM-proxied, per relevant site, paginated, unioned.
                for site_id, ep in _eps_for_domain(domain_id).items():
                    cursor = None
                    failed = False
                    while True:
                        params = {"enforcement_point_path": ep, "page_size": 1000}
                        if cursor:
                            params["cursor"] = cursor
                        try:
                            r = client._get(members_path, params=params)
                            api_calls += 1
                        except Exception as exc:
                            if _is_not_found(exc):
                                # Group not realized at this site: benign in
                                # federated setups with location-scoped spans.
                                benign_skips += 1
                                log.debug("site=%s group=%s/%s not realized there (skipped)",
                                          site_id, domain_id, gid)
                            else:
                                site_fail_counts[site_id] = site_fail_counts.get(site_id, 0) + 1
                                site_first_error.setdefault(site_id, f"group {domain_id}/{gid}: {exc}")
                                if site_fail_counts[site_id] <= 3:
                                    log.warning(
                                        "site=%s group=%s/%s member-fetch via GM failed: %s",
                                        site_id, domain_id, gid, exc,
                                    )
                            failed = True
                            break
                        members = r.get("results") or []
                        for m in members:
                            mid = NsxPolicyClient._extract_vm_id_from_member(m)
                            if mid:
                                ext_ids.add(mid)
                                member_meta.setdefault(mid, {
                                    "display_name": m.get("display_name"),
                                    "site_id": site_id,
                                    "tags": m.get("tags") or [],
                                })
                        cursor = r.get("cursor")
                        if not cursor or not members:
                            break
                    if failed:
                        continue
            else:
                try:
                    members = client.list_policy_group_member_vms(
                        group_id=gid, domain_id=domain_id
                    )
                    # One member fetch per group. The GM branch above counts
                    # each page; here the client pages internally, so this
                    # undercounts only for groups with >1000 members.
                    api_calls += 1
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
                        member_meta.setdefault(mid, {
                            "display_name": m.get("display_name"),
                            "site_id": None,
                            "tags": m.get("tags") or [],
                        })
            group_to_members[gpath] = ext_ids
            groups_by_path[gpath]["member_count"] = len(ext_ids)
            if i % 25 == 0:
                log.info("  ... %d/%d group members fetched in domain %s",
                         i, len(groups), domain_id)
    log.info("Groups indexed: %d across %d domain(s)",
             len(groups_by_path), len(domain_ids))
    if benign_skips:
        log.info("Cross-site lookups skipped as not-realized-at-site (benign): %d",
                 benign_skips)
    log.info("Member API calls: %d (groups pruned as not rule-referenced: %d)",
             api_calls, pruned)
    total_groups = len(groups_by_path)
    for site_id, fails in site_fail_counts.items():
        if fails >= total_groups and total_groups:
            log.error(
                "site=%s: member fetch failed for ALL %d group(s). The GM could "
                "not proxy to this site (site disconnected from GM, wrong "
                "enforcement point, or GM version without proxy support). "
                "First error: %s",
                site_id, fails, site_first_error.get(site_id, "?"),
            )
        elif fails:
            log.warning("site=%s: member fetch failed for %d/%d group(s); "
                        "first error: %s",
                        site_id, fails, total_groups,
                        site_first_error.get(site_id, "?"))
    return groups_by_path, group_to_members, member_meta


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
    gm_site_eps: Optional[Dict[str, str]] = None,
    only_paths: Optional[Set[str]] = None,
) -> Dict[str, Set[str]]:
    """
    For each group, fetch /members/ip-addresses (returns every IP or CIDR the
    group evaluates to, including from IP-only expressions). Returns
    group_path -> set(ip_or_cidr strings). Errors per group are logged and
    the group ends up with an empty set.

    In GM federation mode, the calls go THROUGH THE GM (enforcement_point_path
    per site) and are unioned; no direct LM connections.
    """
    result: Dict[str, Set[str]] = {}
    api_calls = 0
    total_groups = len(groups_by_path)
    to_fetch = (total_groups if only_paths is None
                else sum(1 for gp in groups_by_path if gp in only_paths))
    log.info("Fetching group IP memberships for %d of %d group(s) ...",
             to_fetch, total_groups)
    for i, (gpath, meta) in enumerate(groups_by_path.items(), start=1):
        if only_paths is not None and gpath not in only_paths:
            result[gpath] = set()
            continue
        domain_id = meta["domain_id"]
        gid = meta["id"]
        ips: Set[str] = set()
        path = client._policy_path(
            f"/domains/{client._q(domain_id)}/groups/{client._q(gid)}/members/ip-addresses"
        )
        if gm_site_eps:
            eps = ({domain_id: gm_site_eps[domain_id]}
                   if domain_id in gm_site_eps else gm_site_eps)
            base_params = [(sid, {"enforcement_point_path": ep}) for sid, ep in eps.items()]
        else:
            base_params = [("(single)", {})]
        for label, base in base_params:
            cursor = None
            while True:
                params = dict(base, page_size=1000)
                if cursor:
                    params["cursor"] = cursor
                try:
                    r = client._get(path, params=params)
                    api_calls += 1
                except Exception as exc:
                    s = str(exc)
                    if "could not be found" in s.lower() or "NOT_FOUND" in s:
                        log.debug("group=%s/%s (%s): not realized there (skipped)",
                                  domain_id, gid, label)
                    else:
                        log.warning("group=%s/%s (%s): /members/ip-addresses failed: %s",
                                    domain_id, gid, label, exc)
                    break
                page = r.get("results") or []
                for ip in page:
                    if isinstance(ip, str) and ip.strip():
                        ips.add(ip.strip())
                cursor = r.get("cursor")
                if not cursor or not page:
                    break
        result[gpath] = ips
        if i % 25 == 0:
            log.info("  ... %d/%d group IP members fetched", i, total_groups)
    log.info("IP-member API calls: %d", api_calls)
    total_ips = sum(len(v) for v in result.values())
    log.info("Group IP memberships fetched: %d total IP/CIDR entries across %d group(s)",
             total_ips, len(result))
    return result


def _parse_ip_or_cidr(s: str) -> Optional[Tuple[str, Any]]:
    """Return ('addr', ip_address), ('net', ip_network), or ('range', (lo, hi))
    for a-b range entries; None if unparseable."""
    try:
        if "/" in s:
            return ("net", ipaddress.ip_network(s, strict=False))
        if "-" in s:
            lo_s, hi_s = (x.strip() for x in s.split("-", 1))
            lo, hi = ipaddress.ip_address(lo_s), ipaddress.ip_address(hi_s)
            if lo.version != hi.version or lo > hi:
                return None
            return ("range", (lo, hi))
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
                elif kind == "range":
                    lo, hi = val
                    if any(a.version == lo.version and lo <= a <= hi
                           for a in vm_addrs):
                        hit = True
                        break
                else:  # net
                    if any(a.version == val.version and a in val
                           for a in vm_addrs):
                        hit = True
                        break
            if hit:
                matched.add(gpath)
        if matched:
            out[ext_id] = matched
    return out


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


# ---------- offline inputs (no NSX contact) ----------

def _collect_ip_entries(expression: Optional[List[Dict[str, Any]]]) -> Set[str]:
    """Every IP/CIDR/range an expression tree contributes.

    Recurses NestedExpression (child key 'expressions'). A tool that walks
    expression[] without recursing silently under-reports compound groups,
    which are exactly the ones API/Terraform-built environments produce.
    """
    out: Set[str] = set()
    for e in (expression or []):
        if not isinstance(e, dict):
            continue
        rt = e.get("resource_type")
        if rt == "IPAddressExpression":
            out.update(str(x) for x in (e.get("ip_addresses") or []))
        elif rt == "NestedExpression":
            out.update(_collect_ip_entries(e.get("expressions")))
    return out


def _capture_export_root(bundle: Path) -> Path:
    """nsx_capture/<host>/nsx_export/<host>/ -> the dir holding domains/."""
    direct = bundle / "domains"
    if direct.is_dir():
        return bundle
    exp = bundle / "nsx_export"
    if exp.is_dir():
        for child in sorted(exp.iterdir()):
            if (child / "domains").is_dir():
                return child
    raise SystemExit(f"--from-capture: no domains/ found under {bundle}")


def load_capture_groups(export_root: Path,
                        ) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str],
                                   Dict[str, Set[str]], List[str]]:
    """Read captured group definitions.

    Returns (groups_by_path, group_id_to_path, group_ips, domain_ids).
    group_ips comes from the captured IPAddressExpression entries, which is
    the definition rather than NSX's evaluated /members/ip-addresses answer.
    """
    import yaml
    groups_by_path: Dict[str, Dict[str, Any]] = {}
    id_to_path: Dict[str, str] = {}
    group_ips: Dict[str, Set[str]] = {}
    domain_ids: List[str] = []
    domains_dir = export_root / "domains"
    for ddir in sorted(d for d in domains_dir.iterdir() if d.is_dir()):
        domain_ids.append(ddir.name)
        gdir = ddir / "groups"
        if not gdir.is_dir():
            continue
        for f in sorted(gdir.glob("*.yaml")):
            if f.name == "index.yaml":
                continue
            try:
                obj = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            except Exception as exc:
                log.warning("capture: unreadable group file %s: %s", f.name, exc)
                continue
            gid, gpath = obj.get("id"), obj.get("path")
            if not gid or not gpath:
                continue
            groups_by_path[gpath] = {
                "id": gid,
                "display_name": obj.get("display_name") or gid,
                "domain_id": ddir.name,
                "path": gpath,
                "members_fetched": True,
            }
            id_to_path[gid] = gpath
            ips = _collect_ip_entries(obj.get("expression"))
            if ips:
                group_ips[gpath] = ips
    return groups_by_path, id_to_path, group_ips, domain_ids


def load_capture_rules(export_root: Path) -> List[Dict[str, Any]]:
    """Read captured policies + rules, matching pull_all_rules' output shape."""
    import yaml
    out: List[Dict[str, Any]] = []
    domains_dir = export_root / "domains"
    for ddir in sorted(d for d in domains_dir.iterdir() if d.is_dir()):
        pdir = ddir / "security-policies"
        if not pdir.is_dir():
            continue
        for poldir in sorted(x for x in pdir.iterdir() if x.is_dir()):
            pf = poldir / "policy.yaml"
            if not pf.is_file():
                continue
            try:
                pol = yaml.safe_load(pf.read_text(encoding="utf-8")) or {}
            except Exception as exc:
                log.warning("capture: unreadable policy %s: %s", poldir.name, exc)
                continue
            rdir = poldir / "rules"
            if not rdir.is_dir():
                continue
            for rf in sorted(rdir.glob("*.yaml")):
                if rf.name == "rules_order.yaml":
                    continue
                try:
                    r = yaml.safe_load(rf.read_text(encoding="utf-8")) or {}
                except Exception as exc:
                    log.warning("capture: unreadable rule %s: %s", rf.name, exc)
                    continue
                if not r.get("id"):
                    continue
                r["_policy_id"] = pol.get("id")
                r["_policy_display"] = pol.get("display_name") or pol.get("id")
                r["_policy_path"] = pol.get("path")
                r["_domain_id"] = ddir.name
                r["_category"] = pol.get("category") or ""
                out.append(r)
    return out


def load_membership_export(mdir: Path,
                           ) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]]]:
    """Read tools/nsx/membership.py output.

    Returns (vms, vm_ext_to_group_ids). These are NSX's own evaluated answers,
    so no expression logic is reimplemented here.
    """
    f = mdir / "vm_group_membership.json"
    if not f.is_file():
        raise SystemExit(f"--from-membership: {f} not found")
    rows = json.loads(f.read_text(encoding="utf-8"))
    vms: List[Dict[str, Any]] = []
    ext_to_gids: Dict[str, List[str]] = {}
    for r in rows:
        ext = r.get("external_id") or r.get("vm_id")
        if not ext:
            continue
        vms.append({
            "external_id": ext,
            "display_name": r.get("display_name"),
            "tags": r.get("tags") or [],
            "ips": r.get("ips") or [],
        })
        ext_to_gids[ext] = list(r.get("groups") or [])
    return vms, ext_to_gids


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
        "--output-base", default=None,
        help="Reports root. The run lands at <root>/<manager-host>/vm_rule_membership/<ts>/ "
             "(default root: <NSX_LOG_DIR>/reports).",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help=("Exact directory override (run lands at <dir>/<ts>/). Prefer --output-base. "
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
    parser.add_argument(
        "--from-membership", default=None, metavar="DIR",
        help="Offline mode: read evaluated membership from a "
             "tools/nsx/membership.py export dir "
             "(nsx_membership_export/<host>/). Use with --from-capture. "
             "No NSX contact is made at all.",
    )
    parser.add_argument(
        "--from-capture", default=None, metavar="DIR",
        help="Offline mode: read rules and group definitions from an "
             "nsx_capture bundle (nsx_capture/<host>/). Use with "
             "--from-membership.",
    )
    parser.add_argument(
        "--rate-limit", type=float, default=None, metavar="RPS",
        help="Cap NSX API requests per second for this run (sets "
             "NSX_API_MAX_RPS for the client). "
             "Default is 2 req/s; pass 0 to disable pacing. 429/503 retry "
             "with backoff is always on.",
    )
    parser.add_argument(
        "--members-cache-minutes", type=int, default=0,
        help="GM mode: reuse the on-disk member/IP-member pull for this many "
             "minutes (stored under <NSX_LOG_DIR>/.cache/). 0 (default) "
             "disables. A cache is only used when it covers every "
             "rule-referenced group; otherwise it refetches and rewrites.",
    )
    args = parser.parse_args()
    if args.rate_limit is not None:
        os.environ["NSX_API_MAX_RPS"] = str(args.rate_limit)

    init_cli()
    setup_logging("vm_rule_membership")

    manager_host = resolve_manager(args.manager)
    if not manager_host:
        raise SystemExit(f"Manager not defined for {args.manager}.")

    names_input, list_path = load_vm_names(args.vm_list)
    if not names_input:
        raise SystemExit(f"No VM names loaded (file: {list_path})")

    offline = bool(args.from_membership or args.from_capture)
    if offline and not (args.from_membership and args.from_capture):
        raise SystemExit(
            "--from-membership and --from-capture must be given together: "
            "membership supplies VM-to-group, the capture supplies the rules.")

    offline_vms: Optional[List[Dict[str, Any]]] = None
    client = None
    if offline:
        if args.federation_global:
            raise SystemExit(
                "--federation-global is not supported in offline mode: "
                "membership.py cannot export from a Global Manager.")
        mdir = Path(args.from_membership).expanduser().resolve()
        cdir = Path(args.from_capture).expanduser().resolve()
        log.info("OFFLINE mode - no NSX contact.")
        log.info("  membership : %s", mdir)
        log.info("  capture    : %s", cdir)
        export_root = _capture_export_root(cdir)
        offline_vms, ext_to_gids = load_membership_export(mdir)
        g_by_path, id_to_path, g_ips, dom_ids = load_capture_groups(export_root)
        # Invert VM->group-ids into the group->members map the report expects.
        g_to_members: Dict[str, Set[str]] = {gp: set() for gp in g_by_path}
        unknown_gids: Set[str] = set()
        for ext, gids in ext_to_gids.items():
            for gid in gids:
                gp = id_to_path.get(gid)
                if gp is None:
                    unknown_gids.add(gid)
                    continue
                g_to_members.setdefault(gp, set()).add(ext)
        if unknown_gids:
            log.warning("%d group id(s) in the membership export have no "
                        "definition in the capture (bundles out of sync?); "
                        "first few: %s", len(unknown_gids),
                        sorted(unknown_gids)[:5])
        offline_rules = load_capture_rules(export_root)
        offline_data = {
            "domain_ids": dom_ids,
            "groups": (g_by_path, g_to_members, {}),
            "group_ips": g_ips,
            "rules": offline_rules,
        }
        log.info("  loaded: %d VM(s), %d group(s), %d rule(s), %d domain(s)",
                 len(offline_vms), len(g_by_path), len(offline_rules),
                 len(dom_ids))
        log.info("  NOTE: group IP membership is derived from captured "
                 "IPAddressExpression definitions, not NSX's evaluated "
                 "/members/ip-addresses.")
    else:
        log.info("Target manager: %s (federation_global=%s)",
                 manager_host, args.federation_global)
        client = NsxPolicyClient(nsxmanager=manager_host,
                                 federation_global=args.federation_global)

    # ---- pull VMs (and figure out federation topology) ----
    is_gm_federation = (
        (not offline) and args.federation_global
        and "/global-manager/" in client.POLICY_ROOT
    )
    vm_ext_to_site: Dict[str, str] = {}
    site_display: Dict[str, str] = {}
    gm_site_eps: Dict[str, str] = {}
    pre_domain_ids: Optional[List[str]] = None
    pre_groups: Optional[Tuple[Dict[str, Dict[str, Any]],
                               Dict[str, Set[str]],
                               Dict[str, Dict[str, Any]]]] = None
    pre_group_ips: Optional[Dict[str, Set[str]]] = None
    pre_all_rules: Optional[List[Dict[str, Any]]] = None

    if offline:
        # Declared above, so populate here rather than in the offline block.
        pre_domain_ids = offline_data["domain_ids"]
        pre_groups = offline_data["groups"]
        pre_group_ips = offline_data["group_ips"]
        pre_all_rules = offline_data["rules"]

    if is_gm_federation:
        log.info("Detected GM federation mode. Discovering sites.")
        sites = discover_federation_sites(client)
        if not sites:
            raise SystemExit(
                "GM federation mode: no sites discovered. Nothing to query."
            )
        for s in sites:
            sid = s.get("id")
            if not sid:
                continue
            site_display[sid] = s.get("display_name") or sid
            # Discover the site's enforcement point instead of assuming its id
            # is "default" (real deployments and UUID site ids can differ).
            ep_path = None
            try:
                r = client._get(client.POLICY_ROOT
                                + f"/sites/{client._q(sid)}/enforcement-points")
                eps = r.get("results") or []
                if eps:
                    ep_path = eps[0].get("path")
                    if len(eps) > 1:
                        log.info("site %s has %d enforcement points; using %s",
                                 sid, len(eps), ep_path)
            except Exception as exc:
                log.warning("site %s: enforcement-point discovery failed (%s); "
                            "assuming .../enforcement-points/default",
                            sid, str(exc)[:100])
            gm_site_eps[sid] = ep_path or (
                f"/global-infra/sites/{sid}/enforcement-points/default"
            )
            log.info("  site %s -> enforcement point %s", sid, gm_site_eps[sid])

        vms: List[Dict[str, Any]] = []
        log.info("GM mode: no direct LM connections. VM identity comes from "
                 "the GM member proxy. Fabric VM inventory is LM-only and is "
                 "never queried in federation-global mode (GM-only rule).")

        # Groups + members THROUGH the GM (enforcement-point proxy). This also
        # yields the VM universe for name matching, so LM access is optional.
        try:
            domains = client.list_domains()
        except Exception as exc:
            raise SystemExit(f"list_domains failed: {exc}")
        pre_domain_ids = [d.get("id") for d in domains if d.get("id")]
        if not pre_domain_ids:
            raise SystemExit("No domains returned from NSX.")
        # Rules FIRST: membership only matters for groups that rules
        # reference, so the member fetch is pruned to exactly those.
        pre_all_rules = pull_all_rules(client, pre_domain_ids)
        referenced: Set[str] = set()
        for _r in pre_all_rules:
            for _f in ("source_groups", "destination_groups", "scope"):
                referenced.update(_group_paths(_r.get(_f)))
        log.info("Rule-referenced groups: %d (member fetch limited to these).",
                 len(referenced))

        cache_path = (Path(nsx_log_dir).expanduser().resolve() / ".cache"
                      / f"vm_rule_members_{manager_host}.json")
        cached = _load_members_cache(cache_path, args.members_cache_minutes,
                                     referenced)
        if cached is not None:
            g_by_path, g_to_members, member_meta, pre_group_ips = cached
            log.info("Member cache HIT (%s): 0 member API calls this run.",
                     cache_path.name)
        else:
            g_by_path, g_to_members, member_meta = pull_groups_with_members(
                client, pre_domain_ids, gm_site_eps=gm_site_eps,
                only_paths=referenced,
            )
            pre_group_ips = pull_group_ip_memberships(
                client, g_by_path, gm_site_eps=gm_site_eps,
                only_paths=referenced,
            )
            if args.members_cache_minutes > 0:
                _save_members_cache(cache_path, g_by_path, g_to_members,
                                    member_meta, pre_group_ips)
        pre_groups = (g_by_path, g_to_members, member_meta)
        known_ext = {v.get("external_id") or v.get("id") for v in vms}
        synthesized = 0
        for ext, meta in member_meta.items():
            if meta.get("site_id"):
                vm_ext_to_site.setdefault(ext, meta["site_id"])
            if ext not in known_ext:
                vms.append({"external_id": ext,
                            "display_name": meta.get("display_name"),
                            "tags": meta.get("tags") or []})
                synthesized += 1
        if synthesized:
            log.info("VM universe from GM member proxy: %d VM(s) (no fabric IPs)",
                     synthesized)
    elif offline_vms is not None:
        vms = offline_vms
        log.info("VM universe from the membership export: %d VM(s)", len(vms))
    else:
        # --federation-global with a non-GM target cannot reach this point:
        # NsxPolicyClient refuses that combination in its constructor.
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
    if pre_domain_ids is not None:
        domain_ids = pre_domain_ids
    else:
        try:
            domains = client.list_domains()
        except Exception as exc:
            raise SystemExit(f"list_domains failed: {exc}")
        domain_ids = [d.get("id") for d in domains if d.get("id")]
        if not domain_ids:
            raise SystemExit("No domains returned from NSX.")
    log.info("Domains: %s", ", ".join(domain_ids))

    if pre_groups is not None:
        groups_by_path, group_to_members, _member_meta = pre_groups
    else:
        groups_by_path, group_to_members, _member_meta = pull_groups_with_members(
            client,
            domain_ids,
        )
    vm_to_groups = build_vm_to_groups(group_to_members)

    # ---- augment memberships by IP ----
    # Groups can include IP addresses / CIDRs (either as their only members or
    # mixed with tag/segment/path). NSX evaluates DFW rules against packet IPs,
    # so a VM whose IP falls inside a group's IP set is effectively a member
    # for rule-matching purposes. Fetch /members/ip-addresses per group and
    # add matches into vm_to_groups.
    if pre_group_ips is not None:
        group_ips = pre_group_ips
    else:
        group_ips = pull_group_ip_memberships(
            client,
            groups_by_path,
            gm_site_eps=gm_site_eps if is_gm_federation else None,
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

    all_rules = (pre_all_rules if pre_all_rules is not None
                 else pull_all_rules(client, domain_ids))

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
        out_dir = Path(args.output_dir).expanduser().resolve() / RUN_TS
    else:
        out_dir = report_run_dir("vm_rule_membership", manager_host, args.output_base, RUN_TS, create=False)
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
        "groups_member_fetched": sum(
            1 for g in groups_by_path.values() if g.get("members_fetched", True)),
        "rules_scanned": len(all_rules),
        "rules_hitting_targets": len(hits),
        "output_dir": str(out_dir),
        "markdown": str(md_path),
        "json": str(json_path),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
