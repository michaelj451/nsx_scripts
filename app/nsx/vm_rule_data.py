"""
app/nsx/vm_rule_data.py

Everything the VM rule membership report needs from NSX, collected in one
place so a live report and an offline snapshot run the SAME pull code:

  - VM universe: LM fabric VMs with their VIF IPs attached, or (GM) the VMs
    the GM member proxy returns, with no IPs (GM-only rule, no LM sessions)
  - groups, and per group NSX's evaluated members:
      /members/virtual-machines  -> which VMs are in the group
      /members/ip-addresses      -> which IPs/CIDRs/ranges the group matches
  - every security policy and rule

collect_live() does the GETs. write_snapshot()/load_snapshot() freeze the
result to disk and read it back, so a later lookup for any list of VM names
or IPs costs zero NSX calls and answers exactly what a live run would have
answered at capture time.

Read-only: strict GETs, no writes to any manager.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from nsx.bundle_history import TS_DIR_RE
from nsx.nsx_policy_client import NsxPolicyClient

log = logging.getLogger(__name__)

SNAPSHOT_FILE = "vm_rule_snapshot.json"
SNAPSHOT_SCHEMA = "nsx-vm-rule-snapshot/1"
# First few fetch errors are kept verbatim in the snapshot; the rest are counted.
MAX_ERRORS_KEPT = 50


def _note_error(errors: Optional[List[str]], msg: str) -> None:
    if errors is not None:
        errors.append(msg)


# ---------- rule reference helpers ----------

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


def rule_referenced_group_paths(rules: List[Dict[str, Any]]) -> Set[str]:
    referenced: Set[str] = set()
    for r in rules:
        for f in ("source_groups", "destination_groups", "scope"):
            referenced.update(_group_paths(r.get(f)))
    return referenced


# ---------- GM member cache ----------

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


# ---------- data pull ----------

def attach_vm_ips(client: NsxPolicyClient, vms: List[Dict[str, Any]],
                  errors: Optional[List[str]] = None) -> int:
    """Set vm["ips"] from the fabric VIF list (LM only). A fabric VM record
    carries no addresses of its own: they live on its VIFs. Returns how many
    VMs got at least one IP. A VIF-list failure leaves every VM without IPs,
    so name targets then match by VM membership only."""
    by_ext: Dict[str, Set[str]] = {}
    try:
        vifs = client.list_vm_vifs()
    except Exception as exc:
        log.error("list_vm_vifs failed; VM IPs unavailable: %s", exc)
        _note_error(errors, f"list_vm_vifs: {exc}")
        vifs = []
    for vif in vifs:
        vm_id = NsxPolicyClient._extract_vm_id_from_vif(vif)
        if vm_id:
            by_ext.setdefault(vm_id, set()).update(
                NsxPolicyClient._collect_ips_recursive(vif))
    with_ips = 0
    for vm in vms:
        ext = NsxPolicyClient._extract_vm_id_from_vm(vm)
        ips = set(NsxPolicyClient._collect_ips_recursive(vm)) | by_ext.get(ext or "", set())
        vm["ips"] = sorted(ips)
        if ips:
            with_ips += 1
    log.info("VM IPs from %d VIF(s): %d of %d VM(s) have at least one IP",
             len(vifs), with_ips, len(vms))
    return with_ips


def pull_groups_with_members(
    client: NsxPolicyClient,
    domain_ids: List[str],
    gm_site_eps: Optional[Dict[str, str]] = None,
    only_paths: Optional[Set[str]] = None,
    errors: Optional[List[str]] = None,
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

    Errors on a single group are logged, noted in `errors`, and skipped
    (empty member set).
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
            _note_error(errors, f"list_groups({domain_id}): {exc}")
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
                                _note_error(errors, f"members site={site_id} group={domain_id}/{gid}: {exc}")
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
                    _note_error(errors, f"members group={domain_id}/{gid}: {exc}")
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


def discover_site_enforcement_points(
    client: NsxPolicyClient,
    sites: List[Dict[str, Any]],
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Return (site_display, gm_site_eps): site id -> display name, and
    site id -> enforcement point path used for GM-proxied member calls."""
    site_display: Dict[str, str] = {}
    gm_site_eps: Dict[str, str] = {}
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
    return site_display, gm_site_eps


def pull_group_ip_memberships(
    client: NsxPolicyClient,
    groups_by_path: Dict[str, Dict[str, Any]],
    gm_site_eps: Optional[Dict[str, str]] = None,
    only_paths: Optional[Set[str]] = None,
    errors: Optional[List[str]] = None,
) -> Dict[str, Set[str]]:
    """
    For each group, fetch /members/ip-addresses (returns every IP or CIDR the
    group evaluates to, including from IP-only expressions). Returns
    group_path -> set(ip_or_cidr strings). Errors per group are logged,
    noted in `errors`, and the group ends up with an empty set.

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
                        _note_error(errors, f"ip-addresses {label} group={domain_id}/{gid}: {exc}")
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


def pull_all_rules(
    client: NsxPolicyClient,
    domain_ids: List[str],
    errors: Optional[List[str]] = None,
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
            _note_error(errors, f"list_security_policies({domain_id}): {exc}")
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
                _note_error(errors, f"list_security_rules({domain_id}/{pol_id}): {exc}")
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


def _list_domain_ids(client: NsxPolicyClient) -> List[str]:
    try:
        domains = client.list_domains()
    except Exception as exc:
        raise SystemExit(f"list_domains failed: {exc}")
    domain_ids = [d.get("id") for d in domains if d.get("id")]
    if not domain_ids:
        raise SystemExit("No domains returned from NSX.")
    return domain_ids


def collect_live(
    client: NsxPolicyClient,
    *,
    manager_host: str,
    is_gm: bool,
    members_cache_minutes: int = 0,
    cache_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Pull everything the report needs. Returns the report data dict:

      manager_host, federation_mode ("gm"|"lm"), collected_at,
      site_display, gm_site_eps, vm_ext_to_site, domain_ids,
      vms             [VM objects; LM ones carry "ips" from their VIFs]
      groups_by_path  {group path: {id, display_name, domain_id, ...}}
      group_to_members{group path: set(VM external ids)}
      member_meta     {external id: {display_name, site_id, tags}}
      group_ips       {group path: set(IP / CIDR / range strings)}
      rules           [rule dicts with _policy_* / _domain_id / _category]
      fetch_errors    [non-benign per-object failures; empty = complete]

    GM mode fetches membership only for rule-referenced groups (a group no
    rule uses cannot produce a hit, and NSX rolls nested members up into the
    parent). LM mode fetches every group.
    """
    errors: List[str] = []
    collected_at = datetime.now(timezone.utc).isoformat()
    site_display: Dict[str, str] = {}
    gm_site_eps: Dict[str, str] = {}
    vm_ext_to_site: Dict[str, str] = {}

    if is_gm:
        log.info("Detected GM federation mode. Discovering sites.")
        sites = discover_federation_sites(client)
        if not sites:
            raise SystemExit(
                "GM federation mode: no sites discovered. Nothing to query."
            )
        site_display, gm_site_eps = discover_site_enforcement_points(client, sites)

        vms: List[Dict[str, Any]] = []
        log.info("GM mode: no direct LM connections. VM identity comes from "
                 "the GM member proxy. Fabric VM inventory is LM-only and is "
                 "never queried in federation-global mode (GM-only rule).")

        domain_ids = _list_domain_ids(client)
        # Rules FIRST: membership only matters for groups that rules
        # reference, so the member fetch is pruned to exactly those.
        rules = pull_all_rules(client, domain_ids, errors=errors)
        referenced = rule_referenced_group_paths(rules)
        log.info("Rule-referenced groups: %d (member fetch limited to these).",
                 len(referenced))

        cached = (_load_members_cache(cache_path, members_cache_minutes, referenced)
                  if cache_path is not None else None)
        if cached is not None:
            groups_by_path, group_to_members, member_meta, group_ips = cached
            log.info("Member cache HIT (%s): 0 member API calls this run.",
                     cache_path.name)
        else:
            groups_by_path, group_to_members, member_meta = pull_groups_with_members(
                client, domain_ids, gm_site_eps=gm_site_eps,
                only_paths=referenced, errors=errors,
            )
            group_ips = pull_group_ip_memberships(
                client, groups_by_path, gm_site_eps=gm_site_eps,
                only_paths=referenced, errors=errors,
            )
            if cache_path is not None and members_cache_minutes > 0 and not errors:
                _save_members_cache(cache_path, groups_by_path, group_to_members,
                                    member_meta, group_ips)
        for ext, meta in member_meta.items():
            if meta.get("site_id"):
                vm_ext_to_site.setdefault(ext, meta["site_id"])
            vms.append({"external_id": ext,
                        "display_name": meta.get("display_name"),
                        "tags": meta.get("tags") or []})
        log.info("VM universe from GM member proxy: %d VM(s) (no fabric IPs)", len(vms))
    else:
        # --federation-global with a non-GM target cannot reach this point:
        # NsxPolicyClient refuses that combination in its constructor.
        log.info("Fetching virtual machines from %s", manager_host)
        vms = client.list_virtual_machines()
        attach_vm_ips(client, vms, errors=errors)
        domain_ids = _list_domain_ids(client)
        groups_by_path, group_to_members, member_meta = pull_groups_with_members(
            client, domain_ids, errors=errors,
        )
        group_ips = pull_group_ip_memberships(client, groups_by_path, errors=errors)
        rules = pull_all_rules(client, domain_ids, errors=errors)

    if errors:
        log.warning("%d fetch error(s) during collection: results may be "
                    "incomplete. First: %s", len(errors), errors[0])
    return {
        "manager_host": manager_host,
        "federation_mode": "gm" if is_gm else "lm",
        "collected_at": collected_at,
        "site_display": site_display,
        "gm_site_eps": gm_site_eps,
        "vm_ext_to_site": vm_ext_to_site,
        "domain_ids": domain_ids,
        "vms": vms,
        "groups_by_path": groups_by_path,
        "group_to_members": group_to_members,
        "member_meta": member_meta,
        "group_ips": group_ips,
        "rules": rules,
        "fetch_errors": errors,
    }


# ---------- snapshot I/O ----------

def snapshot_doc(data: Dict[str, Any], *, manager_alias: str) -> Dict[str, Any]:
    """JSON-safe form of a collect_live() result (sets become sorted lists)."""
    errors = list(data.get("fetch_errors") or [])
    return {
        "schema": SNAPSHOT_SCHEMA,
        "manager_alias": manager_alias,
        "manager_host": data["manager_host"],
        "federation_mode": data["federation_mode"],
        "captured_at": data["collected_at"],
        "complete": not errors,
        "fetch_error_count": len(errors),
        "fetch_errors": errors[:MAX_ERRORS_KEPT],
        "counts": {
            "vms": len(data["vms"]),
            "vms_with_ips": sum(1 for v in data["vms"] if v.get("ips")),
            "domains": len(data["domain_ids"]),
            "groups": len(data["groups_by_path"]),
            "groups_member_fetched": sum(
                1 for g in data["groups_by_path"].values() if g.get("members_fetched", True)),
            "rules": len(data["rules"]),
            "sites": len(data["site_display"]),
        },
        "site_display": data["site_display"],
        "gm_site_eps": data["gm_site_eps"],
        "vm_ext_to_site": data["vm_ext_to_site"],
        "domain_ids": data["domain_ids"],
        "vms": data["vms"],
        "groups_by_path": data["groups_by_path"],
        "group_to_members": {k: sorted(v) for k, v in data["group_to_members"].items()},
        "member_meta": data["member_meta"],
        "group_ips": {k: sorted(v) for k, v in data["group_ips"].items()},
        "rules": data["rules"],
    }


def write_snapshot(path: Path, data: Dict[str, Any], *, manager_alias: str) -> Dict[str, Any]:
    doc = snapshot_doc(data, manager_alias=manager_alias)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return doc


def _newest_complete_bundle(host_dir: Path) -> Optional[Path]:
    """Newest <UTC_TS>/ bundle whose manifest says ok. Used when `latest` is
    missing (e.g. Windows without symlink rights)."""
    if not host_dir.is_dir():
        return None
    for d in sorted((x for x in host_dir.iterdir()
                     if x.is_dir() and TS_DIR_RE.match(x.name)), reverse=True):
        try:
            ok = json.loads((d / "manifest.json").read_text(encoding="utf-8")).get("ok")
        except (OSError, ValueError):
            continue
        if ok is True and (d / SNAPSHOT_FILE).is_file():
            return d / SNAPSHOT_FILE
    return None


def resolve_snapshot_path(p: Path) -> Path:
    """Accept the snapshot file, a timestamped bundle dir, or a host dir
    (its `latest` bundle, else its newest complete bundle, is used)."""
    p = p.expanduser()
    if p.is_file():
        return p
    for cand in (p / SNAPSHOT_FILE, p / "latest" / SNAPSHOT_FILE):
        if cand.is_file():
            return cand
    newest = _newest_complete_bundle(p)
    if newest is not None:
        return newest
    raise SystemExit(
        f"No {SNAPSHOT_FILE} under {p}. Pass the file, a bundle dir "
        "(<root>/<host>/<ts>/) or a host dir with a `latest` link "
        "(run tools/nsx/capture_vm_rule_data.py first).")


def load_snapshot(p: Path) -> Dict[str, Any]:
    """Read a snapshot back into the collect_live() shape."""
    path = resolve_snapshot_path(p)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Cannot read snapshot {path}: {exc}")
    if not isinstance(doc, dict) or doc.get("schema") != SNAPSHOT_SCHEMA:
        raise SystemExit(f"{path} is not a {SNAPSHOT_SCHEMA} snapshot "
                         f"(schema={doc.get('schema') if isinstance(doc, dict) else None!r})")
    return {
        "manager_host": doc["manager_host"],
        "manager_alias": doc.get("manager_alias"),
        "federation_mode": doc["federation_mode"],
        "collected_at": doc["captured_at"],
        "snapshot_path": str(path.resolve()),
        "fetch_error_count": doc.get("fetch_error_count", 0),
        "site_display": doc.get("site_display") or {},
        "gm_site_eps": doc.get("gm_site_eps") or {},
        "vm_ext_to_site": doc.get("vm_ext_to_site") or {},
        "domain_ids": doc["domain_ids"],
        "vms": doc["vms"],
        "groups_by_path": doc["groups_by_path"],
        "group_to_members": {k: set(v) for k, v in doc["group_to_members"].items()},
        "member_meta": doc.get("member_meta") or {},
        "group_ips": {k: set(v) for k, v in doc["group_ips"].items()},
        "rules": doc["rules"],
        "fetch_errors": doc.get("fetch_errors") or [],
    }
