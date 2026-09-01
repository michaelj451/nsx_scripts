#!/usr/bin/env python3
"""tools/reports/report_groups_usage.py

Standalone read-only groups-usage report. Companion to
report_rules_usage.py.

For each customer group on the target (LM or GM), queries the evaluated
VM-member list and classifies the group by expression type:

    TAG        one or more Condition entries with key=Tag
    IP         one or more IPAddressExpression entries
    SEGMENT    PathExpression referencing /infra/segments/*
    VM_PATH    PathExpression referencing /infra/domains/.../virtual-machines/*
    NESTED     contains a NestedExpression
    MIXED      more than one distinct expression kind
    EMPTY      no expression at all

Also captures whether the group's Condition set includes ANY tag
condition (surfaces the "tag-driven" population easily).

A --federation-global run against a Global Manager talks to the GM only:
evaluated members are proxied THROUGH the GM with enforcement_point_path,
one call per site per group, and summed. No session is ever opened to a
Local Manager.

OUTPUT:
    $NSX_LOG_DIR/groups_usage_report/<target-host>/<UTC_TS>/
        summary.json               overall counters + per-domain + per-class
        groups_usage.json          per-group full record
        groups_usage.jsonl         one row per line (greppable)
        tag_based_groups.jsonl     only groups with any Tag condition
        empty_groups.jsonl         groups with zero VM members
        report.md                  human-readable markdown
        logs/

Read-only against NSX. Only GETs, never PUT/PATCH/DELETE.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time as _time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.cli_bootstrap import init_cli            # noqa: E402
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.report_paths import report_run_dir, reports_root   # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient            # noqa: E402
from nsx.md_utils import align_markdown_tables               # noqa: E402


log = logging.getLogger(__name__)
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2",
                       "nsx-lm3", "nsx-lm4", "nsx-lm5"]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

CLASS_ORDER = ["TAG", "IP", "SEGMENT", "VM_PATH", "NESTED", "MIXED", "EMPTY"]

# Per-run counter, reported in summary.json and the closing log lines.
_STATS = {"member_api_calls": 0}

# Per-manager tally of every NSX GET this run made, logged at the end and
# written to summary.json so the evidence pack shows exactly how much load
# each manager saw.
_API_CALLS: Dict[str, int] = {}


def _count_api_calls(client, label: str) -> None:
    """Wrap the client INSTANCE's GET transport so each call is tallied under
    `label` (the manager host). Counting only; no behavior change."""
    _API_CALLS.setdefault(label, 0)
    orig = client._get

    def counted(*a, **kw):
        _API_CALLS[label] += 1
        return orig(*a, **kw)
    client._get = counted


def _is_not_found(exc: Exception) -> bool:
    s = str(exc)
    return "could not be found" in s.lower() or "NOT_FOUND" in s or " 600]" in s


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
              logging.FileHandler(bundle_logs_dir / f"report_groups_usage_{RUN_TS}.log",
                                  encoding="utf-8"),
              logging.FileHandler(global_log_dir / f"report_groups_usage_{RUN_TS}.log",
                                  encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    return bundle_logs_dir / f"report_groups_usage_{RUN_TS}.log"


def _walk_expressions(g: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten expression + nested expression trees."""
    out: List[Dict[str, Any]] = []

    def walk(node: Any):
        if isinstance(node, dict):
            rt = node.get("resource_type")
            if rt:
                out.append(node)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    for e in (g.get("expression") or []):
        walk(e)
    return out


def classify_group(g: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Return (class_label, details)."""
    exprs = _walk_expressions(g)
    has_tag = has_ip = has_seg = has_vm_path = has_nested = False
    tag_conds: List[Dict[str, Any]] = []
    ip_ranges: List[str] = []
    segment_paths: List[str] = []

    for e in exprs:
        rt = e.get("resource_type")
        if rt == "Condition" and (e.get("key") == "Tag"):
            has_tag = True
            tag_conds.append({
                "member_type": e.get("member_type"),
                "operator":    e.get("operator"),
                "value":       e.get("value"),
                "scope":       e.get("scope") or "",
            })
        elif rt == "IPAddressExpression":
            has_ip = True
            for v in (e.get("ip_addresses") or []):
                if v: ip_ranges.append(v)
        elif rt == "PathExpression":
            for p in (e.get("paths") or []):
                if "/infra/segments/" in p or "/global-infra/segments/" in p:
                    has_seg = True
                    segment_paths.append(p)
                elif "/virtual-machines/" in p:
                    has_vm_path = True
        elif rt == "NestedExpression":
            has_nested = True

    kinds = [k for k, v in (("TAG", has_tag), ("IP", has_ip),
                             ("SEGMENT", has_seg), ("VM_PATH", has_vm_path),
                             ("NESTED", has_nested)) if v]
    if not exprs or len(kinds) == 0:
        label = "EMPTY"
    elif len(kinds) == 1:
        label = kinds[0]
    else:
        if has_nested:
            label = "NESTED"
        else:
            label = "MIXED"
    return label, {
        "kinds":          kinds,
        "tag_conditions": tag_conds,
        "ip_ranges":      ip_ranges,
        "segment_paths":  segment_paths,
    }


def discover_domains(c: NsxPolicyClient) -> List[str]:
    r = c._get(c.POLICY_ROOT + "/domains")
    return [d.get("id") for d in (r.get("results") or []) if d.get("id")]


def _list_customer_groups(c: NsxPolicyClient, domain_id: str) -> List[Dict[str, Any]]:
    r = c._get(c.POLICY_ROOT + f"/domains/{domain_id}/groups")
    return [g for g in (r.get("results") or []) if not g.get("_system_owned")]


def _get_group_vm_count(c: NsxPolicyClient, domain_id: str, group_id: str) -> Optional[int]:
    try:
        _STATS["member_api_calls"] += 1
        r = c._get(c.POLICY_ROOT + f"/domains/{domain_id}/groups/{group_id}/members/virtual-machines")
        return len(r.get("results") or [])
    except Exception as e:
        log.warning("  %s/%s: member query failed: %s", domain_id, group_id, str(e)[:80])
        return None


def _get_group_vm_count_federated(c: NsxPolicyClient, site_eps: Dict[str, str],
                                    domain_id: str, group_id: str) -> Tuple[Optional[int], Dict[str, Optional[int]]]:
    """GM federation mode: evaluated members are fetched THROUGH THE GM, one
    paginated call per relevant site with `enforcement_point_path`, and
    summed. No session is ever opened to a Local Manager.

    A location-scoped domain (domain id == a site id) exists only at that
    site, so only its own enforcement point is queried; global domains fan
    out to every site. NOT_FOUND from a site means the group is not
    realized there and counts as 0 members at that site.
    """
    targets = {domain_id: site_eps[domain_id]} if domain_id in site_eps else site_eps
    members_path = (c.POLICY_ROOT + f"/domains/{c._q(domain_id)}/groups/{c._q(group_id)}"
                    "/members/virtual-machines")
    per_site: Dict[str, Optional[int]] = {}
    for site_id, ep in targets.items():
        n: Optional[int] = 0
        cursor = None
        while True:
            params: Dict[str, Any] = {"enforcement_point_path": ep, "page_size": 1000}
            if cursor:
                params["cursor"] = cursor
            try:
                _STATS["member_api_calls"] += 1
                r = c._get(members_path, params=params)
            except Exception as e:
                if _is_not_found(e):
                    log.debug("  %s/%s not realized at site %s (0 members there)",
                              domain_id, group_id, site_id)
                else:
                    log.warning("  %s/%s: member query via GM for site %s failed: %s",
                                domain_id, group_id, site_id, str(e)[:80])
                    n = None
                break
            n += len(r.get("results") or [])
            cursor = r.get("cursor")
            if not cursor:
                break
        per_site[site_id] = n
    known = [v for v in per_site.values() if v is not None]
    total: Optional[int] = sum(known) if known else None
    return total, per_site


def write_markdown(out: Path, target: str, domains: List[str],
                   records: List[Dict[str, Any]],
                   summary: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("# Groups Usage Report\n")
    lines.append(f"- **Target**: {target}")
    lines.append(f"- **Domain(s) queried**: {', '.join(domains)}")
    lines.append(f"- **Ran at**: {summary['ran_at']}")
    lines.append(f"- **Read-only**: yes (GET only)\n")

    # Composition totals across all groups
    total_tag_conds = 0
    total_segments  = 0
    total_ips       = 0
    for r in records:
        cinfo = r.get("classification") or {}
        total_tag_conds += len(cinfo.get("tag_conditions") or [])
        total_segments  += len(cinfo.get("segment_paths") or [])
        total_ips       += len(cinfo.get("ip_ranges") or [])

    lines.append("## Summary\n")
    lines.append("| Metric | Value |\n|---|---:|")
    lines.append(f"| Customer groups | {summary['counters']['customer_groups']} |")
    lines.append(f"| Total VM members (evaluated, across all groups) | {summary['counters']['total_vm_members']} |")
    lines.append(f"| Groups with 0 VM members | {summary['counters']['groups_with_no_vms']} |")
    lines.append(f"| Total tag conditions defined | {total_tag_conds} |")
    lines.append(f"| Total segment references defined | {total_segments} |")
    lines.append(f"| Total IP addresses / CIDRs defined | {total_ips} |")
    lines.append("")

    lines.append("## Groups by classification\n")
    lines.append("| Class | Count | Total VM members |\n|---|---:|---:|")
    for k in CLASS_ORDER:
        c = summary["by_class"].get(k, {"count": 0, "total_vm_members": 0})
        lines.append(f"| {k} | {c['count']} | {c['total_vm_members']} |")
    lines.append("")

    if len(domains) > 1:
        lines.append("## Per-domain breakdown\n")
        lines.append("| Domain | Groups | VM members |\n|---|---:|---:|")
        for d, v in sorted((summary.get("per_domain") or {}).items()):
            lines.append(f"| `{d}` | {v['count']} | {v['total_vm_members']} |")
        lines.append("")

    # Detect per-site breakdown for header
    site_ids: List[str] = []
    for r in records:
        for sid in (r.get("per_site_counts") or {}).keys():
            if sid not in site_ids:
                site_ids.append(sid)

    lines.append("## All groups (sorted by VM members DESC)\n")
    lines.append("Each row shows the composition of the group and how many "
                 "VMs currently evaluate as members.\n")
    lines.append("- **VMs**: live evaluated VM members (from tag conditions, path expressions, etc.)")
    lines.append("- **Tag conds**: number of `scope=Tag` conditions in the group's expression")
    lines.append("- **Segments**: number of segment paths the group references")
    lines.append("- **IPs**: number of IP addresses / CIDRs the group has listed via `IPAddressExpression`\n")
    if site_ids:
        hdr = ("| Class | Domain | Group ID | Display | VMs total | " +
               " | ".join(f"VMs @ {s}" for s in site_ids) +
               " | Tag conds | Segments | IPs |")
        sep = "|---|---|---|---|---:|" + "".join("---:|" for _ in site_ids) + "---:|---:|---:|"
    else:
        hdr = "| Class | Domain | Group ID | Display | VMs | Tag conds | Segments | IPs |"
        sep = "|---|---|---|---|---:|---:|---:|---:|"
    lines.append(hdr)
    lines.append(sep)
    for r in sorted(records, key=lambda r: (-(r.get("vm_count") or 0),
                                             r.get("domain_id", ""),
                                             r.get("id", ""))):
        cinfo = r.get("classification") or {}
        n_tag = len(cinfo.get("tag_conditions") or [])
        n_seg = len(cinfo.get("segment_paths") or [])
        n_ip  = len(cinfo.get("ip_ranges") or [])
        row = f"| {r['class']} | {r['domain_id']} | `{r['id']}` | {r.get('display_name','')} | {r.get('vm_count', 'n/a')} |"
        for sid in site_ids:
            v = (r.get("per_site_counts") or {}).get(sid)
            row += f" {v if v is not None else 'n/a'} |"
        row += f" {n_tag} | {n_seg} | {n_ip} |"
        lines.append(row)
    lines.append("")

    tag_records = [r for r in records if r["class"] == "TAG"
                   or ((r["class"] == "MIXED" or r["class"] == "NESTED")
                       and r.get("classification", {}).get("tag_conditions"))]
    lines.append(f"## Tag-based groups only ({len(tag_records)})\n")
    lines.append("Groups whose membership is populated (at least partially) "
                 "by VM tag conditions. VM count is the live evaluated total.\n")
    lines.append("| Group ID | Display | VMs | # Tag conds | Tag conditions |")
    lines.append("|---|---|---:|---:|---|")
    for r in sorted(tag_records, key=lambda r: -(r.get("vm_count") or 0)):
        tag_conds = r.get("classification", {}).get("tag_conditions") or []
        # NSX stores the Tag condition value as "scope|tag" in a single
        # string, so escape ALL pipes for markdown table safety, not just
        # the tag= separator.
        tag_parts = [
            (f"{t.get('member_type','?')} tag={t.get('scope','') or ''}|{t.get('value','')}"
             ).replace("|", "\\|")
            for t in tag_conds
        ]
        lines.append(
            f"| `{r['id']}` | {r.get('display_name','')} | "
            f"{r.get('vm_count', 'n/a')} | {len(tag_conds)} | "
            f"{'; '.join(tag_parts) or ''} |"
        )
    lines.append("")

    # Segment-based groups section
    seg_records = [r for r in records if (r.get("classification") or {}).get("segment_paths")]
    if seg_records:
        lines.append(f"## Groups with segment references ({len(seg_records)})\n")
        lines.append("| Group ID | Display | VMs | # Segments | Segment paths |")
        lines.append("|---|---|---:|---:|---|")
        for r in sorted(seg_records, key=lambda r: -(r.get("vm_count") or 0)):
            paths = (r.get("classification") or {}).get("segment_paths") or []
            short_paths = [p.rsplit("/", 1)[-1] for p in paths]
            lines.append(
                f"| `{r['id']}` | {r.get('display_name','')} | "
                f"{r.get('vm_count', 'n/a')} | {len(paths)} | "
                f"{', '.join(short_paths)} |"
            )
        lines.append("")

    # IP-based groups section
    ip_records = [r for r in records if (r.get("classification") or {}).get("ip_ranges")]
    if ip_records:
        lines.append(f"## Groups with IP address / CIDR entries ({len(ip_records)})\n")
        lines.append("| Group ID | Display | # IPs | Sample IPs |")
        lines.append("|---|---|---:|---|")
        for r in sorted(ip_records, key=lambda r: -len((r.get("classification") or {}).get("ip_ranges") or [])):
            ips = (r.get("classification") or {}).get("ip_ranges") or []
            preview = ", ".join(ips[:5]) + (f" ... (+{len(ips)-5} more)" if len(ips) > 5 else "")
            lines.append(
                f"| `{r['id']}` | {r.get('display_name','')} | "
                f"{len(ips)} | {preview} |"
            )
        lines.append("")

    out.write_text(align_markdown_tables("\n".join(lines)), encoding="utf-8")


def write_json_files(out: Path, records: List[Dict[str, Any]]) -> None:
    (out / "groups_usage.json").write_text(
        json.dumps(records, indent=2, sort_keys=True), encoding="utf-8")
    with (out / "groups_usage.jsonl").open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    with (out / "tag_based_groups.jsonl").open("w", encoding="utf-8") as fh:
        for r in records:
            if r["class"] == "TAG" or (r["class"] in ("MIXED", "NESTED")
                                         and r.get("classification", {}).get("tag_conditions")):
                fh.write(json.dumps(r, sort_keys=True) + "\n")
    with (out / "empty_groups.jsonl").open("w", encoding="utf-8") as fh:
        for r in records:
            if (r.get("vm_count") or 0) == 0:
                fh.write(json.dumps(r, sort_keys=True) + "\n")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    p.add_argument("--domain-id", default="default",
                   help="Single domain to query (ignored if --all-domains).")
    p.add_argument("--all-domains", action="store_true",
                   help="Discover and iterate all domains on the target.")
    p.add_argument("--federation-global", action="store_true")
    p.add_argument("--output-base", default=None,
                   help="Reports root. The run lands at <root>/<manager-host>/group_membership/<ts>/ "
                        "(default root: $NSX_LOG_DIR/reports).")
    args = p.parse_args()

    init_cli()
    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Cannot resolve alias {args.target}")

    out_dir = report_run_dir("group_membership", target_host, args.output_base, RUN_TS)
    logs_dir = out_dir / "logs"
    log_file = setup_logging(logs_dir)
    t_start = _time.monotonic()

    log.info("=" * 60)
    log.info("GROUPS USAGE REPORT")
    log.info("  target:            %s (%s)", args.target, target_host)
    log.info("  federation_global: %s", args.federation_global)
    log.info("  domain_id:         %s", args.domain_id)
    log.info("  all_domains:       %s", args.all_domains)
    log.info("  output:            %s", out_dir)
    log.info("  log file:          %s", log_file)
    log.info("=" * 60)

    c = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global)
    _count_api_calls(c, target_host)
    managers_contacted = [target_host]

    # GM/federation-global: evaluated members are proxied THROUGH THE GM with
    # enforcement_point_path (one call per site per group). This run never
    # opens a session to a Local Manager.
    site_eps: Dict[str, str] = {}
    is_gm_federation = False
    if args.federation_global and "/global-manager/" in c.POLICY_ROOT:
        is_gm_federation = True
        try:
            site_eps = c.list_site_enforcement_points()
        except Exception as e:
            log.warning("  site discovery failed: %s", str(e)[:80])
        for sid, ep in site_eps.items():
            log.info("  site %s -> enforcement point %s", sid, ep)
        log.info("GM mode: no direct LM connections. Member queries go through the GM "
                 "per enforcement point (%d site(s)).", len(site_eps))

    if args.all_domains:
        domains = discover_domains(c)
        log.info("  discovered domains: %s", domains)
    else:
        domains = [args.domain_id]

    records: List[Dict[str, Any]] = []
    per_domain: Dict[str, Dict[str, int]] = {}
    by_class: Dict[str, Dict[str, int]] = {k: {"count": 0, "total_vm_members": 0}
                                             for k in CLASS_ORDER}

    for dom in domains:
        try:
            groups = _list_customer_groups(c, dom)
        except Exception as e:
            log.warning("  domain %s: list failed: %s", dom, str(e)[:80])
            continue
        log.info("  domain %s: %d customer group(s); querying evaluated members ...",
                 dom, len(groups))
        per_domain.setdefault(dom, {"count": 0, "total_vm_members": 0})
        t_dom = _time.monotonic()

        for i, g in enumerate(groups, start=1):
            gid = g.get("id")
            cls, cinfo = classify_group(g)
            per_site_counts: Dict[str, Optional[int]] = {}
            if is_gm_federation and site_eps:
                vm_count, per_site_counts = _get_group_vm_count_federated(
                    c, site_eps, dom, gid)
            else:
                vm_count = _get_group_vm_count(c, dom, gid)
            site_part = ""
            if per_site_counts:
                site_part = " (" + ", ".join(
                    f"{s}={'n/a' if v is None else v}"
                    for s, v in per_site_counts.items()) + ")"
            log.info("  [%d/%d] %s/%s (%s) class=%s vms=%s%s",
                     i, len(groups), dom, gid, g.get("display_name") or "", cls,
                     "n/a" if vm_count is None else vm_count, site_part)
            rec = {
                "domain_id":     dom,
                "id":            gid,
                "display_name":  g.get("display_name"),
                "class":         cls,
                "classification": cinfo,
                "vm_count":      vm_count,
                "per_site_counts": per_site_counts,
                "path":          g.get("path"),
                "_system_owned": g.get("_system_owned", False),
            }
            records.append(rec)
            per_domain[dom]["count"] += 1
            per_domain[dom]["total_vm_members"] += (vm_count or 0)
            by_class[cls]["count"] += 1
            by_class[cls]["total_vm_members"] += (vm_count or 0)

        log.info("  domain %s done: %d group(s), %d VM member(s), %.1fs; "
                 "member API calls so far: %d",
                 dom, per_domain[dom]["count"], per_domain[dom]["total_vm_members"],
                 _time.monotonic() - t_dom, _STATS["member_api_calls"])

    summary = {
        "ran_at":            datetime.now(timezone.utc).isoformat(),
        "target":            f"alias:{args.target} ({target_host})",
        "domains_queried":   domains,
        "federation_global": args.federation_global,
        "managers_contacted": managers_contacted,
        "gm_proxy_mode":     is_gm_federation,
        "member_api_calls":  _STATS["member_api_calls"],
        "api_calls":         dict(_API_CALLS),
        "elapsed_seconds":   round(_time.monotonic() - t_start, 1),
        "log_file":          str(log_file),
        "counters": {
            "customer_groups":     len(records),
            "total_vm_members":    sum((r.get("vm_count") or 0) for r in records),
            "groups_with_no_vms":  sum(1 for r in records if (r.get("vm_count") or 0) == 0),
        },
        "by_class":   by_class,
        "per_domain": per_domain,
    }

    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    write_json_files(out_dir, records)
    write_markdown(out_dir / "report.md", f"alias:{args.target} ({target_host})",
                   domains, records, summary)

    log.info("=" * 60)
    log.info("SUMMARY")
    log.info("  customer groups:  %d", summary["counters"]["customer_groups"])
    log.info("  VM members total: %d", summary["counters"]["total_vm_members"])
    log.info("  by class:")
    for k in CLASS_ORDER:
        v = by_class[k]
        if v["count"]:
            log.info("    %-8s  count=%3d  vm_members=%d", k, v["count"], v["total_vm_members"])
    log.info("Member API calls: %d", _STATS["member_api_calls"])
    log.info("NSX API calls (all GETs): %s",
             ", ".join(f"{k}={v}" for k, v in _API_CALLS.items()) or "0")
    log.info("Managers contacted: %s", ", ".join(managers_contacted))
    log.info("Elapsed: %.1fs", summary["elapsed_seconds"])
    log.info("Log file: %s", log_file)
    log.info("Report: %s", out_dir)
    log.info("=" * 60)
    print(json.dumps({"output_dir": str(out_dir),
                      "summary": summary["counters"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
