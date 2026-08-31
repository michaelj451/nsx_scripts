#!/usr/bin/env python3
"""tools/reports/report_tag_map.py

Standalone read-only tag-correlation report. Ties three things together:

    Tags (on VMs)  <-->  Groups (with Tag conditions)  <-->  VMs

For every unique tag in use across the target, shows:
  - Which VMs currently carry that tag
  - Which groups reference that tag via a Condition
  - The "effective" membership: VMs that populate group X via tag Y

Plus pivots:
  - Per-VM: this VM has these tags -> therefore it matches these groups
  - Per-group: this group's Tag conditions -> therefore these VMs match

For groups with complex expressions (NestedExpression, IP/segment mixes),
the "matching VMs" computation is only reliable for simple single-Condition
groups; complex ones fall back to reporting live-evaluated member counts
from NSX's /members/virtual-machines endpoint.

OUTPUT:
    $NSX_LOG_DIR/reports/tag_map/<host>/<UTC_TS>/
        report.md              human-readable markdown
        summary.json           counters + orphan lists
        tag_map.json           full 3-way correlation
        orphan_tags.jsonl      tags applied to VMs but no group uses them
        orphan_conditions.jsonl group Tag conditions matched by zero VMs
        logs/

Read-only against NSX (GETs only).
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time as _time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.cli_bootstrap import init_cli            # noqa: E402
from nsx.nsx_constants import resolve_manager, nsx_log_dir   # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient            # noqa: E402
from nsx.md_utils import align_markdown_tables               # noqa: E402

log = logging.getLogger(__name__)
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2",
                       "nsx-lm3", "nsx-lm4", "nsx-lm5"]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def setup_logging(logs_dir: Path) -> Path:
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    logging.Formatter.converter = _time.gmtime
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter(
        "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S")
    for h in (logging.StreamHandler(),
              logging.FileHandler(logs_dir / f"report_tag_map_{RUN_TS}.log",
                                  encoding="utf-8"),
              logging.FileHandler(global_log_dir / f"report_tag_map_{RUN_TS}.log",
                                  encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    return logs_dir / f"report_tag_map_{RUN_TS}.log"


def _tag_key(scope: str, tag: str) -> str:
    """Canonical string form of a tag: 'scope|tag'."""
    return f"{scope or ''}|{tag or ''}"


def _md_escape_tag(tag_key: str) -> str:
    """Escape pipes in a tag key for markdown table cell safety."""
    return tag_key.replace("|", "\\|")


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


def _group_is_simple_tag_only(group: Dict[str, Any]) -> bool:
    """True if the group's expression is a flat list of Tag Conditions
    joined only by ConjunctionOperator OR clauses. Simple groups let us
    compute matching VMs offline from the tag inventory. Complex groups
    (NestedExpression, mixed IP/segment/tag) require live evaluation."""
    exprs = group.get("expression") or []
    if not exprs:
        return False
    for e in exprs:
        if not isinstance(e, dict):
            return False
        rt = e.get("resource_type")
        if rt == "Condition":
            if e.get("key") != "Tag":
                return False
        elif rt == "ConjunctionOperator":
            # Only OR joins keep it "simple". AND requires per-VM matching-all logic.
            if e.get("conjunction_operator") not in ("OR", None):
                return False
        else:
            return False
    return True


def _extract_tag_conditions(group: Dict[str, Any]) -> List[Dict[str, str]]:
    """Return every Tag Condition in the group's expression, no matter how nested."""
    conds: List[Dict[str, str]] = []
    for e in _walk_expressions(group):
        if e.get("resource_type") == "Condition" and e.get("key") == "Tag":
            conds.append({
                "member_type": e.get("member_type") or "",
                "operator":    e.get("operator") or "",
                "value":       e.get("value") or "",
                "scope":       e.get("scope") or "",
            })
    return conds


def _condition_to_tag_key(cond: Dict[str, str]) -> str:
    """Convert an NSX Tag Condition's value into the canonical tag_key.

    NSX Condition stores tag value as 'scope|tag' in a single string. If
    the string doesn't contain a pipe, scope is empty.
    """
    v = cond.get("value") or ""
    if "|" in v:
        scope, tag = v.split("|", 1)
        return _tag_key(scope, tag)
    return _tag_key("", v)


def build_correlation(
    vms: List[Dict[str, Any]],
    groups: List[Dict[str, Any]],
    live_group_members: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Build the full 3-way correlation. Returns a dict with:
      - by_tag: {tag_key: {vms:[], groups:[]}}
      - by_vm:  {vm_ext_id: {display, tags, groups_matched}}
      - by_group: {group_id: {display, tag_conditions, matching_vms, ...}}
      - orphan_tags: [tag_key, ...]  (on VMs but no group uses them)
      - orphan_conditions: [{group_id, tag_key}, ...]  (group condition, 0 matches)
    """
    # Build tag -> VMs index
    tag_to_vms: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    vm_index: Dict[str, Dict[str, Any]] = {}
    for vm in vms:
        ext = vm.get("external_id") or ""
        dn = vm.get("display_name") or ext or "?"
        tags = vm.get("tags") or []
        tag_keys: Set[str] = set()
        for t in tags:
            if isinstance(t, dict):
                k = _tag_key(t.get("scope",""), t.get("tag",""))
                tag_keys.add(k)
                tag_to_vms[k].append({"external_id": ext, "display_name": dn})
        vm_index[ext] = {
            "external_id": ext,
            "display_name": dn,
            "type":        vm.get("type") or "?",
            "tag_keys":    sorted(tag_keys),
            "groups_matched": [],  # filled below
        }

    # Build tag -> groups + per-group condition list
    group_index: Dict[str, Dict[str, Any]] = {}
    tag_to_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for g in groups:
        gid = g.get("id") or ""
        gdn = g.get("display_name") or gid
        conds = _extract_tag_conditions(g)
        cond_tag_keys = [_condition_to_tag_key(c) for c in conds]
        simple = _group_is_simple_tag_only(g)

        # Simple groups: matching VMs = VMs that carry ANY of the cond tag keys.
        # (Simple groups use OR joins per our _group_is_simple_tag_only check.)
        matching_vms: List[Dict[str, Any]] = []
        if simple and cond_tag_keys:
            seen: Set[str] = set()
            for k in cond_tag_keys:
                for vm in tag_to_vms.get(k, []):
                    if vm["external_id"] not in seen:
                        matching_vms.append(vm)
                        seen.add(vm["external_id"])

        group_index[gid] = {
            "id":             gid,
            "display_name":   gdn,
            "path":           g.get("path"),
            "expression_kind": "simple_tag_or" if simple else "complex",
            "tag_conditions": conds,
            "cond_tag_keys":  cond_tag_keys,
            "matching_vms":   matching_vms,
            "live_vm_members": live_group_members.get(gid, []),
        }
        # Reverse: for each cond tag key, note this group references it
        for k in cond_tag_keys:
            tag_to_groups[k].append({"id": gid, "display_name": gdn,
                                      "expression_kind": group_index[gid]["expression_kind"]})

    # Fill per-VM groups_matched from what we computed above (simple groups only)
    for gid, ginfo in group_index.items():
        for vm in ginfo["matching_vms"]:
            slot = vm_index.get(vm["external_id"])
            if slot:
                slot["groups_matched"].append({"id": gid, "display_name": ginfo["display_name"]})

    # Also fold in live members for complex groups so per-VM view isn't misleading.
    # These come from NSX's /members/virtual-machines endpoint.
    for gid, live_vms in live_group_members.items():
        ginfo = group_index.get(gid)
        if not ginfo or ginfo["expression_kind"] == "simple_tag_or":
            continue
        for lv in live_vms:
            ext = lv.get("external_id") or lv.get("id") or ""
            slot = vm_index.get(ext)
            if slot:
                slot["groups_matched"].append({"id": gid, "display_name": ginfo["display_name"],
                                                "via": "live_eval"})

    # Assemble the by_tag view (both applied-to-VMs AND referenced-by-groups tag keys)
    all_tag_keys = set(tag_to_vms.keys()) | set(tag_to_groups.keys())
    by_tag: Dict[str, Dict[str, Any]] = {}
    for k in sorted(all_tag_keys):
        by_tag[k] = {
            "tag_key":  k,
            "vms":      tag_to_vms.get(k, []),
            "groups":   tag_to_groups.get(k, []),
            "vm_count": len(tag_to_vms.get(k, [])),
            "group_count": len(tag_to_groups.get(k, [])),
        }

    # Orphan tags: on VMs but no group condition references
    orphan_tags = [k for k in tag_to_vms.keys() if k not in tag_to_groups]

    # Orphan conditions: group condition tag key with zero VMs
    orphan_conditions = []
    for gid, ginfo in group_index.items():
        for k in ginfo["cond_tag_keys"]:
            if not tag_to_vms.get(k):
                orphan_conditions.append({
                    "group_id": gid,
                    "group_display": ginfo["display_name"],
                    "tag_key": k,
                })

    return {
        "by_tag":            by_tag,
        "by_vm":             vm_index,
        "by_group":          group_index,
        "orphan_tags":       sorted(orphan_tags),
        "orphan_conditions": orphan_conditions,
    }


def _fetch_live_group_members(client: NsxPolicyClient, domain_id: str,
                               group_ids: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Query /members/virtual-machines per group. Returns {group_id: [{display_name, external_id}, ...]}"""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for gid in group_ids:
        try:
            r = client._get(client.POLICY_ROOT + f"/domains/{domain_id}/groups/{gid}/members/virtual-machines")
            out[gid] = [
                {"external_id": v.get("external_id") or v.get("id") or "",
                 "display_name": v.get("display_name") or ""}
                for v in (r.get("results") or [])
            ]
        except Exception as e:
            log.warning("  group %s: /members query failed: %s", gid, str(e)[:80])
            out[gid] = []
    return out


def write_markdown(out: Path, target: str, correlation: Dict[str, Any],
                   summary: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("# Tag Map Report\n")
    lines.append(f"- **Target**: {target}")
    lines.append(f"- **Ran at**: {summary['ran_at']}")
    lines.append(f"- **Read-only**: yes (GET only)\n")

    lines.append("## Summary\n")
    lines.append("| Metric | Value |\n|---|---:|")
    lines.append(f"| Unique tags in use | {summary['unique_tags']} |")
    lines.append(f"| Tags applied to VMs | {summary['tags_on_vms']} |")
    lines.append(f"| Tags referenced by group conditions | {summary['tags_in_conditions']} |")
    lines.append(f"| Groups scanned | {summary['groups_scanned']} |")
    lines.append(f"| VMs scanned | {summary['vms_scanned']} |")
    lines.append(f"| Orphan tags (on VMs, no group uses them) | {summary['orphan_tag_count']} |")
    lines.append(f"| Orphan conditions (group cond, 0 matching VMs) | {summary['orphan_condition_count']} |")
    lines.append("")

    # =====================================================================
    # 1) PER-TAG view: for each tag, VMs + groups
    # =====================================================================
    by_tag = correlation["by_tag"]
    lines.append(f"## Per-tag view ({len(by_tag)} unique tags)\n")
    lines.append("For each tag in use anywhere (on a VM or in a group condition):\n")
    lines.append("| Tag | # VMs carrying | # Groups referencing | VMs | Groups |")
    lines.append("|---|---:|---:|---|---|")
    for k, info in by_tag.items():
        vm_names = [v["display_name"] for v in info["vms"]]
        group_names = [g["display_name"] for g in info["groups"]]
        vm_cell = ", ".join(vm_names[:5]) + (f" (+{len(vm_names)-5} more)" if len(vm_names) > 5 else "")
        grp_cell = ", ".join(group_names[:5]) + (f" (+{len(group_names)-5} more)" if len(group_names) > 5 else "")
        lines.append(f"| `{_md_escape_tag(k)}` | {info['vm_count']} | {info['group_count']} | "
                     f"{vm_cell or '(none)'} | {grp_cell or '(none)'} |")
    lines.append("")

    # =====================================================================
    # 2) PER-VM view
    # =====================================================================
    by_vm = correlation["by_vm"]
    lines.append(f"## Per-VM view ({len(by_vm)} VMs)\n")
    lines.append("Only REGULAR (customer) VMs are shown; edges + VC_SYSTEM are elided.\n")
    lines.append("| VM | Type | # Tags | Tags | # Groups matched | Groups |")
    lines.append("|---|---|---:|---|---:|---|")
    for ext_id, vm in sorted(by_vm.items(), key=lambda kv: kv[1]["display_name"]):
        tag_cell = ", ".join(_md_escape_tag(t) for t in vm["tag_keys"][:8]) or "(none)"
        if len(vm["tag_keys"]) > 8:
            tag_cell += f" (+{len(vm['tag_keys'])-8} more)"
        grp_names = sorted({g["display_name"] for g in vm["groups_matched"]})
        grp_cell = ", ".join(grp_names[:6]) + (f" (+{len(grp_names)-6} more)" if len(grp_names) > 6 else "") or "(none)"
        lines.append(f"| {vm['display_name']} | {vm['type']} | {len(vm['tag_keys'])} | "
                     f"{tag_cell} | {len(grp_names)} | {grp_cell} |")
    lines.append("")

    # =====================================================================
    # 3) PER-GROUP view
    # =====================================================================
    by_group = correlation["by_group"]
    lines.append(f"## Per-group view ({len(by_group)} groups)\n")
    lines.append("For each customer group with at least one Tag condition: the conditions, "
                 "the matching VMs (via tag correlation for simple groups, or live evaluation "
                 "for complex groups).\n")
    lines.append("| Group | Expression kind | # Tag conds | Tag conditions | # Matching VMs | Matching VMs |")
    lines.append("|---|---|---:|---|---:|---|")
    for gid, gi in sorted(by_group.items(), key=lambda kv: kv[1]["display_name"]):
        if not gi["tag_conditions"]:
            continue
        cond_cell = ", ".join(_md_escape_tag(k) for k in gi["cond_tag_keys"])
        # Prefer computed matching_vms for simple, fallback to live for complex
        vms = gi["matching_vms"] if gi["expression_kind"] == "simple_tag_or" else gi["live_vm_members"]
        vm_names = [v["display_name"] for v in vms]
        vm_cell = ", ".join(vm_names[:6]) + (f" (+{len(vm_names)-6} more)" if len(vm_names) > 6 else "") or "(none)"
        lines.append(f"| `{gid}` ({gi['display_name']}) | {gi['expression_kind']} | "
                     f"{len(gi['tag_conditions'])} | {cond_cell} | "
                     f"{len(vms)} | {vm_cell} |")
    lines.append("")

    # =====================================================================
    # 4) Orphans
    # =====================================================================
    if correlation["orphan_tags"]:
        lines.append(f"## Orphan tags ({len(correlation['orphan_tags'])})\n")
        lines.append("Tags applied to at least one VM, but no group Condition references them. "
                     "Candidates for cleanup or documentation.\n")
        lines.append("| Tag | # VMs |")
        lines.append("|---|---:|")
        for k in correlation["orphan_tags"]:
            vms = correlation["by_tag"].get(k, {}).get("vms") or []
            lines.append(f"| `{_md_escape_tag(k)}` | {len(vms)} |")
        lines.append("")

    if correlation["orphan_conditions"]:
        lines.append(f"## Orphan conditions ({len(correlation['orphan_conditions'])})\n")
        lines.append("Group Tag conditions that no VM currently satisfies. Either the tag "
                     "hasn't been applied yet or the condition is dead.\n")
        lines.append("| Group | Tag condition |")
        lines.append("|---|---|")
        for oc in correlation["orphan_conditions"]:
            lines.append(f"| `{oc['group_id']}` ({oc['group_display']}) | "
                         f"`{_md_escape_tag(oc['tag_key'])}` |")
        lines.append("")

    out.write_text(align_markdown_tables("\n".join(lines)), encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    p.add_argument("--domain-id", default="default",
                   help="Single domain to query. Ignored if --all-domains is set.")
    p.add_argument("--all-domains", action="store_true",
                   help="Discover and iterate all domains on the target.")
    p.add_argument("--federation-global", action="store_true",
                   help="Refused: VM inventory is a fabric (LM-only) API and a "
                        "federation-global run never opens a session to a "
                        "Local Manager. Run this report once per site LM.")
    p.add_argument("--include-system-vms", action="store_true",
                   help="Also include non-REGULAR VMs (Edge, VC_SYSTEM, etc.). "
                        "Default: only REGULAR customer VMs.")
    p.add_argument("--output-base", default=None)
    args = p.parse_args()

    if args.federation_global:
        raise SystemExit(
            "report_tag_map: --federation-global is not supported. VM tag "
            "inventory is a fabric API that lives only on Local Managers, and "
            "a federation-global run never opens a session to an LM (GM-only "
            "rule). Run this report once per site LM instead."
        )

    init_cli()
    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Cannot resolve alias {args.target}")

    base = Path(args.output_base or Path(nsx_log_dir) / "reports" / "tag_map").expanduser().resolve()
    out_dir = base / target_host / RUN_TS
    logs_dir = out_dir / "logs"
    setup_logging(logs_dir)

    log.info("=" * 60)
    log.info("TAG MAP REPORT")
    log.info("  target:            %s (%s)", args.target, target_host)
    log.info("  federation_global: %s", args.federation_global)
    log.info("  domain_id:         %s", args.domain_id)
    log.info("  all_domains:       %s", args.all_domains)
    log.info("  include_system_vms:%s", args.include_system_vms)
    log.info("  output:            %s", out_dir)
    log.info("=" * 60)

    # --federation-global was refused above: this client is always a single
    # (usually Local) manager, and every call below goes to it alone.
    c = NsxPolicyClient(nsxmanager=target_host, federation_global=False)

    # Fetch VMs (fabric API, local to this manager)
    vms: List[Dict[str, Any]] = []
    for v in (c.list_virtual_machines() or []):
        if args.include_system_vms or v.get("type") == "REGULAR":
            vms.append(v)
    log.info("  VMs collected: %d", len(vms))

    # Fetch groups (from all requested domains)
    if args.all_domains:
        doms = c._get(c.POLICY_ROOT + "/domains")
        domain_ids = [d.get("id") for d in (doms.get("results") or []) if d.get("id")]
    else:
        domain_ids = [args.domain_id]
    log.info("  domains queried: %s", domain_ids)

    all_groups: List[Dict[str, Any]] = []
    group_domain: Dict[str, str] = {}
    for did in domain_ids:
        try:
            r = c._get(c.POLICY_ROOT + f"/domains/{did}/groups")
            for g in (r.get("results") or []):
                if g.get("_system_owned"):
                    continue
                all_groups.append(g)
                group_domain[g.get("id")] = did
        except Exception as e:
            log.warning("  domain %s: group list failed: %s", did, str(e)[:80])
    log.info("  customer groups collected: %d", len(all_groups))

    # For complex groups with Tag conditions, fetch the live member list from
    # the same target manager.
    complex_group_ids = [g.get("id") for g in all_groups
                        if not _group_is_simple_tag_only(g)
                        and _extract_tag_conditions(g)]
    live_group_members: Dict[str, List[Dict[str, Any]]] = {}
    if complex_group_ids:
        log.info("  fetching live members for %d complex group(s) ...", len(complex_group_ids))
        for gid in complex_group_ids:
            did = group_domain.get(gid, "default")
            try:
                r = c._get(c.POLICY_ROOT + f"/domains/{did}/groups/{gid}/members/virtual-machines")
                for v in (r.get("results") or []):
                    live_group_members.setdefault(gid, []).append({
                        "external_id": v.get("external_id") or v.get("id") or "",
                        "display_name": v.get("display_name") or "",
                    })
            except Exception:
                pass

    # Build the correlation
    log.info("  building 3-way correlation ...")
    correlation = build_correlation(vms, all_groups, live_group_members)

    # Summary counters
    tag_keys_on_vms = set()
    for vm in vms:
        for t in (vm.get("tags") or []):
            if isinstance(t, dict):
                tag_keys_on_vms.add(_tag_key(t.get("scope",""), t.get("tag","")))
    tag_keys_in_conditions = set()
    for g in all_groups:
        for c_ in _extract_tag_conditions(g):
            tag_keys_in_conditions.add(_condition_to_tag_key(c_))

    summary = {
        "ran_at":                    datetime.now(timezone.utc).isoformat(),
        "target":                    f"alias:{args.target} ({target_host})",
        "federation_global":         args.federation_global,
        "domains_queried":           domain_ids,
        "unique_tags":               len(set(correlation["by_tag"].keys())),
        "tags_on_vms":               len(tag_keys_on_vms),
        "tags_in_conditions":        len(tag_keys_in_conditions),
        "groups_scanned":            len(all_groups),
        "vms_scanned":               len(vms),
        "orphan_tag_count":          len(correlation["orphan_tags"]),
        "orphan_condition_count":    len(correlation["orphan_conditions"]),
    }

    # Write output files
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "tag_map.json").write_text(
        json.dumps(correlation, indent=2, sort_keys=True, default=str), encoding="utf-8")
    with (out_dir / "orphan_tags.jsonl").open("w", encoding="utf-8") as fh:
        for k in correlation["orphan_tags"]:
            fh.write(json.dumps({"tag_key": k,
                                   "vms": correlation["by_tag"].get(k, {}).get("vms", [])},
                                  sort_keys=True) + "\n")
    with (out_dir / "orphan_conditions.jsonl").open("w", encoding="utf-8") as fh:
        for oc in correlation["orphan_conditions"]:
            fh.write(json.dumps(oc, sort_keys=True) + "\n")
    write_markdown(out_dir / "report.md", f"alias:{args.target} ({target_host})",
                   correlation, summary)

    log.info("=" * 60)
    log.info("SUMMARY")
    log.info("  unique_tags:            %d", summary["unique_tags"])
    log.info("  tags_on_vms:            %d", summary["tags_on_vms"])
    log.info("  tags_in_conditions:     %d", summary["tags_in_conditions"])
    log.info("  groups_scanned:         %d", summary["groups_scanned"])
    log.info("  vms_scanned:            %d", summary["vms_scanned"])
    log.info("  orphan_tags:            %d", summary["orphan_tag_count"])
    log.info("  orphan_conditions:      %d", summary["orphan_condition_count"])
    log.info("Report: %s", out_dir)
    log.info("=" * 60)
    print(json.dumps({"output_dir": str(out_dir), "summary": summary}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
