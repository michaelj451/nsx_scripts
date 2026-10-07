#!/usr/bin/env python3
"""
tools/reports/report_vms_in_rules.py

Rule-centric membership report. Given a list of VM display names and/or IP
addresses, this tool finds every DFW rule that touches any of them and emits
a markdown + JSON report grouped BY RULE.

For each VM in the input list, we determine every group it is a live
member of (all sources: tag, path, segment, IP) from NSX's evaluated
`/members/virtual-machines` per group, plus every group whose evaluated
`/members/ip-addresses` covers one of the VM's IPs. An IP entry is matched
by IP only. We then walk every policy + rule and, for each rule, check
whether any target is:

  - in a group referenced by the rule's source_groups
  - in a group referenced by the rule's destination_groups
  - in a group referenced by the rule's scope (applied_to)

Rules that touch at least one target go into the report. Rules with
ANY on both source AND destination (global rules) are included and
labelled so they stand out.

Data comes from one of:
  live (default)    GETs against --manager (LM, or GM with --federation-global)
  --from-snapshot   a tools/nsx/capture_vm_rule_data.py snapshot: same data,
                    frozen at capture time, zero NSX calls
  --from-capture + --from-membership   legacy offline inputs

Read-only: strict GETs, no writes.

Usage:
  python tools/reports/report_vms_in_rules.py --manager nsx-lm1 \\
    [--targets "web01,10.6.0.101"] [--vm-list vm_rule_report_targets.txt]

  python tools/reports/report_vms_in_rules.py \\
    --from-snapshot nsx_vm_rule_snapshots/nsx-lm1.lab.local \\
    --targets "web01,10.6.0.101,db02"

--targets is comma-separated; every token is its own entry. The --vm-list
file is one entry per line; blank lines and lines starting with `#` are
ignored; `name,ip,...` there attaches IPs to a name. Matching is
case-insensitive. Precedence for the list: --targets > --vm-list >
VM_RULE_REPORT_LIST (.env) > auto-discovered vm_rule_report_targets.txt at
repo root.
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
from nsx.vm_rule_data import (
    _group_paths, _has_any, collect_live, load_snapshot,
)

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
      <ip>                         # IP lookup (no VM name needed)
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


# ---------- indexing / IP matching ----------

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


def _entry_label(meta: Dict[str, Any]) -> str:
    """Display name; an IP entry also names the VM(s) holding that IP."""
    name = str(meta.get("display_name") or "")
    owners = meta.get("owner_vms") or []
    return f"{name} (VM: {', '.join(owners)})" if owners else name


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
    data_source: Optional[Dict[str, Any]] = None,
) -> str:
    site_display = site_display or {}
    data_source = data_source or {"mode": "live"}
    show_site_col = federation_mode == "gm" and bool(site_display)
    lines: List[str] = []
    lines.append(f"# VM Rule Membership Report - {manager_host}\n")
    lines.append(f"- **Ran at**: {ran_at}")
    lines.append(f"- **Manager**: {manager_host}")
    if data_source.get("mode") == "snapshot":
        lines.append(f"- **Data**: snapshot captured {data_source.get('collected_at')} "
                     f"(`{data_source.get('snapshot_path')}`). Offline: no NSX contact; "
                     "membership is as of the capture time.")
    elif data_source.get("mode") == "capture+membership":
        lines.append("- **Data**: legacy offline capture + membership export "
                     "(group IPs from definitions only)")
    else:
        lines.append(f"- **Data**: live query at {data_source.get('collected_at')}")
    if data_source.get("fetch_error_count"):
        lines.append(f"- **WARNING**: {data_source['fetch_error_count']} NSX fetch "
                     "error(s) while collecting; results may be incomplete (see log / snapshot)")
    lines.append(f"- **Mode**: {'GM federation (multi-site aggregated)' if federation_mode == 'gm' else 'LM (single site)'}")
    if show_site_col:
        lines.append(
            f"- **Federated sites**: {len(site_display)} "
            f"({', '.join(sorted(site_display.values()))})"
        )
    n_nsx = sum(1 for m in resolved.values() if m.get("kind") == "NSX")
    n_nsx_ip = sum(1 for m in resolved.values() if m.get("kind") == "NSX+ip")
    n_planned = sum(1 for m in resolved.values() if m.get("kind") == "planned")
    n_ip = sum(1 for m in resolved.values() if m.get("kind") == "IP")
    lines.append(f"- **Entries requested**: {len(vm_names_input)}")
    lines.append(
        f"- **Resolved**: {len(resolved)}   "
        f"(NSX={n_nsx}, NSX+explicit-IPs={n_nsx_ip}, planned={n_planned}, IP={n_ip})"
    )
    lines.append(f"- **Names not found (name-only entries, no NSX match)**: {len(not_found)}")
    if duplicate_names:
        lines.append(f"- **Duplicate/ambiguous input names**: {len(duplicate_names)}")
    lines.append(f"- **Rules scanned**: {total_rules}")
    lines.append(f"- **Rules hitting at least one requested VM/IP**: {len(hits)}")
    lines.append("")

    # -------- resolved VMs --------
    lines.append(f"## Requested VMs / IPs matched ({len(resolved)})\n")
    if not resolved:
        lines.append("_No requested entry resolved (names not found and no IPs supplied)._\n")
    else:
        if show_site_col:
            lines.append("| # | VM / IP | Kind | Site | IPs | Groups | Rules hit |")
            lines.append("|---:|---|---|---|---|---:|---:|")
        else:
            lines.append("| # | VM / IP | Kind | IPs | Groups | Rules hit |")
            lines.append("|---:|---|---|---|---:|---:|")
        for i, (name, meta) in enumerate(resolved.items(), start=1):
            kind = meta.get("kind", "NSX")
            label = _entry_label(meta)
            ips = meta.get("ips") or []
            ips_cell = _md_esc(_short(", ".join(ips) if ips else "-", 50))
            if show_site_col:
                site = site_display.get(meta.get("site_id") or "", "-")
                lines.append(
                    f"| {i} | {_md_esc(label)} | "
                    f"{kind} | "
                    f"{_md_esc(site)} | "
                    f"{ips_cell} | "
                    f"{meta.get('group_count', 0)} | "
                    f"{meta.get('rule_hit_count', 0)} |"
                )
            else:
                lines.append(
                    f"| {i} | {_md_esc(label)} | "
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
        header = f"### {_md_esc(_entry_label(meta))}   `{n} rule{'s' if n != 1 else ''}`"
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


# ---------- targets + correlation over one data set ----------

def parse_targets(values: List[str]) -> List[Tuple[str, Optional[List[str]]]]:
    """--targets "web01, 10.6.0.101, db02": every comma-separated token is its
    own entry. A token that is an IP address is looked up by IP (unless a VM
    is literally named that); anything else is a VM display name. Unlike the
    list FILE, `name,ip` here means two separate entries."""
    entries: List[Tuple[str, Optional[List[str]]]] = []
    for raw in values:
        for tok in raw.split(","):
            t = tok.strip()
            if t:
                entries.append((t, None))
    return entries


def _as_ip(s: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(s.strip()))
    except ValueError:
        return None


def analyze(data: Dict[str, Any],
            names_input: List[Tuple[str, Optional[List[str]]]]) -> Dict[str, Any]:
    """Resolve the requested entries against one data set (live pull or
    snapshot) and walk every rule. No NSX contact."""
    vms = data["vms"]
    vm_ext_to_site = data.get("vm_ext_to_site") or {}
    by_name, _by_ext = build_vm_index(vms)
    log.info("VMs indexed: %d (by-name unique keys=%d)", len(vms), len(by_name))
    ip_owners: Dict[str, List[str]] = {}
    for vm in vms:
        for ip in vm.get("ips") or []:
            ip_owners.setdefault(ip, []).append(vm.get("display_name") or "?")

    # ---- resolve target entries ----
    # Each input entry is (name, ips_or_None):
    #   name is a VM  -> NSX match; its IPs (VIF-derived in LM mode) + any explicit ones
    #   name is an IP -> IP lookup (kind "IP")
    #   otherwise     -> planned when explicit IPs were given, else not found
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
            # NSX-matched: IPs from the VM record, union with explicit
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

        name_ip = _as_ip(raw_name)
        if name_ip:
            ips = sorted({name_ip} | set(explicit_ips))
            synth_ext = f"ip:{name_ip}"
            resolved[raw_name] = {
                "external_id": synth_ext,
                "display_name": raw_name,
                "kind": "IP",
                "tags": [],
                "site_id": None,
                "ips": ips,
                "explicit_ips": ips,
                "auto_ips": [],
                "owner_vms": sorted(set(ip_owners.get(name_ip, []))),
            }
            vm_ips[synth_ext] = ips
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

    vm_to_groups = build_vm_to_groups(data["group_to_members"])

    # ---- augment memberships by IP ----
    # Groups can include IP addresses / CIDRs (either as their only members or
    # mixed with tag/segment/path). NSX evaluates DFW rules against packet IPs,
    # so a VM whose IP falls inside a group's IP set (/members/ip-addresses)
    # is effectively a member for rule-matching purposes.
    ip_based_matches = match_vm_ips_to_groups(vm_ips, data["group_ips"])
    for ext, gps in ip_based_matches.items():
        vm_to_groups.setdefault(ext, set()).update(gps)
    log.info("IP-based membership added: %d VM(s) matched %d additional group(s)",
             len(ip_based_matches), sum(len(v) for v in ip_based_matches.values()))

    # Attach per-VM group counts to the resolved dict for the summary table
    for meta in resolved.values():
        meta["group_count"] = len(vm_to_groups.get(meta["external_id"]) or set())
        meta["rule_hit_count"] = 0  # filled in after rule walk

    # ---- walk rules, find hits ----
    all_rules = data["rules"]
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
    return {
        "resolved": resolved,
        "not_found": not_found,
        "duplicate_names": duplicate_names,
        "hits": hits,
        "vm_to_groups": vm_to_groups,
        "ext_id_to_name": ext_id_to_name,
    }


def load_capture_membership(capture_dir: Path, membership_dir: Path,
                            manager_host: str) -> Dict[str, Any]:
    """Legacy offline input: nsx_capture bundle (rules + group definitions)
    plus a tools/nsx/membership.py export (VM -> groups). Group IPs here are
    the definitions' IPAddressExpression entries, NOT NSX's evaluated
    /members/ip-addresses, so tag/nested/segment IPs are missed. Prefer
    --from-snapshot."""
    export_root = _capture_export_root(capture_dir)
    vms, ext_to_gids = load_membership_export(membership_dir)
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
    rules = load_capture_rules(export_root)
    log.info("  loaded: %d VM(s), %d group(s), %d rule(s), %d domain(s)",
             len(vms), len(g_by_path), len(rules), len(dom_ids))
    log.info("  NOTE: group IP membership is derived from captured "
             "IPAddressExpression definitions, not NSX's evaluated "
             "/members/ip-addresses.")
    return {
        "manager_host": manager_host,
        "federation_mode": "lm",
        "collected_at": None,
        "site_display": {},
        "gm_site_eps": {},
        "vm_ext_to_site": {},
        "domain_ids": dom_ids,
        "vms": vms,
        "groups_by_path": g_by_path,
        "group_to_members": g_to_members,
        "member_meta": {},
        "group_ips": g_ips,
        "rules": rules,
        "fetch_errors": [],
    }


# ---------- main ----------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rule-centric membership report for a list of VM names and/or IPs."
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3",
                 "nsx-lm4", "nsx-lm5", "nsx-lm6"],
        default=None,
        help="Manager to query live. Required unless --from-snapshot is given "
             "(the snapshot names its own manager).",
    )
    parser.add_argument(
        "--targets", action="append", default=None, metavar="LIST",
        help="Comma-separated VM names and/or IP addresses, e.g. "
             "\"web01,10.6.0.101,db02\". Each token is its own entry. "
             "Repeatable. When given, no list file is read.",
    )
    parser.add_argument(
        "--vm-list", default=None,
        help="Path to a VM display-name list (one name per line, `#` "
             "comments allowed). Case-insensitive match. Precedence: this "
             "flag > VM_RULE_REPORT_LIST (.env) > auto-discovered "
             f"{DEFAULT_LIST_FILENAME} at repo root.",
    )
    parser.add_argument(
        "--from-snapshot", default=None, metavar="PATH",
        help="Offline: answer from a tools/nsx/capture_vm_rule_data.py "
             "snapshot instead of querying NSX. PATH is the host dir "
             "(its `latest` is used), a timestamped bundle dir, or the "
             "vm_rule_snapshot.json file. No NSX contact.",
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
        help="Legacy offline mode: read evaluated membership from a "
             "tools/nsx/membership.py export dir "
             "(nsx_membership_export/<host>/). Use with --from-capture. "
             "Group IPs come from definitions only; prefer --from-snapshot.",
    )
    parser.add_argument(
        "--from-capture", default=None, metavar="DIR",
        help="Legacy offline mode: read rules and group definitions from an "
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

    legacy_offline = bool(args.from_membership or args.from_capture)
    if legacy_offline and not (args.from_membership and args.from_capture):
        raise SystemExit(
            "--from-membership and --from-capture must be given together: "
            "membership supplies VM-to-group, the capture supplies the rules.")
    if args.from_snapshot and legacy_offline:
        raise SystemExit("--from-snapshot cannot be combined with "
                         "--from-capture/--from-membership.")
    offline = bool(args.from_snapshot or legacy_offline)
    if offline and args.federation_global:
        raise SystemExit(
            "--federation-global is for live GM queries. A GM snapshot already "
            "records its federation mode; legacy offline mode cannot read a GM.")
    if not args.from_snapshot and not args.manager:
        raise SystemExit("--manager is required unless --from-snapshot is given.")

    if args.targets:
        names_input = parse_targets(args.targets)
        list_path: Any = "--targets"
        log.info("Loaded %d entry/-ies from --targets", len(names_input))
    else:
        names_input, list_path = load_vm_names(args.vm_list)
    if not names_input:
        raise SystemExit(f"No VM names or IPs given (source: {list_path})")

    # ---- get the data: snapshot, legacy offline, or live ----
    if args.from_snapshot:
        data = load_snapshot(Path(args.from_snapshot))
        manager_host = data["manager_host"]
        if args.manager and resolve_manager(args.manager) != manager_host:
            raise SystemExit(
                f"--manager {args.manager} ({resolve_manager(args.manager)}) does not "
                f"match the snapshot's manager {manager_host}.")
        log.info("OFFLINE mode (snapshot) - no NSX contact.")
        log.info("  snapshot : %s", data["snapshot_path"])
        log.info("  captured : %s  (%s, %s)", data["collected_at"], manager_host,
                 data["federation_mode"].upper())
        if data["fetch_error_count"]:
            log.warning("  snapshot recorded %d fetch error(s) at capture time: "
                        "results may be incomplete.", data["fetch_error_count"])
        data_source = {"mode": "snapshot", "snapshot_path": data["snapshot_path"],
                       "collected_at": data["collected_at"],
                       "fetch_error_count": data["fetch_error_count"]}
    else:
        manager_host = resolve_manager(args.manager)
        if not manager_host:
            raise SystemExit(f"Manager not defined for {args.manager}.")
        if legacy_offline:
            mdir = Path(args.from_membership).expanduser().resolve()
            cdir = Path(args.from_capture).expanduser().resolve()
            log.info("OFFLINE mode (capture + membership) - no NSX contact.")
            log.info("  membership : %s", mdir)
            log.info("  capture    : %s", cdir)
            data = load_capture_membership(cdir, mdir, manager_host)
            data_source = {"mode": "capture+membership", "capture": str(cdir),
                           "membership": str(mdir), "collected_at": None,
                           "fetch_error_count": 0}
        else:
            log.info("Target manager: %s (federation_global=%s)",
                     manager_host, args.federation_global)
            client = NsxPolicyClient(nsxmanager=manager_host,
                                     federation_global=args.federation_global)
            is_gm = (args.federation_global
                     and "/global-manager/" in client.POLICY_ROOT)
            cache_path = (Path(nsx_log_dir).expanduser().resolve() / ".cache"
                          / f"vm_rule_members_{manager_host}.json")
            data = collect_live(client, manager_host=manager_host, is_gm=is_gm,
                                members_cache_minutes=args.members_cache_minutes,
                                cache_path=cache_path)
            data_source = {"mode": "live", "collected_at": data["collected_at"],
                           "fetch_error_count": len(data["fetch_errors"])}

    domain_ids = data["domain_ids"]
    log.info("Domains: %s", ", ".join(domain_ids))
    result = analyze(data, names_input)
    resolved = result["resolved"]
    not_found = result["not_found"]
    duplicate_names = result["duplicate_names"]
    hits = result["hits"]
    ext_id_to_name = result["ext_id_to_name"]
    groups_by_path = data["groups_by_path"]
    all_rules = data["rules"]
    federation_mode = data["federation_mode"]
    site_display = data.get("site_display") or {}

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
        vm_to_groups=result["vm_to_groups"],
        federation_mode=federation_mode,
        site_display=site_display,
        data_source=data_source,
    )
    md_path = out_dir / "report.md"
    md_path.write_text(md_text, encoding="utf-8")
    log.info("Markdown report: %s", md_path)

    json_doc = {
        "manager": args.manager or data.get("manager_alias"),
        "manager_host": manager_host,
        "ran_at": ran_at,
        "data_source": data_source,
        "vm_list_source": str(list_path),
        "vm_entries_input": [
            {"name": n, "planned_ips": ips} for (n, ips) in names_input
        ],
        "federation_mode": federation_mode,
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
        "data_source": data_source["mode"],
        "data_as_of": data_source.get("collected_at"),
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
