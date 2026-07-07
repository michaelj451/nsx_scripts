#!/usr/bin/env python3
"""tools/nsx/filter_policy_bundle.py

Offline transform: read a source manager's flat-export bundle (created by
capture_nsx_state.py), filter to security policies matching one or more
categories, walk every reference (groups, services, nested groups,
service-groups), and emit a NEW push-ready bundle containing ONLY the
filtered subset.

The output is directly consumable by the existing push tools:
    services.py push --services-dir <bundle>/services/services
    groups.py   push --groups-dir   <bundle>/groups/groups
    policies.py push --policies-dir <bundle>/policies/security-policies
    rules.py    push --rules-dir    <bundle>/rules/security-policies

USE CASE:
    You captured every DFW object from nsx-lm1, but only want to migrate
    the Application-category rules to nsx-lm4. This tool reads lm1's
    exports, keeps only Application policies plus their rules, referenced
    groups, and referenced services, then produces a minimal bundle that
    pushes cleanly into lm4 without dragging along Infrastructure or
    Ethernet-category policies.

READ-ONLY on source. Only writes to <output-base>/<UTC_TS>/<host>/.
Never touches any NSX manager.

USAGE:
    python tools/nsx/filter_policy_bundle.py \\
        --source nsx-lm1 \\
        --categories Application \\
        [--include-default-sections]

    # Multiple categories:
    python tools/nsx/filter_policy_bundle.py \\
        --source nsx-lm1 \\
        --categories Application,Environment
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.nsx_constants import resolve_manager  # noqa: E402

log = logging.getLogger(__name__)

VALID_CATEGORIES = ("Ethernet", "Emergency", "Infrastructure",
                    "Environment", "Application")


# =============================================================================
# I/O helpers
# =============================================================================

def _load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _write_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, default_flow_style=False)


def _setup_logging(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir = out_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"filter_bundle_{ts}.log"
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter(
        "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S",
    )
    for h in (logging.StreamHandler(), logging.FileHandler(log_file, encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    return log_file


# =============================================================================
# Reference extraction
# =============================================================================

def _extract_group_paths_from_rule(rule: Dict[str, Any]) -> Set[str]:
    """Collect every group path referenced by a rule via source_groups,
    destination_groups, and scope. Excludes 'ANY' and 'any'."""
    paths: Set[str] = set()
    for field in ("source_groups", "destination_groups", "scope"):
        for val in rule.get(field, []) or []:
            if val and val not in ("ANY", "any") and val.startswith("/"):
                paths.add(val)
    return paths


def _extract_service_paths_from_rule(rule: Dict[str, Any]) -> Set[str]:
    """Collect service paths from a rule. Excludes 'ANY'."""
    paths: Set[str] = set()
    for val in rule.get("services", []) or []:
        if val and val not in ("ANY", "any") and val.startswith("/"):
            paths.add(val)
    return paths


def _extract_nested_group_paths(group: Dict[str, Any]) -> Set[str]:
    """Groups can reference OTHER groups through PathExpression. Walk the
    expression tree (including NestedExpression) and collect every group
    path we see. Segment paths (/infra/segments/...) are recorded
    separately by the caller. This function returns groups only."""
    groups: Set[str] = set()
    _walk_expression(group.get("expression") or [], groups)
    return groups


def _extract_segment_paths(group: Dict[str, Any]) -> Set[str]:
    """Segments referenced inside a group's PathExpression. These won't
    exist on the target manager unless recreated separately. The tool
    flags them for operator review."""
    segments: Set[str] = set()
    _walk_expression(group.get("expression") or [], segments, want_segments=True)
    return segments


def _walk_expression(exprs: List[Dict[str, Any]], sink: Set[str],
                     want_segments: bool = False) -> None:
    """Recursive walk. Extracts either group paths (default) or segment
    paths (want_segments=True) from all PathExpression nodes, including
    those nested inside NestedExpression."""
    for e in exprs or []:
        rtype = e.get("resource_type")
        if rtype == "PathExpression":
            for p in e.get("paths", []) or []:
                if want_segments and p.startswith("/infra/segments/"):
                    sink.add(p)
                elif not want_segments and "/groups/" in p:
                    sink.add(p)
        elif rtype == "NestedExpression":
            _walk_expression(e.get("expressions") or [], sink, want_segments)


def _extract_nested_service_paths(service: Dict[str, Any]) -> Set[str]:
    """Service groups can contain member service refs. Returns any /infra/services/... refs."""
    paths: Set[str] = set()
    for entry in service.get("service_entries", []) or []:
        for m in entry.get("members", []) or []:
            if m and m.startswith("/infra/services/"):
                paths.add(m)
    for m in service.get("members", []) or []:
        if m and m.startswith("/infra/services/"):
            paths.add(m)
    return paths


# =============================================================================
# Discovery
# =============================================================================

def _discover_policies(policies_dir: Path) -> Dict[str, Tuple[Path, Dict[str, Any]]]:
    """Return {policy_path: (policy_yaml_file, parsed_policy)} for every
    policy.yaml under the source policies dir."""
    result: Dict[str, Tuple[Path, Dict[str, Any]]] = {}
    for policy_yaml in policies_dir.rglob("policy.yaml"):
        data = _load_yaml(policy_yaml)
        p = data.get("path")
        if p:
            result[p] = (policy_yaml, data)
    return result


def _discover_rules(rules_dir: Path) -> Dict[str, List[Tuple[Path, Dict[str, Any]]]]:
    """Return {parent_policy_path: [(rule_yaml_file, parsed_rule), ...]}."""
    result: Dict[str, List[Tuple[Path, Dict[str, Any]]]] = {}
    for rule_yaml in rules_dir.rglob("rules/*.yaml"):
        data = _load_yaml(rule_yaml)
        parent = data.get("parent_path")
        if parent:
            result.setdefault(parent, []).append((rule_yaml, data))
    return result


def _discover_groups(groups_dir: Path) -> Dict[str, Tuple[Path, Dict[str, Any]]]:
    result: Dict[str, Tuple[Path, Dict[str, Any]]] = {}
    for f in groups_dir.glob("groups/*.yaml"):
        data = _load_yaml(f)
        p = data.get("path")
        if p:
            result[p] = (f, data)
    return result


def _discover_services(services_dir: Path) -> Dict[str, Tuple[Path, Dict[str, Any]]]:
    result: Dict[str, Tuple[Path, Dict[str, Any]]] = {}
    for f in services_dir.glob("services/*.yaml"):
        data = _load_yaml(f)
        p = data.get("path")
        if p:
            result[p] = (f, data)
    return result


# =============================================================================
# Main filter algorithm
# =============================================================================

def filter_bundle(
    policies_dir: Path,
    rules_dir: Path,
    groups_dir: Path,
    services_dir: Path,
    target_categories: Set[str],
    include_default_sections: bool,
    output_dir: Path,
) -> Dict[str, Any]:

    manifest: Dict[str, Any] = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "source_dirs": {
            "policies_dir": str(policies_dir),
            "rules_dir":    str(rules_dir),
            "groups_dir":   str(groups_dir),
            "services_dir": str(services_dir),
        },
        "output_dir":         str(output_dir),
        "target_categories":  sorted(target_categories),
        "include_default_sections": include_default_sections,
    }

    log.info("Discovering source objects ...")
    all_policies = _discover_policies(policies_dir)
    all_rules    = _discover_rules(rules_dir)
    all_groups   = _discover_groups(groups_dir)
    all_services = _discover_services(services_dir)
    log.info("  policies=%d  rules-parent-groups=%d  groups=%d  services=%d",
             len(all_policies), len(all_rules), len(all_groups), len(all_services))

    # Step 1: keep policies matching the categories
    kept_policies: Dict[str, Dict[str, Any]] = {}
    skipped_policies: List[Dict[str, Any]] = []
    for path, (_, pol) in all_policies.items():
        cat = pol.get("category")
        is_default = bool(pol.get("is_default"))
        reason = None
        if cat not in target_categories:
            reason = f"category '{cat}' not in filter"
        elif is_default and not include_default_sections:
            reason = "is_default policy (system default section); pass --include-default-sections to keep"
        if reason:
            skipped_policies.append({
                "path": path, "display_name": pol.get("display_name"),
                "category": cat, "is_default": is_default, "reason": reason,
            })
            continue
        kept_policies[path] = pol
    log.info("Step 1 (policy category filter): kept %d, skipped %d",
             len(kept_policies), len(skipped_policies))

    # Step 2: keep rules for kept policies plus extract refs
    kept_rules_by_policy: Dict[str, List[Dict[str, Any]]] = {}
    ref_group_paths: Set[str] = set()
    ref_service_paths: Set[str] = set()
    rules_total = 0
    for policy_path in kept_policies:
        rules_for_policy = all_rules.get(policy_path, [])
        rules_kept_for_policy: List[Dict[str, Any]] = []
        for _, rule in rules_for_policy:
            rules_kept_for_policy.append(rule)
            ref_group_paths |= _extract_group_paths_from_rule(rule)
            ref_service_paths |= _extract_service_paths_from_rule(rule)
        kept_rules_by_policy[policy_path] = rules_kept_for_policy
        rules_total += len(rules_kept_for_policy)
    log.info("Step 2 (rules per policy): kept %d rules, referenced %d groups, %d services",
             rules_total, len(ref_group_paths), len(ref_service_paths))

    # Step 3: recursively expand group references
    kept_group_paths: Set[str] = set()
    unresolved_group_refs: Set[str] = set()
    segment_refs_seen: Set[str] = set()
    pending: Set[str] = set(ref_group_paths)
    while pending:
        p = pending.pop()
        if p in kept_group_paths:
            continue
        entry = all_groups.get(p)
        if entry is None:
            unresolved_group_refs.add(p)
            continue
        kept_group_paths.add(p)
        _, group = entry
        for nested_p in _extract_nested_group_paths(group):
            if nested_p not in kept_group_paths:
                pending.add(nested_p)
        segment_refs_seen |= _extract_segment_paths(group)
    log.info("Step 3 (group recursion): kept %d groups (recursively), %d unresolved refs, %d segment refs seen",
             len(kept_group_paths), len(unresolved_group_refs), len(segment_refs_seen))

    # Step 4: recursively expand service references
    kept_service_paths: Set[str] = set()
    unresolved_service_refs: Set[str] = set()
    pending = set(ref_service_paths)
    while pending:
        p = pending.pop()
        if p in kept_service_paths:
            continue
        entry = all_services.get(p)
        if entry is None:
            unresolved_service_refs.add(p)
            continue
        kept_service_paths.add(p)
        _, service = entry
        for nested_p in _extract_nested_service_paths(service):
            if nested_p not in kept_service_paths:
                pending.add(nested_p)
    log.info("Step 4 (service recursion): kept %d services, %d unresolved refs",
             len(kept_service_paths), len(unresolved_service_refs))

    # Step 5: write the filtered bundle in push-ready layout
    log.info("Writing filtered bundle to %s ...", output_dir)
    out_services_dir  = output_dir / "services"  / "services"
    out_groups_dir    = output_dir / "groups"    / "groups"
    out_policies_dir  = output_dir / "policies"  / "security-policies"
    out_rules_dir     = output_dir / "rules"     / "security-policies"

    for p in (out_services_dir, out_groups_dir, out_policies_dir, out_rules_dir):
        p.mkdir(parents=True, exist_ok=True)

    for p in sorted(kept_service_paths):
        src_file, service = all_services[p]
        shutil.copy2(src_file, out_services_dir / src_file.name)

    for p in sorted(kept_group_paths):
        src_file, group = all_groups[p]
        shutil.copy2(src_file, out_groups_dir / src_file.name)

    for policy_path in sorted(kept_policies):
        src_policy_yaml, pol = all_policies[policy_path]
        slug_dir = src_policy_yaml.parent.name

        p_out = out_policies_dir / slug_dir
        p_out.mkdir(exist_ok=True)
        shutil.copy2(src_policy_yaml, p_out / "policy.yaml")
        rules_order_src = src_policy_yaml.parent / "rules_order.yaml"
        if rules_order_src.exists():
            shutil.copy2(rules_order_src, p_out / "rules_order.yaml")

        r_out = out_rules_dir / slug_dir
        r_out.mkdir(exist_ok=True)
        shutil.copy2(src_policy_yaml, r_out / "policy.yaml")
        if rules_order_src.exists():
            shutil.copy2(rules_order_src, r_out / "rules_order.yaml")

        candidate = rules_dir / "security-policies" / slug_dir / "rules"
        if candidate.exists():
            (r_out / "rules").mkdir(exist_ok=True)
            for f in candidate.glob("*.yaml"):
                shutil.copy2(f, r_out / "rules" / f.name)

    manifest["kept"] = {
        "policies":  [{"path": p, "display_name": kept_policies[p].get("display_name"),
                       "category": kept_policies[p].get("category")}
                      for p in sorted(kept_policies)],
        "rules_count":     rules_total,
        "groups":          sorted(kept_group_paths),
        "services":        sorted(kept_service_paths),
    }
    manifest["skipped_policies"] = skipped_policies
    manifest["unresolved"] = {
        "group_refs":      sorted(unresolved_group_refs),
        "service_refs":    sorted(unresolved_service_refs),
    }
    manifest["segments_referenced_by_groups"] = sorted(segment_refs_seen)
    manifest["counts"] = {
        "policies_kept":  len(kept_policies),
        "policies_skipped": len(skipped_policies),
        "rules_kept":     rules_total,
        "groups_kept":    len(kept_group_paths),
        "services_kept":  len(kept_service_paths),
        "unresolved_group_refs":   len(unresolved_group_refs),
        "unresolved_service_refs": len(unresolved_service_refs),
        "segments_referenced":     len(segment_refs_seen),
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--source", required=True,
                   help="NSX manager alias whose flat exports to filter. "
                        "Paths are derived from "
                        "nsx_{policies,rules,groups,services}_export/<host>/.")
    p.add_argument("--categories", required=True,
                   help="Comma-separated list of policy categories to KEEP. "
                        f"Valid values: {', '.join(VALID_CATEGORIES)}.")
    p.add_argument("--include-default-sections", action="store_true",
                   help="Also keep policies where is_default=true (the L2/L3 "
                        "default sections). Off by default.")
    p.add_argument("--output-base", default="nsx_filtered_bundle",
                   help="Output root. Default: ./nsx_filtered_bundle/")
    p.add_argument("--source-host-override", default=None,
                   help="Override the derived hostname. Default: resolve --source.")
    args = p.parse_args()

    host = args.source_host_override or resolve_manager(args.source)
    if not host:
        raise SystemExit(f"could not resolve --source={args.source} to a hostname")

    categories = {c.strip() for c in args.categories.split(",") if c.strip()}
    bad = categories - set(VALID_CATEGORIES)
    if bad:
        raise SystemExit(
            f"invalid category value(s): {sorted(bad)}. "
            f"Valid: {', '.join(VALID_CATEGORIES)}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output_base).expanduser().resolve() / ts / host
    _setup_logging(out_dir)

    log.info("=" * 70)
    log.info("FILTER POLICY BUNDLE")
    log.info("  Source host          : %s", host)
    log.info("  Categories to keep   : %s", sorted(categories))
    log.info("  Include defaults     : %s", args.include_default_sections)
    log.info("  Output               : %s", out_dir)
    log.info("=" * 70)

    policies_dir = Path("nsx_policies_export") / host
    rules_dir    = Path("nsx_rules_export")    / host
    groups_dir   = Path("nsx_groups_export")   / host
    services_dir = Path("nsx_services_export") / host

    missing = [d for d in (policies_dir, rules_dir, groups_dir, services_dir) if not d.exists()]
    if missing:
        raise SystemExit(f"missing source directories: {missing}. "
                         "Run capture_nsx_state.py first.")

    manifest = filter_bundle(
        policies_dir=policies_dir,
        rules_dir=rules_dir,
        groups_dir=groups_dir,
        services_dir=services_dir,
        target_categories=categories,
        include_default_sections=args.include_default_sections,
        output_dir=out_dir,
    )

    c = manifest["counts"]
    log.info("=" * 70)
    log.info("SUMMARY")
    log.info("  Policies kept:  %d  (skipped %d)", c["policies_kept"], c["policies_skipped"])
    log.info("  Rules kept:     %d", c["rules_kept"])
    log.info("  Groups kept:    %d  (recursive)", c["groups_kept"])
    log.info("  Services kept:  %d  (recursive)", c["services_kept"])
    if c["unresolved_group_refs"]:
        log.warning("  UNRESOLVED group refs: %d. Rules reference groups not found in the source bundle.",
                    c["unresolved_group_refs"])
    if c["unresolved_service_refs"]:
        log.info("  Service refs not in source bundle: %d (typically built-in NSX services like HTTP, ICMP-ALL, which exist on every target by default; verify list in manifest.json).",
                 c["unresolved_service_refs"])
    if c["segments_referenced"]:
        log.warning("  Segments referenced BY GROUPS: %d. Those segments must exist on the target manager, "
                    "or use groups.py push --segments-mode strip",
                    c["segments_referenced"])
    log.info("=" * 70)
    log.info("Bundle ready. To push to a target manager:")
    log.info("  python tools/nsx/services.py push --target <alias> \\")
    log.info("      --services-dir %s/services/services --apply", out_dir)
    log.info("  python tools/nsx/groups.py   push --target <alias> \\")
    log.info("      --groups-dir   %s/groups/groups --apply", out_dir)
    log.info("  python tools/nsx/policies.py push --target <alias> \\")
    log.info("      --policies-dir %s/policies/security-policies --apply", out_dir)
    log.info("  python tools/nsx/rules.py    push --target <alias> \\")
    log.info("      --rules-dir    %s/rules/security-policies --apply", out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
