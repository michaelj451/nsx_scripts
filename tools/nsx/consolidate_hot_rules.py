#!/usr/bin/env python3
"""tools/nsx/consolidate_hot_rules.py

Query a source NSX manager live for per-rule statistics, filter to rules
with hit_count above a threshold in the requested policy categories, and
emit a push-ready bundle containing:
  - a single new consolidated policy (name and category configurable)
  - all filtered rules re-parented under it, names preserved when unique
  - every group and service that any kept rule references (transitive)

Read-only against source (list_* endpoints and policy statistics only).
Never contacts the target. Writes only to the local output directory.

USE CASE:
    You have several Application-category policies on lm1. Only a subset
    of the rules are actually matching real traffic. You want to build
    a single VDI Citrix policy on a fresh lm4 sandbox that contains
    ONLY those actively-used rules, plus every group and service they
    reference, so you can validate the consolidated policy behavior.

USAGE:
    python tools/nsx/consolidate_hot_rules.py \\
        --source nsx-lm1 \\
        --categories Application \\
        --new-policy-id vdi-ctrix \\
        --new-policy-display "VDI Ctrix"

    python tools/nsx/services.py push --target nsx-lm4 --services-dir <bundle>/services/services --apply
    python tools/nsx/groups.py   push --target nsx-lm4 --groups-dir   <bundle>/groups/groups  --segments-mode strip --apply
    python tools/nsx/policies.py push --target nsx-lm4 --policies-dir <bundle>/policies/security-policies --apply
    python tools/nsx/rules.py    push --target nsx-lm4 --rules-dir    <bundle>/rules/security-policies    --apply
"""
from __future__ import annotations

import argparse
import copy
import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.nsx_constants import resolve_manager           # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient       # noqa: E402

# Reuse helpers from filter_policy_bundle so we do not maintain two copies of
# reference-extraction logic. The consolidator is a sibling tool, same layout.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filter_policy_bundle import (                       # noqa: E402
    _load_yaml,
    _extract_group_paths_from_rule,
    _extract_service_paths_from_rule,
    _extract_nested_group_paths,
    _extract_segment_paths,
    _extract_nested_service_paths,
    _discover_policies,
    _discover_rules,
    _discover_groups,
    _discover_services,
    VALID_CATEGORIES,
)

log = logging.getLogger(__name__)


# =============================================================================
# Statistics correlation (adapted from tools/reports/report_rules_usage.py)
# =============================================================================

def _flatten_policy_stats(stats_doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """The /statistics endpoint nests results per enforcement point with a
    'statistics' wrapper. We aggregate across enforcement points keyed by
    internal_rule_id (a string like '3060' that corresponds to rule_id on
    the rule YAML). See tools/reports/report_rules_usage.py for context."""
    by_irid: Dict[str, Dict[str, Any]] = {}
    sum_fields = ("hit_count", "byte_count", "packet_count", "session_count",
                  "l7_accept_count", "l7_reject_count",
                  "l7_reject_with_response_count", "total_session_count",
                  "active_sessions_count")
    max_fields = ("popularity_index", "max_popularity_index",
                  "max_session_count")
    for ep_block in (stats_doc.get("results") or []):
        wrapper = ep_block.get("statistics") or {}
        rule_rows = wrapper.get("results") or ep_block.get("results") or []
        for row in rule_rows:
            irid = str(row.get("internal_rule_id") or row.get("rule_id") or "")
            if not irid:
                continue
            slot = by_irid.setdefault(irid, {"internal_rule_id": irid})
            for f in sum_fields:
                if row.get(f) is not None:
                    slot[f] = slot.get(f, 0) + int(row[f])
            for f in max_fields:
                if row.get(f) is not None:
                    slot[f] = max(slot.get(f, 0), int(row[f]))
    return by_irid


# =============================================================================
# Bundle output layout helpers
# =============================================================================

def _setup_logging(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir = out_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"consolidate_{ts}.log"
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter(
        "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S",
    )
    for h in (logging.StreamHandler(),
              logging.FileHandler(log_file, encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    return log_file


# =============================================================================
# Rule re-parenting
# =============================================================================

def _reparent_rule(rule: Dict[str, Any],
                   new_policy_id: str,
                   new_seq: int,
                   new_rule_id: Optional[str] = None) -> Dict[str, Any]:
    """Return a deep copy of the rule payload with parent-policy references
    rewritten to point at new_policy_id, sequence_number set to new_seq, and
    the display id renamed if new_rule_id is provided.

    Fields rewritten:
      - id (if new_rule_id given)
      - display_name (if new_rule_id given)
      - path        (rebuilt from parent + id)
      - parent_path
      - relative_path
      - _parent_policy_id
      - sequence_number
      - internal_sequence_number (matched to sequence_number)
      - rule_id (NSX auto-assigns on write; keep our stripping conservative)

    We deliberately strip system-owned bookkeeping fields (_create_time,
    _last_modified_time, etc.) so the push tool cannot get confused between
    source and target revision timestamps.
    """
    r = copy.deepcopy(rule)
    orig_id = r.get("id")
    if new_rule_id is not None:
        r["id"] = new_rule_id
        # Keep display_name original unless it exactly matched the old id
        if r.get("display_name") == orig_id:
            r["display_name"] = new_rule_id

    rule_id = r["id"]
    r["parent_path"] = f"/infra/domains/default/security-policies/{new_policy_id}"
    r["path"] = f"{r['parent_path']}/rules/{rule_id}"
    r["relative_path"] = rule_id
    r["_parent_policy_id"] = new_policy_id
    r["sequence_number"] = new_seq
    if "internal_sequence_number" in r:
        r["internal_sequence_number"] = new_seq

    # Strip source-side bookkeeping fields (target will assign fresh)
    for k in ("_create_time", "_create_user",
              "_last_modified_time", "_last_modified_user",
              "_protection", "_system_owned",
              "rule_id"):   # let target auto-assign the numeric internal id
        r.pop(k, None)
    return r


def _build_new_policy(new_policy_id: str,
                      new_policy_display: str,
                      new_policy_category: str,
                      source_policy_sample: Optional[Dict[str, Any]] = None,
                      ) -> Dict[str, Any]:
    """Assemble the fresh consolidated policy YAML. If a source policy is
    provided we copy its stateful/tcp_strict/scope defaults, otherwise fall
    back to the common Application-category shape."""
    tpl = {
        "resource_type": "SecurityPolicy",
        "id":            new_policy_id,
        "display_name":  new_policy_display,
        "path":          f"/infra/domains/default/security-policies/{new_policy_id}",
        "relative_path": new_policy_id,
        "parent_path":   "/infra/domains/default",
        "category":      new_policy_category,
        "stateful":      True,
        "tcp_strict":    True,
        "locked":        False,
        "sequence_number": 1,
        "scope":         ["ANY"],
        "is_default":    False,
        "logging_enabled": False,
    }
    if source_policy_sample:
        for k in ("stateful", "tcp_strict", "scope", "logging_enabled"):
            if k in source_policy_sample:
                tpl[k] = source_policy_sample[k]
    return tpl


# =============================================================================
# Main algorithm
# =============================================================================

def consolidate(
    client: NsxPolicyClient,
    host: str,
    domain_id: str,
    categories: Set[str],
    include_defaults: bool,
    min_hits: int,
    new_policy_id: str,
    new_policy_display: str,
    new_policy_category: str,
    out_dir: Path,
    policies_dir: Path,
    rules_dir: Path,
    groups_dir: Path,
    services_dir: Path,
) -> Dict[str, Any]:
    """Return a manifest dict describing what got included."""
    manifest: Dict[str, Any] = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "source_host": host,
        "domain_id": domain_id,
        "target_categories": sorted(categories),
        "min_hits": min_hits,
        "include_default_sections": include_defaults,
        "new_policy": {
            "id":       new_policy_id,
            "display_name": new_policy_display,
            "category": new_policy_category,
        },
    }

    # 1. Live query for policies + statistics
    log.info("Fetching policies + live statistics from %s ...", host)
    live_policies = client.list_security_policies(domain_id=domain_id)
    kept_pol_paths: Set[str] = set()
    kept_pol_infos: List[Dict[str, Any]] = []
    hit_by_irid: Dict[str, int] = {}   # internal_rule_id -> aggregated hit_count

    for pol in live_policies:
        cat = pol.get("category")
        if cat not in categories:
            continue
        if pol.get("_system_owned"):
            continue
        if pol.get("is_default") and not include_defaults:
            continue
        pol_id = pol.get("id")
        path = pol.get("path")
        if not pol_id or not path:
            continue
        kept_pol_paths.add(path)
        kept_pol_infos.append({"id": pol_id, "path": path, "category": cat,
                               "display_name": pol.get("display_name")})
        try:
            stats = client.get_security_policy_statistics(
                security_policy_id=pol_id, domain_id=domain_id,
            )
        except Exception as exc:
            log.warning("Could not get statistics for %s: %s", pol_id, exc)
            continue
        for irid, row in _flatten_policy_stats(stats).items():
            hit_by_irid[irid] = hit_by_irid.get(irid, 0) + int(row.get("hit_count") or 0)
    log.info("  in-scope customer policies: %d", len(kept_pol_paths))
    log.info("  rules with any statistics data: %d", len(hit_by_irid))

    # 2. Discover local export files (single source of truth for full YAML shapes)
    log.info("Reading local flat exports ...")
    all_policies = _discover_policies(policies_dir)
    all_rules    = _discover_rules(rules_dir)
    all_groups   = _discover_groups(groups_dir)
    all_services = _discover_services(services_dir)
    log.info("  local exports: policies=%d rules-parent-groups=%d groups=%d services=%d",
             len(all_policies), len(all_rules), len(all_groups), len(all_services))

    # 3. Pick out rules with hit_count > min_hits from kept policies
    kept_rules: List[Dict[str, Any]] = []
    skipped_rules: List[Dict[str, Any]] = []
    per_source_policy: Dict[str, int] = {}
    for policy_path in kept_pol_paths:
        for _, rule in all_rules.get(policy_path, []):
            irid = str(rule.get("rule_id") or "")
            hits = hit_by_irid.get(irid, 0)
            src_pol_id = rule.get("_parent_policy_id") or policy_path.rsplit("/", 1)[-1]
            rec = {"rule_id": rule.get("id"), "internal_rule_id": irid,
                   "source_policy": src_pol_id, "hit_count": hits}
            if hits > min_hits:
                kept_rules.append({"rule": rule, "hits": hits,
                                   "source_policy": src_pol_id})
                per_source_policy[src_pol_id] = per_source_policy.get(src_pol_id, 0) + 1
            else:
                rec["reason"] = f"hit_count {hits} <= min_hits {min_hits}"
                skipped_rules.append(rec)
    log.info("Step 3 (hit filter): kept %d rules with hit_count > %d, skipped %d",
             len(kept_rules), min_hits, len(skipped_rules))

    # Sort surviving rules by hit_count descending so the busiest evaluate first
    kept_rules.sort(key=lambda r: (-int(r["hits"]), r["source_policy"],
                                   r["rule"].get("id", "")))

    # 4. Detect rule-id collisions across source policies
    id_seen: Dict[str, List[str]] = {}
    for kr in kept_rules:
        rid = kr["rule"].get("id")
        id_seen.setdefault(rid, []).append(kr["source_policy"])
    collisions = {rid: pols for rid, pols in id_seen.items() if len(set(pols)) > 1}
    if collisions:
        log.warning("Rule-id collisions across source policies: %s. Prefixing colliding "
                    "rules with '<source-policy>-'.", collisions)

    # 5. Extract every group + service ref (transitive)
    ref_group_paths: Set[str] = set()
    ref_service_paths: Set[str] = set()
    for kr in kept_rules:
        ref_group_paths   |= _extract_group_paths_from_rule(kr["rule"])
        ref_service_paths |= _extract_service_paths_from_rule(kr["rule"])
    log.info("Step 5 (rule references): %d group refs, %d service refs",
             len(ref_group_paths), len(ref_service_paths))

    kept_group_paths: Set[str] = set()
    unresolved_group_refs: Set[str] = set()
    segment_refs_seen: Set[str] = set()
    pending = set(ref_group_paths)
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
        for nested in _extract_nested_group_paths(group):
            if nested not in kept_group_paths:
                pending.add(nested)
        segment_refs_seen |= _extract_segment_paths(group)

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
        for nested in _extract_nested_service_paths(service):
            if nested not in kept_service_paths:
                pending.add(nested)
    log.info("Step 5 recursion: kept %d groups + %d services (with %d segment refs to watch)",
             len(kept_group_paths), len(kept_service_paths), len(segment_refs_seen))

    # 6. Build the new policy YAML and re-parent every kept rule
    # Prefer source policy shape from the first surviving rule for stateful/tcp_strict
    source_policy_sample = None
    if kept_rules:
        first_src = kept_rules[0]["source_policy"]
        for pol_path, (_, pol_data) in all_policies.items():
            if pol_data.get("id") == first_src:
                source_policy_sample = pol_data
                break

    new_policy_yaml = _build_new_policy(new_policy_id, new_policy_display,
                                        new_policy_category, source_policy_sample)
    reparented_rules: List[Dict[str, Any]] = []
    for i, kr in enumerate(kept_rules, start=1):
        orig_id = kr["rule"].get("id")
        needs_rename = (orig_id in collisions) if collisions else False
        new_id = f'{kr["source_policy"]}-{orig_id}' if needs_rename else None
        new_rule = _reparent_rule(kr["rule"], new_policy_id, i, new_rule_id=new_id)
        reparented_rules.append({"rule": new_rule, "orig_id": orig_id,
                                 "orig_policy": kr["source_policy"],
                                 "hit_count": kr["hits"]})

    rules_order = [rr["rule"]["id"] for rr in reparented_rules]

    # 7. Write bundle in the push-tool layout
    log.info("Writing consolidated bundle to %s ...", out_dir)
    out_services_dir = out_dir / "services" / "services"
    out_groups_dir   = out_dir / "groups"   / "groups"
    out_policies_dir = out_dir / "policies" / "security-policies" / new_policy_id
    out_rules_dir    = out_dir / "rules"    / "security-policies" / new_policy_id
    for p in (out_services_dir, out_groups_dir, out_policies_dir, out_rules_dir):
        p.mkdir(parents=True, exist_ok=True)

    for p in sorted(kept_service_paths):
        src_file, _ = all_services[p]
        shutil.copy2(src_file, out_services_dir / src_file.name)

    for p in sorted(kept_group_paths):
        src_file, _ = all_groups[p]
        shutil.copy2(src_file, out_groups_dir / src_file.name)

    # policies/security-policies/<new_policy_id>/policy.yaml + rules_order.yaml
    with (out_policies_dir / "policy.yaml").open("w", encoding="utf-8") as fh:
        yaml.safe_dump(new_policy_yaml, fh, sort_keys=False, default_flow_style=False)
    with (out_policies_dir / "rules_order.yaml").open("w", encoding="utf-8") as fh:
        yaml.safe_dump({"rules_order": rules_order}, fh, sort_keys=False,
                       default_flow_style=False)

    # rules/security-policies/<new_policy_id>/policy.yaml + rules_order.yaml + rules/*.yaml
    with (out_rules_dir / "policy.yaml").open("w", encoding="utf-8") as fh:
        yaml.safe_dump(new_policy_yaml, fh, sort_keys=False, default_flow_style=False)
    with (out_rules_dir / "rules_order.yaml").open("w", encoding="utf-8") as fh:
        yaml.safe_dump({"rules_order": rules_order}, fh, sort_keys=False,
                       default_flow_style=False)
    (out_rules_dir / "rules").mkdir(exist_ok=True)
    for i, rr in enumerate(reparented_rules, start=1):
        # File naming matches the capture convention: NNNN_<rule-id>.yaml
        stem = f"{i:04d}_{rr['rule']['id']}"[:80]
        with (out_rules_dir / "rules" / f"{stem}.yaml").open("w", encoding="utf-8") as fh:
            yaml.safe_dump(rr["rule"], fh, sort_keys=False, default_flow_style=False)

    manifest["source_policies_scanned"] = kept_pol_infos
    manifest["kept_rules"] = [{
        "final_id":     rr["rule"]["id"],
        "orig_id":      rr["orig_id"],
        "orig_policy":  rr["orig_policy"],
        "hit_count":    rr["hit_count"],
        "sequence":     rr["rule"]["sequence_number"],
    } for rr in reparented_rules]
    manifest["skipped_rules"] = skipped_rules
    manifest["kept_groups"]   = sorted(kept_group_paths)
    manifest["kept_services"] = sorted(kept_service_paths)
    manifest["rules_order"]   = rules_order
    manifest["unresolved"] = {
        "group_refs":   sorted(unresolved_group_refs),
        "service_refs": sorted(unresolved_service_refs),
    }
    manifest["segments_referenced_by_groups"] = sorted(segment_refs_seen)
    manifest["counts"] = {
        "policies_scanned": len(kept_pol_paths),
        "rules_kept":       len(kept_rules),
        "rules_skipped":    len(skipped_rules),
        "groups_kept":      len(kept_group_paths),
        "services_kept":    len(kept_service_paths),
        "id_collisions":    len(collisions),
        "unresolved_group_refs":   len(unresolved_group_refs),
        "unresolved_service_refs": len(unresolved_service_refs),
        "segments_referenced":     len(segment_refs_seen),
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--source", required=True,
                   help="NSX manager alias to query for stats and read exports from")
    p.add_argument("--domain-id", default="default")
    p.add_argument("--categories", default="Application",
                   help=f"Comma-separated categories to consider. Default: Application. "
                        f"Valid: {', '.join(VALID_CATEGORIES)}")
    p.add_argument("--include-default-sections", action="store_true",
                   help="Also include is_default=true policies (L2/L3 default sections)")
    p.add_argument("--min-hits", type=int, default=0,
                   help="Include only rules with hit_count > this value. Default: 0 "
                        "(any traffic ever seen).")
    p.add_argument("--new-policy-id", default="vdi-ctrix",
                   help="ID for the new consolidated policy. Default: vdi-ctrix")
    p.add_argument("--new-policy-display", default="VDI Ctrix",
                   help="Display name for the new consolidated policy. Default: 'VDI Ctrix'")
    p.add_argument("--new-policy-category", default="Application",
                   choices=list(VALID_CATEGORIES),
                   help="Category for the new consolidated policy. Default: Application")
    p.add_argument("--output-base", default="nsx_filtered_bundle",
                   help="Output root. Default: ./nsx_filtered_bundle/")
    args = p.parse_args()

    host = resolve_manager(args.source)
    if not host:
        raise SystemExit(f"cannot resolve source alias '{args.source}'")
    categories = {c.strip() for c in args.categories.split(",") if c.strip()}
    bad = categories - set(VALID_CATEGORIES)
    if bad:
        raise SystemExit(f"invalid category value(s): {sorted(bad)}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = (Path(args.output_base).expanduser().resolve()
               / ts / host)
    _setup_logging(out_dir)

    log.info("=" * 70)
    log.info("CONSOLIDATE HOT RULES")
    log.info("  Source host          : %s", host)
    log.info("  Domain               : %s", args.domain_id)
    log.info("  Source categories    : %s", sorted(categories))
    log.info("  Hit threshold        : hit_count > %d", args.min_hits)
    log.info("  New consolidated policy:")
    log.info("    id                 : %s", args.new_policy_id)
    log.info("    display_name       : %s", args.new_policy_display)
    log.info("    category           : %s", args.new_policy_category)
    log.info("  Output               : %s", out_dir)
    log.info("=" * 70)

    policies_dir = Path("nsx_policies_export") / host
    rules_dir    = Path("nsx_rules_export")    / host
    groups_dir   = Path("nsx_groups_export")   / host
    services_dir = Path("nsx_services_export") / host
    missing = [d for d in (policies_dir, rules_dir, groups_dir, services_dir)
               if not d.exists()]
    if missing:
        raise SystemExit(f"missing flat-export dirs: {missing}. "
                         "Run capture_nsx_state.py --source first.")

    client = NsxPolicyClient(nsxmanager=host, federation_global=False)

    manifest = consolidate(
        client=client,
        host=host,
        domain_id=args.domain_id,
        categories=categories,
        include_defaults=args.include_default_sections,
        min_hits=args.min_hits,
        new_policy_id=args.new_policy_id,
        new_policy_display=args.new_policy_display,
        new_policy_category=args.new_policy_category,
        out_dir=out_dir,
        policies_dir=policies_dir,
        rules_dir=rules_dir,
        groups_dir=groups_dir,
        services_dir=services_dir,
    )

    c = manifest["counts"]
    log.info("=" * 70)
    log.info("SUMMARY")
    log.info("  Policies scanned     : %d", c["policies_scanned"])
    log.info("  Rules kept           : %d (skipped %d for hit_count <= %d)",
             c["rules_kept"], c["rules_skipped"], args.min_hits)
    log.info("  Groups kept          : %d (recursive)", c["groups_kept"])
    log.info("  Services kept        : %d (recursive)", c["services_kept"])
    if c["id_collisions"]:
        log.warning("  Rule-id collisions   : %d (renamed to '<source-policy>-<id>')",
                    c["id_collisions"])
    if c["unresolved_service_refs"]:
        log.info("  Service refs not in bundle: %d (typically built-in NSX services)",
                 c["unresolved_service_refs"])
    if c["segments_referenced"]:
        log.warning("  Segments referenced  : %d (use groups.py push --segments-mode strip)",
                    c["segments_referenced"])
    log.info("=" * 70)
    log.info("Bundle ready. Push chain:")
    log.info("  python tools/nsx/services.py push --target <alias> \\")
    log.info("      --services-dir %s/services/services --apply", out_dir)
    log.info("  python tools/nsx/groups.py push --target <alias> \\")
    log.info("      --groups-dir %s/groups/groups --segments-mode strip --apply", out_dir)
    log.info("  python tools/nsx/policies.py push --target <alias> \\")
    log.info("      --policies-dir %s/policies/security-policies --apply", out_dir)
    log.info("  python tools/nsx/rules.py push --target <alias> \\")
    log.info("      --rules-dir %s/rules/security-policies --apply", out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
