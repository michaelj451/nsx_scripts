#!/usr/bin/env python3
"""tools/nsx/wipe_target_manager.py

Surgical wipe of all CUSTOMER security objects on an NSX Local Manager.
Deletes customer rules, customer policies, customer groups, customer
services in the correct order (rules -> policies -> groups -> services)
so referential integrity is never violated.

What it protects:
  - System-owned objects (_system_owned=true) are NEVER deleted.
  - Default sections (default-layer3-section, default-layer2-section)
    are preserved as policies; their system-default rules are preserved.
    Customer-added rules INSIDE the default sections are deleted.
  - The manager itself is never modified beyond DFW customer objects.

Every run captures a pre-wipe state snapshot on disk before writing.
Default mode is DRY-RUN. Use --apply to actually delete.

USAGE:
    # See what would happen
    python tools/nsx/wipe_target_manager.py --target nsx-lm3

    # Apply
    python tools/nsx/wipe_target_manager.py --target nsx-lm3 --apply

OUTPUT:
    nsx_wipe_bundle/<UTC_TS>/<host>/
        pre_wipe_state.json    complete snapshot of what was there
        manifest.json          per-object action + result
        logs/
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.nsx_constants import resolve_manager         # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient     # noqa: E402

log = logging.getLogger(__name__)

DEFAULT_SECTION_IDS = {"default-layer3-section", "default-layer2-section"}


def _setup_logging(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir = out_dir / "logs"
    log_dir.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"wipe_{ts}.log"
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
# Snapshot capture (pre-wipe state)
# =============================================================================

def _snapshot(client: NsxPolicyClient, domain_id: str) -> Dict[str, Any]:
    """Return a JSON-serializable snapshot of every customer DFW object on
    the target. Used both to produce the delete plan and as an audit
    record (written to pre_wipe_state.json)."""
    services = [s for s in client.list_services() if not s.get("_system_owned")]
    groups   = [g for g in client.list_groups(domain_id=domain_id)
                if not g.get("_system_owned")]
    policies_raw = client.list_security_policies(domain_id=domain_id)

    # Customer policies (deletable): not system-owned, not default sections
    customer_policies = [p for p in policies_raw
                         if not p.get("_system_owned")
                         and p.get("id") not in DEFAULT_SECTION_IDS]

    # Default sections (kept, but their customer-added rules are deletable)
    default_sections = [p for p in policies_raw
                        if p.get("id") in DEFAULT_SECTION_IDS
                        or (p.get("is_default") and not p.get("_system_owned"))]

    # For every policy that has customer rules (customer policies OR default
    # sections), collect the customer rules so we can delete them.
    rules_to_delete: List[Dict[str, Any]] = []
    for p in customer_policies + default_sections:
        try:
            rules = client.list_security_rules(security_policy_id=p["id"],
                                               domain_id=domain_id)
        except Exception as exc:
            log.warning("could not list rules for %s: %s", p["id"], exc)
            continue
        for r in rules:
            if r.get("_system_owned"):
                continue
            # NSX-protected default rules (is_default=true on the rule itself)
            # cannot be deleted via API. Skip them so we do not log noise or
            # inflate the failure count. E.g., default-layer3-section/default-layer3-rule.
            if r.get("is_default"):
                continue
            rules_to_delete.append({
                "policy_id": p["id"],
                "policy_is_default": p.get("id") in DEFAULT_SECTION_IDS,
                **r,
            })

    return {
        "domain_id":         domain_id,
        "customer_services": services,
        "customer_groups":   groups,
        "customer_policies": customer_policies,
        "default_sections":  default_sections,
        "rules_to_delete":   rules_to_delete,
    }


# =============================================================================
# Delete phase (LIFO order: rules first)
# =============================================================================

def _delete_rules(client: NsxPolicyClient, snap: Dict[str, Any],
                  domain_id: str, apply_writes: bool
                  ) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for i, r in enumerate(snap["rules_to_delete"], start=1):
        policy_id = r["policy_id"]
        rule_id = r["id"]
        if not apply_writes:
            results.append({"action": "delete_rule", "policy_id": policy_id,
                            "rule_id": rule_id, "result": "dry_run"})
            log.info("  [%d/%d] DRY   %s/%s", i, len(snap["rules_to_delete"]),
                     policy_id, rule_id)
            continue
        try:
            client.delete_security_rule(security_policy_id=policy_id,
                                        rule_id=rule_id, domain_id=domain_id)
            results.append({"action": "delete_rule", "policy_id": policy_id,
                            "rule_id": rule_id, "result": "deleted"})
            log.info("  [%d/%d] DEL   %s/%s", i, len(snap["rules_to_delete"]),
                     policy_id, rule_id)
        except Exception as exc:
            results.append({"action": "delete_rule", "policy_id": policy_id,
                            "rule_id": rule_id, "result": "failed",
                            "error": str(exc)})
            log.error("  [%d/%d] FAIL  %s/%s: %s", i, len(snap["rules_to_delete"]),
                      policy_id, rule_id, exc)
    return results


def _delete_policies(client: NsxPolicyClient, snap: Dict[str, Any],
                     domain_id: str, apply_writes: bool
                     ) -> List[Dict[str, Any]]:
    """Delete customer policies only. Default sections (default-layer3-section,
    default-layer2-section) are kept as policies; only their customer-added
    rules were removed in the previous phase."""
    results: List[Dict[str, Any]] = []
    for i, p in enumerate(snap["customer_policies"], start=1):
        pol_id = p["id"]
        if not apply_writes:
            results.append({"action": "delete_policy", "policy_id": pol_id,
                            "result": "dry_run"})
            log.info("  [%d/%d] DRY   %s", i, len(snap["customer_policies"]), pol_id)
            continue
        try:
            client.delete_security_policy(security_policy_id=pol_id,
                                          domain_id=domain_id)
            results.append({"action": "delete_policy", "policy_id": pol_id,
                            "result": "deleted"})
            log.info("  [%d/%d] DEL   %s", i, len(snap["customer_policies"]), pol_id)
        except Exception as exc:
            results.append({"action": "delete_policy", "policy_id": pol_id,
                            "result": "failed", "error": str(exc)})
            log.error("  [%d/%d] FAIL  %s: %s", i, len(snap["customer_policies"]),
                      pol_id, exc)
    return results


def _delete_groups(client: NsxPolicyClient, snap: Dict[str, Any],
                   domain_id: str, apply_writes: bool
                   ) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for i, g in enumerate(snap["customer_groups"], start=1):
        gid = g["id"]
        if not apply_writes:
            results.append({"action": "delete_group", "group_id": gid,
                            "result": "dry_run"})
            log.info("  [%d/%d] DRY   %s", i, len(snap["customer_groups"]), gid)
            continue
        try:
            client.delete_group(group_id=gid, domain_id=domain_id)
            results.append({"action": "delete_group", "group_id": gid,
                            "result": "deleted"})
            log.info("  [%d/%d] DEL   %s", i, len(snap["customer_groups"]), gid)
        except Exception as exc:
            results.append({"action": "delete_group", "group_id": gid,
                            "result": "failed", "error": str(exc)})
            log.error("  [%d/%d] FAIL  %s: %s", i, len(snap["customer_groups"]),
                      gid, exc)
    return results


def _delete_services(client: NsxPolicyClient, snap: Dict[str, Any],
                     apply_writes: bool) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for i, s in enumerate(snap["customer_services"], start=1):
        sid = s["id"]
        if not apply_writes:
            results.append({"action": "delete_service", "service_id": sid,
                            "result": "dry_run"})
            log.info("  [%d/%d] DRY   %s", i, len(snap["customer_services"]), sid)
            continue
        try:
            client.delete_service(service_id=sid)
            results.append({"action": "delete_service", "service_id": sid,
                            "result": "deleted"})
            log.info("  [%d/%d] DEL   %s", i, len(snap["customer_services"]), sid)
        except Exception as exc:
            results.append({"action": "delete_service", "service_id": sid,
                            "result": "failed", "error": str(exc)})
            log.error("  [%d/%d] FAIL  %s: %s", i, len(snap["customer_services"]),
                      sid, exc)
    return results


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--target", required=True,
                   help="NSX manager alias to wipe (e.g., nsx-lm3)")
    p.add_argument("--domain-id", default="default")
    p.add_argument("--apply", action="store_true",
                   help="Actually delete. Default is dry-run.")
    p.add_argument("--output-base", default="nsx_wipe_bundle",
                   help="Output root. Default: ./nsx_wipe_bundle/")
    args = p.parse_args()

    host = resolve_manager(args.target)
    if not host:
        raise SystemExit(f"cannot resolve target alias: {args.target}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output_base).expanduser().resolve() / ts / host
    _setup_logging(out_dir)

    log.info("=" * 70)
    log.info("WIPE TARGET MANAGER")
    log.info("  Target        : %s (%s)", args.target, host)
    log.info("  Domain        : %s", args.domain_id)
    log.info("  Mode          : %s", "APPLY" if args.apply else "DRY-RUN")
    log.info("  Output bundle : %s", out_dir)
    log.info("=" * 70)

    client = NsxPolicyClient(nsxmanager=host, federation_global=False)

    # Snapshot
    log.info("Capturing pre-wipe state on %s ...", host)
    snap = _snapshot(client, args.domain_id)
    (out_dir / "pre_wipe_state.json").write_text(
        json.dumps(snap, indent=2, sort_keys=True, default=str),
        encoding="utf-8")
    log.info("  customer_services: %d", len(snap["customer_services"]))
    log.info("  customer_groups  : %d", len(snap["customer_groups"]))
    log.info("  customer_policies: %d (excludes default sections)",
             len(snap["customer_policies"]))
    log.info("  default_sections : %d (kept, only their customer rules deleted)",
             len(snap["default_sections"]))
    log.info("  rules to delete  : %d (across customer policies + default sections)",
             len(snap["rules_to_delete"]))

    # Delete in dependency order
    log.info("")
    log.info("Phase 1: delete rules")
    rule_results = _delete_rules(client, snap, args.domain_id, args.apply)

    log.info("")
    log.info("Phase 2: delete customer policies")
    pol_results = _delete_policies(client, snap, args.domain_id, args.apply)

    log.info("")
    log.info("Phase 3: delete customer groups")
    grp_results = _delete_groups(client, snap, args.domain_id, args.apply)

    log.info("")
    log.info("Phase 4: delete customer services")
    svc_results = _delete_services(client, snap, args.apply)

    manifest = {
        "ran_at":  datetime.now(timezone.utc).isoformat(),
        "target":  f"alias:{args.target} ({host})",
        "domain_id": args.domain_id,
        "mode":    "APPLY" if args.apply else "DRY-RUN",
        "counts_before_wipe": {
            "customer_services": len(snap["customer_services"]),
            "customer_groups":   len(snap["customer_groups"]),
            "customer_policies": len(snap["customer_policies"]),
            "rules_to_delete":   len(snap["rules_to_delete"]),
        },
        "results": {
            "rules":    rule_results,
            "policies": pol_results,
            "groups":   grp_results,
            "services": svc_results,
        },
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    # Summary
    log.info("")
    log.info("=" * 70)
    log.info("SUMMARY (%s)", manifest["mode"])
    for phase, res in manifest["results"].items():
        ok = sum(1 for r in res if r["result"] in ("deleted", "dry_run"))
        fail = sum(1 for r in res if r["result"] == "failed")
        log.info("  %-9s  %d %s, %d failed", phase, ok,
                 "planned" if not args.apply else "deleted", fail)
    log.info("Bundle: %s", out_dir)
    log.info("=" * 70)

    total_failed = sum(1 for section in manifest["results"].values()
                       for r in section if r["result"] == "failed")
    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
