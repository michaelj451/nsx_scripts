#!/usr/bin/env python3
"""tools/pan/add_services_to_rules.py

Append a fixed set of service objects to EVERY customer security rule on
Panorama (shared pre-rulebase + shared post-rulebase + all DG pre + all DG
post). Changes are staged to CANDIDATE config; the operator commits manually.

DEFAULT: dry-run. Add --apply to write.

Workflow:
    1. Connect to Panorama (creds from .env)
    2. Discover device groups + enumerate every customer rule
    3. Capture per-rule baseline (current <service> members) → baseline.json
    4. Ensure all target service objects exist under /config/shared/service
       (idempotent SET — creating a service that already exists is a no-op)
    5. Build the per-rule plan: list services NOT already on each rule
    6. Print dry-run plan
    7. If --apply: SET each missing <member> on each rule
       (SET is additive — existing members are untouched)
    8. Write apply_report.json with success/failure per rule

REVERT: a separate revert tool (not yet built) would read baseline.json and
DELETE the members we added on each rule, restoring the prior service set.

OUTPUT:
    $NSX_LOG_DIR/pan_add_services/<UTC_TS>/
        baseline.json          per-rule service list at start (revert input)
        plan.json              per-rule services to append + ensure-svc list
        apply_report.json      success/failure per rule (only on --apply)
        logs/
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Load .env (lab convention: shell does not auto-source)
def _load_env() -> None:
    """Load .env, expanding $VAR and ${VAR} references using values loaded
    earlier in the same file (or already in os.environ). Lines are processed
    top-to-bottom, so e.g. NSX_LOG_DIR=$ROOT_DIR/nsx_logs works as long as
    ROOT_DIR is defined above it."""
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # Expand $VAR / ${VAR} against the already-loaded environment.
        v_expanded = os.path.expandvars(v.strip())
        os.environ.setdefault(k.strip(), v_expanded)


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "app"))
_load_env()
os.environ.setdefault("PANORAMA_TLS_VERIFY", "false")  # lab self-signed

from palo.panorama_api_client import (   # noqa: E402
    PanoramaClient, PanoramaApiError,
    shared_pre_rules_xpath, shared_post_rules_xpath,
    dg_pre_rules_xpath, dg_post_rules_xpath,
    rule_service_xpath, shared_services_xpath,
)

log = logging.getLogger(__name__)

# =============================================================================
# Target services — the 8 common ports to add to every rule
# =============================================================================
# Service objects we'll create on Panorama under /config/shared/service. Names
# are prefixed so they're easy to identify in the UI and revert.
TARGET_SERVICES: List[Dict[str, str]] = [
    {"name": "pano4-tcp-80",   "protocol": "tcp", "port": "80"},
    {"name": "pano4-tcp-443",  "protocol": "tcp", "port": "443"},
    {"name": "pano4-tcp-22",   "protocol": "tcp", "port": "22"},
    {"name": "pano4-tcp-3389", "protocol": "tcp", "port": "3389"},
    {"name": "pano4-tcp-25",   "protocol": "tcp", "port": "25"},
    {"name": "pano4-tcp-53",   "protocol": "tcp", "port": "53"},
    {"name": "pano4-udp-53",   "protocol": "udp", "port": "53"},
    {"name": "pano4-tcp-8080", "protocol": "tcp", "port": "8080"},
]
TARGET_SERVICE_NAMES = [s["name"] for s in TARGET_SERVICES]


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _setup_logging(out_dir: Path) -> None:
    log_dir = out_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter(
        "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S",
    )
    for h in (logging.StreamHandler(),
              logging.FileHandler(log_dir / f"add_services_{_ts()}.log",
                                  encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)


# =============================================================================
# Discovery — DGs + rules
# =============================================================================

def list_device_groups(client: PanoramaClient) -> List[str]:
    """Return the names of every device-group under
    /config/devices/entry[@name='localhost.localdomain']/device-group/entry/.
    Direct children only — not recursive."""
    xpath = ("/config/devices/entry[@name='localhost.localdomain']"
             "/device-group")
    result = client.get_config(xpath)
    if result is None:
        return []
    # The <result> wraps the matched element; entries are direct children of <device-group>
    dg_root = result.find("./device-group")
    if dg_root is None:
        # Some PAN versions return the element directly without the wrapper
        dg_root = result
    return [e.get("name") for e in dg_root.findall("./entry") if e.get("name")]


def list_rules(client: PanoramaClient, rules_xpath: str
               ) -> List[Tuple[str, List[str]]]:
    """Return [(rule_name, current_service_members), ...] for every rule
    under rules_xpath. Rules with no <service> element default to ['any']."""
    result = client.get_config(rules_xpath)
    if result is None:
        return []
    rules_root = result.find("./rules")
    if rules_root is None:
        rules_root = result
    out: List[Tuple[str, List[str]]] = []
    for entry in rules_root.findall("./entry"):
        name = entry.get("name")
        if not name:
            continue
        svc_el = entry.find("./service")
        members = ([m.text for m in svc_el.findall("./member") if m.text]
                   if svc_el is not None else ["any"])
        out.append((name, members))
    return out


# =============================================================================
# Service object create — idempotent SET on /config/shared/service
# =============================================================================

def ensure_service(client: PanoramaClient, svc: Dict[str, str],
                   dry_run: bool) -> Dict[str, Any]:
    """SET a single service object. SET is additive/idempotent — calling it
    when the object exists with the same content is a no-op.

    Returns {"name": ..., "action": "created"|"already_exists"|"dry_run"|"failed", ...}.
    """
    name = svc["name"]
    xpath = f"{shared_services_xpath()}/entry[@name='{name}']"
    element = (f"<protocol><{svc['protocol']}><port>{svc['port']}"
               f"</port></{svc['protocol']}></protocol>")
    # Probe existing
    try:
        existing = client.get_config(xpath)
        has = existing is not None and existing.find(".//entry") is not None
    except PanoramaApiError:
        has = False
    if has:
        return {"name": name, "action": "already_exists", "xpath": xpath}
    if dry_run:
        return {"name": name, "action": "dry_run_would_create", "xpath": xpath,
                "element": element}
    try:
        client.set_config(xpath, element)
        return {"name": name, "action": "created", "xpath": xpath}
    except PanoramaApiError as exc:
        return {"name": name, "action": "failed", "error": str(exc),
                "xpath": xpath}


# =============================================================================
# Per-rule service modification — append OR replace based on existing state
# =============================================================================

# PAN-OS rejects mixing these "special" service tokens with explicit objects.
# A rule whose <service> contains one of these must be EDITED (replaced)
# rather than SET (appended).
SPECIAL_SERVICE_TOKENS = {"application-default", "any"}


def plan_action(services_before: List[str], target_services: List[str]
                ) -> Tuple[str, List[str], List[str]]:
    """Decide what we need to do to a rule's <service> element.

    Returns (action, new_member_list, will_replace_special).
        action: 'noop'    — rule already has all target services
                'append'  — rule has only specific services; SET each missing target
                'replace' — rule has 'application-default' or 'any'; EDIT the whole
                            <service> to the new union (special token discarded)
        new_member_list: the FULL list of <member> values the rule will hold
                         after the change (only meaningful for replace/noop;
                         append uses services_to_add separately)
        will_replace_special: list of special tokens that will be dropped
    """
    has_special = [s for s in services_before if s in SPECIAL_SERVICE_TOKENS]
    explicit = [s for s in services_before if s not in SPECIAL_SERVICE_TOKENS]
    missing  = [s for s in target_services if s not in services_before]

    if not missing:
        return "noop", services_before, []
    if has_special:
        # Replace: drop the special token(s), keep any explicit specifics, add targets
        union = list(dict.fromkeys(explicit + target_services))  # de-dupe, preserve order
        return "replace", union, has_special
    return "append", explicit + target_services, []


def modify_rule_services(client: PanoramaClient, rules_xpath: str,
                         rule_name: str, action: str,
                         services_to_add: List[str],
                         new_full_list: List[str],
                         dry_run: bool) -> Dict[str, Any]:
    """Execute the planned change. SET for 'append', EDIT for 'replace'."""
    svc_xpath = rule_service_xpath(rules_xpath, rule_name)
    added: List[str] = []
    failed: List[Dict[str, str]] = []

    if action == "noop":
        return {"rulebase": rules_xpath, "rule": rule_name,
                "action": "noop", "added": [], "failed": [], "dry_run": dry_run}

    if action == "append":
        for s in services_to_add:
            if dry_run:
                added.append(s); continue
            try:
                client.set_config(svc_xpath, f"<member>{s}</member>")
                added.append(s)
            except PanoramaApiError as exc:
                failed.append({"service": s, "error": str(exc)})

    elif action == "replace":
        # Build the full new <service> element as a single EDIT operation.
        # EDIT replaces the element at svc_xpath with the supplied content.
        # The xpath points to <service>, so the element must be wrapped as
        # <service>...</service> for edit to work.
        members_xml = "".join(f"<member>{m}</member>" for m in new_full_list)
        new_element = f"<service>{members_xml}</service>"
        if dry_run:
            added.extend(services_to_add)
        else:
            try:
                client.edit_config(svc_xpath, new_element)
                added.extend(services_to_add)
            except PanoramaApiError as exc:
                failed.append({"service": "<edit-whole-service-element>",
                               "error": str(exc)})

    return {
        "rulebase":  rules_xpath,
        "rule":      rule_name,
        "action":    action,
        "added":     added,
        "failed":    failed,
        "new_full":  new_full_list,
        "dry_run":   dry_run,
    }


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--apply", action="store_true",
                        help="Write changes to candidate config. Without this, "
                             "dry-run only.")
    parser.add_argument("--output-base", default=None,
                        help="Override output root. Default: $NSX_LOG_DIR/pan_add_services/")
    args = parser.parse_args()

    base = Path(args.output_base or os.environ.get("NSX_LOG_DIR", "nsx_logs"))
    out_dir = base / "pan_add_services" / _ts()
    out_dir.mkdir(parents=True, exist_ok=True)
    _setup_logging(out_dir)

    log.info("=" * 70)
    log.info("PANORAMA — ADD SERVICES TO EVERY CUSTOMER RULE")
    log.info("  Mode    : %s", "APPLY (writes to candidate config)" if args.apply else "DRY-RUN (no writes)")
    log.info("  Output  : %s", out_dir)
    log.info("=" * 70)

    client = PanoramaClient.from_env()
    log.info("Connected to %s", client.base_url)

    # ----- Discovery -----
    log.info("Discovering device groups ...")
    dgs = list_device_groups(client)
    # Filter out anything that's clearly not a DG (PAN sometimes returns weird
    # extras from nested xpaths). DGs have at least one rulebase.
    real_dgs: List[str] = []
    for dg in dgs:
        try:
            pre = list_rules(client, dg_pre_rules_xpath(dg))
            post = list_rules(client, dg_post_rules_xpath(dg))
            if pre or post:
                real_dgs.append(dg)
        except PanoramaApiError:
            continue
    log.info("  device groups: %d total, %d with rules: %s",
             len(dgs), len(real_dgs), real_dgs)

    # ----- Baseline + plan -----
    log.info("Capturing rule baselines + computing per-rule plan ...")
    all_rulebases: List[Tuple[str, str]] = [
        (shared_pre_rules_xpath(),  "shared/pre-rulebase"),
        (shared_post_rules_xpath(), "shared/post-rulebase"),
    ]
    for dg in real_dgs:
        all_rulebases.append((dg_pre_rules_xpath(dg),  f"{dg}/pre-rulebase"))
        all_rulebases.append((dg_post_rules_xpath(dg), f"{dg}/post-rulebase"))

    baseline: List[Dict[str, Any]] = []
    plan:     List[Dict[str, Any]] = []
    for xpath, label in all_rulebases:
        rules = list_rules(client, xpath)
        for name, current_services in rules:
            baseline.append({
                "rulebase":         label,
                "xpath":            xpath,
                "rule":             name,
                "services_before":  current_services,
            })
            action, new_full, dropped_special = plan_action(
                current_services, TARGET_SERVICE_NAMES,
            )
            missing = [s for s in TARGET_SERVICE_NAMES if s not in current_services]
            plan.append({
                "rulebase":           label,
                "xpath":              xpath,
                "rule":               name,
                "services_before":    current_services,
                "services_to_add":    missing,
                "services_already":   [s for s in TARGET_SERVICE_NAMES if s in current_services],
                "action":             action,
                "new_full_list":      new_full,
                "dropped_special":    dropped_special,
            })

    (out_dir / "baseline.json").write_text(
        json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "plan.json").write_text(
        json.dumps({
            "target_services": TARGET_SERVICES,
            "rulebases":       [r[1] for r in all_rulebases],
            "rules":           plan,
        }, indent=2, sort_keys=True), encoding="utf-8")
    log.info("  baseline written: %d rules captured", len(baseline))
    log.info("  plan written:     %d rules", len(plan))

    total_appends = sum(len(p["services_to_add"]) for p in plan)
    log.info("  total <member> SETs queued: %d (across %d rules)",
             total_appends, sum(1 for p in plan if p["services_to_add"]))

    # ----- Print the dry-run plan (concise table) -----
    log.info("")
    log.info("--- DRY-RUN PLAN (per rule) ---")
    log.info("%-25s %-35s %-8s %-5s drops",
             "rulebase", "rule", "action", "+add")
    actions_counter = {"noop": 0, "append": 0, "replace": 0}
    for p in plan:
        actions_counter[p["action"]] = actions_counter.get(p["action"], 0) + 1
        log.info("%-25s %-35s %-8s +%-4d %s",
                 p["rulebase"][:25], p["rule"][:35], p["action"],
                 len(p["services_to_add"]),
                 ",".join(p["dropped_special"]) if p["dropped_special"] else "")
    log.info("")
    log.info("Action breakdown: noop=%d  append=%d  replace=%d",
             actions_counter.get("noop", 0),
             actions_counter.get("append", 0),
             actions_counter.get("replace", 0))

    # ----- Service object ensure step -----
    log.info("")
    log.info("--- Ensuring target service objects exist on /config/shared/service ---")
    svc_report: List[Dict[str, Any]] = []
    for svc in TARGET_SERVICES:
        result = ensure_service(client, svc, dry_run=not args.apply)
        svc_report.append(result)
        log.info("  %-20s %s", svc["name"], result["action"])

    # ----- Apply step (or stop at dry-run) -----
    if not args.apply:
        log.info("")
        log.info("DRY-RUN COMPLETE — nothing written to candidate config.")
        log.info("Review the plan at: %s/plan.json", out_dir)
        log.info("To apply, re-run with --apply.")
        return 0

    log.info("")
    log.info("--- APPLY: SET (append) or EDIT (replace) per rule based on plan ---")
    apply_results: List[Dict[str, Any]] = []
    rules_touched = 0
    members_added = 0
    failures      = 0
    for p in plan:
        if p["action"] == "noop":
            continue
        result = modify_rule_services(
            client, p["xpath"], p["rule"], p["action"],
            p["services_to_add"], p["new_full_list"], dry_run=False,
        )
        apply_results.append(result)
        rules_touched += 1
        members_added += len(result["added"])
        failures      += len(result["failed"])
        log.info("  %-25s %-35s %-8s +%d  fail=%d",
                 p["rulebase"][:25], p["rule"][:35], p["action"],
                 len(result["added"]), len(result["failed"]))

    apply_report = {
        "ran_at":         datetime.now(timezone.utc).isoformat(),
        "panorama":       client.base_url,
        "rules_touched":  rules_touched,
        "members_added":  members_added,
        "failures":       failures,
        "services_ensured": svc_report,
        "rule_results":   apply_results,
    }
    (out_dir / "apply_report.json").write_text(
        json.dumps(apply_report, indent=2, sort_keys=True), encoding="utf-8")

    log.info("")
    log.info("=" * 70)
    log.info("APPLY COMPLETE")
    log.info("  rules touched : %d", rules_touched)
    log.info("  members added : %d", members_added)
    log.info("  failures      : %d", failures)
    log.info("=" * 70)
    log.info("Changes are STAGED to CANDIDATE config — NOT committed.")
    log.info("Review in Panorama UI → Commit when ready (or click 'Revert Pending' to drop).")
    log.info("Baseline preserved at %s for future revert.", out_dir / "baseline.json")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
