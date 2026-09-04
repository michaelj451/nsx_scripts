#!/usr/bin/env python3
"""tools/pan/pan_group_remap_report.py

Panorama twin of the NSX capture + groups.py push --csv-remap DRY RUN:
pull address objects and address groups from a Panorama (shared + every
device group), run them against a subnet-remap CSV, and write a dry-run
report of what an additive remap would do. READ-ONLY: nothing is pushed;
this is the report step only.

Equivalent NSX flow:
    python tools/nsx/capture_nsx_state.py --source $GM --federation-global
    python tools/nsx/groups.py push --target $GM ... --csv-remap $CSV \
        --reports-dir .../ip_remap_dryrun          # (dry run, no --apply)

CSV format: identical to the NSX tools (headers old_subnet,new_subnet;
longest prefix wins; offset-preserving). Ranges and IPv6 are analyzed and
reported but never proposed for remap, matching the NSX decisions.

Coverage: address GROUPS (shared + each device group) and security RULES in
every rulebase Panorama evaluates: shared pre, per-DG pre, per-DG post,
shared post. Rule members are handled whether they are address object names,
address group references, or literal IP/CIDR/range tokens.

Report sections (mirrors the NSX dry-run report):
  1. Would add in groups: member object, current value, mapped value, and
     whether an object with the mapped value exists (reuse) or would need
     creating (with a suggested name).
  2. Would add in rules: same, per rule and side; literals get "add literal".
  3. Already remapped: old/new value pairs both present in a group or rule side.
  4. Ranges: analysis only (mapped / overlaps / no_mapping).
  5. Never remapped: fqdn, IPv6, dynamic groups.
  6. Unresolved members, nested groups, rule group-references.
  7. CSV coverage: matches per row; unmatched rows are the gaps.

USAGE:
    # As the read-only agent account (recommended), against .env's Panorama
    python tools/pan/pan_group_remap_report.py --csv data/nonprod_map.csv \
        --user-env agent_user --password-env agent_password

    # Another Panorama, specific device groups only
    python tools/pan/pan_group_remap_report.py --csv $CSV --host pano2.lab.local \
        --device-groups dg-4,dg-5

    # Plan only, no network calls
    python tools/pan/pan_group_remap_report.py --csv $CSV --dry-run

Outputs (all timestamps UTC):
    pan_capture/<host>/<TS>/           raw pulled JSON (addresses + groups per scope)
    pan_reports/<host>/<TS>/group_remap_dryrun/report.md and report.json
Override the report location with --reports-dir.

Exit codes: 0 report written, 1 pull/analysis failure, 2 bad arguments/.env.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from palo.pan_group_remap import (  # noqa: E402
    PanRemapError, aggregate_report_items, analyze_groups, analyze_rules,
    csv_coverage, flatten_updates, read_csv_mappings, summarize_refs,
)
from palo.pan_rest_client import PanRestClient, PanRestError  # noqa: E402

log = logging.getLogger("pan_group_remap_report")

DEFAULT_CAPTURE_BASE = REPO_ROOT / "pan_capture"
DEFAULT_REPORTS_BASE = REPO_ROOT / "pan_reports"


def pull_rules(client: PanRestClient, scope: str, rulebase: str) -> List[Dict[str, Any]]:
    """Security rules for one scope ('shared' or a DG name) and rulebase
    ('pre'/'post'). An empty rulebase comes back as [] rather than an error."""
    resource = f"Policies/Security{rulebase.capitalize()}Rules"
    try:
        if scope == "shared":
            return client.entries(resource, location="shared")
        return client.entries(resource, device_group=scope)
    except PanRestError as exc:
        text = str(exc).lower()
        if exc.status_code == 404 or "not present" in text or "non exist" in text:
            return []
        raise


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _md_table(headers: List[str], rows: List[List[str]]) -> List[str]:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) if c is not None else "" for c in r) + " |")
    return out


def build_report_md(meta: Dict[str, Any], scopes: List[Dict[str, Any]],
                    rule_scopes: List[Dict[str, Any]],
                    agg: Dict[str, Any],
                    coverage: List[Dict[str, Any]]) -> str:
    L: List[str] = []
    L.append("# Panorama group remap dry run")
    L.append("")
    L += _md_table(["", ""], [
        ["Target", f"`{meta['target']}`"],
        ["Account", f"`{meta['username']}`"],
        ["CSV", f"`{meta['csv']}` ({meta['csv_rows']} rows)"],
        ["Scopes", ", ".join(s["scope"] for s in scopes)],
        ["Firewalls", "not contacted (Panorama config only)"],
        ["Ran at", meta["ran_at"]],
        ["Mode", "DRY RUN (report only, nothing pushed)"],
    ])
    L.append("")
    L.append("Each object appears ONCE, at the location where it is defined "
             "(a shared object's remap is one shared change no matter how many "
             "device-group rules reference it). Full per-reference detail is in "
             "report.json.")
    L.append("")

    L.append("## 1. Object actions (deduplicated)")
    rows = [[a["member"], a["location"], f"`{a['value']}`", f"`{a['mapped_value']}`",
             (f"reuse `{a['existing_object']}`" if a["existing_object"]
              else f"create `{a['suggested_name']}`"),
             summarize_refs(a["refs"])]
            for a in agg["object_actions"]]
    L += _md_table(["Object", "Defined in", "Current value", "Mapped value", "Action",
                    "Referenced by"], rows) if rows else ["(none)"]
    L.append("")

    L.append("## 2. What gets added where (per group and per rule)")
    updates = flatten_updates(agg)
    rows = [[u["scope"],
             ("group" if u["kind"] == "group" else f"{u['rulebase']}-rule"),
             u["name"], u["side"] or "",
             "; ".join(f"`{a['add']}` (for {a['for']})" for a in u["adds"])]
            for u in updates]
    L += _md_table(["Scope", "Type", "Group / Rule", "Side", "Adds"],
                   rows) if rows else ["(none)"]
    L.append("")

    L.append("## 3. Already remapped pairs")
    rows = [[s["scope"], f"group {g['group']}", i["member"], f"`{i['value']}`",
             i["mapped_member"], f"`{i['mapped_value']}`"]
            for s in scopes for g in s["groups"] for i in g["already_remapped"]]
    rows += [[s["scope"], f"{s['rulebase']}-rule {r['rule']} ({i['side']})", i["member"],
              f"`{i['value']}`", i["mapped_member"], f"`{i['mapped_value']}`"]
             for s in rule_scopes for r in s["rules"] for i in r["already_remapped"]]
    L += _md_table(["Scope", "Where", "Old member", "Old value", "New member", "New value"],
                   rows) if rows else ["(none)"]
    L.append("")

    L.append("## 4. Ranges (analysis only; ranges are never auto-remapped)")
    rows = [[a["member"], a["location"], f"`{a['range']}`",
             f"`{a['proposed_change']}`" if a["proposed_change"] else "", a["status"],
             summarize_refs(a["refs"])]
            for a in agg["ranges"]]
    L += _md_table(["Object", "Defined in", "Range", "Would map to", "Status",
                    "Referenced by"], rows) if rows else ["(none)"]
    L.append("")

    L.append("## 5. Never remapped (fqdn / IPv6 / dynamic groups)")
    rows = [[a.get("member") or "", f"`{a['value']}`", a["reason"], summarize_refs(a["refs"])]
            for a in agg["never_remapped"]]
    L += _md_table(["Member", "Value", "Reason", "Referenced by"], rows) if rows else ["(none)"]
    L.append("")

    L.append("## 6. Unresolved members and nested groups")
    rows = [[s["scope"], f"group {g['group']}", m, "nested group"]
            for s in scopes for g in s["groups"] for m in g["nested_groups"]]
    rows += [[s["scope"], f"group {g['group']}", m, "unresolved (no address object found in scope)"]
             for s in scopes for g in s["groups"] for m in g["unresolved"]]
    rows += [[s["scope"], f"{s['rulebase']}-rule {r['rule']} ({i['side']})", i["member"],
              "unresolved (not an object, group, or IP literal in scope)"]
             for s in rule_scopes for r in s["rules"] for i in r["unresolved"]]
    L += _md_table(["Scope", "Where", "Member", "Note"], rows) if rows else ["(none)"]
    L.append("")

    L.append("## 6b. Rules referencing address groups (no rule edit needed)")
    L.append("A rule whose member is a group inherits the group's update from "
             "section 2 automatically; these rules are listed for visibility, "
             "not as work items.")
    updated_groups = {u["name"] for u in flatten_updates(agg) if u["kind"] == "group"}
    rows = [[s["scope"], s["rulebase"], r["rule"], i["side"], i["group"],
             ("inherits additions via this group" if i["group"] in updated_groups
              else "group has no changes")]
            for s in rule_scopes for r in s["rules"] for i in r["group_refs"]]
    L += _md_table(["Scope", "Rulebase", "Rule", "Side", "Group", "Effect"],
                   rows) if rows else ["(none)"]
    L.append("")

    L.append("## 7. CSV coverage")
    rows = [[f"`{c['old_subnet']}`", f"`{c['new_subnet']}`", c["matches"],
             ", ".join(f"`{v}`" for v in c["values"][:6]) + (" ..." if len(c["values"]) > 6 else "")]
            for c in coverage]
    L += _md_table(["old_subnet", "new_subnet", "group-value matches", "matched values"], rows)
    unmatched = [c for c in coverage if c["matches"] == 0]
    L.append("")
    L.append(f"Rows with no matches in any group: {len(unmatched)} of {len(coverage)}.")
    L.append("")
    return "\n".join(L)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("USAGE:", 1)[1] if "USAGE:" in __doc__ else None)
    parser.add_argument("--csv", required=True, help="Subnet map CSV (old_subnet,new_subnet).")
    parser.add_argument("--host", default=None, help="Target Panorama hostname (overrides .env).")
    parser.add_argument("--device-groups", default=None,
                        help="Comma-separated device groups (default: all discovered).")
    parser.add_argument("--no-shared", action="store_true", help="Skip the shared scope.")
    parser.add_argument("--user-env", default=None,
                        help="Env var holding the username (e.g. agent_user). Default: "
                             "canonical PANORAMA_* resolution.")
    parser.add_argument("--password-env", default=None,
                        help="Env var holding the password (e.g. agent_password).")
    parser.add_argument("--capture-base", default=None,
                        help=f"Capture output base (default {DEFAULT_CAPTURE_BASE}).")
    parser.add_argument("--reports-dir", default=None,
                        help="Report output dir (default pan_reports/<host>/<TS>/group_remap_dryrun).")
    parser.add_argument("--no-tls-verify", action="store_true",
                        help="Disable TLS certificate verification for this run.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the plan (target, account, CSV summary); no network calls.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = time.gmtime

    if args.no_tls_verify:
        os.environ["PANORAMA_TLS_VERIFY"] = "false"

    csv_path = Path(args.csv).expanduser().resolve()
    if not csv_path.exists():
        log.error("CSV not found: %s", csv_path)
        return 2
    try:
        maps = read_csv_mappings(csv_path)
    except (PanRemapError, ValueError) as exc:
        log.error("Bad CSV %s: %s", csv_path, exc)
        return 2

    try:
        client = PanRestClient.from_env(user_env=args.user_env, password_env=args.password_env,
                                        host=args.host)
    except PanRestError as exc:
        log.error("%s", exc)
        return 2

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    host_short = client.env.hostname.split(".")[0]
    capture_dir = (Path(args.capture_base).expanduser().resolve() if args.capture_base
                   else DEFAULT_CAPTURE_BASE) / host_short / ts
    reports_dir = (Path(args.reports_dir).expanduser().resolve() if args.reports_dir
                   else DEFAULT_REPORTS_BASE / host_short / ts / "group_remap_dryrun")

    log.info("Target  : %s (account via %s)", client.env.url,
             args.user_env or "PANORAMA_* resolution")
    log.info("CSV     : %s (%d mappings)", csv_path, len(maps))
    log.info("Capture : %s", capture_dir)
    log.info("Reports : %s", reports_dir)
    if args.dry_run:
        log.info("DRY RUN: no network calls, nothing written.")
        return 0

    # ------------------------------------------------------------------ pull
    try:
        all_dgs = client.list_device_groups()
        dgs = ([d.strip() for d in args.device_groups.split(",") if d.strip()]
               if args.device_groups else all_dgs)
        unknown = sorted(set(dgs) - set(all_dgs))
        if unknown:
            log.error("Unknown device groups: %s (available: %s)", unknown, all_dgs)
            return 2

        shared_addresses = client.list_addresses(location="shared")
        shared_groups = client.list_address_groups(location="shared")
        _write_json(capture_dir / "shared" / "addresses.json", shared_addresses)
        _write_json(capture_dir / "shared" / "address_groups.json", shared_groups)

        scopes: List[Dict[str, Any]] = []
        rule_scopes: List[Dict[str, Any]] = []
        values_seen: List[str] = []
        name_locations: Dict[str, str] = {}

        def note_locations(entries: List[Dict[str, Any]], fallback: str) -> None:
            for e in entries:
                if e.get("@name"):
                    name_locations.setdefault(e["@name"], e.get("@location") or fallback)

        note_locations(shared_addresses, "shared")
        note_locations(shared_groups, "shared")

        def analyze_scope_rules(scope: str, addresses, groups) -> None:
            for rulebase in ("pre", "post"):
                rules = pull_rules(client, scope, rulebase)
                _write_json(capture_dir / scope / f"security_{rulebase}_rules.json", rules)
                res = analyze_rules(rules, addresses, groups, maps,
                                    scope=scope, rulebase=rulebase)
                rule_scopes.append(res)
                values_seen.extend(res["values_seen"])
                log.info("%s: %d %s-rules", scope, len(rules), rulebase)

        if not args.no_shared:
            res = analyze_groups(shared_groups, shared_addresses, maps, scope="shared")
            scopes.append(res)
            values_seen += res["values_seen"]
            log.info("shared: %d groups, %d addresses", len(shared_groups), len(shared_addresses))
            analyze_scope_rules("shared", shared_addresses, shared_groups)

        for dg in dgs:
            dg_addresses = client.list_addresses(device_group=dg)
            dg_groups = client.list_address_groups(device_group=dg)
            _write_json(capture_dir / dg / "addresses.json", dg_addresses)
            _write_json(capture_dir / dg / "address_groups.json", dg_groups)
            note_locations(dg_addresses, dg)
            note_locations(dg_groups, dg)
            # A DG resolves members against its own objects plus shared
            # (flat DG hierarchy; ancestors other than shared not walked).
            vis_addresses = dg_addresses + shared_addresses
            vis_groups = dg_groups + shared_groups
            res = analyze_groups(dg_groups, vis_addresses, maps, scope=dg)
            scopes.append(res)
            values_seen += res["values_seen"]
            log.info("%s: %d groups, %d addresses", dg, len(dg_groups), len(dg_addresses))
            analyze_scope_rules(dg, vis_addresses, vis_groups)
    except PanRestError as exc:
        log.error("Pull failed: %s", exc)
        return 1

    # --------------------------------------------------------------- analyze
    coverage = csv_coverage(maps, values_seen)
    agg = aggregate_report_items(scopes, rule_scopes, name_locations)
    updates = flatten_updates(agg)
    meta = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "target": client.env.url,
        "username": client.username,
        "csv": str(csv_path),
        "csv_rows": len(maps),
        "capture_dir": str(capture_dir),
        "read_only": True,
    }

    totals = {
        "object_actions": len(agg["object_actions"]),
        "targets_updated": len(updates),
        "literal_adds": len(agg["literal_adds"]),
        "group_would_add_refs": sum(len(g["would_add"]) for s in scopes for g in s["groups"]),
        "rule_would_add_refs": sum(len(r["would_add"]) for s in rule_scopes for r in s["rules"]),
        "already_remapped": (sum(len(g["already_remapped"]) for s in scopes for g in s["groups"])
                             + sum(len(r["already_remapped"]) for s in rule_scopes for r in s["rules"])),
        "ranges": (sum(len(g["ranges"]) for s in scopes for g in s["groups"])
                   + sum(len(r["ranges"]) for s in rule_scopes for r in s["rules"])),
        "never_remapped": (sum(len(g["never_remapped"]) for s in scopes for g in s["groups"])
                           + sum(len(r["never_remapped"]) for s in rule_scopes for r in s["rules"])),
        "unresolved": (sum(len(g["unresolved"]) for s in scopes for g in s["groups"])
                       + sum(len(r["unresolved"]) for s in rule_scopes for r in s["rules"])),
        "csv_rows_unmatched": sum(1 for c in coverage if c["matches"] == 0),
    }

    report = {"meta": meta, "totals": totals, "actions": agg, "updates": updates,
              "scopes": scopes, "rule_scopes": rule_scopes, "csv_coverage": coverage}
    _write_json(reports_dir / "report.json", report)
    (reports_dir / "report.md").write_text(
        build_report_md(meta, scopes, rule_scopes, agg, coverage), encoding="utf-8")

    log.info("Totals  : %s", totals)
    log.info("Report  : %s", reports_dir / "report.md")
    log.info("          %s", reports_dir / "report.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
