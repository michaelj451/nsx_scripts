#!/usr/bin/env python3
"""
tools/nsx/sync_group_label_tags.py

Mirror a group's tag-based MEMBERSHIP CRITERIA into the group's own LABEL tags.

For every group on the target manager this tool:
  1. Walks the group's membership expression (recursing into NestedExpression,
     so compound/API-authored groups are handled, not just GUI-flattened ones).
  2. Finds every VM Tag Condition whose matched field is in the configured
     match list (default values: network, vm -- from NSX_GROUP_LABEL_MATCH_TAGS
     in .env). Which field is matched is set by --match-on:
       scope (DEFAULT): compare the criterion's SCOPE (the corrected
              orientation, e.g. network|10.6.0.0 matches scope 'network').
       tag            : compare the criterion's TAG value (legacy behavior,
              e.g. the old backward 0|network matches tag 'network').
  3. Ensures each matching {scope, tag} also appears on the group's own `tags`
     (the label / "Tags" you see when editing the group in the UI).

Terminology note (this bit is easy to get backwards):
  NSX stores a Tag condition's value as "scope|tag" -- SCOPE before the pipe,
  TAG after it. In `Virtual Machine | Tag | Equals | 10.6.0.0 | Scope Equals |
  network`, the stored value is "network|10.6.0.0": scope="network",
  tag="10.6.0.0". With the corrected orientation the category lives in the
  scope, so --match-on scope is the right default. The full {scope, tag} pair
  is what gets mirrored onto the label regardless of which field is matched.

The operation is additive and surgical:
  - Existing label tags (ANY scope/tag) are preserved untouched.
  - Only {scope, tag} pairs whose matched field is in the match list are added,
    and only if not already present.
  - Groups with no matching criteria are a no-op.
  - _system_owned groups are skipped.

Federation:
  - Works against a Local Manager (local view), a Local Manager in federated
    view (--federation-global), or a Global Manager (--target nsx-gm1
    --federation-global). list_groups / patch_group follow the right
    /policy vs /global-infra vs /global-manager root automatically.

Safety:
  - Dry-run is the DEFAULT. Real writes require --apply.
  - At --apply time each group is re-GET immediately before PATCH so a tag
    added out-of-band since planning is detected ([NOOP], not clobbered).
  - Writes a revert manifest (apply_manifest.json) recording exactly which
    tags were added to which groups. revert_group_label_tags.py consumes it.

Usage (dry-run, the default):

    python tools/nsx/sync_group_label_tags.py --target nsx-lm1

    python tools/nsx/sync_group_label_tags.py \
        --target nsx-gm1 --federation-global --match-tags network,vm

Usage (apply):

    python tools/nsx/sync_group_label_tags.py --target nsx-gm1 --federation-global --apply
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
from typing import Any, Dict, List, Optional, Set, Tuple

# Make `app/` importable whether run as `python tools/nsx/foo.py` or with
# app already on PYTHONPATH (mirrors tools/reports/*).
sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))

from nsx.cli_bootstrap import init_cli                        # noqa: E402
from nsx.nsx_constants import resolve_manager, nsx_log_dir    # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient, NsxApiError  # noqa: E402

log = logging.getLogger(__name__)

NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2",
                       "nsx-lm3", "nsx-lm4", "nsx-lm5"]
DEFAULT_MATCH_TAGS = "network,vm"
# Which criterion field the match values are compared against. "scope" is the
# corrected orientation (category lives in scope, e.g. network|10.6.0.0);
# "tag" is the legacy value-based behavior (e.g. old 0|network).
DEFAULT_MATCH_ON = "scope"
THROTTLE_SECONDS = 0.2
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


# =============================================================================
# Config / logging
# =============================================================================


def resolve_match_tags(cli_value: Optional[str]) -> List[str]:
    """Match-tag list precedence: --match-tags flag > NSX_GROUP_LABEL_MATCH_TAGS > default.

    These are TAG VALUES (the "Tag" field in a criterion, e.g. network, vm),
    NOT scopes.
    """
    raw = cli_value if cli_value is not None else os.getenv("NSX_GROUP_LABEL_MATCH_TAGS", DEFAULT_MATCH_TAGS)
    return [s.strip() for s in raw.split(",") if s.strip()]


def resolve_match_on(cli_value: Optional[str]) -> str:
    """Which field of a Tag criterion to compare the match values against:
    'scope' (default, corrected orientation) or 'tag' (legacy, value-based).
    Precedence: --match-on flag > NSX_GROUP_LABEL_MATCH_ON > default ('scope').
    """
    raw = (cli_value if cli_value is not None
           else os.getenv("NSX_GROUP_LABEL_MATCH_ON", DEFAULT_MATCH_ON)).strip().lower()
    if raw not in ("scope", "tag"):
        raise SystemExit(f"--match-on must be 'scope' or 'tag', got {raw!r}")
    return raw


def output_dir(host: str) -> Path:
    base = Path(nsx_log_dir).expanduser().resolve()
    d = base / "reports" / "group_label_tags" / host / RUN_TS
    (d / "logs").mkdir(parents=True, exist_ok=True)
    return d


def setup_logging(out_dir: Path) -> Path:
    log_file = (out_dir / "logs" / f"sync_group_label_tags_{RUN_TS}.log").resolve()
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                            "%Y-%m-%dT%H:%M:%S")
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(ch)
    root.addHandler(fh)
    log.info("Logging to %s", log_file)
    return log_file


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


# =============================================================================
# Expression parsing  (mirrors the proven logic in tools/reports/report_tag_map.py)
# =============================================================================


def _walk_expressions(group: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten a group's expression tree, recursing into NestedExpression."""
    out: List[Dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("resource_type"):
                out.append(node)
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    for e in (group.get("expression") or []):
        walk(e)
    return out


def _condition_scope_tag(cond: Dict[str, Any]) -> Tuple[str, str]:
    """Return (scope, tag) for an NSX Tag Condition.

    NSX stores the value as 'scope|tag' (scope BEFORE the pipe, tag after).
    No pipe means empty scope and the whole value is the tag. A rare explicit
    `scope` field is honored as a fallback.
    """
    v = str(cond.get("value") or "")
    if "|" in v:
        scope, tag = v.split("|", 1)
    else:
        scope, tag = str(cond.get("scope") or ""), v
    return scope.strip(), tag.strip()


def desired_label_tags(group: Dict[str, Any], match_values: Set[str],
                       match_on: str = "scope") -> List[Dict[str, str]]:
    """Every {scope, tag} from the group's Tag criteria whose matched field is
    in `match_values`, mirrored (full {scope, tag}) onto the label.

    match_on='scope' (default) compares against the criterion's SCOPE field
    (the corrected orientation, e.g. network|10.6.0.0 -> matches 'network').
    match_on='tag' compares against the TAG field (legacy value-based, e.g.
    old 0|network -> matches 'network')."""
    seen: Set[Tuple[str, str]] = set()
    result: List[Dict[str, str]] = []
    for node in _walk_expressions(group):
        if node.get("resource_type") == "Condition" and node.get("key") == "Tag":
            scope, tag = _condition_scope_tag(node)
            key_val = scope if match_on == "scope" else tag
            if key_val in match_values and (scope, tag) not in seen:
                seen.add((scope, tag))
                result.append({"scope": scope, "tag": tag})
    return result


def existing_tag_pairs(group: Dict[str, Any]) -> Set[Tuple[str, str]]:
    pairs: Set[Tuple[str, str]] = set()
    for t in (group.get("tags") or []):
        if isinstance(t, dict):
            pairs.add((str(t.get("scope") or ""), str(t.get("tag") or "")))
    return pairs


# =============================================================================
# PATCH payload
# =============================================================================

_STRIP_KEYS = {
    "_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
    "_system_owned", "_protection", "_revision", "revision", "unique_id",
    "realization_id", "owner_id", "origin_site_id", "remote_path", "status",
    "children", "path", "relative_path", "parent_path", "marked_for_delete",
    "overridden",
}


def sanitize_for_patch(obj: Dict[str, Any]) -> Dict[str, Any]:
    def walk(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items() if k not in _STRIP_KEYS}
        if isinstance(x, list):
            return [walk(i) for i in x]
        return x
    return walk(obj)


# =============================================================================
# Core
# =============================================================================


def plan_group(group: Dict[str, Any], match_values: Set[str],
               match_on: str = "scope") -> Dict[str, Any]:
    """Compute what (if anything) needs to be added to one group's label."""
    gid = group.get("id")
    desired = desired_label_tags(group, match_values, match_on)
    existing = existing_tag_pairs(group)
    to_add = [t for t in desired if (t["scope"], t["tag"]) not in existing]
    return {
        "group_id": gid,
        "display_name": group.get("display_name"),
        "system_owned": bool(group.get("_system_owned")),
        "matched_criteria_tags": desired,
        "existing_label_tags": sorted(f"{s}|{t}" for s, t in existing),
        "to_add": to_add,
    }


def run(client: NsxPolicyClient, domain_id: str, match_values: Set[str],
        match_on: str, dry_run: bool, out_dir: Path) -> Dict[str, Any]:
    log.info("Listing groups in domain '%s' ...", domain_id)
    groups = client.list_groups(domain_id)
    log.info("Found %d groups", len(groups))

    results: List[Dict[str, Any]] = []
    manifest_entries: List[Dict[str, Any]] = []

    for group in groups:
        plan = plan_group(group, match_values, match_on)
        gid = plan["group_id"]

        if not gid:
            plan["status"] = "skipped"
            plan["reason"] = "missing group id"
            results.append(plan)
            continue

        if plan["system_owned"]:
            plan["status"] = "skipped"
            plan["reason"] = "system_owned"
            results.append(plan)
            continue

        if not plan["to_add"]:
            plan["status"] = "no_change"
            results.append(plan)
            continue

        add_str = ", ".join(f"{t['scope']}|{t['tag']}" for t in plan["to_add"])

        if dry_run:
            log.info("DRY-RUN would add [%s] to group %s (%s)",
                     add_str, gid, plan["display_name"] or "-")
            plan["status"] = "dry_run"
            results.append(plan)
            manifest_entries.append({
                "group_id": gid, "display_name": plan["display_name"],
                "added_tags": plan["to_add"], "prior_tags": _tags_list(group),
            })
            continue

        # Apply: re-GET fresh so an out-of-band change since listing is seen.
        try:
            live = client.get_group(gid, domain_id=domain_id)
        except NsxApiError as e:
            plan["status"] = "failed"
            plan["reason"] = f"get_group: {e}"
            results.append(plan)
            log.error("GET failed for %s: %s", gid, e)
            continue

        live_existing = existing_tag_pairs(live)
        fresh_to_add = [t for t in plan["matched_criteria_tags"]
                        if (t["scope"], t["tag"]) not in live_existing]
        if not fresh_to_add:
            plan["status"] = "noop"
            plan["reason"] = "tags already present at apply time"
            results.append(plan)
            log.info("[NOOP] %s already has %s", gid, add_str)
            continue

        prior_tags = _tags_list(live)
        new_tags = prior_tags + [{"scope": t["scope"], "tag": t["tag"]} for t in fresh_to_add]
        payload = sanitize_for_patch(live)
        payload["tags"] = new_tags

        try:
            client.patch_group(gid, payload, domain_id=domain_id)
            time.sleep(THROTTLE_SECONDS)
        except NsxApiError as e:
            plan["status"] = "failed"
            plan["reason"] = f"patch_group: {e}"
            results.append(plan)
            log.error("PATCH failed for %s: %s", gid, e)
            continue

        plan["status"] = "applied"
        plan["to_add"] = fresh_to_add
        results.append(plan)
        manifest_entries.append({
            "group_id": gid, "display_name": plan["display_name"],
            "added_tags": fresh_to_add, "prior_tags": prior_tags,
        })
        log.info("APPLIED [%s] to group %s (%s)", add_str, gid, plan["display_name"] or "-")

    summary = _summarize(results, domain_id, match_values, match_on, dry_run)
    _write_reports(out_dir, results, manifest_entries, summary, client, domain_id,
                   match_values, match_on, dry_run)
    return summary


def _tags_list(group: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for t in (group.get("tags") or []):
        if isinstance(t, dict):
            out.append({"scope": str(t.get("scope") or ""), "tag": str(t.get("tag") or "")})
    return out


def _summarize(results: List[Dict[str, Any]], domain_id: str,
               match_values: Set[str], match_on: str, dry_run: bool) -> Dict[str, Any]:
    by_status: Dict[str, int] = {}
    tags_added = 0
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        if r["status"] in ("applied", "dry_run"):
            tags_added += len(r.get("to_add") or [])
    return {
        "created_at": utc_now_iso(),
        "domain_id": domain_id,
        "match_tags": sorted(match_values),
        "match_on": match_on,
        "dry_run": dry_run,
        "groups_seen": len(results),
        "by_status": by_status,
        "tag_additions": tags_added,
    }


def _write_reports(out_dir: Path, results: List[Dict[str, Any]],
                   manifest_entries: List[Dict[str, Any]], summary: Dict[str, Any],
                   client: NsxPolicyClient, domain_id: str, match_values: Set[str],
                   match_on: str, dry_run: bool) -> None:
    write_json(out_dir / "results.json", results)
    write_jsonl(out_dir / "results.jsonl", results)
    write_json(out_dir / "summary.json", summary)

    manifest = {
        "created_at": utc_now_iso(),
        "run_ts": RUN_TS,
        "domain_id": domain_id,
        "match_tags": sorted(match_values),
        "match_on": match_on,
        "dry_run": dry_run,
        "manager": getattr(client, "nsxmanager", None),
        "federation_global": getattr(client, "federation_global", None),
        "entries": manifest_entries,
    }
    write_json(out_dir / "apply_manifest.json", manifest)

    # Human-readable per-group diff.
    lines = [
        f"# Group label-tag sync: {'DRY-RUN' if dry_run else 'APPLY'}",
        "",
        f"- Domain: `{domain_id}`",
        f"- Match on: `{match_on}` field  (values compared against each criterion's {match_on})",
        f"- Match values: `{', '.join(sorted(match_values))}`",
        f"- Groups seen: {summary['groups_seen']}",
        f"- Tag additions: {summary['tag_additions']}",
        f"- Status counts: {summary['by_status']}",
        "",
        "| Group | Status | Tags added (scope\\|tag) | Existing label tags |",
        "|---|---|---|---|",
    ]
    for r in results:
        if r["status"] in ("no_change", "skipped"):
            continue
        added = ", ".join(f"{t['scope']}\\|{t['tag']}" for t in (r.get("to_add") or [])) or "-"
        existing = ", ".join(x.replace("|", "\\|") for x in r.get("existing_label_tags") or []) or "-"
        name = r.get("display_name") or "-"
        lines.append(f"| `{r['group_id']}` ({name}) | {r['status']} | {added} | {existing} |")
    (out_dir / "plan.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# =============================================================================
# CLI
# =============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mirror VM Tag criteria into each group's own label tags "
                    "(match on scope [default] or tag value via --match-on)."
    )
    parser.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES,
                        help="Target manager alias from .env/nsx_constants")
    parser.add_argument("--domain-id", default="default")
    parser.add_argument("--federation-global", action="store_true",
                        help="Use the federated/global view (LM federated view or GM native).")
    parser.add_argument("--match-tags", default=None,
                        help="Comma-separated VALUES to match (compared against the field named "
                             "by --match-on). Overrides NSX_GROUP_LABEL_MATCH_TAGS (.env). "
                             "Default: network,vm")
    parser.add_argument("--match-on", default=None, choices=["scope", "tag"],
                        help="Which criterion field the values match against: 'scope' (default; "
                             "corrected orientation where scope=network/vm) or 'tag' (legacy "
                             "value-based). Overrides NSX_GROUP_LABEL_MATCH_ON (.env).")
    parser.add_argument("--apply", action="store_true",
                        help="Actually PATCH groups. Without this the tool dry-runs.")
    args = parser.parse_args()

    init_cli()

    match_tags = resolve_match_tags(args.match_tags)
    if not match_tags:
        raise SystemExit("No match tags configured (set --match-tags or NSX_GROUP_LABEL_MATCH_TAGS).")
    match_on = resolve_match_on(args.match_on)

    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Target manager not defined: {args.target}")

    out_dir = output_dir(target_host)
    log_file = setup_logging(out_dir)
    dry_run = not args.apply

    client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global)

    log.info("Group label-tag sync starting")
    log.info("Target: %s (%s)  federation_global=%s  domain=%s",
             args.target, target_host, args.federation_global, args.domain_id)
    log.info("Match on: %s  values: %s", match_on, match_tags)
    log.info("Mode: %s", "APPLY" if args.apply else "DRY-RUN (default)")

    summary = run(client, args.domain_id, set(match_tags), match_on, dry_run, out_dir)
    summary.update({
        "target": args.target,
        "target_host": target_host,
        "federation_global": args.federation_global,
        "out_dir": str(out_dir),
        "log_file": str(log_file),
    })
    write_json(out_dir / "summary.json", summary)

    log.info("Complete: %s", summary["by_status"])
    print(json.dumps(summary, indent=2))

    if summary["by_status"].get("failed"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
