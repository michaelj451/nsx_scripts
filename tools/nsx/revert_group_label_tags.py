#!/usr/bin/env python3
"""
tools/nsx/revert_group_label_tags.py

Reverse a prior sync_group_label_tags.py --apply run.

Consumes the apply_manifest.json that sync wrote and removes ONLY the
{scope, tag} label tags that run added to each group. Every other label
tag is preserved. Read-modify-write per group:

  1. GET the live group.
  2. Guard: only remove a recorded tag if it is still present.
  3. PATCH the group back with the reduced tag list.

If a recorded tag is no longer present (already removed out-of-band), it is
reported as [GUARD] and left alone.

Safety:
  - Dry-run is the DEFAULT. Real writes require --apply.
  - Only tags listed under this manifest's `entries[].added_tags` are ever
    removed. Nothing else is touched.

Usage (dry-run):

    python tools/nsx/revert_group_label_tags.py \
        --target nsx-lm1 \
        --manifest <NSX_LOG_DIR>/reports/group_label_tags/<host>/<ts>/apply_manifest.json

Usage (apply):

    python tools/nsx/revert_group_label_tags.py --target nsx-lm1 --manifest <path> --apply
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))

from nsx.cli_bootstrap import init_cli                        # noqa: E402
from nsx.nsx_constants import resolve_manager, nsx_log_dir    # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient, NsxApiError  # noqa: E402

log = logging.getLogger(__name__)

NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2",
                       "nsx-lm3", "nsx-lm4", "nsx-lm5"]
THROTTLE_SECONDS = 0.2
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

_STRIP_KEYS = {
    "_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
    "_system_owned", "_protection", "_revision", "revision", "unique_id",
    "realization_id", "owner_id", "origin_site_id", "remote_path", "status",
    "children", "path", "relative_path", "parent_path", "marked_for_delete",
    "overridden",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def setup_logging(out_dir: Path) -> Path:
    (out_dir / "logs").mkdir(parents=True, exist_ok=True)
    log_file = (out_dir / "logs" / f"revert_group_label_tags_{RUN_TS}.log").resolve()
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
    return log_file


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sanitize_for_patch(obj: Dict[str, Any]) -> Dict[str, Any]:
    def walk(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items() if k not in _STRIP_KEYS}
        if isinstance(x, list):
            return [walk(i) for i in x]
        return x
    return walk(obj)


def tags_list(group: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for t in (group.get("tags") or []):
        if isinstance(t, dict):
            out.append({"scope": str(t.get("scope") or ""), "tag": str(t.get("tag") or "")})
    return out


def revert(client: NsxPolicyClient, manifest: Dict[str, Any],
           domain_id: str, dry_run: bool, out_dir: Path) -> Dict[str, Any]:
    entries = manifest.get("entries") or []
    log.info("Manifest has %d entries", len(entries))

    results: List[Dict[str, Any]] = []

    for entry in entries:
        gid = entry.get("group_id")
        remove_pairs: Set[Tuple[str, str]] = {
            (str(t.get("scope") or ""), str(t.get("tag") or ""))
            for t in (entry.get("added_tags") or [])
        }
        row: Dict[str, Any] = {
            "group_id": gid,
            "display_name": entry.get("display_name"),
            "requested_removals": sorted(f"{s}|{t}" for s, t in remove_pairs),
        }

        if not gid or not remove_pairs:
            row["status"] = "skipped"
            row["reason"] = "no group id or nothing to remove"
            results.append(row)
            continue

        try:
            live = client.get_group(gid, domain_id=domain_id)
        except NsxApiError as e:
            row["status"] = "failed"
            row["reason"] = f"get_group: {e}"
            results.append(row)
            log.error("GET failed for %s: %s", gid, e)
            continue

        current = tags_list(live)
        current_pairs = {(t["scope"], t["tag"]) for t in current}
        present = remove_pairs & current_pairs
        absent = remove_pairs - current_pairs

        if not present:
            row["status"] = "guard"
            row["reason"] = "recorded tags no longer present"
            row["already_absent"] = sorted(f"{s}|{t}" for s, t in absent)
            results.append(row)
            log.info("[GUARD] %s: recorded tags already absent", gid)
            continue

        new_tags = [t for t in current if (t["scope"], t["tag"]) not in present]
        removed_str = ", ".join(f"{s}|{t}" for s, t in sorted(present))

        if dry_run:
            row["status"] = "dry_run"
            row["would_remove"] = sorted(f"{s}|{t}" for s, t in present)
            results.append(row)
            log.info("DRY-RUN would remove [%s] from group %s", removed_str, gid)
            continue

        payload = sanitize_for_patch(live)
        payload["tags"] = new_tags
        try:
            client.patch_group(gid, payload, domain_id=domain_id)
            time.sleep(THROTTLE_SECONDS)
        except NsxApiError as e:
            row["status"] = "failed"
            row["reason"] = f"patch_group: {e}"
            results.append(row)
            log.error("PATCH failed for %s: %s", gid, e)
            continue

        row["status"] = "reverted"
        row["removed"] = sorted(f"{s}|{t}" for s, t in present)
        if absent:
            row["already_absent"] = sorted(f"{s}|{t}" for s, t in absent)
        results.append(row)
        log.info("REVERTED [%s] from group %s", removed_str, gid)

    by_status: Dict[str, int] = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1

    summary = {
        "created_at": utc_now_iso(),
        "domain_id": domain_id,
        "dry_run": dry_run,
        "entries_seen": len(entries),
        "by_status": by_status,
    }
    write_json(out_dir / "revert_results.json", results)
    write_json(out_dir / "revert_summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Revert a sync_group_label_tags.py run using its apply_manifest.json."
    )
    parser.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    parser.add_argument("--manifest", required=True,
                        help="Path to apply_manifest.json written by sync_group_label_tags.py")
    parser.add_argument("--domain-id", default=None,
                        help="Override domain. Default: the manifest's domain_id.")
    parser.add_argument("--federation-global", action="store_true",
                        help="Override. Default: the manifest's federation_global.")
    parser.add_argument("--apply", action="store_true",
                        help="Actually PATCH groups. Without this the tool dry-runs.")
    args = parser.parse_args()

    init_cli()

    manifest_path = Path(args.manifest).expanduser().resolve()
    if not manifest_path.exists():
        raise SystemExit(f"Manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("dry_run"):
        raise SystemExit("This manifest is from a DRY-RUN (nothing was applied); nothing to revert.")

    domain_id = args.domain_id or manifest.get("domain_id") or "default"
    federation_global = args.federation_global or bool(manifest.get("federation_global"))

    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Target manager not defined: {args.target}")

    base = Path(nsx_log_dir).expanduser().resolve()
    out_dir = base / "reports" / "group_label_tags_revert" / target_host / RUN_TS
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = setup_logging(out_dir)
    dry_run = not args.apply

    client = NsxPolicyClient(nsxmanager=target_host, federation_global=federation_global)

    log.info("Group label-tag revert starting")
    log.info("Target: %s (%s)  federation_global=%s  domain=%s",
             args.target, target_host, federation_global, domain_id)
    log.info("Manifest: %s", manifest_path)
    log.info("Mode: %s", "APPLY" if args.apply else "DRY-RUN (default)")

    summary = revert(client, manifest, domain_id, dry_run, out_dir)
    summary.update({
        "target": args.target,
        "target_host": target_host,
        "federation_global": federation_global,
        "manifest": str(manifest_path),
        "out_dir": str(out_dir),
        "log_file": str(log_file),
    })
    write_json(out_dir / "revert_summary.json", summary)

    log.info("Complete: %s", summary["by_status"])
    print(json.dumps(summary, indent=2))

    if summary["by_status"].get("failed"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
