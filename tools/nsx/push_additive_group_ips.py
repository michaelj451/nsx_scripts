#!/usr/bin/env python3
"""
tools/nsx/push_additive_group_ips.py

Push only prepared NSX group payloads that contain additive IP updates.

This is intentionally narrow in scope:
  - Groups only
  - No services
  - No policies
  - No rules
  - No delete operations
  - No full payload push

Expected workflow:

  1) Export with the existing trusted exporter:

     python tools/nsx/export_nsx_objects.py \
       --manager nsx-lm1 \
       --domain-id default \
       --base-dir nsx_export \
       --output-format yaml

  2) Build additive prepared groups offline:

     python tools/nsx/nsx_group_ip_remap_offline.py \
       --export-root nsx_export/nsx-lm1.lab.local/default/groups \
       --prepared-root nsx_build_additive/nsx-lm2.lab.local/domains/default/groups \
       --mapping-csv ip_mapping.csv \
       --bidirectional \
       --output-format yaml

  3) Dry-run this focused group push:

     python tools/nsx/push_additive_group_ips.py \
       --target nsx-lm2 \
       --groups-dir nsx_build_additive/nsx-lm2.lab.local/domains/default/groups \
       --domain-id default \
       --dry-run

  4) Real push:

     python tools/nsx/push_additive_group_ips.py \
       --target nsx-lm2 \
       --groups-dir nsx_build_additive/nsx-lm2.lab.local/domains/default/groups \
       --domain-id default \
       --apply

Safety:
  - Real push requires --apply
  - Without --apply, the script dry-runs
  - Only group files under --groups-dir are processed
  - Uses PATCH by default so the operation is update/additive oriented
  - Writes timestamped logs and JSON/JSONL reports
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.nsx_policy_client import NsxPolicyClient, NsxApiError

try:
    import yaml
except ImportError:
    yaml = None


THROTTLE_SECONDS = 0.2

log = logging.getLogger(__name__)


# =============================================================================
# Logging
# =============================================================================


def _resolve_log_dir() -> Path:
    if not nsx_log_dir:
        raise RuntimeError("nsx_log_dir is empty (NSX_LOG_DIR not loaded?)")

    p = Path(nsx_log_dir).expanduser().resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def setup_logging() -> Path:
    log_dir = _resolve_log_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"push_additive_group_ips_{ts}.log"

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S UTC",
    )

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)

    root.addHandler(ch)
    root.addHandler(fh)

    log.info("Logging to %s", log_file)
    return log_file


# =============================================================================
# File helpers
# =============================================================================


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_file(path: Path) -> Dict[str, Any]:
    if path.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML is required to read YAML files")
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                raise RuntimeError(f"Expected object/dict in {path}")
            return data

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"Expected object/dict in {path}")
    return data


def iter_group_files(groups_dir: Path) -> List[Path]:
    if not groups_dir.exists():
        raise RuntimeError(f"Groups directory does not exist: {groups_dir}")

    files: List[Path] = []
    for ext in ("*.yaml", "*.yml", "*.json"):
        files.extend(groups_dir.rglob(ext))

    return sorted(p for p in files if p.is_file() and p.name != "manifest.json")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def default_reports_dir(groups_dir: Path) -> Path:
    # Expected prepared layout:
    #   nsx_build_additive/<manager>/domains/default/groups
    # Reports will land at:
    #   nsx_build_additive/<manager>/domains/default/reports/group-ip-push
    if groups_dir.name == "groups":
        return groups_dir.parent / "reports" / "group-ip-push"
    return groups_dir / "reports" / "group-ip-push"


# =============================================================================
# Payload helpers
# =============================================================================


def sanitize_for_patch(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Remove common NSX read-only fields before PATCH.

    Offline remap output should already be clean, but this makes the push step
    tolerant of files that still contain exported metadata.
    """
    strip_keys = {
        "_create_time",
        "_create_user",
        "_last_modified_time",
        "_last_modified_user",
        "_system_owned",
        "_protection",
        "_revision",
        "revision",
        "unique_id",
        "realization_id",
        "owner_id",
        "origin_site_id",
        "remote_path",
        "status",
        "children",
        "path",
        "relative_path",
        "parent_path",
        "marked_for_delete",
        "overridden",
    }

    def walk(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items() if k not in strip_keys}
        if isinstance(x, list):
            return [walk(i) for i in x]
        return x

    return walk(obj)


def extract_ip_addition_count(obj: Dict[str, Any]) -> int:
    """Best-effort count of IP values in IPAddressExpression entries.

    This is not a change count; it helps reporting show approximate payload size.
    The actual added values are reported by the offline update script.
    """
    count = 0
    expressions = obj.get("expression", [])
    if not isinstance(expressions, list):
        return 0

    for expr in expressions:
        if not isinstance(expr, dict):
            continue
        if expr.get("resource_type") == "IPAddressExpression" or "ip_addresses" in expr:
            values = expr.get("ip_addresses", [])
            if isinstance(values, list):
                count += len(values)

    return count


# =============================================================================
# NSX client compatibility helpers
# =============================================================================


def patch_group(client: NsxPolicyClient, group_id: str, payload: Dict[str, Any], domain_id: str) -> None:
    """Patch a group using the project NsxPolicyClient.

    Prefer patch_group() if available. Fall back to _patch() if needed.
    """
    if hasattr(client, "patch_group"):
        client.patch_group(group_id, payload, domain_id=domain_id)  # type: ignore[attr-defined]
        return

    if hasattr(client, "_patch"):
        q = getattr(client, "_q", lambda v: v)  # fall back if encoder is missing
        path = f"/infra/domains/{q(domain_id)}/groups/{q(group_id)}"
        client._patch(path, payload)  # type: ignore[attr-defined]
        return

    raise RuntimeError("NsxPolicyClient has neither patch_group nor _patch")


# =============================================================================
# Main push logic
# =============================================================================


def push_groups_only(
    client: NsxPolicyClient,
    groups_dir: Path,
    reports_dir: Path,
    domain_id: str,
    dry_run: bool,
    stop_on_error: bool,
) -> Dict[str, Any]:
    group_files = iter_group_files(groups_dir)
    results: List[Dict[str, Any]] = []

    log.info("Groups dir: %s", groups_dir)
    log.info("Reports dir: %s", reports_dir)
    log.info("Group files found: %s", len(group_files))
    log.info("Dry run: %s", dry_run)

    for f in group_files:
        started_at = utc_now_iso()
        result: Dict[str, Any] = {
            "file": str(f),
            "started_at": started_at,
            "domain_id": domain_id,
            "dry_run": dry_run,
        }

        try:
            raw_obj = load_file(f)
            obj = sanitize_for_patch(raw_obj)
            group_id = obj.get("id")
            display_name = obj.get("display_name")
            ip_value_count = extract_ip_addition_count(obj)

            result.update({
                "group_id": group_id,
                "display_name": display_name,
                "ip_value_count_in_payload": ip_value_count,
            })

            if not group_id:
                result.update({
                    "status": "skipped",
                    "reason": "missing group id",
                    "finished_at": utc_now_iso(),
                })
                log.warning("Skipping group without id: %s", f)
                results.append(result)
                continue

            log.info(
                "%s group: %s (%s)",
                "DRY-RUN would PATCH" if dry_run else "PATCHING",
                group_id,
                display_name or "no display_name",
            )

            if dry_run:
                result.update({
                    "status": "dry_run",
                    "reason": "no changes pushed",
                    "finished_at": utc_now_iso(),
                })
                results.append(result)
                continue

            patch_group(client, group_id, obj, domain_id=domain_id)
            time.sleep(THROTTLE_SECONDS)

            result.update({
                "status": "success",
                "finished_at": utc_now_iso(),
            })
            results.append(result)

        except Exception as e:
            result.update({
                "status": "failed",
                "reason": str(e),
                "finished_at": utc_now_iso(),
            })
            results.append(result)
            log.exception("Failed processing %s", f)

            if stop_on_error:
                break

    success = [r for r in results if r.get("status") == "success"]
    failed = [r for r in results if r.get("status") == "failed"]
    skipped = [r for r in results if r.get("status") == "skipped"]
    dry_run_results = [r for r in results if r.get("status") == "dry_run"]

    summary = {
        "created_at": utc_now_iso(),
        "groups_dir": str(groups_dir),
        "reports_dir": str(reports_dir),
        "domain_id": domain_id,
        "dry_run": dry_run,
        "group_files_found": len(group_files),
        "success": len(success),
        "failed": len(failed),
        "skipped": len(skipped),
        "dry_run_count": len(dry_run_results),
        "throttle_seconds": THROTTLE_SECONDS,
    }

    write_json(reports_dir / "push_additive_group_ips_results.json", results)
    write_jsonl(reports_dir / "push_additive_group_ips_results.jsonl", results)
    write_json(reports_dir / "summary_push_additive_group_ips.json", summary)

    return summary


# =============================================================================
# CLI
# =============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Push only prepared additive NSX group IP payloads"
    )

    parser.add_argument(
        "--target",
        required=True,
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        help="Target manager alias from .env/nsx_constants",
    )
    parser.add_argument(
        "--groups-dir",
        required=True,
        help="Directory containing prepared changed group YAML/JSON files",
    )
    parser.add_argument("--domain-id", default="default")
    parser.add_argument("--federation-global", action="store_true")
    parser.add_argument("--reports-dir", help="Optional reports directory")
    parser.add_argument("--dry-run", action="store_true", help="Dry run only")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Required to actually PATCH groups. Without this, script dry-runs.",
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop after first failed group push. Default continues and reports failures.",
    )

    args = parser.parse_args()

    init_cli()
    log_file = setup_logging()

    groups_dir = Path(args.groups_dir).expanduser().resolve()
    reports_dir = Path(args.reports_dir).expanduser().resolve() if args.reports_dir else default_reports_dir(groups_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    target_host = resolve_manager(args.target)
    if not target_host:
        raise RuntimeError(f"Target manager not defined: {args.target}")

    actual_dry_run = args.dry_run or not args.apply

    client = NsxPolicyClient(
        nsxmanager=target_host,
        federation_global=args.federation_global,
    )

    log.info("Starting additive group IP push")
    log.info("Target alias: %s", args.target)
    log.info("Target host: %s", target_host)
    log.info("Federation global: %s", args.federation_global)
    log.info("Domain ID: %s", args.domain_id)
    log.info("Groups dir: %s", groups_dir)
    log.info("Reports dir: %s", reports_dir)
    log.info("Dry run: %s", actual_dry_run)
    log.info("Log file: %s", log_file)

    summary = push_groups_only(
        client=client,
        groups_dir=groups_dir,
        reports_dir=reports_dir,
        domain_id=args.domain_id,
        dry_run=actual_dry_run,
        stop_on_error=args.stop_on_error,
    )

    summary.update({
        "target": args.target,
        "target_host": target_host,
        "federation_global": args.federation_global,
        "log_file": str(log_file),
    })

    write_json(reports_dir / "summary_push_additive_group_ips.json", summary)

    log.info("Complete: %s", summary)
    print(json.dumps(summary, indent=2))

    if summary.get("failed", 0) > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
