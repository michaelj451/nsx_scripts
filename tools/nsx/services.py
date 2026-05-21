#!/usr/bin/env python3
"""
tools/nsx/services.py

Single tool for the services-only round-trip: export from a source NSX
manager into per-service YAMLs, and push those YAMLs to a target.

Two subcommands:

  export  read /policy/api/v1/infra/services from a source manager and write
          one YAML file per customer-defined service. Read-only.

  push    read per-service YAML files from a directory and PUT/PATCH each
          one to a target manager. Live per-service progress. Dry-run by
          default; --apply to actually write.

Examples:

  # Export from nsx-lm1 (skips system-owned by default):
  python tools/nsx/services.py export --source nsx-lm1

  # Dry-run push to nsx-lm2:
  python tools/nsx/services.py push \\
    --target nsx-lm2 \\
    --services-dir nsx_services_export/nsx-lm1.lab.local/services

  # Apply push to nsx-lm2:
  python tools/nsx/services.py push \\
    --target nsx-lm2 \\
    --services-dir nsx_services_export/nsx-lm1.lab.local/services \\
    --apply
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import shutil
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.nsx_policy_client import NsxPolicyClient, NsxApiError


log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
THROTTLE_SECONDS = 0.2

# Char-class allowed in NSX object ids without any encoding concerns.
# Anything else (parens, spaces, commas, ampersands, etc.) gets flagged.
_SAFE_ID_RE = re.compile(r'^[A-Za-z0-9._\-]+$')


def _has_special_chars(value: str) -> bool:
    return not bool(_SAFE_ID_RE.match(str(value or "")))

# Same field set the main exporter strips. Keeps payloads diff-stable and
# avoids conflicting with the target's view of revisions, ownership, etc.
STRIP_KEYS = {
    "_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
    "_revision", "revision", "_protection", "_system_owned",
    "marked_for_delete", "overridden", "remote_path",
    "realization_id", "unique_id", "origin_site_id", "owner_id",
    "_links", "_schema", "_self", "status", "children",
}

EXCLUDED_FILENAMES = {"manifest.json", "summary.json", "summary.txt"}

NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]


# =============================================================================
# Shared helpers
# =============================================================================

def _setup_logging(reports_dir: Path, label: str) -> tuple[Path, Path]:
    """
    UTC, multi-write:
      - Console (INFO+)
      - bundle log file (INFO+, complete record)
      - global log file (INFO+, complete record)
      - bundle errors log file (ERROR+, only the failure detail — easier to scan)

    Returns: (bundle_log, errors_log)
    """
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    bundle_log = (reports_dir / f"services_{label}_{RUN_TS}.log").resolve()
    global_log = (global_log_dir / f"services_{label}_{RUN_TS}.log").resolve()
    errors_log = (reports_dir / f"services_{label}_{RUN_TS}.errors.log").resolve()

    logging.Formatter.converter = time.gmtime
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%S")

    # INFO+ handlers
    for h in (logging.StreamHandler(),
              logging.FileHandler(bundle_log, encoding="utf-8"),
              logging.FileHandler(global_log, encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)

    # ERROR+ handler — just the failures, with full tracebacks
    eh = logging.FileHandler(errors_log, encoding="utf-8")
    eh.setLevel(logging.ERROR)
    eh.setFormatter(fmt)
    root.addHandler(eh)

    return bundle_log, errors_log


def _is_system_object(obj: Dict[str, Any]) -> bool:
    return (
        obj.get("_system_owned") is True
        or obj.get("system_owned") is True
        or obj.get("marked_for_delete") is True
    )


def _sanitize(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively drop NSX-managed read-only fields."""
    def walk(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items() if k not in STRIP_KEYS}
        if isinstance(x, list):
            return [walk(i) for i in x]
        return x
    return walk(obj)


def _slugify(name: str, max_len: int = 50) -> str:
    """Filename-safe slug capped at max_len to keep Windows MAX_PATH happy."""
    s = re.sub(r"[^\w\-\.]+", "_", (name or "").strip())
    s = re.sub(r"_+", "_", s).strip("_") or "unnamed"
    if len(s) <= max_len:
        return s
    h = hashlib.md5(s.encode("utf-8")).hexdigest()[:7]
    keep = max(1, max_len - len(h) - 1)
    return f"{s[:keep]}_{h}"


def _load_file(p: Path) -> Dict[str, Any]:
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        return yaml.safe_load(text) or {}
    return json.loads(text)


def _iter_service_files(services_dir: Path) -> List[Path]:
    if not services_dir.exists():
        return []
    files: List[Path] = []
    for ext in ("*.yaml", "*.yml", "*.json"):
        for p in services_dir.rglob(ext):
            if p.name in EXCLUDED_FILENAMES:
                continue
            files.append(p)
    return sorted(files)


def _is_already_exists_error(e: Exception) -> bool:
    """500127 / 500071 / 'already exists' / 'precondition_failed' / 'different version'."""
    msg = str(e)
    lower = msg.lower()
    return (
        "already exists" in lower
        or "500127" in msg
        or "cannot create an object" in lower
        or "500071" in msg
        or "precondition_failed" in lower
        or "different version" in lower
    )


# =============================================================================
# export
# =============================================================================

def cmd_export(args: argparse.Namespace) -> int:
    source_host = resolve_manager(args.source)
    if not source_host:
        raise SystemExit(f"Manager not defined for {args.source}.")

    using_default = args.output_dir is None
    output_dir = Path(args.output_dir or (REPO_ROOT / "nsx_services_export" / source_host)).expanduser().resolve()
    if using_default and output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    services_dir = output_dir / "services"
    services_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = output_dir / "logs"
    log_file, errors_log = _setup_logging(logs_dir, "export")

    log.info("=" * 60)
    log.info("NSX SERVICES — EXPORT")
    log.info("  Source manager  : %s (%s)", args.source, source_host)
    log.info("  Federation GM   : %s", args.federation_global)
    log.info("  Include system  : %s", args.include_system)
    log.info("  Output bundle   : %s", output_dir)
    log.info("=" * 60)

    client = NsxPolicyClient(nsxmanager=source_host, federation_global=args.federation_global)

    log.info("Fetching services from %s ...", source_host)
    base_path = client._policy_path("/services")
    all_services: List[Dict[str, Any]] = []
    for page in client._get_pages(base_path):
        all_services.extend(page.get("results", []) or [])
    log.info("Fetched %d service(s) from source.", len(all_services))

    rows: List[Dict[str, Any]] = []
    written = 0
    skipped_system = 0
    skipped_no_id = 0
    errors = 0
    special_char_ids: List[Dict[str, str]] = []  # ids containing chars outside [A-Za-z0-9._-]

    for i, svc in enumerate(all_services, start=1):
        sid = svc.get("id")
        sname = svc.get("display_name") or sid or "service"

        if not args.include_system and _is_system_object(svc):
            skipped_system += 1
            continue

        if not sid:
            skipped_no_id += 1
            log.warning("[%d/%d] skip service with no id: display_name=%s", i, len(all_services), sname)
            continue

        if _has_special_chars(sid):
            special_char_ids.append({"id": sid, "display_name": sname})
            log.warning("[%d/%d] special chars in id: %r (URL-encoded on push)", i, len(all_services), sid)

        suffix = sid[:8]
        fname = f"{_slugify(sname, max_len=40)}__{suffix}.yaml"
        path = services_dir / fname

        try:
            payload = _sanitize(svc)
            path.write_text(
                yaml.safe_dump(payload, sort_keys=False, default_flow_style=False),
                encoding="utf-8",
            )
            written += 1
            log.info("[%d/%d  ok=%d sys-skip=%d err=%d] %s",
                     i, len(all_services), written, skipped_system, errors, sid)
            rows.append({"id": sid, "display_name": sname, "file": fname, "status": "ok"})
        except Exception as exc:
            errors += 1
            tb = traceback.format_exc()
            log.exception("[%d/%d] FAILED writing %s", i, len(all_services), sid)
            rows.append({
                "id": sid, "display_name": sname, "file": fname,
                "status": "failed",
                "error": str(exc),
                "error_type": type(exc).__name__,
                "traceback": tb,
            })

    manifest = {
        "command": "services.export",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source": {"alias": args.source, "host": source_host, "federation_global": args.federation_global},
        "counts": {
            "total_returned": len(all_services),
            "written": written,
            "skipped_system_owned": skipped_system,
            "skipped_no_id": skipped_no_id,
            "errors": errors,
            "ids_with_special_chars": len(special_char_ids),
        },
        "services": rows,
        "ids_with_special_chars": special_char_ids,
        "paths": {
            "bundle_dir": str(output_dir),
            "services_dir": str(services_dir),
            "logs_dir": str(logs_dir),
        },
        "log_file": str(log_file),
        "errors_log": str(errors_log),
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    log.info("=" * 60)
    log.info("Export complete: written=%d  sys-skipped=%d  no-id-skipped=%d  errors=%d",
             written, skipped_system, skipped_no_id, errors)
    log.info("Bundle:   %s", output_dir)
    log.info("Manifest: %s", manifest_path)
    log.info("=" * 60)

    print(json.dumps({
        "bundle": str(output_dir),
        "manifest": str(manifest_path),
        "counts": manifest["counts"],
    }, indent=2))

    return 0 if errors == 0 else 1


# =============================================================================
# push
# =============================================================================

def cmd_push(args: argparse.Namespace) -> int:
    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Target manager not defined: {args.target}")

    services_dir = Path(args.services_dir).expanduser().resolve()
    if not services_dir.exists():
        raise SystemExit(f"Services dir does not exist: {services_dir}")

    reports_dir = Path(args.reports_dir or (services_dir.parent / "push_report")).expanduser().resolve()
    log_file, errors_log = _setup_logging(reports_dir, "push")

    mode = "APPLY" if args.apply else "DRY-RUN"
    log.info("=" * 60)
    log.info("NSX SERVICES — PUSH (%s)", mode)
    log.info("  Target          : %s (%s)", args.target, target_host)
    log.info("  Federation GM   : %s", args.federation_global)
    log.info("  Services dir    : %s", services_dir)
    log.info("  Reports dir     : %s", reports_dir)
    log.info("=" * 60)

    files = _iter_service_files(services_dir)
    log.info("Found %d service file(s).", len(files))

    if not args.apply:
        log.info("Dry-run mode: will iterate every file, sanitize, and confirm id — no NSX calls.")
        client = None
    else:
        client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global)

    rows: List[Dict[str, Any]] = []
    ok = 0
    failed = 0
    skipped = 0
    dry_run_count = 0

    for i, f in enumerate(files, start=1):
        row = {
            "index": i,
            "file": str(f),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            obj = _sanitize(_load_file(f))
            sid = obj.get("id")
            row["id"] = sid
            row["display_name"] = obj.get("display_name")

            if not sid:
                row["status"] = "skipped"
                row["reason"] = "missing id"
                skipped += 1
                log.warning("[%d/%d skip] %s — no id in payload", i, len(files), f.name)
                rows.append(row)
                continue

            if not args.apply:
                row["status"] = "dry_run"
                dry_run_count += 1
                log.info("[%d/%d  DRY  ok=%d fail=%d skip=%d] %s",
                         i, len(files), ok, failed, skipped, sid)
                rows.append(row)
                continue

            try:
                client.put_service(sid, obj)
                row["status"] = "success_put"
            except NsxApiError as e:
                if _is_already_exists_error(e):
                    client.patch_service(sid, obj)
                    row["status"] = "success_patch"
                else:
                    raise

            ok += 1
            log.info("[%d/%d  ok=%d fail=%d skip=%d] %s — %s",
                     i, len(files), ok, failed, skipped, sid, row["status"])
            time.sleep(THROTTLE_SECONDS)

        except Exception as e:
            failed += 1
            tb = traceback.format_exc()
            row["status"] = "failed"
            row["error"] = str(e)
            row["error_type"] = type(e).__name__
            row["traceback"] = tb
            log.error(
                "[%d/%d  ok=%d fail=%d skip=%d] %s — FAILED: %s\n%s",
                i, len(files), ok, failed, skipped,
                row.get("id") or f.name, e, tb,
            )

        rows.append(row)

    summary = {
        "command": "services.push",
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "target": {"alias": args.target, "host": target_host, "federation_global": args.federation_global},
        "services_dir": str(services_dir),
        "mode": mode,
        "totals": {
            "files_seen": len(files),
            "ok": ok,
            "failed": failed,
            "skipped": skipped,
            "dry_run": dry_run_count,
        },
        "log_file": str(log_file),
        "errors_log": str(errors_log),
    }

    (reports_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (reports_dir / "services.json").write_text(json.dumps(rows, indent=2, sort_keys=True), encoding="utf-8")
    with (reports_dir / "services.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    if failed:
        failures = [r for r in rows if r.get("status") == "failed"]
        (reports_dir / "failures.json").write_text(json.dumps(failures, indent=2, sort_keys=True), encoding="utf-8")

    log.info("=" * 60)
    log.info("Push services %s — ok=%d failed=%d skipped=%d (dry_run=%d) total=%d",
             mode, ok, failed, skipped, dry_run_count, len(files))
    log.info("Reports: %s", reports_dir)
    log.info("=" * 60)

    print(json.dumps(summary, indent=2))
    return 0 if failed == 0 else 1


# =============================================================================
# CLI dispatch
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(
        description="Export NSX services from a source / push them to a target. Two subcommands.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # --- export subcommand ---
    pe = sub.add_parser(
        "export",
        help="Export services from a source manager into per-file YAMLs (read-only).",
    )
    pe.add_argument("--source", required=True, choices=NSX_MANAGER_CHOICES,
                    help="NSX manager to export FROM (read-only).")
    pe.add_argument("--federation-global", action="store_true",
                    help="Treat --source as a Global Manager.")
    pe.add_argument("--output-dir", default=None,
                    help="Output bundle directory. Defaults to nsx_services_export/<source-host>/. "
                         "Default path is wiped on each run so it always reflects the latest export.")
    pe.add_argument("--include-system", action="store_true",
                    help="Also export system-owned services (default: skip).")
    pe.set_defaults(func=cmd_export)

    # --- push subcommand ---
    pp = sub.add_parser(
        "push",
        help="Push per-file service YAMLs to a target. Dry-run by default; --apply to write.",
    )
    pp.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES,
                    help="NSX manager to push TO.")
    pp.add_argument("--services-dir", required=True,
                    help="Directory containing per-service YAML/JSON files.")
    pp.add_argument("--federation-global", action="store_true",
                    help="Target is a Global Manager.")
    pp.add_argument("--apply", action="store_true", default=False,
                    help="Actually push. Without this, runs as dry-run.")
    pp.add_argument("--reports-dir", default=None,
                    help="Where to write the run's per-service report + log. "
                         "Defaults to <services-dir>/../push_report/.")
    pp.set_defaults(func=cmd_push)

    args = p.parse_args()
    init_cli()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
