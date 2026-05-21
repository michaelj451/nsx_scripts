#!/usr/bin/env python3
"""
tools/nsx/groups.py

Single tool for the groups-only round-trip. Same shape as services.py.

Two subcommands:

  export  read /policy/api/v1/infra/domains/<domain>/groups from a source
          manager and write one YAML file per customer-defined group.
          Read-only.

  push    read per-group YAML files from a directory and PUT/PATCH each
          one to a target manager. Live per-group progress. Dry-run by
          default; --apply to actually write.

The push has an optional --strip-segments flag for the two-phase workflow:

    Phase 1 (structure):  push --target ... --strip-segments
                           Pushes every group with /infra/segments/* refs
                           removed from PathExpression entries. Empty
                           PathExpressions and orphan ConjunctionOperators
                           are cleaned up so NSX accepts the payload.

    Phase 2 (segments):   push --target ...
                           Same files, no flag. Full payloads ship,
                           overwriting phase 1's stripped expressions
                           with the originals (segments back in place).

Other expression types (Condition, IPAddressExpression, MACAddressExpression,
NestedExpression, etc.) are preserved verbatim in both phases.

Examples:

  python tools/nsx/groups.py export --source nsx-lm1

  # Phase 1: structure only, segments stripped
  python tools/nsx/groups.py push \\
    --target nsx-lm2 \\
    --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups \\
    --strip-segments \\
    --apply

  # Phase 2: full payload, restores segment refs
  python tools/nsx/groups.py push \\
    --target nsx-lm2 \\
    --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups \\
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
from typing import Any, Dict, List, Tuple

import yaml

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.nsx_policy_client import NsxPolicyClient, NsxApiError

# Allow importing sibling tools (CSV remap logic lives in nsx_group_ip_remap_offline.py)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from nsx_group_ip_remap_offline import (  # noqa: E402
    _load_mapping_csv as _load_csv_mapping,
    _remap_group_payload as _csv_remap_group,
)


log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
THROTTLE_SECONDS = 0.2

STRIP_KEYS = {
    "_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
    "_revision", "revision", "_protection", "_system_owned",
    "marked_for_delete", "overridden", "remote_path",
    "realization_id", "unique_id", "origin_site_id", "owner_id",
    "_links", "_schema", "_self", "status", "children",
}

EXCLUDED_FILENAMES = {"manifest.json", "summary.json", "summary.txt"}
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]

# Matches /infra/segments/<id> and /global-infra/segments/<id>, plus any
# /ports/... sub-resource path under those.
SEGMENT_PATH_RE = re.compile(r"^/(?:global-)?infra/segments/[^/\s]+(?:/.*)?$")

# Char-class allowed in NSX object ids without any encoding concerns.
# Anything else (parens, spaces, commas, ampersands, etc.) gets flagged.
_SAFE_ID_RE = re.compile(r'^[A-Za-z0-9._\-]+$')


def _has_special_chars(value: str) -> bool:
    return not bool(_SAFE_ID_RE.match(str(value or "")))


# =============================================================================
# Shared helpers
# =============================================================================

def _setup_logging(reports_dir: Path, label: str) -> tuple[Path, Path]:
    """Returns (bundle_log, errors_log). Errors log only captures ERROR+ lines."""
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    bundle_log = (reports_dir / f"groups_{label}_{RUN_TS}.log").resolve()
    global_log = (global_log_dir / f"groups_{label}_{RUN_TS}.log").resolve()
    errors_log = (reports_dir / f"groups_{label}_{RUN_TS}.errors.log").resolve()

    logging.Formatter.converter = time.gmtime
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%S")
    for h in (logging.StreamHandler(),
              logging.FileHandler(bundle_log, encoding="utf-8"),
              logging.FileHandler(global_log, encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
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
    def walk(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items() if k not in STRIP_KEYS}
        if isinstance(x, list):
            return [walk(i) for i in x]
        return x
    return walk(obj)


def _slugify(name: str, max_len: int = 40) -> str:
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


def _iter_group_files(groups_dir: Path) -> List[Path]:
    if not groups_dir.exists():
        return []
    files: List[Path] = []
    for ext in ("*.yaml", "*.yml", "*.json"):
        for p in groups_dir.rglob(ext):
            if p.name in EXCLUDED_FILENAMES:
                continue
            files.append(p)
    return sorted(files)


def _is_already_exists_error(e: Exception) -> bool:
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
# Segment stripping
# =============================================================================

def _load_segment_cidr_map(path: Path) -> Dict[str, List[str]]:
    """
    Read a segment_details.json (the flat list written by
    find_segments_referenced.py / capture_nsx_state.py) and return a
    map: segment_path -> [cidr, cidr, ...] sourced from each segment's
    subnets[].network.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    out: Dict[str, List[str]] = {}
    for seg in data if isinstance(data, list) else []:
        if not isinstance(seg, dict):
            continue
        subnets = seg.get("subnets") or []
        cidrs: List[str] = []
        for sn in subnets:
            if isinstance(sn, dict):
                net = sn.get("network")
                if isinstance(net, str) and net.strip():
                    cidrs.append(net.strip())
        sp = seg.get("path") or seg.get("relative_path")
        if isinstance(sp, str):
            out[sp] = cidrs
        sid = seg.get("id")
        if isinstance(sid, str):
            # Cover both LM and GM path shapes
            out.setdefault(f"/infra/segments/{sid}", cidrs)
            out.setdefault(f"/global-infra/segments/{sid}", cidrs)
    return out


def _transform_segments_in_expression(
    expression: List[Any],
    *,
    mode: str,                                   # "strip" or "convert"
    segments_by_path: Dict[str, List[str]] = None,
) -> Tuple[List[Any], int, int, int]:
    """
    Walk a group's expression list and either strip segment refs or replace
    them with IPAddressExpression CIDR entries. Returns:
      (new_expression, segment_paths_seen, segments_converted, unresolved_count)
    """
    if not isinstance(expression, list):
        return expression, 0, 0, 0

    segments_by_path = segments_by_path or {}
    convert_mode = (mode == "convert")

    paths_seen = 0
    converted = 0
    unresolved = 0
    indices_to_drop: set = set()
    inserts: Dict[int, Dict[str, Any]] = {}
    new_items: List[Any] = []

    for i, item in enumerate(expression):
        if not (isinstance(item, dict) and item.get("resource_type") == "PathExpression"):
            new_items.append(item)
            continue

        paths = item.get("paths") or []
        kept_paths: List[str] = []
        resolved_cidrs: List[str] = []
        seen_cidr: set = set()

        for p in paths:
            if isinstance(p, str) and SEGMENT_PATH_RE.match(p.strip()):
                paths_seen += 1
                if convert_mode:
                    sp = p.strip()
                    cidrs = segments_by_path.get(sp)
                    if cidrs:
                        for c in cidrs:
                            if c not in seen_cidr:
                                seen_cidr.add(c)
                                resolved_cidrs.append(c)
                        converted += 1
                    else:
                        unresolved += 1
                # In strip mode and unresolved-convert mode, the path is just dropped.
            else:
                kept_paths.append(p)

        if not kept_paths and not resolved_cidrs:
            indices_to_drop.add(i)
            new_items.append(None)
        elif not kept_paths and resolved_cidrs:
            # Replace this PathExpression with an IPAddressExpression
            new_items.append({
                "resource_type": "IPAddressExpression",
                "ip_addresses": resolved_cidrs,
            })
        else:
            cloned = dict(item)
            cloned["paths"] = kept_paths
            new_items.append(cloned)
            if resolved_cidrs:
                # Splice an IPAddressExpression in after this kept-paths node,
                # joined by an OR conjunction.
                inserts[i] = {
                    "resource_type": "IPAddressExpression",
                    "ip_addresses": resolved_cidrs,
                }

    # Pair-remove ConjunctionOperators next to dropped operands.
    operators_to_drop: set = set()
    for i in sorted(indices_to_drop):
        if i > 0 and isinstance(new_items[i - 1], dict) \
                and new_items[i - 1].get("resource_type") == "ConjunctionOperator" \
                and (i - 1) not in indices_to_drop:
            operators_to_drop.add(i - 1)
        elif i + 1 < len(new_items) and isinstance(new_items[i + 1], dict) \
                and new_items[i + 1].get("resource_type") == "ConjunctionOperator" \
                and (i + 1) not in indices_to_drop:
            operators_to_drop.add(i + 1)

    all_drop = indices_to_drop | operators_to_drop

    # Emit kept items, splicing in any IPAddressExpression inserts.
    result: List[Any] = []
    for idx, item in enumerate(new_items):
        if idx in all_drop:
            continue
        result.append(item)
        if idx in inserts:
            result.append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})
            result.append(inserts[idx])

    # Trim leading/trailing operators
    while result and isinstance(result[0], dict) and result[0].get("resource_type") == "ConjunctionOperator":
        result.pop(0)
    while result and isinstance(result[-1], dict) and result[-1].get("resource_type") == "ConjunctionOperator":
        result.pop()

    return result, paths_seen, converted, unresolved


# =============================================================================
# export
# =============================================================================

def cmd_export(args: argparse.Namespace) -> int:
    source_host = resolve_manager(args.source)
    if not source_host:
        raise SystemExit(f"Manager not defined for {args.source}.")

    using_default = args.output_dir is None
    output_dir = Path(args.output_dir or (REPO_ROOT / "nsx_groups_export" / source_host)).expanduser().resolve()
    if using_default and output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    groups_dir = output_dir / "groups"
    groups_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = output_dir / "logs"
    log_file, errors_log = _setup_logging(logs_dir, "export")

    log.info("=" * 60)
    log.info("NSX GROUPS — EXPORT")
    log.info("  Source manager  : %s (%s)", args.source, source_host)
    log.info("  Domain          : %s", args.domain_id)
    log.info("  Federation GM   : %s", args.federation_global)
    log.info("  Include system  : %s", args.include_system)
    log.info("  Output bundle   : %s", output_dir)
    log.info("=" * 60)

    client = NsxPolicyClient(nsxmanager=source_host, federation_global=args.federation_global)

    base_path = client._policy_path(f"/domains/{client._q(args.domain_id)}/groups")
    log.info("Fetching groups from %s ...", source_host)
    all_groups: List[Dict[str, Any]] = []
    for page in client._get_pages(base_path):
        all_groups.extend(page.get("results", []) or [])
    log.info("Fetched %d group(s).", len(all_groups))

    rows: List[Dict[str, Any]] = []
    written = 0
    skipped_system = 0
    skipped_no_id = 0
    errors = 0
    special_char_ids: List[Dict[str, str]] = []

    for i, g in enumerate(all_groups, start=1):
        gid = g.get("id")
        gname = g.get("display_name") or gid or "group"

        if not args.include_system and _is_system_object(g):
            skipped_system += 1
            continue

        if not gid:
            skipped_no_id += 1
            log.warning("[%d/%d] skip group with no id: display_name=%s", i, len(all_groups), gname)
            continue

        if _has_special_chars(gid):
            special_char_ids.append({"id": gid, "display_name": gname})
            log.warning("[%d/%d] special chars in id: %r (URL-encoded on push)", i, len(all_groups), gid)

        suffix = gid[:8]
        fname = f"{_slugify(gname)}__{suffix}.yaml"
        path = groups_dir / fname

        try:
            payload = _sanitize(g)
            path.write_text(
                yaml.safe_dump(payload, sort_keys=False, default_flow_style=False),
                encoding="utf-8",
            )
            written += 1
            log.info("[%d/%d  ok=%d sys-skip=%d err=%d] %s",
                     i, len(all_groups), written, skipped_system, errors, gid)
            rows.append({"id": gid, "display_name": gname, "file": fname, "status": "ok"})
        except Exception as exc:
            errors += 1
            tb = traceback.format_exc()
            log.exception("[%d/%d] FAILED writing %s", i, len(all_groups), gid)
            rows.append({
                "id": gid, "display_name": gname, "file": fname,
                "status": "failed", "error": str(exc),
                "error_type": type(exc).__name__,
                "traceback": tb,
            })

    manifest = {
        "command": "groups.export",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source": {"alias": args.source, "host": source_host,
                   "federation_global": args.federation_global, "domain_id": args.domain_id},
        "counts": {
            "total_returned": len(all_groups),
            "written": written,
            "skipped_system_owned": skipped_system,
            "skipped_no_id": skipped_no_id,
            "errors": errors,
            "ids_with_special_chars": len(special_char_ids),
        },
        "groups": rows,
        "ids_with_special_chars": special_char_ids,
        "paths": {
            "bundle_dir": str(output_dir),
            "groups_dir": str(groups_dir),
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

    print(json.dumps({"bundle": str(output_dir), "manifest": str(manifest_path),
                      "counts": manifest["counts"]}, indent=2))
    return 0 if errors == 0 else 1


# =============================================================================
# push
# =============================================================================

def cmd_push(args: argparse.Namespace) -> int:
    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Target manager not defined: {args.target}")

    groups_dir = Path(args.groups_dir).expanduser().resolve()
    if not groups_dir.exists():
        raise SystemExit(f"Groups dir does not exist: {groups_dir}")

    reports_dir = Path(args.reports_dir or (groups_dir.parent / "push_report")).expanduser().resolve()
    log_file, errors_log = _setup_logging(reports_dir, "push")

    # Validate segments-mode args
    segments_by_path: Dict[str, List[str]] = {}
    if args.segments_mode == "convert":
        if not args.segments_from:
            raise SystemExit("--segments-mode convert requires --segments-from <segment_details.json>")
        seg_path = Path(args.segments_from).expanduser().resolve()
        if not seg_path.exists():
            raise SystemExit(f"--segments-from file not found: {seg_path}")
        segments_by_path = _load_segment_cidr_map(seg_path)

    # Validate / load CSV remap if requested
    csv_mapping = None
    csv_invalid_rows: List[Dict[str, Any]] = []
    if args.csv_remap:
        csv_path = Path(args.csv_remap).expanduser().resolve()
        if not csv_path.exists():
            raise SystemExit(f"--csv-remap file not found: {csv_path}")
        csv_mapping, csv_invalid_rows = _load_csv_mapping(csv_path, args.bidirectional)
        log.info("Loaded CSV mapping: %d rule(s), %d invalid row(s)",
                 len(csv_mapping.rows), len(csv_invalid_rows))

    mode = "APPLY" if args.apply else "DRY-RUN"
    log.info("=" * 60)
    log.info("NSX GROUPS — PUSH (%s)", mode)
    log.info("  Target          : %s (%s)", args.target, target_host)
    log.info("  Domain          : %s", args.domain_id)
    log.info("  Federation GM   : %s", args.federation_global)
    log.info("  Segments mode   : %s", args.segments_mode)
    if args.segments_mode == "convert":
        log.info("  Segments from   : %s  (%d segments mapped)",
                 args.segments_from, len(segments_by_path))
    if csv_mapping is not None:
        log.info("  CSV remap       : %s  (mapped-only=%s, bidirectional=%s)",
                 args.csv_remap, args.mapped_only, args.bidirectional)
    log.info("  Groups dir      : %s", groups_dir)
    log.info("  Reports dir     : %s", reports_dir)
    log.info("=" * 60)

    files = _iter_group_files(groups_dir)
    log.info("Found %d group file(s).", len(files))

    client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global) if args.apply else None

    rows: List[Dict[str, Any]] = []
    ok = 0
    failed = 0
    skipped = 0
    dry_run_count = 0
    total_paths_seen = 0
    total_converted = 0
    total_unresolved = 0
    total_csv_changed = 0
    total_csv_added = 0

    for i, f in enumerate(files, start=1):
        row = {
            "index": i,
            "file": str(f),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            obj = _sanitize(_load_file(f))
            gid = obj.get("id")
            row["id"] = gid
            row["display_name"] = obj.get("display_name")

            if not gid:
                row["status"] = "skipped"
                row["reason"] = "missing id"
                skipped += 1
                log.warning("[%d/%d skip] %s — no id in payload", i, len(files), f.name)
                rows.append(row)
                continue

            # --- CSV remap (Workflow B) — runs BEFORE segment handling ---
            csv_changed = False
            csv_added_count = 0
            if csv_mapping is not None:
                updated, csv_report = _csv_remap_group(
                    group=obj,
                    mapping=csv_mapping,
                    mapped_only=args.mapped_only,
                )
                if csv_report.get("status") == "changed":
                    obj = updated
                    csv_changed = True
                    csv_added_count = csv_report.get("added_count", 0)
                    total_csv_changed += 1
                    total_csv_added += csv_added_count
                row["csv_changed"] = csv_changed
                row["csv_added_count"] = csv_added_count

            paths_seen = 0
            converted_here = 0
            unresolved_here = 0
            if args.segments_mode in ("strip", "convert") and isinstance(obj.get("expression"), list):
                new_expr, paths_seen, converted_here, unresolved_here = _transform_segments_in_expression(
                    obj["expression"],
                    mode=args.segments_mode,
                    segments_by_path=segments_by_path,
                )
                obj["expression"] = new_expr
                total_paths_seen += paths_seen
                total_converted += converted_here
                total_unresolved += unresolved_here
                row["segments_seen"] = paths_seen
                row["segments_converted"] = converted_here
                row["segments_unresolved"] = unresolved_here

            if not args.apply:
                row["status"] = "dry_run"
                dry_run_count += 1
                seg_note = ""
                if paths_seen:
                    seg_note = (f" (segments_seen={paths_seen} converted={converted_here}"
                                f" unresolved={unresolved_here})")
                log.info("[%d/%d  DRY  ok=%d fail=%d skip=%d] %s%s",
                         i, len(files), ok, failed, skipped, gid, seg_note)
                rows.append(row)
                continue

            try:
                client.put_group(gid, obj, domain_id=args.domain_id)
                row["status"] = "success_put"
            except NsxApiError as e:
                if _is_already_exists_error(e):
                    client.patch_group(gid, obj, domain_id=args.domain_id)
                    row["status"] = "success_patch"
                else:
                    raise

            ok += 1
            seg_note = ""
            if paths_seen:
                seg_note = (f"  segments_seen={paths_seen} converted={converted_here}"
                            f" unresolved={unresolved_here}")
            log.info("[%d/%d  ok=%d fail=%d skip=%d] %s — %s%s",
                     i, len(files), ok, failed, skipped, gid, row["status"], seg_note)
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
        "command": "groups.push",
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "target": {"alias": args.target, "host": target_host,
                   "federation_global": args.federation_global, "domain_id": args.domain_id},
        "groups_dir": str(groups_dir),
        "mode": mode,
        "segments_mode": args.segments_mode,
        "segments_from": str(args.segments_from) if args.segments_from else None,
        "csv_remap": str(args.csv_remap) if args.csv_remap else None,
        "mapped_only": args.mapped_only if args.csv_remap else None,
        "bidirectional": args.bidirectional if args.csv_remap else None,
        "csv_invalid_rows": csv_invalid_rows if args.csv_remap else None,
        "totals": {
            "files_seen": len(files),
            "ok": ok,
            "failed": failed,
            "skipped": skipped,
            "dry_run": dry_run_count,
            "segment_paths_seen": total_paths_seen,
            "segments_converted": total_converted,
            "segments_unresolved": total_unresolved,
            "csv_groups_changed": total_csv_changed,
            "csv_total_added_values": total_csv_added,
        },
        "log_file": str(log_file),
        "errors_log": str(errors_log),
    }

    (reports_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (reports_dir / "groups.json").write_text(json.dumps(rows, indent=2, sort_keys=True), encoding="utf-8")
    with (reports_dir / "groups.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    if failed:
        failures = [r for r in rows if r.get("status") == "failed"]
        (reports_dir / "failures.json").write_text(json.dumps(failures, indent=2, sort_keys=True), encoding="utf-8")

    log.info("=" * 60)
    log.info("Push groups %s — ok=%d failed=%d skipped=%d (dry_run=%d) total=%d "
             "[segments_mode=%s paths_seen=%d converted=%d unresolved=%d]",
             mode, ok, failed, skipped, dry_run_count, len(files),
             args.segments_mode, total_paths_seen, total_converted, total_unresolved)
    log.info("Reports: %s", reports_dir)
    log.info("=" * 60)

    print(json.dumps(summary, indent=2))
    return 0 if failed == 0 else 1


# =============================================================================
# CLI dispatch
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(
        description="Export NSX groups from a source / push them to a target. Two subcommands.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pe = sub.add_parser("export", help="Export groups from a source manager into per-file YAMLs (read-only).")
    pe.add_argument("--source", required=True, choices=NSX_MANAGER_CHOICES)
    pe.add_argument("--domain-id", default="default")
    pe.add_argument("--federation-global", action="store_true")
    pe.add_argument("--output-dir", default=None,
                    help="Defaults to nsx_groups_export/<source-host>/. Wiped on each run.")
    pe.add_argument("--include-system", action="store_true",
                    help="Also export system-owned groups (default: skip).")
    pe.set_defaults(func=cmd_export)

    pp = sub.add_parser("push", help="Push per-file group YAMLs to a target. Dry-run by default.")
    pp.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    pp.add_argument("--groups-dir", required=True)
    pp.add_argument("--domain-id", default="default")
    pp.add_argument("--federation-global", action="store_true")
    pp.add_argument("--apply", action="store_true", default=False,
                    help="Actually push. Without this, runs as dry-run.")
    pp.add_argument("--segments-mode", choices=["keep", "strip", "convert"], default="keep",
                    help="How to handle /infra/segments/* refs in groups: "
                         "keep (default) = push as-is; "
                         "strip = remove segment paths from PathExpression entries (phase 1); "
                         "convert = replace segment refs with IPAddressExpression CIDRs read from "
                         "--segments-from (phase 2). Other expression types are always preserved.")
    pp.add_argument("--segments-from", default=None,
                    help="Path to segment_details.json (e.g. nsx_capture/<host>/segment_inventory/"
                         "segment_details.json). Required when --segments-mode=convert.")
    pp.add_argument("--csv-remap", default=None,
                    help="Path to a CSV mapping file (old_subnet,new_subnet rows). "
                         "When set, applies offline IP remap to each group's IPAddressExpression "
                         "values before pushing. Used for Workflow B (in-place subnet remap).")
    pp.add_argument("--mapped-only", action="store_true",
                    help="With --csv-remap: replace each IPAddressExpression with only the mapped "
                         "values, dropping unmapped originals. Default: append mapped values.")
    pp.add_argument("--bidirectional", action="store_true",
                    help="With --csv-remap: treat each CSV row as a bidirectional mapping.")
    pp.add_argument("--reports-dir", default=None,
                    help="Defaults to <groups-dir>/../push_report/.")
    pp.set_defaults(func=cmd_push)

    args = p.parse_args()
    init_cli()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
