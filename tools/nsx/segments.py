#!/usr/bin/env python3
"""
tools/nsx/segments.py

Single tool for the segments round-trip. Same shape as
services.py / groups.py / policies.py / rules.py.

Two subcommands:

  export  read /policy/api/v1/infra/segments from a source manager and
          write one YAML file per segment. ALSO produce reverse-reference
          tables so you can answer: "which groups reference this segment?"
          and "which segments does this group reference?"  Read-only.

  push    read per-segment YAML files from a directory and PUT/PATCH each
          to a target manager. Live per-segment progress. Dry-run by
          default; --apply to actually write.

⚠ Cross-manager push caveat: NSX segments reference a transport zone
   (`transport_zone_path`) and usually a T0/T1 (`connectivity_path`). These
   are manager-specific UUIDs — pushing a segment from lm1 to lm2 will fail
   unless the target has matching infrastructure or you pre-edit the YAML.
   The push tool itself just sends what's in the file; it doesn't try to
   rewrite TZ/T1 references.

Layout written by export (overwritten each run when default path is used):

  nsx_segments_export/<source-host>/
    segments/<slug>__<id>.yaml       one file per segment
    segment_to_groups.json           per-segment view: which groups reference each segment
    group_to_segments.json           per-group view:   which segments each group references
    manifest.json
    logs/segments_export_<UTC_TS>.log
    logs/segments_export_<UTC_TS>.errors.log

Examples:

  python tools/nsx/segments.py export --source nsx-lm1

  python tools/nsx/segments.py push \\
    --target nsx-lm2 \\
    --segments-dir nsx_segments_export/nsx-lm1.lab.local/segments \\
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

STRIP_KEYS = {
    "_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
    "_revision", "revision", "_protection", "_system_owned",
    "marked_for_delete", "overridden", "remote_path",
    "realization_id", "unique_id", "origin_site_id", "owner_id",
    "_links", "_schema", "_self", "status", "children",
}

EXCLUDED_FILENAMES = {"manifest.json", "summary.json", "summary.txt"}
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]

# Matches /infra/segments/<id>, /global-infra/segments/<id>, and any
# /ports/... sub-resource path under those.
SEGMENT_PATH_RE = re.compile(r"^/(?:global-)?infra/segments/([^/\s]+)(?:/.*)?$")
_SAFE_ID_RE = re.compile(r'^[A-Za-z0-9._\-]+$')


def _has_special_chars(value: str) -> bool:
    return not bool(_SAFE_ID_RE.match(str(value or "")))


def _setup_logging(reports_dir: Path, label: str) -> tuple[Path, Path]:
    global_log_dir = Path(nsx_log_dir).expanduser().resolve()
    global_log_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    bundle_log = (reports_dir / f"segments_{label}_{RUN_TS}.log").resolve()
    global_log = (global_log_dir / f"segments_{label}_{RUN_TS}.log").resolve()
    errors_log = (reports_dir / f"segments_{label}_{RUN_TS}.errors.log").resolve()

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


def _short_id_filename(nsx_id: str) -> str:
    """Deterministic, MAX_PATH-safe, collision-resistant filename stem.

    Format:
      - slug <= 10 chars:  "<slug>-<8hex>"
      - else:              "<first5>-<last5>-<8hex>"
    """
    raw = (nsx_id or "").strip() or "unnamed"
    s = re.sub(r"[^\w\-\.]+", "_", raw)
    s = re.sub(r"_+", "_", s).strip("_") or "unnamed"
    h = hashlib.md5(raw.encode("utf-8")).hexdigest()[:8]
    if len(s) <= 10:
        return f"{s}-{h}"
    return f"{s[:5]}-{s[-5:]}-{h}"


def _load_file(p: Path) -> Dict[str, Any]:
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        return yaml.safe_load(text) or {}
    return json.loads(text)


def _iter_segment_files(segments_dir: Path) -> List[Path]:
    if not segments_dir.exists():
        return []
    files: List[Path] = []
    for ext in ("*.yaml", "*.yml", "*.json"):
        for p in segments_dir.rglob(ext):
            if p.name in EXCLUDED_FILENAMES:
                continue
            files.append(p)
    return sorted(files)


def _is_missing_dependency_error(err_msg: str) -> bool:
    """A 404 on PUT/PATCH means an object referenced inside the segment payload
    (transport-zone path, segment profiles, etc.) doesn't exist on the target.
    NSX surfaces this as if the URL itself was missing. Queued and retried.
    """
    lower = err_msg.lower()
    return (
        "404" in err_msg
        and "could not be found" in lower
        and "object identifiers are case sensitive" in lower
    )


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


def _segments_referenced_by_expression(expression: List[Any]) -> List[str]:
    """Walk a group's expression list, return all segment-path strings found."""
    refs: List[str] = []
    if not isinstance(expression, list):
        return refs
    for item in expression:
        if isinstance(item, dict) and item.get("resource_type") == "PathExpression":
            for p in item.get("paths") or []:
                if isinstance(p, str) and SEGMENT_PATH_RE.match(p.strip()):
                    refs.append(p.strip())
    return refs


def _segment_id_from_path(path: str) -> str:
    """Extract the segment id from /(global-)?infra/segments/<id> (possibly with subpath)."""
    m = SEGMENT_PATH_RE.match(path.strip())
    return m.group(1) if m else ""


# =============================================================================
# Baseline stack for revert
# =============================================================================

def _baselines_dir(reports_dir: Path) -> Path:
    d = reports_dir / "baselines"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _capture_target_segments(client: NsxPolicyClient) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for seg in client.list_segments():
        if _is_system_object(seg):
            continue
        sid = seg.get("id")
        if sid:
            out[sid] = _sanitize(seg)
    return out


def _append_baseline(reports_dir: Path, baseline: Dict[str, Dict[str, Any]]) -> Path:
    bdir = _baselines_dir(reports_dir)
    path = bdir / f"{RUN_TS}_target_baseline.json"
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _latest_unreverted_baseline(reports_dir: Path) -> Path | None:
    bdir = _baselines_dir(reports_dir)
    candidates = sorted(p for p in bdir.glob("*_target_baseline.json"))
    return candidates[-1] if candidates else None


def _mark_baseline_reverted(path: Path) -> None:
    path.rename(path.with_suffix(".json.reverted"))


# =============================================================================
# export
# =============================================================================

def cmd_export(args: argparse.Namespace) -> int:
    source_host = resolve_manager(args.source)
    if not source_host:
        raise SystemExit(f"Manager not defined for {args.source}.")

    using_default = args.output_dir is None
    output_dir = Path(args.output_dir or (REPO_ROOT / "nsx_segments_export" / source_host)).expanduser().resolve()
    if using_default and output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    segs_dir = output_dir / "segments"
    segs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = output_dir / "logs"
    log_file, errors_log = _setup_logging(logs_dir, "export")

    log.info("=" * 60)
    log.info("NSX SEGMENTS — EXPORT")
    log.info("  Source manager  : %s (%s)", args.source, source_host)
    log.info("  Domain          : %s  (only used for group cross-ref)", args.domain_id)
    log.info("  Federation GM   : %s", args.federation_global)
    log.info("  Include system  : %s", args.include_system)
    log.info("  Output bundle   : %s", output_dir)
    log.info("=" * 60)

    client = NsxPolicyClient(nsxmanager=source_host, federation_global=args.federation_global)

    # --- 1. Fetch all segments
    log.info("Step 1/2: Fetching segments ...")
    all_segments = client.list_segments()
    log.info("  Fetched %d segment(s) total.", len(all_segments))

    # --- 2. Fetch all groups (so we can build segment→group cross-references)
    log.info("Step 2/2: Fetching groups (for segment cross-reference) ...")
    groups_path = client._policy_path(f"/domains/{client._q(args.domain_id)}/groups")
    all_groups: List[Dict[str, Any]] = []
    for page in client._get_pages(groups_path):
        all_groups.extend(page.get("results", []) or [])
    log.info("  Fetched %d group(s) total.", len(all_groups))

    # Build segment_id -> [group_id, ...] and group_id -> [segment_path, ...]
    segment_to_groups: Dict[str, List[str]] = {}
    group_to_segments: Dict[str, List[str]] = {}
    for g in all_groups:
        gid = g.get("id")
        if not gid:
            continue
        if not args.include_system and _is_system_object(g):
            continue
        seg_paths = _segments_referenced_by_expression(g.get("expression") or [])
        if seg_paths:
            group_to_segments[gid] = sorted(set(seg_paths))
            for sp in seg_paths:
                seg_id = _segment_id_from_path(sp)
                if seg_id:
                    segment_to_groups.setdefault(seg_id, []).append(gid)
    for sid in list(segment_to_groups.keys()):
        segment_to_groups[sid] = sorted(set(segment_to_groups[sid]))

    # --- Write per-segment YAMLs + record details
    rows: List[Dict[str, Any]] = []
    written = 0
    skipped_system = 0
    skipped_no_id = 0
    errors = 0
    special_char_ids: List[Dict[str, str]] = []

    for i, seg in enumerate(all_segments, start=1):
        sid = seg.get("id")
        sname = seg.get("display_name") or sid or "segment"

        if not args.include_system and _is_system_object(seg):
            skipped_system += 1
            continue

        if not sid:
            skipped_no_id += 1
            log.warning("[%d/%d] segment has no id: display_name=%s", i, len(all_segments), sname)
            continue

        if _has_special_chars(sid):
            special_char_ids.append({"id": sid, "display_name": sname})
            log.warning("[%d/%d] special chars in id: %r (URL-encoded on push)", i, len(all_segments), sid)

        fname = f"{_short_id_filename(sid)}.yaml"
        path = segs_dir / fname

        try:
            payload = _sanitize(seg)
            path.write_text(
                yaml.safe_dump(payload, sort_keys=False, default_flow_style=False),
                encoding="utf-8",
            )
            written += 1
            ref_count = len(segment_to_groups.get(sid, []))
            log.info("[%d/%d  ok=%d sys-skip=%d err=%d] %s — %d group ref(s)",
                     i, len(all_segments), written, skipped_system, errors, sid, ref_count)
            rows.append({
                "id": sid, "display_name": sname, "file": fname, "status": "ok",
                "subnets": [(sn.get("network") if isinstance(sn, dict) else None)
                            for sn in (seg.get("subnets") or [])],
                "vlan_ids": seg.get("vlan_ids"),
                "transport_zone_path": seg.get("transport_zone_path"),
                "connectivity_path": seg.get("connectivity_path"),
                "type": seg.get("type"),
                "referenced_by_groups": segment_to_groups.get(sid, []),
                "referenced_by_groups_count": ref_count,
            })
        except Exception as exc:
            errors += 1
            tb = traceback.format_exc()
            log.exception("[%d/%d] FAILED writing %s", i, len(all_segments), sid)
            rows.append({
                "id": sid, "display_name": sname, "file": fname,
                "status": "failed", "error": str(exc),
                "error_type": type(exc).__name__, "traceback": tb,
            })

    # --- Write cross-reference files
    (output_dir / "segment_to_groups.json").write_text(
        json.dumps(segment_to_groups, indent=2, sort_keys=True), encoding="utf-8",
    )
    (output_dir / "group_to_segments.json").write_text(
        json.dumps(group_to_segments, indent=2, sort_keys=True), encoding="utf-8",
    )

    manifest = {
        "command": "segments.export",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source": {"alias": args.source, "host": source_host,
                   "federation_global": args.federation_global, "domain_id": args.domain_id},
        "counts": {
            "segments_total": len(all_segments),
            "written": written,
            "skipped_system_owned": skipped_system,
            "skipped_no_id": skipped_no_id,
            "errors": errors,
            "ids_with_special_chars": len(special_char_ids),
            "groups_scanned": len(all_groups),
            "groups_with_segment_refs": len(group_to_segments),
            "segments_referenced_by_at_least_one_group": len(segment_to_groups),
        },
        "segments": rows,
        "ids_with_special_chars": special_char_ids,
        "paths": {
            "bundle_dir": str(output_dir),
            "segments_dir": str(segs_dir),
            "segment_to_groups_file": str(output_dir / "segment_to_groups.json"),
            "group_to_segments_file": str(output_dir / "group_to_segments.json"),
            "logs_dir": str(logs_dir),
        },
        "log_file": str(log_file),
        "errors_log": str(errors_log),
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    log.info("=" * 60)
    log.info("Segments export complete:")
    log.info("  written=%d  sys-skipped=%d  no-id=%d  errors=%d",
             written, skipped_system, skipped_no_id, errors)
    log.info("  groups scanned=%d  groups-with-seg-refs=%d  segments-with-refs=%d",
             len(all_groups), len(group_to_segments), len(segment_to_groups))
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

    segs_dir = Path(args.segments_dir).expanduser().resolve()
    if not segs_dir.exists():
        raise SystemExit(f"Segments dir does not exist: {segs_dir}")

    reports_dir = Path(args.reports_dir or (segs_dir.parent / "push_report")).expanduser().resolve()
    log_file, errors_log = _setup_logging(reports_dir, "push")

    mode = "APPLY" if args.apply else "DRY-RUN"
    log.info("=" * 60)
    log.info("NSX SEGMENTS — PUSH (%s)", mode)
    log.info("  Target          : %s (%s)", args.target, target_host)
    log.info("  Federation GM   : %s", args.federation_global)
    log.info("  Segments dir    : %s", segs_dir)
    log.info("  Reports dir     : %s", reports_dir)
    log.info("=" * 60)
    log.warning("Segments reference transport zones / T1 routers by manager-specific UUID. "
                "If the target's transport zone path differs from the source's, NSX will "
                "reject the PUT with a validation error — that's expected and shows up in "
                "failures.json. Edit the YAML's transport_zone_path / connectivity_path if "
                "you need to map them across managers.")

    files = _iter_segment_files(segs_dir)
    log.info("Found %d segment file(s).", len(files))

    client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global) if args.apply else None
    baseline_path = None
    if args.apply:
        log.info("Capturing target baseline (current customer segments on %s) ...", target_host)
        baseline = _capture_target_segments(client)
        baseline_path = _append_baseline(reports_dir, baseline)
        log.info("  Baseline: %d customer segment(s) → %s", len(baseline), baseline_path)

    rows: List[Dict[str, Any]] = []
    ok = failed = skipped = dry_run_count = 0

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

            path = client._policy_path(f"/segments/{client._q(sid)}")
            try:
                client._put(path, obj)
                row["status"] = "success_put"
            except NsxApiError as e:
                if _is_already_exists_error(e):
                    client._patch(path, obj)
                    row["status"] = "success_patch"
                else:
                    raise

            ok += 1
            log.info("[%d/%d  ok=%d fail=%d skip=%d] %s — %s",
                     i, len(files), ok, failed, skipped, sid, row["status"])
            time.sleep(THROTTLE_SECONDS)

        except Exception as e:
            failed += 1
            err_msg = str(e)
            row["error"] = err_msg
            row["error_type"] = type(e).__name__
            row["traceback"] = traceback.format_exc()

            if _is_missing_dependency_error(err_msg):
                row["status"] = "failed_pending_retry"
                pending = sum(
                    1 for r in rows + [row]
                    if r.get("status") == "failed_pending_retry"
                )
                log.warning(
                    "[%d/%d  ok=%d fail=%d skip=%d] %s — referenced object missing (404); PENDING RETRY (queued=%d)",
                    i, len(files), ok, failed, skipped,
                    row.get("id") or f.name, pending,
                )
            else:
                row["status"] = "failed"
                log.error(
                    "[%d/%d  ok=%d fail=%d skip=%d] %s — FAILED: %s\n%s",
                    i, len(files), ok, failed, skipped,
                    row.get("id") or f.name, e, row["traceback"],
                )

        rows.append(row)

    # ------------------------------------------------------------------
    # Retry pass — segments rarely have inter-segment deps, but transport
    # zone / profile references can 404 if the target is missing them.
    # Retry only failed_pending_retry rows; promote leftovers to "failed".
    # ------------------------------------------------------------------
    MAX_RETRY_ROUNDS = 5
    retry_round = 0
    retry_attempts = 0
    while args.apply and retry_round < MAX_RETRY_ROUNDS:
        to_retry = [r for r in rows if r.get("status") == "failed_pending_retry"]
        if not to_retry:
            break
        retry_round += 1

        log.info("=" * 60)
        log.info("Retry round %d — %d segment(s) pending", retry_round, len(to_retry))
        log.info("=" * 60)

        progress = False
        for row in to_retry:
            retry_attempts += 1
            sid = row.get("id") or ""
            try:
                obj = _sanitize(_load_file(Path(row["file"])))
                path = client._policy_path(f"/segments/{client._q(sid)}")
                try:
                    client._put(path, obj)
                    row["status"] = "success_put_retry"
                except NsxApiError as e:
                    if _is_already_exists_error(e):
                        client._patch(path, obj)
                        row["status"] = "success_patch_retry"
                    else:
                        raise
                row["retry_round"] = retry_round
                row.pop("error", None)
                row.pop("error_type", None)
                row.pop("traceback", None)
                ok += 1
                failed -= 1
                progress = True
                log.info("[retry-%d] %s — %s", retry_round, sid, row["status"])
                time.sleep(THROTTLE_SECONDS)
            except Exception as e:
                err_msg = str(e)
                row["error"] = err_msg
                row["error_type"] = type(e).__name__
                row["retry_round"] = retry_round
                if _is_missing_dependency_error(err_msg):
                    log.warning("[retry-%d] %s — still pending (dep still missing)", retry_round, sid)
                else:
                    row["status"] = "failed"
                    row["traceback"] = traceback.format_exc()
                    log.error("[retry-%d] %s — FAILED: %s", retry_round, sid, err_msg)

        if not progress:
            log.warning("Retry round %d made no progress — promoting %d remaining pending row(s) to FAILED.",
                        retry_round,
                        sum(1 for r in rows if r.get("status") == "failed_pending_retry"))
            break

    for r in rows:
        if r.get("status") == "failed_pending_retry":
            r["status"] = "failed"

    summary = {
        "command": "segments.push",
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "target": {"alias": args.target, "host": target_host,
                   "federation_global": args.federation_global},
        "segments_dir": str(segs_dir),
        "mode": mode,
        "totals": {
            "files_seen": len(files),
            "ok": ok,
            "failed": failed,
            "skipped": skipped,
            "dry_run": dry_run_count,
            "retry_rounds": retry_round,
            "retry_attempts": retry_attempts,
        },
        "baseline_file": str(baseline_path) if baseline_path else None,
        "log_file": str(log_file),
        "errors_log": str(errors_log),
    }

    (reports_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (reports_dir / "segments.json").write_text(json.dumps(rows, indent=2, sort_keys=True), encoding="utf-8")
    with (reports_dir / "segments.jsonl").open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    if failed:
        failures = [r for r in rows if r.get("status") == "failed"]
        (reports_dir / "failures.json").write_text(json.dumps(failures, indent=2, sort_keys=True), encoding="utf-8")

    log.info("=" * 60)
    log.info("Push segments %s — ok=%d failed=%d skipped=%d (dry_run=%d) total=%d",
             mode, ok, failed, skipped, dry_run_count, len(files))
    log.info("Reports: %s", reports_dir)
    log.info("=" * 60)

    print(json.dumps(summary, indent=2))
    return 0 if failed == 0 else 1


# =============================================================================
# revert
# =============================================================================

def cmd_revert(args: argparse.Namespace) -> int:
    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Target manager not defined: {args.target}")

    reports_dir = Path(args.reports_dir).expanduser().resolve() if args.reports_dir else None
    if reports_dir is None:
        candidates = sorted((REPO_ROOT / "nsx_segments_export").glob("*/push_report"))
        if not candidates:
            raise SystemExit("Could not auto-locate push_report. Pass --reports-dir.")
        reports_dir = candidates[-1]
    if not reports_dir.exists():
        raise SystemExit(f"Reports dir does not exist: {reports_dir}")

    log_file, errors_log = _setup_logging(reports_dir, "revert")

    log.info("=" * 60)
    log.info("NSX SEGMENTS — REVERT")
    log.info("  Target          : %s (%s)", args.target, target_host)
    log.info("  Reports dir     : %s", reports_dir)
    log.info("=" * 60)

    if args.from_baseline:
        baseline_path = Path(args.from_baseline).expanduser().resolve()
    else:
        baseline_path = _latest_unreverted_baseline(reports_dir)
    if not baseline_path or not baseline_path.exists():
        raise SystemExit(
            f"No baseline file in {reports_dir / 'baselines'}/. "
            "Run segments.py push --apply first, or pass --from-baseline <path>."
        )

    log.info("Using baseline: %s", baseline_path)
    baseline: Dict[str, Dict[str, Any]] = json.loads(baseline_path.read_text(encoding="utf-8"))
    log.info("  Baseline contains %d customer segment(s)", len(baseline))

    client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global)
    current = _capture_target_segments(client)
    log.info("  Currently %d customer segment(s) on target", len(current))

    to_restore = [(sid, payload) for sid, payload in baseline.items()]
    to_delete = [sid for sid in current.keys() if sid not in baseline]
    log.info("Plan: restore=%d  delete=%d", len(to_restore), len(to_delete))

    if not args.apply:
        log.info("DRY-RUN — no NSX writes. Add --apply to execute.")
        for sid, _ in to_restore:
            log.info("[DRY restore] %s", sid)
        for sid in to_delete:
            log.info("[DRY delete]  %s", sid)
        return 0

    rows: List[Dict[str, Any]] = []
    restored_ok = restored_failed = deleted_ok = deleted_failed = 0

    for i, sid in enumerate(to_delete, start=1):
        try:
            client._delete(client._policy_path(f"/segments/{client._q(sid)}"))
            deleted_ok += 1
            log.info("[DELETE %d/%d  ok=%d fail=%d] %s",
                     i, len(to_delete), deleted_ok, deleted_failed, sid)
            rows.append({"action": "delete", "id": sid, "status": "success"})
            time.sleep(THROTTLE_SECONDS)
        except Exception as e:
            deleted_failed += 1
            tb = traceback.format_exc()
            log.error("[DELETE %d/%d FAIL] %s — %s\n%s", i, len(to_delete), sid, e, tb)
            rows.append({"action": "delete", "id": sid, "status": "failed",
                         "error": str(e), "error_type": type(e).__name__, "traceback": tb})

    for i, (sid, payload) in enumerate(to_restore, start=1):
        try:
            path = client._policy_path(f"/segments/{client._q(sid)}")
            try:
                client._put(path, payload)
                rows.append({"action": "restore", "id": sid, "status": "success_put"})
            except NsxApiError as e:
                if _is_already_exists_error(e):
                    client._patch(path, payload)
                    rows.append({"action": "restore", "id": sid, "status": "success_patch"})
                else:
                    raise
            restored_ok += 1
            log.info("[RESTORE %d/%d  ok=%d fail=%d] %s",
                     i, len(to_restore), restored_ok, restored_failed, sid)
            time.sleep(THROTTLE_SECONDS)
        except Exception as e:
            restored_failed += 1
            tb = traceback.format_exc()
            log.error("[RESTORE %d/%d FAIL] %s — %s\n%s", i, len(to_restore), sid, e, tb)
            rows.append({"action": "restore", "id": sid, "status": "failed",
                         "error": str(e), "error_type": type(e).__name__, "traceback": tb})

    _mark_baseline_reverted(baseline_path)

    summary = {
        "command": "segments.revert",
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "target": {"alias": args.target, "host": target_host,
                   "federation_global": args.federation_global},
        "baseline_file": str(baseline_path) + ".reverted",
        "totals": {
            "restored_ok": restored_ok,
            "restored_failed": restored_failed,
            "deleted_ok": deleted_ok,
            "deleted_failed": deleted_failed,
        },
        "log_file": str(log_file),
        "errors_log": str(errors_log),
    }
    revert_ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    (reports_dir / f"revert_summary_{revert_ts}.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (reports_dir / f"revert_actions_{revert_ts}.jsonl").write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n", encoding="utf-8")

    log.info("=" * 60)
    log.info("Revert complete — restored ok=%d/%d  deleted ok=%d/%d",
             restored_ok, len(to_restore), deleted_ok, len(to_delete))
    log.info("=" * 60)

    print(json.dumps(summary, indent=2))
    return 0 if (restored_failed == 0 and deleted_failed == 0) else 1


# =============================================================================
# CLI dispatch
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(
        description="Export NSX segments from a source / push them to a target. Includes group cross-reference.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pe = sub.add_parser("export", help="Export per-file segment YAMLs + segment↔group cross-reference (read-only).")
    pe.add_argument("--source", required=True, choices=NSX_MANAGER_CHOICES)
    pe.add_argument("--domain-id", default="default",
                    help="Domain to scan for groups when building cross-references. Segments themselves are not domain-scoped.")
    pe.add_argument("--federation-global", action="store_true")
    pe.add_argument("--output-dir", default=None,
                    help="Defaults to nsx_segments_export/<source-host>/. Wiped on each run.")
    pe.add_argument("--include-system", action="store_true",
                    help="Also export system-owned segments (default: skip).")
    pe.set_defaults(func=cmd_export)

    pp = sub.add_parser("push", help="Push per-file segment YAMLs to a target. Dry-run by default.")
    pp.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    pp.add_argument("--segments-dir", required=True)
    pp.add_argument("--federation-global", action="store_true")
    pp.add_argument("--apply", action="store_true", default=False,
                    help="Actually push. Without this, runs as dry-run.")
    pp.add_argument("--reports-dir", default=None,
                    help="Defaults to <segments-dir>/../push_report/.")
    pp.set_defaults(func=cmd_push)

    pr = sub.add_parser("revert", help="Undo the most recent push using the auto-captured baseline.")
    pr.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    pr.add_argument("--federation-global", action="store_true")
    pr.add_argument("--apply", action="store_true", default=False,
                    help="Actually revert. Without this, runs as dry-run.")
    pr.add_argument("--reports-dir", default=None,
                    help="Defaults to nsx_segments_export/<target-host>/push_report/.")
    pr.add_argument("--from-baseline", default=None,
                    help="Specific baseline file (overrides auto-selected latest).")
    pr.set_defaults(func=cmd_revert)

    args = p.parse_args()
    init_cli()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
