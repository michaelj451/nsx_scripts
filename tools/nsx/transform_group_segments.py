#!/usr/bin/env python3
"""
tools/nsx/transform_group_segments.py

Transform segment references in NSX group payloads BEFORE assembling the push
payload. Designed to run between the additive-membership step and
build_complete_nsx_payload.py so you can review the modified groups before
they go into the build dir.

Two modes:

  --mode strip
    Remove `/infra/segments/*` and `/global-infra/segments/*` entries from
    every `PathExpression.paths` list. Drop any `PathExpression` whose
    paths list becomes empty. Clean up the adjacent `ConjunctionOperator`
    so the expression list stays NSX-valid.
    Offline — no NSX API call.

  --mode convert
    Same as strip, but before dropping each segment reference, fetch the
    segment from a live NSX manager (--source-manager) and replace it with
    an `IPAddressExpression` containing the segment's subnet CIDR(s).
    The group becomes an IP-address group that resolves on the target
    even without those segments existing there.

Output:
  - Transformed group tree at --output-dir (mirrors --input-dir structure)
  - segments_stripped.json report under nsx_logs/transform_group_segments/<ts>/
  - Log file

Usage:

  # Strip only (no NSX call):
  PYTHONPATH="$PWD/app" python tools/nsx/transform_group_segments.py \\
    --input-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \\
    --output-dir nsx_groups_transformed/nsx-lm2.lab.local/domains/default/groups \\
    --mode strip \\
    --overwrite

  # Convert via live NSX fetch (requires --source-manager):
  PYTHONPATH="$PWD/app" python tools/nsx/transform_group_segments.py \\
    --input-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \\
    --output-dir nsx_groups_transformed/nsx-lm2.lab.local/domains/default/groups \\
    --mode convert \\
    --source-manager nsx-lm1 \\
    --overwrite
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_log_dir


log = logging.getLogger(__name__)

RUN_TS = datetime.now().strftime("%Y%m%d_%H%M%S")

SEGMENT_PATH_RE = re.compile(r"^/(?:global-)?infra/segments/[^/\s]+(?:/.*)?$")


# =============================================================================
# Logging / Reports
# =============================================================================

def setup_logging() -> Tuple[Path, Path]:
    log_root = Path(nsx_log_dir).expanduser().resolve()
    log_root.mkdir(parents=True, exist_ok=True)

    log_file = log_root / f"transform_group_segments_{RUN_TS}.log"
    reports_dir = log_root / "transform_group_segments" / RUN_TS
    reports_dir.mkdir(parents=True, exist_ok=True)

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
    log.info("Reports dir: %s", reports_dir)
    return log_file, reports_dir


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# =============================================================================
# Expression-walking helpers
# =============================================================================

def _is_operator(item: Any) -> bool:
    return isinstance(item, dict) and item.get("resource_type") == "ConjunctionOperator"


def _is_path_expression(item: Any) -> bool:
    return isinstance(item, dict) and item.get("resource_type") == "PathExpression"


def _extract_subnets_from_segment(seg: Dict[str, Any]) -> List[str]:
    """Pull the `network` CIDR from each subnet entry of a segment object."""
    out: List[str] = []
    for sn in seg.get("subnets", []) or []:
        if isinstance(sn, dict):
            net = sn.get("network")
            if isinstance(net, str) and net.strip():
                out.append(net.strip())
    return out


def _strip_segments_from_expression_list(
    expression: List[Any],
    *,
    segments_by_path: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[List[Any], List[str], int, List[Dict[str, Any]], List[str]]:
    """
    Walk a group's expression list. For each PathExpression, drop entries from
    `paths` that look like segment paths. If `segments_by_path` is provided,
    resolved segments contribute their subnet CIDRs to a new IPAddressExpression
    that replaces (or accompanies) the stripped PathExpression.

    Returns:
      new_expression_list,
      stripped_paths,
      dropped_path_expression_count,
      conversions,            # [{segment_path, segment_display_name, subnets}]
      unresolved_segment_paths
    """
    if not isinstance(expression, list):
        return expression, [], 0, [], []

    stripped_paths: List[str] = []
    conversions: List[Dict[str, Any]] = []
    unresolved: List[str] = []
    indices_to_drop: set[int] = set()
    inserts: Dict[int, Dict[str, Any]] = {}
    new_items: List[Any] = []

    convert_mode = segments_by_path is not None

    for i, item in enumerate(expression):
        if _is_path_expression(item):
            paths = item.get("paths") or []
            kept: List[Any] = []
            resolved_subnets: List[str] = []
            seen_subnet: set[str] = set()

            for p in paths:
                if isinstance(p, str) and SEGMENT_PATH_RE.match(p.strip()):
                    sp = p.strip()
                    stripped_paths.append(sp)

                    if convert_mode:
                        seg = segments_by_path.get(sp) if segments_by_path else None
                        if seg is None:
                            unresolved.append(sp)
                            continue
                        seg_subnets = _extract_subnets_from_segment(seg)
                        if not seg_subnets:
                            unresolved.append(sp)
                            continue
                        for s in seg_subnets:
                            if s not in seen_subnet:
                                seen_subnet.add(s)
                                resolved_subnets.append(s)
                        conversions.append({
                            "segment_path": sp,
                            "segment_display_name": seg.get("display_name"),
                            "subnets": seg_subnets,
                        })
                else:
                    kept.append(p)

            if not kept and not resolved_subnets:
                indices_to_drop.add(i)
                new_items.append(None)
            elif not kept and resolved_subnets:
                new_items.append({
                    "resource_type": "IPAddressExpression",
                    "ip_addresses": resolved_subnets,
                })
            else:
                cloned = dict(item)
                cloned["paths"] = kept
                new_items.append(cloned)
                if resolved_subnets:
                    inserts[i] = {
                        "resource_type": "IPAddressExpression",
                        "ip_addresses": resolved_subnets,
                    }
        else:
            new_items.append(item)

    # Pair-removal of operators adjacent to dropped operands
    operators_to_drop: set[int] = set()
    for i in sorted(indices_to_drop):
        if i > 0 and _is_operator(new_items[i - 1]) and (i - 1) not in indices_to_drop:
            operators_to_drop.add(i - 1)
        elif i + 1 < len(new_items) and _is_operator(new_items[i + 1]) and (i + 1) not in indices_to_drop:
            operators_to_drop.add(i + 1)

    all_drop = indices_to_drop | operators_to_drop

    # Emit kept items in order, splicing in any IPAddressExpression inserts
    result: List[Any] = []
    for idx, item in enumerate(new_items):
        if idx in all_drop:
            continue
        result.append(item)
        if idx in inserts:
            result.append({
                "resource_type": "ConjunctionOperator",
                "conjunction_operator": "OR",
            })
            result.append(inserts[idx])

    while result and _is_operator(result[0]):
        result.pop(0)
    while result and _is_operator(result[-1]):
        result.pop()

    return result, stripped_paths, len(indices_to_drop), conversions, unresolved


def _transform_group(
    group: Dict[str, Any],
    *,
    segments_by_path: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[List[str], int, List[Dict[str, Any]], List[str]]:
    if not isinstance(group, dict):
        return [], 0, [], []

    expression = group.get("expression")
    if not isinstance(expression, list):
        return [], 0, [], []

    new_expression, stripped_paths, dropped, conversions, unresolved = (
        _strip_segments_from_expression_list(expression, segments_by_path=segments_by_path)
    )
    group["expression"] = new_expression
    return stripped_paths, dropped, conversions, unresolved


# =============================================================================
# Segment fetch from live NSX
# =============================================================================

def _fetch_segments_by_path(
    source_manager: Optional[str],
    federation_global: bool,
) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    """
    Fetch all segments from the source manager. On any failure (auth, permission,
    network, etc.) returns ({}, "reason") and the caller can choose how to proceed.
    """
    if not source_manager:
        return {}, None

    try:
        from nsx.nsx_constants import resolve_manager
        from nsx.nsx_policy_client import NsxPolicyClient

        manager_host = resolve_manager(source_manager)
        if not manager_host:
            return {}, f"Manager not defined for {source_manager}"

        client = NsxPolicyClient(nsxmanager=manager_host, federation_global=federation_global)
        log.info(
            "Fetching segments from %s (federation_global=%s) for segment-to-IP conversion",
            manager_host, federation_global,
        )
        all_segments = client.list_segments()

        by_path: Dict[str, Dict[str, Any]] = {}
        for seg in all_segments:
            seg_path = seg.get("path") or seg.get("relative_path")
            if isinstance(seg_path, str):
                by_path[seg_path] = seg
            seg_id = seg.get("id")
            if isinstance(seg_id, str):
                by_path.setdefault(f"/infra/segments/{seg_id}", seg)
                by_path.setdefault(f"/global-infra/segments/{seg_id}", seg)

        log.info("Fetched %d segment object(s) for conversion lookup", len(all_segments))
        return by_path, None

    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc}"
        log.warning(
            "Could not fetch segments from %s for conversion — falling back to "
            "plain strip behavior. Reason: %s",
            source_manager, msg,
        )
        return {}, msg


# =============================================================================
# File I/O
# =============================================================================

def _load_group_file(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(text)
    if suffix in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML is required to load group YAML files")
        return yaml.safe_load(text)
    raise ValueError(f"Unsupported group file type: {path}")


def _write_group_file(path: Path, data: Any) -> None:
    suffix = path.suffix.lower()
    if suffix == ".json":
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return
    if suffix in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML is required to write group YAML files")
        path.write_text(
            yaml.safe_dump(data, sort_keys=False, default_flow_style=False),
            encoding="utf-8",
        )
        return
    raise ValueError(f"Unsupported group file type: {path}")


def _transform_tree(
    groups_dir: Path,
    *,
    segments_by_path: Optional[Dict[str, Dict[str, Any]]] = None,
    fetch_error: Optional[str] = None,
) -> Dict[str, Any]:
    convert_mode = bool(segments_by_path)

    files_seen = 0
    files_modified = 0
    total_paths_stripped = 0
    total_expressions_dropped = 0
    total_segments_converted = 0
    total_unresolved = 0
    per_group: List[Dict[str, Any]] = []
    parse_errors: List[Dict[str, str]] = []

    for ext in ("*.yaml", "*.yml", "*.json"):
        for path in sorted(groups_dir.rglob(ext)):
            if not path.is_file():
                continue
            files_seen += 1

            try:
                data = _load_group_file(path)
            except Exception as exc:
                log.warning("Skipping unreadable group file %s: %s", path, exc)
                parse_errors.append({"file": str(path), "error": str(exc)})
                continue

            if not isinstance(data, dict):
                continue

            stripped_paths, dropped, conversions, unresolved = _transform_group(
                data, segments_by_path=segments_by_path,
            )
            if not stripped_paths and dropped == 0 and not conversions:
                continue

            try:
                _write_group_file(path, data)
            except Exception as exc:
                log.error("Failed writing modified group file %s: %s", path, exc)
                parse_errors.append({"file": str(path), "error": f"write failed: {exc}"})
                continue

            files_modified += 1
            total_paths_stripped += len(stripped_paths)
            total_expressions_dropped += dropped
            total_segments_converted += len(conversions)
            total_unresolved += len(unresolved)

            per_group.append({
                "file": str(path),
                "group_id": data.get("id"),
                "group_display_name": data.get("display_name") or data.get("name"),
                "paths_stripped": stripped_paths,
                "path_expressions_dropped": dropped,
                "segments_converted": conversions,
                "unresolved_segment_paths": unresolved,
            })

            gname = data.get("display_name") or data.get("id") or path.name
            if convert_mode:
                log.info(
                    "Group %s: stripped=%d converted=%d unresolved=%d dropped_path_exprs=%d",
                    gname, len(stripped_paths), len(conversions), len(unresolved), dropped,
                )
            else:
                log.info(
                    "Stripped %d segment path(s) from group %s (dropped %d empty PathExpression)",
                    len(stripped_paths), gname, dropped,
                )

    return {
        "groups_dir": str(groups_dir),
        "convert_mode": convert_mode,
        "fetch_error": fetch_error,
        "files_seen": files_seen,
        "files_modified": files_modified,
        "total_segment_paths_stripped": total_paths_stripped,
        "total_path_expressions_dropped": total_expressions_dropped,
        "total_segments_converted": total_segments_converted,
        "total_unresolved_segment_paths": total_unresolved,
        "parse_errors": parse_errors,
        "groups": per_group,
    }


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Transform segment references in NSX group payloads (strip or "
            "convert-to-IPs) as a reviewable pre-build step."
        )
    )

    parser.add_argument(
        "--input-dir",
        required=True,
        help="Source groups directory to read from (e.g. nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups).",
    )

    parser.add_argument(
        "--output-dir",
        required=True,
        help="Destination directory for transformed group files. The input tree is copied here first, then modified in place.",
    )

    parser.add_argument(
        "--mode",
        choices=["strip", "convert"],
        default="strip",
        help=(
            "strip: drop segment references and clean up operators (offline). "
            "convert: also fetch each segment from --source-manager and "
            "replace it with an IPAddressExpression of its subnets."
        ),
    )

    parser.add_argument(
        "--source-manager",
        default=None,
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        help="Live NSX manager to fetch segment details from (required for --mode convert).",
    )

    parser.add_argument(
        "--federation-global",
        action="store_true",
        help="Treat --source-manager as a Global Manager (/global-infra).",
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Delete the existing --output-dir before populating it.",
    )

    args = parser.parse_args()

    if args.mode == "convert" and not args.source_manager:
        raise SystemExit(
            "--mode convert requires --source-manager (the live NSX manager "
            "to fetch segment subnets from)."
        )

    init_cli()
    log_file, reports_dir = setup_logging()

    input_dir = Path(args.input_dir).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()

    if not input_dir.exists():
        raise SystemExit(f"Input directory does not exist: {input_dir}")
    if not input_dir.is_dir():
        raise SystemExit(f"Input path is not a directory: {input_dir}")

    log.info("Starting transform_group_segments")
    log.info("Mode:        %s", args.mode)
    log.info("Input dir:   %s", input_dir)
    log.info("Output dir:  %s", output_dir)
    log.info("Source mgr:  %s", args.source_manager or "(none)")
    log.info("Federation:  %s", args.federation_global)
    log.info("Overwrite:   %s", args.overwrite)

    if output_dir.exists():
        if not args.overwrite:
            raise SystemExit(
                f"Output dir already exists: {output_dir}\n"
                f"Re-run with --overwrite to replace it."
            )
        log.info("Deleting existing output dir: %s", output_dir)
        shutil.rmtree(output_dir)

    log.info("Copying input tree -> output tree")
    shutil.copytree(input_dir, output_dir)

    segments_by_path: Dict[str, Dict[str, Any]] = {}
    fetch_error: Optional[str] = None

    if args.mode == "convert":
        segments_by_path, fetch_error = _fetch_segments_by_path(
            source_manager=args.source_manager,
            federation_global=args.federation_global,
        )
        if not segments_by_path:
            log.warning(
                "Conversion requested but no segments fetched (reason: %s). "
                "Falling back to plain strip behavior.",
                fetch_error or "unknown",
            )

    report = _transform_tree(
        output_dir,
        segments_by_path=segments_by_path or None,
        fetch_error=fetch_error,
    )

    log.info(
        "Transform complete: files_modified=%d stripped=%d converted=%d unresolved=%d expressions_dropped=%d",
        report["files_modified"],
        report["total_segment_paths_stripped"],
        report["total_segments_converted"],
        report["total_unresolved_segment_paths"],
        report["total_path_expressions_dropped"],
    )

    report_payload = {
        "command": "transform_group_segments",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": args.mode,
        "input_dir": str(input_dir),
        "output_dir": str(output_dir),
        "source_manager": args.source_manager,
        "federation_global": args.federation_global,
        "log_file": str(log_file),
        "reports_dir": str(reports_dir),
        **report,
    }
    write_json(reports_dir / "segments_stripped.json", report_payload)

    log.info("Report written: %s", reports_dir / "segments_stripped.json")
    print(json.dumps({
        "mode": args.mode,
        "input_dir": str(input_dir),
        "output_dir": str(output_dir),
        "source_manager": args.source_manager,
        "files_seen": report["files_seen"],
        "files_modified": report["files_modified"],
        "total_segment_paths_stripped": report["total_segment_paths_stripped"],
        "total_segments_converted": report["total_segments_converted"],
        "total_unresolved_segment_paths": report["total_unresolved_segment_paths"],
        "total_path_expressions_dropped": report["total_path_expressions_dropped"],
        "fetch_error": report["fetch_error"],
        "report": str(reports_dir / "segments_stripped.json"),
        "log_file": str(log_file),
    }, indent=2))


if __name__ == "__main__":
    main()
