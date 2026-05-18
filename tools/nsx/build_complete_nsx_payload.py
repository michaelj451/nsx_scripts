#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import yaml
except ImportError:
    yaml = None

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_log_dir

log = logging.getLogger(__name__)


# Matches /infra/segments/<id> and /global-infra/segments/<id>, including any
# trailing sub-resource (e.g. /ports/...).
SEGMENT_PATH_RE = re.compile(r"^/(?:global-)?infra/segments/[^/\s]+(?:/.*)?$")


# =============================================================================
# Logging / Reports
# =============================================================================

RUN_TS = datetime.now().strftime("%Y%m%d_%H%M%S")


def setup_logging() -> tuple[Path, Path]:
    log_root = Path(nsx_log_dir).expanduser().resolve()
    log_root.mkdir(parents=True, exist_ok=True)

    log_file = log_root / f"build_complete_nsx_payload_{RUN_TS}.log"

    reports_dir = (
        log_root
        / "build_complete_nsx_payload"
        / RUN_TS
    )
    reports_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Important:
    # init_cli() may configure logging before this script.
    # Remove existing handlers so our file logger works.
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%d %H:%M:%S",
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


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


# =============================================================================
# File helpers
# =============================================================================

def copy_tree(src: Path, dst: Path, *, required: bool = True) -> bool:
    if not src.exists():
        msg = f"Source path does not exist: {src}"

        if required:
            raise RuntimeError(msg)

        log.warning(msg)
        return False

    if dst.exists():
        log.info("Deleting existing destination: %s", dst)
        shutil.rmtree(dst)

    log.info("Copying %s -> %s", src, dst)
    shutil.copytree(src, dst)

    return True


def count_files(path: Path) -> int:
    if not path.exists():
        return 0

    total = 0

    for ext in ("*.yaml", "*.yml", "*.json"):
        total += len(list(path.rglob(ext)))

    return total


# =============================================================================
# Segment stripping
# =============================================================================

def _is_operator(item: Any) -> bool:
    return isinstance(item, dict) and item.get("resource_type") == "ConjunctionOperator"


def _is_path_expression(item: Any) -> bool:
    return isinstance(item, dict) and item.get("resource_type") == "PathExpression"


def _strip_segments_from_expression_list(
    expression: List[Any],
) -> Tuple[List[Any], List[str], int]:
    """
    Walk a group's expression list. For each PathExpression, drop entries from
    `paths` that look like segment paths. If a PathExpression's paths list
    becomes empty as a result, drop the whole PathExpression and the operator
    that paired with it.

    Returns (new_expression_list, stripped_paths, dropped_expression_count).
    """
    if not isinstance(expression, list):
        return expression, [], 0

    stripped_paths: List[str] = []
    indices_to_drop: set[int] = set()
    new_items: List[Any] = []

    for i, item in enumerate(expression):
        if _is_path_expression(item):
            paths = item.get("paths") or []
            kept = []
            for p in paths:
                if isinstance(p, str) and SEGMENT_PATH_RE.match(p.strip()):
                    stripped_paths.append(p.strip())
                else:
                    kept.append(p)

            if not kept:
                indices_to_drop.add(i)
                new_items.append(None)
            else:
                cloned = dict(item)
                cloned["paths"] = kept
                new_items.append(cloned)
        else:
            new_items.append(item)

    operators_to_drop: set[int] = set()
    for i in sorted(indices_to_drop):
        # Pair-removal: prefer the operator on the LEFT (the one that joined
        # this operand to the previous one). Fall back to the right operator
        # if this was the first operand.
        if i > 0 and _is_operator(new_items[i - 1]) and (i - 1) not in indices_to_drop:
            operators_to_drop.add(i - 1)
        elif i + 1 < len(new_items) and _is_operator(new_items[i + 1]) and (i + 1) not in indices_to_drop:
            operators_to_drop.add(i + 1)

    all_drop = indices_to_drop | operators_to_drop
    result = [item for idx, item in enumerate(new_items) if idx not in all_drop]

    # Defensive: trim any leading/trailing operators that survived
    while result and _is_operator(result[0]):
        result.pop(0)
    while result and _is_operator(result[-1]):
        result.pop()

    return result, stripped_paths, len(indices_to_drop)


def _strip_segments_from_group(group: Dict[str, Any]) -> Tuple[List[str], int]:
    """Mutate group['expression'] in place. Returns (stripped_paths, dropped_expressions)."""
    if not isinstance(group, dict):
        return [], 0

    expression = group.get("expression")
    if not isinstance(expression, list):
        return [], 0

    new_expression, stripped_paths, dropped = _strip_segments_from_expression_list(expression)
    group["expression"] = new_expression
    return stripped_paths, dropped


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


def strip_segments_in_tree(groups_dir: Path) -> Dict[str, Any]:
    """
    Walk every group file under groups_dir and strip segment-path references.
    Returns a structured report describing what was changed.
    """
    files_seen = 0
    files_modified = 0
    total_paths_stripped = 0
    total_expressions_dropped = 0
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

            stripped_paths, dropped = _strip_segments_from_group(data)
            if not stripped_paths and dropped == 0:
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

            per_group.append({
                "file": str(path),
                "group_id": data.get("id"),
                "group_display_name": data.get("display_name") or data.get("name"),
                "paths_stripped": stripped_paths,
                "path_expressions_dropped": dropped,
            })

            log.info(
                "Stripped %d segment path(s) from group %s (dropped %d empty PathExpression)",
                len(stripped_paths),
                data.get("display_name") or data.get("id") or path.name,
                dropped,
            )

    return {
        "groups_dir": str(groups_dir),
        "files_seen": files_seen,
        "files_modified": files_modified,
        "total_segment_paths_stripped": total_paths_stripped,
        "total_path_expressions_dropped": total_expressions_dropped,
        "parse_errors": parse_errors,
        "groups": per_group,
    }


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build complete NSX payload directory for target manager"
    )

    parser.add_argument(
        "--source-manager-dir",
        required=True,
        help="Source exported manager directory, example: nsx_export/nsx-lm1.lab.local",
    )

    parser.add_argument(
        "--additive-groups-dir",
        required=True,
        help="Additive groups directory with IPAddressExpression entries",
    )

    parser.add_argument(
        "--build-dir",
        required=True,
        help="Final complete build directory to push, example: nsx_build/nsx-lm3.lab.local",
    )

    parser.add_argument(
        "--domain-id",
        default="default",
    )

    parser.add_argument(
        "--include-services",
        action="store_true",
        default=True,
    )

    parser.add_argument(
        "--include-security-policies",
        action="store_true",
        default=True,
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Delete existing build dir before creating it",
    )

    parser.add_argument(
        "--strip-segments",
        action="store_true",
        help=(
            "Strip /infra/segments/* and /global-infra/segments/* references "
            "from group PathExpression blocks in the built payload. Use when "
            "the target manager (e.g. DFW-only access on nsx-lm2) cannot have "
            "those segments created, so leaving the references would land as "
            "dead paths. The adjacent ConjunctionOperator is cleaned up so "
            "the resulting expression list stays NSX-valid."
        ),
    )

    args = parser.parse_args()

    init_cli()
    log_file, reports_dir = setup_logging()

    source_manager_dir = Path(args.source_manager_dir).expanduser().resolve()
    additive_groups_dir = Path(args.additive_groups_dir).expanduser().resolve()
    build_dir = Path(args.build_dir).expanduser().resolve()

    source_domain_dir = source_manager_dir / "domains" / args.domain_id
    build_domain_dir = build_dir / "domains" / args.domain_id

    if not source_domain_dir.exists():
        raise RuntimeError(
            f"Source domain directory does not exist: {source_domain_dir}"
        )

    if not additive_groups_dir.exists():
        raise RuntimeError(
            f"Additive groups directory does not exist: {additive_groups_dir}"
        )

    log.info("Starting build_complete_nsx_payload")
    log.info("Source manager dir: %s", source_manager_dir)
    log.info("Additive groups dir: %s", additive_groups_dir)
    log.info("Build dir: %s", build_dir)
    log.info("Domain ID: %s", args.domain_id)
    log.info("Overwrite: %s", args.overwrite)

    if build_dir.exists():
        if not args.overwrite:
            raise RuntimeError(
                f"Build dir already exists: {build_dir}\n"
                f"Re-run with --overwrite to replace it."
            )

        log.info("Deleting existing build dir: %s", build_dir)
        shutil.rmtree(build_dir)

    build_domain_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # Copy meta if present
    # -------------------------------------------------------------------------

    meta_copied = []

    for meta_name in ("meta.yaml", "meta.yml", "meta.json"):
        src_meta = source_manager_dir / meta_name

        if src_meta.exists():
            dst_meta = build_dir / meta_name

            log.info("Copying meta %s -> %s", src_meta, dst_meta)
            shutil.copy2(src_meta, dst_meta)

            meta_copied.append(str(dst_meta))

    # -------------------------------------------------------------------------
    # Services
    # -------------------------------------------------------------------------

    services_src = source_domain_dir / "services"
    services_dst = build_domain_dir / "services"

    services_copied = copy_tree(
        services_src,
        services_dst,
        required=False,
    )

    # -------------------------------------------------------------------------
    # Security Policies
    # -------------------------------------------------------------------------

    policies_src = source_domain_dir / "security-policies"
    policies_dst = build_domain_dir / "security-policies"

    policies_copied = copy_tree(
        policies_src,
        policies_dst,
        required=False,
    )

    # -------------------------------------------------------------------------
    # Groups
    # -------------------------------------------------------------------------

    groups_dst = build_domain_dir / "groups"

    copy_tree(
        additive_groups_dir,
        groups_dst,
        required=True,
    )

    # -------------------------------------------------------------------------
    # Optional: strip segment references from group payloads
    # -------------------------------------------------------------------------

    strip_report: Dict[str, Any] | None = None
    if args.strip_segments:
        log.info("Stripping segment references from group payloads in: %s", groups_dst)
        strip_report = strip_segments_in_tree(groups_dst)
        log.info(
            "Segment strip complete: files_modified=%d paths_stripped=%d expressions_dropped=%d",
            strip_report["files_modified"],
            strip_report["total_segment_paths_stripped"],
            strip_report["total_path_expressions_dropped"],
        )
        write_json(reports_dir / "segments_stripped.json", strip_report)

    # -------------------------------------------------------------------------
    # Counts / Result
    # -------------------------------------------------------------------------

    result = {
        "command": "build_complete_nsx_payload",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "source_manager_dir": str(source_manager_dir),
        "source_domain_dir": str(source_domain_dir),
        "additive_groups_dir": str(additive_groups_dir),
        "build_dir": str(build_dir),
        "build_domain_dir": str(build_domain_dir),
        "domain_id": args.domain_id,
        "services_copied": services_copied,
        "security_policies_copied": policies_copied,
        "meta_files_copied": meta_copied,
        "strip_segments": bool(args.strip_segments),
        "segments_stripped_summary": (
            {
                "files_modified": strip_report["files_modified"],
                "total_segment_paths_stripped": strip_report["total_segment_paths_stripped"],
                "total_path_expressions_dropped": strip_report["total_path_expressions_dropped"],
            }
            if strip_report else None
        ),
        "counts": {
            "groups": count_files(groups_dst),
            "services": count_files(services_dst),
            "security_policy_files": count_files(policies_dst),
        },
        "reports_dir": str(reports_dir),
        "log_file": str(log_file),
    }

    # -------------------------------------------------------------------------
    # Reports
    # -------------------------------------------------------------------------

    write_json(reports_dir / "summary.json", result)

    write_json(
        reports_dir / "counts.json",
        result["counts"],
    )

    write_json(
        reports_dir / "paths.json",
        {
            "source_manager_dir": str(source_manager_dir),
            "source_domain_dir": str(source_domain_dir),
            "additive_groups_dir": str(additive_groups_dir),
            "build_dir": str(build_dir),
            "build_domain_dir": str(build_domain_dir),
        },
    )

    # -------------------------------------------------------------------------
    # Finish
    # -------------------------------------------------------------------------

    log.info("Build complete: %s", build_dir)
    log.info("Summary: %s", result)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()