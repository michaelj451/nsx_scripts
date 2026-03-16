#!/usr/bin/env python3
# tools/test/build_nsx_import_tree.py

from __future__ import annotations

import argparse
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import (
    nsx_gm1,
    nsx_gm2,
    nsx_lm1,
    nsx_lm2,
    nsx_lm3,
    nsx_lm4,
    nsx_log_dir,
)

log = logging.getLogger(__name__)

RUN_LOG_PATH: Path | None = None
MANIFEST_JSONL_PATH: Path | None = None

STRIP_KEYS = {
    "_revision",
    "revision",
    "_protection",
    "_last_modified_time",
    "_create_time",
    "_system_owned",
    "_links",
    "path",
    "relative_path",
    "parent_path",
    "remote_path",
    "realization_id",
    "unique_id",
    "owner_id",
    "origin_site_id",
    "overridden",
    "marked_for_delete",
}


# ------------------------------------------------
# Logging
# ------------------------------------------------

def _setup_logging() -> None:
    global RUN_LOG_PATH, MANIFEST_JSONL_PATH

    log_dir = Path(nsx_log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    RUN_LOG_PATH = log_dir / f"build_nsx_import_tree_{ts}.log"
    MANIFEST_JSONL_PATH = log_dir / f"build_nsx_import_tree_{ts}.jsonl"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(RUN_LOG_PATH),
            logging.StreamHandler(),
        ],
    )

    log.info("Run log file      : %s", RUN_LOG_PATH)
    log.info("Manifest JSONL    : %s", MANIFEST_JSONL_PATH)


def _append_jsonl(path: Path | None, record: Dict[str, Any]) -> None:
    if not path:
        return
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


# ------------------------------------------------
# Manager helpers
# ------------------------------------------------

def _manager_dirname(mgr: str) -> str:
    return (mgr or "").removeprefix("https://").removeprefix("http://").rstrip("/")


def _manager_hostname(mgr: str) -> str:
    return (mgr or "").removeprefix("https://").removeprefix("http://").rstrip("/")


def _manager_map() -> Dict[str, str]:
    return {
        "nsx-gm1": nsx_gm1,
        "nsx-gm2": nsx_gm2,
        "nsx-lm1": nsx_lm1,
        "nsx-lm2": nsx_lm2,
        "nsx-lm3": nsx_lm3,
        "nsx-lm4": nsx_lm4,
    }


def _resolve_tree_root(base_dir: str, manager_name: str) -> Path:
    base = Path(base_dir)
    return base if base.name == manager_name else (base / manager_name)


def _lm_domain_map_from_env() -> Dict[str, str]:
    return {
        _manager_hostname(nsx_lm1): _manager_hostname(nsx_lm3),
        _manager_hostname(nsx_lm2): _manager_hostname(nsx_lm4),
    }


# ------------------------------------------------
# Transformation helpers
# ------------------------------------------------

def _translate_string(value: str, lm_domain_map: Dict[str, str]) -> str:
    out = value
    for src, dst in lm_domain_map.items():
        out = out.replace(
            f"/global-infra/domains/{src}/",
            f"/global-infra/domains/{dst}/",
        )
        out = out.replace(
            f"/infra/domains/{src}/",
            f"/infra/domains/{dst}/",
        )
        out = out.replace(
            f"/global-infra/domains/{src}",
            f"/global-infra/domains/{dst}",
        )
        out = out.replace(
            f"/infra/domains/{src}",
            f"/infra/domains/{dst}",
        )
    return out


def _classify_path(value: str) -> str:
    if "/groups/" in value:
        return "group"
    if "/services/" in value:
        return "service"
    if "/security-policies/" in value and "/rules/" in value:
            return "rule"
    if "/security-policies/" in value:
        return "policy"
    if "/domains/" in value:
        return "domain"
    return "string"


def _sanitize_obj(
    obj: Any,
    lm_map: Dict[str, str],
    file: Path,
    stats: Dict[str, int],
) -> Any:
    """
    Recursively:
      - strip stale metadata/revision keys
      - translate source LM domain paths to target LM domain paths
    """
    if isinstance(obj, dict):
        new_obj: Dict[str, Any] = {}
        for k, v in obj.items():
            if k in STRIP_KEYS:
                stats["stripped_keys"] += 1
                _append_jsonl(
                    MANIFEST_JSONL_PATH,
                    {
                        "action": "strip_key",
                        "file": str(file),
                        "key": k,
                    },
                )
                continue
            new_obj[k] = _sanitize_obj(v, lm_map, file, stats)
        return new_obj

    if isinstance(obj, list):
        return [_sanitize_obj(v, lm_map, file, stats) for v in obj]

    if isinstance(obj, str):
        new_val = _translate_string(obj, lm_map)
        if new_val != obj:
            stats["translated_strings"] += 1
            _append_jsonl(
                MANIFEST_JSONL_PATH,
                {
                    "action": "translated_string",
                    "file": str(file),
                    "old": obj,
                    "new": new_val,
                    "type": _classify_path(new_val),
                },
            )
        return new_val

    return obj


def _process_yaml_file(path: Path, lm_map: Dict[str, str], stats: Dict[str, int]) -> bool:
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)

    sanitized = _sanitize_obj(data, lm_map, path, stats)
    new_text = yaml.safe_dump(sanitized, sort_keys=True)

    changed = new_text != text
    if changed:
        path.write_text(new_text, encoding="utf-8")
        stats["changed_files"] += 1

    _append_jsonl(
        MANIFEST_JSONL_PATH,
        {
            "action": "process_file",
            "file": str(path),
            "changed": changed,
            "format": "yaml",
        },
    )
    return changed


def _process_json_file(path: Path, lm_map: Dict[str, str], stats: Dict[str, int]) -> bool:
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)

    sanitized = _sanitize_obj(data, lm_map, path, stats)
    new_text = json.dumps(sanitized, indent=2) + "\n"

    changed = new_text != text
    if changed:
        path.write_text(new_text, encoding="utf-8")
        stats["changed_files"] += 1

    _append_jsonl(
        MANIFEST_JSONL_PATH,
        {
            "action": "process_file",
            "file": str(path),
            "changed": changed,
            "format": "json",
        },
    )
    return changed


def _rename_translated_domain_dirs(dst_root: Path, lm_map: Dict[str, str], stats: Dict[str, int]) -> None:
    domains_root = dst_root / "domains"
    if not domains_root.exists():
        return

    for src, dst in lm_map.items():
        src_dir = domains_root / src
        dst_dir = domains_root / dst

        if src_dir.exists():
            if dst_dir.exists():
                raise RuntimeError(
                    f"Destination translated domain dir already exists: {dst_dir}"
                )

            src_dir.rename(dst_dir)
            stats["renamed_domain_dirs"] += 1

            _append_jsonl(
                MANIFEST_JSONL_PATH,
                {
                    "action": "rename_domain_dir",
                    "old": str(src_dir),
                    "new": str(dst_dir),
                },
            )


# ------------------------------------------------
# Manifest helpers
# ------------------------------------------------

def _count_files(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(1 for p in root.rglob("*") if p.is_file())


def _summarize_domain(domain_root: Path) -> Dict[str, Any]:
    return {
        "domain": domain_root.name,
        "services_files": _count_files(domain_root / "services"),
        "groups_files": _count_files(domain_root / "groups"),
        "security_policy_files": _count_files(domain_root / "security-policies"),
    }


def _write_manifest_files(
    dst_root: Path,
    source_root: Path,
    target_root: Path,
    stats: Dict[str, int],
) -> None:
    manifests_dir = dst_root / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)

    domains_root = dst_root / "domains"
    domain_summaries: List[Dict[str, Any]] = []
    if domains_root.exists():
        for domain_dir in sorted(p for p in domains_root.iterdir() if p.is_dir()):
            domain_summaries.append(_summarize_domain(domain_dir))

    object_summary = {
        "source_root": str(source_root),
        "target_root": str(target_root),
        "import_root": str(dst_root),
        "stats": stats,
        "domains": domain_summaries,
    }

    (manifests_dir / "object_summary.json").write_text(
        json.dumps(object_summary, indent=2) + "\n",
        encoding="utf-8",
    )

    import_order = {
        "note": "Suggested federation-global import order: non-default local domains first, then default",
        "order": sorted(
            [d["domain"] for d in domain_summaries if d["domain"] != "default"]
        ) + (["default"] if any(d["domain"] == "default" for d in domain_summaries) else []),
    }

    (manifests_dir / "import_order.json").write_text(
        json.dumps(import_order, indent=2) + "\n",
        encoding="utf-8",
    )

    _append_jsonl(
        MANIFEST_JSONL_PATH,
        {
            "action": "write_manifest_files",
            "manifests_dir": str(manifests_dir),
        },
    )


# ------------------------------------------------
# Main tree builder
# ------------------------------------------------

def _build_import_tree(
    src_root: Path,
    dst_root: Path,
    lm_map: Dict[str, str],
    input_format: str,
    force: bool,
) -> Dict[str, int]:
    if not src_root.exists():
        raise RuntimeError(f"Source export root does not exist: {src_root}")

    if dst_root.exists():
        if not force:
            raise RuntimeError(
                f"Destination import root already exists: {dst_root}\n"
                f"Use --force to replace it."
            )
        shutil.rmtree(dst_root)

    dst_root.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src_root, dst_root)

    stats = {
        "scanned_files": 0,
        "changed_files": 0,
        "translated_strings": 0,
        "stripped_keys": 0,
        "renamed_domain_dirs": 0,
    }

    valid_suffixes = {".yaml", ".yml"} if input_format == "yaml" else {".json"}

    for f in dst_root.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in valid_suffixes:
            continue

        stats["scanned_files"] += 1

        if f.suffix.lower() in {".yaml", ".yml"}:
            _process_yaml_file(f, lm_map, stats)
        elif f.suffix.lower() == ".json":
            _process_json_file(f, lm_map, stats)

    _rename_translated_domain_dirs(dst_root, lm_map, stats)
    return stats


# ------------------------------------------------
# Main
# ------------------------------------------------

def main() -> None:
    _setup_logging()

    parser = argparse.ArgumentParser(
        description="Build a clean nsx_import tree from a read-only nsx_export tree."
    )

    parser.add_argument("--source", required=True, help="Source manager alias, e.g. nsx-gm1")
    parser.add_argument("--target", required=True, help="Target manager alias, e.g. nsx-gm2")
    parser.add_argument("--export-base", default="nsx_export", help="Base export directory")
    parser.add_argument("--import-base", default="nsx_import", help="Base import directory")
    parser.add_argument("--input-format", default="yaml", choices=["yaml", "json"])
    parser.add_argument("--federation-global", action="store_true")
    parser.add_argument("--no-lm-translate", action="store_true")
    parser.add_argument("--force", action="store_true")

    args = parser.parse_args()

    init_cli()

    mgr_map = _manager_map()

    if args.source not in mgr_map:
        raise RuntimeError(f"Unknown source manager alias: {args.source}")
    if args.target not in mgr_map:
        raise RuntimeError(f"Unknown target manager alias: {args.target}")

    src_mgr = mgr_map[args.source]
    dst_mgr = mgr_map[args.target]

    src_folder = _manager_dirname(src_mgr)
    dst_folder = _manager_dirname(dst_mgr)

    src_root = _resolve_tree_root(args.export_base, src_folder)
    dst_root = _resolve_tree_root(args.import_base, dst_folder)

    lm_map: Dict[str, str] = {}
    if args.federation_global and not args.no_lm_translate:
        lm_map = _lm_domain_map_from_env()

    log.info("Source export root : %s", src_root)
    log.info("Target import root : %s", dst_root)
    log.info("Input format       : %s", args.input_format)
    log.info("Federation global  : %s", args.federation_global)
    log.info("LM translation     : %s", bool(lm_map))
    log.info("Force overwrite    : %s", args.force)

    _append_jsonl(
        MANIFEST_JSONL_PATH,
        {
            "action": "start",
            "source_root": str(src_root),
            "target_root": str(dst_root),
            "lm_map": lm_map,
            "input_format": args.input_format,
            "federation_global": args.federation_global,
        },
    )

    stats = _build_import_tree(
        src_root=src_root,
        dst_root=dst_root,
        lm_map=lm_map,
        input_format=args.input_format,
        force=args.force,
    )

    _write_manifest_files(
        dst_root=dst_root,
        source_root=src_root,
        target_root=dst_root,
        stats=stats,
    )

    log.info("Built nsx_import tree successfully")
    log.info("Stats: %s", stats)
    print(
        json.dumps(
            {
                "source_root": str(src_root),
                "target_root": str(dst_root),
                "stats": stats,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()