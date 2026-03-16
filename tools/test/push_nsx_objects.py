#!/usr/bin/env python3
# tools/test/push_nsx_objects.py

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

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
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_object_functions.nsx_object_importer import ImportConfig, NsxImporter

log = logging.getLogger(__name__)

RUN_LOG_PATH: Path | None = None
ERROR_LOG_PATH: Path | None = None
TRANSLATION_JSONL_PATH: Path | None = None


# ------------------------------------------------
# Logging
# ------------------------------------------------

def _setup_logging() -> None:
    global RUN_LOG_PATH, ERROR_LOG_PATH, TRANSLATION_JSONL_PATH

    log_dir = Path(nsx_log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    RUN_LOG_PATH = log_dir / f"push_nsx_objects_{ts}.log"
    ERROR_LOG_PATH = log_dir / f"push_nsx_objects_errors_{ts}.log"
    TRANSLATION_JSONL_PATH = log_dir / f"push_nsx_objects_translations_{ts}.jsonl"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(RUN_LOG_PATH),
            logging.StreamHandler(),
        ],
    )

    log.info("Run log file      : %s", RUN_LOG_PATH)
    log.info("Error log file    : %s", ERROR_LOG_PATH)
    log.info("Translation JSONL : %s", TRANSLATION_JSONL_PATH)


def _append_jsonl(path: Path | None, record: Dict[str, Any]) -> None:
    if not path:
        return
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _extract_missing_paths(message: str) -> List[str]:
    return sorted(
        set(
            re.findall(
                r"(/global-infra/[^\s,\]]+|/infra/[^\s,\]]+)",
                message or "",
            )
        )
    )


def _append_error(domain: str, message: str) -> None:
    record = {
        "domain": domain,
        "error": message,
        "missing_paths": _extract_missing_paths(message),
    }

    if ERROR_LOG_PATH:
        with ERROR_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    _append_jsonl(TRANSLATION_JSONL_PATH, {"action": "error", **record})


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


def _resolve_export_root(base_dir: str, manager_name: str) -> Path:
    base = Path(base_dir)
    return base if base.name == manager_name else (base / manager_name)


# ------------------------------------------------
# Translation / mapping helpers
# ------------------------------------------------

def _lm_domain_map_from_env() -> Dict[str, str]:
    """
    Map source LM domain names to destination LM domain names.
    """
    return {
        _manager_hostname(nsx_lm1): _manager_hostname(nsx_lm3),
        _manager_hostname(nsx_lm2): _manager_hostname(nsx_lm4),
    }


def _translate_string(value: str, lm_domain_map: Dict[str, str]) -> str:
    """
    Translate all occurrences of source LM domain paths inside arbitrary strings.
    Keeps object IDs unchanged.
    """
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
        # Also catch exact domain path occurrences without trailing object type
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
    if "/security-policies/" in value:
        return "policy"
    if "/rules/" in value:
        return "rule"
    if "/domains/" in value:
        return "domain"
    return "string"


def _translate_obj(obj: Any, lm_map: Dict[str, str], file: Path) -> Any:
    if isinstance(obj, dict):
        return {k: _translate_obj(v, lm_map, file) for k, v in obj.items()}

    if isinstance(obj, list):
        return [_translate_obj(v, lm_map, file) for v in obj]

    if isinstance(obj, str):
        new_val = _translate_string(obj, lm_map)
        if new_val != obj:
            _append_jsonl(
                TRANSLATION_JSONL_PATH,
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


def _translate_yaml_file(path: Path, lm_map: Dict[str, str]) -> bool:
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)

    translated = _translate_obj(data, lm_map, path)

    new_text = yaml.safe_dump(translated, sort_keys=True)

    changed = new_text != text
    if changed:
        path.write_text(new_text, encoding="utf-8")

    _append_jsonl(
        TRANSLATION_JSONL_PATH,
        {
            "action": "translate_file",
            "file": str(path),
            "changed": changed,
        },
    )

    return changed


def _translate_json_file(path: Path, lm_map: Dict[str, str]) -> bool:
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)

    translated = _translate_obj(data, lm_map, path)

    new_text = json.dumps(translated, indent=2) + "\n"

    changed = new_text != text
    if changed:
        path.write_text(new_text, encoding="utf-8")

    _append_jsonl(
        TRANSLATION_JSONL_PATH,
        {
            "action": "translate_file",
            "file": str(path),
            "changed": changed,
        },
    )

    return changed


def _rename_translated_domain_dirs(dst_root: Path, lm_map: Dict[str, str]) -> None:
    """
    Rename copied domain directories from source LM names to destination LM names.
    This is critical so the importer resolves the correct target domain IDs.
    """
    domains_root = dst_root / "domains"
    if not domains_root.exists():
        return

    for src, dst in lm_map.items():
        src_dir = domains_root / src
        dst_dir = domains_root / dst

        if src_dir.exists():
            if dst_dir.exists():
                raise RuntimeError(
                    f"Refusing to rename domain dir because destination already exists: "
                    f"{src_dir} -> {dst_dir}"
                )

            src_dir.rename(dst_dir)

            _append_jsonl(
                TRANSLATION_JSONL_PATH,
                {
                    "action": "rename_domain_dir",
                    "old": str(src_dir),
                    "new": str(dst_dir),
                },
            )


def _build_translated_export_tree(src: Path, lm_map: Dict[str, str]) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="nsx_push_translate_"))
    dst = tmp / src.name

    shutil.copytree(src, dst)

    scanned = 0
    changed = 0

    for f in dst.rglob("*"):
        if not f.is_file():
            continue

        scanned += 1

        if f.suffix in [".yaml", ".yml"]:
            if _translate_yaml_file(f, lm_map):
                changed += 1
        elif f.suffix == ".json":
            if _translate_json_file(f, lm_map):
                changed += 1

    _rename_translated_domain_dirs(dst, lm_map)

    log.info("Translated export tree: %s", dst)

    _append_jsonl(
        TRANSLATION_JSONL_PATH,
        {
            "action": "translation_summary",
            "export_root": str(dst),
            "scanned": scanned,
            "changed": changed,
        },
    )

    return dst


# ------------------------------------------------
# Domain discovery / import ordering
# ------------------------------------------------

def _discover_domain_dirs(export_root: Path) -> List[str]:
    domains_root = export_root / "domains"
    if not domains_root.exists():
        return []

    domains = sorted(
        p.name
        for p in domains_root.iterdir()
        if p.is_dir()
    )

    _append_jsonl(
        TRANSLATION_JSONL_PATH,
        {
            "action": "discover_domains",
            "export_root": str(export_root),
            "domains": domains,
        },
    )

    return domains


def _count_files(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(1 for p in root.rglob("*") if p.is_file())


def _has_groups(export_root: Path, domain_id: str) -> bool:
    return _count_files(export_root / "domains" / domain_id / "groups") > 0


def _has_full_domain_content(export_root: Path, domain_id: str) -> bool:
    domain_root = export_root / "domains" / domain_id
    if not domain_root.exists():
        return False

    for sub in ("groups", "services", "security-policies"):
        if _count_files(domain_root / sub) > 0:
            return True

    return False


def _build_import_order(export_root: Path, requested_domain: str) -> List[str]:
    """
    Import all non-default domains first, then requested_domain (usually default).
    After directory renaming, these should already be destination LM domain names.
    """
    domains = [d for d in _discover_domain_dirs(export_root) if _has_full_domain_content(export_root, d)]

    non_default = sorted(d for d in domains if d != "default")
    ordered: List[str] = []
    ordered.extend(non_default)

    if requested_domain in domains:
        ordered.append(requested_domain)
    elif requested_domain not in ordered:
        ordered.append(requested_domain)

    # de-dupe preserving order
    seen = set()
    final = []
    for d in ordered:
        if d not in seen:
            final.append(d)
            seen.add(d)

    _append_jsonl(
        TRANSLATION_JSONL_PATH,
        {
            "action": "import_order",
            "requested_domain": requested_domain,
            "order": final,
        },
    )

    return final


# ------------------------------------------------
# Import routines
# ------------------------------------------------

def _make_importer(
    client: NsxPolicyClient,
    export_root: Path,
    domain_id: str,
    input_format: str,
    dry_run: bool,
    continue_on_error: bool,
) -> NsxImporter:
    cfg = ImportConfig(
        export_root=export_root,
        domain_id=domain_id,
        input_format=input_format,
        dry_run=dry_run,
        continue_on_error=continue_on_error,
    )
    return NsxImporter(client=client, cfg=cfg)


def _run_import_all(
    client: NsxPolicyClient,
    export_root: Path,
    domain_id: str,
    input_format: str,
    dry_run: bool,
    continue_on_error: bool,
) -> Dict[str, Any]:
    importer = _make_importer(
        client=client,
        export_root=export_root,
        domain_id=domain_id,
        input_format=input_format,
        dry_run=dry_run,
        continue_on_error=continue_on_error,
    )

    result = importer.import_all()

    _append_jsonl(
        TRANSLATION_JSONL_PATH,
        {
            "action": "import_result",
            "mode": "full",
            "domain": domain_id,
            "stats": result.get("stats", {}),
        },
    )

    for err in result.get("errors", []) or []:
        _append_error(domain_id, err)

    return result


def _run_import_groups_only(
    client: NsxPolicyClient,
    export_root: Path,
    domain_id: str,
    input_format: str,
    dry_run: bool,
    continue_on_error: bool,
) -> Dict[str, Any]:
    """
    Import only groups for local domains first.
    This avoids trying to push local policies you probably do not need.
    """
    importer = _make_importer(
        client=client,
        export_root=export_root,
        domain_id=domain_id,
        input_format=input_format,
        dry_run=dry_run,
        continue_on_error=continue_on_error,
    )

    stats = {
        "services": 0,
        "groups": 0,
        "policies": 0,
        "rules": 0,
        "skipped": 0,
        "errors": 0,
    }
    errors: List[str] = []

    domain_root = export_root / "domains" / domain_id
    groups_dir = domain_root / "groups"

    log.info("Groups-only import for domain: %s", domain_id)

    if groups_dir.exists() and any(p.is_file() for p in groups_dir.rglob("*")):
        try:
            # This assumes NsxImporter has this method, which is likely based on your logs.
            # If your importer uses a different method name, adjust this single line.
            result = importer.import_groups()
            if isinstance(result, dict):
                result_stats = result.get("stats", {}) or {}
                result_errors = result.get("errors", []) or []
                stats["groups"] += int(result_stats.get("groups", 0) or 0)
                stats["errors"] += int(result_stats.get("errors", 0) or 0)
                errors.extend(result_errors)
            else:
                # Defensive fallback in case import_groups returns None
                pass
        except Exception as exc:
            msg = f"Groups-only import failed for domain {domain_id}: {exc}"
            log.exception(msg)
            errors.append(msg)
            stats["errors"] += 1
    else:
        log.info("No groups found for domain %s; skipping groups-only import", domain_id)

    _append_jsonl(
        TRANSLATION_JSONL_PATH,
        {
            "action": "import_result",
            "mode": "groups_only",
            "domain": domain_id,
            "stats": stats,
        },
    )

    for err in errors:
        _append_error(domain_id, err)

    return {
        "stats": stats,
        "errors": errors,
    }


def _merge_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    merged_stats: Dict[str, int] = {
        "services": 0,
        "groups": 0,
        "policies": 0,
        "rules": 0,
        "skipped": 0,
        "errors": 0,
    }
    merged_errors: List[str] = []

    for result in results:
        stats = result.get("stats", {}) or {}
        for key in merged_stats:
            merged_stats[key] += int(stats.get(key, 0) or 0)
        merged_errors.extend(result.get("errors", []) or [])

    return {
        "stats": merged_stats,
        "errors": merged_errors,
    }


# ------------------------------------------------
# Main
# ------------------------------------------------

def main() -> None:
    _setup_logging()

    parser = argparse.ArgumentParser()

    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)

    parser.add_argument("--base-dir", default="nsx_export")
    parser.add_argument("--domain-id", default="default")

    parser.add_argument("--input-format", default="yaml")
    parser.add_argument("--apply", action="store_true")

    parser.add_argument("--stop-on-error", action="store_true")
    parser.add_argument("--federation-global", action="store_true")

    parser.add_argument("--no-lm-translate", action="store_true")

    args = parser.parse_args()

    init_cli()

    mgr_map = _manager_map()

    src_mgr = mgr_map[args.source]
    dst_mgr = mgr_map[args.target]

    src_folder = _manager_dirname(src_mgr)
    export_root = _resolve_export_root(args.base_dir, src_folder)
    working_export_root = export_root

    if args.federation_global and not args.no_lm_translate:
        lm_map = _lm_domain_map_from_env()
        working_export_root = _build_translated_export_tree(
            export_root,
            lm_map,
        )

    client = NsxPolicyClient(
        nsxmanager=dst_mgr,
        federation_global=args.federation_global,
    )

    results: List[Dict[str, Any]] = []

    if args.federation_global:
        import_order = _build_import_order(
            export_root=working_export_root,
            requested_domain=args.domain_id,
        )
        log.info("Federation-global import order: %s", import_order)

        for domain_id in import_order:
            if domain_id == "default":
                log.info("Starting full import for domain: %s", domain_id)
                result = _run_import_all(
                    client=client,
                    export_root=working_export_root,
                    domain_id=domain_id,
                    input_format=args.input_format,
                    dry_run=(not args.apply),
                    continue_on_error=(not args.stop_on_error),
                )
            else:
                log.info("Starting groups-only import for local domain: %s", domain_id)
                result = _run_import_groups_only(
                    client=client,
                    export_root=working_export_root,
                    domain_id=domain_id,
                    input_format=args.input_format,
                    dry_run=(not args.apply),
                    continue_on_error=(not args.stop_on_error),
                )

            results.append(result)

            if args.stop_on_error and result.get("errors"):
                log.error("Stopping on first domain error due to --stop-on-error")
                break

        final_result = _merge_results(results)

    else:
        final_result = _run_import_all(
            client=client,
            export_root=working_export_root,
            domain_id=args.domain_id,
            input_format=args.input_format,
            dry_run=(not args.apply),
            continue_on_error=(not args.stop_on_error),
        )

    log.info("Import finished: %s", final_result)
    print(final_result)


if __name__ == "__main__":
    main()