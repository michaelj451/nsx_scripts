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


def _append_error(domain: str, message: str) -> None:
    record = {
        "domain": domain,
        "error": message,
        "missing_paths": _extract_missing_paths(message),
    }

    if ERROR_LOG_PATH:
        with ERROR_LOG_PATH.open("a") as fh:
            fh.write(json.dumps(record) + "\n")

    _append_jsonl(TRANSLATION_JSONL_PATH, {"action": "error", **record})


def _extract_missing_paths(message: str) -> List[str]:
    return sorted(
        set(
            re.findall(
                r"(/global-infra/[^\s,\]]+|/infra/[^\s,\]]+)",
                message or "",
            )
        )
    )


# ------------------------------------------------
# Manager helpers
# ------------------------------------------------

def _manager_dirname(mgr: str) -> str:
    mgr = (mgr or "").removeprefix("https://").removeprefix("http://").rstrip("/")
    return mgr


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
# Translation logic
# ------------------------------------------------

def _lm_domain_map_from_env() -> Dict[str, str]:
    return {
        _manager_hostname(nsx_lm1): _manager_hostname(nsx_lm3),
        _manager_hostname(nsx_lm2): _manager_hostname(nsx_lm4),
    }


def _translate_string(value: str, lm_domain_map: Dict[str, str]) -> str:
    out = value
    for src, dst in lm_domain_map.items():
        out = out.replace(
            f"/global-infra/domains/{src}/",
            f"/global-infra/domains/{dst}/",
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
    text = path.read_text()
    data = yaml.safe_load(text)

    translated = _translate_obj(data, lm_map, path)

    new_text = yaml.safe_dump(translated, sort_keys=True)

    changed = new_text != text
    if changed:
        path.write_text(new_text)

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
    text = path.read_text()
    data = json.loads(text)

    translated = _translate_obj(data, lm_map, path)

    new_text = json.dumps(translated, indent=2) + "\n"

    changed = new_text != text
    if changed:
        path.write_text(new_text)

    _append_jsonl(
        TRANSLATION_JSONL_PATH,
        {
            "action": "translate_file",
            "file": str(path),
            "changed": changed,
        },
    )

    return changed


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

    log.info("Translated export tree: %s", dst)

    _append_jsonl(
        TRANSLATION_JSONL_PATH,
        {
            "action": "translation_summary",
            "scanned": scanned,
            "changed": changed,
        },
    )

    return dst


# ------------------------------------------------
# Import wrapper
# ------------------------------------------------

def _run_import(
    client: NsxPolicyClient,
    export_root: Path,
    domain_id: str,
    input_format: str,
    dry_run: bool,
    continue_on_error: bool,
) -> Dict[str, Any]:

    cfg = ImportConfig(
        export_root=export_root,
        domain_id=domain_id,
        input_format=input_format,
        dry_run=dry_run,
        continue_on_error=continue_on_error,
    )

    importer = NsxImporter(client=client, cfg=cfg)

    result = importer.import_all()

    _append_jsonl(
        TRANSLATION_JSONL_PATH,
        {
            "action": "import_result",
            "domain": domain_id,
            "stats": result.get("stats", {}),
        },
    )

    for err in result.get("errors", []):
        _append_error(domain_id, err)

    return result


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

    result = _run_import(
        client=client,
        export_root=working_export_root,
        domain_id=args.domain_id,
        input_format=args.input_format,
        dry_run=(not args.apply),
        continue_on_error=(not args.stop_on_error),
    )

    log.info("Import finished: %s", result)
    print(result)


if __name__ == "__main__":
    main()