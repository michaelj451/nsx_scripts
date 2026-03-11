#!/usr/bin/env python3
# tools/test/push_nsx_objects.py

from __future__ import annotations

import argparse
import json
import logging
import shutil
import tempfile
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
)
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_object_functions.nsx_object_importer import ImportConfig, NsxImporter

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _manager_dirname(mgr: str) -> str:
    """
    Convert a manager URL/hostname into the export folder name.
    Example:
      https://nsx-gm1.lab.local -> nsx-gm1.lab.local
    """
    mgr = (mgr or "").strip()
    mgr = mgr.removeprefix("https://").removeprefix("http://").rstrip("/")
    return mgr or "unknown_manager"


def _manager_hostname(mgr: str) -> str:
    """
    Convert manager URL/hostname into bare hostname used inside NSX paths.
    Example:
      https://nsx-lm1.lab.local -> nsx-lm1.lab.local
    """
    mgr = (mgr or "").strip()
    mgr = mgr.removeprefix("https://").removeprefix("http://").rstrip("/")
    return mgr


def _resolve_export_root(base_dir: str, manager_name: str) -> Path:
    """
    Support either:
      nsx_export/<manager_name>
    or directly:
      <some/path/already/pointing/to/manager_name>
    """
    base = Path(base_dir)
    return base if base.name == manager_name else (base / manager_name)


def _manager_map() -> Dict[str, str]:
    return {
        "nsx-gm1": nsx_gm1,
        "nsx-gm2": nsx_gm2,
        "nsx-lm1": nsx_lm1,
        "nsx-lm2": nsx_lm2,
        "nsx-lm3": nsx_lm3,
        "nsx-lm4": nsx_lm4,
    }


def _validate_domain_root(export_root: Path, domain_id: str) -> Path:
    """
    Support both layouts:
      NEW: <export_root>/<domain_id>/...
      OLD: <export_root>/domains/<domain_id>/...
    """
    new_root = export_root / domain_id
    old_root = export_root / "domains" / domain_id

    if new_root.exists():
        return new_root
    if old_root.exists():
        return old_root

    raise RuntimeError(
        "Could not find domain export layout.\n"
        f"Checked:\n"
        f"  - {new_root}\n"
        f"  - {old_root}"
    )


def _domain_root(export_root: Path, domain_id: str) -> Path:
    """
    Return preferred domain root path, whether or not it exists yet.
    Prefer old layout since that is what your current exports are using.
    """
    old_root = export_root / "domains" / domain_id
    new_root = export_root / domain_id
    return old_root if old_root.exists() else new_root


def _lm_domain_map_from_env() -> Dict[str, str]:
    """
    Build LM domain translation map from environment-backed constants.

    Desired behavior:
      nsx-lm1 -> nsx-lm3
      nsx-lm2 -> nsx-lm4
    """
    src1 = _manager_hostname(nsx_lm1)
    src2 = _manager_hostname(nsx_lm2)
    dst1 = _manager_hostname(nsx_lm3)
    dst2 = _manager_hostname(nsx_lm4)

    mapping: Dict[str, str] = {}
    if src1 and dst1:
        mapping[src1] = dst1
    if src2 and dst2:
        mapping[src2] = dst2

    return mapping


def _translate_string(s: str, lm_domain_map: Dict[str, str]) -> str:
    """
    Rewrite NSX global child-domain paths, for example:
      /global-infra/domains/nsx-lm1.lab.local/groups/x
    ->
      /global-infra/domains/nsx-lm3.lab.local/groups/x
    """
    out = s
    for src_domain, dst_domain in lm_domain_map.items():
        src_prefix = f"/global-infra/domains/{src_domain}/"
        dst_prefix = f"/global-infra/domains/{dst_domain}/"
        if src_prefix in out:
            out = out.replace(src_prefix, dst_prefix)
    return out


def _translate_obj(obj: Any, lm_domain_map: Dict[str, str]) -> Any:
    if isinstance(obj, dict):
        return {k: _translate_obj(v, lm_domain_map) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_translate_obj(v, lm_domain_map) for v in obj]
    if isinstance(obj, str):
        return _translate_string(obj, lm_domain_map)
    return obj


def _translate_yaml_file(path: Path, lm_domain_map: Dict[str, str]) -> bool:
    original_text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(original_text)
    translated = _translate_obj(data, lm_domain_map)
    new_text = yaml.safe_dump(
        translated,
        sort_keys=True,
        default_flow_style=False,
        width=120,
        allow_unicode=True,
    )
    if new_text != original_text:
        path.write_text(new_text, encoding="utf-8")
        return True
    return False


def _translate_json_file(path: Path, lm_domain_map: Dict[str, str]) -> bool:
    original_text = path.read_text(encoding="utf-8")
    data = json.loads(original_text)
    translated = _translate_obj(data, lm_domain_map)
    new_text = json.dumps(translated, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if new_text != original_text:
        path.write_text(new_text, encoding="utf-8")
        return True
    return False


def _build_translated_export_tree(src_export_root: Path, lm_domain_map: Dict[str, str]) -> Path:
    """
    Copy the export tree into a temp directory and rewrite all YAML/JSON payloads
    so importer can run unchanged against the translated tree.
    """
    tmp_parent = Path(tempfile.mkdtemp(prefix="nsx_push_translate_"))
    dst_export_root = tmp_parent / src_export_root.name

    shutil.copytree(src_export_root, dst_export_root)

    changed = 0
    scanned = 0

    for path in dst_export_root.rglob("*"):
        if not path.is_file():
            continue

        suffix = path.suffix.lower()
        try:
            if suffix in {".yaml", ".yml"}:
                scanned += 1
                if _translate_yaml_file(path, lm_domain_map):
                    changed += 1
            elif suffix == ".json":
                scanned += 1
                if _translate_json_file(path, lm_domain_map):
                    changed += 1
        except Exception as exc:
            raise RuntimeError(f"Failed translating file {path}: {exc}") from exc

    log.info("Translated export tree  : %s", dst_export_root)
    log.info("Files scanned          : %d", scanned)
    log.info("Files changed          : %d", changed)

    return dst_export_root


def _copy_group_files_same_ids(
    export_root: Path,
    src_domain_id: str,
    dst_domain_id: str,
) -> int:
    """
    Copy group files from source child domain to translated target child domain,
    preserving the exact same group IDs / filenames.

    Example:
      domains/nsx-lm1.lab.local/groups/*.yaml
    ->
      domains/nsx-lm3.lab.local/groups/*.yaml
    """
    src_groups_dir = _domain_root(export_root, src_domain_id) / "groups"
    dst_groups_dir = _domain_root(export_root, dst_domain_id) / "groups"

    if not src_groups_dir.exists():
        log.warning("Source LM groups dir missing: %s", src_groups_dir)
        return 0

    dst_groups_dir.mkdir(parents=True, exist_ok=True)

    copied = 0
    for path in sorted(src_groups_dir.glob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
            continue

        dst_path = dst_groups_dir / path.name
        shutil.copy2(path, dst_path)
        copied += 1

    return copied


def _prepare_translated_lm_group_domains(
    translated_export_root: Path,
    lm_domain_map: Dict[str, str],
) -> List[str]:
    """
    For each source LM domain, copy its groups directory to the translated target LM domain.
    Group IDs stay exactly the same.

    Returns list of target LM domain IDs to import first.
    """
    target_domains: List[str] = []

    for src_domain, dst_domain in lm_domain_map.items():
        copied = _copy_group_files_same_ids(
            export_root=translated_export_root,
            src_domain_id=src_domain,
            dst_domain_id=dst_domain,
        )
        if copied > 0:
            target_domains.append(dst_domain)
            log.info(
                "Prepared translated LM groups: %s -> %s (%d files)",
                src_domain,
                dst_domain,
                copied,
            )
        else:
            log.warning(
                "No LM group files copied for %s -> %s. "
                "If the source export does not include child-domain groups, rules will still fail.",
                src_domain,
                dst_domain,
            )

    return target_domains


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
    return importer.import_all()


def _merge_results(results: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
    merged_stats: Dict[str, int] = {
        "services": 0,
        "groups": 0,
        "policies": 0,
        "rules": 0,
        "skipped": 0,
        "errors": 0,
    }
    merged_errors: List[str] = []

    for domain_id, result in results:
        stats = result.get("stats", {})
        for key in merged_stats:
            merged_stats[key] += int(stats.get(key, 0))

        for err in result.get("errors", []):
            merged_errors.append(f"[domain={domain_id}] {err}")

    return {"stats": merged_stats, "errors": merged_errors}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import NSX objects from exported YAML/JSON into a target NSX manager"
    )
    parser.add_argument(
        "--source",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        required=True,
        help="Manager name used only to locate the export folder on disk",
    )
    parser.add_argument(
        "--target",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        required=True,
        help="Target NSX manager to push objects into",
    )
    parser.add_argument(
        "--base-dir",
        default="nsx_export",
        help="Base export directory, usually nsx_export",
    )
    parser.add_argument(
        "--domain-id",
        default="default",
        help="NSX domain id to import into",
    )
    parser.add_argument(
        "--input-format",
        choices=["yaml", "json"],
        default="yaml",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually push changes. Default is dry-run.",
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop immediately on first error",
    )
    parser.add_argument(
        "--federation-global",
        action="store_true",
        help="Use global/federation paths for GM imports",
    )
    parser.add_argument(
        "--no-lm-translate",
        action="store_true",
        help="Disable LM domain translation (default is enabled)",
    )

    args = parser.parse_args()

    init_cli()

    mgr_map = _manager_map()

    src_mgr = mgr_map.get(args.source)
    dst_mgr = mgr_map.get(args.target)

    if not src_mgr:
        raise RuntimeError(f"Source manager env var not set for {args.source}")
    if not dst_mgr:
        raise RuntimeError(f"Target manager env var not set for {args.target}")

    src_folder = _manager_dirname(src_mgr)
    export_root = _resolve_export_root(args.base_dir, src_folder)

    if not export_root.exists():
        raise RuntimeError(f"Export root does not exist: {export_root}")

    domain_root = _validate_domain_root(export_root, args.domain_id)

    log.info("Source alias        : %s", args.source)
    log.info("Source export folder: %s", export_root)
    log.info("Resolved domain root: %s", domain_root)
    log.info("Target alias        : %s", args.target)
    log.info("Target manager      : %s", dst_mgr)
    log.info("Federation global   : %s", args.federation_global)
    log.info("Mode                : %s", "APPLY" if args.apply else "DRY-RUN")

    working_export_root = export_root
    lm_target_domains_to_import: List[str] = []

    if args.federation_global and not args.no_lm_translate:
        lm_domain_map = _lm_domain_map_from_env()
        log.info("LM domain map       : %s", lm_domain_map or "<empty>")

        if lm_domain_map:
            working_export_root = _build_translated_export_tree(export_root, lm_domain_map)
            lm_target_domains_to_import = _prepare_translated_lm_group_domains(
                translated_export_root=working_export_root,
                lm_domain_map=lm_domain_map,
            )
        else:
            log.warning("LM translation requested but LM env map is empty; using original export tree")
    else:
        if args.no_lm_translate:
            log.info("LM translation      : disabled by flag")
        else:
            log.info("LM translation      : skipped (not federation-global mode)")

    client = NsxPolicyClient(
        nsxmanager=dst_mgr,
        federation_global=args.federation_global,
    )

    all_results: List[Tuple[str, Dict[str, Any]]] = []

    # -----------------------------------------------------------------------
    # Step 1: import translated LM child-domain groups first
    # -----------------------------------------------------------------------
    for lm_domain_id in lm_target_domains_to_import:
        try:
            lm_domain_root = _validate_domain_root(working_export_root, lm_domain_id)
            log.info("Pre-import LM domain : %s (%s)", lm_domain_id, lm_domain_root)

            result = _run_import(
                client=client,
                export_root=working_export_root,
                domain_id=lm_domain_id,
                input_format=args.input_format,
                dry_run=(not args.apply),
                continue_on_error=(not args.stop_on_error),
            )
            all_results.append((lm_domain_id, result))
        except Exception as exc:
            msg = f"Failed LM pre-import for domain {lm_domain_id}: {exc}"
            log.error(msg)
            if args.stop_on_error:
                raise
            all_results.append((
                lm_domain_id,
                {"stats": {"services": 0, "groups": 0, "policies": 0, "rules": 0, "skipped": 0, "errors": 1},
                 "errors": [msg]}
            ))

    # -----------------------------------------------------------------------
    # Step 2: import requested main domain (usually default)
    # -----------------------------------------------------------------------
    result = _run_import(
        client=client,
        export_root=working_export_root,
        domain_id=args.domain_id,
        input_format=args.input_format,
        dry_run=(not args.apply),
        continue_on_error=(not args.stop_on_error),
    )
    all_results.append((args.domain_id, result))

    merged = _merge_results(all_results)

    log.info("Import complete. Stats=%s Errors=%d", merged["stats"], len(merged["errors"]))
    print(merged)


if __name__ == "__main__":
    main()