#!/usr/bin/env python3
# tools/test/push_nsx_object_tree.py

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

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
PUSH_JSONL_PATH: Path | None = None

PUSH_TYPE_ALL = "all"
PUSH_TYPE_SERVICES = "services"
PUSH_TYPE_GROUPS = "groups"
PUSH_TYPE_RULES = "rules"

VALID_PUSH_TYPES = [
    PUSH_TYPE_ALL,
    PUSH_TYPE_SERVICES,
    PUSH_TYPE_GROUPS,
    PUSH_TYPE_RULES,
]


# ------------------------------------------------
# Logging
# ------------------------------------------------

def _setup_logging() -> None:
    global RUN_LOG_PATH, ERROR_LOG_PATH, PUSH_JSONL_PATH

    log_dir = Path(nsx_log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    RUN_LOG_PATH = log_dir / f"push_nsx_object_tree_{ts}.log"
    ERROR_LOG_PATH = log_dir / f"push_nsx_object_tree_errors_{ts}.log"
    PUSH_JSONL_PATH = log_dir / f"push_nsx_object_tree_{ts}.jsonl"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(RUN_LOG_PATH),
            logging.StreamHandler(),
        ],
    )

    log.info("Run log file   : %s", RUN_LOG_PATH)
    log.info("Error log file : %s", ERROR_LOG_PATH)
    log.info("Push JSONL     : %s", PUSH_JSONL_PATH)


def _append_jsonl(path: Path | None, record: Dict[str, Any]) -> None:
    if not path:
        return
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _append_error(domain: str, message: str) -> None:
    record = {
        "domain": domain,
        "error": message,
    }

    if ERROR_LOG_PATH:
        with ERROR_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    _append_jsonl(PUSH_JSONL_PATH, {"action": "error", **record})


# ------------------------------------------------
# Manager helpers
# ------------------------------------------------

def _manager_dirname(mgr: str) -> str:
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


def _resolve_import_root(base_dir: str, manager_name: str) -> Path:
    base = Path(base_dir)
    return base if base.name == manager_name else (base / manager_name)


# ------------------------------------------------
# Tree inspection helpers
# ------------------------------------------------

def _count_files(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(1 for p in root.rglob("*") if p.is_file())


def _discover_domain_dirs(import_root: Path) -> List[str]:
    domains_root = import_root / "domains"
    if not domains_root.exists():
        return []

    domains = sorted(
        p.name
        for p in domains_root.iterdir()
        if p.is_dir()
    )

    _append_jsonl(
        PUSH_JSONL_PATH,
        {
            "action": "discover_domains",
            "import_root": str(import_root),
            "domains": domains,
        },
    )

    return domains


def _has_groups(import_root: Path, domain_id: str) -> bool:
    return _count_files(import_root / "domains" / domain_id / "groups") > 0


def _has_services(import_root: Path, domain_id: str) -> bool:
    return _count_files(import_root / "domains" / domain_id / "services") > 0


def _has_compiled_policies(import_root: Path, domain_id: str) -> bool:
    return _count_files(import_root / "domains" / domain_id / "security-policies_compiled") > 0


def _has_full_domain_content(import_root: Path, domain_id: str) -> bool:
    domain_root = import_root / "domains" / domain_id
    if not domain_root.exists():
        return False

    for sub in ("groups", "services", "security-policies_compiled"):
        if _count_files(domain_root / sub) > 0:
            return True
    return False


def _build_import_order(import_root: Path, requested_domain: str) -> List[str]:
    domains = [d for d in _discover_domain_dirs(import_root) if _has_full_domain_content(import_root, d)]

    non_default = sorted(d for d in domains if d != "default")
    ordered: List[str] = []
    ordered.extend(non_default)

    if requested_domain in domains:
        ordered.append(requested_domain)
    elif requested_domain not in ordered:
        ordered.append(requested_domain)

    seen = set()
    final = []
    for d in ordered:
        if d not in seen:
            final.append(d)
            seen.add(d)

    _append_jsonl(
        PUSH_JSONL_PATH,
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
    import_root: Path,
    domain_id: str,
    input_format: str,
    dry_run: bool,
    continue_on_error: bool,
) -> NsxImporter:
    cfg = ImportConfig(
        export_root=import_root,
        domain_id=domain_id,
        input_format=input_format,
        dry_run=dry_run,
        continue_on_error=continue_on_error,
    )
    return NsxImporter(client=client, cfg=cfg)


def _import_compiled_policies(
    importer: NsxImporter,
    import_root: Path,
    domain_id: str,
) -> Dict[str, Any]:
    """
    Import compiled policy payloads from:
      domains/<domain_id>/security-policies_compiled/*.yaml|json

    Each compiled file is a full policy object with embedded rules.
    """
    compiled_dir = import_root / "domains" / domain_id / "security-policies_compiled"

    stats = {
        "services": 0,
        "groups": 0,
        "policies": 0,
        "rules": 0,
        "skipped": 0,
        "errors": 0,
    }
    errors: List[str] = []

    if not compiled_dir.exists():
        log.info("No compiled policies directory found for domain %s: %s", domain_id, compiled_dir)
        return {"stats": stats, "errors": errors}

    files = importer._iter_files(compiled_dir)
    log.info("Importing compiled policies from %s (%d files)", compiled_dir, len(files))

    for f in files:
        try:
            data = importer._load_file(f)

            pid = data.get("id")
            if not pid:
                raise ValueError("Compiled policy missing id")

            embedded_rules = data.get("rules")
            embedded_rule_count = len(embedded_rules) if isinstance(embedded_rules, list) else 0

            pol_path = importer._policy_path(
                f"/domains/{domain_id}/security-policies/{pid}"
            )

            importer._put_or_patch(pol_path, data)

            stats["policies"] += 1
            stats["rules"] += embedded_rule_count

            _append_jsonl(
                PUSH_JSONL_PATH,
                {
                    "action": "import_compiled_policy",
                    "domain": domain_id,
                    "file": str(f),
                    "policy_id": pid,
                    "embedded_rule_count": embedded_rule_count,
                },
            )

        except Exception as e:
            msg = f"Failed importing compiled policy file {f}: {e}"
            log.exception(msg)
            errors.append(msg)
            stats["errors"] += 1

            if not importer.cfg.continue_on_error:
                raise

    return {
        "stats": stats,
        "errors": errors,
    }


def _run_import_services_only(
    client: NsxPolicyClient,
    import_root: Path,
    domain_id: str,
    input_format: str,
    dry_run: bool,
    continue_on_error: bool,
) -> Dict[str, Any]:
    importer = _make_importer(
        client=client,
        import_root=import_root,
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

    services_dir = import_root / "domains" / domain_id / "services"
    log.info("Services-only import for domain: %s", domain_id)

    if services_dir.exists() and any(p.is_file() for p in services_dir.rglob("*")):
        try:
            before = dict(importer.stats)
            importer.import_services()
            stats["services"] += importer.stats["services"] - before["services"]
            stats["skipped"] += importer.stats["skipped"] - before["skipped"]
            stats["errors"] += importer.stats["errors"] - before["errors"]
        except Exception as exc:
            msg = f"Services-only import failed for domain {domain_id}: {exc}"
            log.exception(msg)
            errors.append(msg)
            stats["errors"] += 1
            if not continue_on_error:
                raise
    else:
        log.info("No services found for domain %s; skipping services-only import", domain_id)

    _append_jsonl(
        PUSH_JSONL_PATH,
        {
            "action": "import_result",
            "mode": "services_only",
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


def _run_import_groups_only(
    client: NsxPolicyClient,
    import_root: Path,
    domain_id: str,
    input_format: str,
    dry_run: bool,
    continue_on_error: bool,
) -> Dict[str, Any]:
    importer = _make_importer(
        client=client,
        import_root=import_root,
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

    domain_root = import_root / "domains" / domain_id
    groups_dir = domain_root / "groups"

    log.info("Groups-only import for domain: %s", domain_id)

    if groups_dir.exists() and any(p.is_file() for p in groups_dir.rglob("*")):
        try:
            result = importer.import_groups()
            if isinstance(result, dict):
                result_stats = result.get("stats", {}) or {}
                result_errors = result.get("errors", []) or []
                stats["groups"] += int(result_stats.get("groups", 0) or 0)
                stats["errors"] += int(result_stats.get("errors", 0) or 0)
                stats["skipped"] += int(result_stats.get("skipped", 0) or 0)
                errors.extend(result_errors)
        except Exception as exc:
            msg = f"Groups-only import failed for domain {domain_id}: {exc}"
            log.exception(msg)
            errors.append(msg)
            stats["errors"] += 1
            if not continue_on_error:
                raise
    else:
        log.info("No groups found for domain %s; skipping groups-only import", domain_id)

    _append_jsonl(
        PUSH_JSONL_PATH,
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


def _run_import_rules_only(
    client: NsxPolicyClient,
    import_root: Path,
    domain_id: str,
    input_format: str,
    dry_run: bool,
    continue_on_error: bool,
) -> Dict[str, Any]:
    importer = _make_importer(
        client=client,
        import_root=import_root,
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

    compiled_dir = import_root / "domains" / domain_id / "security-policies_compiled"
    log.info("Rules-only import for domain: %s", domain_id)

    if compiled_dir.exists() and any(p.is_file() for p in compiled_dir.rglob("*")):
        try:
            result = _import_compiled_policies(
                importer=importer,
                import_root=import_root,
                domain_id=domain_id,
            )
            result_stats = result.get("stats", {}) or {}
            result_errors = result.get("errors", []) or []
            for key in stats:
                stats[key] += int(result_stats.get(key, 0) or 0)
            errors.extend(result_errors)
        except Exception as exc:
            msg = f"Rules-only import failed for domain {domain_id}: {exc}"
            log.exception(msg)
            errors.append(msg)
            stats["errors"] += 1
            if not continue_on_error:
                raise
    else:
        log.info("No compiled policies found for domain %s; skipping rules-only import", domain_id)

    _append_jsonl(
        PUSH_JSONL_PATH,
        {
            "action": "import_result",
            "mode": "rules_only",
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


def _run_import_default_compiled(
    client: NsxPolicyClient,
    import_root: Path,
    domain_id: str,
    input_format: str,
    dry_run: bool,
    continue_on_error: bool,
) -> Dict[str, Any]:
    """
    Full import for the default domain using compiled policies:
      - services
      - groups
      - compiled policies (with embedded rules)
    """
    importer = _make_importer(
        client=client,
        import_root=import_root,
        domain_id=domain_id,
        input_format=input_format,
        dry_run=dry_run,
        continue_on_error=continue_on_error,
    )

    merged_stats = {
        "services": 0,
        "groups": 0,
        "policies": 0,
        "rules": 0,
        "skipped": 0,
        "errors": 0,
    }
    merged_errors: List[str] = []

    # Services
    try:
        before = dict(importer.stats)
        importer.import_services()
        merged_stats["services"] += importer.stats["services"] - before["services"]
        merged_stats["skipped"] += importer.stats["skipped"] - before["skipped"]
        merged_stats["errors"] += importer.stats["errors"] - before["errors"]
    except Exception as exc:
        msg = f"Service import failed for domain {domain_id}: {exc}"
        log.exception(msg)
        merged_errors.append(msg)
        merged_stats["errors"] += 1
        if not continue_on_error:
            raise

    # Groups
    try:
        result = importer.import_groups()
        if isinstance(result, dict):
            result_stats = result.get("stats", {}) or {}
            result_errors = result.get("errors", []) or []
            for key in merged_stats:
                merged_stats[key] += int(result_stats.get(key, 0) or 0)
            merged_errors.extend(result_errors)
    except Exception as exc:
        msg = f"Group import failed for domain {domain_id}: {exc}"
        log.exception(msg)
        merged_errors.append(msg)
        merged_stats["errors"] += 1
        if not continue_on_error:
            raise

    # Compiled Policies
    try:
        result = _import_compiled_policies(
            importer=importer,
            import_root=import_root,
            domain_id=domain_id,
        )
        result_stats = result.get("stats", {}) or {}
        result_errors = result.get("errors", []) or []
        for key in merged_stats:
            merged_stats[key] += int(result_stats.get(key, 0) or 0)
        merged_errors.extend(result_errors)
    except Exception as exc:
        msg = f"Compiled policy import failed for domain {domain_id}: {exc}"
        log.exception(msg)
        merged_errors.append(msg)
        merged_stats["errors"] += 1
        if not continue_on_error:
            raise

    result = {
        "stats": merged_stats,
        "errors": merged_errors,
    }

    _append_jsonl(
        PUSH_JSONL_PATH,
        {
            "action": "import_result",
            "mode": "default_compiled",
            "domain": domain_id,
            "stats": merged_stats,
        },
    )

    for err in merged_errors:
        _append_error(domain_id, err)

    return result


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


def _run_domain_import(
    client: NsxPolicyClient,
    import_root: Path,
    domain_id: str,
    input_format: str,
    dry_run: bool,
    continue_on_error: bool,
    push_type: str,
    federation_global: bool,
) -> Dict[str, Any]:
    """
    Dispatch import behavior by domain + selected push type.

    Federation-global behavior:
      - default domain can import all/services/groups/rules
      - non-default local domains can import groups only
      - services/rules on non-default domains are skipped
    """
    if federation_global and domain_id != "default":
        if push_type == PUSH_TYPE_ALL:
            log.info("Starting groups-only import for local domain: %s", domain_id)
            return _run_import_groups_only(
                client=client,
                import_root=import_root,
                domain_id=domain_id,
                input_format=input_format,
                dry_run=dry_run,
                continue_on_error=continue_on_error,
            )

        if push_type == PUSH_TYPE_GROUPS:
            log.info("Starting groups-only import for local domain: %s", domain_id)
            return _run_import_groups_only(
                client=client,
                import_root=import_root,
                domain_id=domain_id,
                input_format=input_format,
                dry_run=dry_run,
                continue_on_error=continue_on_error,
            )

        log.info(
            "Skipping domain %s for push-type=%s; local domains only support groups in this script",
            domain_id,
            push_type,
        )
        skipped = {
            "stats": {
                "services": 0,
                "groups": 0,
                "policies": 0,
                "rules": 0,
                "skipped": 0,
                "errors": 0,
            },
            "errors": [],
        }
        _append_jsonl(
            PUSH_JSONL_PATH,
            {
                "action": "import_skipped",
                "domain": domain_id,
                "push_type": push_type,
                "reason": "local domain only supports groups in federation-global mode",
            },
        )
        return skipped

    # default domain, or non-federation mode
    if push_type == PUSH_TYPE_ALL:
        log.info("Starting full import for domain: %s", domain_id)
        return _run_import_default_compiled(
            client=client,
            import_root=import_root,
            domain_id=domain_id,
            input_format=input_format,
            dry_run=dry_run,
            continue_on_error=continue_on_error,
        )

    if push_type == PUSH_TYPE_SERVICES:
        log.info("Starting services-only import for domain: %s", domain_id)
        return _run_import_services_only(
            client=client,
            import_root=import_root,
            domain_id=domain_id,
            input_format=input_format,
            dry_run=dry_run,
            continue_on_error=continue_on_error,
        )

    if push_type == PUSH_TYPE_GROUPS:
        log.info("Starting groups-only import for domain: %s", domain_id)
        return _run_import_groups_only(
            client=client,
            import_root=import_root,
            domain_id=domain_id,
            input_format=input_format,
            dry_run=dry_run,
            continue_on_error=continue_on_error,
        )

    if push_type == PUSH_TYPE_RULES:
        log.info("Starting rules-only import for domain: %s", domain_id)
        return _run_import_rules_only(
            client=client,
            import_root=import_root,
            domain_id=domain_id,
            input_format=input_format,
            dry_run=dry_run,
            continue_on_error=continue_on_error,
        )

    raise RuntimeError(f"Unsupported push type: {push_type}")


# ------------------------------------------------
# Main
# ------------------------------------------------

def main() -> None:
    _setup_logging()

    parser = argparse.ArgumentParser(
        description="Push a prebuilt nsx_import tree to an NSX manager using compiled policies."
    )

    parser.add_argument("--target", required=True, help="Target manager alias, e.g. nsx-gm2")
    parser.add_argument("--import-base", default="nsx_import", help="Base import directory")
    parser.add_argument("--domain-id", default="default")
    parser.add_argument("--input-format", default="yaml", choices=["yaml", "json"])
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--stop-on-error", action="store_true")
    parser.add_argument("--federation-global", action="store_true")
    parser.add_argument(
        "--push-type",
        default=PUSH_TYPE_ALL,
        choices=VALID_PUSH_TYPES,
        help="What to push: all, services, groups, or rules",
    )

    args = parser.parse_args()

    init_cli()

    mgr_map = _manager_map()

    if args.target not in mgr_map:
        raise RuntimeError(f"Unknown target manager alias: {args.target}")

    dst_mgr = mgr_map[args.target]
    dst_folder = _manager_dirname(dst_mgr)

    import_root = _resolve_import_root(args.import_base, dst_folder)

    if not import_root.exists():
        raise RuntimeError(
            f"Import root does not exist: {import_root}\n"
            f"Build it first with build_nsx_import_tree.py and compile_nsx_policies.py."
        )

    log.info("Target manager    : %s", dst_mgr)
    log.info("Import root       : %s", import_root)
    log.info("Input format      : %s", args.input_format)
    log.info("Apply changes     : %s", args.apply)
    log.info("Federation global : %s", args.federation_global)
    log.info("Stop on error     : %s", args.stop_on_error)
    log.info("Push type         : %s", args.push_type)

    _append_jsonl(
        PUSH_JSONL_PATH,
        {
            "action": "start",
            "target_manager": dst_mgr,
            "import_root": str(import_root),
            "input_format": args.input_format,
            "apply": args.apply,
            "federation_global": args.federation_global,
            "push_type": args.push_type,
        },
    )

    client = NsxPolicyClient(
        nsxmanager=dst_mgr,
        federation_global=args.federation_global,
    )

    results: List[Dict[str, Any]] = []

    if args.federation_global:
        import_order = _build_import_order(
            import_root=import_root,
            requested_domain=args.domain_id,
        )
        log.info("Federation-global import order: %s", import_order)

        for domain_id in import_order:
            result = _run_domain_import(
                client=client,
                import_root=import_root,
                domain_id=domain_id,
                input_format=args.input_format,
                dry_run=(not args.apply),
                continue_on_error=(not args.stop_on_error),
                push_type=args.push_type,
                federation_global=args.federation_global,
            )

            results.append(result)

            if args.stop_on_error and result.get("errors"):
                log.error("Stopping on first domain error due to --stop-on-error")
                break

        final_result = _merge_results(results)

    else:
        final_result = _run_domain_import(
            client=client,
            import_root=import_root,
            domain_id=args.domain_id,
            input_format=args.input_format,
            dry_run=(not args.apply),
            continue_on_error=(not args.stop_on_error),
            push_type=args.push_type,
            federation_global=args.federation_global,
        )

    log.info("Import finished: %s", final_result)
    print(final_result)


if __name__ == "__main__":
    main()