#!/usr/bin/env python3
# tools/test/compile_nsx_policies.py

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

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


# ------------------------------------------------
# Logging
# ------------------------------------------------

def _setup_logging() -> None:
    global RUN_LOG_PATH, MANIFEST_JSONL_PATH

    log_dir = Path(nsx_log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    RUN_LOG_PATH = log_dir / f"compile_nsx_policies_{ts}.log"
    MANIFEST_JSONL_PATH = log_dir / f"compile_nsx_policies_{ts}.jsonl"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(RUN_LOG_PATH),
            logging.StreamHandler(),
        ],
    )

    log.info("Run log file   : %s", RUN_LOG_PATH)
    log.info("Manifest JSONL : %s", MANIFEST_JSONL_PATH)


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
# File helpers
# ------------------------------------------------

def _load_file(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")

    if path.suffix.lower() in (".yaml", ".yml"):
        data = yaml.safe_load(text)
    elif path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        raise ValueError(f"Unsupported file type: {path}")

    if not isinstance(data, dict):
        raise ValueError(f"Expected object/dict in file: {path}")

    return data


def _write_file(path: Path, data: Dict[str, Any], fmt: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        text = json.dumps(data, indent=2) + "\n"
    else:
        text = yaml.safe_dump(data, sort_keys=False)

    path.write_text(text, encoding="utf-8")


def _iter_files(root: Path, input_format: str) -> List[Path]:
    if not root.exists():
        return []

    exts = (".yaml", ".yml") if input_format == "yaml" else (".json",)
    return sorted(
        p for p in root.iterdir()
        if p.is_file() and p.suffix.lower() in exts
    )


# ------------------------------------------------
# Rule ordering
# ------------------------------------------------

def _load_rules_order(policy_dir: Path, input_format: str) -> Optional[List[str]]:
    order_file = policy_dir / f"rules_order.{input_format}"
    if not order_file.exists():
        return None

    try:
        data = _load_file(order_file)
        rules = data.get("rules")
        return rules if isinstance(rules, list) else None
    except Exception as e:
        log.warning("Failed to read %s: %s", order_file, e)
        return None


def _sort_rule_files(rule_files: List[Path], explicit_order: Optional[List[str]]) -> List[Path]:
    if not explicit_order:
        return rule_files

    order_index = {rid: idx for idx, rid in enumerate(explicit_order)}

    def _key(path: Path):
        try:
            rule = _load_file(path)
            rid = rule.get("id")
            if rid in order_index:
                return (0, order_index[rid], path.name)
            return (1, 999999, path.name)
        except Exception:
            return (2, 999999, path.name)

    return sorted(rule_files, key=_key)


# ------------------------------------------------
# Compile logic
# ------------------------------------------------

def _compile_policy_dir(
    policy_dir: Path,
    domain_id: str,
    input_format: str,
    output_format: str,
    force: bool,
) -> Dict[str, Any]:
    policy_file = policy_dir / f"policy.{input_format}"
    if not policy_file.exists():
        raise RuntimeError(f"Missing policy file: {policy_file}")

    policy = _load_file(policy_file)
    policy_id = policy.get("id")
    if not policy_id:
        raise ValueError(f"Policy missing id: {policy_file}")

    rules_dir = policy_dir / "rules"
    explicit_order = _load_rules_order(policy_dir, input_format)

    rule_files = _iter_files(rules_dir, input_format) if rules_dir.exists() else []
    rule_files = _sort_rule_files(rule_files, explicit_order)

    compiled_rules: List[Dict[str, Any]] = []
    for rf in rule_files:
        rule = _load_file(rf)
        rid = rule.get("id")
        if not rid:
            log.warning("Skipping rule file with missing id: %s", rf)
            continue
        compiled_rules.append(rule)

    compiled_policy = dict(policy)
    compiled_policy["rules"] = compiled_rules

    return {
        "policy_id": policy_id,
        "domain_id": domain_id,
        "policy_dir": policy_dir,
        "compiled_policy": compiled_policy,
        "rule_count": len(compiled_rules),
    }


def _compile_domain(
    domain_root: Path,
    input_format: str,
    output_format: str,
    force: bool,
) -> Dict[str, Any]:
    security_policies_root = domain_root / "security-policies"
    compiled_root = domain_root / "security-policies_compiled"

    if compiled_root.exists() and force:
        for old in compiled_root.iterdir():
            if old.is_file():
                old.unlink()

    compiled_root.mkdir(parents=True, exist_ok=True)

    if not security_policies_root.exists():
        return {
            "domain": domain_root.name,
            "compiled_policies": 0,
            "compiled_rules": 0,
        }

    policy_dirs = sorted(p for p in security_policies_root.iterdir() if p.is_dir())

    compiled_policies = 0
    compiled_rules = 0

    for policy_dir in policy_dirs:
        result = _compile_policy_dir(
            policy_dir=policy_dir,
            domain_id=domain_root.name,
            input_format=input_format,
            output_format=output_format,
            force=force,
        )

        policy_id = result["policy_id"]
        compiled_policy = result["compiled_policy"]
        rule_count = result["rule_count"]

        suffix = "json" if output_format == "json" else "yaml"
        out_file = compiled_root / f"{policy_id}.{suffix}"

        if out_file.exists() and not force:
            raise RuntimeError(
                f"Compiled policy file already exists: {out_file}\n"
                f"Use --force to overwrite."
            )

        _write_file(out_file, compiled_policy, output_format)

        compiled_policies += 1
        compiled_rules += rule_count

        _append_jsonl(
            MANIFEST_JSONL_PATH,
            {
                "action": "compile_policy",
                "domain": domain_root.name,
                "policy_id": policy_id,
                "policy_dir": str(policy_dir),
                "output_file": str(out_file),
                "rule_count": rule_count,
            },
        )

    return {
        "domain": domain_root.name,
        "compiled_policies": compiled_policies,
        "compiled_rules": compiled_rules,
    }


def _write_summary(import_root: Path, domain_summaries: List[Dict[str, Any]]) -> None:
    manifests_dir = import_root / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "import_root": str(import_root),
        "domains": domain_summaries,
        "totals": {
            "compiled_policies": sum(d["compiled_policies"] for d in domain_summaries),
            "compiled_rules": sum(d["compiled_rules"] for d in domain_summaries),
        },
    }

    (manifests_dir / "compiled_policy_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )

    _append_jsonl(
        MANIFEST_JSONL_PATH,
        {
            "action": "write_summary",
            "summary_file": str(manifests_dir / "compiled_policy_summary.json"),
        },
    )


# ------------------------------------------------
# Main
# ------------------------------------------------

def main() -> None:
    _setup_logging()

    parser = argparse.ArgumentParser(
        description="Compile NSX policy directories into single policy payload files with embedded rules."
    )

    parser.add_argument("--target", required=True, help="Target manager alias, e.g. nsx-gm2")
    parser.add_argument("--import-base", default="nsx_import", help="Base import directory")
    parser.add_argument("--input-format", default="yaml", choices=["yaml", "json"])
    parser.add_argument("--output-format", default="yaml", choices=["yaml", "json"])
    parser.add_argument("--force", action="store_true")

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
            f"Build it first with build_nsx_import_tree.py."
        )

    domains_root = import_root / "domains"
    if not domains_root.exists():
        raise RuntimeError(f"Missing domains directory under import root: {domains_root}")

    log.info("Import root     : %s", import_root)
    log.info("Input format    : %s", args.input_format)
    log.info("Output format   : %s", args.output_format)
    log.info("Force overwrite : %s", args.force)

    _append_jsonl(
        MANIFEST_JSONL_PATH,
        {
            "action": "start",
            "import_root": str(import_root),
            "input_format": args.input_format,
            "output_format": args.output_format,
            "force": args.force,
        },
    )

    domain_summaries: List[Dict[str, Any]] = []

    for domain_dir in sorted(p for p in domains_root.iterdir() if p.is_dir()):
        summary = _compile_domain(
            domain_root=domain_dir,
            input_format=args.input_format,
            output_format=args.output_format,
            force=args.force,
        )
        domain_summaries.append(summary)
        log.info(
            "Compiled domain %s: %s policies, %s rules",
            summary["domain"],
            summary["compiled_policies"],
            summary["compiled_rules"],
        )

    _write_summary(import_root, domain_summaries)

    result = {
        "import_root": str(import_root),
        "domains": domain_summaries,
        "totals": {
            "compiled_policies": sum(d["compiled_policies"] for d in domain_summaries),
            "compiled_rules": sum(d["compiled_rules"] for d in domain_summaries),
        },
    }

    log.info("Policy compilation finished: %s", result["totals"])
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()