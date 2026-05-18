#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_log_dir

log = logging.getLogger(__name__)


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