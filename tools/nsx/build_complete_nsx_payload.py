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


def setup_logging() -> Path:
    log_dir = Path(nsx_log_dir).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / f"build_complete_nsx_payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )

    return log_file


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
    log_file = setup_logging()

    source_manager_dir = Path(args.source_manager_dir).expanduser().resolve()
    additive_groups_dir = Path(args.additive_groups_dir).expanduser().resolve()
    build_dir = Path(args.build_dir).expanduser().resolve()

    source_domain_dir = source_manager_dir / "domains" / args.domain_id
    build_domain_dir = build_dir / "domains" / args.domain_id

    if not source_domain_dir.exists():
        raise RuntimeError(f"Source domain directory does not exist: {source_domain_dir}")

    if not additive_groups_dir.exists():
        raise RuntimeError(f"Additive groups directory does not exist: {additive_groups_dir}")

    if build_dir.exists():
        if not args.overwrite:
            raise RuntimeError(
                f"Build dir already exists: {build_dir}\n"
                f"Re-run with --overwrite to replace it."
            )

        log.info("Deleting existing build dir: %s", build_dir)
        shutil.rmtree(build_dir)

    build_domain_dir.mkdir(parents=True, exist_ok=True)

    # Copy meta if it exists
    for meta_name in ("meta.yaml", "meta.yml", "meta.json"):
        src_meta = source_manager_dir / meta_name
        if src_meta.exists():
            dst_meta = build_dir / meta_name
            log.info("Copying meta %s -> %s", src_meta, dst_meta)
            shutil.copy2(src_meta, dst_meta)

    # Copy services from source export
    services_src = source_domain_dir / "services"
    services_dst = build_domain_dir / "services"
    copy_tree(services_src, services_dst, required=False)

    # Copy security policies/rules from source export
    policies_src = source_domain_dir / "security-policies"
    policies_dst = build_domain_dir / "security-policies"
    copy_tree(policies_src, policies_dst, required=False)

    # Overlay additive groups last
    groups_dst = build_domain_dir / "groups"
    copy_tree(additive_groups_dir, groups_dst, required=True)

    result = {
        "source_manager_dir": str(source_manager_dir),
        "additive_groups_dir": str(additive_groups_dir),
        "build_dir": str(build_dir),
        "domain_id": args.domain_id,
        "counts": {
            "groups": count_files(groups_dst),
            "services": count_files(services_dst),
            "security_policy_files": count_files(policies_dst),
        },
        "log_file": str(log_file),
    }

    log.info("Build complete: %s", build_dir)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()