#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.nsx_policy_client import NsxPolicyClient

try:
    import yaml
except ImportError:
    yaml = None


THROTTLE_SECONDS = 0.2
log = logging.getLogger(__name__)


def setup_logging() -> Path:
    log_dir = Path(nsx_log_dir).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / f"push_complete_nsx_payload_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )
    return log_file


def load_file(path: Path) -> Dict[str, Any]:
    if path.suffix.lower() in (".yaml", ".yml"):
        if yaml is None:
            raise RuntimeError("PyYAML is required")
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    return json.loads(path.read_text(encoding="utf-8"))


def iter_files(path: Path) -> Iterable[Path]:
    if not path.exists():
        return []
    files: List[Path] = []
    for ext in ("*.yaml", "*.yml", "*.json"):
        files.extend(path.rglob(ext))
    return sorted(files)


def sanitize_for_put(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove NSX read-only / realization fields before PUT/PATCH.
    """
    strip_keys = {
        "_create_time",
        "_create_user",
        "_last_modified_time",
        "_last_modified_user",
        "_system_owned",
        "_protection",
        "_revision",
        "revision",
        "unique_id",
        "realization_id",
        "owner_id",
        "origin_site_id",
        "remote_path",
        "status",
        "children",
    }

    def walk(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items() if k not in strip_keys}
        if isinstance(x, list):
            return [walk(i) for i in x]
        return x

    return walk(obj)


def push_services(client: NsxPolicyClient, domain_dir: Path, dry_run: bool) -> int:
    services_dir = domain_dir / "services"
    count = 0

    for f in iter_files(services_dir):
        obj = sanitize_for_put(load_file(f))
        service_id = obj.get("id")

        if not service_id:
            log.warning("Skipping service without id: %s", f)
            continue

        log.info("%s service: %s", "DRY-RUN would push" if dry_run else "Pushing", service_id)

        if not dry_run:
            client.put_service(service_id, obj)
            time.sleep(THROTTLE_SECONDS)

        count += 1

    return count


def push_groups(client: NsxPolicyClient, domain_dir: Path, domain_id: str, dry_run: bool) -> int:
    groups_dir = domain_dir / "groups"
    count = 0

    for f in iter_files(groups_dir):
        obj = sanitize_for_put(load_file(f))
        group_id = obj.get("id")

        if not group_id:
            log.warning("Skipping group without id: %s", f)
            continue

        log.info("%s group: %s", "DRY-RUN would push" if dry_run else "Pushing", group_id)

        if not dry_run:
            client.put_group(group_id, obj, domain_id=domain_id)
            time.sleep(THROTTLE_SECONDS)

        count += 1

    return count


def push_policies_and_rules(client: NsxPolicyClient, domain_dir: Path, domain_id: str, dry_run: bool) -> dict:
    policies_dir = domain_dir / "security-policies"
    policies_count = 0
    rules_count = 0

    if not policies_dir.exists():
        return {"policies": 0, "rules": 0}

    for policy_dir in sorted(p for p in policies_dir.iterdir() if p.is_dir()):
        policy_file = None
        for candidate in ("policy.yaml", "policy.yml", "policy.json"):
            p = policy_dir / candidate
            if p.exists():
                policy_file = p
                break

        if not policy_file:
            continue

        policy = sanitize_for_put(load_file(policy_file))
        policy_id = policy.get("id")

        if not policy_id:
            log.warning("Skipping policy without id: %s", policy_file)
            continue

        log.info("%s policy: %s", "DRY-RUN would push" if dry_run else "Pushing", policy_id)

        if not dry_run:
            client.put_security_policy(policy_id, policy, domain_id=domain_id)
            time.sleep(THROTTLE_SECONDS)

        policies_count += 1

        rules_dir = policy_dir / "rules"
        for rule_file in iter_files(rules_dir):
            rule = sanitize_for_put(load_file(rule_file))
            rule_id = rule.get("id")

            if not rule_id:
                log.warning("Skipping rule without id: %s", rule_file)
                continue

            log.info(
                "%s rule: %s / %s",
                "DRY-RUN would push" if dry_run else "Pushing",
                policy_id,
                rule_id,
            )

            if not dry_run:
                client.put_security_rule(
                    security_policy_id=policy_id,
                    rule_id=rule_id,
                    payload=rule,
                    domain_id=domain_id,
                )
                time.sleep(THROTTLE_SECONDS)

            rules_count += 1

    return {"policies": policies_count, "rules": rules_count}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Push complete NSX payload to target manager: services, groups, policies, rules"
    )

    parser.add_argument(
        "--target",
        required=True,
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
    )
    parser.add_argument(
        "--build-dir",
        required=True,
        help="Complete build dir, example: nsx_build/nsx-lm3.lab.local",
    )
    parser.add_argument("--domain-id", default="default")
    parser.add_argument("--federation-global", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Required to push. Without this, script only dry-runs.",
    )

    args = parser.parse_args()

    init_cli()
    log_file = setup_logging()

    build_dir = Path(args.build_dir).expanduser().resolve()
    domain_dir = build_dir / "domains" / args.domain_id

    if not domain_dir.exists():
        raise RuntimeError(f"Domain build directory does not exist: {domain_dir}")

    target_host = resolve_manager(args.target)
    if not target_host:
        raise RuntimeError(f"Target manager not defined: {args.target}")

    actual_dry_run = args.dry_run or not args.yes

    client = NsxPolicyClient(
        nsxmanager=target_host,
        federation_global=args.federation_global,
    )

    log.info("Target: %s / %s", args.target, target_host)
    log.info("Build dir: %s", build_dir)
    log.info("Domain: %s", args.domain_id)
    log.info("Dry run: %s", actual_dry_run)

    services = push_services(client, domain_dir, actual_dry_run)
    groups = push_groups(client, domain_dir, args.domain_id, actual_dry_run)
    policy_result = push_policies_and_rules(client, domain_dir, args.domain_id, actual_dry_run)

    result = {
        "target": args.target,
        "target_host": target_host,
        "build_dir": str(build_dir),
        "domain_id": args.domain_id,
        "dry_run": actual_dry_run,
        "pushed": {
            "services": services,
            "groups": groups,
            "policies": policy_result["policies"],
            "rules": policy_result["rules"],
        },
        "log_file": str(log_file),
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()