#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager, nsx_log_dir
from nsx.nsx_policy_client import NsxPolicyClient, NsxApiError

try:
    import yaml
except ImportError:
    yaml = None


THROTTLE_SECONDS = 0.2
RUN_TS = datetime.now().strftime("%Y%m%d_%H%M%S")

SKIP_POLICIES = {
    "default-layer2-section",
    "default-layer3-section",
}

log = logging.getLogger(__name__)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def setup_logging(dry_run: bool) -> tuple[Path, Path]:
    log_root = Path(nsx_log_dir).expanduser().resolve()
    log_root.mkdir(parents=True, exist_ok=True)

    mode_name = (
        "push_complete_nsx_payload_dry_run"
        if dry_run
        else "push_complete_nsx_payload_apply"
    )

    log_file = log_root / f"{mode_name}_{RUN_TS}.log"
    reports_dir = log_root / mode_name / RUN_TS
    reports_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)

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


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


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


def is_already_exists_error(e: Exception) -> bool:
    """
    True when a PUT failure indicates the object already exists on the target
    and the right next step is to PATCH instead. Covers two distinct flavors:

      1) "Already exists" (NSX error_code 500127 / HTTP ~400) — classic
         create-collision when PUT is treated as POST.
      2) "Different version" / PRECONDITION_FAILED (NSX error_code 500071 /
         HTTP 412) — optimistic-concurrency rejection because the local
         payload has a stale `_revision` (or none) vs. the live object's
         current revision. This happens when re-pushing rules/policies whose
         parent was just modified earlier in the same run.

    Both conditions mean: object exists, fall back to PATCH.
    """
    msg = str(e)
    lower = msg.lower()
    return (
        "already exists" in lower
        or "500127" in msg
        or "cannot create an object" in lower
        or "500071" in msg
        or "precondition_failed" in lower
        or "different version" in lower
    )


def sanitize_for_put(obj: Dict[str, Any]) -> Dict[str, Any]:
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


def push_services(
    client: NsxPolicyClient,
    domain_dir: Path,
    dry_run: bool,
) -> tuple[int, List[Dict[str, Any]]]:
    services_dir = domain_dir / "services"
    count = 0
    rows: List[Dict[str, Any]] = []

    for f in iter_files(services_dir):
        row = {
            "timestamp": utc_now_iso(),
            "object_type": "service",
            "file": str(f),
            "dry_run": dry_run,
        }

        try:
            obj = sanitize_for_put(load_file(f))
            service_id = obj.get("id")
            row["id"] = service_id

            if not service_id:
                row["status"] = "skipped"
                row["reason"] = "missing id"
                rows.append(row)
                log.warning("Skipping service without id: %s", f)
                continue

            log.info(
                "%s service: %s",
                "DRY-RUN would push" if dry_run else "Pushing",
                service_id,
            )

            if dry_run:
                row["status"] = "dry_run"
            else:
                try:
                    client.put_service(service_id, obj)
                    row["status"] = "success_put"
                except NsxApiError as e:
                    if is_already_exists_error(e):
                        log.info("Service exists, patching instead: %s", service_id)
                        client.patch_service(service_id, obj)
                        row["status"] = "success_patch"
                    else:
                        raise

                time.sleep(THROTTLE_SECONDS)

            count += 1

        except Exception as e:
            row["status"] = "failed"
            row["reason"] = str(e)
            log.exception("Failed processing service file %s", f)

        rows.append(row)

    return count, rows


def push_groups(
    client: NsxPolicyClient,
    domain_dir: Path,
    domain_id: str,
    dry_run: bool,
) -> tuple[int, List[Dict[str, Any]]]:
    groups_dir = domain_dir / "groups"
    count = 0
    rows: List[Dict[str, Any]] = []

    for f in iter_files(groups_dir):
        row = {
            "timestamp": utc_now_iso(),
            "object_type": "group",
            "file": str(f),
            "dry_run": dry_run,
            "domain_id": domain_id,
        }

        try:
            obj = sanitize_for_put(load_file(f))
            group_id = obj.get("id")
            row["id"] = group_id

            if not group_id:
                row["status"] = "skipped"
                row["reason"] = "missing id"
                rows.append(row)
                log.warning("Skipping group without id: %s", f)
                continue

            log.info(
                "%s group: %s",
                "DRY-RUN would push" if dry_run else "Pushing",
                group_id,
            )

            if dry_run:
                row["status"] = "dry_run"
            else:
                try:
                    client.put_group(group_id, obj, domain_id=domain_id)
                    row["status"] = "success_put"
                except NsxApiError as e:
                    if is_already_exists_error(e):
                        log.info("Group exists, patching instead: %s", group_id)
                        client.patch_group(group_id, obj, domain_id=domain_id)
                        row["status"] = "success_patch"
                    else:
                        raise

                time.sleep(THROTTLE_SECONDS)

            count += 1

        except Exception as e:
            row["status"] = "failed"
            row["reason"] = str(e)
            log.exception("Failed processing group file %s", f)

        rows.append(row)

    return count, rows


def push_policies_and_rules(
    client: NsxPolicyClient,
    domain_dir: Path,
    domain_id: str,
    dry_run: bool,
) -> tuple[Dict[str, int], List[Dict[str, Any]], List[Dict[str, Any]]]:
    policies_dir = domain_dir / "security-policies"
    policies_count = 0
    rules_count = 0
    policy_rows: List[Dict[str, Any]] = []
    rule_rows: List[Dict[str, Any]] = []

    if not policies_dir.exists():
        return {"policies": 0, "rules": 0}, policy_rows, rule_rows

    for policy_dir in sorted(p for p in policies_dir.iterdir() if p.is_dir()):
        policy_file = None

        for candidate in ("policy.yaml", "policy.yml", "policy.json"):
            p = policy_dir / candidate
            if p.exists():
                policy_file = p
                break

        if not policy_file:
            continue

        policy_row = {
            "timestamp": utc_now_iso(),
            "object_type": "security_policy",
            "file": str(policy_file),
            "dry_run": dry_run,
            "domain_id": domain_id,
        }

        try:
            policy = sanitize_for_put(load_file(policy_file))
            policy_id = policy.get("id")
            policy_row["id"] = policy_id

            if not policy_id:
                policy_row["status"] = "skipped"
                policy_row["reason"] = "missing id"
                policy_rows.append(policy_row)
                log.warning("Skipping policy without id: %s", policy_file)
                continue

            if policy_id in SKIP_POLICIES:
                policy_row["status"] = "skipped"
                policy_row["reason"] = "built-in/default policy"
                policy_rows.append(policy_row)
                log.info("Skipping built-in/default policy: %s", policy_id)
                continue

            log.info(
                "%s policy: %s",
                "DRY-RUN would push" if dry_run else "Pushing",
                policy_id,
            )

            if dry_run:
                policy_row["status"] = "dry_run"
            else:
                try:
                    client.put_security_policy(policy_id, policy, domain_id=domain_id)
                    policy_row["status"] = "success_put"
                except NsxApiError as e:
                    if is_already_exists_error(e):
                        log.info("Policy exists, patching instead: %s", policy_id)
                        client.patch_security_policy(policy_id, policy, domain_id=domain_id)
                        policy_row["status"] = "success_patch"
                    else:
                        raise

                time.sleep(THROTTLE_SECONDS)

            policies_count += 1

        except Exception as e:
            policy_row["status"] = "failed"
            policy_row["reason"] = str(e)
            log.exception("Failed processing policy file %s", policy_file)

        policy_rows.append(policy_row)

        policy_id = policy_row.get("id")
        if not policy_id or policy_row.get("status") in {"failed", "skipped"}:
            continue

        rules_dir = policy_dir / "rules"

        for rule_file in iter_files(rules_dir):
            rule_row = {
                "timestamp": utc_now_iso(),
                "object_type": "security_rule",
                "file": str(rule_file),
                "dry_run": dry_run,
                "domain_id": domain_id,
                "policy_id": policy_id,
            }

            try:
                rule = sanitize_for_put(load_file(rule_file))
                rule_id = rule.get("id")
                rule_row["id"] = rule_id

                if not rule_id:
                    rule_row["status"] = "skipped"
                    rule_row["reason"] = "missing id"
                    rule_rows.append(rule_row)
                    log.warning("Skipping rule without id: %s", rule_file)
                    continue

                log.info(
                    "%s rule: %s / %s",
                    "DRY-RUN would push" if dry_run else "Pushing",
                    policy_id,
                    rule_id,
                )

                if dry_run:
                    rule_row["status"] = "dry_run"
                else:
                    try:
                        client.put_security_rule(
                            security_policy_id=policy_id,
                            rule_id=rule_id,
                            payload=rule,
                            domain_id=domain_id,
                        )
                        rule_row["status"] = "success_put"
                    except NsxApiError as e:
                        if is_already_exists_error(e):
                            log.info(
                                "Rule exists, patching instead: %s / %s",
                                policy_id,
                                rule_id,
                            )
                            client.patch_security_rule(
                                security_policy_id=policy_id,
                                rule_id=rule_id,
                                payload=rule,
                                domain_id=domain_id,
                            )
                            rule_row["status"] = "success_patch"
                        else:
                            raise

                    time.sleep(THROTTLE_SECONDS)

                rules_count += 1

            except Exception as e:
                rule_row["status"] = "failed"
                rule_row["reason"] = str(e)
                log.exception("Failed processing rule file %s", rule_file)

            rule_rows.append(rule_row)

    return {"policies": policies_count, "rules": rules_count}, policy_rows, rule_rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Push complete NSX payload to target manager: services, groups, policies, rules"
    )

    parser.add_argument(
        "--target",
        required=True,
        choices=[
            "nsx-gm1",
            "nsx-gm2",
            "nsx-lm1",
            "nsx-lm2",
            "nsx-lm3",
            "nsx-lm4",
            "nsx-lm5",
        ],
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
        "--apply",
        action="store_true",
        help="Actually push objects to NSX. Without this, script runs as dry-run.",
    )

    args = parser.parse_args()

    actual_dry_run = args.dry_run or not args.apply

    init_cli()
    log_file, reports_dir = setup_logging(actual_dry_run)

    build_dir = Path(args.build_dir).expanduser().resolve()
    domain_dir = build_dir / "domains" / args.domain_id

    if not domain_dir.exists():
        raise RuntimeError(f"Domain build directory does not exist: {domain_dir}")

    target_host = resolve_manager(args.target)
    if not target_host:
        raise RuntimeError(f"Target manager not defined: {args.target}")

    client = NsxPolicyClient(
        nsxmanager=target_host,
        federation_global=args.federation_global,
    )

    log.info("Starting push_complete_nsx_payload")
    log.info("Target: %s / %s", args.target, target_host)
    log.info("Build dir: %s", build_dir)
    log.info("Domain: %s", args.domain_id)
    log.info("Federation global: %s", args.federation_global)
    log.info("Dry run: %s", actual_dry_run)

    services, service_rows = push_services(client, domain_dir, actual_dry_run)
    groups, group_rows = push_groups(client, domain_dir, args.domain_id, actual_dry_run)

    policy_result, policy_rows, rule_rows = push_policies_and_rules(
        client=client,
        domain_dir=domain_dir,
        domain_id=args.domain_id,
        dry_run=actual_dry_run,
    )

    all_rows = service_rows + group_rows + policy_rows + rule_rows
    failures = [r for r in all_rows if r.get("status") == "failed"]
    skipped = [r for r in all_rows if r.get("status") == "skipped"]
    dry_runs = [r for r in all_rows if r.get("status") == "dry_run"]
    successes = [
        r for r in all_rows
        if str(r.get("status", "")).startswith("success")
    ]

    result = {
        "command": "push_complete_nsx_payload",
        "created_at": utc_now_iso(),
        "target": args.target,
        "target_host": target_host,
        "build_dir": str(build_dir),
        "domain_dir": str(domain_dir),
        "domain_id": args.domain_id,
        "federation_global": args.federation_global,
        "dry_run": actual_dry_run,
        "pushed": {
            "services": services,
            "groups": groups,
            "policies": policy_result["policies"],
            "rules": policy_result["rules"],
        },
        "results": {
            "success": len(successes),
            "failed": len(failures),
            "skipped": len(skipped),
            "dry_run": len(dry_runs),
        },
        "reports_dir": str(reports_dir),
        "log_file": str(log_file),
    }

    write_json(reports_dir / "summary.json", result)

    write_json(reports_dir / "services.json", service_rows)
    write_jsonl(reports_dir / "services.jsonl", service_rows)

    write_json(reports_dir / "groups.json", group_rows)
    write_jsonl(reports_dir / "groups.jsonl", group_rows)

    write_json(reports_dir / "policies.json", policy_rows)
    write_jsonl(reports_dir / "policies.jsonl", policy_rows)

    write_json(reports_dir / "rules.json", rule_rows)
    write_jsonl(reports_dir / "rules.jsonl", rule_rows)

    write_json(reports_dir / "failures.json", failures)
    write_jsonl(reports_dir / "failures.jsonl", failures)

    log.info("Push complete")
    log.info("Summary: %s", result)

    print(json.dumps(result, indent=2))

    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()