#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import sys
import time

from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_constants import nsx_gm1


LOG = logging.getLogger("wipe_app_policies_then_groups")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _is_system_owned(obj: dict) -> bool:
    """True for NSX platform-managed objects we must never delete."""
    return obj.get("_system_owned") is True


def confirm_apply(
    target: str,
    domain_id: str,
    federation_global: bool,
    include_services: bool,
) -> None:
    """
    Require an exact typed confirmation of the target hostname before destructive actions.
    """
    print()
    print("DESTRUCTIVE ACTION WARNING")
    print("--------------------------")
    print(f"Target            : {target}")
    print(f"Domain            : {domain_id}")
    print(f"Federation Global : {federation_global}")
    print(f"Include services  : {include_services}")
    print()
    scope = "ALL Application security policies and ALL non-system groups"
    if include_services:
        scope += " and ALL non-system services"
    print(f"This will delete {scope} visible to this scope.")
    print("System-owned (platform-managed) objects are always preserved.")
    print()
    print(f"To continue, type the target exactly: {target}")
    typed = input("Confirmation: ").strip()

    if typed != target:
        print("Confirmation did not match target. Aborting.")
        raise SystemExit(2)


def get_application_policies(client: NsxPolicyClient, domain_id: str):
    policies = client.list_security_policies(domain_id=domain_id)
    return [
        p for p in policies
        if (p.get("category") or "").strip().lower() == "application"
    ]


def get_groups(client: NsxPolicyClient, domain_id: str):
    return client.list_groups(domain_id=domain_id)


def wipe_application_policies(
    client: NsxPolicyClient,
    domain_id: str,
    apply: bool,
) -> tuple[int, int]:
    policies = get_application_policies(client, domain_id)

    LOG.info("Application policies found: %s", len(policies))

    deleted = 0
    failed = 0

    for policy in policies:
        policy_id = policy.get("id")
        display_name = policy.get("display_name") or policy_id

        if not policy_id:
            LOG.warning("Skipping policy with no id: %s", policy)
            failed += 1
            continue

        if apply:
            LOG.info("Deleting policy: %s (%s)", display_name, policy_id)
            try:
                client.delete_security_policy(
                    security_policy_id=policy_id,
                    domain_id=domain_id,
                )
                deleted += 1
            except Exception as e:
                LOG.warning("Could not delete policy %s: %s", policy_id, e)
                failed += 1
        else:
            LOG.info("[DRY-RUN] Would delete policy: %s (%s)", display_name, policy_id)
            deleted += 1

    return deleted, failed


def wipe_groups(
    client: NsxPolicyClient,
    domain_id: str,
    apply: bool,
) -> tuple[int, int, int]:
    groups = get_groups(client, domain_id)

    total = len(groups)
    system_kept = sum(1 for g in groups if _is_system_owned(g))
    LOG.info("Groups found: %s (system-owned skipped: %s)", total, system_kept)

    deleted = 0
    failed = 0

    for group in groups:
        group_id = group.get("id")
        display_name = group.get("display_name") or group_id

        if not group_id:
            LOG.warning("Skipping group with no id: %s", group)
            failed += 1
            continue

        if _is_system_owned(group):
            LOG.info("KEEP (system-owned) group: %s (%s)", display_name, group_id)
            continue

        if apply:
            LOG.info("Deleting group: %s (%s)", display_name, group_id)
            try:
                client.delete_group(
                    group_id=group_id,
                    domain_id=domain_id,
                )
                deleted += 1
            except Exception as e:
                LOG.warning("Could not delete group %s: %s", group_id, e)
                failed += 1
        else:
            LOG.info("[DRY-RUN] Would delete group: %s (%s)", display_name, group_id)
            deleted += 1

    return deleted, failed, system_kept


def get_services(client: NsxPolicyClient):
    return client.list_services()


def wipe_custom_services(
    client: NsxPolicyClient,
    apply: bool,
) -> tuple[int, int, int]:
    """
    Delete non-system services. System-owned services (every NSX built-in
    like WINS, DNS, etc.) are always preserved.
    """
    services = get_services(client)
    total = len(services)
    system_kept = sum(1 for s in services if _is_system_owned(s))
    LOG.info(
        "Services found: %s (system-owned skipped: %s, custom candidates: %s)",
        total, system_kept, total - system_kept,
    )

    deleted = 0
    failed = 0

    for svc in services:
        svc_id = svc.get("id")
        display_name = svc.get("display_name") or svc_id

        if not svc_id:
            LOG.warning("Skipping service with no id: %s", svc)
            failed += 1
            continue

        if _is_system_owned(svc):
            LOG.debug("KEEP (system-owned) service: %s (%s)", display_name, svc_id)
            continue

        if apply:
            LOG.info("Deleting service: %s (%s)", display_name, svc_id)
            try:
                client.delete_service(service_id=svc_id)
                deleted += 1
            except Exception as e:
                LOG.warning("Could not delete service %s: %s", svc_id, e)
                failed += 1
        else:
            LOG.info("[DRY-RUN] Would delete service: %s (%s)", display_name, svc_id)
            deleted += 1

    return deleted, failed, system_kept


def verify_remaining(
    client: NsxPolicyClient,
    domain_id: str,
    include_services: bool,
) -> tuple[list, list, list]:
    remaining_policies = get_application_policies(client, domain_id)
    remaining_groups = [g for g in get_groups(client, domain_id) if not _is_system_owned(g)]
    remaining_services: list = []
    if include_services:
        remaining_services = [s for s in get_services(client) if not _is_system_owned(s)]

    LOG.warning("VERIFY remaining Application policies : %s", len(remaining_policies))
    LOG.warning("VERIFY remaining non-system groups    : %s", len(remaining_groups))
    if include_services:
        LOG.warning("VERIFY remaining non-system services  : %s", len(remaining_services))

    if remaining_policies:
        LOG.warning("Sample remaining policies: %s",
                    [p.get("id") for p in remaining_policies[:20]])
    if remaining_groups:
        LOG.warning("Sample remaining groups: %s",
                    [g.get("id") for g in remaining_groups[:20]])
    if remaining_services:
        LOG.warning("Sample remaining services: %s",
                    [s.get("id") for s in remaining_services[:20]])

    return remaining_policies, remaining_groups, remaining_services


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Delete all Application security policies, then all non-system "
            "groups, then optionally all non-system services. System-owned "
            "objects are always preserved. Supports both Local Manager and "
            "Global Manager (set --federation-global for GM)."
        )
    )
    p.add_argument(
        "--target",
        default=nsx_gm1,
        help="NSX manager hostname (LM or GM). Defaults to nsx_gm1 from .env.",
    )
    p.add_argument("--domain-id", default="default", help="NSX domain ID")
    p.add_argument(
        "--federation-global",
        action="store_true",
        help="Use the Global Manager API surface (/global-infra/...). Required when --target points at a GM.",
    )
    p.add_argument(
        "--include-services",
        action="store_true",
        help=(
            "After policies and groups, also delete every non-system service. "
            "Off by default for back-compat with the prior behavior. System-owned "
            "services (NSX built-ins: WINS, DNS, etc.) are always preserved."
        ),
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help="Actually delete objects. Without this, runs as dry-run.",
    )
    p.add_argument(
        "--verify-delay",
        type=int,
        default=2,
        help="Seconds to wait before re-query verification",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return p


def main() -> int:
    args = build_parser().parse_args()
    setup_logging(args.verbose)

    LOG.warning("TARGET            : %s", args.target)
    LOG.warning("DOMAIN            : %s", args.domain_id)
    LOG.warning("FEDERATION GLOBAL : %s", args.federation_global)
    LOG.warning("INCLUDE SERVICES  : %s", args.include_services)
    LOG.warning("MODE              : %s", "APPLY" if args.apply else "DRY RUN")

    if args.apply:
        confirm_apply(
            target=args.target,
            domain_id=args.domain_id,
            federation_global=args.federation_global,
            include_services=args.include_services,
        )

    client = NsxPolicyClient(
        nsxmanager=args.target,
        federation_global=args.federation_global,
    )

    # 1. Policies first — removes the references that pin groups in place
    deleted_policies, failed_policies = wipe_application_policies(
        client=client,
        domain_id=args.domain_id,
        apply=args.apply,
    )

    # 2. Then groups (now unreferenced by the deleted application policies)
    deleted_groups, failed_groups, kept_groups = wipe_groups(
        client=client,
        domain_id=args.domain_id,
        apply=args.apply,
    )

    # 3. Optionally services LAST — services may still be referenced by
    #    rules in OTHER policy categories (Infrastructure/Environment/etc.),
    #    so any service that's still referenced will fail to delete and be
    #    counted in failed_services rather than crashing the run.
    deleted_services = 0
    failed_services = 0
    kept_services = 0
    if args.include_services:
        deleted_services, failed_services, kept_services = wipe_custom_services(
            client=client,
            apply=args.apply,
        )

    if args.apply and args.verify_delay > 0:
        LOG.info("Waiting %s seconds before verification...", args.verify_delay)
        time.sleep(args.verify_delay)

    remaining_policies, remaining_groups, remaining_services = verify_remaining(
        client=client,
        domain_id=args.domain_id,
        include_services=args.include_services,
    )

    LOG.warning(
        "Summary: "
        "deleted_policies=%s failed_policies=%s "
        "deleted_groups=%s failed_groups=%s system_groups_kept=%s "
        "deleted_services=%s failed_services=%s system_services_kept=%s "
        "remaining_policies=%s remaining_groups=%s remaining_services=%s",
        deleted_policies, failed_policies,
        deleted_groups, failed_groups, kept_groups,
        deleted_services, failed_services, kept_services,
        len(remaining_policies), len(remaining_groups), len(remaining_services),
    )

    leftover = (
        len(remaining_policies)
        + len(remaining_groups)
        + (len(remaining_services) if args.include_services else 0)
    )
    return 0 if leftover == 0 else 1


if __name__ == "__main__":
    sys.exit(main())