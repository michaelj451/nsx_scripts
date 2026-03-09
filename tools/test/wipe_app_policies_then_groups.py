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


def confirm_apply(target: str, domain_id: str, federation_global: bool) -> None:
    """
    Require an exact typed confirmation of the target hostname before destructive actions.
    """
    print()
    print("DESTRUCTIVE ACTION WARNING")
    print("--------------------------")
    print(f"Target            : {target}")
    print(f"Domain            : {domain_id}")
    print(f"Federation Global : {federation_global}")
    print()
    print("This will delete ALL Application security policies and ALL groups")
    print("visible to this scope.")
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
) -> tuple[int, int]:
    groups = get_groups(client, domain_id)

    LOG.info("Groups found: %s", len(groups))

    deleted = 0
    failed = 0

    for group in groups:
        group_id = group.get("id")
        display_name = group.get("display_name") or group_id

        if not group_id:
            LOG.warning("Skipping group with no id: %s", group)
            failed += 1
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

    return deleted, failed


def verify_remaining(client: NsxPolicyClient, domain_id: str) -> tuple[list, list]:
    remaining_policies = get_application_policies(client, domain_id)
    remaining_groups = get_groups(client, domain_id)

    LOG.warning("VERIFY remaining Application policies: %s", len(remaining_policies))
    LOG.warning("VERIFY remaining groups: %s", len(remaining_groups))

    if remaining_policies:
        LOG.warning(
            "Sample remaining policies: %s",
            [p.get("id") for p in remaining_policies[:20]],
        )

    if remaining_groups:
        LOG.warning(
            "Sample remaining groups: %s",
            [g.get("id") for g in remaining_groups[:20]],
        )

    return remaining_policies, remaining_groups


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Delete all Application security policies, then all groups"
    )
    p.add_argument("--target", default=nsx_gm1, help="NSX manager hostname")
    p.add_argument("--domain-id", default="default", help="NSX domain ID")
    p.add_argument(
        "--federation-global",
        action="store_true",
        help="Use GM/global-infra view",
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
    LOG.warning("MODE              : %s", "APPLY" if args.apply else "DRY RUN")

    if args.apply:
        confirm_apply(
            target=args.target,
            domain_id=args.domain_id,
            federation_global=args.federation_global,
        )

    client = NsxPolicyClient(
        nsxmanager=args.target,
        federation_global=args.federation_global,
    )

    deleted_policies, failed_policies = wipe_application_policies(
        client=client,
        domain_id=args.domain_id,
        apply=args.apply,
    )

    deleted_groups, failed_groups = wipe_groups(
        client=client,
        domain_id=args.domain_id,
        apply=args.apply,
    )

    if args.apply and args.verify_delay > 0:
        LOG.info("Waiting %s seconds before verification...", args.verify_delay)
        time.sleep(args.verify_delay)

    remaining_policies, remaining_groups = verify_remaining(
        client=client,
        domain_id=args.domain_id,
    )

    LOG.warning(
        "Summary: deleted_policies=%s failed_policies=%s deleted_groups=%s failed_groups=%s remaining_policies=%s remaining_groups=%s",
        deleted_policies,
        failed_policies,
        deleted_groups,
        failed_groups,
        len(remaining_policies),
        len(remaining_groups),
    )

    return 0 if not remaining_policies and not remaining_groups else 1


if __name__ == "__main__":
    sys.exit(main())