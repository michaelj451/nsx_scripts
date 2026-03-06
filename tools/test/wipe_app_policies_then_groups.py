#!/usr/bin/env python3
"""
Wipe NSX Application policies, then wipe all groups in a domain.

Default behavior is DRY-RUN.
Use --apply to actually delete objects.

Examples
--------
Dry run against GM/global:
    python tools/nsx/wipe_app_policies_then_groups.py \
      --target nsx-gm1 \
      --federation-global \
      --domain-id default

Actually apply:
    python tools/nsx/wipe_app_policies_then_groups.py \
      --target nsx-gm1 \
      --federation-global \
      --domain-id default \
      --apply
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any, Dict, Iterable, List, Optional

# Adjust these imports to match your repo layout if needed
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_constants import nsx_gm1

LOG = logging.getLogger("wipe_app_policies_then_groups")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def api_prefix(federation_global: bool) -> str:
    # GM/global objects live under /global-infra
    # LM/local objects live under /infra
    return "/global-infra" if federation_global else "/infra"


def normalize_results(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not payload:
        return []
    if isinstance(payload, dict) and "results" in payload:
        return payload.get("results") or []
    if isinstance(payload, list):
        return payload
    return []


def get_path(prefix: str, domain_id: str, kind: str) -> str:
    if kind == "policies":
        return f"{prefix}/domains/{domain_id}/security-policies"
    if kind == "groups":
        return f"{prefix}/domains/{domain_id}/groups"
    raise ValueError(f"Unsupported kind: {kind}")


def list_security_policies(client: NsxPolicyClient, prefix: str, domain_id: str) -> List[Dict[str, Any]]:
    path = get_path(prefix, domain_id, "policies")
    payload = client.get(path)
    return normalize_results(payload)


def list_groups(client: NsxPolicyClient, prefix: str, domain_id: str) -> List[Dict[str, Any]]:
    path = get_path(prefix, domain_id, "groups")
    payload = client.get(path)
    return normalize_results(payload)


def is_application_policy(policy: Dict[str, Any]) -> bool:
    category = str(policy.get("category") or "").strip().lower()
    return category == "application"


def is_default_or_system_group(group: Dict[str, Any]) -> bool:
    """
    Conservative guardrails so you don't accidentally delete obvious built-ins.
    Tweak if you truly want every single group.
    """
    gid = str(group.get("id") or "")
    display_name = str(group.get("display_name") or "")
    path = str(group.get("path") or "")

    protected_ids = {
        "ANY",
    }

    if gid in protected_ids:
        return True

    # Heuristic: skip system-owned defaults if flagged
    if group.get("_system_owned") is True:
        return True

    # Extra paranoia for built-ins
    built_in_markers = ["/infra/domains/", "/global-infra/domains/"]
    if any(marker in path for marker in built_in_markers):
        # not enough alone to skip, since user groups also live here
        pass

    # Keep this mild, not overprotective
    return False


def delete_object(client: NsxPolicyClient, path: str, apply: bool) -> bool:
    if not apply:
        LOG.info("[DRY-RUN] DELETE %s", path)
        return True

    try:
        client.delete(path)
        LOG.info("Deleted: %s", path)
        return True
    except Exception as exc:
        LOG.error("Failed to delete %s :: %s", path, exc)
        return False


def wipe_application_policies(
    client: NsxPolicyClient,
    prefix: str,
    domain_id: str,
    apply: bool,
) -> int:
    policies = list_security_policies(client, prefix, domain_id)
    app_policies = [p for p in policies if is_application_policy(p)]

    LOG.info("Found %d total security policies", len(policies))
    LOG.info("Found %d Application-category policies", len(app_policies))

    deleted = 0
    for policy in app_policies:
        policy_id = policy.get("id")
        display_name = policy.get("display_name", policy_id)
        path = policy.get("path") or f"{get_path(prefix, domain_id, 'policies')}/{policy_id}"

        LOG.info("Removing Application policy: %s (%s)", display_name, policy_id)
        if delete_object(client, path, apply):
            deleted += 1

    return deleted


def wipe_groups(
    client: NsxPolicyClient,
    prefix: str,
    domain_id: str,
    apply: bool,
) -> int:
    groups = list_groups(client, prefix, domain_id)

    LOG.info("Found %d total groups", len(groups))

    deleted = 0
    skipped = 0

    for group in groups:
        group_id = group.get("id")
        display_name = group.get("display_name", group_id)
        path = group.get("path") or f"{get_path(prefix, domain_id, 'groups')}/{group_id}"

        if is_default_or_system_group(group):
            LOG.info("Skipping protected/system group: %s (%s)", display_name, group_id)
            skipped += 1
            continue

        LOG.info("Removing group: %s (%s)", display_name, group_id)
        if delete_object(client, path, apply):
            deleted += 1

    LOG.info("Groups skipped: %d", skipped)
    return deleted


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Wipe Application policies and then groups from an NSX domain.")
    p.add_argument("--target", default=nsx_gm1, help="NSX manager/GM hostname")
    p.add_argument("--domain-id", default="default", help="NSX domain ID")
    p.add_argument(
        "--federation-global",
        action="store_true",
        help="Use /global-infra paths (GM/global objects). Default is local /infra.",
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help="Actually delete objects. Without this flag, script only does a dry-run.",
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

    prefix = api_prefix(args.federation_global)

    LOG.warning("TARGET              : %s", args.target)
    LOG.warning("DOMAIN              : %s", args.domain_id)
    LOG.warning("FEDERATION GLOBAL   : %s", args.federation_global)
    LOG.warning("MODE                : %s", "APPLY" if args.apply else "DRY-RUN")

    try:
        client = NsxPolicyClient(
            nsxmanager=args.target,
            federation_global=args.federation_global,
        )
    except Exception as exc:
        LOG.error("Failed to create NSX client: %s", exc)
        return 2

    # Step 1: Delete Application policies
    deleted_policies = wipe_application_policies(
        client=client,
        prefix=prefix,
        domain_id=args.domain_id,
        apply=args.apply,
    )

    # Step 2: Delete groups
    deleted_groups = wipe_groups(
        client=client,
        prefix=prefix,
        domain_id=args.domain_id,
        apply=args.apply,
    )

    LOG.warning("Done. Policies deleted: %d | Groups deleted: %d", deleted_policies, deleted_groups)
    return 0


if __name__ == "__main__":
    sys.exit(main())