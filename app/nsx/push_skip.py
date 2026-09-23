"""Skip a push when the target already holds identical content.

Every push tool reads the target before writing. When the object already
exists there and its content matches the payload byte for byte once
NSX-managed metadata is set aside, the PUT has nothing to do: it would bump
`_revision`, trigger a realization cycle, and overwrite whatever the target
holds with something identical. Skipping it keeps a re-run free of footprint
and removes the last-writer-wins exposure on objects nobody meant to change.

This is the DEFAULT. `--force-push` turns it off for the rare case where the
write itself is the point, such as forcing a re-realization after an NSX-side
problem.

The comparison uses the same volatile-key set the push tools already trust to
sanitize a payload, so "unchanged" here means exactly what "no measurable
delta" means everywhere else in the toolkit. Verified against the lab on
2026-09-23: all 13 lm1 groups compared identical to their lm2 copies.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

# NSX-managed metadata: server-assigned, or bookkeeping that says nothing
# about what the object DOES. Identical to each push tool's STRIP_KEYS.
VOLATILE_KEYS = {
    "_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
    "_revision", "revision", "_protection", "_system_owned",
    "marked_for_delete", "overridden", "remote_path",
    "realization_id", "unique_id", "origin_site_id", "owner_id",
    "_links", "_schema", "_self", "status", "children",
    # NSX assigns a numeric rule_id per manager, so the same rule cloned to a
    # second manager gets a different one. It identifies nothing about what the
    # rule does.
    "rule_id",
    # Toolkit bookkeeping injected into rule files so a push knows the parent
    # policy. It is never part of the object on NSX.
    "_parent_policy_id",
}


def _strip(obj: Any) -> Any:
    """Normalize an object down to the parts that decide what it DOES.

    Lists of scalars are sorted. In NSX policy objects those are sets, not
    sequences: `scope`, `source_groups`, `destination_groups`, `services`,
    `ip_addresses`, `paths`, `tags`. NSX routinely returns them in a different
    order than they were sent, and that reordering means nothing. Measured on
    lm1/lm2 2026-09-23: `allow-icmp-network-8` came back with its two scope
    groups swapped, and nothing else about it had changed.

    Lists containing dicts keep their order, because there the order IS
    meaning: a group's `expression` list interleaves Conditions with
    ConjunctionOperators, so reordering it changes membership.
    """
    if isinstance(obj, dict):
        return {k: _strip(v) for k, v in sorted(obj.items()) if k not in VOLATILE_KEYS}
    if isinstance(obj, list):
        stripped = [_strip(x) for x in obj]
        if stripped and all(isinstance(x, str) for x in stripped):
            return sorted(stripped)
        return stripped
    return obj


def content_key(obj: Optional[Dict[str, Any]]) -> str:
    """Stable string for the parts of an object that carry meaning."""
    if not isinstance(obj, dict):
        return ""
    return json.dumps(_strip(obj), sort_keys=True, separators=(",", ":"))


def is_unchanged(payload: Optional[Dict[str, Any]],
                 live: Optional[Dict[str, Any]]) -> bool:
    """True when pushing `payload` over `live` would change nothing.

    A missing `live` means the object is not on the target yet, which is a
    creation and never a skip.
    """
    if not isinstance(payload, dict) or not isinstance(live, dict):
        return False
    return content_key(payload) == content_key(live)


SKIPPED_STATUS = "skipped_unchanged"
