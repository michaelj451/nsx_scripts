"""Which manager a revert baseline belongs to.

A baseline is the target's state captured just before an apply, and a rollback
restores it. Nothing in the baseline itself says which manager it was taken
from, and a rollback takes the newest one in its folder. On 2026-09-28 two
workflows shared a folder: WF-A's rules push files its baselines under its
SOURCE host and WF-D's amend-refs under its TARGET, and both were nsx-lm1. An
A rollback would then have restored lm1's rules onto lm2, and a D3 rollback
could have reached A's empty lm2 baseline and deleted every rule on lm1.

So every apply writes, beside its baseline, a record of the manager it
captured, and every rollback checks that record before it sends anything.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

META_SUFFIX = "_target_meta.json"


def meta_path(baseline_path: Path) -> Path:
    """`<ts>_target_meta.json` beside `<ts>_target_baseline.json`, or beside
    the `.reverted` name a consumed baseline is given."""
    baseline_path = Path(baseline_path)
    prefix = baseline_path.name.split("_target_baseline", 1)[0]
    return baseline_path.with_name(prefix + META_SUFFIX)


def write_meta(baseline_path: Path, *, target_host: str, step: str,
               domain_id: Optional[str] = None, federation_global: bool = False) -> Path:
    p = meta_path(baseline_path)
    p.write_text(json.dumps({
        "target_host": target_host,
        "step": step,
        "domain_id": domain_id,
        "federation_global": bool(federation_global),
        "baseline_file": Path(baseline_path).name,
        "written_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2, sort_keys=True), encoding="utf-8")
    return p


def read_meta(baseline_path: Path) -> Optional[Dict[str, Any]]:
    p = meta_path(baseline_path)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def refuse_reason(baseline_path: Path, target_host: str, *, explicit: bool) -> Optional[str]:
    """Why a rollback must not use this baseline on `target_host`, or None.

    A recorded manager that differs always refuses, even for a baseline named
    with --from-baseline. A baseline with no record (one written before this
    check existed) is used only when named explicitly: the rollback will not
    guess whose it is.
    """
    name = Path(baseline_path).name
    meta = read_meta(baseline_path)
    if meta is None:
        if explicit:
            return None
        return (f"baseline {name} records no manager (it predates the manager check), "
                f"so a rollback will not guess whose it is. If you are sure it was taken "
                f"from {target_host}, name it with --from-baseline.")
    recorded = meta.get("target_host")
    if recorded != target_host:
        return (f"baseline {name} was taken from {recorded} (by {meta.get('step')}), not "
                f"{target_host}. Restoring it here would put another manager's state on "
                f"this one.")
    return None
