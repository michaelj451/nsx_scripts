"""What a revert will do (or did), object by object, for the rollback report.

Every revert tool computes the same plan: restore what the baseline holds,
delete what the push created. This module turns that plan into rows a person
can read, and writes them on BOTH a dry run and an apply, so a rollback
preview is a reviewable document and not just log lines.

Per row: the object by display name, the action, the status, and for a restore
exactly what it changes (target now -> baseline), using the same comparison
as a push. A restore whose target already matches the baseline changes nothing
and is skipped by default, the same rule pushes follow; `--force-push` writes
it anyway.

Written next to each tool's other reports as `revert_plan_<ts>.json`. The
older `revert_actions_*.jsonl` / `revert_summary_*.json` files are unchanged.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from nsx.push_skip import field_diff, is_unchanged


def _name(*objs: Optional[Dict[str, Any]]) -> Optional[str]:
    for o in objs:
        if isinstance(o, dict) and o.get("display_name"):
            return o["display_name"]
    return None


def build(kind: str,
          restores: Iterable[Dict[str, Any]],
          deletes: Iterable[Dict[str, Any]],
          *,
          blocked: Iterable[Dict[str, Any]] = (),
          already_gone: Iterable[Dict[str, Any]] = (),
          force: bool = False) -> Tuple[List[Dict[str, Any]], set]:
    """Plan rows plus the set of restore keys that actually need a write.

    Each input item is a dict with: key (the tool's own lookup key), id,
    optionally policy_id / policy_display_name (rules), and `baseline` /
    `current` payloads where they exist.
    """
    rows: List[Dict[str, Any]] = []
    to_write: set = set()
    for it in restores:
        base, cur = it.get("baseline"), it.get("current")
        row = {"kind": kind, "action": "restore", "key": it["key"], "id": it["id"],
               "display_name": _name(base, cur) or it["id"]}
        for k in ("policy_id", "policy_display_name", "ref_names"):
            if it.get(k):
                row[k] = it[k]
        if cur is None:
            # The baseline object is gone from the target: the restore recreates it.
            row["restore_kind"] = "recreate"
            row["status"] = "planned"
            to_write.add(it["key"])
        elif not force and is_unchanged(base, cur):
            row["restore_kind"] = "unchanged"
            row["status"] = "skipped_unchanged"
        else:
            row["restore_kind"] = "revert"
            row["status"] = "planned"
            diff = field_diff(base, cur)       # before = target now, after = baseline
            if diff:
                row["per_field_diff"] = diff
            to_write.add(it["key"])
        rows.append(row)
    for it, status in ([(d, "planned") for d in deletes]
                       + [(d, "blocked") for d in blocked]
                       + [(d, "already_gone") for d in already_gone]):
        row = {"kind": kind, "action": "delete", "key": it["key"], "id": it["id"],
               "display_name": _name(it.get("current")) or it["id"], "status": status}
        for k in ("policy_id", "policy_display_name", "ref_names"):
            if it.get(k):
                row[k] = it[k]
        rows.append(row)
    return rows, to_write


def settle(rows: List[Dict[str, Any]], executed: Iterable[Dict[str, Any]],
           key_of) -> None:
    """After an apply, replace each planned row's status with what happened.
    A planned row with no execution record was never reached (the operator
    stopped, or an earlier failure halted the run)."""
    done = {}
    for e in executed:
        done[(e.get("action"), key_of(e))] = e
    for r in rows:
        if r["status"] != "planned":
            continue
        e = done.get((r["action"], r["key"]))
        if e is None:
            r["status"] = "not_reached"
        else:
            r["status"] = e.get("status") or "success"
            if e.get("error"):
                r["error"] = str(e["error"])[:300]


def write(reports_dir: Path, kind: str, rows: List[Dict[str, Any]], *, apply: bool,
          target: Dict[str, Any], baseline_file: Optional[Path]) -> Path:
    """revert_plan_<ts>.json: the whole plan, in either mode."""
    ts = datetime.now(timezone.utc)
    counts: Dict[str, int] = {}
    for r in rows:
        key = f"{r['action']}:{r.get('restore_kind') or r['status']}"
        counts[key] = counts.get(key, 0) + 1
    doc = {
        "command": f"{kind}.revert",
        "kind": kind,
        "mode": "APPLY" if apply else "DRY-RUN",
        "ran_at": ts.isoformat(),
        "target": target,
        "baseline_file": str(baseline_file) if baseline_file else None,
        "counts": counts,
        "rows": rows,
    }
    path = Path(reports_dir) / f"revert_plan_{ts.strftime('%Y%m%d_%H%M%S_%f')}.json"
    path.write_text(json.dumps(doc, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return path
