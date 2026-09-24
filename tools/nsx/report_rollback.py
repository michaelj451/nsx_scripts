#!/usr/bin/env python3
"""tools/nsx/report_rollback.py

The rollback report: what a `run_workflow.py --rollback` will do (dry run) or
did (apply), object by object, from the `revert_plan_*.json` files each revert
tool writes. The driver runs this at the end of every rollback, the same way it
writes a report for every push, so a rollback preview is a document you can
review and sign off, not four log files.

    python tools/nsx/report_rollback.py --out-dir <dir> --since <iso> \\
        --label "WF-A ROLLBACK DRY RUN: nsx-lm1 to nsx-lm2" \\
        --report-root nsx_rules_export/nsx-lm1.lab.local/push_report ...

Objects are named by display name, never by bare id. A restore shows exactly
what it changes on the target (now -> baseline), with anything the rollback
REMOVES listed first; a restore whose target already matches the baseline is
skipped and counted, not rewritten.
"""
from __future__ import annotations

import argparse
import collections
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from nsx.md_utils import align_markdown_tables  # noqa: E402
from nsx.names import NameMap  # noqa: E402

log = logging.getLogger("report_rollback")

KIND_ORDER = ["rule", "policy", "group", "service"]   # the order the rollback runs in
KIND_LABEL = {"rule": "Rules", "policy": "Policies", "group": "Groups", "service": "Services"}
DONE = {"success", "success_put", "success_patch", "ok"}
NAMES = NameMap()


def _vals(xs: List[str], limit: int = 50) -> str:
    shown = ", ".join(f"`{x}`" for x in xs[:limit])
    return shown + (f", +{len(xs) - limit} more" if len(xs) > limit else "")


def _ref(x: Any) -> str:
    s = str(x)
    return NAMES.label(s) if s.startswith("/") else s


def _clip(v: Any, limit: int = 80) -> str:
    s = v if isinstance(v, str) else json.dumps(v, sort_keys=True, default=str)
    return s if len(s) <= limit else s[:limit - 3] + "..."


def _policy(r: Dict[str, Any]) -> str:
    pid = r.get("policy_id")
    return NAMES.label(f"/security-policies/{pid}") if pid else ""


def _what(r: Dict[str, Any]) -> str:
    """The action in plain words."""
    if r["action"] == "delete":
        return {"blocked": "delete blocked", "already_gone": "already gone"}.get(r["status"], "delete")
    return {"revert": "revert", "recreate": "recreate", "unchanged": "unchanged"}.get(
        r.get("restore_kind"), "restore")


def _status(r: Dict[str, Any], is_apply: bool) -> str:
    s = r["status"]
    if s in DONE:
        return "done"
    if s == "dry_run":
        return "would run"
    return {"skipped_unchanged": "skipped", "not_reached": "NOT REACHED",
            "failed": "FAILED", "blocked": "blocked", "already_gone": "n/a"}.get(s, s)


def detail_lines(r: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    lost = r.get("ips_removed") or []
    if lost:
        out.append(f"- IPs REMOVED by the rollback ({len(lost)}): {_vals(lost)}")
    back = r.get("ips_added") or []
    if back:
        out.append(f"- IPs put back ({len(back)}): {_vals(back)}")
    pfd = r.get("per_field_diff") or {}
    fields = [(f, d) for f, d in pfd.items() if isinstance(d, dict)]
    for f, d in fields:                                # removals first
        if d.get("removed"):
            out.append(f"- `{f}` REMOVED by the rollback ({len(d['removed'])}): "
                       f"{_vals([_ref(x) for x in d['removed']])}")
    for f, d in fields:
        if d.get("added"):
            out.append(f"- `{f}` put back ({len(d['added'])}): {_vals([_ref(x) for x in d['added']])}")
    for f, d in fields:
        if "added" in d or "removed" in d:
            continue
        if f == "expression" and (lost or back):
            continue                                   # the IP lines above already say it
        out.append(f"- `{f}`: `{_clip(d.get('before'))}` -> `{_clip(d.get('after'))}`")
    if r.get("restore_kind") == "recreate":
        out.append("- In the baseline but gone from the target: the rollback recreates it.")
    if r["status"] == "blocked":
        out.append("- Would be deleted, but `--allow-delete` was not given, so it is left in place.")
    if r.get("error"):
        out.append(f"- Error: {_clip(r['error'], 200)}")
    return out


def table(headers: List[str], body: List[List[str]]) -> List[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(c).replace("|", "\\|") for c in row) + " |" for row in body]
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--since", default=None, help="Only plans written at or after this UTC time.")
    ap.add_argument("--label", default="ROLLBACK")
    ap.add_argument("--report-root", action="append", default=[],
                    help="A push_report/ directory a revert wrote into. Repeatable.")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s")

    since = None
    if args.since:
        since = datetime.fromisoformat(args.since.replace("Z", "+00:00"))
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)

    plans: List[Dict[str, Any]] = []
    for root in args.report_root:
        rp = Path(root).expanduser()
        if rp.name == "push_report":
            NAMES.add_bundle(rp.parent)
        for f in sorted(rp.glob("revert_plan_*.json")):
            try:
                doc = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            ran = datetime.fromisoformat(str(doc.get("ran_at")).replace("Z", "+00:00"))
            if since and ran < since:
                continue
            doc["_file"] = str(f)
            doc["_root"] = str(rp)
            plans.append(doc)
    # One plan per class and mode: an apply rewrites its plan after settling, so
    # keep the latest per (kind, mode).
    latest: Dict[tuple, Dict[str, Any]] = {}
    for d in sorted(plans, key=lambda d: d["ran_at"]):
        latest[(d["kind"], d["mode"])] = d
    is_apply = any(m == "APPLY" for (_, m) in latest)
    chosen = {k: d for (k, m), d in latest.items() if (m == "APPLY") == is_apply}

    rows: List[Dict[str, Any]] = []
    for kind, d in chosen.items():
        for r in d.get("rows") or []:
            r["kind"] = kind
            rows.append(r)
            NAMES.add(None, r.get("id"), r.get("display_name"),
                      {"group": "groups", "service": "services", "policy": "security-policies",
                       "rule": "rules"}.get(kind, ""))
            NAMES.add_mapping(r.get("ref_names"))
            if r.get("policy_id"):
                NAMES.add(None, r["policy_id"], r.get("policy_display_name"), "security-policies")

    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    mode_word = "ROLLBACK APPLIED" if is_apply else "ROLLBACK DRY RUN"
    now = datetime.now(timezone.utc)
    md: List[str] = [f"# {args.label}", "",
                     f"**{mode_word}** | generated {now.isoformat()}"
                     + (f" | plans since `{args.since}`" if args.since else ""), ""]
    if not rows:
        md += ["No revert plan was found for this run. The revert steps may have failed before "
               "planning (check the step logs), or there was no baseline to restore.", ""]

    # ---- which apply is being undone --------------------------------------------
    if chosen:
        md += ["## What this undoes", "",
               "Each class restores the most recent baseline that has not been reverted yet. "
               "A baseline is the target as it was just before one apply, so this rolls back "
               "that one apply. Older applies stay stacked underneath and need their own rollback.", ""]
        body = []
        for kind in KIND_ORDER:
            d = chosen.get(kind)
            if not d:
                continue
            bf = Path(d.get("baseline_file") or "")
            stamp = bf.name.split("_target_baseline")[0] if bf.name else "?"
            left = 0
            if bf.parent.exists():
                left = len([p for p in bf.parent.glob("*_target_baseline.json")])
            remaining = left if is_apply else max(left - 1, 0)
            body.append([KIND_LABEL[kind], f"`{stamp}`", str(remaining)])
        md += table(["Class", "Baseline restored (taken before the apply at)",
                     "Older applies still stacked after this"], body) + [""]

    # ---- the answer, first -------------------------------------------------------
    md += ["## What the rollback " + ("did" if is_apply else "would do"), ""]
    counts = {k: collections.Counter(_what(r) for r in rows if r["kind"] == k) for k in KIND_ORDER}
    failed = [r for r in rows if r["status"] in ("failed", "not_reached")]
    cols = ["revert", "recreate", "delete", "unchanged", "delete blocked", "already gone"]
    body = [[KIND_LABEL[k]] + [str(counts[k].get(c, 0) or "") for c in cols]
            for k in KIND_ORDER if counts[k]]
    if body:
        md += table(["Class", "Revert (changed back)", "Recreate", "Delete", "Unchanged (skipped)",
                     "Delete blocked", "Already gone"], body) + [""]
        md += ["- **Revert**: on the target now, but changed since the baseline; put back as it was.",
               "- **Recreate**: in the baseline but gone from the target; created again.",
               "- **Delete**: not in the baseline, so the apply being undone created it.",
               "- **Unchanged**: already identical to the baseline; nothing is sent.", ""]
    if failed:
        md += [f"**{len(failed)} object(s) failed or were never reached.** The rollback is "
               "incomplete: the baseline is only marked reverted when every step succeeds, so "
               "re-running the rollback retries the same baseline.", ""]

    # ---- per class ---------------------------------------------------------------
    acting = [r for r in rows if _what(r) not in ("unchanged", "already gone")]
    for kind in KIND_ORDER:
        hits = [r for r in acting if r["kind"] == kind]
        if not hits:
            continue
        md += [f"### {KIND_LABEL[kind]} ({len(hits)})", ""]
        if kind == "rule":
            md += table(["Name", "Policy", "Action", "Status"],
                        [[r.get("display_name") or r["id"], _policy(r), _what(r), _status(r, is_apply)]
                         for r in sorted(hits, key=lambda x: (_policy(x), str(x.get("display_name"))))]) + [""]
        else:
            md += table(["Name", "Action", "Status"],
                        [[r.get("display_name") or r["id"], _what(r), _status(r, is_apply)]
                         for r in sorted(hits, key=lambda x: str(x.get("display_name")))]) + [""]

    # ---- detail -----------------------------------------------------------------
    detailed = [r for r in acting if detail_lines(r)]
    if detailed:
        md += ["## Change detail", "",
               "What each object looks like on the target now, against what the rollback "
               "puts back. Anything the rollback removes is listed first.", ""]
        for kind in KIND_ORDER:
            hits = [r for r in detailed if r["kind"] == kind]
            if not hits:
                continue
            md += [f"### {KIND_LABEL[kind]}", ""]
            for r in sorted(hits, key=lambda x: (_policy(x), str(x.get("display_name")))):
                where = f" in policy **{_policy(r)}**" if kind == "rule" and _policy(r) else ""
                md += [f"**{r.get('display_name') or r['id']}**{where} "
                       f"({_what(r)}, {_status(r, is_apply)})", ""] + detail_lines(r) + [""]

    same = [r for r in rows if _what(r) == "unchanged"]
    if same:
        md += ["## Already matching the baseline (skipped)", "",
               f"{len(same)} object(s) are already identical to the baseline, so the rollback "
               "sends nothing for them: " + ", ".join(
                   f"{r.get('display_name') or r['id']}" for r in
                   sorted(same, key=lambda x: (x['kind'], str(x.get('display_name'))))), ""]

    (out_dir / "rollback_report.md").write_text(align_markdown_tables("\n".join(md)) + "\n",
                                                encoding="utf-8")
    (out_dir / "rollback_report.json").write_text(json.dumps({
        "generated_at": now.isoformat(), "label": args.label, "mode": mode_word,
        "plans": [{k: v for k, v in d.items() if k != "rows"} for d in chosen.values()],
        "rows": rows}, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    log.info("Rollback report: %s (%d object(s), %d failed/not reached)",
             out_dir / "rollback_report.md", len(rows), len(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
