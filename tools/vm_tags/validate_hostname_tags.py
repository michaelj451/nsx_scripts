#!/usr/bin/env python3
"""
tools/vm_tags/validate_hostname_tags.py

Read-only check: for every eligible VM in a push plan, does the live NSX
state now have the expected hostname tag?

Writes two artifacts under nsx_vm_files/vm_tags_validation/<TS>_<manager>/:
  - validation_report.json  (full per-VM detail)
  - validation_report.md    (PASS/FAIL header + verified matches + any issues)

Usage:
  python tools/vm_tags/validate_hostname_tags.py \\
    --manager nsx-lm1 \\
    --plan-dir vm_tags_plan/nsx-lm1.lab.local
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_vm_log_dir, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.md_utils import align_markdown_tables

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

_TS_DIR_RE = __import__("re").compile(r"^\d{8}_\d{6}$")


def resolve_plan_dir(plan_dir: Path) -> Path:
    """Accept host-level dir (auto-pick latest timestamped run) or a specific run dir."""
    if (plan_dir / "eligible.json").exists():
        return plan_dir
    candidates = [
        p for p in plan_dir.iterdir()
        if p.is_dir() and _TS_DIR_RE.match(p.name) and (p / "eligible.json").exists()
    ] if plan_dir.is_dir() else []
    if not candidates:
        raise SystemExit(
            f"No eligible.json found in {plan_dir} and no timestamped run "
            f"subdirs with eligible.json. Pass --plan-dir at the host-level "
            f"dir or a specific timestamped run dir."
        )
    return sorted(candidates, key=lambda p: p.name)[-1]


def setup_logging(tool: str) -> Path:
    log_dir = Path(nsx_vm_log_dir).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = (log_dir / f"vm_tags_{tool}_{RUN_TS}.log").resolve()
    log_file.touch(exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter(
        "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S",
    )
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(ch)
    root.addHandler(fh)
    log.info("Logging to %s", log_file)
    return log_file


def _hostname_tag(tags: List[Dict[str, str]]) -> str | None:
    for t in tags or []:
        if isinstance(t, dict) and t.get("scope") == "hostname":
            return t.get("tag")
    return None


def write_validation_markdown(out_path: Path, summary: dict, results: dict) -> Path:
    """Human-readable validation report alongside the JSON, mirroring the
    push/revert reports: a PASS/FAIL header, the verified-match list, and one
    table per issue class (only rendered when non-empty)."""
    c = summary.get("counts", {})
    bad = (c.get("mismatch_wrong_value", 0)
           + c.get("missing_hostname_tag", 0)
           + c.get("missing_on_target", 0))
    status = "PASS" if bad == 0 else "FAIL"

    lines = []
    lines.append(f"# VM Hostname Tag Validation - {summary.get('manager','?')} "
                 f"({summary.get('manager_host','?')})\n")
    lines.append(f"- **Result**: **{status}**")
    lines.append(f"- **Ran at**: {summary.get('ran_at','')}")
    lines.append(f"- **Eligible in plan**: {summary.get('eligible_in_plan', 0)}")
    lines.append(f"- **Matched (verified)**: **{c.get('match', 0)}**")
    lines.append(f"- **Mismatched value**: {c.get('mismatch_wrong_value', 0)}")
    lines.append(f"- **Missing hostname tag**: {c.get('missing_hostname_tag', 0)}")
    lines.append(f"- **Missing on target (VM not found live)**: {c.get('missing_on_target', 0)}")
    lines.append("")

    matches = results.get("match") or []
    lines.append(f"## Verified matches ({len(matches)})\n")
    if not matches:
        lines.append("_No verified matches._\n")
    else:
        lines.append("| # | VM | Hostname tag | Ext ID |")
        lines.append("|---:|---|---|---|")
        for i, m in enumerate(matches, start=1):
            lines.append(
                f"| {i} | {m.get('display_name','')} | "
                f"**`hostname\\|{m.get('hostname_tag','')}`** | "
                f"`{(m.get('external_id') or '')[:12]}...` |"
            )
        lines.append("")

    for key, label, cols in (
        ("mismatch_wrong_value", "Mismatched value", ("Expected", "Actual")),
        ("missing_hostname_tag", "Missing hostname tag", ("Expected",)),
        ("missing_on_target", "Missing on target - VM not found live", ()),
    ):
        rows = results.get(key) or []
        if not rows:
            continue
        header = "| # | VM | " + "".join(f"{col} | " for col in cols) + "Ext ID |"
        sep = "|---:|---|" + "".join("---|" for _ in cols) + "---|"
        lines.append(f"## {label} ({len(rows)})\n")
        lines.append(header)
        lines.append(sep)
        for i, r in enumerate(rows, start=1):
            mid = "".join(f"`{r.get(col.lower(),'')}` | " for col in cols)
            lines.append(
                f"| {i} | {r.get('display_name','')} | {mid}"
                f"`{(r.get('external_id') or '')[:12]}...` |"
            )
        lines.append("")

    out_path.write_text(align_markdown_tables("\n".join(lines)), encoding="utf-8")
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify the live NSX VM tag state matches the plan's expectations."
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        required=True,
    )
    parser.add_argument("--plan-dir", required=True, help="Directory with eligible.json")
    args = parser.parse_args()

    init_cli()
    log_file = setup_logging("validate")

    manager_host = resolve_manager(args.manager)
    if not manager_host:
        raise SystemExit(f"Manager not defined for {args.manager}.")

    plan_dir = resolve_plan_dir(Path(args.plan_dir).expanduser().resolve())
    eligible_path = plan_dir / "eligible.json"
    if not eligible_path.exists():
        raise SystemExit(f"eligible.json not found in {plan_dir}")
    log.info("Using plan dir: %s", plan_dir)
    eligible = json.loads(eligible_path.read_text(encoding="utf-8")).get("vms") or []

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=False)
    live = client.list_virtual_machines()
    live_by_id = {vm["external_id"]: vm for vm in live if vm.get("external_id")}

    results = {
        "match": [],
        "mismatch_wrong_value": [],
        "missing_hostname_tag": [],
        "missing_on_target": [],
    }

    for e in eligible:
        ext_id = e["external_id"]
        expected = e["proposed_hostname_tag"]
        display = e.get("display_name") or ext_id
        live_vm = live_by_id.get(ext_id)
        if live_vm is None:
            results["missing_on_target"].append({"external_id": ext_id, "display_name": display})
            continue
        actual = _hostname_tag(live_vm.get("tags") or [])
        if actual is None:
            results["missing_hostname_tag"].append(
                {"external_id": ext_id, "display_name": display, "expected": expected}
            )
        elif actual != expected:
            results["mismatch_wrong_value"].append(
                {"external_id": ext_id, "display_name": display, "expected": expected, "actual": actual}
            )
        else:
            results["match"].append({"external_id": ext_id, "display_name": display, "hostname_tag": actual})

    summary = {
        "manager": args.manager,
        "manager_host": manager_host,
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "eligible_in_plan": len(eligible),
        "counts": {k: len(v) for k, v in results.items()},
        "log_file": str(log_file),
    }

    val_dir = Path(nsx_vm_log_dir).expanduser().resolve() / "vm_tags_validation" / f"{RUN_TS}_{args.manager}"
    val_dir.mkdir(parents=True, exist_ok=True)
    (val_dir / "validation_report.json").write_text(
        json.dumps({"summary": summary, "results": results}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    log.info("Validation report: %s", val_dir / "validation_report.json")
    md_path = val_dir / "validation_report.md"
    write_validation_markdown(md_path, summary, results)
    log.info("Markdown report: %s", md_path)
    print(json.dumps(summary, indent=2, sort_keys=True))

    bad = summary["counts"]["mismatch_wrong_value"] + summary["counts"]["missing_hostname_tag"] + summary["counts"]["missing_on_target"]
    if bad > 0:
        log.warning("Validation found %d issue(s) — see validation_report.json", bad)


if __name__ == "__main__":
    main()
