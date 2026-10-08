"""app/nsx/critical_rules.py

Shared pieces of the critical-rules scripts in tools/nsx/critical_rules/:
copy every Infrastructure policy plus only the Application rules with hits
from one NSX Local Manager to a new, empty one.

One run folder per run, so no script ever has to guess which bundle is newest:

    nsx_critical_runs/<source>_to_<target>/<UTC_TS>/
        run.json                         what each step did, with paths
        stats/<source host>/rules_usage/<ts>/   step 1 rules-usage report
        hits.json                        step 1: the rules with hits
        infra/<ts>/<source host>/        step 2: Infrastructure bundle
        hits/<ts>/<source host>/         step 2: hit-rules bundle
        logs/                            one log per tool each step ran

The scripts only call the existing tools (report_rules_usage, capture,
filter_policy_bundle, consolidate_hot_rules, the four push tools); nothing
here writes to NSX itself.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import yaml

from common.bundles import new_run_dir, timestamped_dirs
from nsx.streaming import stream_command

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_BASE = REPO_ROOT / "nsx_critical_runs"
PY = sys.executable

LM_CHOICES = ["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5", "nsx-lm6"]

CLASSES = ("services", "groups", "policies", "rules")
PUSH_TOOL = {
    "services": ("tools/nsx/services.py", "--services-dir", "services/services"),
    "groups":   ("tools/nsx/groups.py",   "--groups-dir",   "groups/groups"),
    "policies": ("tools/nsx/policies.py", "--policies-dir", "policies/security-policies"),
    "rules":    ("tools/nsx/rules.py",    "--rules-dir",    "rules/security-policies"),
}
BUNDLES = ("infra", "hits")   # push order; revert runs the reverse

# "Push services DRY-RUN <dash> ok=0 failed=0 skipped=0 (dry_run=2) total=2"
_SUMMARY_RE = re.compile(r"Push \w+ [A-Z-]+\W+(ok=\d+ failed=\d+[^\n]*)")


# =============================================================================
# Run folders and the run record
# =============================================================================

def pair_dir(source: str, target: str, base: Path = RUNS_BASE) -> Path:
    return base / f"{source}_to_{target}"


def new_run(source: str, target: str, source_host: str, target_host: str,
            base: Path = RUNS_BASE) -> Path:
    run = new_run_dir(pair_dir(source, target, base))
    save_record(run, {
        "source": source, "source_host": source_host,
        "target": target, "target_host": target_host,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "steps": {}, "history": [],
    })
    return run


def resolve_run(source: str, target: str, run: Optional[str] = None,
                base: Path = RUNS_BASE) -> Path:
    """The --run folder if given, else the newest run for this source/target."""
    if run:
        p = Path(run).expanduser().resolve()
        if not (p / "run.json").is_file():
            raise SystemExit(f"not a critical-rules run folder (no run.json): {p}")
        return p
    runs = timestamped_dirs(pair_dir(source, target, base))
    if not runs:
        raise SystemExit(f"no run for {source} -> {target} under {pair_dir(source, target, base)}; "
                         "start one with step1_stats.py")
    return runs[-1]


def load_record(run: Path) -> Dict[str, Any]:
    return json.loads((run / "run.json").read_text(encoding="utf-8"))


def save_record(run: Path, rec: Dict[str, Any]) -> None:
    (run / "run.json").write_text(json.dumps(rec, indent=2, default=str), encoding="utf-8")


def record_step(run: Path, step: str, data: Dict[str, Any]) -> None:
    """Keep the latest result per step plus every result in history."""
    rec = load_record(run)
    data = {"step": step, "at": datetime.now(timezone.utc).isoformat(), **data}
    rec.setdefault("steps", {})[step] = data
    rec.setdefault("history", []).append(data)
    save_record(run, rec)


def check_pair(rec: Dict[str, Any], source: str, target: str) -> None:
    if (rec.get("source"), rec.get("target")) != (source, target):
        raise SystemExit(f"run is for {rec.get('source')} -> {rec.get('target')}, "
                         f"not {source} -> {target}")


# =============================================================================
# Running the existing tools
# =============================================================================

def run_tool(label: str, cmd: List[str], log_dir: Path) -> Dict[str, Any]:
    """Run one tool with live output, logged to <log_dir>/<label>.log."""
    step_log = log_dir / f"{label}.log"
    log.info("STEP %s", label)
    log.info("  cmd: %s", " ".join(str(c) for c in cmd))
    rc, _ = stream_command([str(c) for c in cmd], REPO_ROOT, step_log)
    log.log(logging.INFO if rc == 0 else logging.ERROR,
            "  %s (rc=%d)  log: %s", "OK" if rc == 0 else "FAILED", rc, step_log)
    return {"label": label, "cmd": [str(c) for c in cmd], "rc": rc, "ok": rc == 0,
            "log": str(step_log), "summary": push_summary(step_log)}


def push_summary(step_log: Path) -> Optional[str]:
    """The 'ok=N failed=N ...' tail of a push tool's summary line, if any."""
    try:
        m = None
        for m in _SUMMARY_RE.finditer(step_log.read_text(encoding="utf-8", errors="replace")):
            pass
        return m.group(1).strip() if m else None
    except OSError:
        return None


def push_steps(bundles: Dict[str, Path], target: str, apply: bool,
               segments_mode: str = "strip") -> List[Tuple[str, List[str]]]:
    """(label, cmd) for every push, Infrastructure bundle first, in class order."""
    steps = []
    n = 0
    for name in BUNDLES:
        for cls in CLASSES:
            n += 1
            tool, flag, sub = PUSH_TOOL[cls]
            cmd = [PY, tool, "push", "--target", target, flag, str(bundles[name] / sub)]
            if cls == "groups":
                cmd += ["--segments-mode", segments_mode]
            if apply:
                cmd.append("--apply")
            steps.append((f"{n:02d}_{name}_{cls}_{'apply' if apply else 'dryrun'}", cmd))
    return steps


def revert_steps(bundles: Dict[str, Path], target: str, apply: bool) -> List[Tuple[str, List[str]]]:
    """(label, cmd) for every revert: hit-rules bundle first, rules down to services.

    groups.py revert needs --allow-delete to remove the groups its push created;
    without it they stay behind and the revert still exits 0.
    """
    steps = []
    n = 0
    for name in reversed(BUNDLES):
        for cls in reversed(CLASSES):
            n += 1
            tool, _, sub = PUSH_TOOL[cls]
            reports = bundles[name] / sub.split("/")[0] / "push_report"
            cmd = [PY, tool, "revert", "--target", target, "--reports-dir", str(reports)]
            if cls == "groups":
                cmd.append("--allow-delete")
            if apply:
                cmd.append("--apply")
            steps.append((f"{n:02d}_{name}_{cls}_revert_{'apply' if apply else 'dryrun'}", cmd))
    return steps


# =============================================================================
# Reading what the tools wrote
# =============================================================================

def newest_report(stats_root: Path, source_host: str) -> Path:
    runs = timestamped_dirs(stats_root / source_host / "rules_usage")
    if not runs:
        raise SystemExit(f"no rules-usage report under {stats_root}")
    return runs[-1]


def single_bundle(root: Path, source_host: str) -> Path:
    """The one <root>/<ts>/<source host> bundle a step wrote."""
    found = [d / source_host for d in timestamped_dirs(root) if (d / source_host).is_dir()]
    if len(found) != 1:
        raise SystemExit(f"expected exactly one bundle under {root}, found {len(found)}: {found}")
    return found[0]


def hit_rows(report_dir: Path) -> List[Dict[str, Any]]:
    """Customer rules with hit_count > 0 (default sections left out)."""
    rows = [json.loads(l) for l in (report_dir / "rules_usage.jsonl").read_text(encoding="utf-8").splitlines()
            if l.strip()]
    keep = [r for r in rows if r.get("hit_count") and not str(r.get("policy_id", "")).startswith("default-layer")]
    return sorted(keep, key=lambda r: (r.get("policy_category", ""), r["policy_id"], r.get("sequence_number") or 0))


def _ids(paths: Sequence[Path]) -> Set[str]:
    return {yaml.safe_load(f.read_text(encoding="utf-8"))["id"] for f in paths}


def bundle_objects(bundle: Path) -> Dict[str, Set[str]]:
    """Every object id a bundle would push; rules as '<policy id>/<rule id>'."""
    rules = set()
    for f in (bundle / "rules/security-policies").glob("*/rules/*.yaml"):
        r = yaml.safe_load(f.read_text(encoding="utf-8"))
        rules.add(f"{r['parent_path'].rsplit('/', 1)[-1]}/{r['id']}")
    return {
        "services": _ids(list((bundle / "services/services").glob("*.yaml"))),
        "groups": _ids(list((bundle / "groups/groups").glob("*.yaml"))),
        "policies": _ids(list((bundle / "policies/security-policies").glob("*/policy.yaml"))),
        "rules": rules,
    }


def merge_objects(parts: Sequence[Dict[str, Set[str]]]) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {k: set() for k in CLASSES}
    for p in parts:
        for k in CLASSES:
            out[k] |= p.get(k, set())
    return out


def target_objects(client: Any, domain_id: str = "default") -> Dict[str, Set[str]]:
    """Customer objects on a manager (read only); default sections left out."""
    pols = [p for p in client.list_security_policies(domain_id=domain_id) if not p.get("is_default")]
    return {
        "services": {s["id"] for s in client.list_services() if not s.get("_system_owned")},
        "groups": {g["id"] for g in client.list_groups(domain_id=domain_id) if not g.get("_system_owned")},
        "policies": {p["id"] for p in pols},
        "rules": {f"{p['id']}/{r['id']}" for p in pols
                  for r in client.list_security_rules(security_policy_id=p["id"], domain_id=domain_id)},
    }


def compare(want: Dict[str, Set[str]], have: Dict[str, Set[str]]) -> Dict[str, Dict[str, List[str]]]:
    return {k: {"expected": sorted(want[k]), "missing": sorted(want[k] - have[k]),
                "extra": sorted(have[k] - want[k])} for k in CLASSES}


def is_empty(objs: Dict[str, Set[str]]) -> bool:
    return not any(objs[k] for k in CLASSES)


def hit_rules_order(bundle: Path) -> List[Dict[str, Any]]:
    """The hit-rules policy in its new order: sequence, action, id, hit count."""
    m = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    hits = {k["final_id"]: k["hit_count"] for k in m.get("kept_rules", [])}
    out = []
    for f in sorted((bundle / "rules/security-policies").glob("*/rules/*.yaml")):
        r = yaml.safe_load(f.read_text(encoding="utf-8"))
        out.append({"sequence": r.get("sequence_number"), "action": r.get("action"),
                    "id": r["id"], "hits": hits.get(r["id"])})
    return out
