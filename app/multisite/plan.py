"""app/multisite/plan.py

The N-site sibling plan, built from ONE source capture and one multi-site map.

THE MODEL

Workloads start on the source manager (S1) and can move to ANY target site.
Every manager must therefore hold the addresses of every other site:

    view                 holds                          built like
    <source> view        S1's own addresses, unmapped   WF-C (no CSV)
    <site> view          addresses mapped for <site>    WF-D (that site's column)

    manager      gets every view except its own
    source       all site views
    each site    the source view + every other site's view

Each view has its own sibling suffix (named after whose addresses it holds),
and each (target, view) pair has its own report folder, so no two pushes
share a baseline folder and no rollback can pick up another push's baseline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from common import ipspan
from common.fileio import read_json
from common.paths import repo_relative


@dataclass
class View:
    key: str                     # whose addresses: source alias or site alias
    suffix: str
    mapped: bool                 # False for the source view
    csv: Optional[Path] = None   # the site's cut-out two-column map
    bundle: Optional[Path] = None    # .../nsx_sibling_groups/<source-host>
    sibling_map: Dict[str, Any] = field(default_factory=dict)

    @property
    def groups_dir(self) -> Optional[Path]:
        return self.bundle / "groups" if self.bundle else None

    @property
    def map_path(self) -> Optional[Path]:
        return self.bundle / "sibling_map.json" if self.bundle else None


def default_suffix(alias: str) -> str:
    """nsx-lm3 -> _lm3_ips. Distinct from the WF-C/WF-D suffixes by design,
    so a test plan can never merge into the siblings the real workflows made."""
    short = re.sub(r"^nsx-", "", alias.strip().lower())
    short = re.sub(r"[^a-z0-9]+", "_", short).strip("_") or "site"
    return f"_{short}_ips"


def build_views(source: str, sites: Sequence[str],
                overrides: Optional[Dict[str, str]] = None) -> List[View]:
    overrides = overrides or {}
    views = [View(key=source, suffix=overrides.get(source, default_suffix(source)), mapped=False)]
    for s in sites:
        views.append(View(key=s, suffix=overrides.get(s, default_suffix(s)), mapped=True))
    return views


def suffix_problems(views: Sequence[View], reserved: Dict[str, str]) -> List[str]:
    """Duplicate suffixes, or a suffix equal to one the real workflows use
    (`reserved` maps a description such as 'OBJECT_APPENDIX' to its value)."""
    out: List[str] = []
    seen: Dict[str, str] = {}
    for v in views:
        if not v.suffix:
            out.append(f"view {v.key} has an empty suffix")
        elif v.suffix in seen:
            out.append(f"views {seen[v.suffix]} and {v.key} share suffix {v.suffix!r}")
        seen.setdefault(v.suffix, v.key)
        for what, value in reserved.items():
            if value and v.suffix == value:
                out.append(f"view {v.key} suffix {v.suffix!r} equals {what}; its siblings would "
                           f"merge into the ones that workflow created")
    return out


def deployment(views: Sequence[View]) -> Dict[str, List[str]]:
    """target manager -> the view keys it receives (every view but its own)."""
    keys = [v.key for v in views]
    return {t: [k for k in keys if k != t] for t in keys}


def load_views(views: Iterable[View]) -> None:
    for v in views:
        v.sibling_map = read_json(v.map_path) if v.map_path and v.map_path.is_file() else {}


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def sibling_ips(row: Dict[str, Any]) -> List[str]:
    """The addresses a sibling holds. A mapped (WF-D style) build records them
    in ips_sibling_mapped; the source (WF-C style) build sets that to None
    because its sibling holds the source addresses as they are."""
    mapped = row.get("ips_sibling_mapped")
    return list(mapped) if mapped is not None else list(row.get("ips_source") or [])


def view_counts(v: View) -> Dict[str, int]:
    rows = v.sibling_map.get("map", [])
    return {"siblings": len(rows),
            "ips": sum(len(sibling_ips(r)) for r in rows),
            "no_sibling": len(v.sibling_map.get("no_sibling", [])),
            "uncovered_ips": sum(len(r.get("ips_uncovered") or []) for r in rows)}


def coverage(v: View) -> Dict[str, Any]:
    """What this view leaves out: groups with no sibling (and why), and
    source addresses that got no mapping for this site."""
    no_sib = [{"group": r.get("original_display_name") or r.get("original_id"),
               "reason": r.get("reason"), "reason_code": r.get("reason_code"),
               "ips_source": r.get("ips_source") or []}
              for r in v.sibling_map.get("no_sibling", [])]
    uncovered = [{"group": r.get("original_display_name") or r.get("original_id"),
                  "ips": r.get("ips_uncovered")}
                 for r in v.sibling_map.get("map", []) if r.get("ips_uncovered")]
    return {"no_sibling": no_sib, "uncovered": uncovered}


def parse_in_use(text: str) -> Tuple[List[ipspan.Span], List[str]]:
    """One host, CIDR or range per line; '#' starts a comment."""
    spans: List[ipspan.Span] = []
    bad: List[str] = []
    for line in text.splitlines():
        token = line.split("#", 1)[0].strip()
        if not token:
            continue
        s = ipspan.try_span(token)
        (spans.append(s) if s else bad.append(token))
    return spans, bad


def in_use_findings(v: View, in_use: Sequence[ipspan.Span]) -> List[Dict[str, Any]]:
    """Mapped addresses in this site's view that touch addresses already in
    use at the site.

      collision  a mapped HOST address is already taken: a different machine
                 at the site would inherit the moved VM's rules
      covers     a mapped SUBNET contains machines already there; by design a
                 subnet entry covers everything in it, listed for review
    """
    # One finding per mapped address, listing every group that carries it.
    found: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in v.sibling_map.get("map", []):
        group = r.get("original_display_name") or r.get("original_id")
        for src, mapped_list in r.get("ip_pairs") or []:
            for mapped in mapped_list or []:
                ms = ipspan.try_span(mapped)
                if ms is None:
                    continue
                hits = [u for u in in_use if ipspan.overlaps(ms, u)]
                if not hits:
                    continue
                kind = "collision" if ms.lo == ms.hi else "covers"
                rec = found.setdefault((src, mapped), {
                    "severity": "error" if kind == "collision" else "info",
                    "kind": kind, "site": v.key, "source": src, "mapped": mapped,
                    "in_use": [ipspan.fmt(h) for h in hits], "groups": []})
                if group not in rec["groups"]:
                    rec["groups"].append(group)
    return sorted(found.values(), key=lambda f: (f["kind"] != "collision", f["mapped"]))


def reserved_addresses(v: View) -> List[str]:
    """Every mapped address this site's view carries, merged. These must stay
    free for migrating VMs until the migration ends: siblings are additive
    only, so a VM's address at the site it did NOT move to is never removed."""
    spans = []
    for r in v.sibling_map.get("map", []):
        for m in sibling_ips(r):
            s = ipspan.try_span(m)
            if s:
                spans.append(s)
    return [ipspan.fmt(s) for s in ipspan.merge(spans)]


# ---------------------------------------------------------------------------
# Commands (printed, never run by this tool)
# ---------------------------------------------------------------------------

def target_dir(run_dir: Path, target: str, view_key: str) -> Path:
    return run_dir / "deploy" / target / view_key


def commands(run_dir: Path, source: str, views: Sequence[View],
             matrix: Dict[str, List[str]]) -> Dict[str, List[str]]:
    by_key = {v.key: v for v in views}
    py = "python3"
    w0 = [f"# Capture {source} with its own credentials (A needs the flat exports):",
          f"{py} tools/nsx/capture_nsx_state.py --source {source} --live-query --emit-flat-exports"]
    for t in matrix:
        if t != source:
            w0.append(f"{py} tools/nsx/run_workflow.py --source {source} --target {t} --phase a"
                      f"          # dry run; add --apply after review")
    w1, w2, rb = [], [], []
    for t, keys in matrix.items():
        for k in keys:
            v = by_key[k]
            d = target_dir(run_dir, t, k)
            w1.append(f"{py} tools/nsx/groups.py push --target {t} "
                      f"--groups-dir {repo_relative(v.groups_dir)} "
                      f"--reports-dir {repo_relative(d / 'push_report')} --skip-no-ip-change")
            w2.append(f"{py} tools/nsx/rules.py amend-refs --target {t} "
                      f"--sibling-map {repo_relative(v.map_path)} "
                      f"--reports-dir {repo_relative(d / 'rules_amend' / 'push_report')}")
            rb.append(f"{py} tools/nsx/rules.py revert --target {t} "
                      f"--reports-dir {repo_relative(d / 'rules_amend' / 'push_report')}")
            rb.append(f"{py} tools/nsx/groups.py revert --target {t} "
                      f"--reports-dir {repo_relative(d / 'push_report')} --allow-delete")
    return {"window_0_prerequisites": w0, "window_1_siblings": w1,
            "window_2_rule_refs": w2, "rollback": rb}
