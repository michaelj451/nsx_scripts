#!/usr/bin/env python3
"""tools/multisite/plan_multisite.py

Offline plan for a THREE-SITE (or N-site) migration: one source NSX manager,
several target sites a VM may move to, and the Palo Alto firewall between
them. Separate from the two-site workflow tools on purpose; nothing here
changes them, and nothing here contacts NSX or Panorama.

WHAT IT DOES

  1. Reads a multi-site subnet map (data/multisite_map.csv):
         old_subnet,nsx-lm2,nsx-lm3
     and checks it strictly: bad cells, duplicate rows, a site whose rows
     send two source addresses to one destination, two sites sharing
     destination addresses. Any error stops the run before anything is built.
  2. Builds one sibling bundle per VIEW from the saved source capture, using
     the existing tools/nsx/build_sibling_groups.py unchanged:
         <source> view   the source's own addresses (WF-C build, no CSV)
         <site> view     addresses mapped for that site (WF-D build, that
                         site's column cut out as a two-column CSV)
  3. Works out which manager needs which views (every view but its own) and
     gives every (target, view) pair its own report folder, so no two pushes
     share a baseline folder.
  4. Checks mapped addresses against addresses already in use at a site
     (--in-use), and lists the addresses each site must keep reserved.
  5. With --vm-snapshot, plans the Palo side as tags: per-VM address objects
     tagged hostname + asl_id, one dynamic address group per NSX group
     (hostname tags up to --sg-threshold members, a unique security_group tag
     above it), and every VM pre-staged at its mapped address for each site.
  6. Writes report.md, plan.json, summary.json and commands.txt. The commands
     are PRINTED for review; this tool never runs them.

USAGE

    python3 tools/multisite/plan_multisite.py \\
        --capture nsx_capture/nsx-lm1.lab.local \\
        --map data/multisite_map.csv \\
        --in-use nsx-lm3=data/multisite_in_use_nsx-lm3.txt \\
        --vm-snapshot nsx_vm_rule_snapshots/nsx-lm1.lab.local

    # just check a map while editing it:
    python3 tools/multisite/plan_multisite.py --map data/multisite_map.csv --check-map-only

OUTPUT
    nsx_multisite_runs/<source-host>/<UTC_TS>/   (`latest` points at the newest)
        report.md  plan.json  summary.json  commands.txt  map_check.json
        maps/<site>.csv                 each site's cut-out two-column map
        views/<view>/nsx_sibling_groups/<source-host>/   sibling bundles
        palo_tag_plan.json              with --vm-snapshot
        logs/

EXIT CODES
    0  plan written, no blocking findings
    1  plan written, with blocking findings (see report.md)
    2  refused: bad map, failed capture gate, suffix clash, or a build failed
"""
from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from common import ipspan                                   # noqa: E402
from common.bundles import find_bundle, new_run_dir, prune_old, update_latest  # noqa: E402
from common.fileio import read_json, read_text, write_json, write_text  # noqa: E402
from common.logs import setup_logging                       # noqa: E402
from common.md import align_markdown_tables, md_table       # noqa: E402
from common.paths import repo_relative                      # noqa: E402
from common.subnet_map import SiteMap, check_site_map, load_site_map  # noqa: E402
from common.timeutil import run_ts, utc_now_iso             # noqa: E402
from multisite import plan as P                             # noqa: E402
from multisite.palo_tags import TagOptions, build_tag_plan  # noqa: E402

log = logging.getLogger("plan_multisite")

# Targets the push tools accept (tools/nsx/groups.py --target choices).
PUSH_TARGETS = {"nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5", "nsx-lm6"}
BUILDER = REPO_ROOT / "tools" / "nsx" / "build_sibling_groups.py"


def _kv(values: Optional[List[str]], flag: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for v in values or []:
        if "=" not in v:
            raise SystemExit(f"{flag} expects SITE=VALUE, got {v!r}")
        k, val = v.split("=", 1)
        out[k.strip()] = val.strip()
    return out


def _reserved_suffixes() -> Dict[str, str]:
    """The suffixes the real WF-C / WF-D runs use, read from .env without
    loading it into the environment (so nothing else changes)."""
    try:
        from dotenv import dotenv_values
    except ImportError:
        return {}
    vals = dotenv_values(REPO_ROOT / ".env")
    return {k: vals.get(k) or "" for k in ("OBJECT_APPENDIX", "OBJECT_APPENDIX_AVS")}


def _build_view(v: P.View, capture: Path, label: str, domain: str, run_dir: Path) -> bool:
    out_base = run_dir / "views" / v.key
    cmd = [sys.executable, str(BUILDER), "--capture", str(capture), "--label", label,
           "--output-base", str(out_base), "--domain-id", domain, "--appendix", v.suffix]
    if v.mapped:
        cmd += ["--csv-remap", str(v.csv), "--skip-segment-groups"]
    log_path = run_dir / "logs" / f"build_{v.key}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log.info("Building view %s (suffix %s)%s", v.key, v.suffix,
             f" from {repo_relative(v.csv)}" if v.mapped else " (source addresses)")
    with log_path.open("w", encoding="utf-8") as f:
        f.write("$ " + " ".join(cmd) + "\n")
        f.flush()
        rc = subprocess.run(cmd, cwd=REPO_ROOT, stdout=f, stderr=subprocess.STDOUT).returncode
    v.bundle = out_base / "nsx_sibling_groups" / label
    if rc != 0 or not (v.bundle / "sibling_map.json").is_file():
        log.error("Build of view %s failed (rc=%d); see %s", v.key, rc, log_path)
        return False
    return True


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _findings_table(rows: List[Dict[str, Any]]) -> List[str]:
    if not rows:
        return ["None."]
    return md_table(["severity", "code", "where", "detail"],
                    [[f.get("severity"), f.get("code"),
                      f.get("site") or f.get("group") or f.get("vm") or f.get("object") or "",
                      f.get("detail")] for f in rows])


def render_report(ctx: Dict[str, Any]) -> str:
    L: List[str] = []
    sm: SiteMap = ctx["site_map"]
    L += [f"# Multi-site plan: {ctx['source']} to {', '.join(sm.sites)}", "",
          f"Generated {ctx['generated_at']}. Offline: no NSX manager and no Panorama was contacted. "
          f"Every command below is printed for review and has NOT been run.", "",
          f"- Map: `{repo_relative(sm.path)}` ({len(sm.sources)} source rows, sites: "
          f"{', '.join(sm.sites)})"]
    if ctx.get("capture"):
        L.append(f"- Source capture: `{repo_relative(ctx['capture'])}` ({ctx['capture_at']})")
    if ctx.get("snapshot_path"):
        L.append(f"- VM snapshot: `{repo_relative(ctx['snapshot_path'])}` ({ctx['snapshot_at']})")
    L += ["", "## 1. Map check", ""]
    if sm.errors:
        L += md_table(["row", "column", "value", "reason"],
                      [[e["row"], e["column"], e["value"], e["reason"]] for e in sm.errors])
    else:
        L += _findings_table(ctx["map_findings"])
    L.append("")
    for s in sm.sites:
        L.append(f"- Addresses `{s}` may receive from the source space: "
                 + ", ".join(f"`{x}`" for x in ctx["map_reserved"].get(s, [])))
    if ctx.get("refused"):
        L += ["", "## Refused", "", f"Nothing was built: {ctx['refused']}"]
    if ctx.get("map_only") or "views" not in ctx:
        return align_markdown_tables("\n".join(L)) + "\n"

    views: List[P.View] = ctx["views"]
    L += ["", "## 2. Views and who gets them", "",
          "Each view is one sibling bundle. A manager gets every view except its own.", ""]
    L += md_table(["view (whose addresses)", "suffix", "built from", "siblings", "IPs",
                   "groups without sibling", "unmapped IPs"],
                  [[v.key, f"`{v.suffix}`", f"`{repo_relative(v.csv)}`" if v.mapped else "source (WF-C)",
                    c["siblings"], c["ips"], c["no_sibling"], c["uncovered_ips"]]
                   for v in views for c in [P.view_counts(v)]],
                  ["l", "l", "l", "r", "r", "r", "r"])
    L += [""]
    L += md_table(["target manager", "receives views"],
                  [[t, ", ".join(keys)] for t, keys in ctx["matrix"].items()])

    L += ["", "## 3. Coverage", ""]
    for v in views:
        cov = P.coverage(v)
        L.append(f"### View `{v.key}`")
        L.append("")
        if cov["uncovered"]:
            L.append("Source addresses with no mapping for this site (left out of the sibling):")
            L += md_table(["group", "unmapped"], [[u["group"], ", ".join(u["ips"])] for u in cov["uncovered"]])
        else:
            L.append("Every address in every sibling has a mapping.")
        L.append("")
        if cov["no_sibling"]:
            L.append("Groups that get no sibling in this view:")
            L += md_table(["group", "reason"], [[n["group"], n["reason"]] for n in cov["no_sibling"]])
            L.append("")

    L += ["## 4. Mapped addresses already in use", ""]
    if not ctx["in_use_given"]:
        L.append("No `--in-use` lists given, so nothing was checked.")
    else:
        L.append("Lists checked: " + ", ".join(f"`{k}` ({n} entries)" for k, n in ctx["in_use_given"].items()))
        L.append("")
        rows = ctx["in_use_findings"]
        if rows:
            L += md_table(["kind", "site", "source", "mapped", "already in use", "groups carrying it"],
                          [[r["kind"], r["site"], r["source"], r["mapped"],
                            ", ".join(r["in_use"]), ", ".join(r["groups"])] for r in rows])
            L += ["", "`collision`: a different machine already has that exact address and would "
                      "inherit the moved VM's rules. `covers`: a mapped subnet contains machines "
                      "already there (by design a subnet entry covers everything in it)."]
        else:
            L.append("No mapped address touches an address in use.")

    L += ["", "## 5. Addresses each site must keep reserved", "",
          "Siblings are additive only, so a VM's address at the site it did not move to is never "
          "removed. Until the migration ends, these must not be handed to unrelated machines.", ""]
    for v in views:
        if v.mapped:
            res = P.reserved_addresses(v)
            L.append(f"- `{v.key}`: " + (", ".join(f"`{x}`" for x in res) if res else "none"))

    tp = ctx.get("tag_plan")
    L += ["", "## 6. Palo Alto tag plan (dg-5)", ""]
    if not tp:
        L.append("Not planned: pass `--vm-snapshot` (from tools/nsx/capture_vm_rule_data.py).")
    else:
        c, o = tp["counts"], tp["options"]
        L += [f"Groups with more than {o['threshold']} member VMs get a unique security_group tag; "
              f"smaller groups match their members' hostname tags (NSX tag scope `{o['hostname_scope']}`, "
              f"asl_id from NSX tag scope `{o['asl_scope']}`). Loose addresses (not a known VM's IP) "
              f"become static objects carrying the group's security_group tag. Pre-staged at: "
              f"{', '.join(o['sites_prestaged']) or 'none'}.", ""]
        L += md_table(["dynamic groups", "by hostname", "by security_group", "VMs", "address objects",
                       "tags", "most tags on one object", "errors", "warnings"],
                      [[c["groups"], c["groups_hostname"], c["groups_security_group"], c["vms"],
                        c["address_objects"], c["tags"], c["max_tags_on_one_object"],
                        c["errors"], c["warnings"]]], ["r"] * 9)
        L += ["", "### Dynamic address groups", ""]
        L += md_table(["name", "strategy", "member VMs", "asl_ids", "filter", "loose addresses"],
                      [[g["name"], g["strategy"], g["member_vms"], ", ".join(g["asl_ids"]),
                        f"`{g['filter']}`" if g["filter"] else "(empty)",
                        ", ".join(g["static_addresses"])] for g in tp["dynamic_groups"]])
        top = sorted(tp["address_objects"], key=lambda x: -len(x["tags"]))[:10]
        L += ["", "### Objects carrying the most tags", ""]
        L += md_table(["object", "value", "tags"],
                      [[x["name"], x["value"], len(x["tags"])] for x in top], ["l", "l", "r"])
        L += ["", "### Findings", ""]
        L += _findings_table(tp["findings"])

    cmds = ctx["commands"]
    L += ["", "## 7. Commands (printed, not run)", "",
          "Order: window 0 once, then window 1 (siblings on every manager; changes nothing that "
          "enforces traffic), then window 2 (rules start using the siblings), then move VMs. "
          "Every command is a dry run as written; add `--apply` only after reviewing its output.", ""]
    for title, key in (("Window 0: capture and WF-A to each site", "window_0_prerequisites"),
                       ("Window 1: siblings", "window_1_siblings"),
                       ("Window 2: rule references", "window_2_rule_refs"),
                       ("Rollback (reverse order)", "rollback")):
        L += [f"### {title}", "", "```bash", *cmds[key], "```", ""]

    L += ["## 8. Known limits", "",
          "- WF-A keeps its push reports under the SOURCE host's export folders, so WF-A to two "
          "sites shares one baseline folder. Its rollback refuses another site's baseline (safe), "
          "but after WF-A to the second site, a default WF-A rollback on the first is blocked; "
          "name the baseline with `--from-baseline`.",
          "- An apply that sends nothing still writes a newer baseline (pending item #11); prefer "
          "`--from-baseline` on rollbacks.",
          "- Palo rules are not generated yet; this plan covers the address objects, tags and "
          "dynamic groups the rules will reference."]
    return align_markdown_tables("\n".join(L)) + "\n"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("WHAT IT DOES", 1)[1])
    p.add_argument("--map", required=True, help="Multi-site CSV: old_subnet,<site>,<site>...")
    p.add_argument("--capture", help="Source capture bundle (capture_nsx_state --live-query).")
    p.add_argument("--source", help="Source manager alias (default: from the capture manifest).")
    p.add_argument("--domain-id", default="default")
    p.add_argument("--suffix", action="append", metavar="VIEW=SUFFIX",
                   help="Override a view's sibling suffix (default _<lmN>_ips).")
    p.add_argument("--in-use", action="append", metavar="SITE=FILE",
                   help="Addresses already in use at SITE (one host/CIDR/range per line).")
    p.add_argument("--vm-snapshot", help="VM rule snapshot (host dir, bundle dir or file) "
                                         "for the Palo tag plan.")
    p.add_argument("--sg-threshold", type=int, default=10,
                   help="Groups with MORE member VMs than this get a security_group tag (default 10).")
    p.add_argument("--hostname-scope", default="hostname",
                   help="NSX tag scope holding the hostname (default hostname). Every VM must "
                        "carry it; there is no fallback to the VM name.")
    p.add_argument("--asl-scope", default="asl_id", help="NSX tag scope holding asl_id.")
    p.add_argument("--all-groups", action="store_true",
                   help="Tag-plan every group, not only those rules reference.")
    p.add_argument("--output-base", default=str(REPO_ROOT / "nsx_multisite_runs"))
    p.add_argument("--retain", type=int, default=0, help="Keep the newest N runs (0 = all).")
    p.add_argument("--check-map-only", action="store_true",
                   help="Validate the map and write the report; build nothing.")
    args = p.parse_args(argv)

    sm = load_site_map(args.map)
    capture = Path(args.capture).resolve() if args.capture else None
    manifest: Dict[str, Any] = {}
    if capture and not args.check_map_only:
        try:
            manifest = read_json(capture / "manifest.json")
        except (OSError, ValueError) as exc:
            print(f"Cannot read capture manifest: {exc}", file=sys.stderr)
            return 2
    origin = manifest.get("captured_from") or {}
    source_host = origin.get("manager_host") or "map-check"
    source = args.source or origin.get("manager_alias") or "source"

    host_dir = Path(args.output_base) / source_host
    run_dir = new_run_dir(host_dir)
    ts = run_dir.name
    setup_logging("plan_multisite", run_dir / "logs", run_ts=ts)
    log.info("Run directory: %s", run_dir)

    ctx: Dict[str, Any] = {"source": source, "generated_at": utc_now_iso(), "site_map": sm,
                           "map_findings": [], "map_reserved": {}, "map_only": True}
    map_findings = check_site_map(sm) if sm.ok else []
    ctx["map_findings"] = map_findings
    if sm.ok:
        from common.subnet_map import reserved_spans
        ctx["map_reserved"] = {s: [ipspan.fmt(x) for x in reserved_spans(sm, s)] for s in sm.sites}
    write_json(run_dir / "map_check.json", {"errors": sm.errors, "findings": map_findings,
                                            "sites": sm.sites})
    map_blocked = bool(sm.errors) or any(f["severity"] == "error" for f in map_findings)

    def finish(code: int, reason: Optional[str] = None) -> int:
        if reason:
            log.error("%s", reason)
            ctx["refused"] = reason
        write_text(run_dir / "report.md", render_report(ctx))
        if code != 2:
            update_latest(host_dir, run_dir)
        removed = prune_old(host_dir, args.retain)
        if removed:
            log.info("Pruned %d old run(s): %s", len(removed), ", ".join(removed))
        log.info("Report: %s", run_dir / "report.md")
        print(run_dir / "report.md")
        return code

    if map_blocked:
        return finish(2, f"the map has {len(sm.errors)} error(s) and "
                         f"{sum(f['severity'] == 'error' for f in map_findings)} blocking "
                         f"finding(s); see section 1.")
    if args.check_map_only:
        log.info("Map OK: %d rows, sites %s.", len(sm.sources), ", ".join(sm.sites))
        return finish(0)
    if not capture:
        return finish(2, "--capture is required unless --check-map-only.")

    from nsx.captured_source import validate_capture
    try:
        validate_capture(capture, source_host, args.domain_id)
    except (ValueError, OSError) as exc:
        return finish(2, f"capture gate failed: {exc}")
    ctx.update(map_only=False, capture=capture, capture_at=manifest.get("captured_at"))

    for s in sm.sites:
        if s not in PUSH_TARGETS:
            log.warning("Site column %r is not a manager the push tools accept; its commands "
                        "will not run as written.", s)
    if source in sm.sites:
        return finish(2, f"the source {source} is also a site column; a manager cannot "
                         f"be its own target.")

    views = P.build_views(source, sm.sites, _kv(args.suffix, "--suffix"))
    problems = P.suffix_problems(views, _reserved_suffixes())
    if problems:
        return finish(2, "suffix problem: " + "; ".join(problems))
    for v in views:
        if v.mapped:
            v.csv = run_dir / "maps" / f"{v.key}.csv"
            n = sm.write_two_column(v.key, v.csv)
            log.info("Wrote %s (%d rows)", repo_relative(v.csv), n)
    for v in views:
        if not _build_view(v, capture, source_host, args.domain_id, run_dir):
            return finish(2, f"the sibling build for view {v.key} failed; see "
                             f"logs/build_{v.key}.log.")
    P.load_views(views)
    matrix = P.deployment(views)
    ctx.update(views=views, matrix=matrix,
               commands=P.commands(run_dir, source, views, matrix))

    in_use_given: Dict[str, int] = {}
    in_use_rows: List[Dict[str, Any]] = []
    for site, path in _kv(args.in_use, "--in-use").items():
        spans, bad = P.parse_in_use(read_text(path))
        for b in bad:
            log.warning("--in-use %s: cannot parse %r", site, b)
        in_use_given[site] = len(spans)
        view = next((v for v in views if v.key == site and v.mapped), None)
        if view is None:
            log.warning("--in-use %s: no such site column; ignored.", site)
            continue
        in_use_rows += P.in_use_findings(view, spans)
    ctx.update(in_use_given=in_use_given, in_use_findings=in_use_rows)

    tag_plan = None
    if args.vm_snapshot:
        snap_path = Path(args.vm_snapshot)
        if snap_path.is_dir():
            bundle = find_bundle(snap_path)
            snap_path = (bundle / "vm_rule_snapshot.json") if bundle else snap_path / "missing"
        snapshot = read_json(snap_path)
        if snapshot.get("manager_host") and snapshot["manager_host"] != source_host:
            log.warning("VM snapshot is from %s but the capture is from %s.",
                        snapshot["manager_host"], source_host)
        if not snapshot.get("complete", True):
            log.warning("VM snapshot is marked incomplete; the tag plan may miss members.")
        tag_plan = build_tag_plan(
            snapshot,
            TagOptions(threshold=args.sg_threshold, hostname_scope=args.hostname_scope,
                       asl_scope=args.asl_scope, all_groups=args.all_groups),
            sm, sm.sites)
        write_json(run_dir / "palo_tag_plan.json", tag_plan)
        ctx.update(tag_plan=tag_plan, snapshot_path=snap_path,
                   snapshot_at=snapshot.get("captured_at"))

    write_text(run_dir / "commands.txt",
               "\n\n".join(f"# {k}\n" + "\n".join(v) for k, v in ctx["commands"].items()) + "\n")
    blocking = (sum(r["severity"] == "error" for r in in_use_rows)
                + (tag_plan["counts"]["errors"] if tag_plan else 0))
    summary = {
        "generated_at": ctx["generated_at"], "run_dir": str(run_dir), "source": source,
        "source_host": source_host, "sites": sm.sites, "map": str(sm.path),
        "capture": str(capture), "views": {v.key: {"suffix": v.suffix, **P.view_counts(v)}
                                           for v in views},
        "matrix": matrix, "in_use_collisions": sum(r["kind"] == "collision" for r in in_use_rows),
        "tag_plan": tag_plan["counts"] if tag_plan else None, "blocking_findings": blocking,
    }
    write_json(run_dir / "summary.json", summary)
    write_json(run_dir / "plan.json", {
        **summary,
        "views": [{"key": v.key, "suffix": v.suffix, "mapped": v.mapped,
                   "csv": str(v.csv) if v.csv else None, "bundle": str(v.bundle),
                   "reserved": P.reserved_addresses(v) if v.mapped else []} for v in views],
        "deploy_dirs": {t: {k: str(P.target_dir(run_dir, t, k)) for k in keys}
                        for t, keys in matrix.items()},
        "in_use_findings": in_use_rows, "commands": ctx["commands"],
    })
    log.info("Views: %s", ", ".join(f"{v.key}={P.view_counts(v)['siblings']}" for v in views))
    log.info("Blocking findings: %d", blocking)
    return finish(1 if blocking else 0)


if __name__ == "__main__":
    sys.exit(main())
