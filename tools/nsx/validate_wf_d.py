#!/usr/bin/env python3
"""tools/nsx/validate_wf_d.py

Read-only post-deployment validator for Workflow D.

Confirms the additive contracts that WF-D promises:

  G1  No customer group present in the baseline was deleted from the target.
  G2  No IP present in any baseline group was removed from the target.
      (Phase 2 forced strip is its own separate validation — this check
      reflects the pre-Phase-2 additive contract. If Phase 2 was applied,
      pass --phase-2-applied to limit G2 to groups WITHOUT siblings.)
  G3  Every Condition / PathExpression entry that was in a baseline group
      is still present in the current target payload (no tag-match or
      segment-ref silently dropped).
  S1  For every (original, sibling) pair in sibling_map.json, both groups
      exist on the target (siblings were created).
  S2  Every sibling carries `group_type: [IPAddress]`.
  R1  For every rule on the target: if its `source_groups` or
      `destination_groups` reference an original that has a sibling per
      sibling_map.json, the rule also references the sibling. This is the
      amend-refs "every rule got its update" check.
  R2  (Optional, with --rules-baseline) Every customer rule in the rules
      baseline still exists on the target (no rule was deleted).

OUTPUT:
  $NSX_LOG_DIR/wf_d_validation/<target-host>/
    validation_report.json    full findings
    summary.json              counters
    logs/

EXIT CODE:
  0  All checks passed.
  1  One or more failures.

Read-only against NSX — never PATCH/PUT/DELETE.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.cli_bootstrap import init_cli            # noqa: E402
from nsx.nsx_constants import resolve_manager, nsx_log_dir   # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient            # noqa: E402

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]


# =============================================================================
# Recursive walkers (mirror build_sibling_groups.py)
# =============================================================================

def _collect_ips(expression: List[Any]) -> List[str]:
    out: Set[str] = set()

    def _walk(items: List[Any]) -> None:
        for e in items or []:
            if not isinstance(e, dict):
                continue
            if e.get("resource_type") == "IPAddressExpression":
                for ip in (e.get("ip_addresses") or []):
                    if isinstance(ip, str):
                        out.add(ip)
            elif e.get("resource_type") == "NestedExpression":
                _walk(e.get("expressions"))
    _walk(expression)
    return sorted(out)


def _collect_conditions(expression: List[Any]) -> List[Tuple[str, str, str]]:
    """Return sorted list of (member_type, key, value) for each Condition."""
    out: List[Tuple[str, str, str]] = []

    def _walk(items: List[Any]) -> None:
        for e in items or []:
            if not isinstance(e, dict):
                continue
            if e.get("resource_type") == "Condition":
                out.append((e.get("member_type") or "", e.get("key") or "", e.get("value") or ""))
            elif e.get("resource_type") == "NestedExpression":
                _walk(e.get("expressions"))
    _walk(expression)
    return sorted(out)


def _collect_path_refs(expression: List[Any]) -> List[str]:
    """Return sorted list of segment paths referenced (PathExpression)."""
    out: Set[str] = set()

    def _walk(items: List[Any]) -> None:
        for e in items or []:
            if not isinstance(e, dict):
                continue
            if e.get("resource_type") == "PathExpression":
                for p in (e.get("paths") or []):
                    if isinstance(p, str):
                        out.add(p)
            elif e.get("resource_type") == "NestedExpression":
                _walk(e.get("expressions"))
    _walk(expression)
    return sorted(out)


# =============================================================================
# I/O
# =============================================================================

def _setup_logging(reports_dir: Path) -> Path:
    log_dir_path = Path(nsx_log_dir).expanduser().resolve()
    log_dir_path.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    bundle_log = (reports_dir / f"validate_wf_d_{RUN_TS}.log").resolve()
    global_log = (log_dir_path / f"validate_wf_d_{RUN_TS}.log").resolve()
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                            "%Y-%m-%dT%H:%M:%S")
    for h in (logging.StreamHandler(), logging.FileHandler(bundle_log, encoding="utf-8"),
              logging.FileHandler(global_log, encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    return bundle_log


def _load_baseline(path: Path) -> Dict[str, Dict[str, Any]]:
    """A WF-D push baseline is JSON keyed by group_id, value = full payload."""
    if not path.exists():
        raise SystemExit(f"--baseline file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"--baseline file is not a dict: {path}")
    return data


def _load_sibling_map(path: Path) -> Dict[str, str]:
    """Returns {original_id: sibling_id}."""
    if not path.exists():
        raise SystemExit(f"--sibling-map file not found: {path}")
    doc = json.loads(path.read_text(encoding="utf-8"))
    out: Dict[str, str] = {}
    for entry in doc.get("map", []) or []:
        oid = entry.get("original_id")
        sid = entry.get("sibling_id")
        if oid and sid:
            out[oid] = sid
    return out


def _live_fetch_groups(client: NsxPolicyClient, domain_id: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for g in client.list_groups(domain_id=domain_id):
        if g.get("_system_owned") or g.get("marked_for_delete"):
            continue
        gid = g.get("id")
        if gid:
            out[gid] = g
    return out


def _live_fetch_rules(client: NsxPolicyClient, domain_id: str) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for pol in client.list_security_policies(domain_id=domain_id):
        if pol.get("_system_owned"):
            continue
        pid = pol.get("id")
        if not pid:
            continue
        try:
            for rule in client.list_security_rules(security_policy_id=pid, domain_id=domain_id):
                if rule.get("_system_owned"):
                    continue
                rules.append({**rule, "_policy_id": pid})
        except Exception as exc:
            log.warning("Could not fetch rules for policy %s: %s", pid, exc)
    return rules


def _ref_to_group_id(ref: str) -> str:
    """Last segment of /infra/domains/<d>/groups/<gid> -> <gid>. Returns '' for ANY etc."""
    if not isinstance(ref, str) or "/" not in ref:
        return ""
    return ref.rsplit("/", 1)[-1]


# =============================================================================
# Checks
# =============================================================================

def _check_groups(baseline: Dict[str, Dict[str, Any]],
                  current: Dict[str, Dict[str, Any]],
                  sibling_map: Dict[str, str],
                  phase_2_applied: bool) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    pair_originals = set(sibling_map.keys())

    for gid, before_g in baseline.items():
        # G1
        if gid not in current:
            findings.append({
                "severity": "CRITICAL", "check": "G1_group_exists",
                "group_id": gid, "msg": "Group present in baseline is missing from target (was deleted).",
            })
            continue

        cur_g = current[gid]

        # G2 — IP preservation (unless Phase 2 stripped this exact group)
        before_ips = _collect_ips(before_g.get("expression") or [])
        cur_ips    = _collect_ips(cur_g.get("expression") or [])
        missing_ips = sorted(set(before_ips) - set(cur_ips))
        if missing_ips:
            if phase_2_applied and gid in pair_originals:
                # Phase 2 explicitly strips IPs from originals whose siblings exist.
                # That's the only forced-removal path the toolkit offers, so report
                # it as INFO rather than CRITICAL.
                findings.append({
                    "severity": "INFO", "check": "G2_phase2_strip",
                    "group_id": gid, "msg": f"Phase-2 strip removed {len(missing_ips)} IPs from this group (sibling carries the mapped equivalents).",
                    "ips_removed": missing_ips,
                })
            else:
                findings.append({
                    "severity": "CRITICAL", "check": "G2_no_ip_removed",
                    "group_id": gid, "msg": f"Group lost {len(missing_ips)} IPs since baseline.",
                    "ips_removed": missing_ips,
                })

        # G3 — Condition / PathExpression preservation
        before_conds = _collect_conditions(before_g.get("expression") or [])
        cur_conds    = _collect_conditions(cur_g.get("expression") or [])
        missing_conds = [c for c in before_conds if c not in cur_conds]
        if missing_conds:
            findings.append({
                "severity": "CRITICAL", "check": "G3_conditions_preserved",
                "group_id": gid, "msg": f"Group lost {len(missing_conds)} Condition(s) since baseline.",
                "conditions_removed": [
                    {"member_type": m, "key": k, "value": v} for (m, k, v) in missing_conds
                ],
            })
        before_paths = _collect_path_refs(before_g.get("expression") or [])
        cur_paths    = _collect_path_refs(cur_g.get("expression") or [])
        missing_paths = sorted(set(before_paths) - set(cur_paths))
        if missing_paths:
            findings.append({
                "severity": "WARNING", "check": "G3_path_refs_preserved",
                "group_id": gid, "msg": f"Group lost {len(missing_paths)} PathExpression entries since baseline.",
                "paths_removed": missing_paths,
            })

    # S1, S2 — each sibling exists with correct group_type
    for oid, sid in sibling_map.items():
        if sid not in current:
            findings.append({
                "severity": "CRITICAL", "check": "S1_sibling_exists",
                "original_id": oid, "sibling_id": sid,
                "msg": f"Sibling group {sid} (paired with original {oid}) is missing from target.",
            })
            continue
        sib = current[sid]
        gt = sib.get("group_type") or []
        if "IPAddress" not in gt:
            findings.append({
                "severity": "WARNING", "check": "S2_sibling_group_type",
                "sibling_id": sid, "msg": f"Sibling {sid} does not carry group_type=[IPAddress] (got {gt}).",
            })

    return findings


def _check_rules(current_rules: List[Dict[str, Any]],
                 sibling_map: Dict[str, str],
                 rules_baseline_path: Optional[Path]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # R1 — each rule that references an original-with-sibling should also reference the sibling
    for rule in current_rules:
        pid = rule.get("_policy_id")
        rid = rule.get("id")
        for field in ("source_groups", "destination_groups"):
            refs = rule.get(field) or []
            ref_ids: Set[str] = {_ref_to_group_id(r) for r in refs}
            for orig_id, sib_id in sibling_map.items():
                if orig_id in ref_ids and sib_id not in ref_ids:
                    findings.append({
                        "severity": "CRITICAL", "check": "R1_sibling_ref_present",
                        "policy_id": pid, "rule_id": rid, "field": field,
                        "original_id": orig_id, "sibling_id": sib_id,
                        "msg": f"Rule {pid}/{rid}.{field} references {orig_id} but is missing {sib_id} — amend-refs did not run for this rule.",
                    })

    # R2 — rule preservation against optional baseline
    if rules_baseline_path is not None:
        try:
            doc = json.loads(rules_baseline_path.read_text(encoding="utf-8"))
        except Exception as exc:
            findings.append({
                "severity": "WARNING", "check": "R2_rules_baseline_load",
                "msg": f"Could not load rules baseline at {rules_baseline_path}: {exc}",
            })
        else:
            # Some toolkit baselines key by "<policy_id>/<rule_id>", some by rule_id only.
            # Accept either; the check is "all rule IDs in baseline are still on target".
            current_keys: Set[str] = set()
            for r in current_rules:
                current_keys.add(r.get("id") or "")
                current_keys.add(f"{r.get('_policy_id') or ''}/{r.get('id') or ''}")
            for key in (doc.keys() if isinstance(doc, dict) else []):
                if key not in current_keys:
                    findings.append({
                        "severity": "CRITICAL", "check": "R2_rule_exists",
                        "baseline_key": key,
                        "msg": f"Rule {key} present in baseline is missing from target.",
                    })

    return findings


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES,
                   help="Live target to validate against (read-only GETs).")
    p.add_argument("--baseline", required=True,
                   help="Path to a WF-D push baseline JSON (e.g. nsx_sibling_groups/"
                        "<host>/push_report/baselines/<ts>_target_baseline.json). "
                        "This is the 'before' snapshot of groups.")
    p.add_argument("--sibling-map", required=True,
                   help="Path to the sibling_map.json from build_sibling_groups.")
    p.add_argument("--rules-baseline", default=None,
                   help="(Optional) Path to a rules baseline JSON for R2 rule-preservation check.")
    p.add_argument("--phase-2-applied", action="store_true",
                   help="Set this flag if Phase 2 (--intentional-ip-removal) was applied. "
                        "G2 will then DOWNGRADE IP-removal findings on tag-side originals "
                        "(those with siblings) from CRITICAL to INFO, since Phase 2 is the "
                        "designated path that DOES remove IPs from those groups.")
    p.add_argument("--domain-id", default="default")
    p.add_argument("--federation-global", action="store_true")
    p.add_argument("--output-base", default=None,
                   help="Output root; default: $NSX_LOG_DIR.")
    args = p.parse_args()

    init_cli()

    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Target manager not defined: {args.target}")

    output_base = (Path(args.output_base).expanduser().resolve()
                   if args.output_base else Path(nsx_log_dir))
    reports_dir = output_base / "wf_d_validation" / target_host
    log_file = _setup_logging(reports_dir / "logs")

    baseline_path = Path(args.baseline).expanduser().resolve()
    sib_map_path  = Path(args.sibling_map).expanduser().resolve()
    rules_baseline_path = Path(args.rules_baseline).expanduser().resolve() if args.rules_baseline else None

    log.info("=" * 60)
    log.info("WF-D VALIDATION")
    log.info("  Target            : %s (%s)", args.target, target_host)
    log.info("  Group baseline    : %s", baseline_path)
    log.info("  Sibling map       : %s", sib_map_path)
    log.info("  Rules baseline    : %s", rules_baseline_path or "(none — R2 skipped)")
    log.info("  Phase 2 applied   : %s", args.phase_2_applied)
    log.info("  Reports           : %s", reports_dir)
    log.info("=" * 60)

    baseline    = _load_baseline(baseline_path)
    sibling_map = _load_sibling_map(sib_map_path)

    log.info("Loaded baseline: %d groups", len(baseline))
    log.info("Loaded sibling map: %d pairs", len(sibling_map))

    client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global)
    log.info("Fetching live groups from %s ...", target_host)
    current_groups = _live_fetch_groups(client, args.domain_id)
    log.info("  current customer groups: %d", len(current_groups))
    log.info("Fetching live rules ...")
    current_rules = _live_fetch_rules(client, args.domain_id)
    log.info("  current customer rules:  %d", len(current_rules))

    findings: List[Dict[str, Any]] = []
    findings.extend(_check_groups(baseline, current_groups, sibling_map, args.phase_2_applied))
    findings.extend(_check_rules(current_rules, sibling_map, rules_baseline_path))

    by_sev: Dict[str, int] = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    by_check: Dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity", "INFO")] = by_sev.get(f.get("severity", "INFO"), 0) + 1
        c = f.get("check", "?")
        by_check[c] = by_check.get(c, 0) + 1

    overall = "PASS" if by_sev["CRITICAL"] == 0 else "FAIL"

    summary = {
        "ran_at":       datetime.now(timezone.utc).isoformat(),
        "target":       f"alias:{args.target} ({target_host})",
        "overall":      overall,
        "baseline":     str(baseline_path),
        "sibling_map":  str(sib_map_path),
        "phase_2_applied": args.phase_2_applied,
        "counts": {
            "baseline_groups":  len(baseline),
            "current_groups":   len(current_groups),
            "current_rules":    len(current_rules),
            "sibling_pairs":    len(sibling_map),
            "findings_total":   len(findings),
            "by_severity":      by_sev,
            "by_check":         by_check,
        },
        "log_file":     str(log_file),
    }

    (reports_dir / "validation_report.json").write_text(
        json.dumps({"summary": summary, "findings": findings}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (reports_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8",
    )

    log.info("=" * 60)
    log.info("WF-D VALIDATION — %s", overall)
    log.info("  Baseline groups       : %d", len(baseline))
    log.info("  Current customer groups: %d", len(current_groups))
    log.info("  Sibling pairs in map  : %d", len(sibling_map))
    log.info("  Findings              : %d total  CRITICAL=%d  WARNING=%d  INFO=%d",
             len(findings), by_sev["CRITICAL"], by_sev["WARNING"], by_sev["INFO"])
    if by_check:
        log.info("  By check:")
        for c, n in sorted(by_check.items()):
            log.info("    %-30s : %d", c, n)
    log.info("Report: %s", reports_dir)
    log.info("=" * 60)
    print(json.dumps(summary, indent=2))

    return 0 if overall == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
