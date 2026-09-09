#!/usr/bin/env python3
"""tools/nsx/verify_avs_run.py

Live, read-only verification that an AVS / WF-C decomposition landed correctly.

Answers the only question that matters after the pushes: does the target now
resolve to the same address space the source did, with the tag criteria and the
IPs living in separate objects?

Six checks, all GET-only:

  V1  every source object exists on the target
      (services, groups, policies, rules; default sections excluded)
  V2  every sibling in sibling_map.json exists on the target
  V3  each sibling's IPs match the SOURCE group's effective IPs exactly
      (source of truth: .../groups/<id>/members/ip-addresses)
  V4  each stripped original on the target carries NO IPAddressExpression
  V5  every rule that referenced an original also references its sibling
  V6  target group membership resolves (no unrealized groups left behind)

V3 is the one that catches the class of bug that made this tool necessary: a
sibling built from reconstructed VM IPs rather than NSX's own answer looks
fine structurally and is quietly missing addresses.

USAGE:
    python tools/nsx/verify_avs_run.py \\
        --source nsx-lm1 --target nsx-lm3 \\
        --sibling-map nsx_avs_runs/v2/nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json \\
        --report-dir nsx_avs_runs/v2/report

Exit code 0 when every check passes, 1 otherwise. Safe as a cutover gate.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from nsx.cli_bootstrap import init_cli                       # noqa: E402
from nsx.nsx_constants import resolve_manager                # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient, NsxApiError  # noqa: E402

log = logging.getLogger("verify_avs_run")

NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2",
                       "nsx-lm3", "nsx-lm4", "nsx-lm5"]
DEFAULT_SECTIONS = {"default-layer2-section", "default-layer3-section"}


def ips_of(group: Dict[str, Any]) -> List[str]:
    """IPs written into a group's own expression (not evaluated membership)."""
    out: set = set()
    for e in group.get("expression", []) or []:
        for ip in e.get("ip_addresses", []) or []:
            out.add(str(ip))
    return sorted(out)


def has_ip_expression(group: Dict[str, Any]) -> bool:
    return any((e or {}).get("resource_type") == "IPAddressExpression"
               for e in group.get("expression", []) or [])


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("USAGE:", 1)[1] if "USAGE:" in __doc__ else None)
    p.add_argument("--source", required=True, choices=NSX_MANAGER_CHOICES)
    p.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES)
    p.add_argument("--sibling-map", required=True,
                   help="sibling_map.json from build_sibling_groups.py")
    p.add_argument("--domain-id", default="default")
    p.add_argument("--report-dir", default=None,
                   help="Write verify_avs_run.json here (default: alongside the sibling map).")
    p.add_argument("--skip-object-parity", action="store_true",
                   help="Skip V1. Use when the target intentionally holds a subset.")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = __import__("time").gmtime
    init_cli()

    smap_path = Path(args.sibling_map).expanduser()
    smap = json.loads(smap_path.read_text(encoding="utf-8"))
    entries = smap.get("map", [])

    src = NsxPolicyClient(nsxmanager=resolve_manager(args.source), federation_global=False)
    tgt = NsxPolicyClient(nsxmanager=resolve_manager(args.target), federation_global=False)
    D = args.domain_id

    checks: List[Dict[str, Any]] = []

    def record(check: str, subject: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": check, "subject": subject, "ok": bool(ok), "detail": detail})
        log.log(logging.INFO if ok else logging.ERROR,
                "  %-4s %-42s %s%s", check, subject[:42], "OK" if ok else "FAIL",
                f"  {detail}" if detail else "")

    # ---- V1: object parity -------------------------------------------------
    if not args.skip_object_parity:
        log.info("V1 object parity (source -> target)")
        s_groups = {g["id"] for g in src.list_groups(domain_id=D) if not g.get("_system_owned")}
        t_groups = {g["id"] for g in tgt.list_groups(domain_id=D) if not g.get("_system_owned")}
        missing = sorted(s_groups - t_groups)
        record("V1", "groups", not missing, f"missing: {missing}" if missing else
               f"{len(s_groups)} present")

        s_svc = {s["id"] for s in src.list_services() if not s.get("_system_owned")}
        t_svc = {s["id"] for s in tgt.list_services() if not s.get("_system_owned")}
        missing = sorted(s_svc - t_svc)
        record("V1", "services", not missing, f"missing: {missing}" if missing else
               f"{len(s_svc)} present")

        s_pol = {p["id"] for p in src.list_security_policies(domain_id=D)
                 if not p.get("_system_owned") and p["id"] not in DEFAULT_SECTIONS}
        t_pol = {p["id"] for p in tgt.list_security_policies(domain_id=D)
                 if not p.get("_system_owned") and p["id"] not in DEFAULT_SECTIONS}
        missing = sorted(s_pol - t_pol)
        record("V1", "policies", not missing, f"missing: {missing}" if missing else
               f"{len(s_pol)} present")

        missing_rules = []
        for pid in sorted(s_pol & t_pol):
            s_r = {r["id"] for r in src.list_security_rules(security_policy_id=pid, domain_id=D)}
            t_r = {r["id"] for r in tgt.list_security_rules(security_policy_id=pid, domain_id=D)}
            missing_rules += [f"{pid}/{r}" for r in sorted(s_r - t_r)]
        record("V1", "rules", not missing_rules,
               f"missing: {missing_rules}" if missing_rules else "all present")

    # ---- V2 / V3 / V4: siblings -------------------------------------------
    log.info("V2 sibling exists / V3 IPs match source truth / V4 original stripped")
    for e in entries:
        sib_id, orig_id = e["sibling_id"], e["original_id"]
        try:
            sib = tgt.get_group(group_id=sib_id, domain_id=D)
        except NsxApiError as exc:
            record("V2", sib_id, False, f"not on target: {exc}")
            continue
        record("V2", sib_id, True, f"{len(ips_of(sib))} ips")

        try:
            truth = sorted(src.get_group_effective_ips(orig_id, domain_id=D))
        except NsxApiError as exc:
            record("V3", sib_id, False, f"source truth unavailable: {exc}")
            truth = None
        if truth is not None:
            got = ips_of(sib)
            extra, missing = sorted(set(got) - set(truth)), sorted(set(truth) - set(got))
            record("V3", sib_id, not missing and not extra,
                   "" if not (missing or extra) else f"missing={missing} extra={extra}")

        try:
            orig = tgt.get_group(group_id=orig_id, domain_id=D)
            record("V4", orig_id, not has_ip_expression(orig),
                   "" if not has_ip_expression(orig) else f"still has {ips_of(orig)}")
        except NsxApiError as exc:
            record("V4", orig_id, False, f"original missing on target: {exc}")

    # ---- V5: rules reference the sibling alongside the original ------------
    log.info("V5 rule references")
    by_orig = {e["original_id"]: e["sibling_id"] for e in entries}
    for pol in tgt.list_security_policies(domain_id=D):
        if pol.get("_system_owned") or pol["id"] in DEFAULT_SECTIONS:
            continue
        for rule in tgt.list_security_rules(security_policy_id=pol["id"], domain_id=D):
            for field in ("source_groups", "destination_groups"):
                refs = rule.get(field) or []
                for ref in refs:
                    oid = str(ref).rsplit("/", 1)[-1]
                    sib = by_orig.get(oid)
                    if not sib:
                        continue
                    want = f"/infra/domains/{D}/groups/{sib}"
                    record("V5", f"{pol['id']}/{rule['id']}.{field}", want in refs,
                           "" if want in refs else f"missing {sib}")

    # ---- V6: target membership realizes ------------------------------------
    log.info("V6 target membership realizes")
    unrealized = []
    for g in tgt.list_groups(domain_id=D):
        if g.get("_system_owned"):
            continue
        try:
            tgt.get_group_effective_ips(g["id"], domain_id=D, realize_attempts=1)
        except NsxApiError:
            unrealized.append(g["id"])
    record("V6", "all target groups", not unrealized,
           f"unrealized: {unrealized}" if unrealized else
           "every group resolves")

    failed = [c for c in checks if not c["ok"]]
    out_dir = Path(args.report_dir).expanduser() if args.report_dir else smap_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "verify_avs_run.json").write_text(json.dumps({
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "source": args.source, "target": args.target,
        "sibling_map": str(smap_path),
        "checks_total": len(checks), "checks_failed": len(failed),
        "ok": not failed, "checks": checks,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    log.info("=" * 62)
    log.info("VERIFY %s: %d checks, %d failed", "OK" if not failed else "FAILED",
             len(checks), len(failed))
    log.info("Report: %s", out_dir / "verify_avs_run.json")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
