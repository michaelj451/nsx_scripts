#!/usr/bin/env python3
"""tools/nsx/critical_rules/step4_verify.py

Critical-rules copy, step 4 of 4: verify the target against the two bundles.

Read only. Compares every service, group, policy and rule the two bundles hold
with the customer objects on the target. PASS means nothing missing and
nothing extra; exit code 0 on PASS, 1 on FAIL.

USAGE:
    python tools/nsx/critical_rules/step4_verify.py --source nsx-lm2 --target nsx-lm3

Runbook: docs/nsx/RUNBOOK_CRITICAL_RULES.md
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "app"))
from common.logs import setup_logging                  # noqa: E402
import nsx.critical_rules as cr                        # noqa: E402

log = logging.getLogger("critical_rules")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--source", required=True, choices=cr.LM_CHOICES)
    p.add_argument("--target", required=True, choices=cr.LM_CHOICES)
    p.add_argument("--run", help="run folder (default: newest for this source/target)")
    args = p.parse_args()

    run = cr.resolve_run(args.source, args.target, args.run)
    rec = cr.load_record(run)
    cr.check_pair(rec, args.source, args.target)
    pull = rec.get("steps", {}).get("pull") or {}
    if not pull.get("ok"):
        raise SystemExit(f"no successful step 2 in {run}; nothing to verify against")
    setup_logging("step4_verify", run / "logs")
    log.info("Run: %s", run)

    from nsx.nsx_policy_client import NsxPolicyClient
    client = NsxPolicyClient(nsxmanager=rec["target_host"], federation_global=False)
    want = cr.merge_objects([cr.bundle_objects(Path(pull["infra"])), cr.bundle_objects(Path(pull["hits"]))])
    result = cr.compare(want, cr.target_objects(client))

    print()
    print(f"Verify {rec['target_host']} against {run.name}:")
    bad = 0
    for k in cr.CLASSES:
        r = result[k]
        bad += len(r["missing"]) + len(r["extra"])
        print(f"  {k:<9} expected {len(r['expected']):>3}  missing {len(r['missing'])}  extra {len(r['extra'])}")
        for x in r["missing"]:
            print(f"      MISSING {x}")
        for x in r["extra"]:
            print(f"      EXTRA   {x}")
    print(f"VERIFY {'PASS' if bad == 0 else 'FAIL'}")

    cr.record_step(run, "verify", {"ok": bad == 0, "result": result})
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
