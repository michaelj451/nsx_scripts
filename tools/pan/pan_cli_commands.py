#!/usr/bin/env python3
"""tools/pan/pan_cli_commands.py

Paste-ready PAN-OS command line text from a run's Palo Alto plan (Mike,
2026-10-09). The Palo push DRY RUN writes it on its own (`nsx_pan_mirror.py
push` without --apply, which a migration request's report and a run's palo
phase both run), for exactly the objects the dry run found missing on
Panorama. `--no-palo-cli` on a request (or `--no-cli-commands` on the push)
leaves it out. This script writes the same text afterwards, by hand, from
any finished run. No device contact.

Default: from the newest push dry run beside the plan (push_*_dryrun.json):

  pan_set_commands.txt     one `set` per missing object, in creation order
                           (addresses, address groups, services, service
                           groups, then the security rules in NSX order).
                           Paste into configure mode to create them.
  pan_delete_commands.txt  the matching `delete` commands, newest first;
                           removes only what the set file creates.

--all-objects: every object of the plan, when the device could not be
checked, as pan_all_set_commands.txt / pan_all_delete_commands.txt (these
include objects that may already exist; check before pasting).

Both files hold commands only: no comments, no `configure`, no `commit`.
Each line is built from the same REST entry `nsx_pan_mirror.py push` sends.

On Panorama:
    set cli scripting-mode on
    configure
    (paste pan_set_commands.txt)
    exit
then review and commit yourself.

USAGE
    python tools/pan/pan_cli_commands.py --plan migration_requests/nsx-lm1_to_nsx-lm3/latest
    python tools/pan/pan_cli_commands.py --plan migration_requests/nsx-lm1_to_nsx-lm3/latest --all-objects

--plan takes a plan.json, the folder holding it, or a migration request or
run folder (its palo/plan.json).
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from common.fileio import read_json                               # noqa: E402
from common.logs import setup_logging                             # noqa: E402
from common.paths import repo_relative                            # noqa: E402
from multisite.pan_set_commands import write_files, write_from_dryrun  # noqa: E402

log = logging.getLogger("pan_cli_commands")


def resolve_plan(path: str) -> Path:
    """A plan.json, its folder, or a run folder whose palo/ holds it."""
    p = Path(path).expanduser().resolve()
    for cand in (p, p / "plan.json", p / "palo" / "plan.json"):
        if cand.is_file() and cand.name == "plan.json":
            return cand
    raise SystemExit(f"No plan.json at {path} (looked in it, and in its palo/ folder).")


def newest_dryrun(plan_path: Path) -> Optional[Path]:
    found = sorted(plan_path.parent.glob("push_*_dryrun.json"))
    return found[-1] if found else None


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("\n\n", 1)[1])
    p.add_argument("--plan", required=True,
                   help="plan.json, its folder, or a migration request / run folder")
    p.add_argument("--all-objects", action="store_true",
                   help="Every object of the plan, without a dry run (pan_all_*_commands.txt).")
    args = p.parse_args(argv)
    setup_logging("pan_cli_commands", None)
    plan_path = resolve_plan(args.plan)
    if args.all_objects:
        writes = read_json(plan_path).get("writes") or []
        if not writes:
            raise SystemExit(f"{plan_path} has no objects (empty plan).")
        paths = write_files(plan_path.parent, "pan_all_", writes)
        log.info("Every object of the plan (%d), not checked against the device: %s", len(writes),
                 repo_relative(paths[0]))
    else:
        dry = newest_dryrun(plan_path)
        if dry is None:
            raise SystemExit(f"No push dry run beside {plan_path}: run the dry run first "
                             "(nsx_pan_mirror.py push --plan ..., or the request's preview --part palo), "
                             "or pass --all-objects.")
        doc = read_json(dry)
        paths = write_from_dryrun(dry, doc)[2:]
        log.info("From dry run %s: %d missing object(s)", repo_relative(dry), (doc.get("summary") or {}).get(
            "would_create", 0))
    log.info("Paste file (configure mode): %s", repo_relative(paths[0]))
    log.info("Undo file (newest first): %s", repo_relative(paths[1]))
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
