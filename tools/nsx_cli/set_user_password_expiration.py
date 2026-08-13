#!/usr/bin/env python3
"""
set_user_password_expiration.py

NSX appliance-node CLI tool: manage the password-expiration policy of a local
appliance user (admin / audit / root / guestuser*) on an NSX Manager or
Global Manager.

This is the API equivalent of the NSX appliance CLI command
`set user <name> password-expiration <days>` (and `clear user <name>
password-expiration`). NSX computes a local user's status from
`last_password_change + password_change_frequency`; once that window is
exceeded the account flips to PASSWORD_EXPIRED and NSX forces a password
reset at next login. Setting `password_change_frequency` to 0 disables
expiration entirely, which clears the "you must reset your password"
requirement.

Endpoints (per-appliance node API, NOT policy/federation):
  GET /api/v1/node/users                 -> list local users
  PUT /api/v1/node/users/<userid>        -> update password_change_frequency

Safety model (matches the rest of the toolkit):
  - Dry-run is the DEFAULT. It reads the user's current state and prints the
    intended change. No write happens without --apply.
  - --apply performs the PUT, then re-reads the user and prints before/after.
  - The password itself is NEVER sent or changed by this tool. Only the
    expiration policy (password_change_frequency, in days) is touched.

Examples:
  # Dry-run: show what turning off expiration for audit would do
  python tools/nsx_cli/set_user_password_expiration.py --target nsx-gm1 --user audit

  # Apply: turn OFF the password-reset requirement for audit (freq -> 0)
  python tools/nsx_cli/set_user_password_expiration.py --target nsx-gm1 --user audit --apply

  # Revert: put the 90-day expiration policy back
  python tools/nsx_cli/set_user_password_expiration.py --target nsx-gm1 --user audit --frequency 90 --apply

  # Disable password expiration for EVERY local user on a manager
  python tools/nsx_cli/set_user_password_expiration.py --target nsx-gm1 --all-users --apply
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make `app/` importable whether run as `python tools/nsx_cli/foo.py` or with
# app already on PYTHONPATH (mirrors tools/nsx/*).
sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))

from nsx.cli_bootstrap import init_cli                        # noqa: E402
from nsx.nsx_constants import resolve_manager, nsx_log_dir    # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient, NsxApiError  # noqa: E402

log = logging.getLogger(__name__)

NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2",
                       "nsx-lm3", "nsx-lm4"]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

NODE_USERS_PATH = "/node/users"          # relative to FABRIC_ROOT (/api/v1)


# =============================================================================
# Logging
# =============================================================================

def output_dir(host: str) -> Path:
    base = Path(nsx_log_dir).expanduser().resolve()
    d = base / "reports" / "user_password_expiration" / host / RUN_TS
    (d / "logs").mkdir(parents=True, exist_ok=True)
    return d


def setup_logging(out_dir: Path) -> Path:
    log_file = (out_dir / "logs" / f"set_user_password_expiration_{RUN_TS}.log").resolve()
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                            "%Y-%m-%dT%H:%M:%S")
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(ch)
    root.addHandler(fh)
    log.info("Logging to %s", log_file)
    return log_file


# =============================================================================
# Node-user helpers (fabric /api/v1/node/users)
# =============================================================================

def list_node_users(client: NsxPolicyClient) -> List[Dict[str, Any]]:
    resp = client._get(client._fabric_path(NODE_USERS_PATH))
    return resp.get("results", []) if isinstance(resp, dict) else []


def find_user(users: List[Dict[str, Any]], *, username: Optional[str],
              userid: Optional[int]) -> Optional[Dict[str, Any]]:
    for u in users:
        if userid is not None and u.get("userid") == userid:
            return u
        if username is not None and str(u.get("username", "")).lower() == username.lower():
            return u
    return None


def summarize(u: Dict[str, Any]) -> str:
    return (f"userid={u.get('userid')} username={u.get('username')!r} "
            f"status={u.get('status')} "
            f"password_change_frequency={u.get('password_change_frequency')} "
            f"last_password_change={u.get('last_password_change')}")


def select_users(users: List[Dict[str, Any]], *, username: Optional[str],
                 userid: Optional[int], all_users: bool) -> List[Dict[str, Any]]:
    if all_users:
        return list(users)
    u = find_user(users, username=username, userid=userid)
    return [u] if u else []


def plan_and_apply(client: NsxPolicyClient, user: Dict[str, Any],
                   frequency: int, apply: bool) -> str:
    """Log the plan for one user and, if apply, perform the PUT.

    Returns an outcome string: 'noop' | 'planned' | 'applied' | 'error'.
    """
    uname = user.get("username")
    current = user.get("password_change_frequency")
    if current == frequency:
        log.info("[%s] no change needed (freq already %s, status=%s)",
                 uname, frequency, user.get("status"))
        return "noop"

    intent = ("disable expiration" if frequency == 0
              else f"expire every {frequency}d")
    log.info("[%s] PLAN freq %s -> %s (%s) status=%s",
             uname, current, frequency, intent, user.get("status"))
    if not apply:
        return "planned"
    try:
        update_password_frequency(client, user, frequency)
        return "applied"
    except NsxApiError as e:
        log.error("[%s] PUT failed: %s", uname, e)
        return "error"


def update_password_frequency(client: NsxPolicyClient, user: Dict[str, Any],
                              frequency: int) -> Dict[str, Any]:
    """PUT a minimal body that changes ONLY the expiration policy.

    We preserve full_name if present so the account's display name is not
    wiped, but we never include any password field. read-only fields
    (status, last_password_change) are intentionally omitted.
    """
    userid = user["userid"]
    payload: Dict[str, Any] = {"password_change_frequency": int(frequency)}
    if user.get("full_name"):
        payload["full_name"] = user["full_name"]
    path = client._fabric_path(f"{NODE_USERS_PATH}/{client._q(userid)}")
    log.info("PUT %s  body=%s", path, payload)
    return client._put(path, payload)


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Turn the local-user password-expiration (reset) "
                    "requirement on/off on an NSX Manager or Global Manager.")
    parser.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES,
                        help="Which NSX appliance to act on (resolved from .env).")
    sel = parser.add_mutually_exclusive_group(required=True)
    sel.add_argument("--user", help="Local username, e.g. audit / admin / root.")
    sel.add_argument("--userid", type=int, help="Numeric userid, e.g. 10002.")
    sel.add_argument("--all-users", action="store_true",
                     help="Apply to EVERY local user on the target (users "
                          "already at the target frequency are skipped).")
    parser.add_argument("--frequency", type=int, default=0,
                        help="Password change frequency in DAYS. 0 disables "
                             "expiration (turns OFF the reset requirement). "
                             "Default: 0.")
    parser.add_argument("--apply", action="store_true",
                        help="Actually perform the change. Without this flag "
                             "the tool only reports (dry-run).")
    args = parser.parse_args()

    if args.frequency < 0:
        parser.error("--frequency must be >= 0")

    init_cli()
    host = resolve_manager(args.target)
    if not host:
        log.error("Target %s did not resolve to a hostname (check .env).", args.target)
        return 2

    out_dir = output_dir(args.target)
    setup_logging(out_dir)

    mode = "APPLY" if args.apply else "DRY-RUN"
    log.info("=== set_user_password_expiration [%s] target=%s (%s) ===",
             mode, args.target, host)

    try:
        client = NsxPolicyClient(host)
    except NsxApiError as e:
        log.error("Could not connect/login to %s: %s", host, e)
        return 2

    try:
        users = list_node_users(client)
    except NsxApiError as e:
        log.error("Failed to list node users: %s", e)
        return 2

    selected = select_users(users, username=args.user, userid=args.userid,
                            all_users=args.all_users)
    if not selected:
        who = args.user if args.user is not None else f"userid={args.userid}"
        log.error("No local user matching %s on %s. Present users: %s",
                  who, args.target,
                  ", ".join(str(u.get("username")) for u in users))
        return 1

    log.info("Selected %d user(s): %s", len(selected),
             ", ".join(str(u.get("username")) for u in selected))
    for u in selected:
        log.info("BEFORE: %s", summarize(u))

    outcomes: Dict[Any, str] = {}
    for u in selected:
        outcomes[u.get("userid")] = plan_and_apply(client, u, args.frequency, args.apply)

    if not args.apply:
        log.info("DRY-RUN: no writes performed. Re-run with --apply to make the change(s).")
        return 0

    # Re-read once so the operator sees real post-change state for everyone.
    try:
        after_by_id = {u.get("userid"): u for u in list_node_users(client)}
    except NsxApiError as e:
        log.warning("Applied, but re-read failed: %s", e)
        after_by_id = {}

    for uid in outcomes:
        au = after_by_id.get(uid)
        if not au:
            continue
        log.info("AFTER:  %s", summarize(au))
        if args.frequency == 0 and str(au.get("status")) == "PASSWORD_EXPIRED":
            log.warning("[%s] expiration is disabled but status is still "
                        "PASSWORD_EXPIRED; the account may need a one-time "
                        "password reset before it becomes ACTIVE.",
                        au.get("username"))

    n_applied = sum(1 for o in outcomes.values() if o == "applied")
    n_noop = sum(1 for o in outcomes.values() if o == "noop")
    n_err = sum(1 for o in outcomes.values() if o == "error")
    log.info("DONE. applied=%d noop=%d errors=%d", n_applied, n_noop, n_err)
    return 0 if n_err == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
