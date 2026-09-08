#!/usr/bin/env python3
"""tools/pan/panorama_rest_auth.py

Authenticate to Panorama over the REST API and prove the credentials work.

This is the REST twin of tools/pan/panorama_auth.py:

    panorama_auth.py        XML API / pan-os-python. Needs a role with XML
                            op+config rights ("show system info").
    panorama_rest_auth.py   THIS FILE. Keygen plus /restapi/<ver>/ GETs only.
                            Works for a restricted role that is denied the XML
                            API but granted read-only REST access.

Read-only against Panorama: a keygen followed by a handful of GETs. Nothing is
written to Panorama, and this script never writes .env (persist a key with
`panorama_auth.py --keygen --write-env`; the key is the same key, keygen is
shared between the two APIs).

What it answers:
  - Which Panorama is .env pointing at, and which variables supplied it?
  - Does keygen succeed for this account? (key fingerprint, never the key)
  - Which REST version is being spoken?
  - Which REST resources does this account actually get to read, and which
    come back 403? That distinction is the whole point for the restricted
    agent account.

USAGE:
    # Check the canonical PANORAMA_* credentials in .env
    python tools/pan/panorama_rest_auth.py

    # Check the restricted read-only account (agent_user / agent_password)
    python tools/pan/panorama_rest_auth.py --agent

    # Any other credential pair by variable name
    python tools/pan/panorama_rest_auth.py --user-env svc_user --password-env svc_password

    # Ignore a stored PANORAMA_API_KEY and force a fresh keygen
    python tools/pan/panorama_rest_auth.py --keygen

    # Point at a different Panorama / REST version / .env
    python tools/pan/panorama_rest_auth.py --host pano2.lab.local --rest-version v11.1
    python tools/pan/panorama_rest_auth.py --env-file /path/to/other.env

    # Also probe policy reads inside one device group
    python tools/pan/panorama_rest_auth.py --agent --device-group DG-Prod

Exit codes:
    0  keygen succeeded and at least one REST resource was readable
    1  keygen / authentication failed
    2  .env does not describe a usable target (missing host or credentials)
    4  authenticated, but every REST probe was denied (role has no REST read)

A JSON report (no secrets; key fingerprint only) is written to
$PANO_REPORTS_DIR (or <repo>/.pano_reports) unless --no-report is given.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from palo.pan_env import API_KEY_VARS, load_repo_env  # noqa: E402
from palo.pan_rest_client import (  # noqa: E402
    DEFAULT_REST_VERSION, PanRestClient, PanRestError,
)

log = logging.getLogger("panorama_rest_auth")

DEFAULT_REPORT_DIR = REPO_ROOT / ".pano_reports"
AGENT_USER_VAR = "agent_user"
AGENT_PASSWORD_VAR = "agent_password"

# Probes run in this order. Each is (label, resource, kwargs-for-get).
# Shared-scope reads only, so the run works on any Panorama without knowing
# a device group name up front.
SHARED_PROBES: Tuple[Tuple[str, str, Dict[str, Any]], ...] = (
    ("device_groups", "Panorama/DeviceGroups", {}),
    ("templates", "Panorama/Templates", {}),
    ("shared_addresses", "Objects/Addresses", {"location": "shared"}),
    ("shared_address_groups", "Objects/AddressGroups", {"location": "shared"}),
    ("shared_services", "Objects/Services", {"location": "shared"}),
    ("shared_tags", "Objects/Tags", {"location": "shared"}),
)

# Only when a device group is known (--device-group, or the first one the
# DeviceGroups probe returned).
DG_PROBES: Tuple[Tuple[str, str], ...] = (
    ("dg_addresses", "Objects/Addresses"),
    ("dg_security_pre_rules", "Policies/SecurityPreRules"),
    ("dg_security_post_rules", "Policies/SecurityPostRules"),
)


# =============================================================================
# Helpers (pure; safe to unit-test)
# =============================================================================

def mask_key(key: Optional[str]) -> str:
    """'ABCD...WXYZ (len=NN)' for display. Never returns the full key."""
    if not key:
        return "(none)"
    if len(key) <= 12:
        return "*" * len(key) + f" (len={len(key)})"
    return f"{key[:4]}...{key[-4:]} (len={len(key)})"


def key_fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def probe(client: PanRestClient, resource: str, **kwargs: Any) -> Dict[str, Any]:
    """Run one read-only GET.

    Returns {"ok": True, "count": N, "sample": [...]} or, on failure,
    {"ok": False, "status": HTTP, "error": msg}. A denied probe is data, not
    a crash: the point of this tool is to report exactly which resources the
    account can and cannot read.
    """
    try:
        entries = client.entries(resource, **kwargs)
    except PanRestError as exc:
        return {"ok": False, "status": exc.status_code, "code": exc.code, "error": str(exc)}
    names = [e.get("@name", "") for e in entries if isinstance(e, dict)]
    return {"ok": True, "count": len(entries), "sample": sorted(n for n in names if n)[:5]}


def _log_probe(label: str, result: Dict[str, Any]) -> None:
    if result["ok"]:
        sample = ", ".join(result["sample"])
        suffix = f"  e.g. {sample}" if sample else ""
        log.info("  %-24s: OK   %d%s", label, result["count"], suffix)
    else:
        status = result.get("status") or "?"
        log.warning("  %-24s: FAIL HTTP %s  %s", label, status, result["error"])


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("USAGE:", 1)[1] if "USAGE:" in __doc__ else None,
    )
    parser.add_argument("--env-file", default=None,
                        help="Path to the .env to load (default: <repo>/.env).")
    parser.add_argument("--agent", action="store_true",
                        help=f"Use the restricted account in {AGENT_USER_VAR} / "
                             f"{AGENT_PASSWORD_VAR} instead of the PANORAMA_* credentials.")
    parser.add_argument("--user-env", default=None,
                        help="Name of the .env variable holding the username "
                             "(use with --password-env).")
    parser.add_argument("--password-env", default=None,
                        help="Name of the .env variable holding the password "
                             "(use with --user-env).")
    parser.add_argument("--keygen", action="store_true",
                        help="Ignore any stored PANORAMA_API_KEY and generate a fresh key "
                             "from the username/password. (Implied by --agent/--user-env.)")
    parser.add_argument("--host", default=None,
                        help="Override the Panorama hostname from .env for this run.")
    parser.add_argument("--rest-version", default=None,
                        help=f"REST API version path segment (default: "
                             f"$PANORAMA_REST_VERSION or {DEFAULT_REST_VERSION}).")
    parser.add_argument("--device-group", default=None,
                        help="Also probe device-group scoped reads in this DG. "
                             "Default: the first DG returned by the DeviceGroups probe.")
    parser.add_argument("--no-dg-probe", action="store_true",
                        help="Skip the device-group scoped probes entirely.")
    parser.add_argument("--show-key", action="store_true",
                        help="Print the API key in the clear (default: masked).")
    parser.add_argument("--no-tls-verify", action="store_true",
                        help="Disable TLS certificate verification for this run "
                             "(same as PANORAMA_TLS_VERIFY=false).")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Per-request timeout in seconds (default: 60).")
    parser.add_argument("--report-dir", default=None,
                        help="Where to write the JSON report (default: $PANO_REPORTS_DIR "
                             f"or {DEFAULT_REPORT_DIR}).")
    parser.add_argument("--no-report", action="store_true", help="Do not write a JSON report.")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )
    logging.Formatter.converter = __import__("time").gmtime

    env_path = Path(args.env_file).expanduser().resolve() if args.env_file else (REPO_ROOT / ".env")
    load_repo_env(env_path)
    log.info("Loaded .env: %s (exists=%s)", env_path, env_path.exists())

    if args.no_tls_verify:
        os.environ["PANORAMA_TLS_VERIFY"] = "false"

    # Which credential pair are we testing?
    user_env, password_env = args.user_env, args.password_env
    if args.agent:
        if user_env or password_env:
            parser.error("--agent and --user-env/--password-env are mutually exclusive.")
        user_env, password_env = AGENT_USER_VAR, AGENT_PASSWORD_VAR
    if bool(user_env) != bool(password_env):
        parser.error("--user-env and --password-env must be given together.")

    environ: Dict[str, str] = dict(os.environ)
    if args.keygen:
        # Drop any stored key so the username/password path is exercised.
        for var in API_KEY_VARS:
            environ.pop(var, None)

    report: Dict[str, Any] = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "env_file": str(env_path),
        "api": "rest",
        "account": f"{user_env}/{password_env}" if user_env else "PANORAMA_* (canonical)",
        "mode": "keygen" if (args.keygen or user_env) else "check",
    }

    try:
        client = PanRestClient.from_env(
            environ,
            user_env=user_env,
            password_env=password_env,
            host=args.host,
            rest_version=args.rest_version,
            load_env=False,
            timeout=args.timeout,
        )
    except PanRestError as exc:
        log.error("%s", exc)
        report["status"] = "env_error"
        report["error"] = str(exc)
        _write_report(args, report)
        return 2

    target = {
        "url": client.env.url,
        "tls_verify": client.env.verify,
        "rest_version": client.rest_version,
        "auth": "stored_api_key" if client._api_key else "keygen",
        "username": client.username,
        "sources": dict(client.env.sources),
    }
    report["target"] = target
    log.info("Target        : %s", target["url"])
    log.info("REST version  : %s", target["rest_version"])
    log.info("TLS verify    : %s", target["tls_verify"])
    log.info("Auth method   : %s", target["auth"])
    log.info("Username      : %s", target["username"])
    log.info("Sources       : %s", target["sources"])

    # ---- authenticate -------------------------------------------------------
    try:
        key = client.api_key
    except PanRestError as exc:
        log.error("Authentication failed: %s", exc)
        report["status"] = "auth_failed"
        report["error"] = str(exc)
        _write_report(args, report)
        return 1

    fp = key_fingerprint(key)
    report["api_key_fingerprint"] = fp
    report["api_key_masked"] = mask_key(key)
    log.info("Authenticated : OK (key fingerprint %s, %s)", fp, mask_key(key))

    # ---- probe what this account may read -----------------------------------
    probes: Dict[str, Any] = {}
    log.info("REST probes (read-only GETs):")
    for label, resource, kwargs in SHARED_PROBES:
        probes[label] = probe(client, resource, **kwargs)
        probes[label]["resource"] = resource
        _log_probe(label, probes[label])

    device_group = args.device_group
    if not device_group and not args.no_dg_probe:
        dg_probe = probes.get("device_groups", {})
        if dg_probe.get("ok") and dg_probe.get("sample"):
            device_group = dg_probe["sample"][0]

    if device_group and not args.no_dg_probe:
        log.info("Device-group scoped probes (device-group=%s):", device_group)
        for label, resource in DG_PROBES:
            probes[label] = probe(client, resource, device_group=device_group)
            probes[label]["resource"] = resource
            probes[label]["device_group"] = device_group
            _log_probe(label, probes[label])

    report["device_group_probed"] = device_group
    report["probes"] = probes

    readable = sorted(k for k, v in probes.items() if v.get("ok"))
    denied = sorted(k for k, v in probes.items() if not v.get("ok"))
    report["readable"] = readable
    report["denied"] = denied

    if args.show_key:
        print(key)

    if not readable:
        log.error("Keygen worked, but every REST probe was denied. This account "
                  "authenticates but has no REST read access.")
        report["status"] = "no_rest_access"
        _write_report(args, report)
        return 4

    report["status"] = "ok"
    log.info("Summary       : %d/%d probes readable (denied: %s)",
             len(readable), len(probes), ", ".join(denied) or "none")
    _write_report(args, report)
    return 0


def _report_dir(args: argparse.Namespace) -> Path:
    if args.report_dir:
        return Path(args.report_dir).expanduser().resolve()
    from_env = os.environ.get("PANO_REPORTS_DIR")
    if from_env:
        return Path(os.path.expandvars(from_env)).expanduser()
    return DEFAULT_REPORT_DIR


def _write_report(args: argparse.Namespace, report: Dict[str, Any]) -> None:
    if args.no_report:
        return
    out_dir = _report_dir(args)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"panorama_rest_auth_{ts}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log.info("Report: %s", path)


if __name__ == "__main__":
    sys.exit(main())
