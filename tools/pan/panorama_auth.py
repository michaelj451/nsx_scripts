#!/usr/bin/env python3
"""tools/pan/panorama_auth.py

Authenticate to Panorama and prove the credentials in .env work.

Read-only against Panorama: a keygen (if needed) plus `show system info` and
a name-only listing of device groups / templates. Nothing is written to
Panorama. The only file this script can write is the repo's .env, and only
when --write-env is given.

What it answers:
  - Which Panorama is .env pointing at, and which variables supplied it?
  - Do the credentials work? Which auth method was used (api_key vs
    username/password keygen)?
  - What did we connect to (hostname, serial, PAN-OS version, model)?
  - How many device groups and templates are visible to this account?

USAGE:
    # Check the current .env (default: read-only, key is masked)
    python tools/pan/panorama_auth.py

    # Force a fresh keygen from username/password even if PANORAMA_API_KEY is set
    python tools/pan/panorama_auth.py --keygen

    # Keygen and persist the key into .env as PANORAMA_API_KEY (asks first)
    python tools/pan/panorama_auth.py --keygen --write-env

    # Print the key in the clear (for pasting somewhere else)
    python tools/pan/panorama_auth.py --keygen --show-key

    # Use a different .env
    python tools/pan/panorama_auth.py --env-file /path/to/other.env

Exit codes:
    0  authenticated and system info retrieved
    1  Panorama reachable but authentication / API call failed
    2  .env does not describe a usable target (missing host or credentials)
    3  --write-env refused (key already present; use --force) or declined

A JSON report (no secrets; key fingerprint only) is written to
.pano_reports/panorama_auth_<UTC ts>.json unless --no-report is given.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from palo.pan_env import (  # noqa: E402
    API_KEY_VARS, PanoramaEnvError, load_repo_env, resolve_panorama_env,
)
from palo.panos_client import PanosClient, PanosClientError  # noqa: E402

log = logging.getLogger("panorama_auth")

DEFAULT_REPORT_DIR = REPO_ROOT / ".pano_reports"
ENV_KEY_VAR = "PANORAMA_API_KEY"


# =============================================================================
# Helpers (pure; unit-tested)
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


def upsert_env_var(env_path: Path, name: str, value: str, *, force: bool = False) -> str:
    """Add or replace `name=value` in a .env file.

    Returns "added" or "replaced". Raises FileExistsError when the variable is
    already present and force is False. Preserves every other line byte for
    byte. A missing file is created.
    """
    pattern = re.compile(rf"^\s*{re.escape(name)}\s*=")
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    hits = [i for i, line in enumerate(lines) if pattern.match(line)]

    if hits and not force:
        raise FileExistsError(f"{name} is already set in {env_path}; pass --force to replace it")

    new_line = f"{name}={value}"
    if hits:
        lines[hits[0]] = new_line
        for i in reversed(hits[1:]):
            del lines[i]
        action = "replaced"
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"# Panorama API key written by tools/pan/panorama_auth.py on "
                     f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(new_line)
        action = "added"

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return action


def _count(label: str, fn) -> Dict[str, Any]:
    """Run an inventory call, returning {count, names} or {error}. Inventory
    failures are informational: an account may be scoped so it cannot list
    templates but can still authenticate."""
    try:
        names = fn()
        return {"count": len(names), "names": names}
    except PanosClientError as exc:
        log.warning("%s listing failed (non-fatal): %s", label, exc)
        return {"error": str(exc)}


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("USAGE:", 1)[1] if "USAGE:" in __doc__ else None)
    parser.add_argument("--env-file", default=None,
                        help="Path to the .env to load (default: <repo>/.env).")
    parser.add_argument("--keygen", action="store_true",
                        help="Ignore any PANORAMA_API_KEY in .env and generate a fresh key "
                             "from the username/password.")
    parser.add_argument("--write-env", action="store_true",
                        help=f"Persist the key into .env as {ENV_KEY_VAR}. Implies --keygen "
                             "when no key is set. Asks for confirmation on a TTY.")
    parser.add_argument("--force", action="store_true",
                        help=f"With --write-env: replace an existing {ENV_KEY_VAR} line.")
    parser.add_argument("--show-key", action="store_true",
                        help="Print the API key in the clear (default: masked).")
    parser.add_argument("--no-tls-verify", action="store_true",
                        help="Disable TLS certificate verification for this run "
                             "(same as PANORAMA_TLS_VERIFY=false).")
    parser.add_argument("--report-dir", default=None,
                        help=f"Where to write the JSON report (default: {DEFAULT_REPORT_DIR}).")
    parser.add_argument("--no-report", action="store_true", help="Do not write a JSON report.")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Do not prompt before --write-env.")
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

    environ: Dict[str, str] = dict(os.environ)
    if args.keygen or args.write_env:
        # Drop any stored key so the username/password path is exercised.
        for var in API_KEY_VARS:
            environ.pop(var, None)

    report: Dict[str, Any] = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "env_file": str(env_path),
        "mode": "keygen" if (args.keygen or args.write_env) else "check",
    }

    try:
        client = PanosClient.from_env(environ, load_env=False)
    except PanosClientError as exc:
        log.error("%s", exc)
        report["status"] = "env_error"
        report["error"] = str(exc)
        _write_report(args, report)
        return 2

    target = client.env.describe()
    report["target"] = target
    log.info("Target        : %s", target["url"])
    log.info("TLS verify    : %s", target["tls_verify"])
    log.info("Auth method   : %s", target["auth"])
    log.info("Username      : %s", target["username"])
    log.info("Sources       : %s", target["sources"])

    if not client.env.has_api_key and not client.env.has_password_auth:
        log.error("No credentials available for the requested mode.")
        report["status"] = "env_error"
        _write_report(args, report)
        return 2

    try:
        system = client.connect()
        key = client.api_key
    except PanosClientError as exc:
        log.error("Authentication failed: %s", exc)
        report["status"] = "auth_failed"
        report["error"] = str(exc)
        _write_report(args, report)
        return 1

    fp = key_fingerprint(key)
    report["status"] = "ok"
    report["api_key_fingerprint"] = fp
    report["api_key_masked"] = mask_key(key)
    report["system"] = {
        k: system.get(k) for k in (
            "hostname", "serial", "sw-version", "model", "ip-address",
            "system-mode", "uptime", "devicename",
        ) if k in system
    }
    report["device_groups"] = _count("device group", client.list_device_groups)
    report["templates"] = _count("template", client.list_templates)
    report["template_stacks"] = _count("template stack", client.list_template_stacks)

    log.info("Authenticated : OK (key fingerprint %s, %s)", fp, mask_key(key))
    for k, v in report["system"].items():
        log.info("  %-13s: %s", k, v)
    for label in ("device_groups", "templates", "template_stacks"):
        entry = report[label]
        if "count" in entry:
            log.info("  %-13s: %d", label, entry["count"])

    if args.show_key:
        print(key)

    if args.write_env:
        if not args.yes and sys.stdin.isatty():
            answer = input(f"Write {ENV_KEY_VAR} (fingerprint {fp}) to {env_path}? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                log.warning("Declined; .env not modified.")
                report["write_env"] = "declined"
                _write_report(args, report)
                return 3
        try:
            action = upsert_env_var(env_path, ENV_KEY_VAR, key, force=args.force)
        except FileExistsError as exc:
            log.error("%s", exc)
            report["write_env"] = "refused_existing"
            _write_report(args, report)
            return 3
        log.info("%s %s in %s", action.capitalize(), ENV_KEY_VAR, env_path)
        report["write_env"] = action

    _write_report(args, report)
    return 0


def _write_report(args: argparse.Namespace, report: Dict[str, Any]) -> None:
    if args.no_report:
        return
    out_dir = Path(args.report_dir).expanduser().resolve() if args.report_dir else DEFAULT_REPORT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"panorama_auth_{ts}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log.info("Report: %s", path)


if __name__ == "__main__":
    sys.exit(main())
