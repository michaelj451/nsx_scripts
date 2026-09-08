#!/usr/bin/env python3
"""tools/pan/probe_api_permissions.py

Map what a Panorama API account is allowed to do.

Authenticates as the given account and attempts a battery of XML API calls,
recording ALLOWED / DENIED / ERROR for each. Used to verify that a
restricted account (e.g. a read-only agent account) has exactly the access
it is supposed to have.

Probe categories:
  keygen        can the account generate an API key at all?
  op            operational "show" commands (system info, devices, jobs,
                admins, devicegroups)
  config-read   candidate get and running show on several xpaths, including
                /config/mgt-config (admin/user definitions)
  export        configuration export (type=export)
  write         OPT-IN (--probe-writes): set a clearly named test address
                object under /config/shared, then delete it again. Proves
                whether the account can modify candidate config. Never
                committed; both the set and the delete are reported.
  commit        NOT probed unless --probe-commit is given. A permitted
                commit would activate ANY pending candidate changes on the
                Panorama, including ones made by other admins. Leave off
                unless the Panorama is known to have a clean candidate.

USAGE:
    # Read-only probes as the account in agent_user/agent_password
    python tools/pan/probe_api_permissions.py \
        --user-env agent_user --password-env agent_password --dry-run
    python tools/pan/probe_api_permissions.py \
        --user-env agent_user --password-env agent_password

    # Include the write probe (creates + deletes one test object, no commit)
    python tools/pan/probe_api_permissions.py \
        --user-env agent_user --password-env agent_password --probe-writes

Exit codes:
    0  probes ran (see report for per-probe outcomes)
    1  keygen failed (no probes possible)
    2  .env / arguments unusable

A JSON report is written to .pano_reports/api_perms_<user>_<UTC ts>.json
unless --no-report is given. The API key never appears in output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

import requests  # noqa: E402
import urllib3  # noqa: E402

from palo.pan_env import PanoramaEnvError, load_repo_env, resolve_panorama_env  # noqa: E402

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("probe_api_permissions")

DEFAULT_REPORT_DIR = REPO_ROOT / ".pano_reports"
WRITE_PROBE_NAME = "agent-perm-probe-DELETE-ME"
WRITE_PROBE_XPATH = f"/config/shared/address/entry[@name='{WRITE_PROBE_NAME}']"

# (name, params) read-only probes. `key` is added at request time.
READ_PROBES = [
    ("op_show_system_info", {"type": "op", "cmd": "<show><system><info></info></system></show>"}),
    ("op_show_clock", {"type": "op", "cmd": "<show><clock></clock></show>"}),
    ("op_show_devices_all", {"type": "op", "cmd": "<show><devices><all></all></devices></show>"}),
    ("op_show_devicegroups", {"type": "op", "cmd": "<show><devicegroups></devicegroups></show>"}),
    ("op_show_templates", {"type": "op", "cmd": "<show><templates></templates></show>"}),
    ("op_show_jobs_all", {"type": "op", "cmd": "<show><jobs><all></all></jobs></show>"}),
    ("op_show_admins", {"type": "op", "cmd": "<show><admins></admins></show>"}),
    ("op_show_system_resources", {"type": "op",
     "cmd": "<show><system><resources></resources></system></show>"}),
    ("config_get_shared_address", {"type": "config", "action": "get",
     "xpath": "/config/shared/address"}),
    ("config_show_shared_address", {"type": "config", "action": "show",
     "xpath": "/config/shared/address"}),
    ("config_get_device_groups", {"type": "config", "action": "get",
     "xpath": "/config/devices/entry[@name='localhost.localdomain']/device-group"}),
    ("config_get_templates", {"type": "config", "action": "get",
     "xpath": "/config/devices/entry[@name='localhost.localdomain']/template"}),
    ("config_get_mgt_users", {"type": "config", "action": "get",
     "xpath": "/config/mgt-config/users"}),
    ("config_show_full_running", {"type": "config", "action": "show", "xpath": "/config"}),
    ("export_configuration", {"type": "export", "category": "configuration"}),
    ("op_proxy_to_device_denied_check", None),  # filled in at runtime if devices visible
]

DENIED_MARKERS = ("unauthorized", "not authorized", "invalid credential", "permission",
                  "insufficient", "type [export] not authorized", "403")


def classify(status_code: int, text: str) -> Tuple[str, str]:
    """(verdict, detail) for a raw API response body."""
    lower = text.lower()
    if status_code in (401, 403):
        return "DENIED", f"HTTP {status_code}"
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # Exports return raw XML config or binary; HTTP 200 non-<response> = allowed
        if status_code == 200:
            return "ALLOWED", f"non-XML-API payload, {len(text)} bytes"
        return "ERROR", f"HTTP {status_code}, unparseable body"
    if root.tag != "response":
        # Successful exports return the raw document (e.g. <config>), not an
        # API <response> wrapper.
        return "ALLOWED", f"raw <{root.tag}> document, {len(text)} bytes"
    if root.get("status") == "success":
        return "ALLOWED", f"{len(text)} bytes"
    code = root.get("code") or ""
    msg = "; ".join(l.text.strip() for l in root.iter("line") if l.text and l.text.strip()) \
          or (root.findtext("./msg") or "")[:200]
    if code == "1" or any(m in msg.lower() for m in DENIED_MARKERS) or any(m in lower for m in DENIED_MARKERS):
        return "DENIED", f"pan-code {code}: {msg[:200]}"
    return "ERROR", f"pan-code {code}: {msg[:200]}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("USAGE:", 1)[1] if "USAGE:" in __doc__ else None)
    parser.add_argument("--host", default=None, help="Target Panorama hostname (overrides .env host).")
    parser.add_argument("--user-env", default="PANORAMA_USERNAME",
                        help="Env var holding the username to probe as (default PANORAMA_USERNAME).")
    parser.add_argument("--password-env", default="PANORAMA_PASSWORD",
                        help="Env var holding the password (default PANORAMA_PASSWORD).")
    parser.add_argument("--probe-writes", action="store_true",
                        help=f"Attempt a candidate write: set then delete {WRITE_PROBE_XPATH}. "
                             "Nothing is committed.")
    parser.add_argument("--probe-commit", action="store_true",
                        help="DANGEROUS on a Panorama with pending changes: attempt a commit. "
                             "Off by default; a permitted commit activates any pending candidate.")
    parser.add_argument("--no-tls-verify", action="store_true",
                        help="Disable TLS certificate verification for this run.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print target, account, and probe list; send nothing.")
    parser.add_argument("--report-dir", default=None,
                        help=f"Where to write the JSON report (default: {DEFAULT_REPORT_DIR}).")
    parser.add_argument("--no-report", action="store_true", help="Do not write a JSON report.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = time.gmtime

    load_repo_env()
    if args.no_tls_verify:
        os.environ["PANORAMA_TLS_VERIFY"] = "false"

    username = os.environ.get(args.user_env, "").strip()
    password = os.environ.get(args.password_env, "").strip()
    if not username or not password:
        log.error("Missing credentials: %s and/or %s not set in .env", args.user_env, args.password_env)
        return 2

    try:
        env = resolve_panorama_env(require_auth=False)
    except PanoramaEnvError as exc:
        log.error("%s", exc)
        return 2
    hostname = args.host.strip() if args.host else env.hostname
    base_url = f"https://{hostname}" if env.port == 443 else f"https://{hostname}:{env.port}"
    verify = env.verify

    probes = [(n, p) for n, p in READ_PROBES if p is not None]
    log.info("Target : %s (tls_verify=%s)", base_url, verify)
    log.info("Account: %s (from %s / %s)", username, args.user_env, args.password_env)
    log.info("Probes : keygen + %d read probes%s%s", len(probes),
             " + write probe (set/delete, no commit)" if args.probe_writes else "",
             " + COMMIT probe" if args.probe_commit else "")
    if args.dry_run:
        for n, _ in probes:
            log.info("  %s", n)
        log.info("DRY RUN: nothing sent.")
        return 0

    report: Dict[str, Any] = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "target": base_url,
        "username": username,
        "probes": {},
    }

    # --- keygen -------------------------------------------------------------
    s = requests.Session()
    r = s.get(f"{base_url}/api/", params={"type": "keygen", "user": username, "password": password},
              verify=verify, timeout=60)
    verdict, detail = classify(r.status_code, r.text)
    key: Optional[str] = None
    if verdict == "ALLOWED":
        key = ET.fromstring(r.text).findtext("./result/key")
    report["probes"]["keygen"] = {"verdict": "ALLOWED" if key else "DENIED", "detail": detail}
    if not key:
        log.error("keygen: DENIED (%s). No further probes possible.", detail)
        _write_report(args, username, report)
        return 1
    report["api_key_fingerprint"] = hashlib.sha256(key.encode()).hexdigest()[:12]
    log.info("  %-32s ALLOWED", "keygen")

    # --- read probes --------------------------------------------------------
    allowed = denied = errored = 0
    for name, params in probes:
        r = s.get(f"{base_url}/api/", params={**params, "key": key}, verify=verify, timeout=120)
        verdict, detail = classify(r.status_code, r.text)
        report["probes"][name] = {"verdict": verdict, "detail": detail}
        allowed += verdict == "ALLOWED"
        denied += verdict == "DENIED"
        errored += verdict == "ERROR"
        log.info("  %-32s %s%s", name, verdict, "" if verdict == "ALLOWED" else f"  ({detail})")

    # --- write probe (opt-in) ----------------------------------------------
    if args.probe_writes:
        r = s.get(f"{base_url}/api/", params={
            "type": "config", "action": "set", "xpath": WRITE_PROBE_XPATH,
            "element": "<ip-netmask>203.0.113.250/32</ip-netmask>", "key": key,
        }, verify=verify, timeout=60)
        verdict, detail = classify(r.status_code, r.text)
        report["probes"]["write_set_shared_address"] = {"verdict": verdict, "detail": detail,
                                                        "xpath": WRITE_PROBE_XPATH}
        log.info("  %-32s %s%s", "write_set_shared_address", verdict,
                 "" if verdict == "ALLOWED" else f"  ({detail})")
        if verdict == "ALLOWED":
            log.warning("Account CAN write candidate config. Cleaning up the probe object...")
            r = s.get(f"{base_url}/api/", params={
                "type": "config", "action": "delete", "xpath": WRITE_PROBE_XPATH, "key": key,
            }, verify=verify, timeout=60)
            v2, d2 = classify(r.status_code, r.text)
            report["probes"]["write_delete_cleanup"] = {"verdict": v2, "detail": d2}
            log.info("  %-32s %s%s", "write_delete_cleanup", v2, "" if v2 == "ALLOWED" else f"  ({d2})")
            if v2 != "ALLOWED":
                log.error("CLEANUP FAILED: %s still exists in candidate config; remove it "
                          "with an admin account before the next commit.", WRITE_PROBE_XPATH)

    # --- commit probe (opt-in, dangerous) -----------------------------------
    if args.probe_commit:
        r = s.get(f"{base_url}/api/", params={"type": "commit", "cmd": "<commit></commit>", "key": key},
                  verify=verify, timeout=60)
        verdict, detail = classify(r.status_code, r.text)
        report["probes"]["commit"] = {"verdict": verdict, "detail": detail}
        log.info("  %-32s %s  (%s)", "commit", verdict, detail)

    report["summary"] = {"allowed": allowed, "denied": denied, "error": errored}
    log.info("Summary: %d allowed, %d denied, %d error (of %d read probes)",
             allowed, denied, errored, len(probes))
    _write_report(args, username, report)
    return 0


def _write_report(args: argparse.Namespace, username: str, report: Dict[str, Any]) -> None:
    if args.no_report:
        return
    out_dir = Path(args.report_dir).expanduser().resolve() if args.report_dir else DEFAULT_REPORT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"api_perms_{username}_{ts}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log.info("Report: %s", path)


if __name__ == "__main__":
    sys.exit(main())
