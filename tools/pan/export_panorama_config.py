#!/usr/bin/env python3
"""tools/pan/export_panorama_config.py

Export the full Panorama running configuration to an XML file, using the
XML API's type=export. This is the config-snapshot path that works for the
READ-ONLY agent account (whose role denies the XML config API that
pull_panorama_config.py uses, but permits export), and the file it writes
is drop-in input for the offline tools:

    python tools/pan/check_policy_match.py --config <exported file> ...
    (and any other tool that takes an exported running-config XML)

There is deliberately no REST path for this: PAN-OS has no REST export
endpoint (verified: /restapi/ probes return 501), so type=export is the
one XML call this tool makes besides keygen.

SECURITY NOTE: the export contains the ENTIRE configuration, including
mgt-config with admin password hashes. Treat the output file like a
credential store; tools/pan/configs/ is git-ignored for this reason.

USAGE:
    # As the read-only agent account
    python tools/pan/export_panorama_config.py \
        --user-env agent_user --password-env agent_password --no-tls-verify

    # Admin account (canonical PANORAMA_* / vm_* resolution), other host
    python tools/pan/export_panorama_config.py --host pano2.lab.local --no-tls-verify

    # Straight into a policy-match check
    CFG=$(python tools/pan/export_panorama_config.py --user-env agent_user \
          --password-env agent_password --no-tls-verify --quiet)
    python tools/pan/check_policy_match.py --config "$CFG" \
        --src-ip 10.1.1.5 --dst-ip 10.2.1.5 --protocol tcp --dst-port 443

Output: tools/pan/configs/<host>-export-<UTC ts>.xml (override with
--out-dir / --out-file). The absolute path is printed on stdout (the only
stdout output, so command substitution works; logs go to stderr).

Exit codes: 0 exported, 1 export/auth failure, 2 bad arguments/.env.
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from palo.pan_rest_client import PanRestClient, PanRestError  # noqa: E402

log = logging.getLogger("export_panorama_config")

DEFAULT_OUT_DIR = REPO_ROOT / "tools" / "pan" / "configs"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("USAGE:", 1)[1] if "USAGE:" in __doc__ else None)
    parser.add_argument("--host", default=None, help="Target Panorama hostname (overrides .env).")
    parser.add_argument("--user-env", default=None,
                        help="Env var holding the username (e.g. agent_user). Default: "
                             "canonical PANORAMA_* resolution.")
    parser.add_argument("--password-env", default=None,
                        help="Env var holding the password (e.g. agent_password).")
    parser.add_argument("--out-dir", default=None,
                        help=f"Output directory (default {DEFAULT_OUT_DIR}).")
    parser.add_argument("--out-file", default=None,
                        help="Exact output file path (overrides --out-dir and the "
                             "default <host>-export-<TS>.xml name).")
    parser.add_argument("--no-tls-verify", action="store_true",
                        help="Disable TLS certificate verification for this run.")
    parser.add_argument("--quiet", action="store_true",
                        help="Log errors only; stdout still carries the output path.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.ERROR if args.quiet else logging.INFO,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = time.gmtime

    if args.no_tls_verify:
        os.environ["PANORAMA_TLS_VERIFY"] = "false"

    try:
        client = PanRestClient.from_env(user_env=args.user_env,
                                        password_env=args.password_env, host=args.host)
    except PanRestError as exc:
        log.error("%s", exc)
        return 2

    log.info("Target : %s (account via %s)", client.env.url,
             args.user_env or "PANORAMA_* resolution")
    try:
        content = client.export_configuration()
    except PanRestError as exc:
        log.error("Export failed: %s", exc)
        return 1

    if args.out_file:
        out_path = Path(args.out_file).expanduser().resolve()
    else:
        out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else DEFAULT_OUT_DIR
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"{client.env.hostname.split('.')[0]}-export-{ts}.xml"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(content)

    digest = hashlib.sha256(content).hexdigest()[:12]
    log.info("Exported: %s (%d bytes, sha256 %s)", out_path, len(content), digest)
    log.info("Contains the FULL config including admin password hashes; "
             "handle accordingly.")
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
