#!/usr/bin/env python3
"""tools/pan/pull_panorama_config.py

Pull a Panorama config snapshot via the XML API and save it to
tools/pan/configs/ (gitignored by repo convention).

Read-only against Panorama — only GETs the config tree. Never writes.

USAGE:
    # Default — pulls CANDIDATE config (includes staged/uncommitted changes)
    python tools/pan/pull_panorama_config.py

    # Pull RUNNING config (what's actually enforcing on managed firewalls)
    python tools/pan/pull_panorama_config.py --running

    # Custom filename prefix
    python tools/pan/pull_panorama_config.py --prefix pano4-prod
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# Load .env with $VAR expansion (same loader as add_services_to_rules.py)
def _load_env() -> None:
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), os.path.expandvars(v.strip()))


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "app"))
_load_env()
os.environ.setdefault("PANORAMA_TLS_VERIFY", "false")

from palo.panorama_api_client import PanoramaClient   # noqa: E402

log = logging.getLogger(__name__)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--running", action="store_true",
                        help="Pull RUNNING config (what's enforcing) instead of "
                             "CANDIDATE (includes staged/uncommitted changes).")
    parser.add_argument("--prefix", default=None,
                        help="Filename prefix. Default derived from PANORAMA host.")
    parser.add_argument("--output-dir", default=None,
                        help="Override output directory. Default: tools/pan/configs/")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )

    out_dir = (Path(args.output_dir).expanduser().resolve()
               if args.output_dir
               else Path(__file__).resolve().parent / "configs")
    out_dir.mkdir(parents=True, exist_ok=True)

    client = PanoramaClient.from_env()
    log.info("Connected to %s (verify=%s)", client.base_url, client.verify)

    # Derive a host slug for the filename
    host_slug = (client.base_url.replace("https://", "").replace("http://", "")
                                .split(".", 1)[0])
    prefix = args.prefix or host_slug

    state = "running" if args.running else "candidate"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"{prefix}-{state}-{ts}.xml"

    log.info("Pulling %s config ...", state.upper())
    if args.running:
        # Operational-mode command: <show><config><running></running></config></show>
        result = client.op("<show><config><running></running></config></show>")
        # response/result/config
        cfg_el = result.find("./result/config") or result.find("./result")
    else:
        # type=config&action=get returns /config under <result>
        result = client.get_config("/config")
        cfg_el = result.find("./config") if result is not None else None

    if cfg_el is None:
        log.error("Could not extract <config> element from response")
        return 1

    xml_bytes = ET.tostring(cfg_el, encoding="utf-8")
    out_path.write_bytes(b'<?xml version="1.0"?>\n' + xml_bytes)

    log.info("Saved: %s  (%d bytes)", out_path, len(xml_bytes))
    print(str(out_path))   # stdout so callers can pipe `--config $(this-tool)` to other scripts
    return 0


if __name__ == "__main__":
    sys.exit(main())
