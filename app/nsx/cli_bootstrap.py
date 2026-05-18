#!/usr/bin/env python3
# app/nsx/cli_bootstrap.py

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from dotenv import load_dotenv


# Force every logging.Formatter to emit timestamps in UTC. JSON records
# elsewhere in the codebase already use UTC; this eliminates the local-time
# vs UTC mismatch that CAB reviewers were seeing between log files and JSON
# audit records.
#
# This is a class attribute, so it affects every Formatter constructed in
# the process from this point forward — including the ones each tool
# creates inside its own setup_logging() function.
logging.Formatter.converter = time.gmtime


def init_cli(level: int = logging.INFO) -> None:
    """
    Bootstrap for manual scripts:
    - Load .env from repo root
    - Configure logging with UTC timestamps
    """
    # Find repo root as: tools/nsx/<script>.py -> parents[2] == repo root
    repo_root = Path(__file__).resolve().parents[2]
    env_path = repo_root / ".env"

    load_dotenv(dotenv_path=env_path, override=False)

    # Re-assert at call time, defending against anything that may have
    # reset the class attribute between import and init_cli().
    logging.Formatter.converter = time.gmtime

    logging.basicConfig(
        level=level,
        format="%(asctime)s UTC %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    logging.getLogger(__name__).info("Loaded .env: %s (exists=%s)", env_path, env_path.exists())