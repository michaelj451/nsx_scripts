#!/usr/bin/env python3
# app/nsx/cli_bootstrap.py

from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv


def init_cli(level: int = logging.INFO) -> None:
    """
    Bootstrap for manual scripts:
    - Load .env from repo root
    - Configure logging
    """
    # Find repo root as: tools/nsx/<script>.py -> parents[2] == repo root
    # But this file lives in app/frontendFastapi/nsx/, so go up 3: nsx -> frontendFastapi -> app -> repo
    repo_root = Path(__file__).resolve().parents[3]
    env_path = repo_root / ".env"

    load_dotenv(dotenv_path=env_path, override=False)

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    logging.getLogger(__name__).info("Loaded .env: %s (exists=%s)", env_path, env_path.exists())