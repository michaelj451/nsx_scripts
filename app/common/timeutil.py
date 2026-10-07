"""app/common/timeutil.py

UTC timestamps in the two shapes the toolkit already uses everywhere:

  run_ts()       20261004_181500   folder names, log file names, baselines
  utc_now_iso()  2026-10-04T18:15:00.123456+00:00   JSON `created_at` fields

Nothing here is computed at import time. A tool that wants one timestamp for
the whole run calls run_ts() once and keeps the value.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

RUN_TS_FORMAT = "%Y%m%d_%H%M%S"
LOG_DATEFMT = "%Y-%m-%dT%H:%M:%S"
LOG_FORMAT = "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def run_ts(now: Optional[datetime] = None) -> str:
    """Folder-safe UTC timestamp, e.g. 20261004_181500."""
    return (now or utc_now()).astimezone(timezone.utc).strftime(RUN_TS_FORMAT)


def utc_now_iso() -> str:
    """ISO-8601 UTC timestamp with offset, for JSON records."""
    return utc_now().isoformat()


def parse_run_ts(value: str) -> datetime:
    """Inverse of run_ts(). Raises ValueError for anything else."""
    return datetime.strptime(value, RUN_TS_FORMAT).replace(tzinfo=timezone.utc)
