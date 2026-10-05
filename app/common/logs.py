"""app/common/logs.py

UTC logging for tools: one console handler and one per-run log file.

Unlike app/nsx/cli_bootstrap.py, nothing here changes a class attribute of
logging.Formatter. The UTC converter is set on the formatter instances this
module creates, so importing it changes no other logger's behavior.
"""
from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Optional, Union

from common.timeutil import LOG_DATEFMT, LOG_FORMAT, run_ts as _run_ts

_HANDLER_TAG = "_common_logs_handler"


def utc_formatter(fmt: str = LOG_FORMAT, datefmt: str = LOG_DATEFMT) -> logging.Formatter:
    f = logging.Formatter(fmt=fmt, datefmt=datefmt)
    f.converter = time.gmtime
    return f


def setup_logging(tool: str, log_dir: Optional[Union[str, Path]] = None, *,
                  level: int = logging.INFO, console: bool = True,
                  run_ts: Optional[str] = None) -> Optional[Path]:
    """Configure the ROOT logger for a tool run and return the log file path.

    The file is <log_dir>/<tool>_<run_ts>.log when log_dir is given, else no
    file. Calling this twice replaces the handlers it added the first time
    instead of stacking duplicates; handlers added by anything else are left
    alone.
    """
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, _HANDLER_TAG, False):
            root.removeHandler(h)
            h.close()
    root.setLevel(level)
    fmt = utc_formatter()

    if console:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        setattr(sh, _HANDLER_TAG, True)
        root.addHandler(sh)

    if log_dir is None:
        return None
    d = Path(log_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{tool}_{run_ts or _run_ts()}.log"
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setFormatter(fmt)
    setattr(fh, _HANDLER_TAG, True)
    root.addHandler(fh)
    return path
