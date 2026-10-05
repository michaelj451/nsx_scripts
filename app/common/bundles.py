"""app/common/bundles.py

Timestamped run history: <root>/<scope...>/<UTC_TS>/ plus a `latest` pointer
and optional retention. Vendor-neutral version of app/nsx/bundle_history.py
(same pruning and symlink rules), with run-dir creation and lookup added.

    host_dir = root / "nsx-lm1.lab.local"
    run = new_run_dir(host_dir)            # .../20261004_181500/
    ...write the bundle...
    update_latest(host_dir, run)           # only after the run is complete
    prune_old(host_dir, retain=10)

`latest` is a relative symlink. Filesystems without symlink rights (Windows
without developer mode) log a warning instead, and find_bundle() falls back
to the newest timestamped directory.
"""
from __future__ import annotations

import logging
import re
import shutil
import time
from pathlib import Path
from typing import List, Optional, Union

from common.timeutil import run_ts as _run_ts

log = logging.getLogger(__name__)

TS_DIR_RE = re.compile(r"^\d{8}_\d{6}$")


def new_run_dir(host_dir: Union[str, Path], run_ts: Optional[str] = None) -> Path:
    """Create and return <host_dir>/<run_ts>/. Never reuses an existing
    directory: with an explicit run_ts that already exists it raises
    FileExistsError; without one it waits for the next second, so two runs
    started in the same second still get separate bundles."""
    if run_ts:
        d = Path(host_dir) / run_ts
        d.mkdir(parents=True, exist_ok=False)
        return d
    for _ in range(5):
        d = Path(host_dir) / _run_ts()
        try:
            d.mkdir(parents=True, exist_ok=False)
            return d
        except FileExistsError:
            time.sleep(1.0)
    raise FileExistsError(f"Could not create a fresh run directory under {host_dir}")


def timestamped_dirs(host_dir: Union[str, Path]) -> List[Path]:
    """Real (non-symlink) timestamped directories, oldest first."""
    p = Path(host_dir)
    if not p.is_dir():
        return []
    return sorted(d for d in p.iterdir()
                  if d.is_dir() and not d.is_symlink() and TS_DIR_RE.match(d.name))


def prune_old(host_dir: Union[str, Path], retain: int) -> List[str]:
    """Delete the oldest timestamped bundles beyond `retain`. retain <= 0 keeps
    everything. `latest` and non-timestamp entries are never touched."""
    if retain <= 0:
        return []
    ts_dirs = timestamped_dirs(host_dir)
    removed: List[str] = []
    for d in ts_dirs[:-retain] if len(ts_dirs) > retain else []:
        shutil.rmtree(d)
        removed.append(d.name)
    return removed


def update_latest(host_dir: Union[str, Path], bundle: Union[str, Path]) -> bool:
    """Point <host_dir>/latest at `bundle`. Returns False (with a warning)
    where symlinks are not allowed."""
    link = Path(host_dir) / "latest"
    try:
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(Path(bundle).name)
        return True
    except OSError as exc:
        log.warning("Could not update %s: %s", link, exc)
        return False


def find_bundle(path: Union[str, Path]) -> Optional[Path]:
    """Resolve a host directory or a bundle directory to one bundle.

    A path that is itself a timestamped bundle is returned as is. A host
    directory resolves through `latest`, else to its newest timestamped
    directory. None when there is nothing to resolve.
    """
    p = Path(path)
    if not p.exists():
        return None
    if p.is_dir() and TS_DIR_RE.match(p.name):
        return p
    latest = p / "latest"
    if latest.exists():
        return latest.resolve()
    dirs = timestamped_dirs(p)
    return dirs[-1] if dirs else None
