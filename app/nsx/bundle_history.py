"""Timestamped bundle history: <root>/<host>/<UTC_TS>/ plus a `latest` symlink.

Shared by tools that keep every run (backup_nsx_state.py,
capture_vm_rule_data.py) instead of wiping one bundle per host.
"""
from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)

TS_DIR_RE = re.compile(r"^\d{8}_\d{6}$")


def prune_old_bundles(host_dir: Path, retain: int) -> List[str]:
    """Delete the oldest timestamped bundles beyond `retain`. retain<=0 keeps
    everything. The `latest` symlink and non-timestamp entries are never touched.
    Returns the names removed."""
    if retain <= 0 or not host_dir.exists():
        return []
    ts_dirs = sorted(
        d for d in host_dir.iterdir()
        if d.is_dir() and not d.is_symlink() and TS_DIR_RE.match(d.name)
    )
    removed: List[str] = []
    for d in ts_dirs[:-retain] if len(ts_dirs) > retain else []:
        shutil.rmtree(d)
        removed.append(d.name)
    return removed


def update_latest_symlink(host_dir: Path, bundle: Path) -> None:
    link = host_dir / "latest"
    try:
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(bundle.name)
    except OSError as exc:   # e.g. filesystems without symlink support
        log.warning("Could not update %s: %s", link, exc)
