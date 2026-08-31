"""app/nsx/report_paths.py

One output-directory convention for every read-only report tool:

    <root>/<manager-host>/<report>/<UTC run timestamp>/

  root    --output-base when given, else $NSX_LOG_DIR/reports
  host    the manager hostname the run targeted (nsx-lm1.lab.local ...)
  report  a short stable name per tool (vm_rule_membership, group_membership,
          rules_usage, hostname_tags_dryrun, ip_remap_audit ...)

So a session evidence pack built with `--output-base nsx_info_nsx-lm1` lines
up as nsx_info_nsx-lm1/<host>/<report>/<ts>/ for every tool, and the
defaults line up the same way under nsx_logs/reports/.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from nsx.nsx_constants import nsx_log_dir

REPORTS_SUBDIR = "reports"


def reports_root(output_base: Optional[str] = None) -> Path:
    if output_base:
        return Path(output_base).expanduser().resolve()
    return Path(nsx_log_dir).expanduser().resolve() / REPORTS_SUBDIR


def report_run_dir(
    report: str,
    host: str,
    output_base: Optional[str] = None,
    run_ts: Optional[str] = None,
    *,
    create: bool = True,
) -> Path:
    """Return <root>/<host>/<report>/<run_ts>/, creating it unless create=False."""
    ts = run_ts or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    d = reports_root(output_base) / host / report / ts
    if create:
        d.mkdir(parents=True, exist_ok=True)
    return d
