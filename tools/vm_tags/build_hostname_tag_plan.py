#!/usr/bin/env python3
"""
tools/vm_tags/build_hostname_tag_plan.py

Offline transform. Read a VM-tag export and classify every VM into one of:

  eligible            : type=REGULAR, name ends in a 3-8 char alphanumeric
                        token after a hyphen, no existing hostname tag.
                        Will be tagged.
  skip_has_tag        : already has a hostname-scope tag. Will be skipped.
                        Logged as separate report (operator review).
  skip_length_out_of_range : trailing token present but its length is below
                        min or above max. Skipped + flagged.
  skip_invalid_name   : name has no trailing hyphen-delimited alphanumeric
                        token at all. Skipped + flagged.
  skip_edge           : NSX Edge VM (type=EDGE). Always skipped.
  skip_other_type     : type is something other than REGULAR / EDGE
                        (e.g. NSX Manager appliances). Always skipped.

The trailing token is captured verbatim, letters and leading zeros included
(e.g. `host-ax2001` -> `ax2001`, `host-0042` -> `0042`). The tagging rule
itself is defined in code below (DEFAULT_HOSTNAME_REGEX), not via env.

This step writes ONLY local files. No NSX writes.

Usage:
  python tools/vm_tags/build_hostname_tag_plan.py \\
    --vm-export vm_tags_export/nsx-lm1.lab.local/vms.json \\
    --output-dir vm_tags_plan/nsx-lm1.lab.local \\
    --overwrite
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_vm_log_dir

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

# Hostname tag extraction rule. Defined here in code on purpose (NOT via
# env) so the tagging behavior is versioned with the tool and shows up in
# code review.
#
# Rule: the last hyphen-delimited token of the VM display_name, 3-8
# alphanumeric chars (e.g. "...-ax2001" -> "ax2001",
# "...-10700101" -> "10700101"). Requiring the leading hyphen rejects a
# token longer than MAX outright (it can't align to the hyphen) instead of
# silently truncating it.
#
# The literal string `{MIN,MAX}` in the regex is substituted with the length
# bounds below at compile time, so length can be retuned by editing MIN/MAX
# without touching quantifier syntax. group(1) of the match becomes the tag.
DEFAULT_HOSTNAME_REGEX = r"-([A-Za-z0-9]{MIN,MAX})$"
DEFAULT_HOSTNAME_MIN_LEN = 3
DEFAULT_HOSTNAME_MAX_LEN = 8

# Compiled once per process. Reset via _reset_hostname_regex_cache() in tests.
_HOSTNAME_REGEX_CACHE: Optional[re.Pattern] = None
_HOSTNAME_TOKEN_REGEX_CACHE: Optional[re.Pattern] = None


def _reset_hostname_regex_cache() -> None:
    global _HOSTNAME_REGEX_CACHE, _HOSTNAME_TOKEN_REGEX_CACHE
    _HOSTNAME_REGEX_CACHE = None
    _HOSTNAME_TOKEN_REGEX_CACHE = None


def hostname_len_bounds() -> tuple[int, int]:
    """The (min, max) trailing-token length bounds, normalized so min <= max."""
    lo, hi = DEFAULT_HOSTNAME_MIN_LEN, DEFAULT_HOSTNAME_MAX_LEN
    return (hi, lo) if lo > hi else (lo, hi)


def hostname_regex() -> re.Pattern:
    """Return the compiled regex used to extract the hostname tag value from
    a VM display_name.

    The pattern is defined in code (DEFAULT_HOSTNAME_REGEX, with the
    DEFAULT_HOSTNAME_MIN_LEN / DEFAULT_HOSTNAME_MAX_LEN length bounds
    substituted into the `{MIN,MAX}` placeholder) and is intentionally NOT
    env-configurable, so the tagging rule is versioned with the tool.
    group(1) of a match becomes the tag value. Result is cached.
    """
    global _HOSTNAME_REGEX_CACHE
    if _HOSTNAME_REGEX_CACHE is not None:
        return _HOSTNAME_REGEX_CACHE

    lo, hi = DEFAULT_HOSTNAME_MIN_LEN, DEFAULT_HOSTNAME_MAX_LEN
    if lo > hi:
        lo, hi = hi, lo
    pattern = DEFAULT_HOSTNAME_REGEX.replace("{MIN,MAX}", f"{{{lo},{hi}}}")

    compiled = re.compile(pattern)
    log.info("VM name-to-tag regex in use: %r  (min_len=%d, max_len=%d)",
             pattern, lo, hi)
    _HOSTNAME_REGEX_CACHE = compiled
    return compiled


def hostname_token_regex() -> re.Pattern:
    """Length-agnostic sibling of hostname_regex(): DEFAULT_HOSTNAME_REGEX with
    the `{MIN,MAX}` quantifier relaxed to `+`. Used only to tell a name with no
    usable trailing token apart from one whose token merely falls outside the
    [MIN,MAX] length window (below min / above max)."""
    global _HOSTNAME_TOKEN_REGEX_CACHE
    if _HOSTNAME_TOKEN_REGEX_CACHE is not None:
        return _HOSTNAME_TOKEN_REGEX_CACHE
    _HOSTNAME_TOKEN_REGEX_CACHE = re.compile(
        DEFAULT_HOSTNAME_REGEX.replace("{MIN,MAX}", "+"))
    return _HOSTNAME_TOKEN_REGEX_CACHE


def supported_vm_types() -> Set[str]:
    """
    Read VM_TAGS_SUPPORTED_TYPES from the environment. Comma-separated list
    of NSX VM type values that are eligible for hostname tagging.
    Default: just REGULAR. Anything not in this list falls into
    skip_other_type (or skip_edge for type=EDGE).
    """
    raw = os.getenv("VM_TAGS_SUPPORTED_TYPES", "REGULAR")
    parsed = {t.strip().upper() for t in raw.split(",") if t.strip()}
    return parsed or {"REGULAR"}


def max_tags_per_vm() -> int:
    """
    Read VM_TAGS_MAX_TAGS_PER_VM from the environment. If a VM already has
    >= this many tags, it falls into skip_too_many_tags and is not pushed
    to. Default 30 (NSX's documented limit per VM).
    """
    raw = os.getenv("VM_TAGS_MAX_TAGS_PER_VM", "30")
    try:
        v = int(raw)
        return v if v > 0 else 30
    except ValueError:
        return 30


def setup_logging(tool: str) -> Path:
    log_dir = Path(nsx_vm_log_dir).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = (log_dir / f"vm_tags_{tool}_{RUN_TS}.log").resolve()
    log_file.touch(exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter(
        "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S",
    )
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(ch)
    root.addHandler(fh)
    log.info("Logging to %s", log_file)
    return log_file


def extract_hostname_value(vm_name: str) -> Optional[str]:
    """Return capture group 1 of the hostname regex applied to vm_name, or
    None if no match. The regex is defined in code (see hostname_regex())."""
    if not vm_name:
        return None
    m = hostname_regex().search(vm_name)
    if not m:
        return None
    return m.group(1)


def find_hostname_tag(tags: List[Dict[str, str]]) -> Optional[str]:
    """Return the value of the hostname-scope tag if present, else None."""
    for t in tags or []:
        if isinstance(t, dict) and t.get("scope") == "hostname":
            return t.get("tag")
    return None


def write_tag_inventory_jsonl(vms: List[Dict[str, Any]], out_path: Path) -> int:
    """
    Write one JSON object per line for EVERY VM (regardless of classification),
    capturing display_name, external_id, type, tag_count, and the full tag list.

    Format per line:
      {
        "display_name": "...",
        "external_id": "...",
        "type": "REGULAR" | "EDGE" | ...,
        "tag_count": N,
        "tags": [{"scope": "...", "tag": "..."}, ...]
      }

    Returns the number of lines written.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out_path.open("w", encoding="utf-8") as fh:
        # Sorted by display name for stable, diff-friendly output
        for vm in sorted(vms, key=lambda v: (v.get("display_name") or "")):
            tags = vm.get("tags") or []
            row = {
                "display_name": vm.get("display_name") or "",
                "external_id": vm.get("external_id") or "",
                "type": vm.get("type") or "UNKNOWN",
                "tag_count": len(tags),
                "tags": [
                    {"scope": t.get("scope"), "tag": t.get("tag")}
                    for t in tags if isinstance(t, dict)
                ],
            }
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            written += 1
    return written


def classify_vm(vm: Dict[str, Any]) -> Dict[str, Any]:
    """Classify a single VM. Returns a dict with classification + reasoning."""
    name = vm.get("display_name") or ""
    ext_id = vm.get("external_id") or ""
    vm_type = vm.get("type") or "UNKNOWN"
    tags = vm.get("tags") or []
    tag_count = len(tags)
    existing_hostname = find_hostname_tag(tags)
    proposed = extract_hostname_value(name)

    base = {
        "external_id": ext_id,
        "display_name": name,
        "type": vm_type,
        "existing_tags": tags,
        "existing_tag_count": tag_count,
        "existing_hostname_tag": existing_hostname,
        "proposed_hostname_tag": proposed,
    }

    if vm_type == "EDGE":
        base["classification"] = "skip_edge"
        base["reason"] = "NSX Edge VM (type=EDGE)"
        return base

    supported = supported_vm_types()
    if vm_type.upper() not in supported:
        base["classification"] = "skip_other_type"
        base["reason"] = (
            f"VM type {vm_type!r} is not in VM_TAGS_SUPPORTED_TYPES "
            f"({sorted(supported)})"
        )
        return base

    if existing_hostname is not None:
        base["classification"] = "skip_has_tag"
        base["reason"] = f"Already has hostname tag: {existing_hostname!r}"
        return base

    cap = max_tags_per_vm()
    if tag_count >= cap:
        base["classification"] = "skip_too_many_tags"
        base["reason"] = (
            f"VM has {tag_count} tags (>= VM_TAGS_MAX_TAGS_PER_VM={cap}); "
            f"refusing to add another to stay under the NSX limit"
        )
        return base

    if proposed is None:
        lo, hi = hostname_len_bounds()
        token_match = hostname_token_regex().search(name)
        if token_match:
            # A trailing token exists; it just falls outside the length window
            # (otherwise the main regex would have matched it).
            token = token_match.group(1)
            n = len(token)
            below = n < lo
            base["classification"] = "skip_length_out_of_range"
            base["length_issue"] = "below_min" if below else "above_max"
            base["candidate_token"] = token
            base["reason"] = (
                f"Trailing token {token!r} length {n} is "
                f"{'below the minimum' if below else 'above the maximum'} "
                f"({lo}-{hi} allowed)"
            )
            return base
        base["classification"] = "skip_invalid_name"
        base["reason"] = "Name has no trailing hyphen-delimited alphanumeric token"
        return base

    base["classification"] = "eligible"
    base["reason"] = (
        f"Will add hostname tag {proposed!r} "
        f"(from trailing token in name; current tag count={tag_count})"
    )
    return base


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the hostname-tag plan from a VM export. Offline; no NSX writes."
    )
    parser.add_argument("--vm-export", required=True, help="Path to vms.json from export_vm_tags.py")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Where to write the plan JSON files (default: <NSX_VM_LOG_DIR>/vm_tags_plan/<manager-host>, derived from the export).",
    )
    parser.add_argument("--overwrite", action="store_true", help="Delete --output-dir before writing")
    args = parser.parse_args()

    init_cli()
    log_file = setup_logging("build_plan")

    src = Path(args.vm_export).expanduser().resolve()
    if not src.exists():
        raise SystemExit(f"VM export not found: {src}")

    if args.output_dir:
        host_dir = Path(args.output_dir).expanduser().resolve()
    else:
        # Derive default from manager_host inside the export payload
        peek = json.loads(src.read_text(encoding="utf-8"))
        manager_host = peek.get("manager_host") or "unknown-manager"
        host_dir = Path(nsx_vm_log_dir).expanduser().resolve() / "vm_tags_plan" / manager_host

    # Per-run timestamped subdir so successive runs accumulate instead of
    # overwriting each other.
    out_dir = host_dir / RUN_TS
    if out_dir.exists():
        if not args.overwrite:
            raise SystemExit(f"Output dir already exists: {out_dir}. Use --overwrite.")
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    log.info("VM export: %s", src)
    log.info("Output dir: %s", out_dir)

    payload = json.loads(src.read_text(encoding="utf-8"))
    vms = payload.get("vms") or []
    log.info("Loaded %d VMs from export", len(vms))

    classified = [classify_vm(v) for v in vms]

    buckets: Dict[str, List[Dict[str, Any]]] = {
        "eligible": [],
        "skip_has_tag": [],
        "skip_too_many_tags": [],
        "skip_length_out_of_range": [],
        "skip_invalid_name": [],
        "skip_edge": [],
        "skip_other_type": [],
    }
    for c in classified:
        buckets[c["classification"]].append(c)

    for key, rows in buckets.items():
        out = out_dir / f"{key}.json"
        out.write_text(json.dumps({"count": len(rows), "vms": rows}, indent=2, sort_keys=True), encoding="utf-8")
        log.info("  %s: %d VM(s) -> %s", key, len(rows), out)

    # Per-VM tag inventory (every VM, regardless of classification)
    inv_path = out_dir / "vm_tag_inventory.jsonl"
    inv_count = write_tag_inventory_jsonl(vms, inv_path)
    log.info("  vm_tag_inventory: %d row(s) -> %s", inv_count, inv_path)

    summary = {
        "source_export": str(src),
        "source_manager": payload.get("manager"),
        "source_manager_host": payload.get("manager_host"),
        "source_exported_at": payload.get("exported_at"),
        "planned_at": datetime.now(timezone.utc).isoformat(),
        "vm_count_total": len(vms),
        "counts": {k: len(v) for k, v in buckets.items()},
        "vm_tag_inventory": str(inv_path),
        "output_dir": str(out_dir),
        "log_file": str(log_file),
    }
    plan = out_dir / "plan.json"
    plan.write_text(json.dumps({"summary": summary, "classified": classified}, indent=2, sort_keys=True), encoding="utf-8")
    log.info("Plan written: %s", plan)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
