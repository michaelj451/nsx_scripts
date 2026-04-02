#!/usr/bin/env python3
"""
tools/nsx/update_rules_from_promoted_groups.py

Update rules by mapping LM group references to promoted GM groups.

Reads promoted groups from:
  <repo>/nsx_promoted_groups/<gm-name>/domains/<dst-domain>/groups

Reads rules from (NOTE: domain matters!):
  <repo>/nsx_export_promote/<gm-name>/domains/<rules-domain>/security-policies

Writes updated rules to:
  <repo>/nsx_updated_rules/<gm-name>/domains/<dst-domain>/<rules-domain>/security-policies

Mapping:
  /global-infra/domains/<lm-domain>/groups/<old_id>
    -> /global-infra/domains/<dst-domain>/groups/<old_id><suffix>
when that promoted group exists.

Modes:
  - default add-only: add promoted ref alongside LM ref
  - --replace: replace LM ref with promoted ref

Logging:
  - Runtime log file: <LOG_DIR>/update_rules_from_promoted_groups_YYYYMMDD_HHMMSS.log
  - JSONL changes (one per changed rule file): <LOG_DIR>/nsx_rule_updates_from_promoted_groups.jsonl
  - Pretty combined JSON: <LOG_DIR>/nsx_rule_updates_from_promoted_groups.pretty.json
  - Pretty per-rule-file JSON: <LOG_DIR>/rule_updates_from_promoted/<relative/path>.json

Dry-run behavior:
  - Does NOT write updated rule files to nsx_updated_rules
  - DOES write logs/JSONL/pretty/per-rule records the same as non-dry-run
  - Uses a separate log directory with "_dry_run" appended to the directory name
    (e.g., ".../nsx_logs_dry_run")
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from nsx.nsx_constants import nsx_lm1, nsx_log_dir  # env-backed values

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e

log = logging.getLogger("update_rules_from_promoted_groups")

REPO_ROOT = Path(__file__).resolve().parents[2]

# ---- Defaults (match your repo layout) ----
RULES_EXPORT_BASE = REPO_ROOT / "nsx_export_promote"

DEFAULT_GM_NAME = "nsx-gm1.lab.local"
DEFAULT_RULES_DOMAIN = nsx_lm1 or "nsx-lm1.lab.local"  # default to LM1 domain exports
DEFAULT_DST_DOMAIN = "default"
DEFAULT_SUFFIX = "_svb_m3"

# ---- Logging defaults (directory only; files are computed later) ----
DEFAULT_LOG_DIR = Path(nsx_log_dir) if nsx_log_dir else (REPO_ROOT / "nsx_logs")


# =============================================================================
# Logging helpers
# =============================================================================

def _append_dry_run_suffix(dir_path: Path) -> Path:
    """
    Append '_dry_run' to the directory name (not as a subdir).
    Example: /a/b/nsx_logs -> /a/b/nsx_logs_dry_run
    """
    return dir_path.with_name(dir_path.name + "_dry_run")


def _resolve_log_dir(log_dir_arg: Path | None, *, dry_run: bool) -> Path:
    """
    Resolve base log directory:
      - If --log-dir is passed: use it
      - Else use env-backed nsx_log_dir
      - Else fallback to repo/nsx_logs

    For dry-run: logs go under <base>/dry_run
    For normal run: logs go under <base>
    """
    if log_dir_arg is not None:
        raw = str(log_dir_arg)
    elif nsx_log_dir:
        raw = str(nsx_log_dir)
    else:
        raw = str(REPO_ROOT / "nsx_logs")

    expanded = os.path.expandvars(os.path.expanduser(raw))
    base = Path(expanded)

    if not base.is_absolute():
        base = (REPO_ROOT / base)

    base = base.resolve()
    base.mkdir(parents=True, exist_ok=True)

    if dry_run:
        effective = base / "rule_updates_from_promoted_dry_run"
        effective.mkdir(parents=True, exist_ok=True)
        return effective

    return base


def _setup_logging(tool_name: str, log_dir: Path, level: str) -> Path:
    """
    Configure console + file logging. Returns runtime log file path.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = (log_dir / f"{tool_name}_{ts}.log").resolve()

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers to prevent duplicates
    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, level.upper(), logging.INFO))
    ch.setFormatter(fmt)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(getattr(logging, level.upper(), logging.INFO))
    fh.setFormatter(fmt)

    root.addHandler(ch)
    root.addHandler(fh)

    logging.getLogger(tool_name).info("Logging to %s", log_file)
    return log_file


def write_jsonl_record(fh, record: Dict[str, Any]) -> None:
    fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    fh.flush()


# =============================================================================
# IO helpers
# =============================================================================

def load_doc(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        return yaml.safe_load(text)
    if path.suffix.lower() == ".json":
        return json.loads(text)
    raise ValueError(f"Unsupported file type: {path}")


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def write_json(path: Path, data: Any, *, indent: int = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=indent), encoding="utf-8")


def iter_docs(root: Path, exts: Tuple[str, ...] = (".yaml", ".yml", ".json")) -> Iterator[Path]:
    if not root.exists():
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in exts:
            yield p


# =============================================================================
# Group detection / normalization
# =============================================================================

def is_group_payload(doc: Any) -> bool:
    # STRICT requirement (as requested)
    return isinstance(doc, dict) and doc.get("resource_type") == "Group"


def extract_group_payloads(doc: Any) -> List[Dict[str, Any]]:
    groups: List[Dict[str, Any]] = []
    if isinstance(doc, dict):
        if is_group_payload(doc):
            return [doc]
        for key in ("results", "children", "items", "data", "objects"):
            val = doc.get(key)
            if isinstance(val, list):
                for x in val:
                    if is_group_payload(x):
                        groups.append(x)
            elif is_group_payload(val):
                groups.append(val)
        return groups
    if isinstance(doc, list):
        for x in doc:
            if is_group_payload(x):
                groups.append(x)
    return groups


# =============================================================================
# Rule detection
# =============================================================================

def is_rule_container(doc: Any) -> bool:
    return isinstance(doc, dict) and isinstance(doc.get("rules"), list)


def is_rule_payload(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    rt = doc.get("resource_type")
    if rt in ("Rule", "SecurityPolicy", "GatewayPolicy", "CommunicationMap"):
        return True
    if "action" in doc and ("source_groups" in doc or "destination_groups" in doc):
        return True
    return False


def iter_rules_from_doc(doc: Any) -> Iterator[Tuple[str, Dict[str, Any], Optional[int]]]:
    """Yields (kind, rule_dict, index)."""
    if is_rule_container(doc):
        for i, r in enumerate(doc["rules"]):
            if isinstance(r, dict):
                yield ("container", r, i)
    elif is_rule_payload(doc):
        yield ("single", doc, None)


# =============================================================================
# Rule updating logic
# =============================================================================

GROUP_REF_KEYS = {
    "source_groups",
    "destination_groups",
    "scope",
    "applied_to",
    "sources",
    "destinations",
}

LM_GROUP_PATH_RE = re.compile(r"^/global-infra/domains/(?P<domain>[^/]+)/groups/(?P<gid>[^/]+)$")


@dataclass(frozen=True)
class PromotedIndex:
    suffix: str
    dst_domain: str
    oldid_to_newid: Dict[str, str]  # old_id -> new_id
    newid_to_path: Dict[str, str]   # new_id -> full path


def build_promoted_index(promoted_groups_dir: Path, *, suffix: str, dst_domain: str) -> PromotedIndex:
    oldid_to_newid: Dict[str, str] = {}
    newid_to_path: Dict[str, str] = {}

    for f in iter_docs(promoted_groups_dir):
        try:
            doc = load_doc(f)
        except Exception as e:
            log.warning("Skip unreadable promoted group file %s: %s", f, e)
            continue

        for g in extract_group_payloads(doc):
            gid = g.get("id")
            if not isinstance(gid, str) or not gid:
                continue
            if not gid.endswith(suffix):
                continue

            old_id = gid[: -len(suffix)]
            if not old_id:
                continue

            new_path = f"/global-infra/domains/{dst_domain}/groups/{gid}"
            oldid_to_newid[old_id] = gid
            newid_to_path[gid] = new_path

    return PromotedIndex(
        suffix=suffix,
        dst_domain=dst_domain,
        oldid_to_newid=oldid_to_newid,
        newid_to_path=newid_to_path,
    )


def remap_lm_ref_to_promoted(ref: str, *, promoted: PromotedIndex) -> Optional[Tuple[str, str, str]]:
    """
    If ref looks like /global-infra/domains/<domain>/groups/<gid> AND <domain> != dst_domain,
    and we have a promoted group for that gid, return (old_ref, new_ref, old_domain).
    """
    if not isinstance(ref, str) or not ref:
        return None
    m = LM_GROUP_PATH_RE.match(ref)
    if not m:
        return None

    old_domain = m.group("domain")
    old_id = m.group("gid")

    # ignore refs already in dst domain
    if old_domain == promoted.dst_domain:
        return None

    new_id = promoted.oldid_to_newid.get(old_id)
    if not new_id:
        return None

    return (ref, promoted.newid_to_path[new_id], old_domain)


def update_rule_refs_from_promoted(rule: Dict[str, Any], *, promoted: PromotedIndex, replace: bool) -> Dict[str, Any]:
    changes: List[Dict[str, Any]] = []
    touched = False

    for key in GROUP_REF_KEYS:
        val = rule.get(key)
        if not isinstance(val, list):
            continue

        before = list(val)
        remaps: List[Tuple[int, str, str, str]] = []

        for i, x in enumerate(val):
            if not isinstance(x, str):
                continue
            r = remap_lm_ref_to_promoted(x, promoted=promoted)
            if r:
                old_ref, new_ref, old_domain = r
                remaps.append((i, old_ref, new_ref, old_domain))

        if not remaps:
            continue

        if replace:
            per = []
            for i, old_ref, new_ref, old_domain in remaps:
                if val[i] == old_ref:
                    val[i] = new_ref
                    per.append({"old": old_ref, "new": new_ref, "old_domain": old_domain, "mode": "replace"})
            if per and before != val:
                touched = True
                changes.append({"field": key, "before": before, "after": list(val), "remaps": per})
        else:
            per = []
            for _i, old_ref, new_ref, old_domain in remaps:
                if new_ref not in val:
                    val.append(new_ref)
                    per.append({"old": old_ref, "new": new_ref, "old_domain": old_domain, "mode": "add"})
            if per and before != val:
                touched = True
                changes.append({"field": key, "before": before, "after": list(val), "remaps": per})

    return {"touched": touched, "changes": changes}


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Update rules by mapping LM group refs to promoted GM groups.")

    ap.add_argument("--gm-name", type=str, default=DEFAULT_GM_NAME)
    ap.add_argument("--rules-domain", type=str, default=DEFAULT_RULES_DOMAIN,
                    help="Domain folder to read rules from (ex: nsx-lm1.lab.local OR default).")
    ap.add_argument("--dst-domain", type=str, default=DEFAULT_DST_DOMAIN)
    ap.add_argument("--suffix", type=str, default=DEFAULT_SUFFIX)

    ap.add_argument("--promoted-groups-dir", type=Path, default=None)
    ap.add_argument("--rules-dir", type=Path, default=None,
                    help="Explicit rules input directory (security-policies). Overrides gm-name/rules-domain defaults.")
    ap.add_argument("--rules-out-dir", type=Path, default=None,
                    help="Explicit rules output directory (security-policies). Overrides defaults.")

    ap.add_argument("--replace", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--write-all", action="store_true")
    ap.add_argument("--copy-unchanged", action="store_true")

    ap.add_argument("--log-dir", type=Path, default=None,
                    help="Base log directory. For dry-run, '_dry_run' is appended to this directory name.")
    ap.add_argument("--changes-jsonl", type=Path, default=None)
    ap.add_argument("--changes-pretty", type=Path, default=None)
    ap.add_argument("--log-level", type=str, default="INFO")

    args = ap.parse_args()

    # Resolve effective log directory (dry-run gets its own dir)
    effective_log_dir = _resolve_log_dir(args.log_dir, dry_run=bool(args.dry_run))

    # Setup runtime logging (console + file) into effective_log_dir
    log_file = _setup_logging(
        tool_name="update_rules_from_promoted_groups",
        log_dir=effective_log_dir,
        level=args.log_level,
    )
    log.info("Log file:            %s", log_file)
    log.info("Dry-run:             %s", bool(args.dry_run))
    log.info("Effective log dir:   %s", effective_log_dir)

    gm_name = args.gm_name
    rules_domain = args.rules_domain
    dst_domain = args.dst_domain
    suffix = args.suffix

    promoted_groups_dir = args.promoted_groups_dir or (
        REPO_ROOT / "nsx_promoted_groups" / gm_name / "domains" / dst_domain / "groups"
    )

    rules_dir = args.rules_dir or (
        RULES_EXPORT_BASE / gm_name / "domains" / rules_domain / "security-policies"
    )

    rules_out_dir = args.rules_out_dir or (
        REPO_ROOT / "nsx_updated_rules" / gm_name / "domains" / dst_domain / rules_domain / "security-policies"
    )

    # Logs/records ALWAYS go to effective_log_dir (including dry-run)
    changes_jsonl: Path = args.changes_jsonl or (effective_log_dir / "nsx_rule_updates_from_promoted_groups.jsonl")
    changes_pretty: Path = args.changes_pretty or (effective_log_dir / "nsx_rule_updates_from_promoted_groups.pretty.json")
    per_rule_log_dir: Path = effective_log_dir / "rule_updates_from_promoted"

    log.info("Promoted groups dir: %s", promoted_groups_dir)
    log.info("Rules input dir:     %s", rules_dir)
    log.info("Rules output dir:    %s", rules_out_dir)
    log.info("Mode:                %s", "REPLACE" if args.replace else "ADD-ONLY")
    log.info("Will write records:  %s", True)
    log.info("Will write rules:    %s", (not args.dry_run))

    if not promoted_groups_dir.exists():
        raise SystemExit(f"Promoted groups dir not found: {promoted_groups_dir}")
    if not rules_dir.exists():
        raise SystemExit(f"Rules input dir not found: {rules_dir}")

    promoted = build_promoted_index(promoted_groups_dir, suffix=suffix, dst_domain=dst_domain)
    log.info("Loaded %d promoted group mapping(s).", len(promoted.oldid_to_newid))

    # Ensure record dirs exist
    effective_log_dir.mkdir(parents=True, exist_ok=True)
    per_rule_log_dir.mkdir(parents=True, exist_ok=True)
    changes_jsonl.parent.mkdir(parents=True, exist_ok=True)

    # We ALWAYS write JSONL + pretty + per-rule records, even in dry-run
    changes_fh = changes_jsonl.open("w", encoding="utf-8")
    all_records: List[Dict[str, Any]] = []
    records_written = 0

    total_files = 0
    changed_files = 0
    touched_rules = 0
    copied_unchanged = 0
    written_files = 0

    for rf in iter_docs(rules_dir):
        total_files += 1
        try:
            rdoc = load_doc(rf)
        except Exception as e:
            log.warning("Skip unreadable rules file %s: %s", rf, e)
            continue

        any_change_in_file = False
        file_changes: List[Dict[str, Any]] = []

        for _kind, rule, idx in iter_rules_from_doc(rdoc):
            res = update_rule_refs_from_promoted(rule, promoted=promoted, replace=args.replace)
            if res["touched"]:
                any_change_in_file = True
                touched_rules += 1
                file_changes.append({
                    "rule_index": idx,
                    "rule_display_name": rule.get("display_name"),
                    "rule_id": rule.get("id"),
                    "changes": res["changes"],
                })

        out_path = rules_out_dir / rf.relative_to(rules_dir)

        # Write updated rules ONLY when not dry-run
        if not args.dry_run:
            if any_change_in_file or args.write_all:
                out_path.parent.mkdir(parents=True, exist_ok=True)

                if (not any_change_in_file) and args.write_all and args.copy_unchanged:
                    shutil.copy2(rf, out_path)
                    copied_unchanged += 1
                    written_files += 1
                else:
                    if rf.suffix.lower() in (".yaml", ".yml"):
                        write_yaml(out_path, rdoc)
                    else:
                        write_json(out_path, rdoc, indent=2)
                    written_files += 1

        if any_change_in_file:
            changed_files += 1
            log.info("[DRY-RUN] Would update %s", rf) if args.dry_run else log.info("Updated %s", rf)

            rec = {
                "type": "rule_file_update_from_promoted_groups",
                "dry_run": bool(args.dry_run),
                "gm_name": gm_name,
                "rules_domain": rules_domain,
                "dst_domain": dst_domain,
                "suffix": suffix,
                "replace_mode": bool(args.replace),
                "promoted_groups_dir": str(promoted_groups_dir),
                "rules_dir": str(rules_dir),
                "file": str(rf),
                "out_file": str(out_path),
                "changes": file_changes,
            }

            all_records.append(rec)
            write_jsonl_record(changes_fh, rec)
            records_written += 1

            # Per-file pretty record
            pretty_path = per_rule_log_dir / rf.relative_to(rules_dir)
            pretty_path = pretty_path.with_suffix(".json")
            write_json(pretty_path, rec, indent=2)

    changes_fh.close()

    # Pretty combined JSON (ALWAYS written, even dry-run)
    write_json(changes_pretty, all_records, indent=2)

    log.info(
        "Complete. Total files=%d, changed files=%d, touched rules=%d",
        total_files, changed_files, touched_rules
    )
    log.info("Records written (jsonl): %d -> %s", records_written, changes_jsonl)
    log.info("Pretty combined:         %s", changes_pretty)
    log.info("Per-file logs:           %s", per_rule_log_dir)

    if not args.dry_run:
        log.info("Rule files written:      %d", written_files)
        if args.write_all and args.copy_unchanged:
            log.info("Unchanged files copied:  %d", copied_unchanged)
    else:
        log.info("Dry-run: rule files were NOT written.")


if __name__ == "__main__":
    main()