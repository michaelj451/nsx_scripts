#!/usr/bin/env python3
"""
tools/nsx/update_rules_from_promoted_groups.py

Read *promoted* GM groups (already created) and update a ruleset (typically GM shared domain)
so any references to Local-Manager domain groups are mapped to the promoted GM groups.

This script does NOT promote groups. It only:
- Reads promoted groups from:
    <repo>/nsx_promoted_groups/<gm-name>/domains/<dst-domain>/groups

- Reads rules from:
    <repo>/nsx_export/<gm-name>/domains/<rules-domain>/security-policies

- Writes UPDATED rules to:
    <repo>/nsx_updated_rules/<gm-name>/domains/<dst-domain>/<rules-domain>/security-policies

How mapping works:
- Promoted groups are assumed to have ids like: <old_id><suffix>  (default suffix "_to_gm")
- Rules may reference LM groups like:
    /global-infra/domains/<lm-domain>/groups/<old_id>
- If we have a promoted group id matching <old_id><suffix>, we can map:
    /global-infra/domains/<lm-domain>/groups/<old_id>
  -> /global-infra/domains/<dst-domain>/groups/<old_id><suffix>

Update mode:
- Default (add-only): if a rule contains an LM ref, add the promoted GM ref (leave LM ref in place)
- --replace: replace the LM ref with the promoted GM ref

Output behavior:
- Default: write ONLY files that changed.
- --write-all: also write/copy unchanged rule files to output, so output tree is complete.
  - If --copy-unchanged: unchanged files are copied byte-for-byte (preserves formatting).
  - Otherwise unchanged files are re-serialized from parsed YAML/JSON (may alter formatting).

Logs:
- JSONL (one record per changed rule file):
    <repo>/nsx_logs/nsx_rule_updates_from_promoted_groups.jsonl
- Pretty combined JSON:
    <repo>/nsx_logs/nsx_rule_updates_from_promoted_groups.pretty.json
- Pretty per-rule-file:
    <repo>/nsx_logs/rule_updates_from_promoted/<relative/path>.json
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e

log = logging.getLogger("update_rules_from_promoted_groups")

# -----------------------------
# Repo defaults (match your layout)
# -----------------------------
REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_GM_NAME = "nsx-gm1.lab.local"
DEFAULT_RULES_DOMAIN = "default"          # production global manager rules live here
DEFAULT_DST_DOMAIN = "default"            # where promoted groups live
DEFAULT_SUFFIX = "_to_gm"

DEFAULT_PROMOTED_GROUPS_DIR = REPO_ROOT / "nsx_promoted_groups" / DEFAULT_GM_NAME / "domains" / DEFAULT_DST_DOMAIN / "groups"
DEFAULT_RULES_ROOT = REPO_ROOT / "nsx_export" / DEFAULT_GM_NAME / "domains"
DEFAULT_RULES_OUT_ROOT = REPO_ROOT / "nsx_updated_rules" / DEFAULT_GM_NAME / "domains" / DEFAULT_DST_DOMAIN

DEFAULT_LOG_DIR = REPO_ROOT / "nsx_logs"
DEFAULT_CHANGES_JSONL = DEFAULT_LOG_DIR / "nsx_rule_updates_from_promoted_groups.jsonl"
DEFAULT_CHANGES_PRETTY = DEFAULT_LOG_DIR / "nsx_rule_updates_from_promoted_groups.pretty.json"
DEFAULT_RULE_LOG_DIR = DEFAULT_LOG_DIR / "rule_updates_from_promoted"

# -----------------------------
# IO helpers
# -----------------------------

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

def write_jsonl_record(fh, record: Dict[str, Any]) -> None:
    fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    fh.flush()

# -----------------------------
# NSX detection / normalization
# -----------------------------

def is_group_payload(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    rt = doc.get("resource_type")
    if rt == "Group":
        return True
    if "expression" in doc and "display_name" in doc and "id" in doc:
        return True
    return False

def extract_group_payloads(doc: Any) -> List[Dict[str, Any]]:
    groups: List[Dict[str, Any]] = []
    if isinstance(doc, dict):
        if is_group_payload(doc):
            return [doc]
        for key in ("results", "children", "items", "data", "objects"):
            val = doc.get(key)
            if isinstance(val, list):
                for x in val:
                    if isinstance(x, dict) and is_group_payload(x):
                        groups.append(x)
            elif isinstance(val, dict) and is_group_payload(val):
                groups.append(val)
        return groups
    if isinstance(doc, list):
        for x in doc:
            if isinstance(x, dict) and is_group_payload(x):
                groups.append(x)
    return groups

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

# -----------------------------
# Rule updating logic
# -----------------------------

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
    """Lookup for promoted groups by old_id (without suffix)."""
    suffix: str
    dst_domain: str
    oldid_to_newid: Dict[str, str]     # old_id -> new_id (old_id+suffix)
    newid_to_path: Dict[str, str]      # new_id -> /global-infra/domains/<dst>/groups/<new_id>

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
                # This can happen if the directory contains other groups; ignore them.
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

def remap_lm_ref_to_promoted(
    ref: str,
    *,
    promoted: PromotedIndex,
) -> Optional[Tuple[str, str, str]]:
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

    new_ref = promoted.newid_to_path[new_id]
    return (ref, new_ref, old_domain)

def update_rule_refs_from_promoted(
    rule: Dict[str, Any],
    *,
    promoted: PromotedIndex,
    replace: bool,
) -> Dict[str, Any]:
    """
    Update a rule by mapping any LM group refs to promoted GM refs.
    - replace=True: replace LM refs with promoted refs
    - replace=False: add promoted ref when LM ref exists
    """
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

# -----------------------------
# Main
# -----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Update rules by mapping LM group references to promoted GM groups (reads promoted groups)."
    )

    ap.add_argument("--gm-name", type=str, default=DEFAULT_GM_NAME)
    ap.add_argument("--rules-domain", type=str, default=DEFAULT_RULES_DOMAIN,
                    help="Domain to read rules from (prod: default).")
    ap.add_argument("--dst-domain", type=str, default=DEFAULT_DST_DOMAIN,
                    help="Destination domain where promoted groups live (usually default).")
    ap.add_argument("--suffix", type=str, default=DEFAULT_SUFFIX,
                    help="Suffix used on promoted group ids (default: _to_gm).")

    ap.add_argument("--promoted-groups-dir", type=Path, default=None,
                    help="Directory containing promoted group YAMLs. Default computed from gm-name/dst-domain.")
    ap.add_argument("--rules-root", type=Path, default=DEFAULT_RULES_ROOT,
                    help="Root containing domains/<rules-domain>/security-policies.")
    ap.add_argument("--rules-out-root", type=Path, default=None,
                    help="Output root for updated rules. Default computed from gm-name/dst-domain.")

    ap.add_argument("--replace", action="store_true", help="Replace LM refs with promoted refs (default add-only).")
    ap.add_argument("--dry-run", action="store_true", help="Do not write outputs; only report changes.")
    ap.add_argument("--write-all", action="store_true",
                    help="Write unchanged files too (complete output tree). Default writes only changed files.")
    ap.add_argument("--copy-unchanged", action="store_true",
                    help="When --write-all and a file is unchanged, copy it byte-for-byte to output.")

    ap.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    ap.add_argument("--changes-jsonl", type=Path, default=None)
    ap.add_argument("--changes-pretty", type=Path, default=None)
    ap.add_argument("--log-level", type=str, default="INFO")

    args = ap.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(levelname)s %(message)s",
    )

    gm_name: str = args.gm_name
    rules_domain: str = args.rules_domain
    dst_domain: str = args.dst_domain
    suffix: str = args.suffix

    promoted_groups_dir = args.promoted_groups_dir or (
        REPO_ROOT / "nsx_promoted_groups" / gm_name / "domains" / dst_domain / "groups"
    )
    rules_dir = args.rules_root / rules_domain / "security-policies"
    rules_out_root = args.rules_out_root or (REPO_ROOT / "nsx_updated_rules" / gm_name / "domains" / dst_domain)
    rules_out_dir = rules_out_root / rules_domain / "security-policies"

    log_dir: Path = args.log_dir
    changes_jsonl: Path = args.changes_jsonl or (log_dir / "nsx_rule_updates_from_promoted_groups.jsonl")
    changes_pretty: Path = args.changes_pretty or (log_dir / "nsx_rule_updates_from_promoted_groups.pretty.json")
    per_rule_log_dir: Path = log_dir / "rule_updates_from_promoted"

    log.info("Promoted groups dir: %s", promoted_groups_dir)
    log.info("Rules input dir:     %s", rules_dir)
    log.info("Rules output dir:    %s", rules_out_dir)
    log.info("Mode:                %s", "REPLACE" if args.replace else "ADD-ONLY")

    if not promoted_groups_dir.exists():
        raise SystemExit(f"Promoted groups dir not found: {promoted_groups_dir}")
    if not rules_dir.exists():
        raise SystemExit(f"Rules input dir not found: {rules_dir}")

    # Build promoted lookup
    promoted = build_promoted_index(promoted_groups_dir, suffix=suffix, dst_domain=dst_domain)
    log.info("Loaded %d promoted group mapping(s).", len(promoted.oldid_to_newid))

    # Prepare logs
    log_dir.mkdir(parents=True, exist_ok=True)
    per_rule_log_dir.mkdir(parents=True, exist_ok=True)
    changes_jsonl.parent.mkdir(parents=True, exist_ok=True)

    changes_fh = None
    all_records: List[Dict[str, Any]] = []
    records_written = 0

    if not args.dry_run:
        changes_fh = changes_jsonl.open("w", encoding="utf-8")

    total_files = 0
    changed_files = 0
    touched_rules = 0

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

        # Write behavior:
        # - changed files are written (unless dry-run)
        # - unchanged files written only if --write-all
        if not args.dry_run:
            if any_change_in_file or args.write_all:
                out_path.parent.mkdir(parents=True, exist_ok=True)

                if (not any_change_in_file) and args.write_all and args.copy_unchanged:
                    shutil.copy2(rf, out_path)
                else:
                    # serialize from parsed doc (changed or unchanged)
                    if rf.suffix.lower() in (".yaml", ".yml"):
                        write_yaml(out_path, rdoc)
                    else:
                        write_json(out_path, rdoc, indent=2)

        if any_change_in_file:
            changed_files += 1

            rec = {
                "type": "rule_file_update_from_promoted_groups",
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

            if args.dry_run:
                log.info("[DRY-RUN] Would update %s", rf)
            else:
                all_records.append(rec)
                if changes_fh:
                    write_jsonl_record(changes_fh, rec)
                    records_written += 1

                # per-file pretty record
                pretty_path = per_rule_log_dir / rf.relative_to(rules_dir)
                pretty_path = pretty_path.with_suffix(".json")
                write_json(pretty_path, rec, indent=2)

    if changes_fh:
        changes_fh.close()

    if (not args.dry_run) and all_records:
        write_json(changes_pretty, all_records, indent=2)

    log.info("Complete. Total files=%d, changed files=%d, touched rules=%d", total_files, changed_files, touched_rules)
    if not args.dry_run:
        log.info("Change log: %s (records=%d)", changes_jsonl, records_written)
        log.info("Pretty log:  %s", changes_pretty)
        log.info("Per-file logs:%s", per_rule_log_dir)


if __name__ == "__main__":
    main()