#!/usr/bin/env python3
"""
tools/nsx/promote_local_groups.py

Promote NSX Local Manager (LM-domain) groups into Global Manager (GM) shared domain
by creating duplicates with a suffix appended, then update rules that reference those groups.

Inputs/Outputs (defaults match your repo layout):

- Reads INPUT groups from additive/remapped directory:
    <repo>/nsx_groups_additive/<gm-name>/domains/<src-domain>/groups

- Writes PROMOTED group YAMLs to:
    <repo>/nsx_promoted_groups/<gm-name>/domains/<dst-domain>/groups
  (filename is the promoted group's display_name, filesystem-safe)

- Reads RULES from export:
    <repo>/nsx_export/<gm-name>/domains/<src-domain>/security-policies

- Writes UPDATED RULES to:
    <repo>/nsx_updated_rules/<gm-name>/domains/<dst-domain>/<src-domain>/security-policies

Rule update logic:
- Does NOT rely on rule.display_name containing the group name.
- Scans group reference fields and touches a rule if it references the group by either:
    - exact old_path match
    - OR endswith "/groups/<old_id>" match
- If --replace: replaces old reference(s) with new_path
- Else (default add-only): adds new_path only when an old reference is present

Logging (what you asked for):
- JSONL event log: one record PER GROUP PROMOTION + one record PER RULE FILE UPDATED
    <repo>/nsx_logs/nsx_group_promotion_changes.jsonl

- Pretty combined JSON (all records in a list):
    <repo>/nsx_logs/nsx_group_promotion_changes.pretty.json

- Pretty per-group records:
    <repo>/nsx_logs/group_promotions/<safe_display_name>.json

- Pretty per-rule-file records (mirrors relative path from rules_dir):
    <repo>/nsx_logs/rule_updates/<relative/path/to/rulesfile>.json
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e

log = logging.getLogger("promote_local_groups")

# -----------------------------
# Repo defaults (match your layout)
# -----------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_GM_NAME = "nsx-gm1.lab.local"
DEFAULT_SRC_DOMAIN = "nsx-lm1.lab.local"  # where LM-scoped objects live on GM in your env
DEFAULT_DST_DOMAIN = "default"            # shared/global domain you want to promote INTO
DEFAULT_SUFFIX = "_to_gm"

# Input groups default: additive/remapped groups
DEFAULT_GROUPS_ROOT = REPO_ROOT / "nsx_groups_additive" / DEFAULT_GM_NAME / "domains"

# Rules default: from export
DEFAULT_RULES_ROOT = REPO_ROOT / "nsx_export" / DEFAULT_GM_NAME / "domains"

# Outputs
DEFAULT_GM_OUT_DIR = REPO_ROOT / "nsx_promoted_groups" / DEFAULT_GM_NAME / "domains" / DEFAULT_DST_DOMAIN / "groups"
DEFAULT_RULES_OUT_ROOT = REPO_ROOT / "nsx_updated_rules" / DEFAULT_GM_NAME / "domains" / DEFAULT_DST_DOMAIN

# Logging outputs
DEFAULT_LOG_DIR = REPO_ROOT / "nsx_logs"
DEFAULT_CHANGES_JSONL = DEFAULT_LOG_DIR / "nsx_group_promotion_changes.jsonl"
DEFAULT_CHANGES_PRETTY = DEFAULT_LOG_DIR / "nsx_group_promotion_changes.pretty.json"
DEFAULT_GROUP_LOG_DIR = DEFAULT_LOG_DIR / "group_promotions"
DEFAULT_RULE_LOG_DIR = DEFAULT_LOG_DIR / "rule_updates"


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

def safe_filename(name: str, *, max_len: int = 180) -> str:
    """Convert a display_name into a filesystem-safe filename."""
    name = (name or "").strip()
    name = re.sub(r"[\\/:\*\?\"<>\|\n\r\t]+", "_", name)  # illegal-ish chars
    name = re.sub(r"\s+", " ", name).strip()
    name = name.replace(" ", "_")
    name = re.sub(r"_+", "_", name).strip("_")
    if not name:
        name = "unnamed"
    return name[:max_len] if len(name) > max_len else name

def write_jsonl_record(fh, record: Dict[str, Any]) -> None:
    """
    Write exactly one JSON object + newline.
    Flush so you can watch it live while running.
    """
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
    """Normalize loaded YAML/JSON into a list of group payload dicts."""
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
# Group getters / path helpers
# -----------------------------

def get_group_id(doc: Dict[str, Any]) -> str:
    gid = doc.get("id")
    if isinstance(gid, str) and gid.strip():
        return gid
    raise ValueError("Group missing id")

def get_group_name(doc: Dict[str, Any]) -> str:
    name = doc.get("display_name")
    if isinstance(name, str) and name.strip():
        return name
    return get_group_id(doc)

def get_group_path(doc: Dict[str, Any]) -> Optional[str]:
    p = doc.get("path")
    if isinstance(p, str) and p.strip():
        return p
    return None

def build_gm_group_path(domain: str, group_id: str) -> str:
    return f"/global-infra/domains/{domain}/groups/{group_id}"

def group_ref_matches(ref: str, *, old_path: Optional[str], old_id: str) -> bool:
    """Match exact old_path or suffix /groups/<old_id>."""
    if not isinstance(ref, str) or not ref:
        return False
    if old_path and ref == old_path:
        return True
    return ref.endswith(f"/groups/{old_id}")


@dataclass(frozen=True)
class Promotion:
    old_id: str
    old_name: str
    old_path: Optional[str]
    new_id: str
    new_name: str
    new_path: str
    source_file: str


def promote_group_payload(
    g: Dict[str, Any],
    *,
    suffix: str,
    dst_domain: str,
    keep_expression: bool = True,
) -> Tuple[Dict[str, Any], Promotion]:
    old_id = get_group_id(g)
    old_name = get_group_name(g)
    old_path = get_group_path(g)

    new_id = f"{old_id}{suffix}"
    new_name = f"{old_name}{suffix}"
    new_path = build_gm_group_path(dst_domain, new_id)

    new_group = dict(g)
    new_group["id"] = new_id
    new_group["display_name"] = new_name
    new_group["path"] = new_path
    new_group["parent_path"] = f"/global-infra/domains/{dst_domain}"
    new_group.setdefault("resource_type", "Group")

    if not keep_expression:
        new_group.pop("expression", None)

    # Strip volatile/read-only keys
    for k in (
        "revision", "_revision",
        "unique_id", "realization_id",
        "marked_for_delete", "overridden",
        "create_time", "create_time_ms",
        "last_modified_time", "last_modified_time_ms",
        "create_user", "last_modified_user",
        "owner_id", "source",
        "_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
        "_system_owned", "_protection",
    ):
        new_group.pop(k, None)

    promo = Promotion(
        old_id=old_id,
        old_name=old_name,
        old_path=old_path,
        new_id=new_id,
        new_name=new_name,
        new_path=new_path,
        source_file="",
    )
    return new_group, promo


# -----------------------------
# Rule updating (by references, not names)
# -----------------------------

GROUP_REF_KEYS = {
    "source_groups",
    "destination_groups",
    "scope",
    "applied_to",
    "sources",
    "destinations",
}

def add_unique_str(lst: List[Any], item: str) -> bool:
    if item in lst:
        return False
    lst.append(item)
    return True

def update_group_refs_in_rule(
    rule: Dict[str, Any],
    *,
    old_id: str,
    old_path: Optional[str],
    new_path: str,
    replace: bool,
) -> Dict[str, Any]:
    """
    Touches a rule only if it references the group in one of GROUP_REF_KEYS lists.
    - replace=True: replace matching entries with new_path
    - replace=False: add new_path but ONLY when a matching old ref exists
    """
    changes: List[Dict[str, Any]] = []
    touched = False

    for key in GROUP_REF_KEYS:
        val = rule.get(key)
        if not isinstance(val, list):
            continue

        before = list(val)
        matches = [
            i for i, x in enumerate(val)
            if isinstance(x, str) and group_ref_matches(x, old_path=old_path, old_id=old_id)
        ]
        if not matches:
            continue

        if replace:
            for i in matches:
                val[i] = new_path
            touched = True
            changes.append({"field": key, "before": before, "after": list(val)})
        else:
            did = add_unique_str(val, new_path)
            if did:
                touched = True
                changes.append({"field": key, "before": before, "after": list(val)})

    return {"touched": touched, "changes": changes}


# -----------------------------
# Main
# -----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Promote LM-domain groups to shared GM domain and update referencing rules.")

    ap.add_argument("--gm-name", type=str, default=DEFAULT_GM_NAME, help="GM name used for default paths.")
    ap.add_argument("--src-domain", type=str, default=DEFAULT_SRC_DOMAIN, help="Source domain (where LM groups currently live).")
    ap.add_argument("--dst-domain", type=str, default=DEFAULT_DST_DOMAIN, help="Destination domain (usually 'default').")

    ap.add_argument("--groups-root", type=Path, default=DEFAULT_GROUPS_ROOT,
                    help=f"Root containing domains/<src-domain>/groups (default: {DEFAULT_GROUPS_ROOT})")
    ap.add_argument("--rules-root", type=Path, default=DEFAULT_RULES_ROOT,
                    help=f"Root containing domains/<src-domain>/security-policies (default: {DEFAULT_RULES_ROOT})")

    ap.add_argument("--gm-out-dir", type=Path, default=None,
                    help="Output dir for promoted group YAMLs. Default computed from gm-name/dst-domain.")
    ap.add_argument("--rules-out-root", type=Path, default=None,
                    help="Output root for updated rules. Default computed from gm-name/dst-domain.")

    ap.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR,
                    help=f"Logging directory (default: {DEFAULT_LOG_DIR})")
    ap.add_argument("--changes-jsonl", type=Path, default=None,
                    help="JSONL change log path. Default: <log-dir>/nsx_group_promotion_changes.jsonl")
    ap.add_argument("--changes-pretty", type=Path, default=None,
                    help="Pretty combined JSON path. Default: <log-dir>/nsx_group_promotion_changes.pretty.json")

    ap.add_argument("--suffix", type=str, default=DEFAULT_SUFFIX, help="Suffix appended to new group id/display_name.")
    ap.add_argument("--replace", action="store_true", help="Replace old refs with new refs (default add-only).")
    ap.add_argument("--dry-run", action="store_true", help="Do not write outputs; only log what would change.")
    ap.add_argument("--log-level", type=str, default="INFO", help="Logging level (DEBUG, INFO, WARNING...).")

    args = ap.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(levelname)s %(message)s",
    )

    gm_name: str = args.gm_name
    src_domain: str = args.src_domain
    dst_domain: str = args.dst_domain
    suffix: str = args.suffix

    # Derived dirs
    groups_in_dir = args.groups_root / src_domain / "groups"
    rules_dir = args.rules_root / src_domain / "security-policies"

    gm_out = args.gm_out_dir or (REPO_ROOT / "nsx_promoted_groups" / gm_name / "domains" / dst_domain / "groups")
    rules_out_root = args.rules_out_root or (REPO_ROOT / "nsx_updated_rules" / gm_name / "domains" / dst_domain)
    rules_out = rules_out_root / src_domain / "security-policies"

    # Logging paths
    log_dir: Path = args.log_dir
    changes_jsonl: Path = args.changes_jsonl or (log_dir / "nsx_group_promotion_changes.jsonl")
    changes_pretty: Path = args.changes_pretty or (log_dir / "nsx_group_promotion_changes.pretty.json")
    group_log_dir: Path = log_dir / "group_promotions"
    rule_log_dir: Path = log_dir / "rule_updates"

    log.info("Groups input dir:  %s", groups_in_dir)
    log.info("Rules input dir:   %s", rules_dir)
    log.info("Groups output dir: %s", gm_out)
    log.info("Rules output dir:  %s", rules_out)
    log.info("Change log (jsonl):%s", changes_jsonl)
    log.info("Change log (pretty):%s", changes_pretty)

    if not groups_in_dir.exists():
        raise SystemExit(f"Groups input directory not found: {groups_in_dir}")

    if not rules_dir.exists():
        log.warning("Rules directory not found (will still promote groups): %s", rules_dir)

    promotions: List[Promotion] = []
    promoted_groups: List[Tuple[Path, Dict[str, Any], Promotion]] = []

    # Open JSONL early so group promotion events also get written
    records_written = 0
    all_records: List[Dict[str, Any]] = []

    changes_jsonl.parent.mkdir(parents=True, exist_ok=True)
    group_log_dir.mkdir(parents=True, exist_ok=True)
    rule_log_dir.mkdir(parents=True, exist_ok=True)

    changes_fh = None
    if not args.dry_run:
        changes_fh = changes_jsonl.open("w", encoding="utf-8")

    # 1) Read groups and create promotions
    for f in iter_docs(groups_in_dir):
        try:
            doc = load_doc(f)
        except Exception as e:
            log.warning("Skip unreadable group file %s: %s", f, e)
            continue

        group_docs = extract_group_payloads(doc)
        if not group_docs:
            continue

        for gdoc in group_docs:
            new_group, promo0 = promote_group_payload(gdoc, suffix=suffix, dst_domain=dst_domain)

            promo = Promotion(
                old_id=promo0.old_id,
                old_name=promo0.old_name,
                old_path=promo0.old_path,
                new_id=promo0.new_id,
                new_name=promo0.new_name,
                new_path=promo0.new_path,
                source_file=str(f),
            )

            # Output filename MUST be display name (safe)
            base = safe_filename(promo.new_name)
            out_file = gm_out / f"{base}.yaml"
            # Collision guard
            if any(out_file == p for (p, _, _) in promoted_groups):
                out_file = gm_out / f"{base}__{promo.new_id}.yaml"

            promotions.append(promo)
            promoted_groups.append((out_file, new_group, promo))

    log.info("Found %d group(s) to promote from %s.", len(promotions), groups_in_dir)

    # 2) Write promoted groups + write group promotion log records (1 per group)
    if not args.dry_run:
        for out_file, new_group, promo in promoted_groups:
            write_yaml(out_file, new_group)

            rec = {
                "type": "group_promotion",
                "gm_name": gm_name,
                "src_domain": src_domain,
                "dst_domain": dst_domain,
                "source_file": promo.source_file,
                "out_file": str(out_file),
                "promotion": {
                    "old_id": promo.old_id,
                    "old_name": promo.old_name,
                    "old_path": promo.old_path,
                    "new_id": promo.new_id,
                    "new_name": promo.new_name,
                    "new_path": promo.new_path,
                },
            }
            all_records.append(rec)
            if changes_fh:
                write_jsonl_record(changes_fh, rec)
                records_written += 1

            # Pretty per-group file
            pretty_group_path = group_log_dir / f"{safe_filename(promo.new_name)}.json"
            write_json(pretty_group_path, rec, indent=2)

        log.info("Wrote %d promoted group file(s) to %s", len(promoted_groups), gm_out)
    else:
        log.info("Dry-run: not writing promoted group files/logs.")

    # 3) Update rules (write 1 record per RULE FILE updated + pretty per-rule file)
    updated_rule_files = 0
    touched_rules_total = 0

    if rules_dir.exists():
        for rf in iter_docs(rules_dir):
            try:
                rdoc = load_doc(rf)
            except Exception as e:
                log.warning("Skip unreadable rules file %s: %s", rf, e)
                continue

            any_change_in_file = False
            file_changes: List[Dict[str, Any]] = []

            for _kind, rule, idx in iter_rules_from_doc(rdoc):
                rule_updates: List[Dict[str, Any]] = []

                for promo in promotions:
                    result = update_group_refs_in_rule(
                        rule,
                        old_id=promo.old_id,
                        old_path=promo.old_path,
                        new_path=promo.new_path,
                        replace=args.replace,
                    )
                    if result["touched"]:
                        rule_updates.append({
                            "promotion": {
                                "old_id": promo.old_id,
                                "old_name": promo.old_name,
                                "old_path": promo.old_path,
                                "new_id": promo.new_id,
                                "new_name": promo.new_name,
                                "new_path": promo.new_path,
                            },
                            "changes": result["changes"],
                        })

                if rule_updates:
                    any_change_in_file = True
                    touched_rules_total += 1
                    file_changes.append({
                        "rule_index": idx,
                        "rule_display_name": rule.get("display_name"),
                        "rule_id": rule.get("id"),
                        "updates": rule_updates,
                    })

            if any_change_in_file:
                updated_rule_files += 1
                out_path = rules_out / rf.relative_to(rules_dir)

                rec = {
                    "type": "rule_file_update",
                    "gm_name": gm_name,
                    "src_domain": src_domain,
                    "dst_domain": dst_domain,
                    "groups_dir": str(groups_in_dir),
                    "rules_dir": str(rules_dir),
                    "file": str(rf),
                    "out_file": str(out_path),
                    "replace_mode": bool(args.replace),
                    "changes": file_changes,
                }

                if not args.dry_run:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    if rf.suffix.lower() in (".yaml", ".yml"):
                        write_yaml(out_path, rdoc)
                    else:
                        write_json(out_path, rdoc, indent=2)

                    all_records.append(rec)
                    if changes_fh:
                        write_jsonl_record(changes_fh, rec)
                        records_written += 1

                    # Pretty per-rule file mirrors relative path
                    pretty_rule_path = rule_log_dir / rf.relative_to(rules_dir)
                    pretty_rule_path = pretty_rule_path.with_suffix(".json")
                    write_json(pretty_rule_path, rec, indent=2)

                else:
                    log.info("Dry-run: would update rules file %s", rf)

    if changes_fh:
        changes_fh.close()

    # 4) Pretty combined JSON
    if (not args.dry_run) and all_records:
        write_json(changes_pretty, all_records, indent=2)

    log.info("Rule update complete. Updated files=%d, touched rules=%d", updated_rule_files, touched_rules_total)
    if not args.dry_run:
        log.info("Change log: %s (records=%d)", changes_jsonl, records_written)
        log.info("Pretty log:  %s", changes_pretty)
        log.info("Group logs:  %s", group_log_dir)
        log.info("Rule logs:   %s", rule_log_dir)


if __name__ == "__main__":
    main()