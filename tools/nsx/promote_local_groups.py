#!/usr/bin/env python3
"""
tools/nsx/promote_local_groups.py

Promote NSX Local Manager (LM-domain) groups into Global Manager (GM) shared domain
by creating duplicates with a suffix appended, then update rules that reference those groups.

Key behavior:
- Reads *input groups* from your additive/remapped directory (default):
    <repo>/nsx_groups_additive/<gm-name>/domains/<src-domain>/groups
- Writes *promoted groups* to (default):
    <repo>/nsx_promoted_groups/<gm-name>/domains/<dst-domain>/groups
- Reads *rules* from (default):
    <repo>/nsx_export/<gm-name>/domains/<src-domain>/security-policies
- Writes *updated rules* to (default):
    <repo>/nsx_updated_rules/<gm-name>/domains/<dst-domain>/<src-domain>/security-policies

Rule update logic (IMPORTANT):
- Does NOT rely on rule.display_name containing the group name.
- Instead, scans group reference fields and touches a rule if it references the group
  by either:
    - exact old_path match
    - OR endswith "/groups/<old_id>" match
- If --replace: replaces old reference(s) with new_path
- Else (default add-only): adds new_path only when an old reference is present
"""

from __future__ import annotations

import argparse
import json
import logging
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

# Input groups default: additive/remapped groups (THIS is the important change)
DEFAULT_GROUPS_ROOT = REPO_ROOT / "nsx_groups_additive" / DEFAULT_GM_NAME / "domains"

# Rules default: still from export (unless you override)
DEFAULT_RULES_ROOT = REPO_ROOT / "nsx_export" / DEFAULT_GM_NAME / "domains"

# Outputs
DEFAULT_GM_OUT_DIR = REPO_ROOT / "nsx_promoted_groups" / DEFAULT_GM_NAME / "domains" / DEFAULT_DST_DOMAIN / "groups"
DEFAULT_RULES_OUT_ROOT = REPO_ROOT / "nsx_updated_rules" / DEFAULT_GM_NAME / "domains" / DEFAULT_DST_DOMAIN


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

def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

def iter_docs(root: Path, exts: Tuple[str, ...] = (".yaml", ".yml", ".json")) -> Iterator[Path]:
    if not root.exists():
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in exts:
            yield p


# -----------------------------
# NSX detection / normalization
# -----------------------------

def is_group_payload(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    rt = doc.get("resource_type")
    if rt == "Group":
        return True
    # Heuristic: group-ish payloads often have these keys
    if "expression" in doc and "display_name" in doc and "id" in doc:
        return True
    return False

def extract_group_payloads(doc: Any) -> List[Dict[str, Any]]:
    """
    Normalize loaded YAML/JSON into a list of group dict payloads.
    Handles:
      - single group dict
      - list of group dicts
      - container dicts with common keys
    """
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
    """
    Yields (kind, rule_dict, index)
      kind: "container" if from doc["rules"], else "single"
      index: int if container, else None
    """
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
    """
    Return True if a rule group reference string refers to this group, either:
    - exact match on old_path (best)
    - or suffix match /groups/<old_id> (handles slight domain/path differences)
    """
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

    new_group = dict(g)  # shallow copy
    new_group["id"] = new_id
    new_group["display_name"] = new_name
    new_group["path"] = new_path
    new_group["parent_path"] = f"/global-infra/domains/{dst_domain}"
    new_group.setdefault("resource_type", "Group")

    if not keep_expression:
        new_group.pop("expression", None)

    # Strip volatile/read-only keys (keep diffs sane)
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
    - replace=False: add new_path (add-only) but ONLY when a matching old ref exists
    """
    changes: List[Dict[str, Any]] = []
    touched = False

    for key in GROUP_REF_KEYS:
        val = rule.get(key)
        if not isinstance(val, list):
            continue

        before = list(val)
        matches = [i for i, x in enumerate(val) if isinstance(x, str) and group_ref_matches(x, old_path=old_path, old_id=old_id)]
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
    ap.add_argument("--src-domain", type=str, default=DEFAULT_SRC_DOMAIN, help="Source domain (where the LM groups currently live).")
    ap.add_argument("--dst-domain", type=str, default=DEFAULT_DST_DOMAIN, help="Destination domain to promote INTO (usually 'default').")

    ap.add_argument(
        "--groups-root",
        type=Path,
        default=DEFAULT_GROUPS_ROOT,
        help=f"Root that contains domains/<src-domain>/groups (default: {DEFAULT_GROUPS_ROOT})",
    )
    ap.add_argument(
        "--rules-root",
        type=Path,
        default=DEFAULT_RULES_ROOT,
        help=f"Root that contains domains/<src-domain>/security-policies (default: {DEFAULT_RULES_ROOT})",
    )

    ap.add_argument(
        "--gm-out-dir",
        type=Path,
        default=None,
        help="Output directory for promoted GM group YAML files. Default computed from gm-name/dst-domain.",
    )
    ap.add_argument(
        "--rules-out-root",
        type=Path,
        default=None,
        help="Output root for updated rules. Default computed from gm-name/dst-domain.",
    )

    ap.add_argument("--suffix", type=str, default=DEFAULT_SUFFIX, help="Suffix appended to new group id and display_name.")
    ap.add_argument("--replace", action="store_true", help="Replace old group refs with new group refs (default is add-only).")
    ap.add_argument("--dry-run", action="store_true", help="Do not write outputs; only log what would change.")
    ap.add_argument("--changes-jsonl", type=Path, default=Path("nsx_group_promotion_changes.jsonl"), help="JSONL change log path.")
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
    lm_groups_dir = args.groups_root / src_domain / "groups"
    rules_dir = args.rules_root / src_domain / "security-policies"

    gm_out = args.gm_out_dir or (REPO_ROOT / "nsx_promoted_groups" / gm_name / "domains" / dst_domain / "groups")
    rules_out_root = args.rules_out_root or (REPO_ROOT / "nsx_updated_rules" / gm_name / "domains" / dst_domain)
    rules_out = rules_out_root / src_domain / "security-policies"

    log.info("Groups input dir: %s", lm_groups_dir)
    log.info("Rules input dir:  %s", rules_dir)
    log.info("Groups output dir:%s", gm_out)
    log.info("Rules output dir: %s", rules_out)

    if not lm_groups_dir.exists():
        raise SystemExit(f"Groups input directory not found: {lm_groups_dir}")

    if not rules_dir.exists():
        log.warning("Rules directory not found (will still promote groups): %s", rules_dir)

    promotions: List[Promotion] = []
    promoted_groups: List[Tuple[Path, Dict[str, Any], Promotion]] = []

    # 1) Read groups and create promotions
    for f in iter_docs(lm_groups_dir):
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

            out_file = gm_out / f"{promo.new_id}.yaml"
            promotions.append(promo)
            promoted_groups.append((out_file, new_group, promo))

    log.info("Found %d group(s) to promote from %s.", len(promotions), lm_groups_dir)

    # 2) Write promoted groups
    if not args.dry_run:
        for out_file, new_group, _promo in promoted_groups:
            write_yaml(out_file, new_group)
        log.info("Wrote %d promoted group file(s) to %s", len(promoted_groups), gm_out)
    else:
        log.info("Dry-run: not writing promoted group files.")

    # 3) Update rules
    changes_fh = None
    if not args.dry_run:
        args.changes_jsonl.parent.mkdir(parents=True, exist_ok=True)
        changes_fh = args.changes_jsonl.open("w", encoding="utf-8")

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

                if not args.dry_run:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    if rf.suffix.lower() in (".yaml", ".yml"):
                        write_yaml(out_path, rdoc)
                    else:
                        write_json(out_path, rdoc)

                    if changes_fh:
                        changes_fh.write(json.dumps({
                            "gm_name": gm_name,
                            "src_domain": src_domain,
                            "dst_domain": dst_domain,
                            "groups_dir": str(lm_groups_dir),
                            "rules_dir": str(rules_dir),
                            "file": str(rf),
                            "out_file": str(out_path),
                            "replace_mode": bool(args.replace),
                            "changes": file_changes,
                        }) + "\n")
                else:
                    log.info("Dry-run: would update rules file %s", rf)

    if changes_fh:
        changes_fh.close()

    log.info("Rule update complete. Updated files=%d, touched rules=%d", updated_rule_files, touched_rules_total)
    if not args.dry_run:
        log.info("Change log: %s", args.changes_jsonl)


if __name__ == "__main__":
    main()