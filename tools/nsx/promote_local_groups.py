#!/usr/bin/env python3
"""
tools/nsx/promote_local_groups.py

Promote NSX Local Manager (LM) groups into Global Manager (GM) by creating duplicates
with a suffix appended, then update rules whose names match those groups.

Updates in this version (per your repo layout):
- Makes inputs optional with sane defaults
- Defaults to LM folder: nsx-lm1.lab.local
- Defaults export root to: <repo>/nsx_export/nsx-gm1.lab.local/domains/default
- Derives LM groups dir as: <export_root>/<lm_name>/groups
- Derives rules dir (default) as: <export_root>/<lm_name>/security-policies
- Derives GM out dir (default) as: <repo>/nsx_promoted_groups/nsx-gm1.lab.local/domains/<domain>/groups
- Derives rules out dir (default) as: <repo>/nsx_updated_rules/nsx-gm1.lab.local/domains/<domain>/<lm_name>/security-policies

Behavior is unchanged otherwise.
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
DEFAULT_DOMAIN = "default"
DEFAULT_LM_NAME = "nsx-lm1.lab.local"

DEFAULT_EXPORT_ROOT = REPO_ROOT / "nsx_export" / DEFAULT_GM_NAME / "domains" / DEFAULT_DOMAIN

DEFAULT_GM_OUT_DIR = REPO_ROOT / "nsx_promoted_groups" / DEFAULT_GM_NAME / "domains" / DEFAULT_DOMAIN / "groups"
DEFAULT_RULES_OUT_DIR = REPO_ROOT / "nsx_updated_rules" / DEFAULT_GM_NAME / "domains" / DEFAULT_DOMAIN


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


def looks_local_path(path: str) -> bool:
    # LM: /infra/domains/<domain>/groups/<id>
    # GM: /global-infra/domains/<domain>/groups/<id>
    return path.startswith("/infra/domains/") or path.startswith("/infra/")


def build_gm_group_path(domain: str, group_id: str) -> str:
    return f"/global-infra/domains/{domain}/groups/{group_id}"


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
    domain: str,
    keep_expression: bool = True,
) -> Tuple[Dict[str, Any], Promotion]:
    old_id = get_group_id(g)
    old_name = get_group_name(g)
    old_path = get_group_path(g)

    new_id = f"{old_id}{suffix}"
    new_name = f"{old_name}{suffix}"
    new_path = build_gm_group_path(domain, new_id)

    new_group = dict(g)  # shallow copy
    new_group["id"] = new_id
    new_group["display_name"] = new_name
    new_group["path"] = new_path
    new_group["parent_path"] = f"/global-infra/domains/{domain}"
    new_group.setdefault("resource_type", "Group")

    if not keep_expression:
        new_group.pop("expression", None)

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
# Rule updating
# -----------------------------

GROUP_REF_KEYS = {
    "source_groups",
    "destination_groups",
    "scope",
    "applied_to",
    "sources",
    "destinations",
}


def ci_contains(haystack: str, needle: str) -> bool:
    return needle.lower() in haystack.lower()


def add_unique_str(lst: List[Any], item: str) -> bool:
    if item in lst:
        return False
    lst.append(item)
    return True


def update_group_refs_in_rule(
    rule: Dict[str, Any],
    *,
    match_group_name: str,
    old_path: Optional[str],
    new_path: str,
    replace: bool,
) -> Dict[str, Any]:
    """
    Only touches the rule if rule.display_name contains match_group_name (case-insensitive).
    Then:
      - If replace=True: replace old_path occurrences with new_path in group lists
      - Else: add new_path to group lists (add-only)
    """
    rule_name = rule.get("display_name") or rule.get("id") or ""
    if not isinstance(rule_name, str):
        rule_name = str(rule_name)

    if not ci_contains(rule_name, match_group_name):
        return {"touched": False, "changes": []}

    changes: List[Dict[str, Any]] = []

    for key in GROUP_REF_KEYS:
        val = rule.get(key)
        if not isinstance(val, list):
            continue

        before = list(val)

        if replace and old_path:
            did = False
            for i, x in enumerate(val):
                if isinstance(x, str) and x == old_path:
                    val[i] = new_path
                    did = True
            if did:
                changes.append({"field": key, "before": before, "after": list(val)})
        else:
            did = add_unique_str(val, new_path)
            if did:
                changes.append({"field": key, "before": before, "after": list(val)})

    return {"touched": bool(changes), "changes": changes}


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
# Main
# -----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Promote LM groups to GM duplicates and update matching rules.")

    ap.add_argument(
        "--export-root",
        type=Path,
        default=DEFAULT_EXPORT_ROOT,
        help=f"Export root containing LM folders (default: {DEFAULT_EXPORT_ROOT})",
    )
    ap.add_argument(
        "--lm-name",
        type=str,
        default=DEFAULT_LM_NAME,
        help=f"Local Manager folder name (default: {DEFAULT_LM_NAME})",
    )
    ap.add_argument(
        "--gm-name",
        type=str,
        default=DEFAULT_GM_NAME,
        help=f"GM name used for output path defaults (default: {DEFAULT_GM_NAME})",
    )
    ap.add_argument(
        "--domain",
        type=str,
        default=DEFAULT_DOMAIN,
        help="NSX domain id (default: default).",
    )

    ap.add_argument(
        "--gm-out-dir",
        type=Path,
        default=DEFAULT_GM_OUT_DIR,
        help=f"Output directory for promoted GM group YAML files (default: {DEFAULT_GM_OUT_DIR})",
    )
    ap.add_argument(
        "--rules-dir",
        type=Path,
        default=None,
        help="Directory containing rules YAML/JSON files to scan/update. "
             "Default: <export-root>/<lm-name>/security-policies",
    )
    ap.add_argument(
        "--rules-out-dir",
        type=Path,
        default=DEFAULT_RULES_OUT_DIR,
        help=f"Output directory for updated rules (default: {DEFAULT_RULES_OUT_DIR})",
    )

    ap.add_argument("--suffix", type=str, default="_to_gm", help="Suffix appended to new group id and display_name.")
    ap.add_argument("--replace", action="store_true", help="Replace old LM group path with new GM group path.")
    ap.add_argument("--dry-run", action="store_true", help="Do not write outputs; only log what would change.")
    ap.add_argument("--changes-jsonl", type=Path, default=Path("nsx_group_promotion_changes.jsonl"), help="JSONL change log path.")
    ap.add_argument("--log-level", type=str, default="INFO", help="Logging level (DEBUG, INFO, WARNING...).")

    args = ap.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(levelname)s %(message)s")

    # Resolve defaults that depend on other args
    export_root: Path = args.export_root
    lm_name: str = args.lm_name
    domain: str = args.domain
    gm_name: str = args.gm_name

    lm_groups_dir = export_root / lm_name / "groups"

    if args.rules_dir is None:
        rules_dir = export_root / lm_name / "security-policies"
    else:
        rules_dir = args.rules_dir

    # If user changed gm-name/domain, adjust default outputs unless they explicitly provided paths
    # (We keep args.gm_out_dir / args.rules_out_dir as-is, but if they left defaults, recompute.)
    default_gm_out = REPO_ROOT / "nsx_promoted_groups" / gm_name / "domains" / domain / "groups"
    default_rules_out = REPO_ROOT / "nsx_updated_rules" / gm_name / "domains" / domain

    gm_out: Path = args.gm_out_dir if args.gm_out_dir != DEFAULT_GM_OUT_DIR else default_gm_out
    rules_out_root: Path = args.rules_out_dir if args.rules_out_dir != DEFAULT_RULES_OUT_DIR else default_rules_out

    # Place updated rules under <rules_out_root>/<lm-name>/security-policies/... to mirror source
    rules_out = rules_out_root / lm_name / "security-policies"

    suffix = args.suffix

    if not lm_groups_dir.exists():
        raise SystemExit(f"LM groups directory not found: {lm_groups_dir}")

    if not rules_dir.exists():
        log.warning("Rules directory not found (will still promote groups): %s", rules_dir)

    promotions: List[Promotion] = []
    promoted_groups: List[Tuple[Path, Dict[str, Any], Promotion]] = []

    # 1) Read LM groups and create promotions
    for f in iter_docs(lm_groups_dir):
        try:
            doc = load_doc(f)
        except Exception as e:
            log.warning("Skip unreadable file %s: %s", f, e)
            continue

        if not is_group_payload(doc):
            continue

        old_path = get_group_path(doc) or ""
        if old_path and not looks_local_path(old_path):
            continue

        new_group, promo = promote_group_payload(doc, suffix=suffix, domain=domain)
        promo = Promotion(
            old_id=promo.old_id,
            old_name=promo.old_name,
            old_path=promo.old_path,
            new_id=promo.new_id,
            new_name=promo.new_name,
            new_path=promo.new_path,
            source_file=str(f),
        )

        out_file = gm_out / (f.stem + f"{suffix}.yaml")

        promotions.append(promo)
        promoted_groups.append((out_file, new_group, promo))

    log.info("Found %d LM groups to promote from %s.", len(promotions), lm_groups_dir)

    # 2) Write promoted groups
    if not args.dry_run:
        for out_file, new_group, _promo in promoted_groups:
            write_yaml(out_file, new_group)
        log.info("Wrote %d promoted GM group files to %s", len(promoted_groups), gm_out)
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
                rule_changes: List[Dict[str, Any]] = []

                for promo in promotions:
                    result = update_group_refs_in_rule(
                        rule,
                        match_group_name=promo.old_name,
                        old_path=promo.old_path,
                        new_path=promo.new_path,
                        replace=args.replace,
                    )
                    if result["touched"]:
                        rule_changes.append({
                            "promotion": {
                                "old_name": promo.old_name,
                                "old_path": promo.old_path,
                                "new_name": promo.new_name,
                                "new_path": promo.new_path,
                            },
                            "changes": result["changes"],
                        })

                if rule_changes:
                    any_change_in_file = True
                    touched_rules_total += 1
                    file_changes.append({
                        "rule_index": idx,
                        "rule_display_name": rule.get("display_name"),
                        "rule_id": rule.get("id"),
                        "updates": rule_changes,
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
                            "lm_name": lm_name,
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