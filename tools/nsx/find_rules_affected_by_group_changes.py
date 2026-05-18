#!/usr/bin/env python3
# tools/nsx/find_rules_affected_by_group_changes.py

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

try:
    import yaml
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e

"""
COMMAND TEST BLOCK (disabled)

python tools/nsx/find_rules_affected_by_group_changes.py --federation-global

python tools/nsx/find_rules_affected_by_group_changes.py --federation-global --verbose

python tools/nsx/find_rules_affected_by_group_changes.py \
  --additive-root nsx_groups_additive \
  --export-root nsx_export \
  --output-dir nsx_logs/affected_rule_reports \
  --federation-global \
  --verbose
"""


# =============================================================================
# Defaults
# =============================================================================

DEFAULT_ADDITIVE_ROOT = "nsx_groups_additive"
DEFAULT_EXPORT_ROOT = "nsx_export"
DEFAULT_OUTPUT_DIR = "nsx_logs/affected_rule_reports"
LOG_FILE_NAME = "find_rules_affected_by_group_changes.log"


# =============================================================================
# Logging
# =============================================================================

def setup_logging(output_dir: Path, verbose: bool = False) -> logging.Logger:
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / LOG_FILE_NAME

    logger = logging.getLogger("find_rules_affected_by_group_changes")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%dT%H:%M:%S UTC",
    )

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG if verbose else logging.INFO)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    logger.debug("Logging initialized. Log file: %s", log_path)
    return logger


# =============================================================================
# Data classes
# =============================================================================

@dataclass(frozen=True)
class ChangedGroup:
    manager: str
    domain_id: str
    group_id: str
    file_path: str
    display_name: Optional[str]
    group_path: Optional[str]
    aliases: Tuple[str, ...]

@dataclass(frozen=True)
class AffectedGroupRef:
    manager: str
    domain_id: str
    group_id: str
    display_name: Optional[str]
    group_path: Optional[str]
    file_path: str

@dataclass(frozen=True)
class AffectedRule:
    manager: str
    domain_id: Optional[str]
    policy_id: Optional[str]
    policy_display_name: Optional[str]
    policy_path: Optional[str]
    rule_id: str
    rule_display_name: Optional[str]
    rule_name_or_id: str
    rule_path: Optional[str]
    rule_file: str
    affected_group_ids: Tuple[str, ...]
    affected_groups: Tuple[Dict[str, Any], ...]
    matched_reference_values: Tuple[str, ...]
    match_fields: Tuple[str, ...]

@dataclass(frozen=True)
class AffectedPolicy:
    manager: str
    domain_id: Optional[str]
    policy_id: str
    policy_display_name: Optional[str]
    policy_name_or_id: str
    policy_path: Optional[str]
    source_file: str
    affected_rule_ids: Tuple[str, ...]
    affected_rule_names_or_ids: Tuple[str, ...]
    changed_groups: Tuple[str, ...]
    affected_groups: Tuple[Dict[str, Any], ...]


# =============================================================================
# File loading
# =============================================================================

def load_structured_file(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    if suffix == ".json":
        return json.loads(text)

    if suffix in {".yaml", ".yml"}:
        docs = list(yaml.safe_load_all(text))
        if len(docs) == 1:
            return docs[0]
        return docs

    raise ValueError(f"Unsupported file type: {path}")


def iter_structured_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".json", ".yaml", ".yml"}:
            yield path


# =============================================================================
# Generic helpers
# =============================================================================

def safe_get_str(d: Dict[str, Any], key: str) -> Optional[str]:
    v = d.get(key)
    return v if isinstance(v, str) and v.strip() else None


def unique_sorted(values: Iterable[str]) -> Tuple[str, ...]:
    return tuple(sorted({v for v in values if isinstance(v, str) and v.strip()}))


def walk_dicts(obj: Any) -> Iterator[Dict[str, Any]]:
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from walk_dicts(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_dicts(item)


def walk_strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from walk_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_strings(item)


def get_manager_from_relative_path(root: Path, path: Path) -> Optional[str]:
    rel = path.relative_to(root)
    if not rel.parts:
        return None
    return rel.parts[0]


def get_domain_from_relative_path(root: Path, path: Path) -> Optional[str]:
    rel = path.relative_to(root)
    parts = list(rel.parts)
    if "domains" in parts:
        idx = parts.index("domains")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def find_first_value(obj: Any, keys: Iterable[str]) -> Optional[str]:
    keyset = set(keys)
    for d in walk_dicts(obj):
        for k in keyset:
            v = d.get(k)
            if isinstance(v, str) and v.strip():
                return v
    return None


def file_path_contains_segment(path: Path, segment: str) -> bool:
    return segment in set(path.parts)


# =============================================================================
# Group discovery
# =============================================================================

def is_group_file_path(additive_root: Path, path: Path) -> bool:
    rel = path.relative_to(additive_root)
    parts = rel.parts
    return "domains" in parts and "groups" in parts


def build_group_aliases(
    domain_id: str,
    group_id: str,
    payload: Any,
    *,
    federation_global: bool,
) -> Tuple[str, ...]:
    aliases: Set[str] = set()

    aliases.add(group_id)

    # Keep both forms for cross-checking exported data, but let the flag exist
    # explicitly so the run is federation-aware and logged as such.
    aliases.add(f"/infra/domains/{domain_id}/groups/{group_id}")
    aliases.add(f"/global-infra/domains/{domain_id}/groups/{group_id}")

    if federation_global:
        aliases.add(f"/global-infra/domains/{domain_id}/groups/{group_id}")
    else:
        aliases.add(f"/infra/domains/{domain_id}/groups/{group_id}")

    for d in walk_dicts(payload):
        for key in ("id", "path", "relative_path", "display_name"):
            v = d.get(key)
            if isinstance(v, str) and v.strip():
                aliases.add(v)

    return unique_sorted(aliases)


def discover_changed_groups(
    additive_root: Path,
    logger: logging.Logger,
    *,
    federation_global: bool,
) -> List[ChangedGroup]:
    groups: List[ChangedGroup] = []

    for path in iter_structured_files(additive_root):
        if not is_group_file_path(additive_root, path):
            continue

        try:
            payload = load_structured_file(path)
        except Exception as e:
            logger.warning("Skipping unreadable group file %s: %s", path, e)
            continue

        manager = get_manager_from_relative_path(additive_root, path) or "unknown-manager"
        domain_id = get_domain_from_relative_path(additive_root, path) or "default"

        group_id = find_first_value(payload, ("id",)) or path.stem
        display_name = find_first_value(payload, ("display_name",))
        group_path = find_first_value(payload, ("path", "relative_path"))

        aliases = build_group_aliases(
            domain_id,
            group_id,
            payload,
            federation_global=federation_global,
        )

        groups.append(
            ChangedGroup(
                manager=manager,
                domain_id=domain_id,
                group_id=group_id,
                file_path=str(path),
                display_name=display_name,
                group_path=group_path,
                aliases=aliases,
            )
        )

    logger.info("Discovered %d changed group file(s) in %s", len(groups), additive_root)
    return groups


# =============================================================================
# Rule / policy extraction
# =============================================================================

RULE_REFERENCE_FIELDS = {
    "source_groups",
    "destination_groups",
    "scope",
    "applied_tos",
    "profiles",
    "group_paths",
    "groups",
    "sources",
    "destinations",
}

POLICY_TYPE_HINTS = {
    "SecurityPolicy",
    "GatewayPolicy",
    "Policy",
}

RULE_TYPE_HINTS = {
    "Rule",
}


def looks_like_policy(d: Dict[str, Any]) -> bool:
    rt = d.get("resource_type")
    category = d.get("category")
    if isinstance(rt, str):
        if rt in POLICY_TYPE_HINTS:
            return True
        if rt.endswith("Policy"):
            return True
    if "rules" in d and isinstance(d["rules"], list):
        return True
    if category is not None and "rules" in d:
        return True
    return False


def looks_like_rule(d: Dict[str, Any]) -> bool:
    rt = d.get("resource_type")
    if isinstance(rt, str):
        if rt in RULE_TYPE_HINTS or rt.endswith("Rule"):
            return True

    if any(k in d for k in ("source_groups", "destination_groups", "scope")):
        return True

    if "id" in d and (
        "action" in d
        or "services" in d
        or "source_groups" in d
        or "destination_groups" in d
    ):
        return True

    return False


def build_fallback_policy_context(file_path: Path, manager: str, file_domain: Optional[str]) -> Dict[str, Any]:
    """
    Best-effort fallback when nested policy metadata is missing.
    """
    policy_id = file_path.stem
    policy_display_name = file_path.stem
    policy_path = None

    parts = list(file_path.parts)
    if "domains" in parts and "security-policies" in parts:
        try:
            domain_idx = parts.index("domains")
            policy_idx = parts.index("security-policies")
            domain_id = parts[domain_idx + 1] if domain_idx + 1 < len(parts) else file_domain
            policy_name = parts[policy_idx + 1] if policy_idx + 1 < len(parts) else file_path.stem
            policy_path = f"/infra/domains/{domain_id}/security-policies/{policy_name}"
        except Exception:
            domain_id = file_domain
    else:
        domain_id = file_domain

    return {
        "policy_id": policy_id,
        "policy_display_name": policy_display_name,
        "policy_path": policy_path,
        "domain_id": domain_id,
        "manager": manager,
    }


def extract_policy_context(obj: Any, *, fallback_context: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    """
    Build a map from id(dict_obj) -> nearest policy-ish metadata.
    """
    context_map: Dict[int, Dict[str, Any]] = {}

    def _walk(node: Any, current_policy: Optional[Dict[str, Any]]) -> None:
        if isinstance(node, dict):
            next_policy = current_policy
            if looks_like_policy(node):
                next_policy = {
                    "policy_id": safe_get_str(node, "id") or fallback_context.get("policy_id"),
                    "policy_display_name": safe_get_str(node, "display_name") or fallback_context.get("policy_display_name"),
                    "policy_path": safe_get_str(node, "path") or fallback_context.get("policy_path"),
                    "domain_id": (
                        find_first_value(node, ("domain_id",))
                        or safe_get_str(node, "domain_id")
                        or fallback_context.get("domain_id")
                    ),
                }

            context_map[id(node)] = next_policy or fallback_context
            for v in node.values():
                _walk(v, next_policy)

        elif isinstance(node, list):
            for item in node:
                _walk(item, current_policy)

    _walk(obj, fallback_context)
    return context_map


def extract_candidate_rules(payload: Any) -> Iterator[Dict[str, Any]]:
    for d in walk_dicts(payload):
        if looks_like_rule(d):
            yield d


def extract_group_ips(payload: Any) -> List[str]:
    """Return all ip_addresses entries from IPAddressExpression blocks in a group payload."""
    ips: Set[str] = set()
    for d in walk_dicts(payload):
        if d.get("resource_type") == "IPAddressExpression":
            for v in d.get("ip_addresses", []) or []:
                if isinstance(v, str) and v.strip():
                    ips.add(v.strip())
    return sorted(ips)


# =============================================================================
# Matching logic
# =============================================================================

def build_alias_index(changed_groups: List[ChangedGroup]) -> Dict[str, List[ChangedGroup]]:
    alias_index: Dict[str, List[ChangedGroup]] = {}
    for grp in changed_groups:
        for alias in grp.aliases:
            alias_index.setdefault(alias, []).append(grp)
    return alias_index


def collect_rule_field_strings(rule: Dict[str, Any]) -> Dict[str, Set[str]]:
    found: Dict[str, Set[str]] = {}

    for field in RULE_REFERENCE_FIELDS:
        if field not in rule:
            continue

        vals: Set[str] = set()
        for s in walk_strings(rule[field]):
            if s.strip():
                vals.add(s.strip())

        if vals:
            found[field] = vals

    all_strings = {s.strip() for s in walk_strings(rule) if isinstance(s, str) and s.strip()}
    if all_strings:
        found["_all_strings"] = all_strings

    return found


def find_rule_matches(
    rule: Dict[str, Any],
    alias_index: Dict[str, List[ChangedGroup]],
) -> Tuple[Set[ChangedGroup], Set[str], Set[str]]:
    matched_groups: Set[ChangedGroup] = set()
    matched_values: Set[str] = set()
    matched_fields: Set[str] = set()

    field_values = collect_rule_field_strings(rule)

    for field, values in field_values.items():
        for value in values:
            groups = alias_index.get(value)
            if groups:
                matched_groups.update(groups)
                matched_values.add(value)
                matched_fields.add(field)

    return matched_groups, matched_values, matched_fields


def group_ref_from_changed_group(grp: ChangedGroup) -> Dict[str, Any]:
    return asdict(
        AffectedGroupRef(
            manager=grp.manager,
            domain_id=grp.domain_id,
            group_id=grp.group_id,
            display_name=grp.display_name,
            group_path=grp.group_path,
            file_path=grp.file_path,
        )
    )


# =============================================================================
# Impact report builder
# =============================================================================

def build_impact_report(
    sorted_rule_list: List[AffectedRule],
    group_ips: Dict[str, List[str]],
) -> List[Dict[str, Any]]:
    """
    Build a clean, human-readable impact report keyed by rule name.
    For each affected rule: rule name, policy name, and for each group the
    display name + the subnets/IPs that are changing in that group.
    Intended for post-change troubleshooting — "is this issue related to the migration?"
    """
    out: List[Dict[str, Any]] = []
    for rule in sorted_rule_list:
        groups = []
        for g in rule.affected_groups:
            groups.append({
                "group_name": g["display_name"] or g["group_id"],
                "group_id": g["group_id"],
                "manager": g["manager"],
                "domain_id": g["domain_id"],
                "subnets_added": group_ips.get(g["group_id"], []),
            })
        out.append({
            "rule_name": rule.rule_display_name or rule.rule_id,
            "rule_id": rule.rule_id,
            "policy_name": rule.policy_display_name or rule.policy_id,
            "policy_id": rule.policy_id,
            "manager": rule.manager,
            "domain_id": rule.domain_id,
            "affected_groups": groups,
        })
    return out


# =============================================================================
# Main analysis
# =============================================================================

def analyze(
    additive_root: Path,
    export_root: Path,
    output_dir: Path,
    logger: logging.Logger,
    *,
    federation_global: bool,
) -> int:
    if not additive_root.exists():
        logger.error("Additive root does not exist: %s", additive_root)
        return 2

    if not export_root.exists():
        logger.error("Export root does not exist: %s", export_root)
        return 2

    changed_groups = discover_changed_groups(
        additive_root,
        logger,
        federation_global=federation_global,
    )
    if not changed_groups:
        logger.warning("No changed groups found under %s", additive_root)

    # For each changed group, compute only the IPs that were added (additive - original).
    # This is what gets shown in the impact report so reviewers see exactly what changed.
    group_ips: Dict[str, List[str]] = {}
    for grp in changed_groups:
        try:
            additive_payload = load_structured_file(Path(grp.file_path))
            additive_ips = set(extract_group_ips(additive_payload))

            rel = Path(grp.file_path).relative_to(additive_root)
            export_file = export_root / rel
            if export_file.exists():
                export_payload = load_structured_file(export_file)
                original_ips = set(extract_group_ips(export_payload))
            else:
                original_ips = set()

            group_ips[grp.group_id] = sorted(additive_ips - original_ips)
        except Exception as e:
            logger.warning("Could not compute IP diff for group %s: %s", grp.file_path, e)
            group_ips[grp.group_id] = []

    alias_index = build_alias_index(changed_groups)

    affected_rules: Dict[Tuple[str, str], AffectedRule] = {}
    policy_rollup: Dict[Tuple[str, str], Dict[str, Any]] = {}

    export_files = list(iter_structured_files(export_root))
    logger.info("Scanning %d structured file(s) under %s", len(export_files), export_root)

    for file_path in export_files:
        try:
            payload = load_structured_file(file_path)
        except Exception as e:
            logger.warning("Skipping unreadable export file %s: %s", file_path, e)
            continue

        manager = get_manager_from_relative_path(export_root, file_path) or "unknown-manager"
        file_domain = get_domain_from_relative_path(export_root, file_path)

        fallback_context = build_fallback_policy_context(file_path, manager, file_domain)
        policy_context = extract_policy_context(payload, fallback_context=fallback_context)

        for rule in extract_candidate_rules(payload):
            rule_id = safe_get_str(rule, "id")
            if not rule_id:
                continue

            matched_groups, matched_values, matched_fields = find_rule_matches(rule, alias_index)
            if not matched_groups:
                continue

            ctx = policy_context.get(id(rule), fallback_context)
            policy_id = ctx.get("policy_id") or fallback_context["policy_id"]
            policy_display_name = ctx.get("policy_display_name") or fallback_context["policy_display_name"]
            policy_path = ctx.get("policy_path") or fallback_context.get("policy_path")
            domain_id = ctx.get("domain_id") or file_domain

            rule_display_name = safe_get_str(rule, "display_name")
            rule_name_or_id = rule_display_name or rule_id
            sorted_group_refs = tuple(
                sorted(
                    (group_ref_from_changed_group(g) for g in matched_groups),
                    key=lambda x: (x["manager"], x["domain_id"], x["group_id"]),
                )
            )

            rule_key = (str(file_path), rule_id)

            affected_rules[rule_key] = AffectedRule(
                manager=manager,
                domain_id=domain_id,
                policy_id=policy_id,
                policy_display_name=policy_display_name,
                policy_path=policy_path,
                rule_id=rule_id,
                rule_display_name=rule_display_name,
                rule_name_or_id=rule_name_or_id,
                rule_path=safe_get_str(rule, "path"),
                rule_file=str(file_path),
                affected_group_ids=unique_sorted(g.group_id for g in matched_groups),
                affected_groups=sorted_group_refs,
                matched_reference_values=unique_sorted(matched_values),
                match_fields=unique_sorted(matched_fields),
            )

            pol_key = (str(file_path), policy_id or file_path.stem)
            entry = policy_rollup.setdefault(
                pol_key,
                {
                    "manager": manager,
                    "domain_id": domain_id,
                    "policy_id": policy_id or file_path.stem,
                    "policy_display_name": policy_display_name,
                    "policy_path": policy_path,
                    "source_file": str(file_path),
                    "affected_rule_ids": set(),
                    "affected_rule_names_or_ids": set(),
                    "changed_groups": set(),
                    "affected_groups": {},
                },
            )

            entry["affected_rule_ids"].add(rule_id)
            entry["affected_rule_names_or_ids"].add(rule_name_or_id)

            for g in matched_groups:
                entry["changed_groups"].add(g.group_id)
                entry["affected_groups"][g.group_id] = group_ref_from_changed_group(g)

    affected_policies: List[AffectedPolicy] = []
    for entry in policy_rollup.values():
        policy_id = entry["policy_id"]
        policy_display_name = entry["policy_display_name"]
        policy_name_or_id = policy_display_name or policy_id
        affected_group_refs = tuple(
            sorted(
                entry["affected_groups"].values(),
                key=lambda x: (x["manager"], x["domain_id"], x["group_id"]),
            )
        )

        affected_policies.append(
            AffectedPolicy(
                manager=entry["manager"],
                domain_id=entry["domain_id"],
                policy_id=policy_id,
                policy_display_name=policy_display_name,
                policy_name_or_id=policy_name_or_id,
                policy_path=entry["policy_path"],
                source_file=entry["source_file"],
                affected_rule_ids=unique_sorted(entry["affected_rule_ids"]),
                affected_rule_names_or_ids=unique_sorted(entry["affected_rule_names_or_ids"]),
                changed_groups=unique_sorted(entry["changed_groups"]),
                affected_groups=affected_group_refs,
            )
        )

    sorted_rule_list = sorted_rules(affected_rules.values())
    impact_report = build_impact_report(sorted_rule_list, group_ips)

    write_jsonl(output_dir / "changed_groups.jsonl", [asdict(g) for g in changed_groups])
    write_jsonl(output_dir / "affected_rules.jsonl", [asdict(r) for r in sorted_rule_list])
    write_jsonl(output_dir / "affected_policies.jsonl", [asdict(p) for p in sorted_policies(affected_policies)])
    write_json(output_dir / "affected_rules.json", [asdict(r) for r in sorted_rule_list])
    write_json(output_dir / "affected_rules_impact.json", impact_report, sort_keys=False)

    logger.info("Changed groups:    %d", len(changed_groups))
    logger.info("Affected rules:    %d", len(affected_rules))
    logger.info("Affected policies: %d", len(affected_policies))
    logger.info("Wrote reports to %s", output_dir)

    print("")
    print("Analysis complete")
    print(f"  Changed groups:    {len(changed_groups)}")
    print(f"  Affected rules:    {len(affected_rules)}")
    print(f"  Affected policies: {len(affected_policies)}")
    print(f"  Federation global: {federation_global}")
    print(f"  Output dir:        {output_dir}")
    print("")
    print("Files written:")
    print(f"  - {output_dir / 'changed_groups.jsonl'}")
    print(f"  - {output_dir / 'affected_rules.jsonl'}")
    print(f"  - {output_dir / 'affected_policies.jsonl'}")
    print(f"  - {output_dir / 'affected_rules.json'}")
    print(f"  - {output_dir / 'affected_rules_impact.json'}  <-- human-readable: rule -> groups -> subnets")
    print("")

    return 0


# =============================================================================
# Output helpers
# =============================================================================

def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path: Path, rows: List[Dict[str, Any]], *, sort_keys: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, indent=2, ensure_ascii=False, sort_keys=sort_keys), encoding="utf-8")


def sorted_rules(rules: Iterable[AffectedRule]) -> List[AffectedRule]:
    return sorted(
        rules,
        key=lambda r: (
            r.manager,
            r.domain_id or "",
            r.policy_id or "",
            r.rule_name_or_id,
            r.rule_id,
            r.rule_file,
        ),
    )


def sorted_policies(policies: Iterable[AffectedPolicy]) -> List[AffectedPolicy]:
    return sorted(
        policies,
        key=lambda p: (
            p.manager,
            p.domain_id or "",
            p.policy_name_or_id,
            p.policy_id,
            p.source_file,
        ),
    )


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze nsx_groups_additive and list all exported rules/policies "
            "affected by changed groups."
        )
    )
    parser.add_argument(
        "--additive-root",
        default=DEFAULT_ADDITIVE_ROOT,
        help=f"Path to additive group tree (default: {DEFAULT_ADDITIVE_ROOT})",
    )
    parser.add_argument(
        "--export-root",
        default=DEFAULT_EXPORT_ROOT,
        help=f"Path to exported NSX object tree (default: {DEFAULT_EXPORT_ROOT})",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory for JSONL output (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--federation-global",
        action="store_true",
        help="Treat the run as federation-global aware (/global-infra).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    additive_root = Path(args.additive_root).expanduser().resolve()
    export_root = Path(args.export_root).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()

    logger = setup_logging(output_dir=output_dir, verbose=args.verbose)
    logger.info("Additive root:      %s", additive_root)
    logger.info("Export root:        %s", export_root)
    logger.info("Output dir:         %s", output_dir)
    logger.info("Federation global:  %s", args.federation_global)

    return analyze(
        additive_root=additive_root,
        export_root=export_root,
        output_dir=output_dir,
        logger=logger,
        federation_global=args.federation_global,
    )


if __name__ == "__main__":
    raise SystemExit(main())