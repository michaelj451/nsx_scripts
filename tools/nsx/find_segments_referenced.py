#!/usr/bin/env python3
"""
tools/nsx/find_segments_referenced.py

Inventory every NSX segment path referenced by exported groups, rules, and
security policies.

Why this exists:
  When the operator has only DFW access on the target manager, segments
  themselves cannot be created by the clone tooling. Any rule or group on
  the source manager that points at a segment path (e.g.
  /infra/segments/web-tier) requires that same path to already exist on
  the target.

  Groups that reference segments are partially mitigated because the
  live-member-resolution step in Workflow A snapshots resolved VM IPs as a
  static IPAddressExpression. Rules that reference segments directly are
  NOT mitigated.

  This tool produces a list of every segment path your export depends on,
  so the network team can confirm presence on the target before push.

Usage:
  python tools/nsx/find_segments_referenced.py \\
    --export-root nsx_export \\
    --output-dir nsx_logs/segment_inventory \\
    --verbose

Optionally enrich each segment with its live details (subnets, vlan_ids,
transport zone, etc.) by querying the source NSX manager. If you don't have
segment-read permission this call is wrapped in try/except — the tool will
log a warning and still produce the path inventory:

  python tools/nsx/find_segments_referenced.py \\
    --export-root nsx_export \\
    --source-manager nsx-lm1 \\
    --output-dir nsx_logs/segment_inventory \\
    --verbose

Outputs:
  - segments_inventory.json   (full report with per-segment references and
                               optional live details)
  - segment_paths.txt         (flat list, one path per line)
  - segment_details.json      (flat list of fetched segment objects; only
                               written when --source-manager succeeds)
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

try:
    import yaml
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e


DEFAULT_EXPORT_ROOT = "nsx_export"
DEFAULT_OUTPUT_DIR = "nsx_logs/segment_inventory"
LOG_FILE_NAME = "find_segments_referenced.log"

# Matches /infra/segments/<id> and /global-infra/segments/<id> exactly.
# Trailing /ports/... or other sub-resources are treated as the parent segment.
SEGMENT_PATH_RE = re.compile(
    r"^/(?:global-)?infra/segments/[^/\s]+$"
)
SEGMENT_PATH_PREFIX_RE = re.compile(
    r"^(/(?:global-)?infra/segments/[^/\s]+)(?:/.*)?$"
)

GROUP_RESOURCE_TYPES = {"Group"}
RULE_RESOURCE_TYPES = {"Rule"}
POLICY_RESOURCE_TYPE_SUFFIXES = ("Policy",)


# =============================================================================
# Logging
# =============================================================================

def setup_logging(output_dir: Path, verbose: bool = False) -> logging.Logger:
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / LOG_FILE_NAME

    logger = logging.getLogger("find_segments_referenced")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%d %H:%M:%S",
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
# Classification
# =============================================================================

def looks_like_group(d: Dict[str, Any]) -> bool:
    rt = d.get("resource_type")
    if isinstance(rt, str) and rt in GROUP_RESOURCE_TYPES:
        return True
    return False


def looks_like_rule(d: Dict[str, Any]) -> bool:
    rt = d.get("resource_type")
    if isinstance(rt, str):
        if rt in RULE_RESOURCE_TYPES or rt.endswith("Rule"):
            return True
    has_rule_signals = any(
        k in d for k in ("source_groups", "destination_groups", "scope", "action")
    )
    return "id" in d and has_rule_signals


def looks_like_policy(d: Dict[str, Any]) -> bool:
    rt = d.get("resource_type")
    if isinstance(rt, str):
        for suffix in POLICY_RESOURCE_TYPE_SUFFIXES:
            if rt.endswith(suffix):
                return True
    return isinstance(d.get("rules"), list) and "id" in d


# =============================================================================
# Reference collection
# =============================================================================

@dataclass(frozen=True)
class SegmentRef:
    segment_path: str
    owner_type: str           # "group", "rule", "policy", "unknown"
    owner_id: Optional[str]
    owner_display_name: Optional[str]
    parent_policy_id: Optional[str]
    parent_policy_display_name: Optional[str]
    field: str
    source_file: str


def _canonicalize_segment_path(value: str) -> Optional[str]:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    m = SEGMENT_PATH_PREFIX_RE.match(s)
    if not m:
        return None
    return m.group(1)


def walk_for_segment_refs(
    payload: Any,
    file_path: Path,
) -> Iterator[SegmentRef]:
    """
    Walk the payload and yield a SegmentRef for every string that looks like
    a segment path. Track the nearest owning Group/Rule/Policy for context.
    """

    def _walk(
        node: Any,
        current_owner: Optional[Dict[str, Any]],
        current_owner_type: Optional[str],
        current_policy: Optional[Dict[str, Any]],
        field_name: str,
    ) -> Iterator[SegmentRef]:
        if isinstance(node, dict):
            new_owner = current_owner
            new_owner_type = current_owner_type
            new_policy = current_policy

            if looks_like_policy(node):
                new_policy = node
                new_owner = node
                new_owner_type = "policy"
            if looks_like_group(node):
                new_owner = node
                new_owner_type = "group"
            elif looks_like_rule(node):
                new_owner = node
                new_owner_type = "rule"

            for k, v in node.items():
                yield from _walk(v, new_owner, new_owner_type, new_policy, k)

        elif isinstance(node, list):
            for item in node:
                yield from _walk(item, current_owner, current_owner_type, current_policy, field_name)

        elif isinstance(node, str):
            canonical = _canonicalize_segment_path(node)
            if canonical is None:
                return

            owner_id = None
            owner_display = None
            if current_owner is not None:
                owner_id = current_owner.get("id")
                owner_display = current_owner.get("display_name") or current_owner.get("name")

            policy_id = None
            policy_display = None
            if current_policy is not None and current_owner_type == "rule":
                policy_id = current_policy.get("id")
                policy_display = current_policy.get("display_name") or current_policy.get("name")

            yield SegmentRef(
                segment_path=canonical,
                owner_type=current_owner_type or "unknown",
                owner_id=str(owner_id) if owner_id is not None else None,
                owner_display_name=str(owner_display) if owner_display is not None else None,
                parent_policy_id=str(policy_id) if policy_id is not None else None,
                parent_policy_display_name=str(policy_display) if policy_display is not None else None,
                field=field_name,
                source_file=str(file_path),
            )

    yield from _walk(payload, None, None, None, "$")


# =============================================================================
# Report assembly
# =============================================================================

@dataclass
class SegmentSummary:
    segment_path: str
    total_references: int = 0
    referenced_by_groups: int = 0
    referenced_by_rules: int = 0
    referenced_by_policies: int = 0
    referenced_by_unknown: int = 0
    references: List[Dict[str, Any]] = field(default_factory=list)


def aggregate(refs: List[SegmentRef]) -> List[SegmentSummary]:
    by_path: Dict[str, SegmentSummary] = {}

    for ref in refs:
        entry = by_path.setdefault(ref.segment_path, SegmentSummary(segment_path=ref.segment_path))
        entry.total_references += 1
        if ref.owner_type == "group":
            entry.referenced_by_groups += 1
        elif ref.owner_type == "rule":
            entry.referenced_by_rules += 1
        elif ref.owner_type == "policy":
            entry.referenced_by_policies += 1
        else:
            entry.referenced_by_unknown += 1

        entry.references.append({
            "owner_type": ref.owner_type,
            "owner_id": ref.owner_id,
            "owner_display_name": ref.owner_display_name,
            "parent_policy_id": ref.parent_policy_id,
            "parent_policy_display_name": ref.parent_policy_display_name,
            "field": ref.field,
            "source_file": ref.source_file,
        })

    for s in by_path.values():
        s.references.sort(key=lambda r: (r["owner_type"], r["source_file"], str(r.get("owner_id") or "")))

    return sorted(by_path.values(), key=lambda s: s.segment_path)


# =============================================================================
# Main analysis
# =============================================================================

def _fetch_segment_details(
    source_manager: Optional[str],
    federation_global: bool,
    referenced_paths: Set[str],
    logger: logging.Logger,
) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    """
    Try to fetch segment objects from the source manager. Returns
    (segments_by_path, error_message). On any failure (auth, permission,
    network, missing module), returns ({}, "reason") so the caller can
    continue without enrichment.
    """
    if not source_manager:
        return {}, None

    try:
        from nsx.cli_bootstrap import init_cli
        from nsx.nsx_constants import resolve_manager
        from nsx.nsx_policy_client import NsxPolicyClient

        init_cli()
        manager_host = resolve_manager(source_manager)
        if not manager_host:
            return {}, f"Manager not defined for {source_manager}"

        client = NsxPolicyClient(nsxmanager=manager_host, federation_global=federation_global)
        logger.info("Fetching live segment details from %s (federation_global=%s)",
                    manager_host, federation_global)
        all_segments = client.list_segments()

        by_path: Dict[str, Dict[str, Any]] = {}
        for seg in all_segments:
            seg_path = seg.get("path") or seg.get("relative_path")
            if isinstance(seg_path, str):
                by_path[seg_path] = seg
            seg_id = seg.get("id")
            if isinstance(seg_id, str):
                by_path.setdefault(f"/infra/segments/{seg_id}", seg)
                by_path.setdefault(f"/global-infra/segments/{seg_id}", seg)

        logger.info("Fetched %d segment object(s) from %s", len(all_segments), source_manager)

        missing = sorted(p for p in referenced_paths if p not in by_path)
        if missing:
            logger.warning(
                "%d referenced segment path(s) were NOT found on %s — these will "
                "fail when DFW rules referencing them are pushed to a target that "
                "lacks them.",
                len(missing),
                source_manager,
            )
            for m in missing:
                logger.warning("  missing on source: %s", m)

        return by_path, None

    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc}"
        logger.warning(
            "Could not fetch segment details from %s — continuing without "
            "enrichment. Reason: %s",
            source_manager,
            msg,
        )
        return {}, msg


def _extract_segment_detail(seg: Dict[str, Any]) -> Dict[str, Any]:
    """Pull the fields that matter for an operator: subnets, VLANs, TZ, etc."""
    subnets: List[Dict[str, Any]] = []
    for sn in seg.get("subnets", []) or []:
        if isinstance(sn, dict):
            subnets.append({
                "network": sn.get("network"),
                "gateway_address": sn.get("gateway_address"),
                "dhcp_ranges": sn.get("dhcp_ranges"),
            })

    return {
        "id": seg.get("id"),
        "display_name": seg.get("display_name"),
        "path": seg.get("path"),
        "type": seg.get("type"),
        "transport_zone_path": seg.get("transport_zone_path"),
        "connectivity_path": seg.get("connectivity_path"),
        "vlan_ids": seg.get("vlan_ids"),
        "subnets": subnets,
        "domain_name": seg.get("domain_name"),
        "replication_mode": seg.get("replication_mode"),
        "admin_state": seg.get("admin_state"),
        "advanced_config": seg.get("advanced_config"),
    }


def analyze(
    export_root: Path,
    output_dir: Path,
    logger: logging.Logger,
    *,
    source_manager: Optional[str] = None,
    federation_global: bool = False,
) -> int:
    if not export_root.exists():
        logger.error("Export root does not exist: %s", export_root)
        return 2

    output_dir.mkdir(parents=True, exist_ok=True)

    files = list(iter_structured_files(export_root))
    logger.info("Scanning %d structured file(s) under %s", len(files), export_root)

    all_refs: List[SegmentRef] = []
    files_with_refs = 0

    for file_path in files:
        try:
            payload = load_structured_file(file_path)
        except Exception as e:
            logger.warning("Skipping unreadable file %s: %s", file_path, e)
            continue

        file_refs = list(walk_for_segment_refs(payload, file_path))
        if file_refs:
            files_with_refs += 1
            all_refs.extend(file_refs)

    summaries = aggregate(all_refs)

    rules_with_segment_refs = sorted({
        (r.parent_policy_id or "", r.owner_id or "")
        for r in all_refs if r.owner_type == "rule"
    })
    groups_with_segment_refs = sorted({
        r.owner_id or "" for r in all_refs if r.owner_type == "group"
    })

    referenced_paths: Set[str] = {s.segment_path for s in summaries}
    segments_by_path, fetch_error = _fetch_segment_details(
        source_manager=source_manager,
        federation_global=federation_global,
        referenced_paths=referenced_paths,
        logger=logger,
    )

    report = {
        "scan_root": str(export_root),
        "files_scanned": len(files),
        "files_with_segment_refs": files_with_refs,
        "total_segment_references": len(all_refs),
        "unique_segment_paths": len(summaries),
        "unique_rules_with_segment_refs": len(rules_with_segment_refs),
        "unique_groups_with_segment_refs": len(groups_with_segment_refs),
        "source_manager": source_manager,
        "fetch_error": fetch_error,
        "segments_fetched_from_source": len(segments_by_path) if source_manager else None,
        "segments": [
            {
                "segment_path": s.segment_path,
                "total_references": s.total_references,
                "referenced_by_groups": s.referenced_by_groups,
                "referenced_by_rules": s.referenced_by_rules,
                "referenced_by_policies": s.referenced_by_policies,
                "referenced_by_unknown": s.referenced_by_unknown,
                "details": _extract_segment_detail(segments_by_path[s.segment_path])
                    if s.segment_path in segments_by_path else None,
                "found_on_source": s.segment_path in segments_by_path if source_manager else None,
                "references": s.references,
            }
            for s in summaries
        ],
    }

    inventory_path = output_dir / "segments_inventory.json"
    inventory_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    flat_list_path = output_dir / "segment_paths.txt"
    flat_list_path.write_text(
        "\n".join(s.segment_path for s in summaries) + ("\n" if summaries else ""),
        encoding="utf-8",
    )

    details_path: Optional[Path] = None
    if segments_by_path:
        details_path = output_dir / "segment_details.json"
        details_payload = [
            _extract_segment_detail(segments_by_path[p])
            for p in sorted(referenced_paths) if p in segments_by_path
        ]
        details_path.write_text(
            json.dumps(details_payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    logger.info("Files scanned:                  %d", len(files))
    logger.info("Files with segment refs:        %d", files_with_refs)
    logger.info("Total segment references:       %d", len(all_refs))
    logger.info("Unique segment paths:           %d", len(summaries))
    logger.info("Rules with segment refs:        %d", len(rules_with_segment_refs))
    logger.info("Groups with segment refs:       %d", len(groups_with_segment_refs))
    if source_manager:
        if fetch_error:
            logger.warning("Source-manager fetch failed:    %s", fetch_error)
        else:
            logger.info("Segments fetched from source:   %d", len(segments_by_path))
    logger.info("Inventory written:              %s", inventory_path)
    logger.info("Flat segment-path list:         %s", flat_list_path)
    if details_path:
        logger.info("Segment details written:        %s", details_path)

    print("")
    print("Segment inventory complete")
    print(f"  Files scanned:           {len(files)}")
    print(f"  Unique segment paths:    {len(summaries)}")
    print(f"  Total references:        {len(all_refs)}")
    print(f"  Rules referencing segs:  {len(rules_with_segment_refs)}")
    print(f"  Groups referencing segs: {len(groups_with_segment_refs)}")
    if source_manager:
        if fetch_error:
            print(f"  Source fetch:            FAILED ({fetch_error})")
        else:
            print(f"  Source fetch:            OK ({len(segments_by_path)} segments)")
    print("")
    print("Files written:")
    print(f"  - {inventory_path}")
    print(f"  - {flat_list_path}")
    if details_path:
        print(f"  - {details_path}")
    print("")

    return 0


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Inventory every NSX segment path referenced by exported groups, "
            "rules, and security policies. Use this to confirm the target "
            "manager has the same segments before pushing DFW rules."
        )
    )
    parser.add_argument(
        "--export-root",
        default=DEFAULT_EXPORT_ROOT,
        help=f"Path to exported NSX object tree (default: {DEFAULT_EXPORT_ROOT})",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory for output (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--source-manager",
        default=None,
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"],
        help=(
            "Optional: live NSX manager to fetch segment details from "
            "(subnets, VLANs, transport zone, etc.). If the call fails "
            "(no access, network, etc.) the tool still produces the path "
            "inventory."
        ),
    )
    parser.add_argument(
        "--federation-global",
        action="store_true",
        help="Treat --source-manager as a Global Manager (/global-infra).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    export_root = Path(args.export_root).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()

    logger = setup_logging(output_dir=output_dir, verbose=args.verbose)
    logger.info("Export root:        %s", export_root)
    logger.info("Output dir:         %s", output_dir)
    logger.info("Source manager:     %s", args.source_manager or "(none — path inventory only)")
    logger.info("Federation global:  %s", args.federation_global)

    return analyze(
        export_root=export_root,
        output_dir=output_dir,
        logger=logger,
        source_manager=args.source_manager,
        federation_global=args.federation_global,
    )


if __name__ == "__main__":
    raise SystemExit(main())
