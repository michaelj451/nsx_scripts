#!/usr/bin/env python3
"""
tools/nsx/promote_local_groups.py

PROMOTE ONLY: Promote NSX Local Manager (LM-domain) groups into Global Manager (GM) shared domain
by creating duplicates with a suffix appended.

Default behavior (updated):
- Reads groups from: nsx_export_promote/<gm-host>/domains/<imported-lm1-host>/groups
  (i.e., by default it reads from the LM1 domain imported into GM)
- With --all-lm-domains, reads from ALL LM domains under:
    nsx_export_promote/<gm-host>/domains/<lm-domain>/groups
- Writes promoted group YAMLs to:
    nsx_promoted_groups/<gm-host>/domains/<dst-domain>/groups

Logging:
- JSONL event log (one per promoted group):
    <NSX_LOG_DIR>/nsx_group_promotion_changes.jsonl
- Pretty combined JSON:
    <NSX_LOG_DIR>/nsx_group_promotion_changes.pretty.json
- Pretty per-group:
    <NSX_LOG_DIR>/group_promotions/<safe_display_name>.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from nsx.nsx_constants import (
    nsx_gm1,
    nsx_gm2,
    nsx_lm1,
    nsx_lm2,
    nsx_lm3,
    nsx_lm4,
    object_appendix,
    nsx_log_dir,
)

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e

log = logging.getLogger("promote_local_groups")

REPO_ROOT = Path(__file__).resolve().parents[2]

# -----------------------------------------------------------------------------
# Defaults (UPDATED)
# -----------------------------------------------------------------------------

DEFAULT_GM_NAME = nsx_gm1                      # e.g. "nsx-gm1.lab.local" (dir name)
DEFAULT_IMPORTED_LM1_DOMAIN = nsx_lm2          # e.g. "nsx-lm1.lab.local" (imported LM1 domain on GM)

DEFAULT_DST_DOMAIN = "default"
DEFAULT_SUFFIX = object_appendix

# NEW: promotion input base directory
DEFAULT_PROMOTE_SOURCE_BASE = REPO_ROOT / "nsx_export_promote"

# Reads from: nsx_export_promote/<gm>/domains/<imported-lm1>/groups
DEFAULT_GROUPS_ROOT = DEFAULT_PROMOTE_SOURCE_BASE / DEFAULT_GM_NAME / "domains"
DEFAULT_GROUPS_DIR = DEFAULT_GROUPS_ROOT / DEFAULT_IMPORTED_LM1_DOMAIN / "groups"

# Writes to: nsx_promoted_groups/<gm>/domains/<dst>/groups
DEFAULT_GM_OUT_DIR = REPO_ROOT / "nsx_promoted_groups" / DEFAULT_GM_NAME / "domains" / DEFAULT_DST_DOMAIN / "groups"

DEFAULT_LM_DOMAINS = [
    nsx_lm1,
    nsx_lm2,
    nsx_lm3,
    nsx_lm4,
]


# -----------------------------
# Logging dir resolver
# -----------------------------

def _resolve_log_dir() -> Path:
    """
    nsx_log_dir should be an absolute path after your env fix.
    Still expandvars/expanduser just in case, and always mkdir.
    """
    if not nsx_log_dir:
        p = (REPO_ROOT / "nsx_logs").resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p

    expanded = os.path.expandvars(os.path.expanduser(str(nsx_log_dir)))
    p = Path(expanded).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


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
    name = (name or "").strip()
    name = re.sub(r"[\\/:\*\?\"<>\|\n\r\t]+", "_", name)
    name = re.sub(r"\s+", " ", name).strip()
    name = name.replace(" ", "_")
    name = re.sub(r"_+", "_", name).strip("_")
    if not name:
        name = "unnamed"
    return name[:max_len] if len(name) > max_len else name

def write_jsonl_record(fh, record: Dict[str, Any]) -> None:
    fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    fh.flush()


# -----------------------------
# Group detection / extraction
# -----------------------------

def is_group_payload(doc: Any) -> bool:
    # Tolerant: if it has an id, treat as a group (we already read from /groups/)
    return isinstance(doc, dict) and isinstance(doc.get("id"), str) and doc["id"].strip() != ""

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


# -----------------------------
# Group getters / promotion
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
    return p if isinstance(p, str) and p.strip() else None

def build_gm_group_path(domain: str, group_id: str) -> str:
    return f"/global-infra/domains/{domain}/groups/{group_id}"


@dataclass(frozen=True)
class Promotion:
    old_id: str
    old_name: str
    old_path: Optional[str]
    old_domain: str
    new_id: str
    new_name: str
    new_path: str
    source_file: str


def promote_group_payload(
    g: Dict[str, Any],
    *,
    src_domain: str,
    suffix: str,
    dst_domain: str,
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
        old_domain=src_domain,
        new_id=new_id,
        new_name=new_name,
        new_path=new_path,
        source_file="",
    )
    return new_group, promo


# -----------------------------
# Main
# -----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Promote LM-domain groups to shared GM domain (promote-only).")

    ap.add_argument("--gm-name", type=str, default=DEFAULT_GM_NAME,
                    help="GM directory name (default: env NSX_GM1 value)")
    ap.add_argument("--imported-lm1", type=str, default=DEFAULT_IMPORTED_LM1_DOMAIN,
                    help="Imported LM1 domain name on GM (default: env NSX_LM1 value)")

    ap.add_argument("--dst-domain", type=str, default=DEFAULT_DST_DOMAIN,
                    help="Destination domain (default: default)")

    ap.add_argument("--promote-source-base", type=Path, default=DEFAULT_PROMOTE_SOURCE_BASE,
                    help="Base directory holding exported domains for promotion (default: ./nsx_export_promote)")

    ap.add_argument("--groups-root", type=Path, default=None,
                    help="Override full groups root (the directory that contains 'domains/<domain>/groups'). "
                         "If unset, computed from --promote-source-base and --gm-name.")

    ap.add_argument("--all-lm-domains", action="store_true",
                    help="Promote from ALL LM domains under groups-root (lm1..lm4).")

    ap.add_argument("--lm-domains", nargs="*", default=DEFAULT_LM_DOMAINS,
                    help="Which LM domain directory names to include when using --all-lm-domains "
                         "(default: env NSX_LM1..4 values).")

    ap.add_argument("--gm-out-dir", type=Path, default=None,
                    help="Override output dir for promoted group YAMLs.")

    ap.add_argument("--suffix", type=str, default=DEFAULT_SUFFIX,
                    help="Suffix appended to new group id/display_name.")

    ap.add_argument("--skip-already-promoted", action="store_true", default=True,
                    help="Skip groups whose id/display_name already ends with suffix (default: True).")

    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--log-level", type=str, default="INFO")

    args = ap.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    gm_name: str = args.gm_name
    imported_lm1: str = args.imported_lm1
    dst_domain: str = args.dst_domain
    suffix: str = args.suffix

    promote_source_base: Path = args.promote_source_base
    groups_root: Path = args.groups_root or (promote_source_base / gm_name / "domains")

    gm_out = args.gm_out_dir or (REPO_ROOT / "nsx_promoted_groups" / gm_name / "domains" / dst_domain / "groups")

    # Log dir + files
    log_dir = _resolve_log_dir()
    changes_jsonl = log_dir / "nsx_group_promotion_changes.jsonl"
    changes_pretty = log_dir / "nsx_group_promotion_changes.pretty.json"
    group_log_dir = log_dir / "group_promotions"

    log.info("Promote source base: %s", promote_source_base.resolve())
    log.info("Groups root:         %s", groups_root.resolve())
    log.info("Imported LM1 domain: %s", imported_lm1)
    log.info("All LM domains:      %s", args.all_lm_domains)
    log.info("LM domain allowlist: %s", [d for d in args.lm_domains if d])
    log.info("Destination domain:  %s", dst_domain)
    log.info("Output dir:          %s", gm_out.resolve())
    log.info("Suffix:              %s", suffix)
    log.info("Log dir:             %s", log_dir.resolve())

    if not groups_root.exists():
        raise SystemExit(f"Groups root does not exist: {groups_root}")

    # Determine which domain/group dirs to read
    groups_in_dirs: List[Tuple[str, Path]] = []
    lm_allow = {d for d in args.lm_domains if isinstance(d, str) and d.strip()}

    if args.all_lm_domains:
        for domain_dir in sorted(groups_root.iterdir()):
            if not domain_dir.is_dir():
                continue
            domain_name = domain_dir.name

            # Only LM domains
            if lm_allow and domain_name not in lm_allow:
                continue

            # Never promote from destination domain
            if domain_name == dst_domain:
                continue

            groups_in_dirs.append((domain_name, domain_dir / "groups"))
    else:
        # Default behavior: read from imported LM1 groups only
        groups_in_dirs = [(imported_lm1, groups_root / imported_lm1 / "groups")]

    existing = [(d, g) for (d, g) in groups_in_dirs if g.exists()]
    if not existing:
        raise SystemExit("No groups input directories found. Check groups_root/imported_lm1/lm-domains.")

    log.info("Input group dirs found: %d", len(existing))
    for d, g in existing:
        log.info("  - %s: %s", d, g.resolve())

    # Ensure output dirs
    gm_out.mkdir(parents=True, exist_ok=True)
    group_log_dir.mkdir(parents=True, exist_ok=True)
    changes_jsonl.parent.mkdir(parents=True, exist_ok=True)

    scanned_files = 0
    parsed_groups = 0
    promoted_count = 0
    skipped_unreadable = 0
    skipped_no_groups_in_file = 0
    skipped_already_promoted = 0

    promoted_groups: List[Tuple[Path, Dict[str, Any], Promotion]] = []
    all_records: List[Dict[str, Any]] = []

    changes_fh = None
    if not args.dry_run:
        changes_fh = changes_jsonl.open("w", encoding="utf-8")

    for domain_name, groups_in_dir in existing:
        for f in iter_docs(groups_in_dir):
            scanned_files += 1
            try:
                doc = load_doc(f)
            except Exception as e:
                skipped_unreadable += 1
                log.warning("Skip unreadable file %s: %s", f, e)
                continue

            group_docs = extract_group_payloads(doc)
            if not group_docs:
                skipped_no_groups_in_file += 1
                continue

            for gdoc in group_docs:
                parsed_groups += 1
                old_id = get_group_id(gdoc)
                old_name = get_group_name(gdoc)

                if args.skip_already_promoted and (old_id.endswith(suffix) or old_name.endswith(suffix)):
                    skipped_already_promoted += 1
                    log.info("SKIP already promoted: id=%s domain=%s file=%s", old_id, domain_name, f)
                    continue

                new_group, promo0 = promote_group_payload(
                    gdoc,
                    src_domain=domain_name,
                    suffix=suffix,
                    dst_domain=dst_domain,
                )

                promo = Promotion(
                    old_id=promo0.old_id,
                    old_name=promo0.old_name,
                    old_path=promo0.old_path,
                    old_domain=domain_name,
                    new_id=promo0.new_id,
                    new_name=promo0.new_name,
                    new_path=promo0.new_path,
                    source_file=str(f),
                )

                base = safe_filename(promo.new_name)
                out_file = gm_out / f"{base}.yaml"
                if any(out_file == p for (p, _, _) in promoted_groups):
                    out_file = gm_out / f"{base}__{promo.new_id}.yaml"

                promoted_groups.append((out_file, new_group, promo))

    log.info("Scanned files:               %d", scanned_files)
    log.info("Parsed group payloads:       %d", parsed_groups)
    log.info("Promotions to write:         %d", len(promoted_groups))
    log.info("Skipped unreadable files:    %d", skipped_unreadable)
    log.info("Skipped (no groups in file): %d", skipped_no_groups_in_file)
    log.info("Skipped already promoted:    %d", skipped_already_promoted)

    if args.dry_run:
        log.info("Dry-run: not writing outputs.")
        return

    for out_file, new_group, promo in promoted_groups:
        write_yaml(out_file, new_group)
        promoted_count += 1

        rec = {
            "type": "group_promotion",
            "gm_name": gm_name,
            "src_domain": promo.old_domain,
            "dst_domain": dst_domain,
            "source_file": promo.source_file,
            "out_file": str(out_file),
            "promotion": {
                "old_id": promo.old_id,
                "old_name": promo.old_name,
                "old_path": promo.old_path,
                "old_domain": promo.old_domain,
                "new_id": promo.new_id,
                "new_name": promo.new_name,
                "new_path": promo.new_path,
            },
        }
        all_records.append(rec)

        if changes_fh:
            write_jsonl_record(changes_fh, rec)

        pretty_group_path = group_log_dir / f"{safe_filename(promo.new_name)}.json"
        write_json(pretty_group_path, rec, indent=2)

    if changes_fh:
        changes_fh.close()

    write_json(changes_pretty, all_records, indent=2)

    log.info("Wrote promoted group files: %d", promoted_count)
    log.info("Change log (jsonl):         %s", changes_jsonl)
    log.info("Change log (pretty):        %s", changes_pretty)
    log.info("Per-group logs:             %s", group_log_dir)


if __name__ == "__main__":
    main()