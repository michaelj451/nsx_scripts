#!/usr/bin/env python3
# app/nsx/nsx_object_functions/nsx_group_remap.py
from __future__ import annotations

import csv
import ipaddress
import json
import re
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Tuple, Iterable

try:
    import yaml  # PyYAML
except ImportError as e:
    raise SystemExit("Missing dependency: PyYAML. Install with: pip install pyyaml") from e


# =============================================================================
# Logging
# =============================================================================

LOG_DIR_NAME = "nsx_logs"
LOG_FILE_NAME = "nsx_group_remap.log"
CHANGES_FILE_NAME = "nsx_group_remap_changes.jsonl"


def setup_logging() -> logging.Logger:
    repo_root = Path(__file__).resolve().parents[3]  # .../app/nsx/nsx_object_functions -> repo root
    log_dir = repo_root / LOG_DIR_NAME
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / LOG_FILE_NAME

    logger = logging.getLogger("nsx_group_remap")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)

    logger.info("Log file: %s", log_file)
    return logger


logger = setup_logging()


def _changes_path() -> Path:
    repo_root = Path(__file__).resolve().parents[3]
    p = repo_root / LOG_DIR_NAME / CHANGES_FILE_NAME
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _write_change_record(record: dict) -> None:
    p = _changes_path()
    record = dict(record)
    record.setdefault("ts", datetime.utcnow().isoformat() + "Z")
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _log_ip_list_changes(group_id: str, expr_id: str, before: list[str], after: list[str]) -> None:
    removed = [x for x in before if x not in after]
    added = [x for x in after if x not in before]
    if not removed and not added:
        return

    logger.info("Group %s expr %s ip_addresses changed: -%d +%d", group_id, expr_id, len(removed), len(added))
    if removed:
        logger.info("  removed: %s", removed)
    if added:
        logger.info("  added: %s", added)

    for token in removed:
        _write_change_record({
            "kind": _classify_token(token),
            "action": "removed",
            "value": token,
            "group_id": group_id,
            "expr_id": expr_id,
        })

    for token in added:
        _write_change_record({
            "kind": _classify_token(token),
            "action": "added",
            "value": token,
            "group_id": group_id,
            "expr_id": expr_id,
        })


# =============================================================================
# CSV mapping model
# =============================================================================

@dataclass(frozen=True)
class SubnetMap:
    old: ipaddress._BaseNetwork
    new: ipaddress._BaseNetwork

def read_csv_mappings(csv_path: Path) -> list[SubnetMap]:
    required = {"old_subnet", "new_subnet"}
    maps: list[SubnetMap] = []

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit("CSV has no headers.")

        missing = required - set(h.strip() for h in reader.fieldnames)
        if missing:
            raise SystemExit(f"CSV missing required headers: {sorted(missing)}")

        for row in reader:
            old_s = (row.get("old_subnet") or "").strip()
            new_s = (row.get("new_subnet") or "").strip()
            if not old_s or not new_s:
                continue

            old_net = ipaddress.ip_network(old_s, strict=False)
            new_net = ipaddress.ip_network(new_s, strict=False)

            if old_net.version != new_net.version:
                raise SystemExit(f"IP version mismatch: {old_net} -> {new_net}")

            maps.append(
                SubnetMap(
                    old=old_net,
                    new=new_net
                )
            )

    maps.sort(key=lambda m: (m.old.version, -m.old.prefixlen))
    logger.info("Loaded %d subnet mappings from %s", len(maps), csv_path)
    return maps


# =============================================================================
# YAML / JSON IO
# =============================================================================

def load_doc(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    if path.suffix.lower() in {".yml", ".yaml"}:
        return yaml.safe_load(text)
    raise SystemExit(f"Unsupported input extension: {path.suffix}")


def write_output(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(obj, indent=2), encoding="utf-8")
        return
    if path.suffix.lower() in {".yml", ".yaml"}:
        path.write_text(yaml.safe_dump(obj, sort_keys=False), encoding="utf-8")
        return
    raise SystemExit(f"Unsupported output extension: {path.suffix}")


# =============================================================================
# Group document shape handling
# =============================================================================

def find_groups_container(doc: Any) -> Tuple[Any, list[dict]]:
    def looks_like_group(g: dict) -> bool:
        return bool(set(g) & {"display_name", "name", "expression", "id", "path"})

    if isinstance(doc, list) and all(isinstance(x, dict) for x in doc):
        return doc, doc

    if isinstance(doc, dict):
        if looks_like_group(doc):
            return doc, [doc]

        for key in ("results", "groups", "items", "data", "resources", "children"):
            if isinstance(doc.get(key), list) and all(isinstance(x, dict) for x in doc[key]):
                return doc, doc[key]

        for v in doc.values():
            if isinstance(v, dict) and isinstance(v.get("groups"), list):
                return v, v["groups"]

        if all(isinstance(v, dict) for v in doc.values()):
            values = list(doc.values())
            if any(looks_like_group(v) for v in values):
                return doc, values

    raise SystemExit("Unrecognized group document shape")


def append_new_to_group_name(group: dict[str, Any], group_name_append: str) -> None:
    if "display_name" in group:
        group["display_name"] = f"{group['display_name']}{group_name_append}"
    elif "name" in group:
        group["name"] = f"{group['name']}{group_name_append}"


# =============================================================================
# Path / identity helpers
# =============================================================================

def derive_new_group_path(new_domain_path: str, new_group_id: str) -> str:
    return f"{new_domain_path.rstrip('/')}/groups/{new_group_id}"


def apply_new_identity(group: dict, new_group_id: str, new_domain_path: str) -> None:
    group["_source_id"] = group.get("id")
    group["_source_path"] = group.get("path")

    group["id"] = new_group_id
    group["relative_path"] = new_group_id

    group["parent_path"] = new_domain_path
    group["path"] = derive_new_group_path(new_domain_path, new_group_id)


def rebuild_expression_paths(expr: dict, new_group_path: str) -> None:
    expr_id = expr.get("id") or expr.get("relative_path")
    if not expr_id:
        raise SystemExit("Expression missing id / relative_path")

    expr["parent_path"] = new_group_path
    expr["relative_path"] = expr_id

    rt = expr.get("resource_type", "")
    segment = "expressions"
    if rt == "IPAddressExpression":
        segment = "ip-address-expressions"

    expr["path"] = f"{new_group_path}/{segment}/{expr_id}"


# =============================================================================
# IP / CIDR / Range remapping
# =============================================================================

_RANGE_RE = re.compile(r"^\s*([0-9a-fA-F\.:]+)\s*-\s*([0-9a-fA-F\.:]+)\s*$")


def _classify_token(s: str) -> str:
    """Return 'ip_range', 'subnet', or 'ip_address' for a token.

      - Contains '-'              => ip_range  (e.g. 10.1.0.1-10.1.0.10)
      - CIDR with prefix < /32   => subnet     (e.g. 10.1.0.0/24)
      - /32, bare IP, or fallback => ip_address (e.g. 10.1.2.3/32, 10.1.2.3)
    """
    if _RANGE_RE.match(s):
        return "ip_range"
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
            if net.prefixlen < net.max_prefixlen:
                return "subnet"
        except ValueError:
            pass
    return "ip_address"


def looks_like_ip_token(s: str) -> bool:
    if not s:
        return False
    if _RANGE_RE.match(s):
        return True
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def _find_mapping_for_ip(ip: ipaddress._BaseAddress, maps: list[SubnetMap]) -> Optional[SubnetMap]:
    for m in maps:
        if ip.version == m.old.version and ip in m.old:
            return m
    return None


def _remap_ip(ip: ipaddress._BaseAddress, m: SubnetMap) -> ipaddress._BaseAddress:
    offset = int(ip) - int(m.old.network_address)
    return ipaddress.ip_address(int(m.new.network_address) + offset)


def remap_token(token: str, maps: list[SubnetMap]) -> str:
    token = str(token).strip()
    if not token:
        return token

    mrange = _RANGE_RE.match(token)
    if mrange:
        a = ipaddress.ip_address(mrange.group(1))
        b = ipaddress.ip_address(mrange.group(2))
        ma = _find_mapping_for_ip(a, maps)
        mb = _find_mapping_for_ip(b, maps)
        if ma and mb and ma.old == mb.old:
            return f"{_remap_ip(a, ma)}-{_remap_ip(b, ma)}"
        return token

    try:
        net = ipaddress.ip_network(token, strict=False)
        for m in maps:
            if net == m.old:
                return str(m.new)
            if net.subnet_of(m.old):
                offset = int(net.network_address) - int(m.old.network_address)
                new_base = ipaddress.ip_address(int(m.new.network_address) + offset)
                return str(ipaddress.ip_network(f"{new_base}/{net.prefixlen}", strict=False))
        return token
    except ValueError:
        pass

    try:
        ip = ipaddress.ip_address(token)
        m = _find_mapping_for_ip(ip, maps)
        if not m:
            return token
        return str(_remap_ip(ip, m))
    except ValueError:
        return token


def remap_ip_addresses_new_only(tokens: Iterable[Any], maps: list[SubnetMap]) -> tuple[list[str], int]:
    """
    NEW-ONLY mode:
      - If token maps => keep the mapped value
      - If token doesn't map => drop it
    Returns (new_tokens, changed_count)
    """
    out: list[str] = []
    changes = 0

    for t in tokens:
        s = str(t).strip()
        if not s:
            continue
        if not looks_like_ip_token(s):
            # ip_addresses should only contain IP-ish tokens; if it doesn't, keep it? safer to drop.
            continue

        new_s = remap_token(s, maps)
        if new_s != s:
            out.append(new_s)
            changes += 1
        else:
            # unchanged means "no mapping found" -> drop
            continue

    return out, changes


# =============================================================================
# Cleanup helpers
# =============================================================================

def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# =============================================================================
# Conversion logic
# =============================================================================

def convert_groups_in_doc(
    doc: Any,
    maps: list[SubnetMap],
    new_domain_path: str,
    group_name_append: str,
) -> tuple[Any, int, int]:
    """
    Creates NEW group docs ONLY when at least one IP token maps.
    For IPAddressExpression.ip_addresses: keep ONLY mapped (new) tokens.
    """
    _, groups = find_groups_container(doc)

    converted: list[dict] = []
    changed_total = 0

    for g in groups:
        if not isinstance(g, dict):
            continue

        # Work on a deep-copied-ish structure via JSON roundtrip (safe for dict/list/scalars)
        new_g = json.loads(json.dumps(g))
        group_changed = 0

        # Only mutate IPAddressExpression.ip_addresses (not arbitrary strings elsewhere)
        for expr in new_g.get("expression", []) or []:
            if not isinstance(expr, dict):
                continue
            if expr.get("resource_type") != "IPAddressExpression":
                continue

            ips = expr.get("ip_addresses") or []
            if not isinstance(ips, list) or not ips:
                continue

            before = [str(x).strip() for x in ips if str(x).strip()]
            after, changes = remap_ip_addresses_new_only(before, maps)

            # Dedupe after mapping (common when ranges/cidrs overlap)
            after = _dedupe_preserve_order(after)

            # Log before/after (even if it becomes empty)
            _log_ip_list_changes(
                group_id=str(new_g.get("id", "unknown")),
                expr_id=str(expr.get("id", expr.get("relative_path", "unknown"))),
                before=before,
                after=after,
            )

            expr["ip_addresses"] = after
            group_changed += changes

        # If nothing mapped anywhere in this group, DO NOT create a new group.
        if group_changed == 0:
            continue

        old_id = new_g.get("id")
        if not old_id:
            raise SystemExit("Group missing id")

        new_group_id = f"{old_id}{group_name_append}"
        apply_new_identity(new_g, new_group_id, new_domain_path)

        for expr in new_g.get("expression", []) or []:
            if isinstance(expr, dict):
                rebuild_expression_paths(expr, new_g["path"])

        append_new_to_group_name(new_g, group_name_append)

        converted.append(new_g)
        changed_total += group_changed

    # Rebuild output doc shape
    if isinstance(doc, dict) and len(groups) == 1 and groups[0] is doc:
        return (converted[0], 1, changed_total) if converted else (doc, 0, 0)

    if isinstance(doc, list):
        return converted, len(converted), changed_total

    out = dict(doc) if isinstance(doc, dict) else {"results": converted}
    for key in ("results", "groups"):
        if isinstance(out, dict) and key in out:
            out[key] = converted
            return out, len(converted), changed_total

    return converted, len(converted), changed_total

# =============================================================================
# ADDITIVE mapping logic (keep old + add new)
# =============================================================================

def add_mapped_ip_addresses_additive(tokens: Iterable[Any], maps: list[SubnetMap]) -> tuple[list[str], int]:
    """
    ADDITIVE mode:
      - Keep all original IP-ish tokens
      - If a token maps => add the mapped value (if not already present)
      - Never remove anything
    Returns (new_tokens, added_count)
    """
    original: list[str] = []
    for t in tokens:
        s = str(t).strip()
        if not s:
            continue
        # ip_addresses should only contain IP-ish tokens; ignore junk safely
        if not looks_like_ip_token(s):
            continue
        original.append(s)

    # Preserve original order; then append newly derived mapped tokens.
    out = list(original)
    seen = set(original)
    added = 0

    for s in original:
        mapped = remap_token(s, maps)
        if mapped != s and mapped not in seen:
            out.append(mapped)
            seen.add(mapped)
            added += 1

    return out, added


def add_mapped_ips_in_doc(doc: Any, maps: list[SubnetMap]) -> tuple[Any, int, int, list]:
    """
    Mutates group docs in-place (additive):
      - Only modifies IPAddressExpression.ip_addresses
      - Keeps original tokens and appends mapped tokens
    Returns (doc, groups_touched, tokens_added_total, snapshots)
    where snapshots is a list of per-group before/after/added dicts.
    """
    _, groups = find_groups_container(doc)

    groups_touched = 0
    tokens_added_total = 0
    snapshots: list[dict] = []

    for g in groups:
        if not isinstance(g, dict):
            continue

        group_added = 0
        before_all: list[str] = []
        after_all: list[str] = []

        for expr in g.get("expression", []) or []:
            if not isinstance(expr, dict):
                continue
            if expr.get("resource_type") != "IPAddressExpression":
                continue

            ips = expr.get("ip_addresses") or []
            if not isinstance(ips, list) or not ips:
                continue

            before = [str(x).strip() for x in ips if str(x).strip()]
            after, added = add_mapped_ip_addresses_additive(before, maps)
            after = _dedupe_preserve_order(after)

            # Log the delta
            _log_ip_list_changes(
                group_id=str(g.get("id", "unknown")),
                expr_id=str(expr.get("id", expr.get("relative_path", "unknown"))),
                before=before,
                after=after,
            )

            if added > 0:
                expr["ip_addresses"] = after
                group_added += added

            before_all.extend(before)
            after_all.extend(after)

        if group_added > 0:
            groups_touched += 1
            tokens_added_total += group_added

        if before_all or after_all:
            before_set = set(before_all)
            after_set = set(after_all)
            added_ips = [ip for ip in after_all if ip not in before_set]
            removed_ips = [ip for ip in before_all if ip not in after_set]
            snapshots.append({
                "group_id": str(g.get("id", "unknown")),
                "group_display_name": g.get("display_name") or g.get("name"),
                "before": {
                    "ip_count": len(before_all),
                    "ips": [{"value": ip, "type": _classify_token(ip), "status": "pre-existing"} for ip in before_all],
                },
                "after": {
                    "ip_count": len(after_all),
                    "ips": [
                        {"value": ip, "type": _classify_token(ip), "status": "added" if ip not in before_set else "pre-existing"}
                        for ip in after_all
                    ],
                },
                "added": [{"value": ip, "type": _classify_token(ip), "status": "added"} for ip in added_ips],
                "removed": [{"value": ip, "type": _classify_token(ip), "status": "removed"} for ip in removed_ips],
            })

    return doc, groups_touched, tokens_added_total, snapshots


# =============================================================================
# File handling
# =============================================================================

def iter_group_files(nsx_export_dir: Path) -> list[Path]:
    return sorted(
        p for p in nsx_export_dir.rglob("*")
        if p.is_file()
        and p.suffix.lower() in {".yml", ".yaml", ".json"}
        and "/groups/" in p.as_posix().lower()
    )


def out_path_for(in_file: Path, src: Path, dst: Path) -> Path:
    return dst / in_file.relative_to(src)