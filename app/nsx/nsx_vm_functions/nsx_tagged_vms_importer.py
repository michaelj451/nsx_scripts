# frontendFastapi/nsx/nsx_file_import_functions/nsx_tagged_vms_importer.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
import json
import yaml
import logging

log = logging.getLogger(__name__)

Tag = Dict[str, str]  # {"scope":"...", "tag":"..."}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class VmTagsImportConfig:
    # SOURCE export root (where tagged-vms/tagged_vms__index.yaml lives)
    export_root: Path

    # DEST export root (where vm-inventory/vms.yaml lives)
    dest_inventory_root: Path

    input_format: str = "yaml"          # yaml | json
    dry_run: bool = True
    continue_on_error: bool = True

    # Only allow source rows whose vm_type is in this list (optional)
    accepted_source_vm_types: Optional[Sequence[str]] = None

    # Optional: only apply tags that have a scope prefix (None means no filter)
    only_scope_prefix: Optional[str] = None


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------

def _read_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")


def _load_any(path: Path) -> Any:
    if path.suffix in (".yaml", ".yml"):
        return _read_yaml(path)
    return _read_json(path)


def pick_file(dir_path: Path, base_names: Sequence[str], fmt: str) -> Path:
    if fmt == "yaml":
        exts = (".yaml", ".yml")
    elif fmt == "json":
        exts = (".json",)
    else:
        raise ValueError(f"Unsupported format: {fmt}")

    for bn in base_names:
        for ext in exts:
            p = dir_path / f"{bn}{ext}"
            if p.exists():
                return p

    existing = sorted(p.name for p in dir_path.glob("*") if p.is_file())
    raise FileNotFoundError(
        f"Did not find {base_names} in {dir_path} for format {fmt}. Files present: {existing}"
    )


# ---------------------------------------------------------------------------
# Tag helpers
# ---------------------------------------------------------------------------

def _norm_tag(t: Tag) -> Tuple[str, str]:
    return (str(t.get("scope", "") or ""), str(t.get("tag", "") or ""))


def _dedupe_tags(tags: Sequence[Tag]) -> List[Tag]:
    seen: set[Tuple[str, str]] = set()
    out: List[Tag] = []
    for t in tags or []:
        if not isinstance(t, dict):
            continue
        nt = _norm_tag(t)
        if nt == ("", ""):
            continue
        if nt in seen:
            continue
        out.append({"scope": nt[0], "tag": nt[1]})
        seen.add(nt)
    return out


def _filter_tags(tags: Sequence[Tag], only_scope_prefix: Optional[str]) -> List[Tag]:
    tags = list(tags or [])
    if only_scope_prefix:
        tags = [t for t in tags if str(t.get("scope", "") or "").startswith(only_scope_prefix)]
    return _dedupe_tags(tags)


# ---------------------------------------------------------------------------
# The mapping function (your simplified version)
# ---------------------------------------------------------------------------

def map_dest_name_to_source_name(dest_name: str) -> Optional[str]:
    """
    Convert DEST name -> SOURCE name exactly:
      ubuntu...-10.7.2.101 -> ubuntu...-10.6.2.101
    """
    if not dest_name:
        return None
    marker = "-10.7."
    if marker not in dest_name:
        return None
    return dest_name.replace(marker, "-10.6.", 1)


# ---------------------------------------------------------------------------
# Parse source tags index (tagged_vms_index.yaml)
# ---------------------------------------------------------------------------

def load_source_index_by_name(data: Any, path: Path) -> Dict[str, Dict[str, Any]]:
    """
    Your source tagged_vms_index.yaml is:
      meta: ...
      counts: ...
      vms:
        <external_id>:
          display_name: ...
          tags: [...]
          vm_type: REGULAR|EDGE
    We index by display_name for easy lookup.
    """
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected dict at top level")

    vms = data.get("vms")
    if not isinstance(vms, dict):
        raise ValueError(f"{path}: expected 'vms' to be dict keyed by external_id")

    out: Dict[str, Dict[str, Any]] = {}
    for _, vm in vms.items():
        if not isinstance(vm, dict):
            continue
        name = (vm.get("display_name") or "").strip()
        if not name:
            continue
        out[name] = vm
    return out


# ---------------------------------------------------------------------------
# Parse dest allowlist (vm-inventory/vms.yaml)
# ---------------------------------------------------------------------------

def load_dest_allowlist(data: Any, path: Path) -> List[Dict[str, Any]]:
    """
    Your dest vms.yaml is:
      type: vm-inventory
      vms:
        - display_name: ...
          vm_id: ...
    """
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected dict at top level")

    vms = data.get("vms")
    if not isinstance(vms, list):
        raise ValueError(f"{path}: expected 'vms' to be a list")

    out: List[Dict[str, Any]] = []
    for vm in vms:
        if isinstance(vm, dict):
            out.append(vm)
    return out


# ---------------------------------------------------------------------------
# NSX API write
# ---------------------------------------------------------------------------

def nsx_add_tagged_vms(client: Any, *, vm_external_id: str, tags_to_add: List[Tag]) -> Any:
    """
    POST /api/v1/fabric/virtual-machines?action=add_tags
    payload: {"external_id":"...", "tags":[...]}
    """
    path = "/api/v1/fabric/virtual-machines?action=add_tags"
    payload = {"external_id": vm_external_id, "tags": tags_to_add}
    return client._post(path, payload)


# ---------------------------------------------------------------------------
# Importer (ALLOWLIST-DRIVEN)
# ---------------------------------------------------------------------------

class NsxVmTagsImporter:
    """
    Allowlist-driven tagging:

      - Read SOURCE tags from: <export_root>/tagged-vms/tagged_vms_index.(yaml|json)
      - Read DEST allowlist from: <dest_inventory_root>/vm-inventory/vms.(yaml|json)
      - For each dest VM:
          dest_name -> src_name (map_dest_name_to_source_name)
          find src_name in source index
          apply tags to dest vm_id

    This is the "reverse" you described (10.6 has tags, 10.7 gets them).
    """

    def __init__(self, client: Any, cfg: VmTagsImportConfig):
        self.client = client
        self.cfg = cfg

    def _load_source_by_name(self) -> Dict[str, Dict[str, Any]]:
        tagged_vms_dir = self.cfg.export_root / "tagged-vms"
        src_path = pick_file(tagged_vms_dir, ["tagged_vms_index"], self.cfg.input_format)
        raw = _load_any(src_path)
        idx = load_source_index_by_name(raw, src_path)
        log.info("Loaded %d source VMs (by name) from %s", len(idx), src_path)
        return idx

    def _load_dest_allowlist(self) -> List[Dict[str, Any]]:
        inv_dir = self.cfg.dest_inventory_root / "vm-inventory"
        inv_path = pick_file(inv_dir, ["vms"], self.cfg.input_format)
        raw = _load_any(inv_path)
        vms = load_dest_allowlist(raw, inv_path)
        log.info("Loaded %d dest allowlist VMs from %s", len(vms), inv_path)
        return vms

    def push_tagged_vms(self) -> Dict[str, Any]:
        source_by_name = self._load_source_by_name()
        dest_vms = self._load_dest_allowlist()

        accepted_types = set(self.cfg.accepted_source_vm_types or [])
        type_filter_enabled = bool(accepted_types)

        stats = {
            "dest_allowlist_total": len(dest_vms),
            "processed": 0,
            "updated": 0,
            "skipped": 0,
            "errors": 0,
            "skip_dest_no_id": 0,
            "skip_map_failed": 0,
            "skip_source_not_found": 0,
            "skip_source_type": 0,
            "skip_source_no_tags": 0,
            "would_add": 0,
        }
        errors: List[str] = []
        rows: List[Dict[str, Any]] = []

        for d in dest_vms:
            stats["processed"] += 1

            dest_name = (d.get("display_name") or "").strip()
            dest_id = (d.get("vm_id") or d.get("external_id") or d.get("externalId") or "").strip()

            if not dest_name or not dest_id:
                stats["skipped"] += 1
                stats["skip_dest_no_id"] += 1
                rows.append({"dest_name": dest_name, "reason": "dest_missing_name_or_id"})
                continue

            src_name = map_dest_name_to_source_name(dest_name)
            if not src_name:
                stats["skipped"] += 1
                stats["skip_map_failed"] += 1
                rows.append({"dest_name": dest_name, "reason": "map_failed"})
                continue

            src_vm = source_by_name.get(src_name)
            if not src_vm:
                stats["skipped"] += 1
                stats["skip_source_not_found"] += 1
                rows.append({"dest_name": dest_name, "src_name": src_name, "reason": "source_not_found"})
                continue

            if type_filter_enabled:
                src_type = (src_vm.get("vm_type") or "").strip()
                if src_type and src_type not in accepted_types:
                    stats["skipped"] += 1
                    stats["skip_source_type"] += 1
                    rows.append({"dest_name": dest_name, "src_name": src_name, "src_type": src_type, "reason": "source_type_filtered"})
                    continue

            desired_tags = _filter_tags(src_vm.get("tags") or [], self.cfg.only_scope_prefix)
            if not desired_tags:
                stats["skipped"] += 1
                stats["skip_source_no_tags"] += 1
                rows.append({"dest_name": dest_name, "src_name": src_name, "reason": "source_no_tags"})
                continue

            desired_tags = _dedupe_tags(desired_tags)
            stats["would_add"] += len(desired_tags)

            try:
                if self.cfg.dry_run:
                    rows.append({
                        "dest_name": dest_name,
                        "dest_id": dest_id,
                        "src_name": src_name,
                        "tags_to_add": desired_tags,
                        "result": "dry_run",
                    })
                else:
                    nsx_add_tagged_vms(self.client, vm_external_id=str(dest_id), tags_to_add=desired_tags)
                    stats["updated"] += 1
                    rows.append({
                        "dest_name": dest_name,
                        "dest_id": dest_id,
                        "src_name": src_name,
                        "tags_added": desired_tags,
                        "result": "applied",
                    })

            except Exception as e:
                stats["errors"] += 1
                msg = f"{dest_name} ({dest_id}) <- {src_name}: {e}"
                errors.append(msg)
                rows.append({"dest_name": dest_name, "dest_id": dest_id, "src_name": src_name, "error": str(e), "result": "error"})
                if not self.cfg.continue_on_error:
                    break

        # Write report next to SOURCE tags (keeps behavior consistent with your earlier runs)
        report_yaml = self.cfg.export_root / "tagged-vms" / "push_report_allowlist.yaml"
        report_json = self.cfg.export_root / "tagged-vms" / "push_report_allowlist.json"
        _write_yaml(report_yaml, {"stats": stats, "rows": rows[:1000]})
        _write_json(report_json, {"stats": stats, "rows": rows[:1000]})

        return {
            "stats": stats,
            "errors": errors,
            "report_yaml": str(report_yaml),
            "report_json": str(report_json),
        }