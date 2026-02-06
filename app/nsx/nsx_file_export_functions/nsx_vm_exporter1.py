# nsx_yaml_functions/nsx1_vm_file_exporter.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal, Optional, Sequence
from datetime import datetime, timezone
import json
import yaml
import logging
from utilities.file_utilities import write_json, write_yaml, manager_dirname

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class VmTagsExportConfig:
    export_root: Path
    output_format: Literal["yaml", "json", "both"] = "yaml"
    page_size: int = 500

    # NEW: only export tags for these VM types (default = REGULAR only)
    accepted_vm_types: Sequence[str] = ("REGULAR",)


# # ---------------------------------------------------------------------------
# # IO helpers
# # ---------------------------------------------------------------------------

# def _write_yaml(path: Path, data: Any) -> None:
#     path.parent.mkdir(parents=True, exist_ok=True)
#     path.write_text(
#         yaml.safe_dump(
#             data,
#             sort_keys=True,
#             default_flow_style=False,
#             width=120,
#             allow_unicode=True,
#         ),
#         encoding="utf-8",
#     )


# def _write_json(path: Path, data: Any) -> None:
#     path.parent.mkdir(parents=True, exist_ok=True)
#     path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------

class NsxVmTagsExporter:
    def __init__(self, client: Any, cfg: VmTagsExportConfig):
        self.client = client
        self.cfg = cfg

    def _extract_external_id(self, vm: Dict[str, Any]) -> Optional[str]:
        ext = vm.get("external_id") or vm.get("externalId")
        if ext:
            return str(ext)

        # fallback paths seen in some realized-state payloads
        for s in vm.get("compute_ids", []) or []:
            if isinstance(s, str):
                if "externalId:" in s:
                    return s.split("externalId:", 1)[1]
                if "instanceUuid:" in s:
                    return s.split("instanceUuid:", 1)[1]
        return None

    def _extract_vm_type(self, vm: Dict[str, Any]) -> Optional[str]:
        """
        Realized-state VM objects may expose type in different fields depending
        on NSX version and backing compute manager.

        We try a few common keys and return an UPPERCASE string if found.
        """
        candidates = [
            vm.get("vm_type"),
            vm.get("type"),
            vm.get("resource_type"),
            vm.get("virtual_machine_type"),
        ]
        for c in candidates:
            if isinstance(c, str) and c.strip():
                return c.strip().upper()
        return None

    def pull_tagged_vms(self) -> Dict[str, int]:
        # Ensure base export root exists
        self.cfg.export_root.mkdir(parents=True, exist_ok=True)

        out_dir = self.cfg.export_root / "tagged-vms"
        out_dir.mkdir(parents=True, exist_ok=True)

        # IMPORTANT: suffix should NOT include /infra if _policy_path already includes it
        list_path = self.client._policy_path("/realized-state/virtual-machines")

        exported = 0
        skipped = 0
        errors = 0
        skipped_no_id = 0
        skipped_no_tags = 0
        skipped_type = 0

        accepted = {str(x).upper() for x in (self.cfg.accepted_vm_types or [])}

        # Store as one big index file (recommended)
        tag_index: Dict[str, Any] = {
            "meta": {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "manager": getattr(self.client, "NSX_MANAGER", "unknown"),
                "accepted_vm_types": sorted(list(accepted)),
            },
            "counts": {
                "exported": 0,
                "skipped": 0,
                "skipped_no_id": 0,
                "skipped_no_tags": 0,
                "skipped_type": 0,
                "errors": 0,
            },
            "vms": {},
        }

        # paging loop (cursor-based)
        cursor = None
        while True:
            params = {"page_size": self.cfg.page_size}
            if cursor:
                params["cursor"] = cursor

            page = self.client._get(list_path, params=params) or {}
            results = page.get("results", []) or []

            for vm in results:
                try:
                    if not isinstance(vm, dict):
                        skipped += 1
                        continue

                    ext_id = self._extract_external_id(vm)
                    if not ext_id:
                        skipped += 1
                        skipped_no_id += 1
                        continue

                    name = (vm.get("display_name") or "").strip()
                    tags = vm.get("tags") or []
                    if not isinstance(tags, list) or not tags:
                        skipped += 1
                        skipped_no_tags += 1
                        continue

                    vm_type = self._extract_vm_type(vm) or "UNKNOWN"

                    # NEW: filter by vm_type
                    if accepted and vm_type not in accepted:
                        skipped += 1
                        skipped_type += 1
                        continue

                    tag_index["vms"][ext_id] = {
                        "display_name": name,
                        "external_id": ext_id,
                        "vm_type": vm_type,  # NEW: included in output
                        "tags": tags,
                    }
                    exported += 1

                except Exception as e:
                    errors += 1
                    logger.exception("Error processing vm record: %s", e)

            cursor = page.get("cursor")
            if not cursor:
                break

        tag_index["counts"] = {
            "exported": exported,
            "skipped": skipped,
            "skipped_no_id": skipped_no_id,
            "skipped_no_tags": skipped_no_tags,
            "skipped_type": skipped_type,
            "errors": errors,
        }

        # write index file
        base_name = "vm_tags_index"
        if self.cfg.output_format in ("yaml", "both"):
            write_yaml(out_dir / f"{base_name}.yaml", tag_index)
        if self.cfg.output_format in ("json", "both"):
            write_json(out_dir / f"{base_name}.json", tag_index)

        return {"exported": exported, "skipped": skipped, "errors": errors}