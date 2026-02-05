# frontendFastapi/nsx/nsx2_vm_file_exporter.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Literal
import json
import yaml
import re
import logging


from frontendFastapi.nsx.nsx_constants import nsx_manager2

from typing import Optional

def slugify(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"[^\w\-\.]+", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    return name or "unnamed"


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            data,
            sort_keys=True,
            default_flow_style=False,
            width=120,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


@dataclass
class VmInventoryExportConfig:
    export_root: Path                      # e.g. Path("nsx_export") / "nsx2.mxferguson.com"
    output_format: Literal["yaml", "json", "both"] = "yaml"
    contains: Optional[str] = None
    case_sensitive: bool = False
    page_size: int = 1000


class NsxVmInventoryExporter:
    """
    Export realized-state VM inventory (id + display_name + tags if present)
    into nsx_export/<manager>/vm-inventory/vms.(yaml|json).
    """

    def __init__(self, client: Any, cfg: VmInventoryExportConfig):
        self.client = client
        self.cfg = cfg

    def _list_realized_vms(self) -> List[Dict[str, Any]]:
        # IMPORTANT: your NsxPolicyClient._policy_path requires a suffix.
        # Also don't accidentally create /infra/infra.
        list_path = self.client._policy_path("/realized-state/virtual-machines")

        results: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            params: Dict[str, Any] = {"page_size": self.cfg.page_size}
            if cursor:
                params["cursor"] = cursor

            page = self.client._get(list_path, params=params) or {}
            page_results = page.get("results") or []
            results.extend(page_results)

            cursor = page.get("cursor")
            if not cursor:
                break

        return results

    def _filter(self, vms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self.cfg.contains:
            return vms

        needle = self.cfg.contains if self.cfg.case_sensitive else self.cfg.contains.lower()

        out: List[Dict[str, Any]] = []
        for vm in vms:
            name = (vm.get("display_name") or "").strip()
            hay = name if self.cfg.case_sensitive else name.lower()
            if needle in hay:
                out.append(vm)
        return out

    @staticmethod
    def _vm_id(vm: Dict[str, Any]) -> str:
        # realized-state payloads vary; these are common fields
        return (vm.get("external_id") or vm.get("id") or vm.get("unique_id") or "").strip()

    def export_inventory(self) -> Dict[str, Any]:
        raw = self._list_realized_vms()
        raw = self._filter(raw)

        # keep a tidy, stable structure
        vms_out: List[Dict[str, Any]] = []
        skipped_no_id = 0

        for vm in raw:
            vm_id = self._vm_id(vm)
            if not vm_id:
                skipped_no_id += 1
                continue

            vms_out.append(
                {
                    "vm_id": vm_id,
                    "display_name": (vm.get("display_name") or "").strip(),
                    # Sometimes realized-state includes tags; keep them if present
                    "tags": vm.get("tags") or [],
                }
            )

        doc = {
            "export_version": 1,
            "type": "vm-inventory",
            "nsx_manager": getattr(self.client, "NSX_MANAGER", None) or "unknown",
            "filters": {
                "contains": self.cfg.contains,
                "case_sensitive": self.cfg.case_sensitive,
            },
            "counts": {
                "vms_total_returned": len(raw),
                "vms_written": len(vms_out),
                "skipped_no_id": skipped_no_id,
            },
            "vms": vms_out,
        }

        out_dir = self.cfg.export_root / "vm-inventory"
        out_base = out_dir / "vms"

        if self.cfg.output_format in ("yaml", "both"):
            write_yaml(out_base.with_suffix(".yaml"), doc)
        if self.cfg.output_format in ("json", "both"):
            write_json(out_base.with_suffix(".json"), doc)

        return {
            "written_yaml": str(out_base.with_suffix(".yaml")) if self.cfg.output_format in ("yaml", "both") else None,
            "written_json": str(out_base.with_suffix(".json")) if self.cfg.output_format in ("json", "both") else None,
            "counts": doc["counts"],
        }


# -----------------------------------------------------------------------------
# Manual callable helper (nice for testing)
# -----------------------------------------------------------------------------

def export_nsx_vm_inventory_to_files(
    nsxmanager: str,
    export_root: Optional[Path] = None,
    federation_global: bool = False,
    output_format: Literal["yaml", "json", "both"] = "yaml",
    contains: Optional[str] = None,
    case_sensitive: bool = False,
) -> Dict[str, Any]:
    """
    Manual callable helper (safe for CLI use).

    IMPORTANT:
    - Do NOT compute env-dependent defaults at import time.
    - If export_root is not provided, default to nsx_export/<nsxmanager>.
    """
    from frontendFastapi.nsx.nsx_policy_client import NsxPolicyClient

    if not nsxmanager:
        raise ValueError("nsxmanager must be provided")

    if export_root is None:
        export_root = Path("nsx_export") / nsxmanager

    client = NsxPolicyClient(nsxmanager=nsxmanager, federation_global=federation_global)
    cfg = VmInventoryExportConfig(
        export_root=export_root,
        output_format=output_format,
        contains=contains,
        case_sensitive=case_sensitive,
    )
    exporter = NsxVmInventoryExporter(client=client, cfg=cfg)
    return exporter.export_inventory()