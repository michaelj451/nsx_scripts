#!/usr/bin/env python3
# nsx_yaml_functions/nsx_object_exporter.py
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Literal

import json
import re
import yaml

from utilities.file_utilities import write_json, write_yaml, manager_dirname

import logging

# If you already have these, import them
# from nsx.nsx_policy_client import NsxPolicyClient

DEFAULT_STRIP_KEYS = {
    "revision", "_revision",
    "unique_id", "realization_id",
    "marked_for_delete", "overridden",
    "create_time", "create_time_ms",
    "last_modified_time", "last_modified_time_ms",
    "create_user", "last_modified_user",
    "owner_id", "source",
}

def sanitize_payload(raw: Dict[str, Any], strip_keys: Iterable[str] = DEFAULT_STRIP_KEYS) -> Dict[str, Any]:
    """Remove volatile/read-only keys so YAML diffs stay sane."""
    def _walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k in strip_keys:
                    continue
                out[k] = _walk(v)
            return out
        if isinstance(obj, list):
            return [_walk(x) for x in obj]
        return obj

    return _walk(raw)

def slugify(name: str) -> str:
    """Safe filename slug."""
    name = (name or "").strip()
    name = re.sub(r"[^\w\-\.]+", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    return name or "unnamed"


def yaml_dump(data: Any) -> str:
    """
    Deterministic-ish YAML:
    - sort_keys=True stabilizes dict key order
    - default_flow_style=False gives multi-line readability
    """
    return yaml.safe_dump(
        data,
        sort_keys=True,
        default_flow_style=False,
        width=120,
        allow_unicode=True,
    )

@dataclass
class ExportConfig:
    base_dir: Path = Path("nsx_export")
    domain_id: str = "default"
    page_size: int = 200
    output_format: Literal["yaml", "json", "both"] = "yaml"
    strip_keys: Iterable[str] = field(default_factory=lambda: set(DEFAULT_STRIP_KEYS))


class NsxExporter:
    def __init__(self, client: Any, cfg: ExportConfig):
        self.client = client
        self.cfg = cfg
        mgr = manager_dirname(self.client)
        base = self.cfg.base_dir
        # If base_dir already ends with the manager folder, don't append again.
        self.export_root = base if base.name == mgr else (base / mgr)

    # ---- paging helper ----
    def _get_pages(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterator[Dict[str, Any]]:
        """
        Generic pager for NSX Policy API list endpoints.
        NSX typically returns: {"results":[...], "cursor":"...", "result_count":...}
        """
        params = dict(params or {})
        params.setdefault("page_size", self.cfg.page_size)

        cursor = None
        while True:
            p = dict(params)
            if cursor:
                p["cursor"] = cursor
            page = self.client._get(path, params=p)
            yield page
            cursor = page.get("cursor")
            if not cursor:
                break

    def write_object(self, base_path: Path, name: str, data: Any) -> None:
        if self.cfg.output_format in ("yaml", "both"):
            write_yaml(base_path / f"{name}.yaml", data)

        if self.cfg.output_format in ("json", "both"):
            write_json(base_path / f"{name}.json", data)

    # ---- exporters ----
    def export_meta(self) -> None:
        manager = getattr(self.client, "NSX_MANAGER", None)
        meta = {
            "export_version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "nsx": {
                "manager": manager or "unknown",
                "api": "policy",
            },
            "scope": {"domains": [self.cfg.domain_id]},
            "notes": [
                "Sanitized payloads (stripped volatile keys like _revision, unique_id, timestamps, etc.)",
                "Objects exported as one YAML per object",
            ],
        } 
        self.write_object(self.export_root, "meta", meta)

    def export_groups(self) -> int:
        base = self.client._policy_path(f"/domains/{self.cfg.domain_id}/groups")
        out_dir = self.export_root / "domains" / self.cfg.domain_id / "groups"
        out_dir.mkdir(parents=True, exist_ok=True)
        count = 0

        for page in self._get_pages(base):
            for g in page.get("results", []) or []:
                gname = g.get("display_name") or g.get("id") or "group"
                gid = g.get("id") or ""
                suffix = (gid[:8] if gid else "noid")
                fname = f"{slugify(gname)}__{suffix}"
                data = sanitize_payload(g, strip_keys=self.cfg.strip_keys)
                self.write_object(out_dir, fname, data)
                count += 1
        return count

    def export_services(self) -> int:
        base = self.client._policy_path(f"/services")
        out_dir = self.export_root / "domains" / self.cfg.domain_id / "services"
        out_dir.mkdir(parents=True, exist_ok=True)
        count = 0

        for page in self._get_pages(base):
            for s in page.get("results", []) or []:
                if s.get("_system_owned") is True:
                    continue  # skip system services
                sname = s.get("display_name") or s.get("id") or "service"
                sid = s.get("id") or ""
                suffix = (sid[:8] if sid else "noid")
                fname = f"{slugify(sname)}__{suffix}"
                data = sanitize_payload(s, strip_keys=self.cfg.strip_keys)
                self.write_object(out_dir, fname, data)
                count += 1
        return count

    def export_security_policies_and_rules(self) -> int:
        base = self.client._policy_path(f"/domains/{self.cfg.domain_id}/security-policies")
        pol_dir = self.export_root / "domains" / self.cfg.domain_id / "security-policies"
        total_rules = 0
        total_policies = 0

        for page in self._get_pages(base):
            for p in page.get("results", []) or []:
                pol_id = p.get("id") 
                if not pol_id:
                    logging.warning("Skipping policy with no ID")
                    continue
                pol_slug = slugify(pol_id)
                policy_folder = pol_dir / pol_slug
                rules_folder = policy_folder / "rules"

                # write the policy itself
                policy_data = sanitize_payload(p, strip_keys=self.cfg.strip_keys)
                self.write_object(policy_folder, "policy", policy_data)
                total_policies += 1

                # now fetch rules for this policy
                rules_path = self.client._policy_path(f"/domains/{self.cfg.domain_id}/security-policies/{pol_id}/rules")
                rule_ids_in_order: List[str] = []
                seq = 0

                for rpage in self._get_pages(rules_path):
                    for r in rpage.get("results", []) or []:
                        rid = r.get("id") or r.get("display_name") or f"rule_{seq}"
                        rule_ids_in_order.append(rid)

                        seq += 1
                        # Prefix with an incrementing number for nice diffs/ordering
                        fname = f"{seq:04d}_{slugify(rid)}"
                        rule_data = sanitize_payload(r, strip_keys=self.cfg.strip_keys)
                        self.write_object(rules_folder, fname, rule_data)

                        total_rules += 1

                # store explicit ordering (so you can re-apply deterministically)
                self.write_object(policy_folder, "rules_order", {"policy": pol_id, "rules": rule_ids_in_order})

        # optional: summary index
        self.write_object(pol_dir, "index", {"policies_exported": total_policies, "rules_exported": total_rules})
        return total_policies

    def export_all(self) -> Dict[str, int]:
        self.export_root.mkdir(parents=True, exist_ok=True)
        self.export_meta()
        groups = self.export_groups()
        services = self.export_services()
        policies = self.export_security_policies_and_rules()
        return {"groups": groups, "services": services, "policies": policies}


# ---- example runner ----
def run_export(client: Any, base_dir: str = "nsx_export", domain_id: str = "default", output_format: str = "yaml") -> Dict[str, int]:
    cfg = ExportConfig(base_dir=Path(base_dir), domain_id=domain_id, output_format=output_format)
    exporter = NsxExporter(client=client, cfg=cfg)
    return exporter.export_all()