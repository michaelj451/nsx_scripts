#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Literal

import hashlib
import json
import logging
import re
import yaml

from utilities.file_utilities import write_json, write_yaml, manager_dirname, short_id_filename

log = logging.getLogger(__name__)

DEFAULT_STRIP_KEYS = {
    "revision", "_revision",
    "unique_id", "realization_id",
    "marked_for_delete", "overridden",
    "create_time", "create_time_ms",
    "last_modified_time", "last_modified_time_ms",
    "create_user", "last_modified_user",
    "owner_id", "source",
}


def is_system_object(obj: Dict[str, Any]) -> bool:
    """
    Return True when object should not be migrated/exported.

    NSX commonly marks built-in objects with _system_owned.
    marked_for_delete objects should also be ignored.
    """
    if not isinstance(obj, dict):
        return True

    return (
        obj.get("_system_owned") is True
        or obj.get("system_owned") is True
        or obj.get("marked_for_delete") is True
    )


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


def slugify(name: str, max_len: int = 50) -> str:
    """Filename-safe slug capped at max_len to keep Windows MAX_PATH happy.

    Names longer than max_len are truncated and suffixed with a 7-char
    MD5 hash of the original, so long display names can't collide and
    can't blow past the 260-char path limit on Windows.
    """
    s = re.sub(r"[^\w\-\.]+", "_", (name or "").strip())
    s = re.sub(r"_+", "_", s).strip("_") or "unnamed"
    if len(s) <= max_len:
        return s
    h = hashlib.md5(s.encode("utf-8")).hexdigest()[:7]
    keep = max(1, max_len - len(h) - 1)
    return f"{s[:keep]}_{h}"


def yaml_dump(data: Any) -> str:
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
    page_size: int = 1000
    output_format: Literal["yaml", "json", "both"] = "yaml"
    strip_keys: Iterable[str] = field(default_factory=lambda: set(DEFAULT_STRIP_KEYS))

    # Migration-safe default
    skip_system_objects: bool = True


class NsxExporter:
    def __init__(self, client: Any, cfg: ExportConfig):
        self.client = client
        self.cfg = cfg

        mgr = manager_dirname(self.client)
        base = self.cfg.base_dir

        # If base_dir already ends with the manager folder, don't append again.
        self.export_root = base if base.name == mgr else (base / mgr)

        self.skipped = {
            "groups_system": 0,
            "services_system": 0,
            "policies_system": 0,
            "rules_system": 0,
        }

    def _should_skip(self, obj: Dict[str, Any], object_type: str) -> bool:
        if self.cfg.skip_system_objects and is_system_object(obj):
            obj_id = obj.get("id") or obj.get("display_name") or obj.get("path") or "unknown"
            log.info("Skipping system/deleted %s: %s", object_type, obj_id)
            return True
        return False

    # ---- paging helper ----
    def _get_pages(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterator[Dict[str, Any]]:
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
        base_path.mkdir(parents=True, exist_ok=True)

        if self.cfg.output_format in ("yaml", "both"):
            write_yaml(base_path / f"{name}.yaml", data)

        if self.cfg.output_format in ("json", "both"):
            write_json(base_path / f"{name}.json", data)

    # ---- exporters ----
    def export_meta(self) -> None:
        manager = getattr(self.client, "NSX_MANAGER", None)

        meta = {
            "export_version": 2,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "nsx": {
                "manager": manager or "unknown",
                "api": "policy",
            },
            "scope": {
                "domains": [self.cfg.domain_id],
                "skip_system_objects": self.cfg.skip_system_objects,
            },
            "notes": [
                "Migration-safe export.",
                "System-owned and marked-for-delete objects are skipped.",
                "Sanitized payloads strip volatile/read-only keys.",
                "Objects exported as one YAML/JSON per object.",
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
                if self._should_skip(g, "group"):
                    self.skipped["groups_system"] += 1
                    continue

                gid = g.get("id") or g.get("display_name") or "group"
                fname = short_id_filename(gid)

                data = sanitize_payload(g, strip_keys=self.cfg.strip_keys)
                self.write_object(out_dir, fname, data)
                count += 1

        return count

    def export_services(self) -> int:
        base = self.client._policy_path("/services")
        out_dir = self.export_root / "domains" / self.cfg.domain_id / "services"
        out_dir.mkdir(parents=True, exist_ok=True)

        count = 0

        for page in self._get_pages(base):
            for s in page.get("results", []) or []:
                if self._should_skip(s, "service"):
                    self.skipped["services_system"] += 1
                    continue

                sid = s.get("id") or s.get("display_name") or "service"
                fname = short_id_filename(sid)

                data = sanitize_payload(s, strip_keys=self.cfg.strip_keys)
                self.write_object(out_dir, fname, data)
                count += 1

        return count

    def export_security_policies_and_rules(self) -> int:
        base = self.client._policy_path(f"/domains/{self.cfg.domain_id}/security-policies")
        pol_dir = self.export_root / "domains" / self.cfg.domain_id / "security-policies"
        pol_dir.mkdir(parents=True, exist_ok=True)

        total_rules = 0
        total_policies = 0

        for page in self._get_pages(base):
            for p in page.get("results", []) or []:
                if self._should_skip(p, "security-policy"):
                    self.skipped["policies_system"] += 1
                    continue

                pol_id = p.get("id")
                if not pol_id:
                    log.warning("Skipping policy with no ID")
                    continue

                pol_slug = short_id_filename(pol_id)
                policy_folder = pol_dir / pol_slug
                rules_folder = policy_folder / "rules"

                policy_data = sanitize_payload(p, strip_keys=self.cfg.strip_keys)
                self.write_object(policy_folder, "policy", policy_data)
                total_policies += 1

                rules_path = self.client._policy_path(
                    f"/domains/{self.cfg.domain_id}/security-policies/{pol_id}/rules"
                )

                rule_ids_in_order: List[str] = []
                seq = 0

                for rpage in self._get_pages(rules_path):
                    for r in rpage.get("results", []) or []:
                        if self._should_skip(r, "security-rule"):
                            self.skipped["rules_system"] += 1
                            continue

                        rid = r.get("id") or r.get("display_name") or f"rule_{seq}"
                        rule_ids_in_order.append(rid)

                        seq += 1
                        fname = f"{seq:04d}_{short_id_filename(rid)}"

                        rule_data = sanitize_payload(r, strip_keys=self.cfg.strip_keys)
                        self.write_object(rules_folder, fname, rule_data)

                        total_rules += 1

                self.write_object(
                    policy_folder,
                    "rules_order",
                    {
                        "policy": pol_id,
                        "rules": rule_ids_in_order,
                    },
                )

        self.write_object(
            pol_dir,
            "index",
            {
                "policies_exported": total_policies,
                "rules_exported": total_rules,
                "skipped": self.skipped,
            },
        )

        return total_policies

    def export_all(self) -> Dict[str, int]:
        self.export_root.mkdir(parents=True, exist_ok=True)

        self.export_meta()

        groups = self.export_groups()
        services = self.export_services()
        policies = self.export_security_policies_and_rules()

        return {
            "groups": groups,
            "services": services,
            "policies": policies,
            "skipped_groups_system": self.skipped["groups_system"],
            "skipped_services_system": self.skipped["services_system"],
            "skipped_policies_system": self.skipped["policies_system"],
            "skipped_rules_system": self.skipped["rules_system"],
        }


def run_export(
    client: Any,
    base_dir: str = "nsx_export",
    domain_id: str = "default",
    output_format: str = "yaml",
    skip_system_objects: bool = True,
) -> Dict[str, int]:
    cfg = ExportConfig(
        base_dir=Path(base_dir),
        domain_id=domain_id,
        output_format=output_format,  # type: ignore[arg-type]
        skip_system_objects=skip_system_objects,
    )

    exporter = NsxExporter(client=client, cfg=cfg)
    return exporter.export_all()