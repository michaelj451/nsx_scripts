#!/usr/bin/env python3
# app/nsx/nsx_file_import_functions/nsx_object_importer.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
import json
import yaml
import logging

log = logging.getLogger(__name__)


@dataclass
class ImportConfig:
    export_root: Path
    domain_id: str = "default"
    input_format: Literal["yaml", "json"] = "yaml"
    dry_run: bool = True
    continue_on_error: bool = True


class NsxImporter:
    def __init__(self, client: Any, cfg: ImportConfig):
        self.client = client
        self.cfg = cfg

        # Support both layouts:
        # NEW: <export_root>/<domain_id>/...
        # OLD: <export_root>/domains/<domain_id>/...
        new_root = self.cfg.export_root / self.cfg.domain_id
        old_root = self.cfg.export_root / "domains" / self.cfg.domain_id

        if new_root.exists():
            self.dom_root = new_root
        else:
            self.dom_root = old_root

        self.stats = {
            "services": 0,
            "groups": 0,
            "policies": 0,
            "rules": 0,
            "skipped": 0,
            "errors": 0,
        }
        self.errors: List[str] = []

    # ---------------- helpers ----------------

    def _load_file(self, path: Path) -> Dict[str, Any]:
        if path.suffix.lower() in (".yaml", ".yml"):
            return yaml.safe_load(path.read_text(encoding="utf-8"))
        if path.suffix.lower() == ".json":
            return json.loads(path.read_text(encoding="utf-8"))
        raise ValueError(f"Unsupported file type: {path}")

    def _iter_files(self, root: Path) -> List[Path]:
        if not root.exists():
            return []
        exts = (".yaml", ".yml") if self.cfg.input_format == "yaml" else (".json",)
        return sorted(p for p in root.iterdir() if p.is_file() and p.suffix.lower() in exts)

    def _policy_path(self, rel: str) -> str:
        """
        Use the client's policy root logic (LM vs GM federation-global).
        Falls back to rel if client doesn't provide helper.
        """
        fn = getattr(self.client, "_policy_path", None)
        return fn(rel) if callable(fn) else rel

    def _put_or_patch(self, path: str, payload: Dict[str, Any]) -> None:
        if self.cfg.dry_run:
            log.info("[DRY-RUN] PUT/PATCH %s (id=%s)", path, payload.get("id"))
            return

        try:
            self.client._put(path, payload)
        except Exception as e:
            # retry as PATCH if already exists
            if "already exists" in str(e) or "500127" in str(e):
                self.client._patch(path, payload)
            else:
                raise

    def _record_error(self, msg: str):
        self.stats["errors"] += 1
        self.errors.append(msg)
        log.error(msg)
        if not self.cfg.continue_on_error:
            raise RuntimeError(msg)

    def _load_rules_order(self, policy_dir: Path) -> Optional[List[str]]:
        """
        Optional: read rules_order.yaml/json if present.
        """
        order_file = policy_dir / f"rules_order.{self.cfg.input_format}"
        if not order_file.exists():
            return None
        try:
            data = self._load_file(order_file)
            rules = data.get("rules")
            return rules if isinstance(rules, list) else None
        except Exception as e:
            log.warning("Failed to read %s: %s", order_file, e)
            return None

    # ---------------- import stages ----------------

    def import_services(self):
        svc_dir = self.dom_root / "services"

        for f in self._iter_files(svc_dir):
            try:
                data = self._load_file(f)

                if data.get("_system_owned") is True:
                    self.stats["skipped"] += 1
                    continue

                sid = data.get("id")
                if not sid:
                    raise ValueError("Service missing id")

                path = self._policy_path(f"/services/{sid}")
                self._put_or_patch(path, data)
                self.stats["services"] += 1

            except Exception as e:
                self._record_error(f"Failed importing service file {f}: {e}")

    def import_groups(self):
        grp_dir = self.dom_root / "groups"

        for f in self._iter_files(grp_dir):
            try:
                data = self._load_file(f)

                if data.get("system_defined") is True or data.get("_system_owned") is True:
                    self.stats["skipped"] += 1
                    continue

                gid = data.get("id")
                if not gid:
                    raise ValueError("Group missing id")

                path = self._policy_path(f"/domains/{self.cfg.domain_id}/groups/{gid}")
                self._put_or_patch(path, data)
                self.stats["groups"] += 1

            except Exception as e:
                self._record_error(f"Failed importing group file {f}: {e}")

    def import_policies_and_rules(self):
        pol_root = self.dom_root / "security-policies"
        if not pol_root.exists():
            return

        for pol_dir in sorted(p for p in pol_root.iterdir() if p.is_dir()):
            try:
                policy_file = pol_dir / f"policy.{self.cfg.input_format}"
                if not policy_file.exists():
                    self.stats["skipped"] += 1
                    continue

                policy = self._load_file(policy_file)
                pid = policy.get("id")
                if not pid:
                    raise ValueError("Policy missing id")

                pol_path = self._policy_path(f"/domains/{self.cfg.domain_id}/security-policies/{pid}")
                self._put_or_patch(pol_path, policy)
                self.stats["policies"] += 1

                # rules
                rules_dir = pol_dir / "rules"
                if not rules_dir.exists():
                    continue

                rule_files = self._iter_files(rules_dir)

                # Optional: enforce explicit order if present
                explicit_order = self._load_rules_order(pol_dir)
                if explicit_order:
                    # files are named like 0001_<id>.yaml; ordering is mostly fine already,
                    # but explicit_order lets you sanity-check / re-apply deterministically.
                    # We still iterate files because payload contains rule id.
                    pass

                for rf in rule_files:
                    rule = self._load_file(rf)
                    rid = rule.get("id")
                    if not rid:
                        self.stats["skipped"] += 1
                        continue

                    rule_path = self._policy_path(f"/domains/{self.cfg.domain_id}/security-policies/{pid}/rules/{rid}")
                    self._put_or_patch(rule_path, rule)
                    self.stats["rules"] += 1

            except Exception as e:
                self._record_error(f"Failed importing policy folder {pol_dir}: {e}")

    # ---------------- entrypoint ----------------

    def import_all(self) -> Dict[str, Any]:
        log.info("Starting NSX import from %s (domain layout root: %s)", self.cfg.export_root, self.dom_root)

        self.import_services()
        self.import_groups()
        self.import_policies_and_rules()

        return {
            "stats": self.stats,
            "errors": self.errors,
        }