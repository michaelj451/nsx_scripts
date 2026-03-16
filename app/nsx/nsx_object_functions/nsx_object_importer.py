#!/usr/bin/env python3
# app/nsx/nsx_file_import_functions/nsx_object_importer.py

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple
import copy
import json
import logging

import yaml

log = logging.getLogger(__name__)


STRIP_KEYS = {
    "_revision",
    "revision",
    "_protection",
    "_last_modified_time",
    "_create_time",
    "_system_owned",
    "_links",
    "path",
    "relative_path",
    "parent_path",
    "remote_path",
    "realization_id",
    "unique_id",
    "owner_id",
    "origin_site_id",
    "overridden",
    "marked_for_delete",
}


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
        elif old_root.exists():
            self.dom_root = old_root
        else:
            raise RuntimeError(
                "Could not determine domain root.\n"
                f"Checked:\n"
                f"  - {new_root}\n"
                f"  - {old_root}"
            )

        self.stats = {
            "services": 0,
            "groups": 0,
            "policies": 0,
            "rules": 0,
            "skipped": 0,
            "errors": 0,
        }
        self.errors: List[str] = []

    # -------------------------------------------------------------------------
    # helpers
    # -------------------------------------------------------------------------

    def _load_file(self, path: Path) -> Dict[str, Any]:
        text = path.read_text(encoding="utf-8")

        if path.suffix.lower() in (".yaml", ".yml"):
            data = yaml.safe_load(text)
        elif path.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            raise ValueError(f"Unsupported file type: {path}")

        if not isinstance(data, dict):
            raise ValueError(f"Expected object/dict in file: {path}")

        return data

    def _iter_files(self, root: Path) -> List[Path]:
        if not root.exists():
            return []

        exts = (".yaml", ".yml") if self.cfg.input_format == "yaml" else (".json",)
        return sorted(
            p for p in root.iterdir()
            if p.is_file() and p.suffix.lower() in exts
        )

    def _policy_path(self, rel: str) -> str:
        """
        Delegate path generation to the client if possible.
        For example:
          LM  -> /infra/...
          GM  -> /global-infra/...
        """
        fn = getattr(self.client, "_policy_path", None)
        return fn(rel) if callable(fn) else rel

    def _sanitize_payload(self, obj: Any) -> Any:
        """
        Remove source-side metadata/revision/path fields that should not be
        replayed into the target NSX manager.
        """
        if isinstance(obj, dict):
            clean: Dict[str, Any] = {}
            for k, v in obj.items():
                if k in STRIP_KEYS:
                    continue
                clean[k] = self._sanitize_payload(v)
            return clean

        if isinstance(obj, list):
            return [self._sanitize_payload(v) for v in obj]

        return obj

    def _is_precondition_failed(self, exc: Exception) -> bool:
        msg = str(exc)
        return (
            "PRECONDITION_FAILED" in msg
            or "500071" in msg
            or "different version" in msg
            or "412" in msg
        )

    def _is_already_exists(self, exc: Exception) -> bool:
        msg = str(exc)
        return "already exists" in msg or "500127" in msg

    def _is_not_found(self, exc: Exception) -> bool:
        msg = str(exc)
        return (
            "404" in msg
            or "NOT_FOUND" in msg
            or "The requested object" in msg
            or "cannot be found" in msg
            or "was not found" in msg
        )

    def _is_rule_path(self, path: str) -> bool:
        return "/security-policies/" in path and "/rules/" in path

    def _is_policy_path(self, path: str) -> bool:
        return "/security-policies/" in path and "/rules/" not in path

    def _parent_policy_path_from_rule_path(self, path: str) -> Optional[str]:
        if not self._is_rule_path(path):
            return None
        return path.split("/rules/", 1)[0]

    def _client_get(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Try client._get first since this importer already uses client._put/_patch.
        Fall back to client.get if present.
        Return None on 404/not-found.
        """
        getter = getattr(self.client, "_get", None)
        if not callable(getter):
            getter = getattr(self.client, "get", None)

        if not callable(getter):
            log.debug("Client has no _get/get method; skipping existence check for %s", path)
            return None

        try:
            obj = getter(path)
            if obj is None:
                return None
            if not isinstance(obj, dict):
                log.debug(
                    "GET %s returned non-dict type %s; treating as existing without revision",
                    path,
                    type(obj).__name__,
                )
                return {}
            return obj
        except Exception as e:
            if self._is_not_found(e):
                return None
            raise

    def _prepare_write_payload(
        self,
        path: str,
        payload: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], bool, Optional[Any]]:
        """
        Build sanitized payload and inject a live revision when needed.

        Normal objects:
          - check object itself

        Rules:
          - check parent policy revision, because NSX validates rule writes
            against the parent policy version
        """
        clean_payload = self._sanitize_payload(copy.deepcopy(payload))

        lookup_path = path
        if self._is_rule_path(path):
            parent_policy_path = self._parent_policy_path_from_rule_path(path)
            if parent_policy_path:
                lookup_path = parent_policy_path

        existing = self._client_get(lookup_path)

        if existing is None:
            clean_payload.pop("_revision", None)
            clean_payload.pop("revision", None)
            return clean_payload, False, None

        live_revision = existing.get("_revision")
        if live_revision is not None:
            clean_payload["_revision"] = live_revision
        else:
            clean_payload.pop("_revision", None)
            clean_payload.pop("revision", None)

        return clean_payload, True, live_revision

    def _put_or_patch(self, path: str, payload: Dict[str, Any]) -> None:
        """
        Write behavior:
          - Policies: if policy exists, PATCH; otherwise PUT
          - Other objects: PUT first, PATCH fallback on already exists
          - Retry once on 412 after refreshing revision

        This preserves prior behavior while handling policy/rule revision drift.
        """
        clean_payload, exists, live_revision = self._prepare_write_payload(path, payload)
        obj_id = clean_payload.get("id", payload.get("id", "<missing-id>"))

        if self.cfg.dry_run:
            if self._is_policy_path(path) and exists:
                chosen_method = "PATCH"
            else:
                chosen_method = "PUT/PATCH"
            log.info(
                "[DRY-RUN] %s %s (id=%s, exists=%s, live_rev=%s)",
                chosen_method,
                path,
                obj_id,
                exists,
                live_revision,
            )
            return

        # Policies: if they already exist, PATCH them directly.
        if self._is_policy_path(path) and exists:
            try:
                log.info(
                    "PATCH existing policy %s (id=%s, exists=%s, live_rev=%s)",
                    path,
                    obj_id,
                    exists,
                    live_revision,
                )
                self.client._patch(path, clean_payload)
                return
            except Exception as e:
                if self._is_precondition_failed(e):
                    retry_payload, retry_exists, retry_live_revision = self._prepare_write_payload(path, payload)
                    log.warning(
                        "PATCH hit 412 for existing policy %s (id=%s); refreshing revision and retrying PATCH once (exists=%s, live_rev=%s)",
                        path,
                        obj_id,
                        retry_exists,
                        retry_live_revision,
                    )
                    self.client._patch(path, retry_payload)
                    return
                raise

        # Everything else: PUT first, PATCH fallback if already exists.
        try:
            log.info(
                "PUT %s (id=%s, exists=%s, live_rev=%s)",
                path,
                obj_id,
                exists,
                live_revision,
            )
            self.client._put(path, clean_payload)
            return

        except Exception as e:
            if self._is_already_exists(e):
                try:
                    patch_payload, patch_exists, patch_live_revision = self._prepare_write_payload(path, payload)
                    log.info(
                        "PATCH fallback %s (id=%s, exists=%s, live_rev=%s)",
                        path,
                        obj_id,
                        patch_exists,
                        patch_live_revision,
                    )
                    self.client._patch(path, patch_payload)
                    return

                except Exception as patch_exc:
                    if self._is_precondition_failed(patch_exc):
                        retry_payload, retry_exists, retry_live_revision = self._prepare_write_payload(path, payload)
                        log.warning(
                            "PATCH hit 412 for %s (id=%s); refreshing revision and retrying PATCH once (exists=%s, live_rev=%s)",
                            path,
                            obj_id,
                            retry_exists,
                            retry_live_revision,
                        )
                        self.client._patch(path, retry_payload)
                        return
                    raise

            if self._is_precondition_failed(e):
                retry_payload, retry_exists, retry_live_revision = self._prepare_write_payload(path, payload)
                log.warning(
                    "PUT hit 412 for %s (id=%s); refreshing revision and retrying PUT once (exists=%s, live_rev=%s)",
                    path,
                    obj_id,
                    retry_exists,
                    retry_live_revision,
                )
                self.client._put(path, retry_payload)
                return

            raise

    def _record_error(self, msg: str) -> None:
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

    def _sort_rule_files(self, rule_files: List[Path], explicit_order: Optional[List[str]]) -> List[Path]:
        """
        If rules_order is present, sort files by rule id according to that order.
        Otherwise fall back to filename sort.
        """
        if not explicit_order:
            return rule_files

        order_index = {rid: idx for idx, rid in enumerate(explicit_order)}

        def _key(path: Path):
            try:
                rule = self._load_file(path)
                rid = rule.get("id")
                if rid in order_index:
                    return (0, order_index[rid], path.name)
                return (1, 999999, path.name)
            except Exception:
                return (2, 999999, path.name)

        return sorted(rule_files, key=_key)

    # -------------------------------------------------------------------------
    # import stages
    # -------------------------------------------------------------------------

    def import_services(self) -> None:
        svc_dir = self.dom_root / "services"
        files = self._iter_files(svc_dir)

        log.info("Importing services from %s (%d files)", svc_dir, len(files))

        for f in files:
            try:
                data = self._load_file(f)

                if data.get("_system_owned") is True:
                    log.info("Skipping system-owned service file: %s", f.name)
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

    def import_groups(self) -> Dict[str, Any]:
        grp_dir = self.dom_root / "groups"
        files = self._iter_files(grp_dir)

        log.info("Importing groups from %s (%d files)", grp_dir, len(files))

        start_groups = self.stats["groups"]
        start_errors = self.stats["errors"]
        start_skipped = self.stats["skipped"]

        local_errors_before = len(self.errors)

        for f in files:
            try:
                data = self._load_file(f)

                if data.get("system_defined") is True or data.get("_system_owned") is True:
                    log.info("Skipping system-defined/system-owned group file: %s", f.name)
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

        return {
            "stats": {
                "services": 0,
                "groups": self.stats["groups"] - start_groups,
                "policies": 0,
                "rules": 0,
                "skipped": self.stats["skipped"] - start_skipped,
                "errors": self.stats["errors"] - start_errors,
            },
            "errors": self.errors[local_errors_before:],
        }

    def import_policies_and_rules(self) -> None:
        pol_root = self.dom_root / "security-policies"
        if not pol_root.exists():
            log.info("No security-policies folder found under %s", self.dom_root)
            return

        policy_dirs = sorted(p for p in pol_root.iterdir() if p.is_dir())
        log.info("Importing security policies from %s (%d policy dirs)", pol_root, len(policy_dirs))

        # Pass 1: import/update policies first
        loaded_policies: List[Tuple[Path, str]] = []

        for pol_dir in policy_dirs:
            try:
                policy_file = pol_dir / f"policy.{self.cfg.input_format}"
                if not policy_file.exists():
                    log.warning("Skipping %s because %s is missing", pol_dir, policy_file.name)
                    self.stats["skipped"] += 1
                    continue

                policy = self._load_file(policy_file)
                pid = policy.get("id")
                if not pid:
                    raise ValueError("Policy missing id")

                pol_path = self._policy_path(f"/domains/{self.cfg.domain_id}/security-policies/{pid}")
                self._put_or_patch(pol_path, policy)
                self.stats["policies"] += 1
                loaded_policies.append((pol_dir, pid))

            except Exception as e:
                self._record_error(f"Failed importing policy folder {pol_dir}: {e}")

        # Pass 2: import rules after policies exist
        for pol_dir, pid in loaded_policies:
            try:
                rules_dir = pol_dir / "rules"
                if not rules_dir.exists():
                    log.info("No rules folder for policy %s", pid)
                    continue

                rule_files = self._iter_files(rules_dir)
                explicit_order = self._load_rules_order(pol_dir)
                rule_files = self._sort_rule_files(rule_files, explicit_order)

                log.info("Importing %d rules for policy %s", len(rule_files), pid)

                for rf in rule_files:
                    try:
                        rule = self._load_file(rf)
                        rid = rule.get("id")
                        if not rid:
                            log.warning("Skipping rule file with missing id: %s", rf)
                            self.stats["skipped"] += 1
                            continue

                        rule_path = self._policy_path(
                            f"/domains/{self.cfg.domain_id}/security-policies/{pid}/rules/{rid}"
                        )
                        self._put_or_patch(rule_path, rule)
                        self.stats["rules"] += 1

                    except Exception as e:
                        self._record_error(f"Failed importing rule file {rf}: {e}")

            except Exception as e:
                self._record_error(f"Failed importing rules for policy {pid}: {e}")

    # -------------------------------------------------------------------------
    # entrypoint
    # -------------------------------------------------------------------------

    def import_all(self) -> Dict[str, Any]:
        log.info("Starting NSX import from export_root=%s", self.cfg.export_root)
        log.info("Resolved domain layout root: %s", self.dom_root)
        log.info("Input format: %s", self.cfg.input_format)
        log.info("Dry run: %s", self.cfg.dry_run)
        log.info("Continue on error: %s", self.cfg.continue_on_error)

        self.import_services()
        self.import_groups()
        self.import_policies_and_rules()

        return {
            "stats": self.stats,
            "errors": self.errors,
        }