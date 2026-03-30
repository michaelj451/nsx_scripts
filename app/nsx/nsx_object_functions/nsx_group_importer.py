#!/usr/bin/env python3
# app/nsx/nsx_object_functions/nsx_group_importer.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set

import json
import yaml
import logging

from nsx.nsx_object_functions.nsx_group_remap import _classify_token

log = logging.getLogger(__name__)


def sanitize_group_payload_for_put(raw: dict) -> dict:
    """
    Remove keys that NSX Policy API rejects on PUT/PATCH.

    Keep only the fields we actually want to define for a Group.
    """
    if not isinstance(raw, dict):
        return raw

    # Hard remove: anything clearly read-only / export metadata
    DROP_EXACT = {
        "_source_id", "_source_path",
        "_create_time", "_create_user",
        "_last_modified_time", "_last_modified_user",
        "_revision", "revision",
        "unique_id", "realization_id",
        "owner_id", "source",
        "marked_for_delete", "overridden",
        "path", "relative_path", "parent_path",
    }

    out = {}
    for k, v in raw.items():
        # Drop explicit bad keys
        if k in DROP_EXACT:
            continue

        # Drop any other leading-underscore metadata keys (safe default)
        # If you later find a legitimate "_" key you need, whitelist it here.
        if k.startswith("_"):
            continue

        out[k] = v

    return out


@dataclass
class GroupImportConfig:
    export_root: Path
    domain_id: str = "default"
    input_format: Literal["yaml", "json"] = "yaml"
    dry_run: bool = True
    continue_on_error: bool = True

    # Only import groups, or everything
    mode: Literal["all", "groups_only"] = "groups_only"

    # Only import groups that match:
    # - allowlist (preferred, safest), OR
    # - suffix match on id/display_name
    new_group_suffix: Optional[str] = None
    new_groups_allowlist_file: Optional[Path] = None


class NsxGroupImporter:
    def __init__(self, client: Any, cfg: GroupImportConfig):
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
        self.snapshots: List[Dict] = []
        self._groups_allowlist: Optional[Set[str]] = self._load_groups_allowlist()

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
        fn = getattr(self.client, "_policy_path", None)
        return fn(rel) if callable(fn) else rel

    def _put_or_patch(self, path: str, payload: Dict[str, Any]) -> None:
        if self.cfg.dry_run:
            log.info("[DRY-RUN] PUT/PATCH %s (id=%s)", path, payload.get("id"))
            return

        try:
            self.client._put(path, payload)
        except Exception as e:
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

    def _load_groups_allowlist(self) -> Optional[Set[str]]:
        f = self.cfg.new_groups_allowlist_file
        if not f:
            return None
        if not f.exists():
            raise FileNotFoundError(f"new_groups_allowlist_file not found: {f}")

        raw = self._load_file(f) if f.suffix.lower() in (".yaml", ".yml", ".json") else None
        if raw is None:
            raise ValueError(f"Unsupported allowlist file type: {f}")

        if isinstance(raw, list):
            return {str(x) for x in raw}

        if isinstance(raw, dict):
            groups = raw.get("groups", raw.get("group_ids", raw.get("ids")))
            if isinstance(groups, list):
                return {str(x) for x in groups}

        raise ValueError(f"Allowlist file {f} must be a list or dict with a 'groups' list")

    def _is_new_group(self, group_payload: Dict[str, Any]) -> bool:
        gid = str(group_payload.get("id") or "")
        name = str(group_payload.get("display_name") or "")

        if self._groups_allowlist is not None:
            return (gid in self._groups_allowlist) or (name in self._groups_allowlist)

        if self.cfg.new_group_suffix:
            suf = self.cfg.new_group_suffix
            return gid.endswith(suf) or name.endswith(suf)

        # If neither configured, allow all groups in folder
        return True

    def _stable_json(self, value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def _normalize_ip_list(self, ips: List[str]) -> List[str]:
        seen = set()
        out: List[str] = []

        for ip in ips:
            s = str(ip).strip()
            if not s:
                continue
            if s not in seen:
                out.append(s)
                seen.add(s)

        return out

    def _extract_ip_expression_ips(self, expr: Dict[str, Any]) -> List[str]:
        if not isinstance(expr, dict):
            return []

        if expr.get("resource_type") != "IPAddressExpression":
            return []

        ips = expr.get("ip_addresses") or []
        if not isinstance(ips, list):
            return []

        return [str(x).strip() for x in ips if str(x).strip()]

    def _merge_ip_address_expressions_only(
        self,
        live: Dict[str, Any],
        incoming: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Additive-only merge for IPAddressExpression objects.

        Rules:
        - Preserve the live object as the source of truth.
        - Only inspect incoming IPAddressExpression entries.
        - Only add missing IPs.
        - Do not remove existing IPs.
        - Do not modify non-IPAddressExpression entries.
        - Do not modify unrelated scalar fields.
        """
        merged = dict(live)

        live_exprs = list(live.get("expression") or [])
        incoming_exprs = list(incoming.get("expression") or [])

        if not isinstance(live_exprs, list):
            live_exprs = []
        if not isinstance(incoming_exprs, list):
            incoming_exprs = []

        incoming_ips: List[str] = []
        for expr in incoming_exprs:
            incoming_ips.extend(self._extract_ip_expression_ips(expr))

        incoming_ips = self._normalize_ip_list(incoming_ips)

        if not incoming_ips:
            return merged

        # Find first live IPAddressExpression to append into
        live_ip_expr_index: Optional[int] = None
        existing_ips: List[str] = []

        for idx, expr in enumerate(live_exprs):
            if isinstance(expr, dict) and expr.get("resource_type") == "IPAddressExpression":
                live_ip_expr_index = idx
                existing_ips = self._extract_ip_expression_ips(expr)
                break

        if live_ip_expr_index is not None:
            combined_ips = self._normalize_ip_list(existing_ips + incoming_ips)
            updated_expr = dict(live_exprs[live_ip_expr_index])
            updated_expr["ip_addresses"] = combined_ips
            live_exprs[live_ip_expr_index] = updated_expr
        else:
            # No live IP expression exists; append a new one.
            live_exprs.append({
                "resource_type": "IPAddressExpression",
                "ip_addresses": incoming_ips,
            })

        merged["expression"] = live_exprs
        return merged

    # ---------------- import stages ----------------

    def import_groups(self):
        grp_dir = self.dom_root / "groups"

        for f in self._iter_files(grp_dir):
            try:
                data = self._load_file(f)

                if data.get("system_defined") is True or data.get("_system_owned") is True:
                    self.stats["skipped"] += 1
                    continue

                if not self._is_new_group(data):
                    self.stats["skipped"] += 1
                    log.info(
                        "Skipping group not matched by allowlist/suffix: id=%s display_name=%s file=%s",
                        data.get("id"),
                        data.get("display_name"),
                        f,
                    )
                    continue

                gid = data.get("id")
                if not gid:
                    raise ValueError("Group missing id")

                path = self._policy_path(f"/domains/{self.cfg.domain_id}/groups/{gid}")

                incoming = sanitize_group_payload_for_put(data)

                # Read live object so we can do additive-only merge
                live = self.client._get(path)
                if not isinstance(live, dict) or not live:
                    raise ValueError(f"Live group not found or unreadable: {gid}")

                live_clean = sanitize_group_payload_for_put(live)

                # Merge only IPAddressExpression IPs
                payload = self._merge_ip_address_expressions_only(
                    live=live_clean,
                    incoming=incoming,
                )

                before_ips: List[str] = []
                after_ips: List[str] = []

                for expr in live_clean.get("expression") or []:
                    if isinstance(expr, dict) and expr.get("resource_type") == "IPAddressExpression":
                        before_ips.extend(self._extract_ip_expression_ips(expr))

                for expr in payload.get("expression") or []:
                    if isinstance(expr, dict) and expr.get("resource_type") == "IPAddressExpression":
                        after_ips.extend(self._extract_ip_expression_ips(expr))

                before_ips = self._normalize_ip_list(before_ips)
                after_ips = self._normalize_ip_list(after_ips)
                added_ips = [ip for ip in after_ips if ip not in set(before_ips)]

                self.snapshots.append({
                    "group_id": gid,
                    "group_display_name": payload.get("display_name"),
                    "domain_id": self.cfg.domain_id,
                    "file": str(f),
                    "before": {
                        "ip_count": len(before_ips),
                        "ips": [{"value": ip, "type": _classify_token(ip)} for ip in before_ips],
                    },
                    "after": {
                        "ip_count": len(after_ips),
                        "ips": [{"value": ip, "type": _classify_token(ip)} for ip in after_ips],
                    },
                    "added": [{"value": ip, "type": _classify_token(ip)} for ip in added_ips],
                })

                if self.cfg.dry_run:
                    log.info(
                        "[DRY-RUN] PATCH %s (id=%s) additive IP merge only; added_ip_count=%d added_ips=%s",
                        path,
                        gid,
                        len(added_ips),
                        added_ips,
                    )
                else:
                    self.client._patch(path, payload)
                    log.info(
                        "Patched group %s with additive IP merge only; added_ip_count=%d",
                        gid,
                        len(added_ips),
                    )

                self.stats["groups"] += 1

            except Exception as e:
                self._record_error(f"Failed importing group file {f}: {e}")

    def import_all(self) -> Dict[str, Any]:
        log.info(
            "Starting NSX import from %s (domain layout root: %s) mode=%s suffix=%s allowlist=%s",
            self.cfg.export_root,
            self.dom_root,
            self.cfg.mode,
            self.cfg.new_group_suffix,
            str(self.cfg.new_groups_allowlist_file) if self.cfg.new_groups_allowlist_file else None,
        )
        log.info("Group importer behavior: additive IPAddressExpression merge only; existing non-IP expressions are preserved")

        # For your use case, keep it tight:
        if self.cfg.mode in ("groups_only", "all"):
            self.import_groups()

        return {"stats": self.stats, "errors": self.errors, "snapshots": self.snapshots}