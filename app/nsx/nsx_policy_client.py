#!/usr/bin/env python3
# app/nsx/nsx_policy_client.py

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Iterator, List, Optional, Set

import requests
import urllib3

from nsx.nsx_constants import (
    nsx_gm1,
    nsx_gm2,
    nsx_lm1,
    nsx_lm2,
    nsx_lm3,
    nsx_lm4,
    nsx_username,
    nsx_password,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NsxApiError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"[HTTP {status_code}] {message}")


class NsxPolicyClient:
    def __init__(self, nsxmanager: str = nsx_gm1, *, federation_global: bool = False):
        logging.info(
            f"Creating NSX session for manager: {nsxmanager} "
            f"(federation_global={federation_global})"
        )

        nsxmanager = (nsxmanager or "").strip()
        nsxmanager = nsxmanager.removeprefix("https://").removeprefix("http://").rstrip("/")

        self.NSX_MANAGER = f"https://{nsxmanager}"
        self.USERNAME = nsx_username
        self.PASSWORD = nsx_password
        self.federation_global = federation_global

        mgr_norm = nsxmanager.lower()
        gm_hosts = {
            (nsx_gm1 or "").lower(),
            (nsx_gm2 or "").lower(),
        }

        is_gm = any(
            mgr_norm == h
            or mgr_norm.startswith(h + ".")
            or h.startswith(mgr_norm + ".")
            for h in gm_hosts
            if h
        )

        if federation_global:
            self.POLICY_ROOT = (
                "/global-manager/api/v1/global-infra"
                if is_gm
                else "/policy/api/v1/global-infra"
            )
        else:
            self.POLICY_ROOT = "/policy/api/v1/infra"

        self.FABRIC_ROOT = "/api/v1"

        self.session, self.xsrf_token = self.get_nsx_session()
        self.session.headers.setdefault("Content-Type", "application/json")

        self.status = "success"
        self.errors: List[str] = []

    # ---------------------------
    # Auth / Session
    # ---------------------------

    def get_nsx_session(self):
        s = requests.Session()
        s.verify = False
        s.headers.update({"Accept": "application/json"})

        login_resp = s.post(
            f"{self.NSX_MANAGER}/api/session/create",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"j_username": self.USERNAME, "j_password": self.PASSWORD},
            timeout=15,
        )

        if not login_resp.ok:
            raise NsxApiError(
                login_resp.status_code,
                f"Login failed: {login_resp.status_code} {login_resp.text}",
            )

        xsrf_token = (
            login_resp.headers.get("X-XSRF-TOKEN")
            or s.cookies.get("XSRF-TOKEN")
            or s.cookies.get("xsrf-token")
        )

        if xsrf_token:
            s.headers["X-XSRF-TOKEN"] = xsrf_token

        return s, xsrf_token

    # ---------------------------
    # Path helpers
    # ---------------------------

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.NSX_MANAGER}{path}"

    def _policy_path(self, suffix: str) -> str:
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{self.POLICY_ROOT}{suffix}"

    def _fabric_path(self, suffix: str) -> str:
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{self.FABRIC_ROOT}{suffix}"

    # ---------------------------
    # HTTP helpers
    # ---------------------------

    def _raise_for_resp(self, resp, method: str, path: str):
        if not resp.ok:
            raise NsxApiError(
                resp.status_code,
                f"{method} {path} failed: {resp.status_code} {resp.text}",
            )

    def _json_or_empty(self, resp) -> Dict[str, Any]:
        if not resp.text:
            return {}
        try:
            return resp.json()
        except Exception:
            return {"raw": resp.text}

    def _get(
        self,
        path: str,
        params: Optional[dict] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        resp = self.session.get(self._url(path), params=params, timeout=timeout)
        self._raise_for_resp(resp, "GET", path)
        return self._json_or_empty(resp)

    def _put(self, path: str, payload: dict, timeout: int = 60) -> Dict[str, Any]:
        resp = self.session.put(self._url(path), json=payload, timeout=timeout)
        self._raise_for_resp(resp, "PUT", path)
        return self._json_or_empty(resp) or {"status": "ok"}

    def _patch(self, path: str, payload: dict, timeout: int = 60) -> Dict[str, Any]:
        resp = self.session.patch(self._url(path), json=payload, timeout=timeout)
        self._raise_for_resp(resp, "PATCH", path)
        return self._json_or_empty(resp) or {"status": "ok"}

    def _post(self, path: str, payload: dict | None = None, timeout: int = 60) -> Dict[str, Any]:
        resp = self.session.post(self._url(path), json=payload, timeout=timeout)
        self._raise_for_resp(resp, "POST", path)
        return self._json_or_empty(resp) or {"status": "ok"}

    def _delete(self, path: str, timeout: int = 60) -> Dict[str, Any]:
        resp = self.session.delete(self._url(path), timeout=timeout)
        self._raise_for_resp(resp, "DELETE", path)
        return self._json_or_empty(resp) or {"status": "ok"}

    # ---------------------------
    # Paging helpers
    # ---------------------------

    def _get_pages(
        self,
        path: str,
        params: Optional[dict] = None,
        *,
        page_size: int = 1000,
        timeout: int = 60,
        max_pages: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        p = dict(params or {})
        p.setdefault("page_size", page_size)

        pages = 0
        cursor = None

        while True:
            if cursor:
                p["cursor"] = cursor
            else:
                p.pop("cursor", None)

            page = self._get(path, params=p, timeout=timeout)
            yield page

            pages += 1
            if max_pages is not None and pages >= max_pages:
                return

            cursor = page.get("cursor")
            if not cursor:
                return

    def _get_all_results(
        self,
        path: str,
        params: Optional[dict] = None,
        *,
        page_size: int = 1000,
        timeout: int = 60,
        item_key: str = "results",
        max_items: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        all_items: List[Dict[str, Any]] = []

        for page in self._get_pages(
            path,
            params=params,
            page_size=page_size,
            timeout=timeout,
        ):
            items = page.get(item_key, []) or []
            all_items.extend(items)

            if max_items is not None and len(all_items) >= max_items:
                return all_items[:max_items]

        return all_items

    # ---------------------------
    # Policy list methods
    # ---------------------------

    def list_domains(self, *, page_size: int = 1000, timeout: int = 60) -> List[Dict[str, Any]]:
        path = self._policy_path("/domains")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_groups(
        self,
        domain_id: str = "default",
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        path = self._policy_path(f"/domains/{domain_id}/groups")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_services(self, *, page_size: int = 1000, timeout: int = 60) -> List[Dict[str, Any]]:
        path = self._policy_path("/services")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_security_policies(
        self,
        domain_id: str = "default",
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_security_rules(
        self,
        security_policy_id: str,
        domain_id: str = "default",
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        path = self._policy_path(
            f"/domains/{domain_id}/security-policies/{security_policy_id}/rules"
        )
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_policy_group_members(
        self,
        domain_id: str,
        group_id: str,
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        path = self._policy_path(
            f"/domains/{domain_id}/groups/{group_id}/members/virtual-machines"
        )
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_policy_group_member_vms(
        self,
        group_id: str,
        domain_id: str,
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        return self.list_policy_group_members(
            domain_id=domain_id,
            group_id=group_id,
            page_size=page_size,
            timeout=timeout,
        )

    def list_policy_group_member_vms_all(
        self,
        domain_id: str,
        page_size: int = 1000,
    ) -> List[Dict[str, Any]]:
        groups = self.list_groups(domain_id=domain_id)
        result: List[Dict[str, Any]] = []

        for grp in groups:
            group_id = grp.get("id")
            if not group_id:
                continue

            try:
                members = self.list_policy_group_members(
                    domain_id=domain_id,
                    group_id=group_id,
                    page_size=page_size,
                )
                result.extend(members)
            except Exception as e:
                logging.error("Error processing group members for %s: %s", group_id, e)
                self.errors.append(str(e))

        return result

    # ---------------------------
    # Fabric LM-only methods
    # ---------------------------

    def _require_lm(self, feature: str):
        if self.federation_global:
            raise NsxApiError(
                400,
                f"{feature} is a Local Manager fabric API. "
                f"Use federation_global=False and point at an LM.",
            )

    def list_virtual_machines(
        self,
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        self._require_lm("list_virtual_machines")
        path = self._fabric_path("/fabric/virtual-machines")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_vm_vifs(
        self,
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        self._require_lm("list_vm_vifs")
        path = self._fabric_path("/fabric/vifs")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    # ---------------------------
    # NEW: Group member IP helpers
    # ---------------------------

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value.strip()))

    @classmethod
    def _collect_ips_recursive(cls, obj: Any) -> Set[str]:
        """
        Broad recursive IP collector for NSX VM/VIF payloads.

        This intentionally searches common IP/address fields because NSX payloads
        can vary by version and object type.
        """
        ips: Set[str] = set()

        def add_value(v: Any) -> None:
            if isinstance(v, str):
                candidate = v.strip()
                if cls._is_ipv4(candidate):
                    ips.add(candidate)
            elif isinstance(v, list):
                for item in v:
                    add_value(item)
            elif isinstance(v, dict):
                walk(v)

        def walk(x: Any) -> None:
            if isinstance(x, dict):
                for k, v in x.items():
                    kl = str(k).lower()
                    if "ip" in kl or "address" in kl:
                        add_value(v)
                    else:
                        if isinstance(v, (dict, list)):
                            walk(v)
            elif isinstance(x, list):
                for item in x:
                    walk(item)

        walk(obj)
        return ips

    @staticmethod
    def _extract_vm_id_from_member(member: Dict[str, Any]) -> Optional[str]:
        for key in (
            "external_id",
            "externalId",
            "target_id",
            "targetId",
            "compute_id",
            "computeId",
            "id",
        ):
            value = member.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        return None

    @staticmethod
    def _extract_vm_id_from_vm(vm: Dict[str, Any]) -> Optional[str]:
        for key in (
            "external_id",
            "externalId",
            "id",
            "instance_uuid",
            "instanceUuid",
            "bios_uuid",
            "biosUuid",
        ):
            value = vm.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        return None

    @staticmethod
    def _extract_vm_id_from_vif(vif: Dict[str, Any]) -> Optional[str]:
        for key in (
            "owner_vm_id",
            "ownerVmId",
            "vm_id",
            "vmId",
            "external_id",
            "externalId",
            "owner_id",
            "ownerId",
        ):
            value = vif.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        owner = vif.get("owner")
        if isinstance(owner, dict):
            for key in ("target_id", "targetId", "id", "external_id", "externalId"):
                value = owner.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

        attachment = vif.get("attachment")
        if isinstance(attachment, dict):
            for key in ("owner_vm_id", "ownerVmId", "vm_id", "vmId", "id"):
                value = attachment.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

        return None

    def build_vm_ip_index(
        self,
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> Dict[str, List[str]]:
        """
        Build a VM ID -> IP list index using fabric VMs and VIFs.

        Must be run against a Local Manager with federation_global=False.
        """
        self._require_lm("build_vm_ip_index")

        vm_ips: Dict[str, Set[str]] = {}

        logging.info("Building VM IP index from fabric VMs")
        for vm in self.list_virtual_machines(page_size=page_size, timeout=timeout):
            vm_id = self._extract_vm_id_from_vm(vm)
            if not vm_id:
                continue

            ips = self._collect_ips_recursive(vm)
            if ips:
                vm_ips.setdefault(vm_id, set()).update(ips)

        logging.info("Building VM IP index from fabric VIFs")
        for vif in self.list_vm_vifs(page_size=page_size, timeout=timeout):
            vm_id = self._extract_vm_id_from_vif(vif)
            if not vm_id:
                continue

            ips = self._collect_ips_recursive(vif)
            if ips:
                vm_ips.setdefault(vm_id, set()).update(ips)

        return {vm_id: sorted(ips) for vm_id, ips in vm_ips.items()}

    def list_group_member_vm_ids(
        self,
        group_id: str,
        domain_id: str = "default",
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> List[str]:
        """
        Return VM IDs for the evaluated members of a policy group.
        """
        members = self.list_policy_group_members(
            domain_id=domain_id,
            group_id=group_id,
            page_size=page_size,
            timeout=timeout,
        )

        vm_ids: Set[str] = set()

        for member in members:
            if not isinstance(member, dict):
                continue

            vm_id = self._extract_vm_id_from_member(member)
            if vm_id:
                vm_ids.add(vm_id)

        return sorted(vm_ids)

    def get_group_member_vm_ips(
        self,
        group_id: str,
        domain_id: str = "default",
        *,
        page_size: int = 1000,
        timeout: int = 60,
        vm_ip_index: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, List[str]]:
        """
        Return VM IDs and IP addresses for evaluated members of a group.

        Returns:
          {
            "vm-external-id-1": ["10.1.1.10"],
            "vm-external-id-2": ["10.1.1.11", "10.1.1.12"]
          }

        Best practice:
          Build vm_ip_index once and pass it in when looping many groups.
        """
        self._require_lm("get_group_member_vm_ips")

        vm_ids = self.list_group_member_vm_ids(
            group_id=group_id,
            domain_id=domain_id,
            page_size=page_size,
            timeout=timeout,
        )

        if not vm_ids:
            return {}

        if vm_ip_index is None:
            vm_ip_index = self.build_vm_ip_index(
                page_size=page_size,
                timeout=timeout,
            )

        result: Dict[str, List[str]] = {}

        for vm_id in vm_ids:
            ips = vm_ip_index.get(vm_id, [])
            if ips:
                result[vm_id] = sorted(set(ips))

        return result

    def get_group_member_ips(
        self,
        group_id: str,
        domain_id: str = "default",
        *,
        page_size: int = 1000,
        timeout: int = 60,
        vm_ip_index: Optional[Dict[str, List[str]]] = None,
    ) -> List[str]:
        """
        Return a flat, deduped list of IPs for evaluated VM members of a group.
        """
        vm_to_ips = self.get_group_member_vm_ips(
            group_id=group_id,
            domain_id=domain_id,
            page_size=page_size,
            timeout=timeout,
            vm_ip_index=vm_ip_index,
        )

        ips: Set[str] = set()
        for values in vm_to_ips.values():
            ips.update(values)

        return sorted(ips)

    # ---------------------------
    # Update / Upsert helpers
    # ---------------------------

    def get_group(
        self,
        group_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/groups/{group_id}")
        return self._get(path, timeout=timeout)

    def put_group(
        self,
        group_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/groups/{group_id}")
        return self._put(path, payload, timeout=timeout)

    def patch_group(
        self,
        group_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/groups/{group_id}")
        return self._patch(path, payload, timeout=timeout)

    def delete_group(
        self,
        group_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/groups/{group_id}")
        return self._delete(path, timeout=timeout)

    def get_service(self, service_id: str, timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/services/{service_id}")
        return self._get(path, timeout=timeout)

    def put_service(self, service_id: str, payload: Dict[str, Any], timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/services/{service_id}")
        return self._put(path, payload, timeout=timeout)

    def patch_service(self, service_id: str, payload: Dict[str, Any], timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/services/{service_id}")
        return self._patch(path, payload, timeout=timeout)

    def delete_service(self, service_id: str, timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/services/{service_id}")
        return self._delete(path, timeout=timeout)

    def get_security_policy(
        self,
        security_policy_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}")
        return self._get(path, timeout=timeout)

    def put_security_policy(
        self,
        security_policy_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}")
        return self._put(path, payload, timeout=timeout)

    def patch_security_policy(
        self,
        security_policy_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}")
        return self._patch(path, payload, timeout=timeout)

    def delete_security_policy(
        self,
        security_policy_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}")
        return self._delete(path, timeout=timeout)

    def get_security_rule(
        self,
        security_policy_id: str,
        rule_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(
            f"/domains/{domain_id}/security-policies/{security_policy_id}/rules/{rule_id}"
        )
        return self._get(path, timeout=timeout)

    def put_security_rule(
        self,
        security_policy_id: str,
        rule_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(
            f"/domains/{domain_id}/security-policies/{security_policy_id}/rules/{rule_id}"
        )
        return self._put(path, payload, timeout=timeout)

    def patch_security_rule(
        self,
        security_policy_id: str,
        rule_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(
            f"/domains/{domain_id}/security-policies/{security_policy_id}/rules/{rule_id}"
        )
        return self._patch(path, payload, timeout=timeout)

    def delete_security_rule(
        self,
        security_policy_id: str,
        rule_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(
            f"/domains/{domain_id}/security-policies/{security_policy_id}/rules/{rule_id}"
        )
        return self._delete(path, timeout=timeout)