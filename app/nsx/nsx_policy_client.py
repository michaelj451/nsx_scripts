#!/usr/bin/env python3
# app/nsx/nsx_policy_client.py
import requests
import logging
from fastapi import HTTPException
from typing import Any, Dict, Iterator, List, Optional

from nsx.nsx_constants import nsx_gm1, nsx_lm1, nsx_lm2, nsx_username, nsx_password

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NsxPolicyClient:
    def __init__(self, nsxmanager: str = nsx_lm2, *, federation_global: bool = False):
        logging.info(f"Creating NSX session for manager: {nsxmanager} (federation_global={federation_global})")

        self.NSX_MANAGER = f"https://{nsxmanager}"
        self.USERNAME = nsx_username
        self.PASSWORD = nsx_password
        self.federation_global = federation_global

        # Decide if this host is a GM endpoint
        mgr_norm = (nsxmanager or "").strip().removeprefix("https://").removeprefix("http://").rstrip("/").lower()
        gm_hosts = {  # keep in nsx_constants ideally
            (nsx_gm1 or "").lower(),
            # add nsx_gm2 if you have it, etc.
        }
        is_gm = mgr_norm in gm_hosts

        # Policy API root depends on (GM vs LM) and federation mode
        if federation_global:
            # Federation "global-infra" view:
            # - GM uses /global-manager/api/v1/global-infra
            # - LM exposes a local read-only view at /policy/api/v1/global-infra
            self.POLICY_ROOT = "/global-manager/api/v1/global-infra" if is_gm else "/policy/api/v1/global-infra"
        else:
            # Local manager policy store
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
        s.verify = False  # NOTE: your original behavior. Consider mounting CA instead.
        s.headers.update({"Accept": "application/json"})

        login_resp = s.post(
            f"{self.NSX_MANAGER}/api/session/create",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"j_username": self.USERNAME, "j_password": self.PASSWORD},
            timeout=15,
        )

        if not login_resp.ok:
            raise HTTPException(
                status_code=401,
                detail=f"NSX login failed: {login_resp.status_code} {login_resp.text}",
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
            raise HTTPException(
                status_code=resp.status_code,
                detail=f"NSX {method} failed {path}: {resp.status_code} {resp.text}",
            )

    def _json_or_empty(self, resp) -> Dict[str, Any]:
        if not resp.text:
            return {}
        try:
            return resp.json()
        except Exception:
            # Some NSX responses can be empty/odd; keep it safe.
            return {"raw": resp.text}

    def _get(self, path: str, params: Optional[dict] = None, timeout: int = 30) -> Dict[str, Any]:
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
    # Paging helpers (cursor-based)
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
        """
        Yields each page dict returned by NSX Policy API list endpoints.
        Handles cursor-based pagination.
        """
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
        """
        Returns a single list containing all items across all pages.
        """
        all_items: List[Dict[str, Any]] = []
        for page in self._get_pages(path, params=params, page_size=page_size, timeout=timeout):
            items = page.get(item_key, []) or []
            all_items.extend(items)

            if max_items is not None and len(all_items) >= max_items:
                return all_items[:max_items]

        return all_items

    # ---------------------------
    # Concrete list methods (Policy)
    # ---------------------------
    def list_domains(self, *, page_size: int = 1000, timeout: int = 60) -> List[Dict[str, Any]]:
        path = self._policy_path("/domains")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_groups(self, domain_id: str = "default", *, page_size: int = 1000, timeout: int = 60) -> List[Dict[str, Any]]:
        path = self._policy_path(f"/domains/{domain_id}/groups")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_services(self, *, page_size: int = 1000, timeout: int = 60) -> List[Dict[str, Any]]:
        path = self._policy_path("/services")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_security_policies(self, domain_id: str = "default", *, page_size: int = 1000, timeout: int = 60) -> List[Dict[str, Any]]:
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
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}/rules")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_policy_group_members(
        self,
        domain_id: str,
        group_id: str,
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        # NOTE: This endpoint exists on LM. On GM, group membership is evaluated per site and may not be directly listable the same way.
        # We'll still attempt it; if GM rejects it, you’ll get a clear HTTPException.
        path = self._policy_path(f"/domains/{domain_id}/groups/{group_id}/members/virtual-machines")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_policy_group_member_vms(
        self,
        group_id: str,
        domain_id: str,
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        path = self._policy_path(f"/domains/{domain_id}/groups/{group_id}/members/virtual-machines")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_policy_group_member_vms_all(self, domain_id: str, page_size: int = 1000) -> List[Dict[str, Any]]:
        groups = self.list_groups(domain_id=domain_id)
        result: List[Dict[str, Any]] = []
        try:
            for grp in groups:
                group_id = grp.get("id")
                if not group_id:
                    continue
                members_payload = self.list_policy_group_members(domain_id=domain_id, group_id=group_id, page_size=page_size)
                result.extend(members_payload)
        except Exception as e:
            logging.error(f"Error processing group members: {e}")
            self.errors.append(str(e))

        return result

    # ---------------------------
    # Fabric (LM-only) list methods
    # ---------------------------
    def _require_lm(self, feature: str):
        if self.federation_global:
            raise HTTPException(
                status_code=400,
                detail=f"{feature} is a Local Manager fabric API. Use federation_global=False and point at an LM.",
            )

    def list_virtual_machines(self, *, page_size: int = 1000, timeout: int = 60) -> List[Dict[str, Any]]:
        self._require_lm("list_virtual_machines")
        path = self._fabric_path("/fabric/virtual-machines")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_vm_vifs(self, *, page_size: int = 1000, timeout: int = 60) -> List[Dict[str, Any]]:
        self._require_lm("list_vm_vifs")
        path = self._fabric_path("/fabric/vifs")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    # ---------------------------
    # Update / Upsert helpers (Policy)
    # ---------------------------
    def get_group(self, group_id: str, domain_id: str = "default", timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/groups/{group_id}")
        return self._get(path, timeout=timeout)

    def put_group(self, group_id: str, payload: Dict[str, Any], domain_id: str = "default", timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/groups/{group_id}")
        return self._put(path, payload, timeout=timeout)

    def patch_group(self, group_id: str, payload: Dict[str, Any], domain_id: str = "default", timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/groups/{group_id}")
        return self._patch(path, payload, timeout=timeout)

    def delete_group(self, group_id: str, domain_id: str = "default", timeout: int = 60) -> Dict[str, Any]:
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

    def get_security_policy(self, security_policy_id: str, domain_id: str = "default", timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}")
        return self._get(path, timeout=timeout)

    def put_security_policy(self, security_policy_id: str, payload: Dict[str, Any], domain_id: str = "default", timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}")
        return self._put(path, payload, timeout=timeout)

    def patch_security_policy(self, security_policy_id: str, payload: Dict[str, Any], domain_id: str = "default", timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}")
        return self._patch(path, payload, timeout=timeout)

    def delete_security_policy(self, security_policy_id: str, domain_id: str = "default", timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}")
        return self._delete(path, timeout=timeout)

    def get_security_rule(
        self,
        security_policy_id: str,
        rule_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}/rules/{rule_id}")
        return self._get(path, timeout=timeout)

    def put_security_rule(
        self,
        security_policy_id: str,
        rule_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}/rules/{rule_id}")
        return self._put(path, payload, timeout=timeout)

    def patch_security_rule(
        self,
        security_policy_id: str,
        rule_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}/rules/{rule_id}")
        return self._patch(path, payload, timeout=timeout)

    def delete_security_rule(
        self,
        security_policy_id: str,
        rule_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{domain_id}/security-policies/{security_policy_id}/rules/{rule_id}")
        return self._delete(path, timeout=timeout)