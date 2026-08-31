#!/usr/bin/env python3
# app/nsx/nsx_policy_client.py

from __future__ import annotations

import logging
import os
import re
import threading
import time
from typing import Any, Dict, Iterator, List, Optional, Set
from urllib.parse import quote as _urlquote

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
    def __init__(self, nsxmanager: str = nsx_gm1, *, federation_global: bool = False,
                 max_rps: Optional[float] = None):
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

        # GM-only rule: a federation-global run talks to a Global Manager and
        # nothing else. Refusing here, before any HTTP session is opened,
        # makes it structurally impossible for ANY tool to open a session to
        # a Local Manager while --federation-global is in effect.
        if federation_global and not is_gm:
            raise NsxApiError(
                400,
                f"federation_global=True requires a Global Manager target; "
                f"'{nsxmanager}' is not a configured GM host (NSX_GM1/NSX_GM2). "
                f"A federation-global run never opens a session to a Local "
                f"Manager. Point at the GM, or drop federation_global for a "
                f"direct LM run.",
            )

        if federation_global:
            self.POLICY_ROOT = "/global-manager/api/v1/global-infra"
        else:
            self.POLICY_ROOT = "/policy/api/v1/infra"

        self.FABRIC_ROOT = "/api/v1"

        self.session, self.xsrf_token = self.get_nsx_session()
        self.session.headers.setdefault("Content-Type", "application/json")

        # Client-side rate limiting. Precedence: constructor param, then
        # NSX_API_MAX_RPS from .env, then the DEFAULT of 2 req/s. Set
        # NSX_API_MAX_RPS=0 (or max_rps=0) to disable pacing entirely.
        # Independently, 429/503 responses are retried with backoff honoring
        # Retry-After (NSX_API_RETRY_MAX attempts, default 5).
        DEFAULT_MAX_RPS = 2.0
        if max_rps is None:
            env_val = (os.getenv("NSX_API_MAX_RPS") or "").strip()
            if env_val == "":
                max_rps = DEFAULT_MAX_RPS
            else:
                try:
                    max_rps = float(env_val)
                except ValueError:
                    logging.getLogger(__name__).warning(
                        "NSX_API_MAX_RPS=%r is not a number; using default %.1f",
                        env_val, DEFAULT_MAX_RPS)
                    max_rps = DEFAULT_MAX_RPS
        self._min_interval = (1.0 / max_rps) if max_rps and max_rps > 0 else 0.0
        self._retry_max = int(os.getenv("NSX_API_RETRY_MAX") or 5)
        self._pace_lock = threading.Lock()
        self._last_request = 0.0
        if self._min_interval:
            level = (logging.DEBUG if max_rps == DEFAULT_MAX_RPS else logging.INFO)
            logging.getLogger(__name__).log(
                level, "NSX client rate limit: %.1f req/s (min interval %.3fs)",
                max_rps, self._min_interval)

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

    @staticmethod
    def _q(value: Any) -> str:
        """
        URL-encode an object id for safe interpolation into a URL path segment.

        NSX object ids legally include `(`, `)`, ` `, `,`, `&`, `+`, `'`, etc.
        (e.g. `App_00731__-_PCFS_Loan_Manager_(Ext_servers_1)`). Some of those
        are RFC 3986 "sub-delims" — technically allowed in paths but
        inconsistently handled by NSX and various HTTP intermediaries. The
        safest, most portable approach is to percent-encode every non-
        unreserved char before building the URL.

        Apply to every id-like value interpolated into a path:

            path = self._policy_path(f"/domains/{self._q(domain_id)}/groups/{self._q(group_id)}")

        Pure ASCII / alphanumeric / `.` / `_` / `-` / `~` pass through unchanged.
        """
        return _urlquote(str(value), safe="")

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

    def _pace(self) -> None:
        """Enforce the client-side minimum interval between requests."""
        if not self._min_interval:
            return
        with self._pace_lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

    def _send(self, send_fn, method: str, path: str):
        """Single choke point: pace every request; retry 429/503 with backoff,
        honoring the server's Retry-After header when present."""
        attempts = 0
        while True:
            self._pace()
            resp = send_fn()
            if resp.status_code in (429, 503) and attempts < self._retry_max:
                attempts += 1
                retry_after = 0.0
                try:
                    retry_after = float(resp.headers.get("Retry-After") or 0)
                except (TypeError, ValueError):
                    pass
                delay = retry_after or min(0.5 * (2 ** attempts), 10.0)
                logging.getLogger(__name__).warning(
                    "NSX %s %s throttled (HTTP %d); retry %d/%d in %.1fs",
                    method, path, resp.status_code, attempts, self._retry_max, delay)
                time.sleep(delay)
                continue
            self._raise_for_resp(resp, method, path)
            return resp

    def _get(
        self,
        path: str,
        params: Optional[dict] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        resp = self._send(
            lambda: self.session.get(self._url(path), params=params, timeout=timeout),
            "GET", path)
        return self._json_or_empty(resp)

    def _put(self, path: str, payload: dict, timeout: int = 60) -> Dict[str, Any]:
        resp = self._send(
            lambda: self.session.put(self._url(path), json=payload, timeout=timeout),
            "PUT", path)
        return self._json_or_empty(resp) or {"status": "ok"}

    def _patch(self, path: str, payload: dict, timeout: int = 60) -> Dict[str, Any]:
        resp = self._send(
            lambda: self.session.patch(self._url(path), json=payload, timeout=timeout),
            "PATCH", path)
        return self._json_or_empty(resp) or {"status": "ok"}

    def _post(self, path: str, payload: dict | None = None, timeout: int = 60) -> Dict[str, Any]:
        resp = self._send(
            lambda: self.session.post(self._url(path), json=payload, timeout=timeout),
            "POST", path)
        return self._json_or_empty(resp) or {"status": "ok"}

    def _delete(self, path: str, timeout: int = 60) -> Dict[str, Any]:
        resp = self._send(
            lambda: self.session.delete(self._url(path), timeout=timeout),
            "DELETE", path)
        return self._json_or_empty(resp) or {"status": "ok"}

    # ---------------------------
    # Federation helpers
    # ---------------------------

    def list_site_enforcement_points(self) -> Dict[str, str]:
        """GM only: {site_id: enforcement_point_path} for every federation site,
        from GET <POLICY_ROOT>/sites and .../sites/<id>/enforcement-points.

        Tools use this to proxy member and statistics queries THROUGH the GM
        (`enforcement_point_path=...`) so a federation-global run never opens
        a session to a Local Manager. When a site's enforcement-point list
        cannot be read, the conventional .../enforcement-points/default path
        is assumed for that site.
        """
        eps: Dict[str, str] = {}
        r = self._get(self.POLICY_ROOT + "/sites")
        for s in (r.get("results") or []):
            sid = s.get("id")
            if not sid:
                continue
            ep_path = None
            try:
                er = self._get(self.POLICY_ROOT + f"/sites/{self._q(sid)}/enforcement-points")
                found = er.get("results") or []
                if found:
                    ep_path = found[0].get("path")
            except NsxApiError as exc:
                logging.getLogger(__name__).warning(
                    "site %s: enforcement-point discovery failed (%s); "
                    "assuming .../enforcement-points/default", sid, str(exc)[:100])
            eps[sid] = ep_path or f"/global-infra/sites/{sid}/enforcement-points/default"
        return eps

    def list_site_lm_fqdns(self) -> Dict[str, str]:
        """GM only: {site_id: lm_fqdn} for every federation site, taken from
        GET <POLICY_ROOT>/sites `site_connection_info`. The LM addresses come
        from the GM's own site registry, NEVER from local configuration
        (.env aliases). When a site carries no connection info, the site id
        itself (which the GM also provided) is used; in most deployments the
        id already is the LM FQDN.
        """
        out: Dict[str, str] = {}
        r = self._get(self.POLICY_ROOT + "/sites")
        for s in (r.get("results") or []):
            sid = s.get("id")
            if not sid:
                continue
            fqdn = None
            for ci in (s.get("site_connection_info") or []):
                if ci.get("fqdn"):
                    fqdn = ci["fqdn"]
                    break
            out[sid] = fqdn or sid
        return out

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
        path = self._policy_path(f"/domains/{self._q(domain_id)}/groups")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_services(self, *, page_size: int = 1000, timeout: int = 60) -> List[Dict[str, Any]]:
        path = self._policy_path("/services")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_segments(self, *, page_size: int = 1000, timeout: int = 60) -> List[Dict[str, Any]]:
        """
        List all segments on the manager. Returns full segment objects including
        subnets, vlan_ids, transport_zone_path, connectivity_path, type, etc.

        Caller may not have permission to read segments (DFW-only roles); the
        caller is responsible for handling NsxApiError accordingly.
        """
        path = self._policy_path("/segments")
        return self._get_all_results(path, page_size=page_size, timeout=timeout)

    def list_security_policies(
        self,
        domain_id: str = "default",
        *,
        page_size: int = 1000,
        timeout: int = 60,
    ) -> List[Dict[str, Any]]:
        path = self._policy_path(f"/domains/{self._q(domain_id)}/security-policies")
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
            f"/domains/{self._q(domain_id)}/security-policies/{self._q(security_policy_id)}/rules"
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
            f"/domains/{self._q(domain_id)}/groups/{self._q(group_id)}/members/virtual-machines"
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

    def update_vm_tags(
        self,
        external_id: str,
        tags: List[Dict[str, str]],
        *,
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """
        Replace the tag set on a VM via the NSX fabric API.

        NSX semantics: this POST REPLACES the entire tag set for the given VM.
        Callers must do read-modify-write — fetch the current tags, mutate the
        list, then call this with the full intended set.

        Args:
            external_id: VM external_id (the BIOS UUID from vCenter)
            tags: full intended tag list, each entry like {"scope": "...", "tag": "..."}
        """
        self._require_lm("update_vm_tags")
        path = self._fabric_path("/fabric/virtual-machines?action=update_tags")
        payload = {"external_id": external_id, "tags": tags}
        return self._post(path, payload, timeout=timeout)

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
        path = self._policy_path(f"/domains/{self._q(domain_id)}/groups/{self._q(group_id)}")
        return self._get(path, timeout=timeout)

    def put_group(
        self,
        group_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{self._q(domain_id)}/groups/{self._q(group_id)}")
        return self._put(path, payload, timeout=timeout)

    def patch_group(
        self,
        group_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{self._q(domain_id)}/groups/{self._q(group_id)}")
        return self._patch(path, payload, timeout=timeout)

    def delete_group(
        self,
        group_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{self._q(domain_id)}/groups/{self._q(group_id)}")
        return self._delete(path, timeout=timeout)

    def get_service(self, service_id: str, timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/services/{self._q(service_id)}")
        return self._get(path, timeout=timeout)

    def put_service(self, service_id: str, payload: Dict[str, Any], timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/services/{self._q(service_id)}")
        return self._put(path, payload, timeout=timeout)

    def patch_service(self, service_id: str, payload: Dict[str, Any], timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/services/{self._q(service_id)}")
        return self._patch(path, payload, timeout=timeout)

    def delete_service(self, service_id: str, timeout: int = 60) -> Dict[str, Any]:
        path = self._policy_path(f"/services/{self._q(service_id)}")
        return self._delete(path, timeout=timeout)

    def get_security_policy(
        self,
        security_policy_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{self._q(domain_id)}/security-policies/{self._q(security_policy_id)}")
        return self._get(path, timeout=timeout)

    def put_security_policy(
        self,
        security_policy_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{self._q(domain_id)}/security-policies/{self._q(security_policy_id)}")
        return self._put(path, payload, timeout=timeout)

    def patch_security_policy(
        self,
        security_policy_id: str,
        payload: Dict[str, Any],
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{self._q(domain_id)}/security-policies/{self._q(security_policy_id)}")
        return self._patch(path, payload, timeout=timeout)

    def delete_security_policy(
        self,
        security_policy_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(f"/domains/{self._q(domain_id)}/security-policies/{self._q(security_policy_id)}")
        return self._delete(path, timeout=timeout)

    def get_security_rule(
        self,
        security_policy_id: str,
        rule_id: str,
        domain_id: str = "default",
        timeout: int = 60,
    ) -> Dict[str, Any]:
        path = self._policy_path(
            f"/domains/{self._q(domain_id)}/security-policies/{self._q(security_policy_id)}/rules/{self._q(rule_id)}"
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
            f"/domains/{self._q(domain_id)}/security-policies/{self._q(security_policy_id)}/rules/{self._q(rule_id)}"
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
            f"/domains/{self._q(domain_id)}/security-policies/{self._q(security_policy_id)}/rules/{self._q(rule_id)}"
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
            f"/domains/{self._q(domain_id)}/security-policies/{self._q(security_policy_id)}/rules/{self._q(rule_id)}"
        )
        return self._delete(path, timeout=timeout)

    def get_security_policy_statistics(
        self,
        security_policy_id: str,
        domain_id: str = "default",
        enforcement_point_path: Optional[str] = None,
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """Returns runtime statistics for every rule in a policy.

        Response shape (NSX policy API):
            {"results": [{"internal_rule_id": "...",
                          "rule": "/infra/.../rules/<rule-id>",
                          "rule_path": "/infra/.../rules/<rule-id>",
                          "hit_count": int,
                          "byte_count": int,
                          "packet_count": int,
                          "popularity_index": int,
                          "max_session_count": int,
                          "l7_accept_count": int,
                          "l7_reject_count": int,
                          "l7_reject_with_response_count": int,
                          "active_sessions_count": int,
                          "last_modified_time": int  # ms since epoch
                          ...}, ...]}

        enforcement_point_path defaults to the default enforcement point when
        omitted. Returns {} on 404 (some NSX builds 404 if the policy was just
        created and has no stats yet).
        """
        path = self._policy_path(
            f"/domains/{self._q(domain_id)}/security-policies/{self._q(security_policy_id)}/statistics"
        )
        params: Dict[str, str] = {}
        if enforcement_point_path:
            params["enforcement_point_path"] = enforcement_point_path
        try:
            return self._get(path, params=params, timeout=timeout)
        except NsxApiError as exc:
            if exc.status_code == 404:
                return {}
            raise

    def get_security_rule_statistics(
        self,
        security_policy_id: str,
        rule_id: str,
        domain_id: str = "default",
        enforcement_point_path: Optional[str] = None,
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """Returns runtime statistics for a single rule.

        Same field set as get_security_policy_statistics, but for one rule.
        Returns {} on 404.
        """
        path = self._policy_path(
            f"/domains/{self._q(domain_id)}/security-policies/{self._q(security_policy_id)}/rules/{self._q(rule_id)}/statistics"
        )
        params: Dict[str, str] = {}
        if enforcement_point_path:
            params["enforcement_point_path"] = enforcement_point_path
        try:
            return self._get(path, params=params, timeout=timeout)
        except NsxApiError as exc:
            if exc.status_code == 404:
                return {}
            raise