import grp
import requests
import json
import urllib3
import logging
import os
from typing import Any, Dict, List, Optional, Set
from frontendFastapi.nsx.nsx_constants import nsx_manager1, nsx_username, nsx_password, nsx_manager1, nsx_manager2
from frontendFastapi.nsx.nsx_db_functions.nsx_db_functions_group_members import NsxPolicyGroupMembersSync
from frontendFastapi.nsx.nsx_db_functions.nsx_db_functions_rules import NsxPolicyRulesSync
from frontendFastapi.nsx.schemas.nsx_schema_vms import (
    NsxVm,
    NsxVmRenameMapping,
    mapping_row_from_vm,
)
from frontendFastapi.nsx.nsx_policy_client import NsxPolicyClient
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from sqlalchemy import func


from fastapi import HTTPException

log = logging.getLogger("root")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)

def get_nsx1_policy_client() -> NsxPolicyClient:
    return NsxPolicyClient(nsxmanager=nsx_manager1)

def get_nsx2_policy_client() -> NsxPolicyClient:
    return NsxPolicyClient(nsxmanager=nsx_manager2)

class NSXtoken:

    def __init__(self, dc: str = "nsx-lab", nsxmanager: str = nsx_manager1):

        logging.info(f"Creating NSXtoken for manager: {nsxmanager}")

        self.dc = dc
        self.NSX_MANAGER = f'https://{nsxmanager}'
        self.USERNAME = nsx_username
        self.PASSWORD = nsx_password

        self.session, self.xsrf_token = self.get_nsx_session()

    def get_nsx_session(self):
        s = requests.Session()
        s.verify = False
        s.headers.update({"Accept": "application/json"})

        login_resp = s.post(
            f"{self.NSX_MANAGER}/api/session/create",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "j_username": self.USERNAME,
                "j_password": self.PASSWORD,
            },
            timeout=15,
        )

        if not login_resp.ok:
            raise HTTPException(
                status_code=401,
                detail=f"NSX login failed: {login_resp.status_code} {login_resp.text}",
            )

        # XSRF may be header OR cookie depending on build/config
        xsrf_token = (
            login_resp.headers.get("X-XSRF-TOKEN")
            or s.cookies.get("XSRF-TOKEN")
            or s.cookies.get("XSRF-TOKEN".lower())  # harmless fallback
        )

        if xsrf_token:
            # header name NSX expects for writes
            s.headers["X-XSRF-TOKEN"] = xsrf_token

        return s, xsrf_token
    
    def reset_edge_vm_placement(self):
        tn_id = "e0e27fd1-d02f-4bb2-9351-d558fb9b150c"
        vm_id = "vm-1018"

        # GET transport node
        tn = self.session.get(f"{self.NSX_MANAGER}/api/v1/transport-nodes/{tn_id}", timeout=30)
        tn.raise_for_status()
        tn_json = tn.json()

        deploy_cfg = tn_json["node_deployment_info"]["deployment_config"]
        payload = {
            "vm_id": vm_id,
            "vm_deployment_config": deploy_cfg["vm_deployment_config"],
            "node_user_settings": deploy_cfg["node_user_settings"],
        }

        # POST placement fix (XSRF header already set on s)
        resp = self.session.post(
            f"{self.NSX_MANAGER}/api/v1/transport-nodes/{tn_id}?action=addOrUpdatePlacementReferences",
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        return {"status": "ok", "response": resp.text}
    
## THIS CLASS IS DEPRECATED IN FAVOR OF NsxPolicyClient ##
class NSX:
    def __init__(self, dc: str = "nsx-lab", nsxmanager: str = nsx_manager1):
        self.dc = dc
        self.base = f"https://{nsxmanager}"
        self.username = nsx_username
        self.password = nsx_password

        self.s = requests.Session()
        self.s.verify = False
        self.s.headers.update({"Accept": "application/json"})

        self.status = "success"
        self.total_added = 0
        self.total_disabled = 0
        self.errors = []

        self._login()

    def _login(self):
        # NSX Manager session cookie + XSRF token
        r = self.s.post(
            f"{self.base}/api/session/create",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"j_username": self.username, "j_password": self.password},
            timeout=15,
        )
        r.raise_for_status()

        xsrf = (
            r.headers.get("X-XSRF-TOKEN")
            or self.s.cookies.get("XSRF-TOKEN")
            or self.s.cookies.get("XSRF-TOKEN".lower())
        )
        if xsrf:
            self.s.headers["X-XSRF-TOKEN"] = xsrf

    def _get(self, path, params=None):
        url = f"{self.base}{path}"
        r = self.s.get(url, params=params, timeout=30)
        # If session expired, re-login once and retry
        try:
            if r.status_code in (401, 403):
                self._login()
                r = self.s.get(url, params=params, timeout=30)
            r.raise_for_status()
        except requests.HTTPError as e:
            logging.error(f"GET {url} failed: {e}")
            return f'{r.status_code}: {r.text}'
        return r.json()

    def _paged_get_policy(self, path: str, page_size: int = 1000) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            params = {"page_size": page_size}
            if cursor:
                params["cursor"] = cursor

            data = self._get(path, params=params) or {}
            results.extend(data.get("results", []))
            cursor = data.get("cursor")
            if not cursor:
                break

        return results


def get_policy_group_member_vms_all(nsxmanager: str, group_id: str, domain_id: str = "default", page_size: int = 1000) -> List[Dict[str, Any]]:
    
    nsx = NsxPolicyClient(nsxmanager=nsxmanager)
    groups = nsx.list_groups(domain_id=domain_id)

    result = []
    try:
        for grp in groups:
            group_id = grp.get("id")
            if not group_id:
                continue

            members_payload = nsx.list_policy_group_members(domain_id=domain_id, group_id=group_id, page_size=page_size)
            result.extend(members_payload)
    except Exception as e:
        logging.error(f"Error processing group members: {e}")
        nsx.status = "error"
        nsx.errors.append(str(e))

    return result

def get_group_tags_and_scopes(
    nsxmanager: str,
    domain_id: str = "default",
    page_size: int = 1000,
) -> List[Dict[str, Any]]:

    nsx = NsxPolicyClient(nsxmanager=nsxmanager)

    path = f"/policy/api/v1/infra/domains/{domain_id}/groups"
    res = nsx._get_all_results(path, page_size=page_size)

    # _get_all_results may return either:
    #  - a list of group dicts
    #  - OR a dict like {"results": [..]}
    if isinstance(res, list):
        groups = res
    elif isinstance(res, dict):
        groups = res.get("results", []) or []
    else:
        groups = []

    out: List[Dict[str, Any]] = []

    for grp in groups:
        group_id = grp.get("id")
        group_name = grp.get("display_name")

        # 1) metadata tags ON the group object
        for t in (grp.get("tags") or []):
            out.append({
                "group_id": group_id,
                "group_name": group_name,
                "tag_type": "group_metadata",
                "scope": t.get("scope"),
                "tag": t.get("tag"),
                "operator": None,
            })

        # 2) tag-based membership conditions
        for expr in (grp.get("expression") or []):
            if (
                expr.get("resource_type") == "Condition"
                and expr.get("key") == "Tag"
            ):
                out.append({
                    "group_id": group_id,
                    "group_name": group_name,
                    "tag_type": "membership_condition",
                    "scope": expr.get("scope"),
                    "tag": expr.get("value"),     # 'value' holds the tag value for Tag conditions
                    "operator": expr.get("operator"),
                })

    return out


### for VM migration testing ###

def resolve_new_vm_ids(
    session: Session,
    *,
    dc: str,
    target_nsx_manager: str = "nsx2",
    statuses: tuple[str, ...] = ("planned", "in_progress"),
    limit: int | None = None,
) -> dict[str, int]:
    """
    For mappings in dc with missing new_vm_id, find the NSX2 VM by new_vm_name and store vm_id into new_vm_id.
    """
    q = (
        session.query(NsxVmRenameMapping)
        .filter(NsxVmRenameMapping.dc == dc)
        .filter(NsxVmRenameMapping.enabled.is_(True))
        .filter(NsxVmRenameMapping.status.in_(statuses))
        .filter(NsxVmRenameMapping.new_vm_id.is_(None))
    )

    if limit:
        q = q.limit(limit)

    mappings = q.all()

    updated = 0
    missing = 0

    for m in mappings:
        new_vm = (
            session.query(NsxVm)
            .filter(
                NsxVm.dc == dc,
                NsxVm.nsx_manager == target_nsx_manager,
                NsxVm.display_name == m.new_vm_name,
                NsxVm.enabled.is_(True),
            )
            .first()
        )

        if not new_vm:
            missing += 1
            log.info(
                f"resolve_new_vm_ids: missing new VM in inventory "
                f"dc={dc} nsx_manager={target_nsx_manager} name={m.new_vm_name}"
            )
            continue

        m.new_vm_id = new_vm.vm_id
        m.target_nsx_manager = target_nsx_manager
        updated += 1

    session.commit()
    return {"updated": updated, "missing": missing, "processed": len(mappings)}

def populate_vm_rename_mappings(
    session: Session,
    *,
    dc: str | None = None,
    source_nsx_manager: str = "nsx1",
    only_regular: bool = True,
) -> int:
    """
    Populate ruledata.nsx_vm_rename_mappings from ruledata.nsx_vms.

    Deterministic, idempotent.

    - Pulls VMs from ONE source nsx_manager (default nsx1)
    - Optional dc scoping
    - Optional vm_type == 'REGULAR'
    """
    q = session.query(NsxVm).filter(NsxVm.enabled.is_(True))

    # ✅ scope to source manager inventory
    q = q.filter(NsxVm.nsx_manager == source_nsx_manager)

    # ✅ correct dc filter
    if dc:
        q = q.filter(NsxVm.dc == dc)

    # optional: only regular VMs
    if only_regular:
        q = q.filter(NsxVm.vm_type == "REGULAR")

    rows: list[dict] = []

    for vm in q.all():
        name = vm.display_name or ""
        if not name:
            continue
        if "-10.6." not in name:
            continue

        log.info(f"Processing VM for rename mapping: {name}")
        rows.append(mapping_row_from_vm(vm))

    if not rows:
        return 0

    stmt = insert(NsxVmRenameMapping).values(rows)

    stmt = stmt.on_conflict_do_update(
        constraint="uq_nsx_vm_rename_dc_old",
        set_={
            "new_vm_name": stmt.excluded.new_vm_name,
            "old_vm_id": stmt.excluded.old_vm_id,
            "old_ip": stmt.excluded.old_ip,
            "new_ip": stmt.excluded.new_ip,
            "mapping_updated": True,
            "updated_at": func.now(),
        },
    )

    result = session.execute(stmt)
    session.commit()
    return int(result.rowcount or 0)