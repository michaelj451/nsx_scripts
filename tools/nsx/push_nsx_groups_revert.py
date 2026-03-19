#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------

DEFAULT_STRIP_KEYS = {
    "_create_time",
    "_create_user",
    "_last_modified_time",
    "_last_modified_user",
    "_links",
    "_protection",
    "_schema",
    "_self",
    "_system_owned",
    "_revision",
    "revision",
    "realization_id",
    "unique_id",
    "marked_for_delete",
    "remote_path",
    "overridden",
    "origin_site_id",
    "owner_id",
}


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------

class NsxPolicyRollbackClient:
    def __init__(
        self,
        manager: str,
        username: str,
        password: str,
        *,
        federation_global: bool = False,
        verify_ssl: bool = False,
        timeout: int = 30,
    ) -> None:
        self.manager = manager.rstrip("/")
        self.username = username
        self.password = password
        self.federation_global = federation_global
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        if self.federation_global:
            # GM Policy API
            self.base_url = f"{self.manager}/global-manager/api/v1"
        else:
            # LM Policy API
            self.base_url = f"{self.manager}/policy/api/v1"

        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = self.verify_ssl
        self.session.headers.update({"Content-Type": "application/json"})

    def request(
        self,
        method: str,
        path: str,
        *,
        expected: Tuple[int, ...] = (200,),
        data: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        resp = self.session.request(
            method=method,
            url=url,
            json=data,
            timeout=self.timeout,
        )

        if resp.status_code not in expected:
            raise RuntimeError(
                f"{method} {url} failed: HTTP {resp.status_code} - {resp.text}"
            )

        if not resp.text.strip():
            return None

        ctype = resp.headers.get("Content-Type", "")
        if "application/json" in ctype:
            return resp.json()

        return resp.text

    def list_groups(self, domain_id: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            path = f"/infra/domains/{domain_id}/groups"
            if cursor:
                path += f"?cursor={cursor}"

            payload = self.request("GET", path, expected=(200,))
            page_results = payload.get("results", [])
            results.extend(page_results)

            cursor = payload.get("cursor")
            if not cursor:
                break

        return results

    def get_group(self, domain_id: str, group_id: str) -> Optional[Dict[str, Any]]:
        try:
            return self.request(
                "GET",
                f"/infra/domains/{domain_id}/groups/{group_id}",
                expected=(200,),
            )
        except RuntimeError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise

    def patch_group(self, domain_id: str, group_id: str, payload: Dict[str, Any]) -> None:
        self.request(
            "PATCH",
            f"/infra/domains/{domain_id}/groups/{group_id}",
            expected=(200, 201),
            data=payload,
        )

    def delete_group(self, domain_id: str, group_id: str) -> None:
        self.request(
            "DELETE",
            f"/infra/domains/{domain_id}/groups/{group_id}",
            expected=(200, 204),
        )


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def load_file(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def clean_payload(obj: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = {}
    for k, v in obj.items():
        if k in DEFAULT_STRIP_KEYS:
            continue
        cleaned[k] = v
    return cleaned


def discover_group_files(export_root: Path, domain_id: str) -> List[Path]:
    candidates = [
        export_root / domain_id / "groups",
        export_root / "domains" / domain_id / "groups",
    ]

    for root in candidates:
        if root.exists():
            files = sorted(
                [p for p in root.iterdir() if p.is_file() and p.suffix.lower() in {".yaml", ".yml", ".json"}]
            )
            return files

    raise FileNotFoundError(
        f"Could not find group export folder under either:\n"
        f"  {candidates[0]}\n"
        f"  {candidates[1]}"
    )


def load_desired_groups(export_root: Path, domain_id: str) -> Dict[str, Dict[str, Any]]:
    desired: Dict[str, Dict[str, Any]] = {}

    for path in discover_group_files(export_root, domain_id):
        obj = load_file(path)
        if not obj:
            continue

        group_id = obj.get("id")
        if not group_id:
            log.warning("Skipping %s because it has no 'id'", path)
            continue

        desired[group_id] = clean_payload(obj)

    return desired


def summarize_changes(
    existing_ids: set[str],
    desired_ids: set[str],
) -> Tuple[List[str], List[str], List[str]]:
    to_create = sorted(desired_ids - existing_ids)
    to_update = sorted(desired_ids & existing_ids)
    to_delete = sorted(existing_ids - desired_ids)
    return to_create, to_update, to_delete


# -----------------------------------------------------------------------------
# Main rollback logic
# -----------------------------------------------------------------------------

def rollback_groups(
    client: NsxPolicyRollbackClient,
    export_root: Path,
    domain_id: str,
    *,
    dry_run: bool = True,
    delete_extraneous: bool = False,
) -> None:
    desired = load_desired_groups(export_root, domain_id)
    if not desired:
        log.warning("No desired groups found in export set")
        return

    existing_groups = client.list_groups(domain_id)
    existing = {g["id"]: g for g in existing_groups if "id" in g}

    desired_ids = set(desired.keys())
    existing_ids = set(existing.keys())

    to_create, to_update, to_delete = summarize_changes(existing_ids, desired_ids)

    log.info("Rollback summary for domain '%s':", domain_id)
    log.info("  desired groups : %d", len(desired_ids))
    log.info("  existing groups: %d", len(existing_ids))
    log.info("  create         : %d", len(to_create))
    log.info("  update         : %d", len(to_update))
    log.info("  delete extra   : %d", len(to_delete) if delete_extraneous else 0)

    if dry_run:
        for gid in to_create:
            log.info("[DRY-RUN] would create group: %s", gid)
        for gid in to_update:
            log.info("[DRY-RUN] would update group: %s", gid)
        if delete_extraneous:
            for gid in to_delete:
                log.info("[DRY-RUN] would delete extraneous group: %s", gid)
        return

    # Restore all desired groups
    for gid in sorted(desired.keys()):
        payload = desired[gid]
        log.info("Restoring group: %s", gid)
        client.patch_group(domain_id, gid, payload)

    # Optionally delete groups that are not part of snapshot
    if delete_extraneous:
        for gid in to_delete:
            log.info("Deleting extraneous group: %s", gid)
            try:
                client.delete_group(domain_id, gid)
            except Exception as exc:
                log.error("Failed deleting %s: %s", gid, exc)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Rollback NSX Policy groups from exported files")
    p.add_argument("--manager", required=True, help="NSX manager URL, ex: https://nsx-gm2.lab.local")
    p.add_argument("--username", required=True, help="NSX username")
    p.add_argument("--password", required=True, help="NSX password")
    p.add_argument("--export-root", required=True, help="Export root folder")
    p.add_argument("--domain-id", default="default", help="NSX domain ID")
    p.add_argument(
        "--federation-global",
        action="store_true",
        help="Use Global Manager API base path",
    )
    p.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify TLS certificate",
    )
    p.add_argument(
        "--delete-extraneous",
        action="store_true",
        help="Delete groups that exist in NSX but are not in the rollback snapshot",
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help="Actually make changes. Default is dry-run.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)

    client = NsxPolicyRollbackClient(
        manager=args.manager,
        username=args.username,
        password=args.password,
        federation_global=args.federation_global,
        verify_ssl=args.verify_ssl,
    )

    rollback_groups(
        client=client,
        export_root=Path(args.export_root),
        domain_id=args.domain_id,
        dry_run=not args.apply,
        delete_extraneous=args.delete_extraneous,
    )


if __name__ == "__main__":
    main()