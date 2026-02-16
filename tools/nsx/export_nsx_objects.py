#!/usr/bin/env python3
# tools/nsx/export_nsx_objects.py
from __future__ import annotations

from pathlib import Path
import argparse
import logging
import json
import shutil

from nsx.cli_bootstrap import init_cli
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_object_functions.nsx_object_exporter import run_export
from nsx.nsx_constants import resolve_manager

log = logging.getLogger(__name__)


def _resolve_manager_base(base_dir: str, manager_name: str) -> Path:
    """
    If base_dir already ends with manager_name, don't append it again.
    Examples:
      base_dir="nsx_export" -> nsx_export/nsx-gm1.lab.local
      base_dir="nsx_export/nsx-gm1.lab.local" -> nsx_export/nsx-gm1.lab.local
    """
    base = Path(base_dir)
    if base.name == manager_name:
        return base
    return base / manager_name


def _manager_dirname(manager_host: str) -> str:
    # Normalize "https://nsx-gm1.lab.local" -> "nsx-gm1.lab.local"
    return manager_host.replace("https://", "").rstrip("/")


def _extract_domain_ids(domains_payload) -> list[str]:
    """
    Accepts common shapes:
      - {"domains": [ { "id": "...", "path": "...", ... }, ... ], ...}
      - [ { "id": "..."} , ... ]
      - ["default", "prod", ...]
    Returns: list of domain IDs (strings)
    """
    if domains_payload is None:
        return []

    if isinstance(domains_payload, dict) and "domains" in domains_payload:
        domains_payload = domains_payload.get("domains", [])

    domain_ids: list[str] = []
    for d in domains_payload:
        if isinstance(d, str):
            domain_ids.append(d)
        elif isinstance(d, dict) and "id" in d:
            domain_ids.append(d["id"])
        else:
            domain_ids.append(getattr(d, "id"))
    return domain_ids


def _write_manager_manifest(
    manager_base: Path,
    manager_host: str,
    federation_global: bool,
    domains_payload,
) -> None:
    """
    Writes a small manifest at:
      <base-dir>/<manager>/_manifest.json
    """
    try:
        manifest = {
            "manager": manager_host,
            "federation_global": federation_global,
        }

        if isinstance(domains_payload, dict):
            for key in ("policy_root", "manager", "federation_global"):
                if key in domains_payload:
                    manifest[key] = domains_payload[key]
            if "domains" in domains_payload:
                manifest["domains"] = domains_payload["domains"]

        manager_base.mkdir(parents=True, exist_ok=True)
        (manager_base / "_manifest.json").write_text(
            json.dumps(manifest, indent=2),
            encoding="utf-8",
        )
    except Exception as e:
        log.warning("Failed to write manager manifest: %s", e)


def _purge_groups_output_dirs(manager_base: Path, domain_id: str) -> None:
    """
    Always delete pre-existing exported GROUP files for the target domain,
    for both supported layouts:

      NEW: <manager_base>/<domain_id>/groups
      OLD: <manager_base>/domains/<domain_id>/groups

    This prevents stale group files from lingering across exports.
    """
    candidates = [
        manager_base / domain_id / "groups",
        manager_base / "domains" / domain_id / "groups",
    ]

    for p in candidates:
        if p.exists():
            log.info("Deleting pre-existing groups directory: %s", p)
            shutil.rmtree(p)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export NSX Policy objects (groups, services, policies, rules) to YAML/JSON"
    )
    parser.add_argument(
        "--base-dir",
        default="nsx_export",
        help="Base output directory (default: nsx_export)",
    )
    parser.add_argument(
        "--domain-id",
        default="default",
        help="NSX Policy domain ID (default: default)",
    )
    parser.add_argument(
        "--federation-global",
        action="store_true",
        help="Use global federation endpoints",
    )
    parser.add_argument(
        "--manager",
        choices=["nsx-gm1", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        default="nsx-lm1",
        help="Which NSX manager to export from (default: nsx-lm1)",
    )
    parser.add_argument(
        "--output-format",
        choices=["yaml", "json", "both"],
        default="yaml",
        help="Output format for exported objects (default: yaml)",
    )
    parser.add_argument(
        "--all-domains",
        action="store_true",
        help="Export objects from all policy domains",
    )

    args = parser.parse_args()

    init_cli()

    manager_host = resolve_manager(args.manager)
    if not manager_host:
        raise RuntimeError(f"NSX manager host is not set for {args.manager}. Check your .env.")

    client = NsxPolicyClient(
        nsxmanager=manager_host,
        federation_global=args.federation_global,
    )

    manager_name = _manager_dirname(manager_host)
    manager_base = _resolve_manager_base(args.base_dir, manager_name)

    all_stats: dict[str, object] = {}

    if args.all_domains:
        domains_payload = client.list_domains()
        domain_ids = _extract_domain_ids(domains_payload)

        log.info("Found %d domains on %s", len(domain_ids), manager_name)

        _write_manager_manifest(manager_base, manager_host, args.federation_global, domains_payload)

        for domain_id in domain_ids:
            log.info("Exporting domain: %s (manager: %s)", domain_id, manager_name)

            # NEW: purge group output dirs for this domain before exporting
            _purge_groups_output_dirs(manager_base, domain_id)

            stats = run_export(
                client=client,
                base_dir=str(manager_base),
                domain_id=domain_id,
                output_format=args.output_format,
            )
            all_stats[domain_id] = stats

    else:
        # NEW: purge group output dirs for this domain before exporting
        _purge_groups_output_dirs(manager_base, args.domain_id)

        stats = run_export(
            client=client,
            base_dir=str(manager_base),
            domain_id=args.domain_id,
            output_format=args.output_format,
        )
        all_stats[args.domain_id] = stats

    log.info("NSX object export complete: %s", all_stats)
    print(all_stats)


if __name__ == "__main__":
    main()