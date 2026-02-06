from __future__ import annotations

import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone
import json
import yaml

from utilities.file_utilities import write_json, write_yaml, manager_dirname

from nsx.nsx_constants import nsx_gm1, nsx_lm1, nsx_lm2, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("export_domains")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export NSX domains")
    parser.add_argument("--manager", choices=["nsx-gm1", "nsx-lm1", "nsx-lm2"], default="nsx-gm1")
    parser.add_argument("--federation-global", action="store_true", default=True)
    parser.add_argument("--output-format", choices=["yaml", "json", "both"], default="yaml")
    parser.add_argument("--base-dir", default="nsx_export")
    args = parser.parse_args()

    mgr_map = {
        "nsx-gm1": nsx_gm1,
        "nsx-lm1": nsx_lm1,
        "nsx-lm2": nsx_lm2,
    }

    manager_host = resolve_manager(args.manager)

    client = NsxPolicyClient(
        nsxmanager=manager_host,
        federation_global=args.federation_global,
    )

    log.info("NSX_MANAGER=%s", client.NSX_MANAGER)
    log.info("POLICY_ROOT=%s", client.POLICY_ROOT)

    domains = client.list_domains(page_size=1000)

    export_root = Path(args.base_dir) / manager_dirname(client)
    out_dir = export_root / "domains"

    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "manager": client.NSX_MANAGER,
        "federation_global": client.federation_global,
        "domains": [
            {
                "id": d.get("id"),
                "display_name": d.get("display_name") or d.get("name"),
                "description": d.get("description"),
                "path": d.get("path"),
                "_system_owned": d.get("_system_owned"),
            }
            for d in domains
        ],
    }

    if args.output_format in ("yaml", "both"):
        write_yaml(out_dir / "domains.yaml", payload)

    if args.output_format in ("json", "both"):
        write_json(out_dir / "domains.json", payload)

    print(f"Exported {len(domains)} domains to {out_dir}")


if __name__ == "__main__":
    main()