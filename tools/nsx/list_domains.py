#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import yaml

from nsx.nsx_constants import nsx_gm1, nsx_lm1, nsx_lm2, resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient  # uses YOUR class

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("list_domains")


def _write_outputs(out: Dict[str, Any], outdir: Path, fmt: str) -> None:
    outdir.mkdir(parents=True, exist_ok=True)

    if fmt in ("json", "both"):
        (outdir / "domains.json").write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")

    if fmt in ("yaml", "both"):
        (outdir / "domains.yaml").write_text(yaml.safe_dump(out, sort_keys=False), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="List NSX domains using NsxPolicyClient")
    parser.add_argument("--manager", choices=["nsx-gm1", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"], default="nsx-lm1")
    parser.add_argument("--federation-global", action="store_true", help="Use GM global-infra endpoints")
    parser.add_argument("--output", choices=["none", "json", "yaml", "both"], default="none")
    parser.add_argument("--outdir", default="nsx_domain_meta", help="Where to write domains.yaml/domains.json")
    args = parser.parse_args()

    manager_host = resolve_manager(args.manager)

    if not manager_host:
        raise RuntimeError(f"NSX manager host is not set for {args.manager}. Check your .env.")

    client = NsxPolicyClient(
        nsxmanager=manager_host,
        federation_global=args.federation_global,
    )

    client = NsxPolicyClient(nsxmanager=manager_host, federation_global=args.federation_global)

    # Helpful debug so you KNOW what you're calling
    log.info("NSX_MANAGER=%s", getattr(client, "NSX_MANAGER", None))
    log.info("federation_global=%s", getattr(client, "federation_global", None))
    log.info("POLICY_ROOT=%s", getattr(client, "POLICY_ROOT", None))

    domains: List[Dict[str, Any]] = client.list_domains(page_size=1000)

    # Print a clean summary
    print(f"\nDomains returned: {len(domains)}\n")
    for d in domains:
        did = d.get("id")
        name = d.get("display_name") or d.get("name") or ""
        desc = d.get("description") or ""
        print(f"- id={did}  name={name}  desc={desc}".rstrip())

    out = {
        "manager": manager_host,
        "federation_global": bool(args.federation_global),
        "policy_root": getattr(client, "POLICY_ROOT", None),
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

    if args.output != "none":
        _write_outputs(out, Path(args.outdir), args.output)
        print(f"\nWrote outputs to: {Path(args.outdir).resolve()}\n")


if __name__ == "__main__":
    main()