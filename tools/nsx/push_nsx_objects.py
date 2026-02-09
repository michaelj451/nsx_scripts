from __future__ import annotations

import argparse
import logging
from pathlib import Path

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_lm1, nsx_lm2, nsx_lm3, nsx_lm4
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_functions.nsx_object_importer import ImportConfig, NsxImporter

log = logging.getLogger(__name__)


def _manager_dirname(mgr: str) -> str:
    mgr = (mgr or "").strip()
    mgr = mgr.removeprefix("https://").removeprefix("http://").rstrip("/")
    return mgr or "unknown_manager"


def _resolve_export_root(base_dir: str, manager_name: str) -> Path:
    base = Path(base_dir)
    return base if base.name == manager_name else (base / manager_name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Import NSX objects from exported YAML/JSON into a target NSX manager")
    parser.add_argument("--source", choices=["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"], default="nsx-lm1")
    parser.add_argument("--target", choices=["nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"], default="nsx-lm2")
    parser.add_argument("--base-dir", default="nsx_export")
    parser.add_argument("--domain-id", default="default")
    parser.add_argument("--input-format", choices=["yaml", "json"], default="yaml")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--stop-on-error", action="store_true")
    parser.add_argument("--federation-global", action="store_true")

    args = parser.parse_args()

    init_cli()

    mgr_map = {
        "nsx-lm1": nsx_lm1,
        "nsx-lm2": nsx_lm2,
        "nsx-lm3": nsx_lm3,
        "nsx-lm4": nsx_lm4,
    }

    src_mgr = mgr_map.get(args.source)
    dst_mgr = mgr_map.get(args.target)

    if not src_mgr:
        raise RuntimeError(f"Source manager env var not set for {args.source} (check NSX_LM1/NSX_LM2).")
    if not dst_mgr:
        raise RuntimeError(f"Target manager env var not set for {args.target} (check NSX_LM1/NSX_LM2).")

    src_folder = _manager_dirname(src_mgr)
    export_root = _resolve_export_root(args.base_dir, src_folder)

    if not export_root.exists():
        raise RuntimeError(f"Export root does not exist: {export_root}")

    client = NsxPolicyClient(nsxmanager=dst_mgr, federation_global=args.federation_global)

    cfg = ImportConfig(
        export_root=export_root,
        domain_id=args.domain_id,
        input_format=args.input_format,
        dry_run=(not args.apply),
        continue_on_error=(not args.stop_on_error),
    )

    importer = NsxImporter(client=client, cfg=cfg)
    result = importer.import_all()

    log.info("Import complete. Stats=%s Errors=%d", result["stats"], len(result["errors"]))
    print(result)


if __name__ == "__main__":
    main()