#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:
    yaml = None


LOG = logging.getLogger("prepare_export_for_push")

SUPPORTED_EXTS = {".yaml", ".yml", ".json"}

DEFAULT_STRIP_KEYS = {
    "revision", "_revision",
    "unique_id", "realization_id",
    "marked_for_delete", "overridden",
    "create_time", "create_time_ms",
    "last_modified_time", "last_modified_time_ms",
    "create_user", "last_modified_user",
    "owner_id", "source",
    "remote_path",
    "origin_site_id",
    "owner_path",
}


@dataclass
class TransformConfig:
    input_root: Path
    output_root: Path
    source_domain: str
    target_domain: str
    target_scope: str  # "infra" or "global-infra"
    output_format: str  # "yaml", "json", "both"
    overwrite: bool = False
    copy_meta: bool = True


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def load_data(path: Path) -> Any:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")

    if suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is required to read YAML files")
        return yaml.safe_load(text)

    if suffix == ".json":
        return json.loads(text)

    raise ValueError(f"Unsupported file type: {path}")


def save_data(path: Path, data: Any, fmt: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "yaml":
        if yaml is None:
            raise RuntimeError("PyYAML is required to write YAML files")
        path.write_text(
            yaml.safe_dump(
                data,
                sort_keys=False,
                default_flow_style=False,
                width=120,
                allow_unicode=True,
            ),
            encoding="utf-8",
        )
        return

    if fmt == "json":
        path.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8",
        )
        return

    raise ValueError(f"Unsupported output format: {fmt}")


def sanitize_payload(raw: Any, strip_keys: Iterable[str] = DEFAULT_STRIP_KEYS) -> Any:
    def _walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k in strip_keys:
                    continue
                out[k] = _walk(v)
            return out
        if isinstance(obj, list):
            return [_walk(x) for x in obj]
        return obj

    return _walk(raw)


def replace_scope_and_domain_in_string(value: str, source_domain: str, target_domain: str, target_scope: str) -> str:
    """
    Rewrites:
      /infra/domains/<source_domain>/...
      /global-infra/domains/<source_domain>/...
    to:
      /<target_scope>/domains/<target_domain>/...
    Also rewrites exact domain-id string matches.
    """
    escaped_src = re.escape(source_domain)

    value = re.sub(
        rf"/(?:infra|global-infra)/domains/{escaped_src}(?=/|$)",
        f"/{target_scope}/domains/{target_domain}",
        value,
    )

    if value == source_domain:
        value = target_domain

    return value


def transform_payload(obj: Any, cfg: TransformConfig) -> Any:
    def _walk(x: Any) -> Any:
        if isinstance(x, dict):
            out = {}
            for k, v in x.items():
                new_v = _walk(v)

                # Fix explicit domain fields if present
                if k in {"domain_id", "domain"} and isinstance(new_v, str) and new_v == cfg.source_domain:
                    new_v = cfg.target_domain

                # Fix path-like scope fields
                if k in {"path", "parent_path", "relative_path"} and isinstance(new_v, str):
                    new_v = replace_scope_and_domain_in_string(
                        new_v,
                        source_domain=cfg.source_domain,
                        target_domain=cfg.target_domain,
                        target_scope=cfg.target_scope,
                    )

                out[k] = new_v
            return out

        if isinstance(x, list):
            return [_walk(i) for i in x]

        if isinstance(x, str):
            return replace_scope_and_domain_in_string(
                x,
                source_domain=cfg.source_domain,
                target_domain=cfg.target_domain,
                target_scope=cfg.target_scope,
            )

        return x

    cleaned = sanitize_payload(obj)
    return _walk(cleaned)


def iter_object_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for ext in SUPPORTED_EXTS:
        files.extend(root.rglob(f"*{ext}"))
    return sorted(files)


def relative_export_root(input_root: Path, source_domain: str) -> Path:
    """
    Expect exporter layout:
      <input_root>/domains/<source_domain>/...
    or allow pointing directly at:
      <input_root>/...
    where input_root already is the domain root.
    """
    domains_root = input_root / "domains" / source_domain
    if domains_root.exists():
        return domains_root

    # If caller points directly to the domain folder, accept that too
    if (input_root / "groups").exists() or (input_root / "security-policies").exists():
        return input_root

    raise FileNotFoundError(
        f"Could not find exported domain root. Expected either '{domains_root}' "
        f"or a direct domain folder containing groups/security-policies under '{input_root}'."
    )


def output_domain_root(output_root: Path, target_domain: str) -> Path:
    return output_root / "domains" / target_domain


def write_transformed_file(src: Path, src_domain_root: Path, dst_domain_root: Path, cfg: TransformConfig) -> None:
    rel = src.relative_to(src_domain_root)
    stem = src.stem

    data = load_data(src)
    transformed = transform_payload(data, cfg)

    if cfg.output_format in {"yaml", "both"}:
        save_data(dst_domain_root / rel.with_suffix(".yaml"), transformed, "yaml")

    if cfg.output_format in {"json", "both"}:
        save_data(dst_domain_root / rel.with_suffix(".json"), transformed, "json")


def copy_meta_if_present(input_root: Path, output_root: Path, cfg: TransformConfig) -> None:
    if not cfg.copy_meta:
        return

    for name in ("meta.yaml", "meta.yml", "meta.json"):
        src = input_root / name
        if src.exists():
            dst = output_root / src.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            LOG.info("Copied meta file: %s", src)


def build_push_manifests(dst_domain_root: Path) -> None:
    """
    Create simple manifest files that can help push scripts later.
    """
    groups = sorted(str(p.relative_to(dst_domain_root)) for p in (dst_domain_root / "groups").glob("*.yaml"))
    services = sorted(str(p.relative_to(dst_domain_root)) for p in (dst_domain_root / "services").glob("*.yaml"))

    policies: list[dict[str, Any]] = []
    pol_root = dst_domain_root / "security-policies"
    if pol_root.exists():
        for pol_dir in sorted(p for p in pol_root.iterdir() if p.is_dir()):
            rule_files = sorted(str(p.relative_to(dst_domain_root)) for p in (pol_dir / "rules").glob("*.yaml"))
            policies.append(
                {
                    "policy_dir": str(pol_dir.relative_to(dst_domain_root)),
                    "policy_file": str((pol_dir / "policy.yaml").relative_to(dst_domain_root))
                    if (pol_dir / "policy.yaml").exists()
                    else None,
                    "rules": rule_files,
                }
            )

    manifest = {
        "groups": groups,
        "services": services,
        "policies": policies,
    }

    save_data(dst_domain_root / "push_manifest.yaml", manifest, "yaml")
    save_data(dst_domain_root / "push_manifest.json", manifest, "json")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Read exported NSX objects and produce push-ready transformed files."
    )
    p.add_argument(
        "--input-root",
        required=True,
        help="Exporter root, e.g. nsx_export/nsx-lm3.lab.local",
    )
    p.add_argument(
        "--output-root",
        required=True,
        help="Output root, e.g. nsx_push_ready/nsx-gm2.lab.local",
    )
    p.add_argument(
        "--source-domain",
        required=True,
        help="Source exported domain ID, e.g. nsx-lm3.lab.local",
    )
    p.add_argument(
        "--target-domain",
        required=True,
        help="Target domain ID, e.g. default",
    )
    p.add_argument(
        "--target-scope",
        choices=["infra", "global-infra"],
        default="global-infra",
        help="Rewrite embedded paths to this scope",
    )
    p.add_argument(
        "--output-format",
        choices=["yaml", "json", "both"],
        default="yaml",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="Delete output root first if it already exists",
    )
    p.add_argument(
        "--no-copy-meta",
        action="store_true",
        help="Do not copy exporter meta files",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)

    cfg = TransformConfig(
        input_root=Path(args.input_root).resolve(),
        output_root=Path(args.output_root).resolve(),
        source_domain=args.source_domain,
        target_domain=args.target_domain,
        target_scope=args.target_scope,
        output_format=args.output_format,
        overwrite=args.overwrite,
        copy_meta=not args.no_copy_meta,
    )

    src_domain_root = relative_export_root(cfg.input_root, cfg.source_domain)
    dst_domain_root = output_domain_root(cfg.output_root, cfg.target_domain)

    if cfg.output_root.exists() and cfg.overwrite:
        LOG.warning("Deleting existing output root: %s", cfg.output_root)
        shutil.rmtree(cfg.output_root)

    dst_domain_root.mkdir(parents=True, exist_ok=True)

    copy_meta_if_present(cfg.input_root, cfg.output_root, cfg)

    files = iter_object_files(src_domain_root)
    processed = 0

    for src in files:
        # Skip exporter-generated indexes/order files if you don't want them as push payloads
        if src.name in {"index.yaml", "index.yml", "index.json", "rules_order.yaml", "rules_order.yml", "rules_order.json"}:
            LOG.debug("Skipping helper file: %s", src)
            continue

        write_transformed_file(src, src_domain_root, dst_domain_root, cfg)
        processed += 1
        LOG.info("Transformed: %s", src.relative_to(src_domain_root))

    build_push_manifests(dst_domain_root)

    LOG.warning("Done. Processed %s files.", processed)
    LOG.warning("Input domain root : %s", src_domain_root)
    LOG.warning("Output domain root: %s", dst_domain_root)
    LOG.warning("Target domain     : %s", cfg.target_domain)
    LOG.warning("Target scope      : %s", cfg.target_scope)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())