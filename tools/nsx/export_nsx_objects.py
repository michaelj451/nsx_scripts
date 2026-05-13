#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import shutil
import time
from datetime import datetime
from pathlib import Path

from nsx.cli_bootstrap import init_cli
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_object_functions.nsx_object_exporter import run_export
from nsx.nsx_constants import resolve_manager, nsx_log_dir

try:
    import yaml
except ImportError:
    yaml = None

# =============================================================================
# Throttle
# =============================================================================
# 5 requests/second => 0.2s between requests
THROTTLE_RPS = 5.0
THROTTLE_INTERVAL_S = 1.0 / THROTTLE_RPS

# =============================================================================
# Repo Root
# =============================================================================

REPO_ROOT = Path(__file__).resolve().parents[2]

# =============================================================================
# Logging
# =============================================================================

def _resolve_log_dir() -> Path:
    if not nsx_log_dir:
        raise RuntimeError("nsx_log_dir is empty (NSX_LOG_DIR not loaded?)")

    p = Path(nsx_log_dir).expanduser().resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _setup_logging(tool_name: str) -> Path:
    log_dir = _resolve_log_dir()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = (log_dir / f"{tool_name}_{ts}.log").resolve()

    log_file.touch(exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    for h in list(root.handlers):
        root.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)

    root.addHandler(ch)
    root.addHandler(fh)

    logging.getLogger(__name__).info("Logging to %s", log_file)
    return log_file


log = logging.getLogger(__name__)

# =============================================================================
# Helpers
# =============================================================================

def _resolve_manager_base(base_dir: str, manager_name: str) -> Path:
    base = Path(base_dir).expanduser()
    if base.name == manager_name:
        return base
    return base / manager_name


def _manager_dirname(manager_host: str) -> str:
    return (
        manager_host
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
    )


def _extract_domain_ids(domains_payload) -> list[str]:
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


def _purge_domain_output_dirs(manager_base: Path, domain_id: str) -> None:
    """
    Purge previously exported object directories for a clean fresh export.

    Exporter writes under:
      <base>/<manager>/domains/<domain>/groups
      <base>/<manager>/domains/<domain>/services
      <base>/<manager>/domains/<domain>/security-policies

    This also handles older layout:
      <base>/<manager>/<domain>/...
    """
    object_dirs = [
        "groups",
        "services",
        "security-policies",
    ]

    candidate_roots = [
        manager_base / domain_id,
        manager_base / "domains" / domain_id,
    ]

    for root in candidate_roots:
        for obj_dir in object_dirs:
            p = root / obj_dir
            if p.exists():
                log.info("Deleting pre-existing export directory: %s", p)
                shutil.rmtree(p)


# =============================================================================
# Object Counting
# =============================================================================

def _iter_object_files(dir_path: Path) -> list[Path]:
    if not dir_path.exists():
        return []

    files: list[Path] = []
    for ext in ("*.yaml", "*.yml", "*.json"):
        files.extend(dir_path.rglob(ext))

    return files


def _load_object(path: Path) -> dict:
    try:
        if path.suffix.lower() in (".yaml", ".yml"):
            if yaml is None:
                return {}
            with path.open("r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}

        return json.loads(path.read_text(encoding="utf-8"))

    except Exception as e:
        log.warning("Failed to parse %s: %s", path, e)
        return {}


def _count_domain_objects(manager_base: Path, domain_id: str) -> dict[str, int]:
    new_root = manager_base / domain_id
    old_root = manager_base / "domains" / domain_id
    root = new_root if new_root.exists() else old_root

    counts = {
        "services_total": 0,
        "groups_total": 0,
        "policies_total": 0,
        "rules_total": 0,
    }

    counts["services_total"] = len(_iter_object_files(root / "services"))
    counts["groups_total"] = len(_iter_object_files(root / "groups"))

    policies_dir = root / "security-policies"
    if policies_dir.exists():
        for policy_dir in policies_dir.iterdir():
            if not policy_dir.is_dir():
                continue

            counts["policies_total"] += 1
            rules_dir = policy_dir / "rules"
            counts["rules_total"] += len(_iter_object_files(rules_dir))

    return counts


# =============================================================================
# Throttling wrapper
# =============================================================================

def _apply_throttle_to_client(client: NsxPolicyClient) -> None:
    """
    Always-on GET throttling.

    5 req/sec = minimum 0.2 seconds between GET requests.
    """
    if hasattr(client, "_throttle_wrapped") and getattr(client, "_throttle_wrapped"):
        return

    if not hasattr(client, "_get"):
        log.warning("Client has no _get method; throttle not applied")
        return

    orig_get = client._get
    last_ts = {"t": 0.0}

    def throttled_get(*args, **kwargs):
        now = time.monotonic()

        if last_ts["t"] > 0:
            elapsed = now - last_ts["t"]
            wait = THROTTLE_INTERVAL_S - elapsed
            if wait > 0:
                time.sleep(wait)

        path = args[0] if args else kwargs.get("path", "?")
        log.info("GET %s", path)

        resp = orig_get(*args, **kwargs)
        last_ts["t"] = time.monotonic()
        return resp

    client._get = throttled_get  # type: ignore[attr-defined]

    setattr(client, "_throttle_wrapped", True)

    log.info(
        "Enabled NSX GET throttling: %.2f req/sec, min interval %.3fs",
        THROTTLE_RPS,
        THROTTLE_INTERVAL_S,
    )


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export non-system NSX Policy objects: groups, services, policies, and rules"
    )

    parser.add_argument("--base-dir", default="nsx_export")
    parser.add_argument("--domain-id", default="default")
    parser.add_argument("--federation-global", action="store_true")

    parser.add_argument(
        "--manager",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        default="nsx-gm1",
    )

    parser.add_argument(
        "--output-format",
        choices=["yaml", "json", "both"],
        default="yaml",
    )

    parser.add_argument("--all-domains", action="store_true")

    parser.add_argument(
        "--include-system-objects",
        action="store_true",
        help="Export system-owned objects too. Default is to skip them.",
    )

    args = parser.parse_args()

    log_file = _setup_logging("export_nsx_objects")

    init_cli()

    manager_host = resolve_manager(args.manager)
    if not manager_host:
        raise RuntimeError(f"Manager not defined for {args.manager}")

    client = NsxPolicyClient(
        nsxmanager=manager_host,
        federation_global=args.federation_global,
    )

    _apply_throttle_to_client(client)

    manager_name = _manager_dirname(manager_host)
    manager_base = _resolve_manager_base(args.base_dir, manager_name)

    skip_system_objects = not args.include_system_objects

    log.info("Starting NSX export")
    log.info("Manager alias: %s", args.manager)
    log.info("Manager host: %s", manager_host)
    log.info("Federation global: %s", args.federation_global)
    log.info("Base dir: %s", manager_base.resolve())
    log.info("Output format: %s", args.output_format)
    log.info("Skip system objects: %s", skip_system_objects)
    log.info("Throttle: %.2f req/sec GET", THROTTLE_RPS)

    all_stats = {}
    all_counts = {}

    if args.all_domains:
        domains_payload = client.list_domains()
        domain_ids = _extract_domain_ids(domains_payload)
        log.info("Discovered domains: %s", domain_ids)
    else:
        domain_ids = [args.domain_id]

    for domain_id in domain_ids:
        log.info("Exporting domain: %s", domain_id)

        _purge_domain_output_dirs(manager_base, domain_id)

        stats = run_export(
            client=client,
            base_dir=str(manager_base),
            domain_id=domain_id,
            output_format=args.output_format,
            skip_system_objects=skip_system_objects,
        )

        all_stats[domain_id] = stats
        all_counts[domain_id] = _count_domain_objects(manager_base, domain_id)

    log.info("Export complete.")
    log.info("Stats: %s", all_stats)
    log.info("Counts: %s", all_counts)

    result = {
        "manager": args.manager,
        "manager_host": manager_host,
        "base_dir": str(manager_base.resolve()),
        "skip_system_objects": skip_system_objects,
        "export_stats": all_stats,
        "object_counts": all_counts,
        "log_file": str(log_file),
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()