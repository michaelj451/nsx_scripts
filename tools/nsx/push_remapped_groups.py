#!/usr/bin/env python3
# tools/nsx/push_nsx_groups.py
from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path
from typing import Dict

from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import nsx_gm1, nsx_gm2, nsx_lm1, nsx_lm2, nsx_lm3, nsx_lm4
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_object_functions.nsx_group_importer import GroupImportConfig, NsxGroupImporter
from nsx.nsx_constants import nsx_log_dir

DEFAULT_INPUT_DIR = "nsx_groups_additive"
LOG_DIR_NAME = nsx_log_dir
LOG_FILE_NAME = "push_nsx_groups.log"

GROUP_PATCH_INTERVAL_SECONDS = 1.0
PROMPT_EVERY_N_UPDATES = 1


def setup_logging() -> logging.Logger:
    repo_root = Path(__file__).resolve().parents[2]
    log_dir = repo_root / LOG_DIR_NAME
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / LOG_FILE_NAME

    logger = logging.getLogger("push_nsx_groups")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

        fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(fmt)

        sh = logging.StreamHandler()
        sh.setLevel(logging.INFO)
        sh.setFormatter(fmt)

        logger.addHandler(fh)
        logger.addHandler(sh)

    logger.info("Log file: %s", log_file)
    return logger


log = setup_logging()


def _build_mgr_map() -> Dict[str, str]:
    return {
        "nsx-gm1": nsx_gm1,
        "nsx-gm2": nsx_gm2,
        "nsx-lm1": nsx_lm1,
        "nsx-lm2": nsx_lm2,
        "nsx-lm3": nsx_lm3,
        "nsx-lm4": nsx_lm4,
    }


def _default_input_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / DEFAULT_INPUT_DIR


def _manager_dirname(manager_host: str) -> str:
    return manager_host.replace("https://", "").rstrip("/")


def _select_input_root_for_target(input_dir: Path, target_manager_host: str) -> Path:
    """
    If input_dir contains per-manager subfolders (common), pick the one matching the target host.
    Example:
        input_dir = nsx_groups_additive/
        contains:
          nsx-gm1.lab.local/
          nsx-lm1.lab.local/
    If target is nsx-lm1.lab.local, use nsx_groups_additive/nsx-lm1.lab.local.
    """
    target_name = _manager_dirname(target_manager_host)

    # If user already pointed at a manager folder, keep it
    if input_dir.name == target_name:
        return input_dir

    candidate = input_dir / target_name
    if candidate.is_dir():
        return candidate

    # Fall back to original behavior if no match
    return input_dir


def _find_domain_root(export_root: Path) -> Path:
    """
    Determine the actual domain layout root.
    Supports:
      1) <export_root>/domains/...
      2) <export_root>/<something>/domains/...
    Returns the directory that contains 'domains/'.
    """
    if (export_root / "domains").is_dir():
        return export_root

    for sub in export_root.iterdir():
        if sub.is_dir() and (sub / "domains").is_dir():
            return sub

    raise RuntimeError(
        "Could not find a 'domains' directory. Expected either:\n"
        f"  1) {export_root}/domains/<domain-id>/groups\n"
        f"  2) {export_root}/<manager>/domains/<domain-id>/groups"
    )


def _resolve_groups_dir(domain_root: Path, domain_id: str) -> Path:
    """
    Match importer layout support:
      - NEW: <domain_root>/<domain_id>/groups
      - OLD: <domain_root>/domains/<domain_id>/groups
    """
    new_dir = domain_root / domain_id / "groups"
    old_dir = domain_root / "domains" / domain_id / "groups"
    return new_dir if new_dir.is_dir() else old_dir


def _prompt_to_continue(applied_count: int) -> None:
    while True:
        answer = input(
            f"\nApplied {applied_count} group updates. Continue with next batch? [y/N]: "
        ).strip().lower()

        if answer in ("y", "yes"):
            log.info("Operator chose to continue after %d applied updates.", applied_count)
            return

        if answer in ("", "n", "no"):
            log.warning("Operator aborted after %d applied updates.", applied_count)
            raise KeyboardInterrupt(f"Stopped by operator after {applied_count} applied updates.")

        print("Please enter 'y' or 'n'.")


def _wrap_group_patch_controls(
    client: NsxPolicyClient,
    *,
    dry_run: bool,
    throttle_seconds: float = GROUP_PATCH_INTERVAL_SECONDS,
    prompt_every: int = PROMPT_EVERY_N_UPDATES,
) -> None:
    """
    Wrap client._patch so real group updates:
      - run at most once per throttle_seconds
      - pause for confirmation every prompt_every successful patch calls

    Dry-run mode is left untouched because importer does not actually call _patch then.
    """
    if dry_run:
        log.info("Dry-run mode: group patch throttling/prompt wrapper not applied.")
        return

    if getattr(client, "_group_patch_controls_wrapped", False):
        return

    if not hasattr(client, "_patch"):
        raise RuntimeError("NsxPolicyClient has no _patch method to wrap.")

    orig_patch = client._patch
    state = {
        "last_patch_ts": 0.0,
        "applied_count": 0,
    }

    def controlled_patch(path, payload, *args, **kwargs):
        now = time.monotonic()
        wait = throttle_seconds - (now - state["last_patch_ts"])
        if wait > 0:
            log.info("Throttling next group update for %.3f seconds", wait)
            time.sleep(wait)

        response = orig_patch(path, payload, *args, **kwargs)

        state["last_patch_ts"] = time.monotonic()
        state["applied_count"] += 1

        group_id = None
        if isinstance(payload, dict):
            group_id = payload.get("id")

        log.info(
            "Applied group update #%d%s",
            state["applied_count"],
            f" (id={group_id})" if group_id else "",
        )

        if prompt_every > 0 and state["applied_count"] % prompt_every == 0:
            _prompt_to_continue(state["applied_count"])

        return response

    client._patch = controlled_patch  # type: ignore[attr-defined]
    setattr(client, "_group_patch_controls_wrapped", True)

    log.info(
        "Enabled group patch controls: throttle=%.3fs, prompt_every=%d applied updates",
        throttle_seconds,
        prompt_every,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Push NSX Group updates from files (additive-only, existing groups) into a target NSX manager"
    )

    parser.add_argument(
        "--target",
        choices=["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4"],
        required=True,
        help="NSX manager to push groups into.",
    )

    parser.add_argument(
        "--input-dir",
        type=Path,
        default=_default_input_dir(),
        help=f"Root folder containing exported groups layout (default: <repo>/{DEFAULT_INPUT_DIR}).",
    )

    parser.add_argument(
        "--domain-id",
        default="default",
        choices=["default", nsx_gm1, nsx_gm2, nsx_lm1, nsx_lm2, nsx_lm3, nsx_lm4],
        help="Domain ID to operate on (default: default).",
    )

    parser.add_argument("--input-format", choices=["yaml", "json"], default="yaml")
    parser.add_argument("--apply", action="store_true", help="Actually push changes (otherwise dry-run).")
    parser.add_argument("--stop-on-error", action="store_true", help="Stop on first error.")
    parser.add_argument("--federation-global", action="store_true", help="Use GM global endpoints (global-infra).")

    parser.add_argument(
        "--group-interval-seconds",
        type=float,
        default=GROUP_PATCH_INTERVAL_SECONDS,
        help=f"Minimum seconds between applied group updates (default: {GROUP_PATCH_INTERVAL_SECONDS}).",
    )
    parser.add_argument(
        "--prompt-every",
        type=int,
        default=PROMPT_EVERY_N_UPDATES,
        help=f"Prompt to continue after this many applied updates (default: {PROMPT_EVERY_N_UPDATES}). Use 0 to disable.",
    )

    args = parser.parse_args()
    init_cli()

    mgr_map = _build_mgr_map()
    dst_mgr = mgr_map.get(args.target)
    if not dst_mgr:
        raise RuntimeError(f"Target manager env var not set for {args.target}. Check your .env / constants.")

    input_dir: Path = args.input_dir
    if not input_dir.exists():
        raise RuntimeError(f"Input directory does not exist: {input_dir}")

    selected_root = _select_input_root_for_target(input_dir, dst_mgr)
    if selected_root != input_dir:
        log.info("Selected manager subtree for %s: %s", args.target, selected_root.resolve())
    else:
        log.info("Using input-dir as provided (no manager subtree match found): %s", selected_root.resolve())

    domain_root = _find_domain_root(selected_root)
    groups_dir = _resolve_groups_dir(domain_root, args.domain_id)

    log.info("Starting push_nsx_groups (file-based updates, existing groups)")
    log.info("Target:            %s (%s)", args.target, dst_mgr)
    log.info("Federation GM:     %s", args.federation_global)
    log.info("Mode:              %s", "APPLY" if args.apply else "DRY-RUN")
    log.info("Input dir:         %s", input_dir.resolve())
    log.info("Selected root:     %s", selected_root.resolve())
    log.info("Using domain root: %s", domain_root.resolve())
    log.info("Groups dir:        %s", groups_dir.resolve())
    log.info("Domain ID:         %s", args.domain_id)
    log.info("Input format:      %s", args.input_format)
    log.info("Stop on error:     %s", args.stop_on_error)
    log.info("Group interval:    %s", args.group_interval_seconds)
    log.info("Prompt every:      %s", args.prompt_every)

    client = NsxPolicyClient(nsxmanager=dst_mgr, federation_global=args.federation_global)

    _wrap_group_patch_controls(
        client,
        dry_run=(not args.apply),
        throttle_seconds=args.group_interval_seconds,
        prompt_every=args.prompt_every,
    )

    cfg = GroupImportConfig(
        export_root=domain_root,
        domain_id=args.domain_id,
        input_format=args.input_format,
        dry_run=(not args.apply),
        continue_on_error=(not args.stop_on_error),
        mode="groups_only",
    )

    importer = NsxGroupImporter(client=client, cfg=cfg)

    try:
        result = importer.import_all()
    except KeyboardInterrupt as exc:
        log.warning("Push interrupted: %s", exc)
        raise SystemExit(130)

    log.info("Push complete. Stats=%s Errors=%d", result.get("stats"), len(result.get("errors", [])))
    print(result)


if __name__ == "__main__":
    main()