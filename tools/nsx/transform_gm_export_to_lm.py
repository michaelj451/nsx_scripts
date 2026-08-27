#!/usr/bin/env python3
"""
tools/nsx/transform_gm_export_to_lm.py

Offline transform: make a Global Manager export pushable to a Local Manager.

A GM export references everything through the GM API surface:

    /global-infra/domains/<domain>/groups/<id>
    /global-infra/services/<id>

An LM only knows /infra/... paths, so pushing GM-exported objects (rules'
source_groups / destination_groups / scope / services, nested service refs,
group PathExpressions) fails validation on the LM. This tool walks an export
tree and rewrites every such reference:

    /global-infra/...                    ->  /infra/...
    /infra/domains/<source-domain>/...   ->  /infra/domains/<target-domain>/...
                                             (only when --target-domain is given)

No NSX API calls. Reads one directory tree, writes a transformed copy.
Everything else in each document is preserved byte-faithfully (YAML is
re-serialized; key order kept).

USAGE:
  # Surface rewrite only (GM default domain -> LM default domain)
  python tools/nsx/transform_gm_export_to_lm.py \\
    --input-root nsx_groups_export/nsx-gm1.lab.local/groups \\
    --output-root nsx_gm_to_lm/nsx-gm1.lab.local/groups

  # Also rename the domain (e.g. GM location domain -> LM default)
  python tools/nsx/transform_gm_export_to_lm.py \\
    --input-root ... --output-root ... \\
    --source-domain nsx-lm1.lab.local --target-domain default

Skipped subdirectories (never copied): push_report, baselines, logs, reports.
The output root must not overlap the input root and is purged before writing
(--no-clean to merge instead).
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from nsx.cli_bootstrap import init_cli            # noqa: E402
from nsx.nsx_constants import nsx_log_dir          # noqa: E402

log = logging.getLogger(__name__)

EXCLUDED_DIRS = {"push_report", "baselines", "logs", "reports"}
GLOBAL_PREFIX = "/global-infra/"
LOCAL_PREFIX = "/infra/"


def rewrite_string(value: str, source_domain: str | None, target_domain: str | None) -> Tuple[str, int]:
    """Rewrite one string. Returns (new_value, refs_rewritten)."""
    hits = 0
    out = value
    if GLOBAL_PREFIX in out:
        hits += out.count(GLOBAL_PREFIX)
        out = out.replace(GLOBAL_PREFIX, LOCAL_PREFIX)
    if out == "/global-infra":     # bare root, e.g. a service's parent_path
        hits += 1
        out = "/infra"
    if source_domain and target_domain and source_domain != target_domain:
        needle = f"{LOCAL_PREFIX}domains/{source_domain}/"
        repl = f"{LOCAL_PREFIX}domains/{target_domain}/"
        if needle in out:
            hits += out.count(needle)
            out = out.replace(needle, repl)
    return out, hits


def rewrite_payload(obj: Any, source_domain: str | None, target_domain: str | None) -> Tuple[Any, int]:
    """Recursively rewrite every string in a payload. Returns (new_obj, refs)."""
    if isinstance(obj, str):
        return rewrite_string(obj, source_domain, target_domain)
    if isinstance(obj, list):
        total = 0
        out_l: List[Any] = []
        for item in obj:
            new, n = rewrite_payload(item, source_domain, target_domain)
            out_l.append(new)
            total += n
        return out_l, total
    if isinstance(obj, dict):
        total = 0
        out_d: Dict[Any, Any] = {}
        for k, v in obj.items():
            new, n = rewrite_payload(v, source_domain, target_domain)
            out_d[k] = new
            total += n
        return out_d, total
    return obj, 0


def iter_object_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in (".yaml", ".yml", ".json"):
            continue
        if any(part in EXCLUDED_DIRS for part in p.relative_to(root).parts):
            continue
        files.append(p)
    return files


def transform_tree(
    input_root: Path,
    output_root: Path,
    *,
    source_domain: str | None,
    target_domain: str | None,
) -> Dict[str, Any]:
    files = iter_object_files(input_root)
    changed = 0
    refs_total = 0
    errors: List[Dict[str, str]] = []

    for f in files:
        rel = f.relative_to(input_root)
        out = output_root / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            text = f.read_text(encoding="utf-8")
            doc = json.loads(text) if f.suffix.lower() == ".json" else yaml.safe_load(text)
        except Exception as exc:
            errors.append({"file": str(rel), "error": str(exc)})
            continue
        new_doc, refs = rewrite_payload(doc, source_domain, target_domain)
        refs_total += refs
        if refs:
            changed += 1
        if f.suffix.lower() == ".json":
            out.write_text(json.dumps(new_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            out.write_text(yaml.safe_dump(new_doc, sort_keys=False, default_flow_style=False), encoding="utf-8")

    return {
        "files_seen": len(files),
        "files_changed": changed,
        "refs_rewritten": refs_total,
        "parse_errors": errors,
    }


def main() -> int:
    p = argparse.ArgumentParser(
        description="Rewrite /global-infra references in a GM export so it can be pushed to an LM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--input-root", required=True, help="GM export directory to read (never modified).")
    p.add_argument("--output-root", required=True, help="Transformed copy destination (purged first).")
    p.add_argument("--source-domain", default=None,
                   help="Domain id in the source paths to rename (e.g. nsx-lm1.lab.local).")
    p.add_argument("--target-domain", default=None,
                   help="Domain id to rename it to on the LM (e.g. default). "
                        "Both --source-domain and --target-domain must be given to rename.")
    p.add_argument("--clean", action=argparse.BooleanOptionalAction, default=True,
                   help="Purge --output-root before writing (default). --no-clean merges.")
    args = p.parse_args()

    init_cli()

    input_root = Path(args.input_root).expanduser().resolve()
    output_root = Path(args.output_root).expanduser().resolve()
    if not input_root.exists():
        raise SystemExit(f"--input-root does not exist: {input_root}")
    if (output_root == input_root or output_root in input_root.parents
            or input_root in output_root.parents):
        raise SystemExit(f"--output-root ({output_root}) overlaps --input-root ({input_root}); refusing.")
    if (args.source_domain is None) != (args.target_domain is None):
        raise SystemExit("--source-domain and --target-domain must be given together.")

    if args.clean and output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    log.info("GM -> LM export transform")
    log.info("  input  : %s", input_root)
    log.info("  output : %s", output_root)
    log.info("  domain : %s", (f"{args.source_domain} -> {args.target_domain}"
                               if args.source_domain else "(unchanged)"))

    result = transform_tree(input_root, output_root,
                            source_domain=args.source_domain, target_domain=args.target_domain)
    summary = {
        "command": "transform_gm_export_to_lm",
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "input_root": str(input_root),
        "output_root": str(output_root),
        "source_domain": args.source_domain,
        "target_domain": args.target_domain,
        **result,
    }
    (output_root / "transform_manifest.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log.info("  files=%d changed=%d refs_rewritten=%d errors=%d",
             result["files_seen"], result["files_changed"], result["refs_rewritten"],
             len(result["parse_errors"]))
    print(json.dumps(summary, indent=2))
    return 0 if not result["parse_errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
