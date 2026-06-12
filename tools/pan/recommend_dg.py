#!/usr/bin/env python3
"""tools/pan/recommend_dg.py

Given a `(src_ip, dst_ip, [protocol], [dst_port])` flow that DOESN'T match
any existing Panorama rule, recommend which Device Group is the natural
home for a new rule allowing it.

USE CASE:
    Customer or operator says "I need to allow 10.50.5.10 → 8.8.8.8 tcp/443.
    Where does the new rule go?". This tool tells you which DG's existing
    rule population has the strongest affinity to the flow's address space.

ALGORITHM:
    1. Parse the Panorama XML config (offline — no API).
    2. For each DG, walk the full eval chain. If any rule already matches
       the flow → tool reports the existing match and exits 0 (no new rule
       needed).
    3. If no DG has a matching rule:
       a. Compute src_subnet = src_ip with the chosen mask (default /24)
          dst_subnet = dst_ip with the chosen mask (default /24)
       b. For each DG, scan its DG-specific rulebases only (DG-pre +
          DG-post, NOT shared, NOT default). Count rules whose source
          addresses cover any IP inside src_subnet, and rules whose
          destination addresses cover any IP inside dst_subnet.
       c. Also count the same for shared/pre + shared/post (informational
          — these aren't DG-recommendable, but they tell you whether the
          flow already belongs to a shared policy lineage).
       d. Score each DG by (src_count + dst_count). Recommend the DG with
          the highest score. Ties broken alphabetically.
       e. If every DG scores zero AND shared scores zero, recommend
          "shared/post-rulebase" as the default catch-all home.

READ-ONLY, FILE-DRIVEN. Same production safety properties as
check_policy_match.py: no network calls, no credentials, no writes
anywhere customer-side.

USAGE:
    python tools/pan/recommend_dg.py \\
        --config tools/pan/configs/<customer>-<ts>.xml \\
        --src-ip 10.50.5.10 --dst-ip 8.8.8.8 \\
        --protocol tcp --dst-port 443

    Add --subnet-mask 16 to widen the affinity check (default /24).
    Add --json to suppress human output. --no-disk to skip the audit
    write to $PANO_REPORTS_DIR/recommend_dg/<UTC_TS>/.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_policy_match as cpm  # noqa: E402

log = logging.getLogger(__name__)


# =============================================================================
# .env path resolver — narrow, reads only PANO_REPORTS_DIR (and ROOT_DIR for
# $VAR expansion). Mirrors the same prod-safe approach used in
# check_policy_match.py.
# =============================================================================

def _resolve_default_output_dir() -> Path:
    if os.environ.get("PANO_REPORTS_DIR"):
        return Path(os.environ["PANO_REPORTS_DIR"])
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if env_path.exists():
        values: Dict[str, str] = {}
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if k not in ("ROOT_DIR", "PANO_REPORTS_DIR"):
                continue
            for known_k, known_v in values.items():
                v = v.replace(f"${known_k}", known_v).replace(f"${{{known_k}}}", known_v)
            values[k] = v
        if "PANO_REPORTS_DIR" in values:
            return Path(values["PANO_REPORTS_DIR"])
    return Path(".pano_reports")


# =============================================================================
# Subnet-affinity scoring
# =============================================================================

@dataclass
class DGAffinity:
    """Per-DG counts of rules whose addresses overlap the query's /N subnets."""
    domain:         str
    rulebases:      List[str]                  # which rulebases were scanned
    rules_scanned:  int    = 0
    src_overlap:    int    = 0                 # rules with src_addrs ∩ src_subnet
    dst_overlap:    int    = 0                 # rules with dst_addrs ∩ dst_subnet
    both_overlap:   int    = 0                 # rules with src AND dst overlap
    sample_rules:   List[Dict[str, Any]] = field(default_factory=list)  # top-3 most-relevant

    @property
    def score(self) -> int:
        # Both-overlap counts double (high signal — the rule already touches
        # both ends of the flow's neighborhood).
        return self.src_overlap + self.dst_overlap + self.both_overlap


def _networks_overlap_subnet(networks: List[cpm.IPNet],
                             subnet:   ipaddress._BaseNetwork) -> bool:
    """True if any network in `networks` overlaps with `subnet`. Robust to
    mixed v4/v6 — only compares within the same address family."""
    for n in networks:
        if n.version != subnet.version:
            continue
        if n.overlaps(subnet):
            return True
    return False


def _score_rulebase(rules: List[cpm.SecurityRule],
                    rulebase_label: str,
                    src_subnet: ipaddress._BaseNetwork,
                    dst_subnet: ipaddress._BaseNetwork,
                    config: cpm.PanoramaConfig,
                    affinity: DGAffinity) -> None:
    """Walk `rules`, increment affinity counters, and record up to 3 sample
    matches for the recommendation rationale."""
    affinity.rulebases.append(rulebase_label)
    for rule in rules:
        if rule.disabled:
            continue
        affinity.rules_scanned += 1

        # Resolve src + dst addrs to networks
        src_nets: List[cpm.IPNet] = []
        if "any" in rule.source_addresses:
            # 'any' technically overlaps everything, but for affinity
            # scoring we want SPECIFIC addresses — 'any' rules contribute
            # no positional signal.
            pass
        else:
            for name in rule.source_addresses:
                nets, _ = config.resolve_address(name)
                src_nets.extend(nets)

        dst_nets: List[cpm.IPNet] = []
        if "any" in rule.destination_addresses:
            pass
        else:
            for name in rule.destination_addresses:
                nets, _ = config.resolve_address(name)
                dst_nets.extend(nets)

        src_hit = _networks_overlap_subnet(src_nets, src_subnet)
        dst_hit = _networks_overlap_subnet(dst_nets, dst_subnet)
        if src_hit:
            affinity.src_overlap += 1
        if dst_hit:
            affinity.dst_overlap += 1
        if src_hit and dst_hit:
            affinity.both_overlap += 1
        # Record sample rule if it's relevant
        if src_hit or dst_hit:
            affinity.sample_rules.append({
                "rulebase": rulebase_label,
                "name":     rule.name,
                "position": rule.position,
                "action":   rule.action,
                "src_overlap": src_hit,
                "dst_overlap": dst_hit,
            })


def _trim_samples(aff: DGAffinity, max_samples: int = 5) -> None:
    """Keep at most `max_samples` rules, prioritizing rules where BOTH
    src and dst overlap (strongest signal)."""
    aff.sample_rules.sort(key=lambda r: (r["src_overlap"] and r["dst_overlap"],
                                         r["src_overlap"], r["dst_overlap"]),
                          reverse=True)
    aff.sample_rules = aff.sample_rules[:max_samples]


# =============================================================================
# Per-DG existing-match check (reuses check_policy_match's matcher logic)
# =============================================================================

def _find_first_match(config: cpm.PanoramaConfig,
                      query:  cpm.Query) -> cpm.Verdict:
    """Reuse check_policy_match's evaluate() to see if any rule already
    matches the flow."""
    return cpm.evaluate(config, query)


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--config", required=True,
                   help="Path to the Panorama running-config XML file")
    p.add_argument("--src-ip", required=True)
    p.add_argument("--dst-ip", required=True)
    p.add_argument("--src-zone", default=None)
    p.add_argument("--dst-zone", default=None)
    p.add_argument("--protocol", default=None, choices=["tcp", "udp"])
    p.add_argument("--dst-port", default=None, type=int)
    p.add_argument("--subnet-mask", default=24, type=int,
                   help="CIDR mask used to compute the src/dst /N subnets "
                        "for affinity scoring. Default 24.")
    p.add_argument("--max-samples", default=5, type=int,
                   help="Top-N rules per DG to record as recommendation "
                        "rationale. Default 5.")
    p.add_argument("--json", action="store_true",
                   help="Suppress human-readable output; print JSON only.")
    p.add_argument("--output-dir", default=None,
                   help="Override the report root. Default is "
                        "$PANO_REPORTS_DIR/recommend_dg/<UTC_TS>/.")
    p.add_argument("--no-disk", action="store_true",
                   help="Suppress on-disk recommendation.json (stdout only).")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )

    config = cpm.PanoramaConfig(Path(args.config))

    # Compute the /N subnets used for affinity scoring
    try:
        src_subnet = ipaddress.ip_network(
            f"{args.src_ip}/{args.subnet_mask}", strict=False)
        dst_subnet = ipaddress.ip_network(
            f"{args.dst_ip}/{args.subnet_mask}", strict=False)
    except ValueError as exc:
        log.error("invalid IP/mask combination: %s", exc)
        return 2

    # ---- Step 1: existing-match check across every DG ----
    log.info("Checking for existing matches across %d DGs ...",
             len(config.device_groups))
    existing_matches: List[Dict[str, Any]] = []
    for dg_name in config.device_groups:
        q = cpm.Query(
            src_ip=args.src_ip, dst_ip=args.dst_ip,
            src_zone=args.src_zone, dst_zone=args.dst_zone,
            protocol=args.protocol, dst_port=args.dst_port,
            device_group=dg_name,
        )
        v = _find_first_match(config, q)
        # We deliberately treat default-rule matches as "no match" —
        # we're looking for a CUSTOMER rule that would fire.
        if v.matched_rule and v.matched_rulebase != "default-rules":
            existing_matches.append({
                "device_group":     dg_name,
                "matched_rule":     v.matched_rule,
                "matched_rulebase": v.matched_rulebase,
                "matched_position": v.matched_position,
                "action":           v.action,
                "caveats":          v.caveats,
            })

    if existing_matches:
        # The flow already matches — no recommendation needed.
        report = {
            "query": {
                "src_ip": args.src_ip, "dst_ip": args.dst_ip,
                "src_subnet": str(src_subnet), "dst_subnet": str(dst_subnet),
                "protocol": args.protocol, "dst_port": args.dst_port,
                "src_zone": args.src_zone, "dst_zone": args.dst_zone,
            },
            "needs_new_rule":  False,
            "existing_matches": existing_matches,
            "recommendation":  None,
        }
        _emit(report, args)
        return 0

    # ---- Step 2: no existing match — score every DG by /N affinity ----
    log.info("No existing customer rule matches the flow. Scoring DG affinity "
             "with src_subnet=%s dst_subnet=%s ...",
             src_subnet, dst_subnet)

    per_dg: Dict[str, DGAffinity] = {}
    for dg_name in config.device_groups:
        aff = DGAffinity(domain=f"dg:{dg_name}", rulebases=[])
        dg = config.device_groups[dg_name]
        _score_rulebase(dg.pre_rulebase,  f"{dg_name}/pre-rulebase",
                        src_subnet, dst_subnet, config, aff)
        _score_rulebase(dg.post_rulebase, f"{dg_name}/post-rulebase",
                        src_subnet, dst_subnet, config, aff)
        _trim_samples(aff, args.max_samples)
        per_dg[dg_name] = aff

    # Shared rulebases — informational
    shared_aff = DGAffinity(domain="shared", rulebases=[])
    _score_rulebase(config.shared_pre_rules,  "shared/pre-rulebase",
                    src_subnet, dst_subnet, config, shared_aff)
    _score_rulebase(config.shared_post_rules, "shared/post-rulebase",
                    src_subnet, dst_subnet, config, shared_aff)
    _trim_samples(shared_aff, args.max_samples)

    # ---- Step 3: rank + recommend ----
    ranked = sorted(per_dg.items(), key=lambda kv: (-kv[1].score, kv[0]))
    top = ranked[0] if ranked else None

    if top and top[1].score > 0:
        recommendation = {
            "type":             "device_group",
            "device_group":     top[0],
            "rationale":        (
                f"{top[0]} has the strongest affinity to the flow's address "
                f"space: {top[1].src_overlap} rule(s) with sources in {src_subnet}, "
                f"{top[1].dst_overlap} rule(s) with destinations in {dst_subnet}, "
                f"{top[1].both_overlap} rule(s) covering both. "
                f"Total score: {top[1].score}."
            ),
            "score":            top[1].score,
            "sample_rules":     top[1].sample_rules,
        }
    else:
        # No DG had any affinity. Fall back to shared.
        if shared_aff.score > 0:
            recommendation = {
                "type":             "shared_rulebase",
                "rulebase":         "shared/pre-rulebase",
                "rationale":        (
                    f"No DG had any rule referencing {src_subnet} or {dst_subnet}, "
                    f"but {shared_aff.src_overlap + shared_aff.dst_overlap} shared "
                    f"rule(s) do. The flow likely belongs to a shared policy "
                    f"lineage; consider adding to shared/pre-rulebase."
                ),
                "score":            shared_aff.score,
                "sample_rules":     shared_aff.sample_rules,
            }
        else:
            recommendation = {
                "type":             "shared_rulebase",
                "rulebase":         "shared/post-rulebase",
                "rationale":        (
                    f"No DG and no shared rule references {src_subnet} or "
                    f"{dst_subnet}. The flow is unconnected to any existing "
                    f"policy lineage; the default home is shared/post-rulebase "
                    f"(catch-all). Operator should review before adding."
                ),
                "score":            0,
                "sample_rules":     [],
            }

    report = {
        "query": {
            "src_ip": args.src_ip, "dst_ip": args.dst_ip,
            "src_subnet": str(src_subnet), "dst_subnet": str(dst_subnet),
            "subnet_mask": args.subnet_mask,
            "protocol": args.protocol, "dst_port": args.dst_port,
            "src_zone": args.src_zone, "dst_zone": args.dst_zone,
        },
        "needs_new_rule":   True,
        "existing_matches": [],
        "per_dg_affinity": [
            {
                "device_group":  name,
                "score":         aff.score,
                "src_overlap":   aff.src_overlap,
                "dst_overlap":   aff.dst_overlap,
                "both_overlap":  aff.both_overlap,
                "rules_scanned": aff.rules_scanned,
                "rulebases":     aff.rulebases,
                "sample_rules":  aff.sample_rules,
            }
            for name, aff in ranked
        ],
        "shared_affinity": {
            "score":         shared_aff.score,
            "src_overlap":   shared_aff.src_overlap,
            "dst_overlap":   shared_aff.dst_overlap,
            "both_overlap":  shared_aff.both_overlap,
            "rules_scanned": shared_aff.rules_scanned,
            "rulebases":     shared_aff.rulebases,
            "sample_rules":  shared_aff.sample_rules,
        },
        "recommendation": recommendation,
    }
    _emit(report, args)
    return 0


# =============================================================================
# Output formatting + emission
# =============================================================================

def _format_text(report: Dict[str, Any]) -> str:
    q = report["query"]
    lines = [
        "=" * 72,
        "DG RECOMMENDATION REPORT",
        "=" * 72,
        f"Query:        src={q['src_ip']}  dst={q['dst_ip']}",
        f"              src_subnet={q['src_subnet']}  dst_subnet={q['dst_subnet']}",
        f"              proto={q['protocol'] or '(any)'}  port={q['dst_port'] or '(any)'}",
    ]
    if report.get("existing_matches"):
        lines.append("")
        lines.append("Status: EXISTING RULES ALREADY MATCH this flow — no new rule needed.")
        for m in report["existing_matches"]:
            lines.append(f"  [{m['device_group']}] {m['matched_rulebase']} / pos {m['matched_position']} "
                         f"/ {m['matched_rule']!r} → {m['action'].upper()}")
        return "\n".join(lines)

    lines.append("")
    lines.append("Status: NO existing rule matches — new rule needed.")
    lines.append("")
    lines.append("Per-DG affinity to the flow's /N subnets (DG-specific rulebases only):")
    lines.append(f"  {'DG':10s} {'score':>5s} {'src':>4s} {'dst':>4s} {'both':>5s} {'scanned':>8s}")
    for dg in report["per_dg_affinity"]:
        lines.append(f"  {dg['device_group']:10s} {dg['score']:>5d} "
                     f"{dg['src_overlap']:>4d} {dg['dst_overlap']:>4d} "
                     f"{dg['both_overlap']:>5d} {dg['rules_scanned']:>8d}")
    sa = report["shared_affinity"]
    lines.append(f"  {'shared':10s} {sa['score']:>5d} {sa['src_overlap']:>4d} "
                 f"{sa['dst_overlap']:>4d} {sa['both_overlap']:>5d} "
                 f"{sa['rules_scanned']:>8d}  (informational)")
    lines.append("")
    rec = report["recommendation"]
    if rec["type"] == "device_group":
        lines.append(f"RECOMMENDATION: add new rule to device-group '{rec['device_group']}'")
    else:
        lines.append(f"RECOMMENDATION: add new rule to {rec['rulebase']}")
    lines.append(f"  Rationale: {rec['rationale']}")
    if rec.get("sample_rules"):
        lines.append("  Top supporting rules:")
        for s in rec["sample_rules"]:
            tags = []
            if s["src_overlap"]: tags.append("src")
            if s["dst_overlap"]: tags.append("dst")
            lines.append(f"    - {s['rulebase']} / pos {s['position']} / {s['name']!r}  "
                         f"({'+'.join(tags)} overlap)")
    return "\n".join(lines)


def _emit(report: Dict[str, Any], args: argparse.Namespace) -> None:
    if not args.no_disk:
        base = (Path(args.output_dir).expanduser().resolve()
                if args.output_dir
                else _resolve_default_output_dir().expanduser().resolve())
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_dir = base / "recommend_dg" / ts
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "recommendation.json").write_text(
            json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        (out_dir / "recommendation.txt").write_text(
            _format_text(report), encoding="utf-8")
        log.info("report written to %s", out_dir / "recommendation.json")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_format_text(report))


if __name__ == "__main__":
    sys.exit(main())
