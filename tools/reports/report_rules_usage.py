#!/usr/bin/env python3
"""tools/nsx/report_rules_usage.py

Standalone read-only rule-usage report.

Queries NSX's per-policy statistics endpoint
(/policy/api/v1/infra/domains/<d>/security-policies/<p>/statistics) for
every customer policy on a target, correlates each rule's runtime
counters (hit_count, byte_count, packet_count, session_count,
popularity_index) with the rule definition (services, source/dest
groups, sequence_number, action, last_modified_time), and classifies
each rule as:

    HOT     hit_count >= --hot-threshold (default 1000)
    USED    1 <= hit_count < --hot-threshold
    UNUSED  hit_count == 0, but rule is <= --fresh-days days old (default 30)
            — too new to draw conclusions
    DORMANT hit_count == 0 AND rule is older than --fresh-days days
            — strong candidate for cleanup or low-risk amend-refs

OUTPUT:
    $NSX_LOG_DIR/rules_usage_report/<target-host>/<UTC_TS>/
        summary.json              overall counters + classification breakdown
        rules_usage.json          per-rule full record
        rules_usage.jsonl         one row per line (greppable)
        hot_rules.{json,jsonl}    top-N rules by hit_count
        unused_rules.{json,jsonl} hit_count==0 (UNUSED + DORMANT)
        dormant_rules.{json,jsonl} hit_count==0 AND older than fresh-days
        stale_rules.{json,jsonl}  had hits, none in stale-days
        no_hits_in_n_days.{json,jsonl}  (with --min-days-since-hit) — combined view
        diff.json                 (only with --compare-to) per-rule delta vs prior report
        logs/

OPTIONAL DIFF MODE:
    --compare-to <prior-report-dir>
    Loads rules_usage.json from a prior run and computes:
        - hit_count delta per rule
        - which rules "lit up" (was 0, now > 0) — sibling activation signal
        - which rules went dormant (was > 0, now 0 — possible enforcement gap)

Read-only against NSX — only GETs, never PUT/PATCH/DELETE.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent / "app"))
from nsx.cli_bootstrap import init_cli            # noqa: E402
from nsx.nsx_constants import resolve_manager, nsx_log_dir   # noqa: E402
from nsx.nsx_policy_client import NsxPolicyClient            # noqa: E402

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
NSX_MANAGER_CHOICES = ["nsx-gm1", "nsx-gm2", "nsx-lm1", "nsx-lm2", "nsx-lm3", "nsx-lm4", "nsx-lm5"]

# These policy IDs are NSX system defaults — operators care less about their
# stats than about customer-defined policies. Excluded from default classification
# but still shown via --include-defaults.
DEFAULT_SYSTEM_POLICY_IDS = {"default-layer3-section", "default-layer2-section"}

# Rules under these policies (the L2/L3 default sections) match a lot of
# infrastructure traffic and skew the "used" classification — kept in their own
# bucket in the report.


# =============================================================================
# Read-only lockdown — defense in depth
# =============================================================================

class ReadOnlyViolationError(RuntimeError):
    """Raised if any code path in this tool attempts a non-GET NSX request."""


def _lock_client_read_only(client: NsxPolicyClient) -> None:
    """Replace every write-side transport method on the client INSTANCE with a
    raising stub. The class itself is unchanged — other tools that import the
    same client keep working normally. This is per-instance defense in depth:
    if a future edit to this file (or a transitive call) tries to PUT/PATCH/
    POST/DELETE against NSX, it fails loudly in Python before any HTTP request
    is dispatched.

    The contract this tool offers is "read-only against NSX". This guards it.
    """
    def _refuse(method_name: str):
        def stub(*_a, **_kw):
            raise ReadOnlyViolationError(
                f"report_rules_usage.py is read-only; NsxPolicyClient.{method_name}() "
                f"is blocked. Only GET methods (list_*/get_*) are permitted."
            )
        stub.__name__ = method_name
        return stub

    for transport in ("_post", "_put", "_patch", "_delete"):
        if hasattr(client, transport):
            setattr(client, transport, _refuse(transport))


# =============================================================================
# I/O helpers
# =============================================================================

def _setup_logging(reports_dir: Path) -> Path:
    log_dir_path = Path(nsx_log_dir).expanduser().resolve()
    log_dir_path.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    bundle_log = (reports_dir / f"report_rules_usage_{RUN_TS}.log").resolve()
    global_log = (log_dir_path / f"report_rules_usage_{RUN_TS}.log").resolve()
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter("%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                            "%Y-%m-%dT%H:%M:%S")
    for h in (logging.StreamHandler(), logging.FileHandler(bundle_log, encoding="utf-8"),
              logging.FileHandler(global_log, encoding="utf-8")):
        h.setFormatter(fmt)
        root.addHandler(h)
    return bundle_log


def _epoch_ms_to_iso(ms: Optional[int]) -> Optional[str]:
    if ms is None:
        return None
    try:
        return datetime.fromtimestamp(ms / 1000.0, timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def _days_since(ms: Optional[int], now_ms: int) -> Optional[int]:
    if ms is None:
        return None
    try:
        return max(0, int((now_ms - ms) // (24 * 3600 * 1000)))
    except (TypeError, ValueError):
        return None


# =============================================================================
# Statistics correlation
# =============================================================================

def _flatten_policy_stats(stats_doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """The /statistics endpoint nests results per enforcement point with
    a `statistics` wrapper:

        {"results": [
            {"enforcement_point": "/infra/...",
             "statistics": {"internal_section_id": "...",
                            "results": [{"internal_rule_id": "...",
                                         "hit_count": ..., ...}, ...]}}
        ]}

    For the report we aggregate (sum) across enforcement points keyed by
    internal_rule_id. Aggregation is a sum for counters; for popularity_index
    and max_* we take the max.
    """
    by_irid: Dict[str, Dict[str, Any]] = {}
    sum_fields = ("hit_count", "byte_count", "packet_count", "session_count",
                  "l7_accept_count", "l7_reject_count",
                  "l7_reject_with_response_count", "total_session_count",
                  "active_sessions_count")
    max_fields = ("popularity_index", "max_popularity_index", "max_session_count")
    for ep_block in (stats_doc.get("results") or []):
        wrapper = ep_block.get("statistics") or {}
        # NSX has shipped two response shapes — newer builds put rule rows
        # inside wrapper["results"]; older ones put them directly in
        # ep_block["results"]. Accept both.
        rule_rows = wrapper.get("results") or ep_block.get("results") or []
        for row in rule_rows:
            irid = str(row.get("internal_rule_id") or row.get("rule_id") or "")
            if not irid:
                continue
            slot = by_irid.setdefault(irid, {"internal_rule_id": irid})
            for f in sum_fields:
                if row.get(f) is not None:
                    slot[f] = slot.get(f, 0) + int(row[f])
            for f in max_fields:
                if row.get(f) is not None:
                    slot[f] = max(slot.get(f, 0), int(row[f]))
    return by_irid


# =============================================================================
# Classification
# =============================================================================

def _classify(rec: Dict[str, Any], hot_threshold: int, fresh_days: int,
              stale_days: int) -> str:
    """Five-bucket classification:

      HOT     hit_count >= hot_threshold
      USED    1 <= hit_count < hot_threshold AND hit recently (within stale_days)
      STALE   hit_count >  0 AND days_since_hit_changed > stale_days
              (rule used to enforce, no longer does — strong cleanup signal)
      UNUSED  hit_count == 0 AND rule_age_days <= fresh_days
              (too new to draw conclusions)
      DORMANT hit_count == 0 AND rule_age_days >  fresh_days
              (never observed matching; old enough to act on)
    """
    hits = int(rec.get("hit_count") or 0)
    if hits >= hot_threshold:
        return "HOT"
    if hits > 0:
        days_since = rec.get("days_since_hit_changed")
        # STALE only fires when we have history evidence — without it, default USED.
        if days_since is not None and days_since > stale_days:
            return "STALE"
        return "USED"
    age = rec.get("rule_age_days")
    if age is None or age <= fresh_days:
        return "UNUSED"
    return "DORMANT"


# =============================================================================
# Snapshot history scan — derives "days_since_hit_changed" per rule
# =============================================================================

def _load_history(history_dir: Path, current_keyset: set) -> Tuple[Dict[Tuple[str, str], Dict[str, Any]], int]:
    """Walk all timestamped snapshot dirs under history_dir, collect each
    rule's hit_count progression, and compute the most recent snapshot
    timestamp where hit_count INCREASED (the rule's last-known-active anchor).

    Returns ({(policy_id, rule_id): {first_seen_iso, last_change_iso, last_hit_count}}, snapshot_count).
    """
    history: Dict[Tuple[str, str], Dict[str, Any]] = {}
    if not history_dir.exists():
        return history, 0

    # Each snapshot lives at <history_dir>/<UTC_TS>/rules_usage.json
    snapshots = sorted(history_dir.glob("*/rules_usage.json"))
    if not snapshots:
        return history, 0

    for snap_path in snapshots:
        try:
            doc = json.loads(snap_path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("could not read %s: %s — skipping", snap_path, exc)
            continue
        snap_ts_iso = (doc.get("summary") or {}).get("ran_at")
        for r in (doc.get("rules") or []):
            # Older snapshots (pre-multi-domain) don't have domain_id; fall back to "default"
            did = r.get("domain_id") or "default"
            key = (did, r.get("policy_id"), r.get("rule_id"))
            if not all(key):
                continue
            slot = history.setdefault(key, {
                "first_seen_iso": snap_ts_iso,
                "last_change_iso": None,
                "last_hit_count": None,
            })
            prev_hits = slot["last_hit_count"]
            cur_hits = int(r.get("hit_count") or 0)
            # hit_count increased between snapshots: mark this as the last-change anchor.
            # Also treat the first snapshot we see a non-zero hit as a change.
            if prev_hits is None and cur_hits > 0:
                slot["last_change_iso"] = snap_ts_iso
            elif prev_hits is not None and cur_hits > prev_hits:
                slot["last_change_iso"] = snap_ts_iso
            elif prev_hits is not None and cur_hits < prev_hits:
                # Counter reset (manager upgrade, host reboot, section recreate).
                # We don't treat a reset as a "hit" but the next increase will be caught.
                slot["counter_reset_observed"] = True
            slot["last_hit_count"] = cur_hits
        # Also note rules that appeared for the first time in THIS snapshot.
        # Not strictly needed for the days-since-hit calc, but useful audit.
    return history, len(snapshots)


def _days_between_iso(later_iso: str, earlier_iso: Optional[str]) -> Optional[int]:
    """Floor-days between two ISO timestamps. Returns None if either is None."""
    if not earlier_iso or not later_iso:
        return None
    try:
        a = datetime.fromisoformat(later_iso.replace("Z", "+00:00"))
        b = datetime.fromisoformat(earlier_iso.replace("Z", "+00:00"))
        return max(0, int((a - b).total_seconds() // (24 * 3600)))
    except Exception:
        return None


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--target", required=True, choices=NSX_MANAGER_CHOICES,
                   help="NSX manager to query (read-only GETs).")
    p.add_argument("--domain-id", default="default",
                   help="Single domain to query. Ignored if --all-domains is set.")
    p.add_argument("--all-domains", action="store_true",
                   help="Discover every domain on the target and report on all of them "
                        "in one snapshot. Each rule record is tagged with its domain_id "
                        "and summary.json includes a per-domain breakdown. Useful for "
                        "Global Managers which expose Global + per-LM domains.")
    p.add_argument("--federation-global", action="store_true")
    p.add_argument("--include-defaults", action="store_true",
                   help="Also report on NSX default L2/L3 section policies. "
                        "Off by default — those carry infrastructure traffic "
                        "and skew the 'used' bucket.")
    p.add_argument("--hot-threshold", type=int, default=1000,
                   help="hit_count >= this value classifies a rule as HOT. Default: 1000.")
    p.add_argument("--fresh-days", type=int, default=30,
                   help="A rule with hit_count=0 but younger than this is UNUSED "
                        "rather than DORMANT (too new to draw conclusions). Default: 30.")
    p.add_argument("--stale-days", type=int, default=365,
                   help="A rule with hit_count > 0 whose hit_count hasn't increased "
                        "in the last N days (per accumulated snapshot history) is "
                        "STALE — used to enforce but no longer does. Default: 365.")
    p.add_argument("--history-dir", default=None,
                   help="Directory of prior report snapshots used to compute "
                        "'days since hit_count last changed' per rule. "
                        "Default: $NSX_LOG_DIR/rules_usage_report/<host>/ "
                        "(the same dir this run writes into — older runs are read).")
    p.add_argument("--min-days-since-hit", type=int, default=None,
                   help="(filter) Emit a separate stale_rules.json containing only "
                        "rules whose hit_count hasn't changed in at least N days. "
                        "Set N=365 to find rules unused in the past year.")
    p.add_argument("--top-n", type=int, default=20,
                   help="Number of rules to include in hot_rules.json. Default: 20.")
    p.add_argument("--compare-to", default=None,
                   help="Path to a prior rules_usage_report/<host>/<ts>/ directory; "
                        "computes a per-rule delta and writes diff.json.")
    p.add_argument("--output-base", default=None,
                   help="Output root; default: $NSX_LOG_DIR.")
    args = p.parse_args()

    init_cli()

    target_host = resolve_manager(args.target)
    if not target_host:
        raise SystemExit(f"Target manager not defined: {args.target}")

    output_base = (Path(args.output_base).expanduser().resolve()
                   if args.output_base else Path(nsx_log_dir))
    reports_dir = output_base / "rules_usage_report" / target_host / RUN_TS
    log_file = _setup_logging(reports_dir / "logs")

    history_dir = (Path(args.history_dir).expanduser().resolve()
                   if args.history_dir
                   else reports_dir.parent)  # the per-host dir; older sibling timestamps live here

    log.info("=" * 60)
    log.info("RULES USAGE REPORT")
    log.info("  Target              : %s (%s)", args.target, target_host)
    log.info("  Domain              : %s", "ALL (auto-discover)" if args.all_domains else args.domain_id)
    log.info("  Include defaults    : %s", args.include_defaults)
    log.info("  Hot threshold       : %d hits", args.hot_threshold)
    log.info("  Fresh-days threshold: %d days (UNUSED vs DORMANT split)", args.fresh_days)
    log.info("  Stale-days threshold: %d days (USED vs STALE split)", args.stale_days)
    log.info("  History dir         : %s", history_dir)
    log.info("  Top-N rules         : %d", args.top_n)
    log.info("  Compare to          : %s", args.compare_to or "(no diff mode)")
    log.info("  Min days since hit  : %s", args.min_days_since_hit or "(disabled)")
    log.info("  Reports             : %s", reports_dir)
    log.info("=" * 60)

    client = NsxPolicyClient(nsxmanager=target_host, federation_global=args.federation_global)
    _lock_client_read_only(client)
    log.info("Read-only lockdown engaged on NsxPolicyClient instance "
             "(_post/_put/_patch/_delete will raise ReadOnlyViolationError)")

    # Discover the domain set to query. On an LM there is one domain ("default").
    # On a GM there's "default" (Global) plus one domain per federation member.
    if args.all_domains:
        log.info("--all-domains: discovering domains on %s ...", target_host)
        domains = client.list_domains()
        domains_to_query = [d.get("id") for d in domains if d.get("id")]
        log.info("  discovered %d domain(s): %s",
                 len(domains_to_query), ", ".join(domains_to_query))
    else:
        domains_to_query = [args.domain_id]

    # Collect policies across all selected domains. Each policy is paired with
    # the domain it belongs to so the rule-collection loop can use the right
    # domain_id on each NSX call.
    log.info("Fetching customer security policies ...")
    policies_with_domain: List[Tuple[str, Dict[str, Any]]] = []  # (domain_id, policy_doc)
    total_seen = 0
    for did in domains_to_query:
        try:
            domain_policies = client.list_security_policies(domain_id=did)
        except Exception as exc:
            log.warning("  domain %s: could not list policies: %s", did, exc)
            continue
        total_seen += len(domain_policies)
        for p in domain_policies:
            if p.get("_system_owned"):
                continue
            if not args.include_defaults and p.get("id") in DEFAULT_SYSTEM_POLICY_IDS:
                continue
            policies_with_domain.append((did, p))
        log.info("  domain %s: %d policies total, %d customer",
                 did, len(domain_policies),
                 sum(1 for d, _ in policies_with_domain if d == did))
    customer_policies = [p for _, p in policies_with_domain]
    log.info("  customer policies total: %d (of %d total across %d domain(s))",
             len(customer_policies), total_seen, len(domains_to_query))

    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    now_iso = datetime.now(timezone.utc).isoformat()
    rules_records: List[Dict[str, Any]] = []

    # Scan accumulated snapshot history to derive 'days since last hit_count change' per rule.
    history, snapshot_count = _load_history(history_dir, set())
    log.info("History scan: %d prior snapshot(s) found; %d rules with hit-anchor data",
             snapshot_count, sum(1 for v in history.values() if v.get("last_change_iso")))

    for did, pol in policies_with_domain:
        pol_id = pol.get("id")
        pol_display = pol.get("display_name") or pol_id
        if not pol_id:
            continue
        log.info("Domain: %s | Policy: %s (%s)", did, pol_id, pol_display)

        # Fetch rules + stats in two API calls per policy.
        try:
            rules = client.list_security_rules(security_policy_id=pol_id, domain_id=did)
        except Exception as exc:
            log.warning("  could not list rules for %s/%s: %s", did, pol_id, exc)
            continue
        try:
            stats_doc = client.get_security_policy_statistics(
                security_policy_id=pol_id, domain_id=did,
            )
        except Exception as exc:
            log.warning("  could not fetch stats for %s/%s: %s", did, pol_id, exc)
            stats_doc = {}
        stats_by_irid = _flatten_policy_stats(stats_doc)

        for rule in rules:
            if rule.get("_system_owned"):
                continue
            rid = rule.get("id")
            irid = str(rule.get("rule_id") or "")
            stats = stats_by_irid.get(irid, {})
            mod_time_ms = rule.get("_last_modified_time")
            create_time_ms = rule.get("_create_time")
            # Prefer the older of create/modify as the "age" baseline — a rule
            # last modified yesterday but created two years ago is NOT fresh.
            age_baseline_ms = create_time_ms if create_time_ms else mod_time_ms

            record = {
                "domain_id":          did,
                "policy_id":          pol_id,
                "policy_display":     pol_display,
                "rule_id":            rid,
                "rule_display":       rule.get("display_name") or rid,
                "internal_rule_id":   irid,
                "sequence_number":    rule.get("sequence_number"),
                "action":             rule.get("action"),
                "direction":          rule.get("direction"),
                "disabled":           bool(rule.get("disabled")),
                "logged":             bool(rule.get("logged")),
                "ip_protocol":        rule.get("ip_protocol"),
                "scope":              rule.get("scope") or [],
                "source_groups":      rule.get("source_groups") or [],
                "destination_groups": rule.get("destination_groups") or [],
                "services":           rule.get("services") or [],
                # Statistics — aggregated across enforcement points
                "hit_count":                    int(stats.get("hit_count")          or 0),
                "byte_count":                   int(stats.get("byte_count")         or 0),
                "packet_count":                 int(stats.get("packet_count")       or 0),
                "session_count":                int(stats.get("session_count")      or 0),
                "active_sessions_count":        int(stats.get("active_sessions_count") or 0),
                "popularity_index":             int(stats.get("popularity_index")   or 0),
                "max_popularity_index":         int(stats.get("max_popularity_index") or 0),
                "max_session_count":            int(stats.get("max_session_count") or 0),
                "total_session_count":          int(stats.get("total_session_count") or 0),
                "l7_accept_count":              int(stats.get("l7_accept_count")    or 0),
                "l7_reject_count":              int(stats.get("l7_reject_count")    or 0),
                "l7_reject_with_response_count":int(stats.get("l7_reject_with_response_count") or 0),
                # Lifecycle
                "create_time":   _epoch_ms_to_iso(create_time_ms),
                "modified_time": _epoch_ms_to_iso(mod_time_ms),
                "rule_age_days": _days_since(age_baseline_ms, now_ms),
            }
            # History-derived "last hit" anchor (approximate, accurate to snapshot frequency).
            # Keyed on (domain_id, policy_id, rule_id) so that two domains with same rule_id
            # don't collide in the history.
            hist = history.get((did, pol_id, rid)) or history.get((pol_id, rid)) or {}
            record["history_first_seen_iso"]  = hist.get("first_seen_iso")
            record["history_last_change_iso"] = hist.get("last_change_iso")
            record["history_counter_reset_observed"] = bool(hist.get("counter_reset_observed"))
            record["days_since_hit_changed"]  = _days_between_iso(now_iso, hist.get("last_change_iso"))
            record["history_snapshot_count"]  = snapshot_count
            record["classification"] = _classify(
                record, args.hot_threshold, args.fresh_days, args.stale_days,
            )
            rules_records.append(record)

    log.info("Collected %d customer rules total", len(rules_records))

    # Classification buckets
    by_class: Dict[str, List[Dict[str, Any]]] = {
        "HOT": [], "USED": [], "STALE": [], "UNUSED": [], "DORMANT": [],
    }
    for r in rules_records:
        by_class.setdefault(r["classification"], []).append(r)

    hot_rules     = sorted(rules_records, key=lambda r: r["hit_count"], reverse=True)[:args.top_n]
    unused_rules  = [r for r in rules_records if r["hit_count"] == 0]
    dormant_rules = [r for r in rules_records if r["classification"] == "DORMANT"]
    stale_rules   = [r for r in rules_records if r["classification"] == "STALE"]

    # --min-days-since-hit filter — emit a separate "no recent hits" view that
    # the operator can use to find rules unused in the past N days (e.g., 365).
    min_days_filter: Optional[List[Dict[str, Any]]] = None
    if args.min_days_since_hit is not None:
        min_days_filter = [
            r for r in rules_records
            if (r.get("days_since_hit_changed") is not None
                and r["days_since_hit_changed"] >= args.min_days_since_hit)
            # Include never-hit DORMANT rules too — those are always "no hit in N days"
            or (r["hit_count"] == 0 and (r.get("rule_age_days") or 0) >= args.min_days_since_hit)
        ]

    # =============================================================================
    # Diff mode
    # =============================================================================
    diff_records: Optional[List[Dict[str, Any]]] = None
    if args.compare_to:
        prior_dir = Path(args.compare_to).expanduser().resolve()
        prior_path = prior_dir / "rules_usage.json"
        if not prior_path.exists():
            log.warning("--compare-to: prior rules_usage.json not found at %s — skipping diff", prior_path)
        else:
            try:
                prior_doc = json.loads(prior_path.read_text(encoding="utf-8"))
                prior_by_key = {
                    (r.get("domain_id", "default"), r["policy_id"], r["rule_id"]): r
                    for r in (prior_doc.get("rules") or [])
                }
                current_by_key = {
                    (r.get("domain_id", "default"), r["policy_id"], r["rule_id"]): r
                    for r in rules_records
                }
                all_keys = set(prior_by_key) | set(current_by_key)
                diff_records = []
                for key in sorted(all_keys):
                    p_rec = prior_by_key.get(key)
                    c_rec = current_by_key.get(key)
                    p_hits = p_rec["hit_count"] if p_rec else None
                    c_hits = c_rec["hit_count"] if c_rec else None
                    delta = None
                    transition = "unchanged"
                    if p_rec and not c_rec:
                        transition = "removed_from_target"
                    elif c_rec and not p_rec:
                        transition = "new_on_target"
                    elif p_hits == 0 and c_hits and c_hits > 0:
                        transition = "lit_up"  # rule started matching traffic between snapshots
                        delta = c_hits - p_hits
                    elif p_hits and p_hits > 0 and c_hits == 0:
                        transition = "went_dormant"  # rule was matching, now isn't
                        delta = c_hits - p_hits
                    elif p_hits is not None and c_hits is not None:
                        delta = c_hits - p_hits
                        if delta != 0:
                            transition = "delta"
                    diff_records.append({
                        "domain_id":     key[0],
                        "policy_id":     key[1],
                        "rule_id":       key[2],
                        "transition":    transition,
                        "hit_count_prior":   p_hits,
                        "hit_count_current": c_hits,
                        "hit_count_delta":   delta,
                    })
                log.info("Diff mode: %d rules compared, %d transitions",
                         len(diff_records),
                         sum(1 for d in diff_records if d["transition"] != "unchanged"))
            except Exception as exc:
                log.exception("--compare-to: could not load prior report: %s", exc)
                diff_records = None

    # =============================================================================
    # Write reports
    # =============================================================================
    # Per-domain counter breakdown — every customer rule grouped by its source domain.
    per_domain_counts: Dict[str, Dict[str, int]] = {}
    for r in rules_records:
        slot = per_domain_counts.setdefault(r["domain_id"], {
            "rules": 0, "HOT": 0, "USED": 0, "STALE": 0, "UNUSED": 0, "DORMANT": 0,
            "total_hit_count": 0, "total_byte_count": 0, "total_packet_count": 0,
        })
        slot["rules"] += 1
        slot[r["classification"]] += 1
        slot["total_hit_count"]    += r["hit_count"]
        slot["total_byte_count"]   += r["byte_count"]
        slot["total_packet_count"] += r["packet_count"]

    summary = {
        "ran_at":           datetime.now(timezone.utc).isoformat(),
        "target":           f"alias:{args.target} ({target_host})",
        "domain_id":        args.domain_id,
        "all_domains_mode": args.all_domains,
        "domains_queried":  domains_to_query,
        "per_domain":       per_domain_counts,
        "federation_global": args.federation_global,
        "read_only":         True,
        "include_defaults": args.include_defaults,
        "hot_threshold":    args.hot_threshold,
        "fresh_days":       args.fresh_days,
        "stale_days":       args.stale_days,
        "history_snapshot_count": snapshot_count,
        "min_days_since_hit": args.min_days_since_hit,
        "counters": {
            "customer_policies":  len(customer_policies),
            "customer_rules":     len(rules_records),
            "HOT":                len(by_class["HOT"]),
            "USED":               len(by_class["USED"]),
            "STALE":              len(by_class["STALE"]),
            "UNUSED":             len(by_class["UNUSED"]),
            "DORMANT":            len(by_class["DORMANT"]),
            "total_hit_count":    sum(r["hit_count"]    for r in rules_records),
            "total_byte_count":   sum(r["byte_count"]   for r in rules_records),
            "total_packet_count": sum(r["packet_count"] for r in rules_records),
            "rules_filtered_by_min_days_since_hit": (
                len(min_days_filter) if min_days_filter is not None else None
            ),
        },
        "compare_to":  args.compare_to,
        "log_file":    str(log_file),
    }

    (reports_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (reports_dir / "rules_usage.json").write_text(
        json.dumps({"summary": summary, "rules": rules_records}, indent=2, sort_keys=True),
        encoding="utf-8")
    with (reports_dir / "rules_usage.jsonl").open("w", encoding="utf-8") as fh:
        for r in rules_records:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    def _write_filter(name: str, rule_list: List[Dict[str, Any]],
                      extra_meta: Optional[Dict[str, Any]] = None) -> None:
        """Emit a filter view as BOTH .json (with metadata + nested rules) and
        .jsonl (one rule per line, greppable). Keeps the two formats in sync —
        any future filter view that calls this helper gets both for free."""
        meta = {"count": len(rule_list)}
        if extra_meta:
            meta.update(extra_meta)
        (reports_dir / f"{name}.json").write_text(
            json.dumps({**meta, "rules": rule_list}, indent=2, sort_keys=True),
            encoding="utf-8")
        with (reports_dir / f"{name}.jsonl").open("w", encoding="utf-8") as fh:
            for r in rule_list:
                fh.write(json.dumps(r, sort_keys=True) + "\n")

    _write_filter("hot_rules",     hot_rules,     {"top_n": args.top_n})
    _write_filter("unused_rules",  unused_rules)
    _write_filter("dormant_rules", dormant_rules, {"fresh_days": args.fresh_days})
    _write_filter("stale_rules",   stale_rules,
                  {"stale_days": args.stale_days,
                   "history_snapshot_count": snapshot_count})

    if min_days_filter is not None:
        _write_filter("no_hits_in_n_days", min_days_filter, {
            "min_days_since_hit":     args.min_days_since_hit,
            "history_snapshot_count": snapshot_count,
            "note": ("Includes both STALE rules (had hits, none in N days) and "
                     "DORMANT rules (hit_count=0 throughout, rule older than N days). "
                     "If history_snapshot_count is low, 'days_since_hit_changed' is "
                     "based on a short observation window and may underestimate."),
        })
    if diff_records is not None:
        (reports_dir / "diff.json").write_text(
            json.dumps({"count": len(diff_records),
                        "compared_to": str(Path(args.compare_to).expanduser().resolve()),
                        "transitions": diff_records}, indent=2, sort_keys=True),
            encoding="utf-8")

    log.info("=" * 60)
    log.info("RULES USAGE — complete")
    log.info("  Customer policies        : %d", len(customer_policies))
    log.info("  Customer rules           : %d", len(rules_records))
    log.info("  HOT     (>= %d hits)        : %d", args.hot_threshold, len(by_class["HOT"]))
    log.info("  USED    (1..%d, recent)      : %d", args.hot_threshold - 1, len(by_class["USED"]))
    log.info("  STALE   (had hits, none in %dd) : %d", args.stale_days, len(by_class["STALE"]))
    log.info("  UNUSED  (0 hits, <= %dd old)    : %d", args.fresh_days, len(by_class["UNUSED"]))
    log.info("  DORMANT (0 hits, > %dd old)     : %d", args.fresh_days, len(by_class["DORMANT"]))
    log.info("  History snapshots scanned     : %d", snapshot_count)
    if args.min_days_since_hit is not None and min_days_filter is not None:
        log.info("  Rules with no hits in >= %dd  : %d (see no_hits_in_n_days.json)",
                 args.min_days_since_hit, len(min_days_filter))
    log.info("  Total hit_count          : %d", summary["counters"]["total_hit_count"])
    log.info("  Total byte_count         : %d", summary["counters"]["total_byte_count"])
    if diff_records is not None:
        lit_up      = sum(1 for d in diff_records if d["transition"] == "lit_up")
        went_dorm   = sum(1 for d in diff_records if d["transition"] == "went_dormant")
        delta_only  = sum(1 for d in diff_records if d["transition"] == "delta")
        log.info("  Diff: lit_up=%d  went_dormant=%d  delta=%d", lit_up, went_dorm, delta_only)
    log.info("Report: %s", reports_dir)
    log.info("=" * 60)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
