#!/usr/bin/env python3
"""tools/pan/report_flow_rules.py

Batch "which rules cover these flows" report for Panorama.

This is the PAN analogue of tools/reports/report_vms_in_rules.py. Where the
NSX report takes a list of VMs and finds every DFW rule that touches them,
this takes a list of source/destination pairs and finds every Panorama
security rule that covers them, grouped by flow AND rolled up by rule.

TWO INPUT LISTS drive the report:

  1. --flows <csv>
     A CSV of source/destination pairs, one row per flow to look up.
     Optional per-row protocol, port and zones. See "FLOW CSV" below.

  2. --subnet-filter <file>
     A list of subnets used to SUPPRESS matches by attribution. A rule that
     matched a flow is dropped from the report when the ONLY reason it
     matched is an address drawn from one of these subnets. See
     "SUBNET FILTER" below.

Unlike check_policy_match.py (which returns the single first-match verdict),
this reports EVERY rule in the evaluation chain that covers each flow, and
flags which one actually decides the traffic. Shadowed rules are exactly
what a cleanup or consolidation review needs to see.

THIS IS READ-ONLY. It parses an exported Panorama config XML and writes
report files to disk. No writes back to Panorama.

FLOW CSV
--------
Header row is auto-detected; column names are case-insensitive and accept
common aliases:

    source       src, src_ip, source_ip, from
    destination  dst, dest, dst_ip, destination_ip, to
    protocol     proto                                   (optional)
    port         dst_port, destination_port              (optional)
    src_zone     source_zone                             (optional)
    dst_zone     destination_zone                        (optional)
    name         label, id, flow, ticket                 (optional)

A headerless file is also accepted, positionally:
    src, dst[, protocol[, port]]

Blank lines and lines starting with '#' are ignored. Source and destination
must be single host IPs (a /32 or /128 suffix is tolerated and stripped);
rows carrying a wider CIDR are reported as invalid rather than silently
tested on their network address.

SUBNET FILTER
-------------
Each non-comment line is a subnet (a bare IP is read as /32 or /128).

When a rule matches a flow, the tool records WHICH address object and WHICH
network inside it actually covered the source IP, and the same for the
destination. That attribution is what the filter acts on:

  A side's match is filtered when EVERY network that covered the IP on that
  side is excluded by the list. If any covering network survives, the match
  is a real one and the rule stays in the report.

  If either the source side or the destination side is filtered, the whole
  rule/flow match is suppressed.

That "every covering network" rule is deliberate. If a rule's source is an
address group holding both 10.0.0.0/8 (filtered) and 10.6.0.101/32 (not
filtered), a flow from 10.6.0.101 is a genuine specific match and the rule
is kept, even though the broad object also covered it.

Two comparison modes control what "excluded by the list" means:

  --subnet-filter-mode broad   (default)
      A covering network is excluded when it equals a listed subnet or is
      BROADER than one. Listing 10.0.0.0/8 drops matches attributed to the
      10.0.0.0/8 object itself and to any/0.0.0.0/0, but keeps a match on a
      specific 10.6.0.101/32 object. Use this to strip out matches that only
      happened because a rule carries a catch-all address object.

  --subnet-filter-mode within
      A covering network is excluded when it equals a listed subnet or sits
      INSIDE one. Listing 10.0.0.0/8 drops every match attributed to
      anything in 10/8. Use this to mute an entire address space.

A rule with a negated source or destination is never suppressed by the
subnet filter: a negated match cannot be attributed to a covering network.

Suppressed matches are not thrown away silently. They are written to
suppressed_matches.jsonl with the attribution that got them dropped, and
when a suppressed rule sits EARLIER in the chain than the reported deciding
rule, the flow is flagged 'shadowed_by_suppressed' so the report never
implies the wrong rule is enforcing.

USAGE
-----
    python tools/pan/report_flow_rules.py \\
        --config tools/pan/configs/<customer>-<ts>.xml \\
        --flows pan_flow_report_targets.csv \\
        --subnet-filter tools/pan/subnet_filter.txt

    --live candidate|running   pull the config first (GET-only), then report
    --device-group NAME        scope to one DG (default: all device groups)
    --include-defaults         keep intrazone/interzone-default matches
    --no-subnet-filter         bypass the subnet list entirely
    --rule-filter / --skip-rule / --no-filter
                               rule-NAME filtering, same as check_policy_match

OUTPUT
------
    $PANO_REPORTS_DIR/flow_rule_report/<UTC_TS>/
        summary.json                counters + both filters as applied
        flow_rules.json             per-flow record, every matching rule
        flow_rules.jsonl            one row per kept (flow, dg, rule) match
        suppressed_matches.jsonl    one row per subnet-filtered match
        report.md                   by-flow detail + by-rule rollup
        logs/
"""
from __future__ import annotations

import argparse
import csv
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

REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
DEFAULT_FLOW_FILENAME = "pan_flow_report_targets.csv"
DEFAULT_SUBNET_FILTER_FILENAME = "subnet_filter.txt"

SRC_ALIASES  = ("source", "src", "src_ip", "source_ip", "from")
DST_ALIASES  = ("destination", "dst", "dest", "dst_ip", "destination_ip", "to")
PROTO_ALIASES = ("protocol", "proto")
PORT_ALIASES = ("port", "dst_port", "destination_port")
SZONE_ALIASES = ("src_zone", "source_zone", "from_zone")
DZONE_ALIASES = ("dst_zone", "destination_zone", "to_zone")
NAME_ALIASES = ("name", "label", "id", "flow", "ticket")


# =============================================================================
# Input list 1 - the flow CSV
# =============================================================================

@dataclass
class Flow:
    row:      int
    label:    str
    src:      str
    dst:      str
    protocol: Optional[str] = None
    dst_port: Optional[int] = None
    src_zone: Optional[str] = None
    dst_zone: Optional[str] = None

    def describe(self) -> str:
        svc = ""
        if self.protocol or self.dst_port is not None:
            svc = f" {self.protocol or 'ip'}/{self.dst_port if self.dst_port is not None else 'any'}"
        return f"{self.src} -> {self.dst}{svc}"


def _norm_ip(token: str) -> Tuple[Optional[str], Optional[str]]:
    """Normalise a flow endpoint to a host IP string.

    Returns (ip, error). A /32 or /128 suffix is stripped; a wider CIDR is
    an error, because a network cannot be evaluated as a single host IP and
    silently testing its network address would misreport the result.
    """
    token = token.strip()
    if not token:
        return None, "empty value"
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            return None, f"not an IP or CIDR: {token!r}"
        if net.num_addresses != 1:
            return None, (f"{token!r} is a network, not a host IP; "
                          f"list the individual hosts you want evaluated")
        return str(net.network_address), None
    try:
        return str(ipaddress.ip_address(token)), None
    except ValueError:
        return None, f"not an IP address: {token!r}"


def _pick(header_map: Dict[str, int], aliases: Tuple[str, ...]) -> Optional[int]:
    for a in aliases:
        if a in header_map:
            return header_map[a]
    return None


def _resolve_flow_path(explicit: Optional[str]) -> Path:
    """--flows > PAN_FLOW_REPORT_LIST > repo-root pan_flow_report_targets.csv."""
    explicit = (explicit or "").strip()
    if explicit:
        p = Path(os.path.expandvars(explicit)).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"--flows file not found: {p}")
        return p
    envvar = (os.getenv("PAN_FLOW_REPORT_LIST") or "").strip()
    if envvar:
        p = Path(os.path.expandvars(envvar)).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"PAN_FLOW_REPORT_LIST file not found: {p}")
        return p
    p = REPO_ROOT / DEFAULT_FLOW_FILENAME
    if p.exists():
        return p
    raise FileNotFoundError(
        f"no flow list given. Pass --flows <csv>, set PAN_FLOW_REPORT_LIST, "
        f"or create {p}"
    )


def load_flows(path: Path) -> Tuple[List[Flow], List[Dict[str, Any]]]:
    """Parse the flow CSV. Returns (flows, invalid_rows)."""
    raw_lines = path.read_text(encoding="utf-8").splitlines()
    # Keep original line numbers so an operator can find a bad row.
    numbered = [(i, ln) for i, ln in enumerate(raw_lines, start=1)
                if ln.strip() and not ln.strip().startswith("#")]
    if not numbered:
        return [], []

    line_nums = [i for i, _ in numbered]
    body = [ln for _, ln in numbered]
    rows = list(csv.reader(body))

    flows: List[Flow] = []
    invalid: List[Dict[str, Any]] = []

    # Header detection: first row has no parseable IP in its first two cells
    # and at least one recognised column name.
    header_map: Dict[str, int] = {}
    start = 0
    if rows:
        first = [c.strip().lower() for c in rows[0]]
        known = set(SRC_ALIASES) | set(DST_ALIASES) | set(PROTO_ALIASES) \
            | set(PORT_ALIASES) | set(SZONE_ALIASES) | set(DZONE_ALIASES) | set(NAME_ALIASES)
        if any(c in known for c in first):
            header_map = {c: i for i, c in enumerate(first) if c}
            start = 1

    if header_map:
        i_src   = _pick(header_map, SRC_ALIASES)
        i_dst   = _pick(header_map, DST_ALIASES)
        i_proto = _pick(header_map, PROTO_ALIASES)
        i_port  = _pick(header_map, PORT_ALIASES)
        i_sz    = _pick(header_map, SZONE_ALIASES)
        i_dz    = _pick(header_map, DZONE_ALIASES)
        i_name  = _pick(header_map, NAME_ALIASES)
        if i_src is None or i_dst is None:
            raise ValueError(
                f"{path}: header row found but no source/destination column. "
                f"Expected one of {SRC_ALIASES} and one of {DST_ALIASES}; "
                f"got {sorted(header_map)}"
            )
    else:
        i_src, i_dst, i_proto, i_port = 0, 1, 2, 3
        i_sz = i_dz = i_name = None
        log.info("%s: no header row detected, reading positionally as "
                 "src,dst[,protocol[,port]]", path.name)

    def cell(row: List[str], idx: Optional[int]) -> str:
        if idx is None or idx >= len(row):
            return ""
        return row[idx].strip()

    for offset, row in enumerate(rows[start:], start=start):
        lineno = line_nums[offset]
        if not any(c.strip() for c in row):
            continue
        src_raw, dst_raw = cell(row, i_src), cell(row, i_dst)
        if not src_raw or not dst_raw:
            invalid.append({"line": lineno, "raw": ",".join(row),
                            "error": "missing source or destination"})
            continue
        src, err_s = _norm_ip(src_raw)
        dst, err_d = _norm_ip(dst_raw)
        if err_s or err_d:
            invalid.append({"line": lineno, "raw": ",".join(row),
                            "error": err_s or err_d})
            continue

        proto = (cell(row, i_proto) or "").lower() or None
        if proto in ("any", "-", "ip"):
            proto = None
        if proto and proto not in ("tcp", "udp"):
            invalid.append({"line": lineno, "raw": ",".join(row),
                            "error": f"protocol must be tcp, udp or blank; got {proto!r}"})
            continue

        port_raw = cell(row, i_port)
        port: Optional[int] = None
        if port_raw and port_raw.lower() not in ("any", "-"):
            try:
                port = int(port_raw)
            except ValueError:
                invalid.append({"line": lineno, "raw": ",".join(row),
                                "error": f"port not an integer: {port_raw!r}"})
                continue

        label = cell(row, i_name) or f"row{lineno}"
        flows.append(Flow(
            row=lineno, label=label, src=src, dst=dst,
            protocol=proto, dst_port=port,
            src_zone=cell(row, i_sz) or None,
            dst_zone=cell(row, i_dz) or None,
        ))

    return flows, invalid


# =============================================================================
# Input list 2 - the subnet filter
# =============================================================================

IPNet = cpm.IPNet


def load_subnet_filter(explicit_path: Optional[Path],
                       inline: Optional[List[str]],
                       disabled: bool,
                       ) -> Tuple[List[IPNet], Optional[Path]]:
    """Load the subnet exclusion list.

    Resolution order mirrors check_policy_match._load_rule_filter:
      1. --no-subnet-filter  -> empty, no file consulted
      2. --subnet-filter <path>
      3. tools/pan/subnet_filter.txt next to this script, if present
    Any --exclude-subnet values from the CLI are always merged in.
    """
    nets: List[IPNet] = []
    source: Optional[Path] = None

    def add(token: str, origin: str) -> None:
        token = token.strip()
        if not token:
            return
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            try:
                net = ipaddress.ip_network(token + "/32", strict=False)
            except ValueError:
                log.warning("%s: skipping unparseable subnet %r", origin, token)
                return
        if net not in nets:
            nets.append(net)

    for tok in (inline or []):
        add(tok, "--exclude-subnet")

    if disabled:
        return nets, None

    if explicit_path is not None:
        source = Path(explicit_path).expanduser().resolve()
        if not source.exists():
            raise FileNotFoundError(f"--subnet-filter file not found: {source}")
    else:
        default_path = Path(__file__).resolve().parent / DEFAULT_SUBNET_FILTER_FILENAME
        if default_path.exists():
            source = default_path

    if source is not None:
        for line in source.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                add(line, str(source))

    return nets, source


@dataclass
class Attribution:
    """Which address object, and which network inside it, covered the IP."""
    object_name: str
    network:     str
    net:         IPNet

    def to_json(self) -> Dict[str, str]:
        return {"object": self.object_name, "network": self.network}


def _net_excluded(net: IPNet, filt: IPNet, mode: str) -> bool:
    """Is a covering network excluded by a listed filter subnet?"""
    if net.version != filt.version:
        return False
    try:
        if mode == "within":
            # net equals filt, or sits inside it
            return net.subnet_of(filt)
        # 'broad': net equals filt, or is broader than it
        return filt.subnet_of(net)
    except TypeError:
        return False


def _suppression_reason(attrs: List[Attribution], filter_nets: List[IPNet],
                        mode: str, side: str) -> Optional[str]:
    """Suppress only when EVERY covering network on this side is excluded.

    One surviving covering network means the rule matched for a real,
    specific reason and the match is kept.
    """
    if not attrs or not filter_nets:
        return None
    hits: List[str] = []
    for a in attrs:
        matched_filter = next(
            (f for f in filter_nets if _net_excluded(a.net, f, mode)), None)
        if matched_filter is None:
            return None
        hits.append(f"{a.object_name}={a.network} (filtered by {matched_filter})")
    return f"{side} match attributable only to filtered subnets: " + "; ".join(hits)


def attribute_match(ip_str: str, address_names: List[str],
                    config: "cpm.PanoramaConfig",
                    ) -> Tuple[bool, List[Attribution], List[str]]:
    """Like check_policy_match._match_addresses, but records WHY it matched."""
    caveats: List[str] = []
    ip = ipaddress.ip_address(ip_str)
    if "any" in address_names:
        any_net = ipaddress.ip_network("0.0.0.0/0") if ip.version == 4 \
            else ipaddress.ip_network("::/0")
        return True, [Attribution("any", str(any_net), any_net)], caveats
    attrs: List[Attribution] = []
    for name in address_names:
        nets, c = config.resolve_address(name)
        caveats.extend(c)
        for n in nets:
            if ip in n:
                attrs.append(Attribution(name, str(n), n))
    return bool(attrs), attrs, caveats


# =============================================================================
# Scan - every rule in the chain that covers a flow
# =============================================================================

@dataclass
class RuleMatch:
    device_group: str
    rulebase:     str
    position:     int
    name:         str
    action:       str
    source_addresses:      List[str]
    destination_addresses: List[str]
    services:     List[str]
    applications: List[str]
    src_attributions: List[Attribution] = field(default_factory=list)
    dst_attributions: List[Attribution] = field(default_factory=list)
    deciding:     bool = False
    is_default:   bool = False
    suppressed_reason: Optional[str] = None
    caveats:      List[str] = field(default_factory=list)

    @property
    def key(self) -> Tuple[str, int, str]:
        return (self.rulebase, self.position, self.name)

    def to_json(self) -> Dict[str, Any]:
        return {
            "device_group": self.device_group,
            "rulebase":     self.rulebase,
            "position":     self.position,
            "name":         self.name,
            "action":       self.action,
            "deciding":     self.deciding,
            "is_default":   self.is_default,
            "source_addresses":      self.source_addresses,
            "destination_addresses": self.destination_addresses,
            "services":     self.services,
            "applications": self.applications,
            "src_attribution": [a.to_json() for a in self.src_attributions],
            "dst_attribution": [a.to_json() for a in self.dst_attributions],
            "suppressed_reason": self.suppressed_reason,
            "caveats":      sorted(set(self.caveats)),
        }


@dataclass
class FlowResult:
    flow:      Flow
    device_groups: List[str] = field(default_factory=list)
    matches:   List[RuleMatch] = field(default_factory=list)
    suppressed: List[RuleMatch] = field(default_factory=list)
    shadowed_by_suppressed: List[RuleMatch] = field(default_factory=list)
    caveats:   List[str] = field(default_factory=list)

    # Each device group runs its own evaluation chain, so each one has its
    # own deciding rule. Everything below is scoped per DG for that reason.
    def matches_for(self, dg: str) -> List[RuleMatch]:
        return [m for m in self.matches if m.device_group == dg]

    def suppressed_for(self, dg: str) -> List[RuleMatch]:
        return [m for m in self.suppressed if m.device_group == dg]

    def shadowed_for(self, dg: str) -> List[RuleMatch]:
        return [m for m in self.shadowed_by_suppressed if m.device_group == dg]

    def deciding_for(self, dg: str) -> Optional[RuleMatch]:
        return next((m for m in self.matches
                     if m.device_group == dg and m.deciding), None)

    @property
    def custom_matches(self) -> List[RuleMatch]:
        """Matches on real rules, excluding the synthetic PAN defaults."""
        return [m for m in self.matches if not m.is_default]

    def to_json(self) -> Dict[str, Any]:
        by_dg: Dict[str, Any] = {}
        for dg in self.device_groups:
            d = self.deciding_for(dg)
            by_dg[dg] = {
                "effective_action":   d.action if d else None,
                "effective_rule":     d.name if d else None,
                "effective_rulebase": d.rulebase if d else None,
                "effective_is_default": d.is_default if d else None,
                "match_count":      len(self.matches_for(dg)),
                "suppressed_count": len(self.suppressed_for(dg)),
                "shadowed_by_suppressed": [
                    {"rulebase": m.rulebase, "position": m.position,
                     "name": m.name, "reason": m.suppressed_reason}
                    for m in self.shadowed_for(dg)
                ],
            }
        return {
            "label":    self.flow.label,
            "csv_line": self.flow.row,
            "src_ip":   self.flow.src,
            "dst_ip":   self.flow.dst,
            "protocol": self.flow.protocol,
            "dst_port": self.flow.dst_port,
            "src_zone": self.flow.src_zone,
            "dst_zone": self.flow.dst_zone,
            "match_count":        len(self.matches),
            "custom_match_count": len(self.custom_matches),
            "suppressed_count":   len(self.suppressed),
            "by_device_group":    by_dg,
            "matches":    [m.to_json() for m in self.matches],
            "suppressed": [m.to_json() for m in self.suppressed],
            "caveats":    sorted(set(self.caveats)),
        }


def scan_flow(config: "cpm.PanoramaConfig", flow: Flow, device_groups: List[str],
              rule_filter: List[str], filter_nets: List[IPNet], filter_mode: str,
              include_defaults: bool) -> FlowResult:
    """Walk each DG's evaluation chain and collect EVERY covering rule."""
    result = FlowResult(flow=flow, device_groups=list(device_groups))
    if not flow.src_zone or not flow.dst_zone:
        result.caveats.append(
            "flow is zone-agnostic (src_zone or dst_zone not supplied); rules "
            "with specific zone restrictions are treated as matching")

    for dg in device_groups:
        chain = config.evaluation_chain(dg)
        if rule_filter:
            chain = [r for r in chain
                     if not cpm._rule_matches_filter(r.name, rule_filter)]
        query = cpm.Query(
            src_ip=flow.src, dst_ip=flow.dst,
            src_zone=flow.src_zone, dst_zone=flow.dst_zone,
            protocol=flow.protocol, dst_port=flow.dst_port, device_group=dg,
        )
        decided_here = False

        for rule in chain:
            if rule.disabled:
                continue
            is_default = rule.rulebase_path == "default-rules"
            # The defaults are any/any and always match. Only the one that
            # actually decides the traffic is worth reporting.
            if is_default and decided_here and not include_defaults:
                continue
            if flow.src_zone and "any" not in rule.source_zones \
                    and flow.src_zone not in rule.source_zones:
                continue
            if flow.dst_zone and "any" not in rule.destination_zones \
                    and flow.dst_zone not in rule.destination_zones:
                continue

            src_ok, src_attrs, src_cav = attribute_match(
                flow.src, rule.source_addresses, config)
            if rule.negate_source:
                src_ok, src_attrs = (not src_ok), []
            if not src_ok:
                continue

            dst_ok, dst_attrs, dst_cav = attribute_match(
                flow.dst, rule.destination_addresses, config)
            if rule.negate_destination:
                dst_ok, dst_attrs = (not dst_ok), []
            if not dst_ok:
                continue

            svc_ok, svc_cav = cpm._match_services(query, rule.services, config)
            if not svc_ok:
                continue

            caveats = list(src_cav) + list(dst_cav) + list(svc_cav)
            if "any" not in rule.applications:
                caveats.append(
                    f"rule requires application(s) {rule.applications!r}; "
                    f"App-ID cannot be evaluated offline")
            if rule.negate_source or rule.negate_destination:
                caveats.append(
                    "rule uses a negated address; subnet filter does not apply "
                    "because a negated match has no covering network")

            match = RuleMatch(
                device_group=dg, rulebase=rule.rulebase_path,
                position=rule.position, name=rule.name, action=rule.action,
                source_addresses=list(rule.source_addresses),
                destination_addresses=list(rule.destination_addresses),
                services=list(rule.services), applications=list(rule.applications),
                src_attributions=src_attrs, dst_attributions=dst_attrs,
                is_default=is_default, caveats=caveats,
            )

            reason = None
            if filter_nets:
                reason = (_suppression_reason(src_attrs, filter_nets, filter_mode, "source")
                          or _suppression_reason(dst_attrs, filter_nets, filter_mode, "destination"))
            if reason:
                match.suppressed_reason = reason
                result.suppressed.append(match)
                if not decided_here:
                    # A dropped rule sitting ahead of the rule we are about to
                    # report as deciding. Say so, or the report implies the
                    # wrong rule is enforcing.
                    result.shadowed_by_suppressed.append(match)
                continue

            if not decided_here:
                match.deciding = True
                decided_here = True
            result.matches.append(match)

    return result


# =============================================================================
# Output
# =============================================================================

def _md_table(headers: List[str], rows: List[List[Any]]) -> str:
    def cell(v: Any) -> str:
        return ("" if v is None else str(v)).replace("|", "\\|")
    srows = [[cell(c) for c in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in srows:
        for i in range(len(headers)):
            if i < len(r):
                widths[i] = max(widths[i], len(r[i]))
    out = ["| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + " |",
           "| " + " | ".join("-" * widths[i] for i in range(len(headers))) + " |"]
    for r in srows:
        out.append("| " + " | ".join(
            (r[i] if i < len(r) else "").ljust(widths[i])
            for i in range(len(headers))) + " |")
    return "\n".join(out)


def build_markdown(results: List[FlowResult], invalid: List[Dict[str, Any]],
                   summary: Dict[str, Any]) -> str:
    L: List[str] = []
    L.append("# Panorama flow / rule report")
    L.append("")
    L.append(f"Generated: {summary['generated_utc']}")
    L.append(f"Config: `{summary['config']}`")
    L.append(f"Device groups: {', '.join(summary['device_groups'])}")
    L.append("")

    sf = summary["subnet_filter"]
    L.append("## Filters applied")
    L.append("")
    L.append(f"- Subnet filter: {len(sf['subnets'])} subnet(s), mode `{sf['mode']}`"
             + (f", from `{sf['source']}`" if sf["source"] else ""))
    for s in sf["subnets"]:
        L.append(f"  - `{s}`")
    rf = summary["rule_filter"]
    L.append(f"- Rule-name filter: {len(rf['keywords'])} keyword(s)"
             + (f", from `{rf['source']}`" if rf["source"] else ""))
    L.append("")

    L.append("## Summary")
    L.append("")
    L.append(_md_table(
        ["Metric", "Value"],
        [["Flows evaluated", summary["flows_total"]],
         ["Flows covered by a real rule", summary["flows_with_custom_match"]],
         ["Flows falling through to a default rule only",
          summary["flows_without_custom_match"]],
         ["Invalid CSV rows", summary["flows_invalid"]],
         ["Rule matches reported", summary["rule_matches_total"]],
         ["Rule matches suppressed by subnet filter", summary["rule_matches_suppressed"]],
         ["Flows whose deciding rule is shadowed by a suppressed rule",
          summary["flows_shadowed_by_suppressed"]],
         ["Distinct rules touched", summary["rules_touched"]]]))
    L.append("")

    L.append("## Flows")
    L.append("")
    L.append("One row per flow per device group: each device group runs its own "
             "evaluation chain and so has its own deciding rule.")
    L.append("")
    rows = []
    for r in results:
        for dg in r.device_groups:
            d = r.deciding_for(dg)
            rows.append([
                r.flow.label, dg, r.flow.src, r.flow.dst,
                r.flow.protocol or "any",
                r.flow.dst_port if r.flow.dst_port is not None else "any",
                (cpm.ACTION_LABELS.get(d.action, d.action.upper()) if d else "NO MATCH"),
                (f"{d.name} (default)" if d and d.is_default else (d.name if d else "-")),
                len(r.matches_for(dg)), len(r.suppressed_for(dg)),
            ])
    L.append(_md_table(
        ["Flow", "DG", "Source", "Destination", "Proto", "Port",
         "Effective", "Deciding rule", "Rules", "Suppressed"], rows))
    L.append("")

    L.append("## Flow detail")
    L.append("")
    for r in results:
        L.append(f"### {r.flow.label}: {r.flow.describe()}")
        L.append("")
        if r.shadowed_by_suppressed:
            L.append("> WARNING: the following rules matched EARLIER in the chain but "
                     "were removed by the subnet filter. On the real firewall one of "
                     "them decides this traffic, not the rule reported below.")
            L.append(">")
            for m in r.shadowed_by_suppressed:
                L.append(f"> - [{m.device_group}] `{m.rulebase}` pos {m.position} "
                         f"`{m.name}` ({m.action}) - {m.suppressed_reason}")
            L.append("")
        if not r.matches:
            L.append("No rule in any evaluated chain covers this flow.")
            L.append("")
            continue
        mrows = []
        for m in r.matches:
            mrows.append([
                "YES" if m.deciding else "",
                m.device_group, m.rulebase, m.position, m.name, m.action,
                ", ".join(a.network for a in m.src_attributions) or "-",
                ", ".join(a.network for a in m.dst_attributions) or "-",
                ", ".join(m.services),
            ])
        L.append(_md_table(
            ["Deciding", "DG", "Rulebase", "Pos", "Rule", "Action",
             "Src matched via", "Dst matched via", "Services"], mrows))
        L.append("")
        cav = sorted({c for m in r.matches for c in m.caveats} | set(r.caveats))
        if cav:
            L.append("Caveats:")
            for c in cav:
                L.append(f"- {c}")
            L.append("")

    L.append("## Rule rollup")
    L.append("")
    rollup: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
    for r in results:
        for m in r.matches:
            e = rollup.setdefault(m.key, {
                "rulebase": m.rulebase, "position": m.position, "name": m.name,
                "action": m.action, "dgs": set(), "flows": [], "deciding_for": 0,
            })
            e["dgs"].add(m.device_group)
            if r.flow.label not in e["flows"]:
                e["flows"].append(r.flow.label)
            if m.deciding:
                e["deciding_for"] += 1
    if not rollup:
        L.append("No rules matched any flow.")
    else:
        rrows = []
        for e in sorted(rollup.values(),
                        key=lambda x: (-len(x["flows"]), x["rulebase"], x["position"])):
            rrows.append([e["rulebase"], e["position"], e["name"], e["action"],
                          len(e["flows"]), e["deciding_for"],
                          ", ".join(sorted(e["dgs"])),
                          ", ".join(e["flows"])])
        L.append(_md_table(
            ["Rulebase", "Pos", "Rule", "Action", "Flows", "Deciding for",
             "Device groups", "Flow labels"], rrows))
    L.append("")

    if invalid:
        L.append("## Invalid CSV rows")
        L.append("")
        L.append(_md_table(["Line", "Row", "Error"],
                           [[i["line"], i["raw"], i["error"]] for i in invalid]))
        L.append("")

    return "\n".join(L) + "\n"


# =============================================================================
# CLI
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(
        description="Report every Panorama rule covering a CSV of flows, "
                    "with a subnet list that suppresses matches by attribution.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--config", default=None,
                     help="Panorama running/candidate config XML to evaluate.")
    src.add_argument("--live", choices=["candidate", "running"], default=None,
                     help="Pull the config from Panorama first (GET-only), then report.")

    p.add_argument("--flows", default=None,
                   help="Flow CSV. Precedence: --flows > PAN_FLOW_REPORT_LIST > "
                        f"repo-root {DEFAULT_FLOW_FILENAME}.")

    p.add_argument("--subnet-filter", default=None,
                   help=f"Subnet exclusion list. Defaults to tools/pan/"
                        f"{DEFAULT_SUBNET_FILTER_FILENAME} if present.")
    p.add_argument("--exclude-subnet", action="append", default=[], metavar="CIDR",
                   help="Extra subnet to exclude, repeatable. Merged with the file.")
    p.add_argument("--subnet-filter-mode", choices=["broad", "within"], default="broad",
                   help="'broad' (default): drop a match when its covering network "
                        "equals or is broader than a listed subnet. 'within': drop "
                        "when the covering network equals or sits inside one.")
    p.add_argument("--no-subnet-filter", action="store_true",
                   help="Ignore the subnet list entirely.")

    dg = p.add_mutually_exclusive_group()
    dg.add_argument("--device-group", default=None,
                    help="Scope to a single device group.")
    dg.add_argument("--all-device-groups", action="store_true",
                    help="Evaluate every device group (default).")

    p.add_argument("--rule-filter", default=None,
                   help="Rule-NAME filter file (see rule_filter.example.txt).")
    p.add_argument("--skip-rule", action="append", default=[],
                   help="Extra rule-name substring to filter, repeatable.")
    p.add_argument("--no-filter", action="store_true",
                   help="Ignore the rule-name filter entirely.")

    p.add_argument("--include-defaults", action="store_true",
                   help="Report intrazone/interzone-default matches beyond the "
                        "one that decides the flow.")
    p.add_argument("--output-dir", default=None,
                   help="Report root. Defaults to $PANO_REPORTS_DIR.")
    p.add_argument("--no-disk", action="store_true",
                   help="Do not write report files; stdout only.")
    p.add_argument("--json", action="store_true",
                   help="Emit the full report as JSON on stdout.")
    args = p.parse_args()

    import time as _time
    logging.Formatter.converter = _time.gmtime
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr,
    )

    if not args.config and not args.live:
        p.error("one of --config or --live is required")

    # ----- Input list 1: flows -----
    try:
        flow_path = _resolve_flow_path(args.flows)
        flows, invalid = load_flows(flow_path)
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        return 2
    log.info("Loaded %d flow(s) from %s (%d invalid row(s))",
             len(flows), flow_path, len(invalid))
    for i in invalid:
        log.warning("flow list line %s skipped: %s", i["line"], i["error"])
    if not flows:
        log.error("no usable flows in %s", flow_path)
        return 2

    # ----- Input list 2: subnets -----
    try:
        filter_nets, subnet_source = load_subnet_filter(
            explicit_path=(Path(args.subnet_filter) if args.subnet_filter else None),
            inline=args.exclude_subnet, disabled=args.no_subnet_filter,
        )
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 2
    if filter_nets:
        log.info("Subnet filter active: %d subnet(s), mode=%s%s",
                 len(filter_nets), args.subnet_filter_mode,
                 f", from {subnet_source}" if subnet_source else " (CLI only)")
        # In 'within' mode a default route swallows the entire report: every
        # covering network sits inside 0.0.0.0/0. Say so rather than emit an
        # empty report the operator has to work backwards from.
        if args.subnet_filter_mode == "within":
            catch_all = [n for n in filter_nets if n.prefixlen == 0]
            if catch_all:
                log.warning(
                    "subnet filter contains %s in 'within' mode: EVERY match sits "
                    "inside it, so every rule will be suppressed. Drop that entry, "
                    "or use --subnet-filter-mode broad to hide only any/any rules.",
                    ", ".join(str(n) for n in catch_all))

    # ----- Rule-name filter (same loader as check_policy_match) -----
    try:
        rule_filter, rule_filter_source = cpm._load_rule_filter(
            explicit_path=(Path(args.rule_filter) if args.rule_filter else None),
            inline_keywords=args.skip_rule, disabled=args.no_filter,
        )
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 2
    if rule_filter:
        log.info("Rule-name filter active: %d keyword(s)", len(rule_filter))

    # ----- Config -----
    if args.live:
        import subprocess
        pull_cmd = [sys.executable,
                    str(Path(__file__).resolve().parent / "pull_panorama_config.py")]
        if args.live == "running":
            pull_cmd.append("--running")
        log.info("--live %s: pulling config from Panorama (GET-only) ...", args.live)
        proc = subprocess.run(pull_cmd, capture_output=True, text=True, cwd=REPO_ROOT)
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            log.error("--live pull failed (exit %d); check .env Panorama credentials",
                      proc.returncode)
            return 2
        pulled = proc.stdout.strip().splitlines()[-1].strip()
        if not pulled or not Path(pulled).exists():
            log.error("--live pull did not yield a config file (got %r)", pulled)
            return 2
        args.config = pulled
    config = cpm.PanoramaConfig(Path(args.config))

    # ----- Device groups -----
    if not args.device_group and not args.all_device_groups:
        args.all_device_groups = True
    if args.all_device_groups:
        target_dgs = list(config.device_groups.keys()) or ["shared"]
    else:
        if (args.device_group not in config.device_groups
                and args.device_group != "shared"):
            log.warning("device-group %r not found. Known: %s",
                        args.device_group, sorted(config.device_groups))
        target_dgs = [args.device_group]
    log.info("Evaluating %d flow(s) against %d device group(s)",
             len(flows), len(target_dgs))

    # ----- Scan -----
    results = [scan_flow(config, f, target_dgs, rule_filter, filter_nets,
                         args.subnet_filter_mode, args.include_defaults)
               for f in flows]

    rules_touched = {m.key for r in results for m in r.matches}
    summary = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "config": str(Path(args.config).resolve()),
        "flow_list": str(flow_path.resolve()),
        "device_groups": target_dgs,
        "flows_total": len(flows),
        "flows_invalid": len(invalid),
        "flows_with_custom_match": sum(1 for r in results if r.custom_matches),
        "flows_without_custom_match": sum(1 for r in results if not r.custom_matches),
        "flows_shadowed_by_suppressed":
            sum(1 for r in results if r.shadowed_by_suppressed),
        "rule_matches_total": sum(len(r.matches) for r in results),
        "rule_matches_suppressed": sum(len(r.suppressed) for r in results),
        "rules_touched": len(rules_touched),
        "subnet_filter": {
            "source": str(subnet_source) if subnet_source else None,
            "mode": args.subnet_filter_mode,
            "subnets": [str(n) for n in filter_nets],
        },
        "rule_filter": {
            "source": str(rule_filter_source) if rule_filter_source else None,
            "keywords": rule_filter,
        },
    }

    # ----- Write -----
    if not args.no_disk:
        base = (Path(args.output_dir).expanduser().resolve() if args.output_dir
                else cpm._resolve_default_output_dir().expanduser().resolve())
        out_dir = base / "flow_rule_report" / RUN_TS
        (out_dir / "logs").mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(out_dir / "logs" / f"flow_rule_report_{RUN_TS}.log",
                                 encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
            "%Y-%m-%dT%H:%M:%S"))
        logging.getLogger().addHandler(fh)

        (out_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        (out_dir / "flow_rules.json").write_text(
            json.dumps({"summary": summary,
                        "flows": [r.to_json() for r in results],
                        "invalid_rows": invalid},
                       indent=2, sort_keys=True), encoding="utf-8")
        with (out_dir / "flow_rules.jsonl").open("w", encoding="utf-8") as fp:
            for r in results:
                for m in r.matches:
                    fp.write(json.dumps({
                        "flow": r.flow.label, "src_ip": r.flow.src,
                        "dst_ip": r.flow.dst, "protocol": r.flow.protocol,
                        "dst_port": r.flow.dst_port, **m.to_json(),
                    }, sort_keys=True) + "\n")
        with (out_dir / "suppressed_matches.jsonl").open("w", encoding="utf-8") as fp:
            for r in results:
                for m in r.suppressed:
                    fp.write(json.dumps({
                        "flow": r.flow.label, "src_ip": r.flow.src,
                        "dst_ip": r.flow.dst, **m.to_json(),
                    }, sort_keys=True) + "\n")
        (out_dir / "report.md").write_text(
            build_markdown(results, invalid, summary), encoding="utf-8")
        log.info("Report written to %s", out_dir)

    # ----- stdout -----
    if args.json:
        print(json.dumps({"summary": summary,
                          "flows": [r.to_json() for r in results],
                          "invalid_rows": invalid}, indent=2, sort_keys=True))
    else:
        print("=" * 78)
        print("PANORAMA FLOW / RULE REPORT")
        print("=" * 78)
        print(f"Flows: {summary['flows_total']}   "
              f"covered by a real rule: {summary['flows_with_custom_match']}   "
              f"default-rule only: {summary['flows_without_custom_match']}   "
              f"invalid rows: {summary['flows_invalid']}")
        print(f"Rule matches: {summary['rule_matches_total']}   "
              f"suppressed by subnet filter: {summary['rule_matches_suppressed']}   "
              f"distinct rules: {summary['rules_touched']}")
        print()
        for r in results:
            print(f"  {r.flow.label}: {r.flow.describe()}")
            for dg in r.device_groups:
                d = r.deciding_for(dg)
                label = (cpm.ACTION_LABELS.get(d.action, d.action.upper())
                         if d else "NO MATCH")
                rule = (f"{d.rulebase}/pos {d.position} {d.name!r}"
                        if d else "(no rule covers this flow)")
                tag = "  <- default-rule fall-through" if d and d.is_default else ""
                shadowed = len(r.matches_for(dg)) - (1 if d else 0)
                extra = f"  (+{shadowed} shadowed)" if shadowed > 0 else ""
                print(f"      [{dg:<10}] {label:<8} {rule}{tag}{extra}")
                for m in r.shadowed_for(dg):
                    print(f"          ! suppressed rule ahead of it: "
                          f"{m.rulebase}/pos {m.position} {m.name!r}")
                    print(f"            {m.suppressed_reason}")
        print()

    # 0 = every flow is covered by a real rule, 1 = at least one falls through
    # to a PAN default rule only
    return 0 if summary["flows_without_custom_match"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
