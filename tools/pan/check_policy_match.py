#!/usr/bin/env python3
"""tools/pan/check_policy_match.py

Offline Panorama "can A reach B" policy lookup.

Given an exported Panorama running-config XML and a query (source IP,
destination IP, optional zones, optional service/port), walks the full
Panorama rulebase evaluation chain in the correct order and reports the
verdict (ALLOWED / DENIED / DROPPED) plus the rule that determined it
and a trace of every rule considered.

THIS IS READ-ONLY. The tool only reads the XML file and writes report
files to disk; it makes no network calls and never modifies the input.

EVALUATION CHAIN (matches PAN-OS firewall behavior):
    1. shared pre-rulebase
    2. ancestor DG pre-rulebases (parent → grandparent → …)
    3. target DG pre-rulebase
    4. (firewall-local rulebase — not present in Panorama XML, skipped)
    5. target DG post-rulebase
    6. ancestor DG post-rulebases (reverse order)
    7. shared post-rulebase
    8. default rules (intrazone-default allow, interzone-default deny)

KNOWN OFFLINE LIMITATIONS (surfaced as caveats in the verdict):
    - App-ID matching is impossible offline (depends on payload classification).
      Rules requiring a specific app match are reported as "would match if app=X".
    - Dynamic Address Group (DAG) membership is runtime-bound.
      Rules referencing DAGs are reported with the match filter and a caveat.
    - NAT rules are NOT evaluated (only security rules). Effective IPs after
      NAT are treated as the same as input IPs. v2 can add NAT chain.
    - User-ID is treated as `any` (no user identity in queries).
    - 'application-default' service entries cannot be resolved offline —
      reported with a caveat.
    - Local rulebase (rules on the firewall itself, not in Panorama) is
      invisible to this tool. Some traffic may match a local rule that
      this tool can't see; the tool will report the Panorama verdict.

USAGE:
    python tools/pan/check_policy_match.py \\
        --config panorama-running-config.xml \\
        --device-group BranchOffice-DG \\
        --src-ip 10.20.5.7 \\
        --dst-ip 192.168.10.42 \\
        --dst-port 443 --protocol tcp

    Add --src-zone trust --dst-zone dmz for zone-aware evaluation.
    Add --json to suppress human-readable output (script-friendly).
    Add --output-dir <path> to write the verdict + trace to disk.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

log = logging.getLogger(__name__)


def _resolve_default_output_dir() -> Path:
    """Return the default report root.

    Resolution order:
      1. $PANO_REPORTS_DIR if already in os.environ (operator exported it)
      2. Read ROOT_DIR + PANO_REPORTS_DIR only from .env if present
         (never reads credentials — this tool stays prod-safe)
      3. Fallback: ./.pano_reports relative to cwd

    Only the path keys are read from .env. Credentials, manager hostnames,
    API tokens, and everything else are deliberately untouched, so this
    function does NOT compromise the production-tool guarantee that no
    Panorama credentials are loaded into the process.
    """
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
            # Only consider the two path keys; nothing else
            if k not in ("ROOT_DIR", "PANO_REPORTS_DIR"):
                continue
            # Expand $VAR / ${VAR} against keys we've already collected
            for known_k, known_v in values.items():
                v = v.replace(f"${known_k}", known_v).replace(f"${{{known_k}}}", known_v)
            values[k] = v
        if "PANO_REPORTS_DIR" in values:
            return Path(values["PANO_REPORTS_DIR"])

    return Path(".pano_reports")

# =============================================================================
# Data model — in-memory representation of the parsed Panorama config
# =============================================================================

IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass
class AddressObject:
    name:        str
    kind:        str    # 'ip-netmask' | 'ip-range' | 'fqdn'
    value:       str    # raw value (e.g. "10.0.0.0/24", "1.2.3.4-1.2.3.10", "host.example.com")
    networks:    List[IPNet] = field(default_factory=list)  # resolved nets (fqdn → empty offline)
    description: Optional[str] = None
    tags:        List[str] = field(default_factory=list)


@dataclass
class AddressGroup:
    name:        str
    kind:        str           # 'static' | 'dynamic'
    members:     List[str] = field(default_factory=list)  # for 'static': object/group names
    dag_filter:  Optional[str] = None  # for 'dynamic': raw filter expression (e.g. "'web' and 'prod'")
    description: Optional[str] = None


@dataclass
class ServiceObject:
    name:     str
    protocol: str           # 'tcp' | 'udp'
    ports:    str           # raw port spec — "443", "80,8080", "8000-8100"


@dataclass
class ServiceGroup:
    name:    str
    members: List[str] = field(default_factory=list)


@dataclass
class SecurityRule:
    name:                  str
    rulebase_path:         str    # human-readable: "shared/pre-rulebase" or "DG-name/post-rulebase"
    position:              int
    disabled:              bool   = False
    source_zones:          List[str] = field(default_factory=lambda: ["any"])
    destination_zones:     List[str] = field(default_factory=lambda: ["any"])
    source_addresses:      List[str] = field(default_factory=lambda: ["any"])
    destination_addresses: List[str] = field(default_factory=lambda: ["any"])
    source_users:          List[str] = field(default_factory=lambda: ["any"])
    applications:          List[str] = field(default_factory=lambda: ["any"])
    services:              List[str] = field(default_factory=lambda: ["any"])
    categories:            List[str] = field(default_factory=lambda: ["any"])
    action:                str    = "allow"   # 'allow'|'deny'|'drop'|'reset-client'|'reset-server'|'reset-both'
    negate_source:         bool   = False
    negate_destination:    bool   = False
    log_setting:           Optional[str] = None
    log_start:             bool   = False
    log_end:               bool   = True


@dataclass
class DeviceGroup:
    name:           str
    parent:         Optional[str]                 # parent DG name, or None for top-level
    pre_rulebase:   List[SecurityRule] = field(default_factory=list)
    post_rulebase:  List[SecurityRule] = field(default_factory=list)


# =============================================================================
# XML parser — Panorama running-config → in-memory model
# =============================================================================

class PanoramaConfig:
    """Parses an exported Panorama running-config XML.

    The XML is read once; subsequent queries reuse the parsed model.
    Read-only — never writes to the XML or back to Panorama.
    """
    def __init__(self, xml_path: Path):
        self.xml_path = xml_path
        log.info("Parsing Panorama config: %s", xml_path)
        self.tree = ET.parse(xml_path)
        self.root = self.tree.getroot()

        # Shared config is /config/shared/...
        # Device groups are /config/devices/entry[@name='localhost.localdomain']/device-group/entry
        self.shared_root = self.root.find("./shared")
        self.devices_root = self.root.find("./devices/entry/device-group")

        self.addresses:      Dict[str, AddressObject] = {}
        self.address_groups: Dict[str, AddressGroup] = {}
        self.services:       Dict[str, ServiceObject] = {}
        self.service_groups: Dict[str, ServiceGroup] = {}
        self.device_groups:  Dict[str, DeviceGroup] = {}
        self.shared_pre_rules:  List[SecurityRule] = []
        self.shared_post_rules: List[SecurityRule] = []

        self._parse_shared_objects()
        self._parse_shared_rulebases()
        self._parse_device_groups()
        self._inject_default_rules()
        log.info(
            "Parsed: %d addresses, %d address-groups, %d services, %d service-groups, "
            "%d device-groups, %d shared-pre + %d shared-post rules.",
            len(self.addresses), len(self.address_groups), len(self.services),
            len(self.service_groups), len(self.device_groups),
            len(self.shared_pre_rules), len(self.shared_post_rules),
        )

    # ---- parsing helpers ----

    @staticmethod
    def _text(node: Optional[ET.Element], default: Optional[str] = None) -> Optional[str]:
        return node.text.strip() if (node is not None and node.text) else default

    @staticmethod
    def _members(parent: Optional[ET.Element], tag: str = "member") -> List[str]:
        if parent is None:
            return []
        return [m.text.strip() for m in parent.findall(tag) if m.text]

    @staticmethod
    def _parse_ip_netmask(raw: str) -> List[IPNet]:
        """Convert PAN ip-netmask value to a list of one IP network.
        PAN allows bare IPs (no mask) — treat as /32 or /128."""
        try:
            return [ipaddress.ip_network(raw, strict=False)]
        except ValueError:
            try:
                return [ipaddress.ip_network(raw + "/32", strict=False)]
            except ValueError:
                return []

    @staticmethod
    def _parse_ip_range(raw: str) -> List[IPNet]:
        """Convert 'a.b.c.d-w.x.y.z' to summarized networks."""
        if "-" not in raw:
            return []
        a, b = raw.split("-", 1)
        try:
            first = ipaddress.ip_address(a.strip())
            last  = ipaddress.ip_address(b.strip())
            return list(ipaddress.summarize_address_range(first, last))
        except ValueError:
            return []

    # ---- shared objects (addresses, services) ----

    def _parse_shared_objects(self) -> None:
        # Addresses can appear under /shared/address AND inside each device-group/address.
        # First pass: shared scope.
        self._parse_addresses_under(self.shared_root, scope_label="shared")
        self._parse_address_groups_under(self.shared_root, scope_label="shared")
        self._parse_services_under(self.shared_root, scope_label="shared")
        self._parse_service_groups_under(self.shared_root, scope_label="shared")

    def _parse_addresses_under(self, root: Optional[ET.Element], scope_label: str) -> None:
        if root is None:
            return
        for ent in root.findall("./address/entry"):
            name = ent.get("name")
            if not name or name in self.addresses:
                continue
            ipnm = self._text(ent.find("./ip-netmask"))
            iprg = self._text(ent.find("./ip-range"))
            fqdn = self._text(ent.find("./fqdn"))
            tags = self._members(ent.find("./tag"))
            desc = self._text(ent.find("./description"))
            if ipnm:
                self.addresses[name] = AddressObject(
                    name=name, kind="ip-netmask", value=ipnm,
                    networks=self._parse_ip_netmask(ipnm),
                    description=desc, tags=tags,
                )
            elif iprg:
                self.addresses[name] = AddressObject(
                    name=name, kind="ip-range", value=iprg,
                    networks=self._parse_ip_range(iprg),
                    description=desc, tags=tags,
                )
            elif fqdn:
                # FQDN can't be resolved offline; record name only.
                self.addresses[name] = AddressObject(
                    name=name, kind="fqdn", value=fqdn,
                    networks=[], description=desc, tags=tags,
                )

    def _parse_address_groups_under(self, root: Optional[ET.Element], scope_label: str) -> None:
        if root is None:
            return
        for ent in root.findall("./address-group/entry"):
            name = ent.get("name")
            if not name or name in self.address_groups:
                continue
            static = ent.find("./static")
            dynamic = ent.find("./dynamic")
            if static is not None:
                self.address_groups[name] = AddressGroup(
                    name=name, kind="static",
                    members=self._members(static),
                    description=self._text(ent.find("./description")),
                )
            elif dynamic is not None:
                # DAG filter is a string expression like "'web' and 'prod'"
                self.address_groups[name] = AddressGroup(
                    name=name, kind="dynamic",
                    dag_filter=self._text(dynamic.find("./filter")),
                    description=self._text(ent.find("./description")),
                )

    def _parse_services_under(self, root: Optional[ET.Element], scope_label: str) -> None:
        if root is None:
            return
        for ent in root.findall("./service/entry"):
            name = ent.get("name")
            if not name or name in self.services:
                continue
            for proto in ("tcp", "udp"):
                proto_node = ent.find(f"./protocol/{proto}")
                if proto_node is not None:
                    ports = self._text(proto_node.find("./port"), default="")
                    self.services[name] = ServiceObject(
                        name=name, protocol=proto, ports=ports or "",
                    )
                    break

    def _parse_service_groups_under(self, root: Optional[ET.Element], scope_label: str) -> None:
        if root is None:
            return
        for ent in root.findall("./service-group/entry"):
            name = ent.get("name")
            if not name or name in self.service_groups:
                continue
            self.service_groups[name] = ServiceGroup(
                name=name, members=self._members(ent.find("./members")),
            )

    # ---- rulebases ----

    def _parse_shared_rulebases(self) -> None:
        if self.shared_root is None:
            return
        self.shared_pre_rules  = self._parse_rules(
            self.shared_root.find("./pre-rulebase/security/rules"),
            rulebase_path="shared/pre-rulebase",
        )
        self.shared_post_rules = self._parse_rules(
            self.shared_root.find("./post-rulebase/security/rules"),
            rulebase_path="shared/post-rulebase",
        )

    def _parse_rules(self, rules_root: Optional[ET.Element], rulebase_path: str) -> List[SecurityRule]:
        if rules_root is None:
            return []
        rules: List[SecurityRule] = []
        for i, ent in enumerate(rules_root.findall("./entry"), start=1):
            name = ent.get("name") or f"<unnamed-{i}>"
            rules.append(SecurityRule(
                name=name,
                rulebase_path=rulebase_path,
                position=i,
                disabled=(self._text(ent.find("./disabled")) == "yes"),
                source_zones=         self._members(ent.find("./from"))      or ["any"],
                destination_zones=    self._members(ent.find("./to"))        or ["any"],
                source_addresses=     self._members(ent.find("./source"))    or ["any"],
                destination_addresses=self._members(ent.find("./destination"))or ["any"],
                source_users=         self._members(ent.find("./source-user"))or ["any"],
                applications=         self._members(ent.find("./application"))or ["any"],
                services=             self._members(ent.find("./service"))   or ["any"],
                categories=           self._members(ent.find("./category"))  or ["any"],
                action=               self._text(ent.find("./action"), default="allow"),
                negate_source=        (self._text(ent.find("./negate-source"))      == "yes"),
                negate_destination=   (self._text(ent.find("./negate-destination")) == "yes"),
                log_setting=          self._text(ent.find("./log-setting")),
                log_start=            (self._text(ent.find("./log-start")) == "yes"),
                log_end=              (self._text(ent.find("./log-end")) != "no"),  # default yes
            ))
        return rules

    # ---- device groups + their rulebases + objects ----

    def _parse_device_groups(self) -> None:
        if self.devices_root is None:
            log.warning("No device-groups found at /config/devices/entry/device-group/entry — "
                        "if this is a firewall-only export (no Panorama), only shared rules will be evaluated.")
            return
        for ent in self.devices_root.findall("./entry"):
            name = ent.get("name")
            if not name:
                continue
            parent = self._text(ent.find("./parent-dg"))
            # DG-scoped objects (addresses, services) are also valid here.
            self._parse_addresses_under(ent, scope_label=f"dg:{name}")
            self._parse_address_groups_under(ent, scope_label=f"dg:{name}")
            self._parse_services_under(ent, scope_label=f"dg:{name}")
            self._parse_service_groups_under(ent, scope_label=f"dg:{name}")
            pre  = self._parse_rules(ent.find("./pre-rulebase/security/rules"),
                                     rulebase_path=f"{name}/pre-rulebase")
            post = self._parse_rules(ent.find("./post-rulebase/security/rules"),
                                     rulebase_path=f"{name}/post-rulebase")
            self.device_groups[name] = DeviceGroup(
                name=name, parent=parent, pre_rulebase=pre, post_rulebase=post,
            )

    # ---- default rules (synthetic — PAN system defaults) ----

    def _inject_default_rules(self) -> None:
        """PAN has two system default rules at the very end of the chain:
           intrazone-default: allow any traffic within the same zone
           interzone-default: deny any traffic between different zones
        These don't appear in the XML; we synthesize them so the trace
        always terminates explicitly.
        """
        self._intrazone_default = SecurityRule(
            name="intrazone-default", rulebase_path="default-rules",
            position=1, action="allow",
            source_zones=["any"], destination_zones=["any"],
        )
        self._interzone_default = SecurityRule(
            name="interzone-default", rulebase_path="default-rules",
            position=2, action="deny",
            source_zones=["any"], destination_zones=["any"],
        )

    # =============================================================================
    # Hierarchy resolution — evaluation chain for a given DG
    # =============================================================================

    def ancestor_chain(self, dg_name: str) -> List[str]:
        """Walk parent links from dg_name up. Returns chain ordered
        leaf → root, e.g. for Branch-A (parent=Region-X (parent=None)):
        returns ['Branch-A', 'Region-X']."""
        chain: List[str] = []
        seen: Set[str] = set()
        cur: Optional[str] = dg_name
        while cur and cur not in seen and cur in self.device_groups:
            chain.append(cur)
            seen.add(cur)
            cur = self.device_groups[cur].parent
        return chain

    def evaluation_chain(self, dg_name: str) -> List[SecurityRule]:
        """Return the ordered list of rules to walk for traffic targeting
        device-group dg_name. Order matches PAN-OS:

            1. shared pre-rulebase
            2. ancestor DG pre-rulebases (oldest ancestor first → leaf last)
            3. target DG pre-rulebase                (== last pre we add)
            4. target DG post-rulebase
            5. ancestor DG post-rulebases (leaf-adjacent → root last)
            6. shared post-rulebase
            7. default rules
        """
        chain: List[SecurityRule] = []
        chain.extend(self.shared_pre_rules)
        ancestors = self.ancestor_chain(dg_name)  # leaf → root
        # Pre-rulebases evaluated root → leaf
        for dg in reversed(ancestors):
            chain.extend(self.device_groups[dg].pre_rulebase)
        # Post-rulebases evaluated leaf → root
        for dg in ancestors:
            chain.extend(self.device_groups[dg].post_rulebase)
        chain.extend(self.shared_post_rules)
        # Defaults always last
        chain.append(self._intrazone_default)
        chain.append(self._interzone_default)
        return chain

    # =============================================================================
    # Address resolution — name → expanded set of IP networks
    # =============================================================================

    def resolve_address(self, name: str,
                        _visited: Optional[Set[str]] = None,
                        ) -> Tuple[List[IPNet], List[str]]:
        """Returns (networks, caveats). Caveats list strings explaining any
        offline-unresolvable parts (fqdn, dynamic groups, missing references)."""
        _visited = _visited or set()
        caveats: List[str] = []
        if name in _visited:
            caveats.append(f"address group cycle on {name!r}")
            return [], caveats
        _visited = _visited | {name}

        if name == "any":
            return [], []   # 'any' is handled specially by the matcher

        obj = self.addresses.get(name)
        if obj is not None:
            if obj.kind == "fqdn":
                caveats.append(f"address {name!r} is an FQDN ({obj.value!r}) — "
                               f"offline IP resolution unavailable")
                return [], caveats
            return list(obj.networks), caveats

        grp = self.address_groups.get(name)
        if grp is not None:
            if grp.kind == "dynamic":
                caveats.append(f"group {name!r} is a Dynamic Address Group "
                               f"(filter={grp.dag_filter!r}) — runtime membership "
                               f"unknown offline")
                return [], caveats
            # static group: recurse
            nets: List[IPNet] = []
            for m in grp.members:
                m_nets, m_caveats = self.resolve_address(m, _visited)
                nets.extend(m_nets)
                caveats.extend(m_caveats)
            return nets, caveats

        # Try parsing as a literal IP/CIDR (PAN rules can reference literals)
        try:
            return [ipaddress.ip_network(name, strict=False)], []
        except ValueError:
            pass

        caveats.append(f"unresolved address reference: {name!r}")
        return [], caveats

    # =============================================================================
    # Service resolution — name → set of (protocol, port-range) tuples
    # =============================================================================

    def resolve_service(self, name: str,
                        _visited: Optional[Set[str]] = None,
                        ) -> Tuple[List[Tuple[str, str]], List[str]]:
        """Returns ([(protocol, port-spec), ...], caveats). protocol is
        'tcp'/'udp'; port-spec is raw, e.g. '443' or '8000-8100' or '80,8080'.
        """
        _visited = _visited or set()
        caveats: List[str] = []
        if name in _visited:
            caveats.append(f"service group cycle on {name!r}")
            return [], caveats
        _visited = _visited | {name}

        if name == "any":
            return [], []
        if name == "application-default":
            caveats.append("service 'application-default' depends on App-ID — "
                           "cannot be resolved offline; treating as match-any-port")
            return [], caveats

        # Built-ins
        builtins = {
            "service-http":  ("tcp", "80"),
            "service-https": ("tcp", "443"),
        }
        if name in builtins:
            return [builtins[name]], []

        svc = self.services.get(name)
        if svc is not None:
            return [(svc.protocol, svc.ports)], []

        grp = self.service_groups.get(name)
        if grp is not None:
            entries: List[Tuple[str, str]] = []
            for m in grp.members:
                m_entries, m_caveats = self.resolve_service(m, _visited)
                entries.extend(m_entries)
                caveats.extend(m_caveats)
            return entries, caveats

        caveats.append(f"unresolved service reference: {name!r}")
        return [], caveats


# =============================================================================
# Matcher — walk the evaluation chain and emit a Verdict
# =============================================================================

@dataclass
class Query:
    src_ip:       str
    dst_ip:       str
    src_zone:     Optional[str] = None
    dst_zone:     Optional[str] = None
    protocol:     Optional[str] = None   # 'tcp' | 'udp' | None
    dst_port:     Optional[int] = None
    device_group: str = "shared"


@dataclass
class TraceEntry:
    rulebase: str
    position: int
    name:     str
    decision: str    # 'matched' | 'skipped'
    reasons:  List[str] = field(default_factory=list)


@dataclass
class Verdict:
    action:          str               # 'allow' | 'deny' | 'drop' | ...
    matched_rule:    Optional[str]
    matched_rulebase:Optional[str]
    matched_position:Optional[int]
    caveats:         List[str] = field(default_factory=list)
    trace:           List[TraceEntry] = field(default_factory=list)
    query:           Optional[Query] = None


def _ip_in_networks(ip_str: str, nets: List[IPNet]) -> bool:
    if not nets:
        return False
    ip = ipaddress.ip_address(ip_str)
    return any(ip in n for n in nets)


def _port_matches(port: Optional[int], port_spec: str) -> bool:
    """Match a single port against PAN port-spec (e.g. '80', '80,8080', '8000-8100')."""
    if port is None or not port_spec:
        return True  # query didn't specify port → don't fail on it
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                if int(lo) <= port <= int(hi):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(part) == port:
                    return True
            except ValueError:
                continue
    return False


def _match_addresses(ip: str, address_names: List[str], config: PanoramaConfig,
                     ) -> Tuple[bool, List[str]]:
    """Returns (matched, caveats). 'any' always matches."""
    caveats: List[str] = []
    if "any" in address_names:
        return True, caveats
    for name in address_names:
        nets, c = config.resolve_address(name)
        caveats.extend(c)
        if _ip_in_networks(ip, nets):
            return True, caveats
    return False, caveats


def _match_services(query: Query, service_names: List[str], config: PanoramaConfig,
                    ) -> Tuple[bool, List[str]]:
    """Returns (matched, caveats). 'any' always matches."""
    caveats: List[str] = []
    if "any" in service_names:
        return True, caveats
    # If the query didn't specify a protocol/port, but the rule restricts to specific
    # services, we can't conclusively say it matches. Default to "match if any service
    # resolves but flag with a caveat".
    if query.protocol is None and query.dst_port is None:
        caveats.append("query did not specify protocol/port; rule requires service(s) "
                       f"{service_names!r} — match treated as port-agnostic")
        return True, caveats
    for name in service_names:
        entries, c = config.resolve_service(name)
        caveats.extend(c)
        for proto, ports in entries:
            if query.protocol and proto.lower() != query.protocol.lower():
                continue
            if _port_matches(query.dst_port, ports):
                return True, caveats
        # If the service resolved but contained no entries (e.g., application-default)
        # treat that as a wildcard match — caveats already record the offline limit.
        if not entries and any("application-default" in cv or "cannot be resolved" in cv
                                for cv in caveats):
            return True, caveats
    return False, caveats


def evaluate(config: PanoramaConfig, query: Query) -> Verdict:
    chain = config.evaluation_chain(query.device_group)
    trace: List[TraceEntry] = []
    cumulative_caveats: List[str] = []
    if not query.src_zone or not query.dst_zone:
        cumulative_caveats.append(
            "query is zone-agnostic (src_zone or dst_zone not supplied) — "
            "rules with specific zone restrictions are treated as matching; "
            "actual firewall enforcement may differ if zones don't apply"
        )

    for rule in chain:
        reasons: List[str] = []
        if rule.disabled:
            trace.append(TraceEntry(rule.rulebase_path, rule.position, rule.name,
                                    "skipped", ["rule disabled"]))
            continue

        # Zone match (skip if rule restricts and query is zone-aware)
        if query.src_zone and "any" not in rule.source_zones \
                and query.src_zone not in rule.source_zones:
            reasons.append(f"src_zone {query.src_zone!r} not in {rule.source_zones!r}")
        if query.dst_zone and "any" not in rule.destination_zones \
                and query.dst_zone not in rule.destination_zones:
            reasons.append(f"dst_zone {query.dst_zone!r} not in {rule.destination_zones!r}")

        # Source address match
        src_ok, src_caveats = _match_addresses(query.src_ip, rule.source_addresses, config)
        if rule.negate_source:
            src_ok = not src_ok
        if not src_ok:
            reasons.append(f"src_ip {query.src_ip} not in {rule.source_addresses!r}"
                           + (" (negated)" if rule.negate_source else ""))

        # Destination address match
        dst_ok, dst_caveats = _match_addresses(query.dst_ip, rule.destination_addresses, config)
        if rule.negate_destination:
            dst_ok = not dst_ok
        if not dst_ok:
            reasons.append(f"dst_ip {query.dst_ip} not in {rule.destination_addresses!r}"
                           + (" (negated)" if rule.negate_destination else ""))

        # Service match
        svc_ok, svc_caveats = _match_services(query, rule.services, config)
        if not svc_ok:
            reasons.append(f"service {(query.protocol, query.dst_port)} not in {rule.services!r}")

        # App-ID offline caveat
        if "any" not in rule.applications:
            cumulative_caveats.append(
                f"rule {rule.name!r} requires application(s) {rule.applications!r} — "
                f"App-ID match cannot be evaluated offline"
            )

        if reasons:
            trace.append(TraceEntry(rule.rulebase_path, rule.position, rule.name,
                                    "skipped", reasons))
            continue

        # MATCH
        trace.append(TraceEntry(rule.rulebase_path, rule.position, rule.name, "matched", []))
        return Verdict(
            action=rule.action,
            matched_rule=rule.name,
            matched_rulebase=rule.rulebase_path,
            matched_position=rule.position,
            caveats=cumulative_caveats + src_caveats + dst_caveats + svc_caveats,
            trace=trace,
            query=query,
        )

    # If we exhaust the chain (defaults at the end always match) something is wrong
    return Verdict(
        action="deny", matched_rule=None, matched_rulebase=None, matched_position=None,
        caveats=cumulative_caveats + ["no rule matched — should have hit interzone-default"],
        trace=trace, query=query,
    )


# =============================================================================
# Output formatting
# =============================================================================

ACTION_LABELS = {
    "allow":          "ALLOWED",
    "deny":           "DENIED",
    "drop":           "DROPPED",
    "reset-client":   "RESET (client)",
    "reset-server":   "RESET (server)",
    "reset-both":     "RESET (both)",
}


def format_verdict_text(verdict: Verdict, config: PanoramaConfig, verbose: bool = False) -> str:
    q = verdict.query
    lines: List[str] = []
    lines.append("=" * 70)
    lines.append(f"VERDICT: {ACTION_LABELS.get(verdict.action, verdict.action.upper())}")
    lines.append("=" * 70)
    if q:
        lines.append(f"Query:        src={q.src_ip}  dst={q.dst_ip}")
        if q.src_zone or q.dst_zone:
            lines.append(f"              src_zone={q.src_zone or '(any)'}  dst_zone={q.dst_zone or '(any)'}")
        if q.protocol or q.dst_port:
            lines.append(f"              protocol={q.protocol or '(any)'}  dst_port={q.dst_port or '(any)'}")
        lines.append(f"              device-group={q.device_group}")
    if verdict.matched_rule:
        lines.append("")
        lines.append(f"Matched rule: {verdict.matched_rulebase} / position {verdict.matched_position} / "
                     f"{verdict.matched_rule!r}")
    else:
        lines.append("")
        lines.append("Matched rule: (none — fell through to default deny)")
    if verdict.caveats:
        lines.append("")
        lines.append("Caveats:")
        for c in verdict.caveats:
            lines.append(f"  • {c}")
    if verbose:
        lines.append("")
        lines.append("Trace (in evaluation order):")
        for t in verdict.trace:
            tag = "✓ MATCH " if t.decision == "matched" else "  skip  "
            lines.append(f"  {tag} {t.rulebase}/{t.position:3d}  {t.name}")
            for r in t.reasons:
                lines.append(f"            → {r}")
    lines.append("")
    lines.append(f"Rules evaluated: {len(verdict.trace)}")
    return "\n".join(lines)


def verdict_to_json(verdict: Verdict) -> Dict[str, Any]:
    q = verdict.query
    return {
        "verdict":          ACTION_LABELS.get(verdict.action, verdict.action.upper()),
        "action":           verdict.action,
        "matched_rule":     verdict.matched_rule,
        "matched_rulebase": verdict.matched_rulebase,
        "matched_position": verdict.matched_position,
        "caveats":          verdict.caveats,
        "rules_evaluated":  len(verdict.trace),
        "query": ({
            "src_ip":       q.src_ip,    "dst_ip":       q.dst_ip,
            "src_zone":     q.src_zone,  "dst_zone":     q.dst_zone,
            "protocol":     q.protocol,  "dst_port":     q.dst_port,
            "device_group": q.device_group,
        } if q else None),
        "trace": [
            {"rulebase": t.rulebase, "position": t.position, "name": t.name,
             "decision": t.decision, "reasons": t.reasons}
            for t in verdict.trace
        ],
    }


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--config", required=True,
                   help="Path to exported Panorama running-config XML.")
    dg_grp = p.add_mutually_exclusive_group(required=True)
    dg_grp.add_argument("--device-group",
                        help="Target device-group name (the DG whose firewall would "
                             "receive this traffic). Use this when you know the DG.")
    dg_grp.add_argument("--all-device-groups", action="store_true",
                        help="Evaluate the query against EVERY device-group in the "
                             "config and report a per-DG verdict. Use this when you "
                             "don't know which DG owns the flow.")
    p.add_argument("--src-ip", required=True)
    p.add_argument("--dst-ip", required=True)
    p.add_argument("--src-zone", default=None,
                   help="Source zone name. If omitted, zone-agnostic match (caveat emitted).")
    p.add_argument("--dst-zone", default=None,
                   help="Destination zone name. If omitted, zone-agnostic match (caveat emitted).")
    p.add_argument("--protocol", default=None, choices=["tcp", "udp"])
    p.add_argument("--dst-port", default=None, type=int)
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print the full per-rule evaluation trace.")
    p.add_argument("--json", action="store_true",
                   help="Suppress human-readable output; print only the JSON verdict.")
    p.add_argument("--output-dir", default=None,
                   help="Override the report directory. Default is taken from "
                        "$PANO_REPORTS_DIR (in shell env or .env), or "
                        "./.pano_reports if neither is set. Each run lands at "
                        "<dir>/check_policy_match/<UTC_TS>/verdict.json.")
    p.add_argument("--no-disk", action="store_true",
                   help="Do not write a report bundle to disk for this run "
                        "(stdout only). Use when running CAB-question one-offs "
                        "where audit trail isn't wanted.")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )

    config = PanoramaConfig(Path(args.config))

    # ----- Resolve the DG list (single or all) -----
    if args.all_device_groups:
        target_dgs = list(config.device_groups.keys())
        if not target_dgs:
            log.warning("config has no device-groups; running against 'shared' scope only")
            target_dgs = ["shared"]
    else:
        if (args.device_group not in config.device_groups
                and args.device_group != "shared"):
            log.warning("device-group %r not found in config. Known: %s",
                        args.device_group, sorted(config.device_groups.keys()))
        target_dgs = [args.device_group]

    # ----- Evaluate one or more DGs -----
    verdicts: List[Tuple[str, Verdict]] = []
    for dg in target_dgs:
        q = Query(
            src_ip=args.src_ip, dst_ip=args.dst_ip,
            src_zone=args.src_zone, dst_zone=args.dst_zone,
            protocol=args.protocol, dst_port=args.dst_port,
            device_group=dg,
        )
        verdicts.append((dg, evaluate(config, q)))

    # ----- Write bundle to disk -----
    if not args.no_disk:
        # Default to $PANO_REPORTS_DIR / check_policy_match / <UTC_TS> when
        # --output-dir isn't given. The resolver only reads path keys from .env;
        # credentials are never loaded (prod-safety guarantee).
        base = (Path(args.output_dir).expanduser().resolve()
                if args.output_dir
                else _resolve_default_output_dir().expanduser().resolve())
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_dir = base / "check_policy_match" / ts
        out_dir.mkdir(parents=True, exist_ok=True)
        if args.all_device_groups:
            doc = {
                "mode": "all_device_groups",
                "src_ip": args.src_ip, "dst_ip": args.dst_ip,
                "src_zone": args.src_zone, "dst_zone": args.dst_zone,
                "protocol": args.protocol, "dst_port": args.dst_port,
                "device_groups": [
                    {"device_group": dg, **verdict_to_json(v)}
                    for dg, v in verdicts
                ],
            }
        else:
            doc = verdict_to_json(verdicts[0][1])
        (out_dir / "verdict.json").write_text(
            json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8",
        )
        log.info("verdict + trace written to %s", out_dir / "verdict.json")

    # ----- Emit stdout -----
    if args.json:
        if args.all_device_groups:
            print(json.dumps({
                "mode": "all_device_groups",
                "device_groups": [
                    {"device_group": dg, **verdict_to_json(v)}
                    for dg, v in verdicts
                ],
            }, indent=2, sort_keys=True))
        else:
            print(json.dumps(verdict_to_json(verdicts[0][1]), indent=2, sort_keys=True))
    else:
        if args.all_device_groups:
            # Compact per-DG table
            print("=" * 72)
            print("ALL-DG POLICY MATCH")
            print("=" * 72)
            print(f"Query:        src={args.src_ip}  dst={args.dst_ip}")
            print(f"              proto={args.protocol or '(any)'}  port={args.dst_port or '(any)'}")
            print()
            custom_allow_count = sum(
                1 for _, v in verdicts
                if v.action == "allow" and v.matched_rulebase != "default-rules")
            for dg, v in verdicts:
                label = ACTION_LABELS.get(v.action, v.action.upper())
                rule  = v.matched_rule or "(default — no match)"
                rb    = v.matched_rulebase or "default-rules"
                # Visually mark default-rule fall-through (no custom rule matched).
                # In zone-agnostic mode, intrazone-default appears to "allow" but
                # on a real firewall this depends on whether src/dst share a zone.
                tag = "  ← default-rule fall-through" if rb == "default-rules" else ""
                print(f"  [{dg:10s}] {label:8s}  {rb}/pos {v.matched_position or '-'}  {rule!r}{tag}")
            # Summary line at the bottom of the table
            print()
            print(f"  Summary: {custom_allow_count}/{len(verdicts)} DGs have a CUSTOMER rule "
                  f"explicitly allowing this flow.")
            if custom_allow_count < len(verdicts) and not args.src_zone:
                print(f"  Caveat:  default-rule matches above depend on actual src/dst "
                      f"zones (not specified in this query).")
            if args.verbose:
                # Full trace per DG below the summary
                for dg, v in verdicts:
                    print()
                    print(format_verdict_text(v, config, verbose=True))
        else:
            print(format_verdict_text(verdicts[0][1], config, verbose=args.verbose))

    # ----- Exit code -----
    # Single-DG: 0 = ALLOWED, 1 = anything else
    # All-DG:    0 = at least one DG allows, 1 = no DG allows
    if any(v.action == "allow" for _, v in verdicts):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
