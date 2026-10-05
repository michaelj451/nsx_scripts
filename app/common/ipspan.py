"""app/common/ipspan.py

IP address spans: hosts, CIDRs and ranges as inclusive integer intervals.

Both vendors need "does this address set touch that one" arithmetic: NSX
groups hold hosts, CIDRs and ranges in one ip_addresses list, PAN address
objects can be ip-netmask or ip-range. A range is not a network, so the
common currency is an interval {version, lo, hi}, the same model
app/palo/pan_ip_rules.py and app/palo/pan_dg_subnets.py use internally.

    span_of("10.6.0.0/24")            Span(4, 168165376, 168165631)
    span_of("10.6.0.5-10.6.0.9")      a range
    subtract(a, [b, c])               what is left of a
    merge(spans)                      sorted, touching spans joined
    fmt(span)                         back to "10.6.0.0/24", "10.6.0.5" or "a-b"
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, List, Optional


@dataclass(frozen=True, order=True)
class Span:
    version: int
    lo: int
    hi: int

    @property
    def size(self) -> int:
        return self.hi - self.lo + 1


def span_of_network(net: "ipaddress._BaseNetwork") -> Span:
    return Span(net.version, int(net.network_address), int(net.broadcast_address))


def span_of(text: str, *, strict: bool = False) -> Span:
    """Parse a host, CIDR or 'a-b' range. Raises ValueError when it is none
    of those. strict=True rejects a CIDR with host bits set (10.10.3.0/23)."""
    s = (text or "").strip()
    if not s:
        raise ValueError("empty address")
    if "-" in s and "/" not in s:
        left, right = (x.strip() for x in s.split("-", 1))
        a, b = ipaddress.ip_address(left), ipaddress.ip_address(right)
        if a.version != b.version:
            raise ValueError(f"range mixes IPv4 and IPv6: {s}")
        if int(b) < int(a):
            raise ValueError(f"range end is before its start: {s}")
        return Span(a.version, int(a), int(b))
    return span_of_network(ipaddress.ip_network(s, strict=strict))


def try_span(text: str) -> Optional[Span]:
    try:
        return span_of(text)
    except ValueError:
        return None


def overlaps(a: Span, b: Span) -> bool:
    return a.version == b.version and a.lo <= b.hi and b.lo <= a.hi


def contains(outer: Span, inner: Span) -> bool:
    return outer.version == inner.version and outer.lo <= inner.lo and inner.hi <= outer.hi


def intersection(a: Span, b: Span) -> Optional[Span]:
    if not overlaps(a, b):
        return None
    return Span(a.version, max(a.lo, b.lo), min(a.hi, b.hi))


def shift(a: Span, delta: int) -> Span:
    return Span(a.version, a.lo + delta, a.hi + delta)


def merge(spans: Iterable[Span]) -> List[Span]:
    """Sort and join overlapping or adjacent spans (per IP version)."""
    out: List[Span] = []
    for s in sorted(spans):
        if out and out[-1].version == s.version and s.lo <= out[-1].hi + 1:
            last = out[-1]
            out[-1] = Span(last.version, last.lo, max(last.hi, s.hi))
        else:
            out.append(s)
    return out


def subtract(a: Span, holes: Iterable[Span]) -> List[Span]:
    """What is left of `a` after removing every hole."""
    left = [a]
    for h in merge(x for x in holes if x.version == a.version):
        nxt: List[Span] = []
        for piece in left:
            if not overlaps(piece, h):
                nxt.append(piece)
                continue
            if piece.lo < h.lo:
                nxt.append(Span(piece.version, piece.lo, h.lo - 1))
            if h.hi < piece.hi:
                nxt.append(Span(piece.version, h.hi + 1, piece.hi))
        left = nxt
    return left


def _addr(version: int, value: int) -> str:
    return str(ipaddress.ip_address(value) if version == 4 else ipaddress.IPv6Address(value))


def fmt(a: Span) -> str:
    """Shortest faithful text: one host, one CIDR, or 'lo-hi'."""
    if a.lo == a.hi:
        return _addr(a.version, a.lo)
    nets = list(ipaddress.summarize_address_range(
        ipaddress.ip_address(a.lo) if a.version == 4 else ipaddress.IPv6Address(a.lo),
        ipaddress.ip_address(a.hi) if a.version == 4 else ipaddress.IPv6Address(a.hi)))
    if len(nets) == 1:
        return str(nets[0])
    return f"{_addr(a.version, a.lo)}-{_addr(a.version, a.hi)}"


def to_cidrs(a: Span) -> List[str]:
    """The span as the minimal list of CIDRs (useful for PAN ip-netmask objects)."""
    lo = ipaddress.ip_address(a.lo) if a.version == 4 else ipaddress.IPv6Address(a.lo)
    hi = ipaddress.ip_address(a.hi) if a.version == 4 else ipaddress.IPv6Address(a.hi)
    return [str(n) for n in ipaddress.summarize_address_range(lo, hi)]
