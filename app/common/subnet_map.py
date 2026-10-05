"""app/common/subnet_map.py

Subnet maps with ONE OR MORE target sites, read from one CSV.

FORMAT

    old_subnet,nsx-lm2,nsx-lm3
    10.6.0.0/16,10.7.0.0/16,10.8.0.0/16
    10.6.1.0/24,10.7.1.0/24,10.8.1.0/24
    10.10.1.0/24,10.20.1.0/24,

  * The first column is always `old_subnet`: the source address space.
  * Every other column is one target site, named by its header (use the
    manager alias, e.g. nsx-lm3, so tools can take the column by --target).
  * A blank cell means "this row has no mapping for that site". The site
    falls through to its next broader row, exactly as if the row were absent.
  * A classic two-column file (old_subnet,new_subnet) loads as one site
    named `new_subnet`.

THE ONE RULE THAT DEFINES A COLUMN

Each site column behaves exactly like the two-column file you get by cutting
that column out and dropping its blank rows. pairs(site) returns that cut,
and write_two_column(site, path) writes it, so the existing tools
(build_sibling_groups --csv-remap, groups.py push --csv-remap) read a site's
map through their own, unchanged loader.

VALIDATION (strict: any error refuses the whole map, nothing is skipped)

Per cell, the same rules as tools/nsx/nsx_group_ip_remap_offline.py:
IPv4 host or CIDR only (no ranges, no IPv6), CIDRs on their network
boundary, new != old, and the new network no smaller than the old one.
Plus: duplicate old_subnet rows, duplicate or empty site headers, and
values in columns that have no header are errors. The existing loader
skips a bad row with a warning; here a bad row stops the run, because a
skipped row silently drops traffic for every address it covered.

MAP CHECKS (check_site_map)

  collision_within_site   ERROR  two different source addresses map to the
                                 same address at one site (e.g. a /24 row
                                 that disagrees with its /16 parent)
  collision_between_sites ERROR  two sites map into the same addresses, so
                                 an address would exist at both
  lands_in_source_space   WARN   a mapped range overlaps the source space
                                 itself (an old_subnet of any row)

Mapping semantics match the existing engine: the most specific old_subnet
containing a value wins, and the value keeps its offset inside the subnet.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from common import ipspan
from common.fileio import read_csv_rows, write_csv

SOURCE_COLUMN = "old_subnet"
LEGACY_TARGET_COLUMN = "new_subnet"

Network = ipaddress.IPv4Network


@dataclass(frozen=True)
class MapCell:
    row: int                 # 1-based file line number (header is line 1)
    site: str
    old: Network
    new: Network

    @property
    def delta(self) -> int:
        return int(self.new.network_address) - int(self.old.network_address)


@dataclass
class SiteMap:
    path: Optional[Path]
    sites: List[str]
    cells: Dict[str, List[MapCell]] = field(default_factory=dict)
    sources: List[Tuple[int, Network]] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def require_site(self, site: str) -> List[MapCell]:
        if site not in self.cells:
            raise KeyError(f"Map has no column {site!r}; columns: {', '.join(self.sites)}")
        return self.cells[site]

    def pairs(self, site: str) -> List[Tuple[str, str]]:
        """The site's cut-out two-column map, in file order."""
        return [(str(c.old), str(c.new)) for c in self.require_site(site)]

    def write_two_column(self, site: str, path: Union[str, Path]) -> int:
        rows = self.pairs(site)
        write_csv(path, [SOURCE_COLUMN, LEGACY_TARGET_COLUMN], rows)
        return len(rows)

    def _best_cell(self, site: str, net: Network) -> Optional[MapCell]:
        best: Optional[MapCell] = None
        for c in self.require_site(site):
            if net.subnet_of(c.old) and (best is None or c.old.prefixlen > best.old.prefixlen):
                best = c
        return best

    def map_value(self, site: str, value: str) -> Optional[str]:
        """Map one IPv4 host or CIDR for `site`, or None when no row covers it.
        A host stays a host (10.6.0.5 -> 10.7.0.5); a CIDR keeps its prefix."""
        raw = (value or "").strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return None
        if net.version != 4:
            return None
        cell = self._best_cell(site, net)
        if cell is None:
            return None
        mapped = int(net.network_address) + cell.delta
        if "/" not in raw:
            return str(ipaddress.IPv4Address(mapped))
        return str(ipaddress.IPv4Network((mapped, net.prefixlen)))


def _parse_cell(raw: str) -> Tuple[Optional[Network], Optional[str]]:
    """(network, None) or (None, reason). Mirrors the existing loader's rules."""
    s = raw.strip()
    if "-" in s and "/" not in s:
        return None, "IP ranges are never remapped; use a host or CIDR"
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None, "not a valid IPv4 host or CIDR"
    if net.version != 4:
        return None, "IPv6 is never remapped"
    if "/" in s:
        try:
            ipaddress.ip_network(s, strict=True)
        except ValueError:
            return None, (f"{s} is not on a /{net.prefixlen} boundary (it would silently "
                          f"mean {net}); fix the network address or the prefix")
    return net, None


def load_site_map(path: Union[str, Path]) -> SiteMap:
    """Read and validate a one-or-more-site map. Never raises for content
    problems: they are collected in .errors (check .ok before using it)."""
    p = Path(path)
    header, rows = read_csv_rows(p)
    sm = SiteMap(path=p, sites=[])

    def err(row: int, column: str, value: str, reason: str) -> None:
        sm.errors.append({"row": row, "column": column, "value": value, "reason": reason})

    if not header:
        err(1, "", "", "file is empty")
        return sm
    if header[0].strip().lower() != SOURCE_COLUMN:
        err(1, header[0], header[0], f"first column must be {SOURCE_COLUMN!r}")
        return sm

    # Site columns: named headers after the first. A trailing empty header is
    # allowed only when no row has a value under it (a stray trailing comma).
    site_cols: List[Tuple[int, str]] = []
    for idx, name in enumerate(header[1:], start=1):
        if not name:
            continue
        if name.lower() == SOURCE_COLUMN:
            err(1, name, name, "old_subnet appears twice in the header")
            continue
        if name in (n for _, n in site_cols):
            err(1, name, name, f"duplicate site column {name!r}")
            continue
        site_cols.append((idx, name))
    if not site_cols:
        err(1, "", "", "no site columns after old_subnet")
        return sm
    sm.sites = [n for _, n in site_cols]
    sm.cells = {n: [] for n in sm.sites}
    named_idx = {i for i, _ in site_cols}

    seen_old: Dict[Network, int] = {}
    for offset, row in enumerate(rows):
        line = offset + 2
        for i, v in enumerate(row):
            if i > 0 and v and i not in named_idx:
                err(line, f"column {i + 1}", v, "value in a column with no header")
        old_raw = row[0] if row else ""
        site_vals = [(name, row[i] if i < len(row) else "") for i, name in site_cols]
        if not old_raw:
            if any(v for _, v in site_vals):
                err(line, SOURCE_COLUMN, "", "row has site values but no old_subnet")
            continue
        old, why = _parse_cell(old_raw)
        if old is None:
            err(line, SOURCE_COLUMN, old_raw, why or "invalid")
            continue
        if old in seen_old:
            err(line, SOURCE_COLUMN, old_raw,
                f"duplicate old_subnet {old}; first defined on row {seen_old[old]}")
            continue
        seen_old[old] = line
        sm.sources.append((line, old))
        for name, raw in site_vals:
            if not raw:
                continue
            new, why = _parse_cell(raw)
            if new is None:
                err(line, name, raw, why or "invalid")
                continue
            if new == old:
                err(line, name, raw, "maps a subnet to itself; leave the cell blank instead")
                continue
            if new.prefixlen > old.prefixlen:
                err(line, name, raw, (f"/{new.prefixlen} is smaller than old_subnet "
                                      f"/{old.prefixlen}; part of the old range would have "
                                      f"nowhere to map"))
                continue
            sm.cells[name].append(MapCell(row=line, site=name, old=old, new=new))
    return sm


# ---------------------------------------------------------------------------
# Map checks
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Image:
    cell: MapCell
    source: ipspan.Span      # the part of cell.old this row actually maps
    image: ipspan.Span       # where that part lands


def site_images(sm: SiteMap, site: str) -> List[_Image]:
    """Where each row of `site` actually sends addresses.

    A row only maps the part of its old_subnet that no more specific row of
    the SAME site claims (most specific wins), so its effective source is its
    old_subnet minus those children. Each piece shifts by the row's offset.
    """
    cells = sm.require_site(site)
    out: List[_Image] = []
    for c in cells:
        whole = ipspan.span_of_network(c.old)
        children = [ipspan.span_of_network(o.old) for o in cells
                    if o is not c and o.old.prefixlen > c.old.prefixlen and o.old.subnet_of(c.old)]
        for piece in ipspan.subtract(whole, children):
            out.append(_Image(cell=c, source=piece, image=ipspan.shift(piece, c.delta)))
    return out


def _example(img: _Image, at: int) -> str:
    return ipspan.fmt(ipspan.Span(4, at - img.cell.delta, at - img.cell.delta))


def check_site_map(sm: SiteMap) -> List[Dict[str, Any]]:
    """Cross-row and cross-site findings. Run only on a map with no errors."""
    findings: List[Dict[str, Any]] = []
    images = {s: site_images(sm, s) for s in sm.sites}

    # A row can map in several pieces (a more specific row splits it), so
    # hits are collected per row pair and reported once, with merged spans.
    within: Dict[Tuple[str, int, int], List[Tuple[_Image, _Image, ipspan.Span]]] = {}
    for site, imgs in images.items():
        for i, a in enumerate(imgs):
            for b in imgs[i + 1:]:
                if a.cell is b.cell:
                    continue
                hit = ipspan.intersection(a.image, b.image)
                if hit is not None:
                    within.setdefault((site, a.cell.row, b.cell.row), []).append((a, b, hit))
    for (site, _, _), hits in within.items():
        a, b, first = hits[0]
        spans = ipspan.merge(h for _, _, h in hits)
        findings.append({
            "severity": "error", "code": "collision_within_site", "site": site,
            "rows": [a.cell.row, b.cell.row],
            "destination": ", ".join(ipspan.fmt(s) for s in spans),
            "detail": (f"{site}: {ipspan.fmt(ipspan.Span(4, first.lo, first.lo))} is reached from "
                       f"{_example(a, first.lo)} (row {a.cell.row}, {a.cell.old} -> {a.cell.new}) "
                       f"and from {_example(b, first.lo)} (row {b.cell.row}, "
                       f"{b.cell.old} -> {b.cell.new}); colliding range "
                       f"{', '.join(ipspan.fmt(s) for s in spans)}"),
        })

    between: Dict[Tuple[str, str, int, int], List[ipspan.Span]] = {}
    sites = list(images)
    for i, s1 in enumerate(sites):
        for s2 in sites[i + 1:]:
            for a in images[s1]:
                for b in images[s2]:
                    hit = ipspan.intersection(a.image, b.image)
                    if hit is not None:
                        between.setdefault((s1, s2, a.cell.row, b.cell.row), []).append(hit)
    for (s1, s2, ra, rb), hits in between.items():
        spans = ", ".join(ipspan.fmt(s) for s in ipspan.merge(hits))
        findings.append({
            "severity": "error", "code": "collision_between_sites",
            "site": f"{s1}+{s2}", "rows": [ra, rb], "destination": spans,
            "detail": f"{spans} is used by {s1} (row {ra}) and by {s2} (row {rb})",
        })

    source_spans = ipspan.merge(ipspan.span_of_network(n) for _, n in sm.sources)
    into_source: Dict[Tuple[str, int], List[ipspan.Span]] = {}
    for site, imgs in images.items():
        for a in imgs:
            for src in source_spans:
                hit = ipspan.intersection(a.image, src)
                if hit is not None:
                    into_source.setdefault((site, a.cell.row), []).append(hit)
    for (site, row), hits in into_source.items():
        spans = ", ".join(ipspan.fmt(s) for s in ipspan.merge(hits))
        findings.append({
            "severity": "warning", "code": "lands_in_source_space", "site": site,
            "rows": [row], "destination": spans,
            "detail": (f"{site} row {row} maps into {spans}, which is also source "
                       f"space (an old_subnet in this map)"),
        })
    return findings


def reserved_spans(sm: SiteMap, site: str) -> List[ipspan.Span]:
    """Every address `site` may receive from the source space, merged."""
    return ipspan.merge(i.image for i in site_images(sm, site))
