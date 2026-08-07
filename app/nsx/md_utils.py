"""app/nsx/md_utils.py

Small markdown helpers shared by the report tools under tools/reports/.

align_markdown_tables(text):
    Scan a markdown document for tables (consecutive lines starting with `|`)
    and rewrite each so column widths match the widest cell (plus one space
    of padding on each side of `|`). Left-align text columns and right-align
    numeric columns based on the separator row's `---:` / `:---` markers.

    Everything outside table blocks is preserved byte-for-byte.

    Idempotent: re-running against already-aligned output changes nothing.
"""
from __future__ import annotations

from typing import List, Tuple


def _split_row(line: str) -> List[str]:
    """Parse a markdown table row into cells. Strips outer pipes only. Cells
    keep their leading/trailing whitespace stripped. Respects `\\|` as a
    literal pipe inside a cell (does NOT split on it)."""
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    # Trailing pipe: only strip if it's an unescaped delimiter, i.e. the char
    # before it is not a backslash.
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    cells: List[str] = []
    buf: List[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] == "|":
            buf.append("\\|")
            i += 2
        elif s[i] == "|":
            cells.append("".join(buf).strip())
            buf = []
            i += 1
        else:
            buf.append(s[i])
            i += 1
    cells.append("".join(buf).strip())
    return cells


def _is_separator_row(cells: List[str]) -> bool:
    """A separator row's cells look like `---`, `:---`, `---:`, or `:---:`."""
    if not cells:
        return False
    for c in cells:
        s = c.strip()
        if not s:
            return False
        core = s.strip(":")
        if not core or set(core) != {"-"}:
            return False
    return True


def _detect_align(sep_cell: str) -> str:
    """Return 'l' / 'r' / 'c' based on separator cell colons."""
    s = sep_cell.strip()
    left = s.startswith(":")
    right = s.endswith(":")
    if left and right:
        return "c"
    if right:
        return "r"
    return "l"


def _pad(cell: str, width: int, align: str) -> str:
    if align == "r":
        return cell.rjust(width)
    if align == "c":
        return cell.center(width)
    return cell.ljust(width)


def _render_sep(width: int, align: str) -> str:
    """Build a separator cell of the given rendered width. width>=3 always."""
    w = max(width, 3)
    if align == "r":
        return "-" * (w - 1) + ":"
    if align == "c":
        return ":" + "-" * (w - 2) + ":"
    return "-" * w


def _render_table(block: List[str]) -> List[str]:
    """Take a run of markdown-table lines (header, separator, then rows) and
    return the same table with cells padded so all `|` pipes align."""
    parsed: List[List[str]] = [_split_row(l) for l in block]
    # Locate separator row - by convention it's index 1, but tolerate absence.
    sep_idx = None
    for i, cells in enumerate(parsed[:2]):
        if _is_separator_row(cells):
            sep_idx = i
            break
    if sep_idx is None:
        # No separator found - not a real table; leave the block untouched.
        return block

    n = max(len(r) for r in parsed)
    # Pad short rows with empty cells so widths compute cleanly
    for r in parsed:
        while len(r) < n:
            r.append("")

    aligns = [
        _detect_align(parsed[sep_idx][i]) if i < len(parsed[sep_idx]) else "l"
        for i in range(n)
    ]

    # Column widths from headers + data rows only (skip the separator row).
    widths = [0] * n
    for idx, row in enumerate(parsed):
        if idx == sep_idx:
            continue
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)
    # Enforce a minimum width so separator can render (`---` or `---:`).
    for i in range(n):
        if widths[i] < 3:
            widths[i] = 3

    out: List[str] = []
    for idx, row in enumerate(parsed):
        if idx == sep_idx:
            cells = [_render_sep(widths[i], aligns[i]) for i in range(n)]
        else:
            cells = [_pad(row[i], widths[i], aligns[i]) for i in range(n)]
        out.append("| " + " | ".join(cells) + " |")
    return out


def align_markdown_tables(text: str) -> str:
    """Rewrite every table block in `text` so columns visually line up. Non-
    table content is preserved. Blocks are runs of consecutive lines whose
    stripped form starts with `|`."""
    lines = text.split("\n")
    out: List[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("|"):
            # Collect the whole run of table lines
            block: List[str] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                block.append(lines[i])
                i += 1
            out.extend(_render_table(block))
        else:
            out.append(line)
            i += 1
    return "\n".join(out)
