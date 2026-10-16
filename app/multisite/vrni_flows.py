"""app/multisite/vrni_flows.py

Filter a vRNI flow export (CSV) by the NSX rule each flow hit (Mike,
2026-10-15): flows whose rule sits in an Infrastructure-category policy are
taken out, so what is left is the application traffic a migration has to
carry. No NSX calls here: tools/multisite/filter_vrni_flows.py reads the
manager (or a capture) and calls these functions.

A flow is matched to its rule by number: vRNI's "firewall ruleid" column is
NSX's numeric rule_id on the manager the flows were seen on. Each manager
numbers its rules itself, so the rules must come from that same manager.

Every row lands in exactly one of three lists, with its original columns:

  kept       the rule is known and its policy is not in an excluded category
  removed    the rule's policy is in an excluded category (Infrastructure)
  unmatched  no rule id in the row, or a number that is not on the manager
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from common.md import align_markdown_tables, md_table

DEFAULT_EXCLUDE = ("Infrastructure",)
# Logical column -> header text in the vRNI export, matched case-insensitively.
# The packet-count header carries the export window, so it is matched by prefix.
COLUMNS = {"rule_number": "firewall ruleid", "rule_name": "firewall rule", "src_ip": "source ip address",
           "dst_ip": "destination ip address", "action": "firewall action", "packets": "flow packet count"}
PREFIX_COLUMNS = ("packets",)
REQUIRED = ("rule_number",)


def find_columns(header: Sequence[str]) -> Dict[str, int]:
    """Logical column -> index. Raises ValueError naming the headers found
    when a required column is missing."""
    norm = [str(h or "").strip().lower() for h in header]
    out: Dict[str, int] = {}
    for key, want in COLUMNS.items():
        for i, h in enumerate(norm):
            if h == want or (key in PREFIX_COLUMNS and h.startswith(want)):
                out[key] = i
                break
    missing = [COLUMNS[k] for k in REQUIRED if k not in out]
    if missing:
        raise ValueError(f"column(s) {', '.join(repr(m) for m in missing)} not found; the file has: "
                         + ", ".join(repr(h) for h in header))
    return out


def window(header: Sequence[str], cols: Dict[str, int]) -> Optional[str]:
    """The export window from the packet-count header, e.g. "14/10/2026 ... to ..."."""
    if "packets" not in cols:
        return None
    h = str(header[cols["packets"]])
    return h[h.find("(") + 1:h.rfind(")")] if "(" in h and ")" in h else None


def parse_rule_number(text: Any) -> Optional[int]:
    """"8168", "8,168", "8168.0" -> 8168; blank or not a number -> None."""
    s = str(text or "").strip().replace(",", "")
    if not s:
        return None
    try:
        return int(float(s))
    except ValueError:
        return None


def rule_index(pairs: Iterable[Tuple[Dict[str, Any], Dict[str, Any]]]) -> Dict[int, Dict[str, Any]]:
    """(policy, rule) pairs from one manager -> {rule number: what the report needs}."""
    out: Dict[int, Dict[str, Any]] = {}
    for pol, rule in pairs:
        n = parse_rule_number(rule.get("rule_id"))
        if n is None:
            continue
        out[n] = {"number": n, "policy_id": pol.get("id"), "policy": pol.get("display_name") or pol.get("id"),
                  "category": pol.get("category") or "", "rule_id": rule.get("id"),
                  "rule": rule.get("display_name") or rule.get("id"), "action": rule.get("action"),
                  "default_section": bool(pol.get("is_default"))}
    return out


def read_flows(path: Path) -> Tuple[List[str], List[List[str]]]:
    """(header, rows). Excel's UTF-8 byte-order mark is accepted; blank lines are skipped."""
    with Path(path).open(encoding="utf-8-sig", newline="") as fh:
        rows = [r for r in csv.reader(fh) if any(c.strip() for c in r)]
    if not rows:
        raise ValueError(f"{path} is empty")
    return rows[0], rows[1:]


def classify(rows: Sequence[Sequence[str]], cols: Dict[str, int], index: Dict[int, Dict[str, Any]],
             exclude_categories: Sequence[str] = DEFAULT_EXCLUDE) -> Dict[str, Any]:
    """Split the rows into kept / removed / unmatched; each entry is
    (row, rule or None, reason). Also counts flows per rule."""
    excl = {c.lower() for c in exclude_categories}
    out: Dict[str, Any] = {"kept": [], "removed": [], "unmatched": [], "per_rule": {}}
    col = cols["rule_number"]
    for row in rows:
        raw = row[col] if col < len(row) else ""
        n = parse_rule_number(raw)
        rule = index.get(n) if n is not None else None
        if n is None:
            out["unmatched"].append((row, None, "no rule id in the row" if not str(raw).strip()
                                     else f"rule id {raw!r} is not a number"))
            continue
        if rule is None:
            out["unmatched"].append((row, None, f"rule {n} is not on the manager the rules were read from"))
            continue
        slot = out["per_rule"].setdefault(n, {"rule": rule, "flows": 0, "packets": 0})
        slot["flows"] += 1
        if "packets" in cols and cols["packets"] < len(row):
            slot["packets"] += parse_rule_number(row[cols["packets"]]) or 0
        if rule["category"].lower() in excl:
            out["removed"].append((row, rule, f"{rule['category']} rule: {rule['policy']} / {rule['rule']}"))
        else:
            out["kept"].append((row, rule, ""))
    return out


def write_csv(path: Path, header: Sequence[str], entries: Sequence[Tuple[List[str], Any, str]],
              reason_column: Optional[str] = None) -> None:
    """Original columns, in order; `reason_column` adds one more at the end.
    Written with a byte-order mark so Excel opens it as UTF-8."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(list(header) + ([reason_column] if reason_column else []))
        for row, _rule, reason in entries:
            w.writerow(list(row) + ([reason] if reason_column else []))


RULES_HEADER = ["rule #", "rule name", "rule id", "policy", "category", "action", "flows", "packets", "result"]


def rules_rows(result: Dict[str, Any], exclude_categories: Sequence[str]) -> List[List[Any]]:
    """One row per rule seen in the export (Mike, 2026-10-16): its number,
    display name, NSX id, policy, category, action, flow and packet counts,
    and whether its flows were kept or removed. Kept rules first."""
    excl = {c.lower() for c in exclude_categories}
    out = []
    for s in result["per_rule"].values():
        r = s["rule"]
        removed = r["category"].lower() in excl
        out.append([r["number"], r["rule"], r["rule_id"], r["policy"], r["category"], r["action"], s["flows"],
                    s.get("packets", 0),
                    "removed" if removed else "kept (NSX default section)" if r["default_section"] else "kept"])
    return sorted(out, key=lambda x: (x[-1] == "removed", str(x[3]), x[0]))


KEPT_TITLE = "Rules kept (application traffic)"
INFRA_TITLE = "Infrastructure rules hit (removed)"


def write_rules_csv(path: Path, rows: Sequence[Sequence[Any]]) -> None:
    """Two sections, each with its own title and header (Mike, 2026-10-16):
    the rules kept, then the Infrastructure rules the flows hit."""
    path.parent.mkdir(parents=True, exist_ok=True)
    kept = [r for r in rows if r[-1] != "removed"]
    infra = [r for r in rows if r[-1] == "removed"]
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        for i, (title, part) in enumerate(((KEPT_TITLE, kept), (INFRA_TITLE, infra))):
            if i:
                w.writerow([])
            w.writerow([f"{title}: {len(part)} rule(s)"])
            w.writerow(RULES_HEADER)
            w.writerows(part or [["none"]])


def summary_md(src: str, rules_from: str, header: Sequence[str], cols: Dict[str, int],
               result: Dict[str, Any], files: Dict[str, str], exclude_categories: Sequence[str]) -> str:
    total = sum(len(result[k]) for k in ("kept", "removed", "unmatched"))
    L = ["# vRNI flow filter", "",
         f"Flows `{src}`" + (f", window {window(header, cols)}" if window(header, cols) else "")
         + f". Rules read from {rules_from}. Left out: rules in "
         + ", ".join(f"**{c}**" for c in exclude_categories) + " policies.", ""]
    L += md_table(["rows", "kept", "removed", "unmatched"],
                  [[total, len(result["kept"]), len(result["removed"]), len(result["unmatched"])]], ["r"] * 4)
    L += ["", "## Files", ""] + [f"- {k}: `{v}`" for k, v in files.items()]
    rows = rules_rows(result, exclude_categories)
    cols_md = ["rule #", "rule name", "rule id", "policy", "category", "action", "flows", "packets", "result"]
    align = ["r", "l", "l", "l", "l", "l", "r", "r", "l"]
    for title, part in ((KEPT_TITLE, [r for r in rows if r[-1] != "removed"]),
                        (INFRA_TITLE, [r for r in rows if r[-1] == "removed"])):
        L += ["", f"## {title}", ""]
        L += md_table(cols_md, part, align) if part else ["None."]
    L += ["", "Rules are matched by vRNI's firewall ruleid to NSX's numeric rule id on that manager."]
    if result["unmatched"]:
        L += ["", "## Unmatched rows", "",
              "Not classified, so neither kept nor removed: review them by hand.", ""]
        why: Dict[str, int] = {}
        for _row, _rule, reason in result["unmatched"]:
            why[reason] = why.get(reason, 0) + 1
        L += md_table(["reason", "rows"], [[k, v] for k, v in sorted(why.items())], ["l", "r"])
    return align_markdown_tables("\n".join(L)) + "\n"
