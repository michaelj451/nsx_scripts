from __future__ import annotations

import argparse
import difflib
import os
from pathlib import Path
import sys
import xml.dom.minidom


def pretty_print_xml(src: Path, dst: Path) -> None:

    try:
        doc = xml.dom.minidom.parse(str(src))
    except Exception as e:
        raise RuntimeError(f"Failed to parse XML: {src}\n{e}")
    
    pretty = doc.toprettyxml(indent="   ", encoding="utf-8")
    text = pretty.decode("utf-8", errors="replace")

    lines = (ln for ln in text.splitlines() if ln.strip() != "")
    dst.write_text("\n".join(lines) + "\n", encoding="utf-8")

def normalize_lines(lines: list[str], ignore_ws: bool) -> list[str]:

    if not ignore_ws:
        return lines
    
    return [" ".join(ln.split()) + "\n" for ln in lines]

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("before", help="Path to first XML file")
    ap.add_argument("after", help="Path to second XML file")
    ap.add_argument("--out", default="xml_diff.txt", help="Output diff file path (default)")
    ap.add_argument("--workdir", default="_xml_diff_work", help="Directory for pretty-print")
    ap.add_argument("--ignore-ws", action="store_true", help="Ignore whitespace-only characters")
    ap.add_argument("--context", type=int, default=3, help="Diff conitext lines (default: 3)")
    args = ap.parse_args()

    before = Path(args.before).expanduser().resolve()
    after = Path(args.after).expanduser().resolve()

    if not before.exists():
        print(f"ERROR: before not found: {before}", file=sys.stderr)
    if not after.exists():
        print(f"ERROR: after not found: {after}", file=sys.stderr)

    workdir = Path(args.workdir).expanduser().resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    before_pretty = workdir / (before.stem + ".pretty.xml")
    after_pretty = workdir / (after.stem + ".pretty.xml")

    print(f"Pretty-print:\n {before} -> {before_pretty}\n {after} -> {after_pretty}")
    pretty_print_xml(before, before_pretty)
    pretty_print_xml(after, after_pretty)

    before_lines = before_pretty.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    after_lines = after_pretty.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)

    before_lines = normalize_lines(before_lines, args.ignore_ws)
    after_lines = normalize_lines(after_lines, args.ignore_ws)

    diff_lines = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=str(before_pretty),
        tofile=str(after_pretty),
        n=args.context,
        lineterm="",
    )

    out_path = Path(args.out).expanduser().resolve()
    out_path.write_text("\n".join(diff_lines) + "\n", encoding="utf-8")

    size = out_path.stat().st_size
    print(f'Wrote diff: {out_path} ({size,} bytes)')

    txt = out_path.read_text(encoding="utf-8", errors="replace")
    adds = sum(1 for ln in txt.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
    dels = sum(1 for ln in  txt.splitlines() if ln.startswith("-") and not ln.startswith("---"))
    print(f"approx changes: +{adds}/ -{dels}")
    
    return 0

if __name__ == "__main__":
    raise SystemExit(main())



    
