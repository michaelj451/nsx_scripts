"""app/common/fileio.py

File IO used by both the NSX and the Palo Alto tools: JSON, YAML, JSONL,
CSV and text, plus SHA-256 helpers for change evidence.

Writes create parent directories and are ATOMIC by default: the content goes
to a temporary file in the same directory, which then replaces the target in
one step. A crash or Ctrl-C mid-write leaves the previous file intact instead
of a truncated one, which matters for baselines and manifests that a later
rollback reads.

Reads use UTF-8. CSV reads use utf-8-sig so a file saved by Excel (with a
byte-order mark) parses the same as one saved by an editor.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Sequence, Tuple, Union

import yaml

PathLike = Union[str, Path]


def ensure_dir(path: PathLike) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# text
# ---------------------------------------------------------------------------

def read_text(path: PathLike) -> str:
    return Path(path).read_text(encoding="utf-8")


def write_text(path: PathLike, text: str, *, atomic: bool = True) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not atomic:
        p.write_text(text, encoding="utf-8")
        return p
    fd, tmp = tempfile.mkstemp(prefix=f".{p.name}.", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return p


# ---------------------------------------------------------------------------
# JSON / JSONL
# ---------------------------------------------------------------------------

def read_json(path: PathLike) -> Any:
    return json.loads(read_text(path))


def write_json(path: PathLike, data: Any, *, indent: int = 2,
               sort_keys: bool = True, atomic: bool = True) -> Path:
    """Same defaults as app/utilities/file_utilities.write_json (indent 2,
    sorted keys), plus a trailing newline and an atomic replace."""
    text = json.dumps(data, indent=indent, sort_keys=sort_keys, default=str) + "\n"
    return write_text(path, text, atomic=atomic)


def read_jsonl(path: PathLike) -> List[Any]:
    out: List[Any] = []
    for line in read_text(path).splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def iter_jsonl(path: PathLike) -> Iterator[Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: PathLike, rows: Iterable[Any], *, atomic: bool = True) -> Path:
    text = "".join(json.dumps(r, sort_keys=True, default=str) + "\n" for r in rows)
    return write_text(path, text, atomic=atomic)


def append_jsonl(path: PathLike, row: Any) -> Path:
    """Append one record. Not atomic by nature; use for logs, not baselines."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True, default=str) + "\n")
    return p


# ---------------------------------------------------------------------------
# YAML
# ---------------------------------------------------------------------------

def read_yaml(path: PathLike) -> Any:
    return yaml.safe_load(read_text(path))


def write_yaml(path: PathLike, data: Any, *, sort_keys: bool = False,
               atomic: bool = True) -> Path:
    """Same defaults as app/utilities/file_utilities.write_yaml (key order kept)."""
    return write_text(path, yaml.safe_dump(data, sort_keys=sort_keys), atomic=atomic)


def read_doc(path: PathLike) -> Any:
    """Read .json, .yaml or .yml by extension; anything else is an error."""
    suffix = Path(path).suffix.lower()
    if suffix == ".json":
        return read_json(path)
    if suffix in (".yaml", ".yml"):
        return read_yaml(path)
    raise ValueError(f"Unsupported document extension {suffix!r}: {path}")


def write_doc(path: PathLike, data: Any) -> Path:
    suffix = Path(path).suffix.lower()
    if suffix == ".json":
        return write_json(path, data)
    if suffix in (".yaml", ".yml"):
        return write_yaml(path, data)
    raise ValueError(f"Unsupported document extension {suffix!r}: {path}")


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def read_csv_rows(path: PathLike) -> Tuple[List[str], List[List[str]]]:
    """(header, rows) with every cell stripped. Blank lines are dropped.

    Plain csv.reader rather than DictReader, so duplicate header names are
    visible to the caller instead of silently collapsing into one key.
    """
    with Path(path).open("r", encoding="utf-8-sig", newline="") as f:
        lines = [[c.strip() for c in row] for row in csv.reader(f)]
    lines = [r for r in lines if any(c for c in r)]
    if not lines:
        return [], []
    return lines[0], lines[1:]


def read_csv_dicts(path: PathLike) -> List[Dict[str, str]]:
    """Rows as dicts keyed by the stripped header. Duplicate headers raise."""
    header, rows = read_csv_rows(path)
    seen = set()
    for h in header:
        if h and h in seen:
            raise ValueError(f"Duplicate CSV header {h!r} in {path}")
        seen.add(h)
    return [{h: (r[i] if i < len(r) else "") for i, h in enumerate(header) if h} for r in rows]


def write_csv(path: PathLike, header: Sequence[str], rows: Iterable[Sequence[Any]],
              *, atomic: bool = True) -> Path:
    import io
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(list(header))
    for r in rows:
        w.writerow(list(r))
    return write_text(path, buf.getvalue(), atomic=atomic)


# ---------------------------------------------------------------------------
# SHA-256 (change evidence: "this is exactly what the dry run previewed")
# ---------------------------------------------------------------------------

def sha256_file(path: PathLike) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_tree(root: PathLike, *, exclude_dirs: Sequence[str] = ()) -> Dict[str, Any]:
    """Per-file SHA-256 of every file under `root`, sorted by relative path,
    plus one digest over that sorted manifest. Directories named in
    `exclude_dirs` (at any depth) are skipped, e.g. ("push_report", "logs")."""
    base = Path(root)
    files: Dict[str, str] = {}
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(base)
        if any(part in exclude_dirs for part in rel.parts[:-1]):
            continue
        files[rel.as_posix()] = sha256_file(p)
    manifest = "".join(f"{digest}  {rel}\n" for rel, digest in files.items())
    return {"files": files,
            "manifest_sha256": hashlib.sha256(manifest.encode("utf-8")).hexdigest()}
