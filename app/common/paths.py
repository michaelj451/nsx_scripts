"""app/common/paths.py

Repo root, env-driven directories and filesystem-safe names.

Env values are read when a function is called, never at import, and this
module never loads .env. A tool that wants .env values loads it first (for
example with python-dotenv) and then asks for the directory.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Optional, Union

PathLike = Union[str, Path]

# app/common/paths.py -> parents[2] is the repo root. A constant, not a lookup.
REPO_ROOT = Path(__file__).resolve().parents[2]


def expand_path(raw: Optional[PathLike]) -> Optional[Path]:
    """Expand $VARS and ~, then make absolute. None or '' gives None."""
    if raw is None or str(raw).strip() == "":
        return None
    return Path(os.path.expandvars(os.path.expanduser(str(raw)))).resolve()


def env_dir(var: str, default: PathLike) -> Path:
    """The directory named by env var `var` (expanded), else `default`.

    A relative `default` is taken relative to the repo root, not the current
    directory, so a tool behaves the same wherever it is started from.
    Nothing is created.
    """
    found = expand_path(os.environ.get(var))
    if found is not None:
        return found
    d = Path(default)
    return d.resolve() if d.is_absolute() else (REPO_ROOT / d).resolve()


def repo_relative(path: PathLike) -> str:
    """`path` relative to the repo root when it is inside it, else absolute.
    Used to print commands an operator can paste from the repo root."""
    p = Path(path).resolve()
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def safe_name(value: str) -> str:
    """Host or label -> one safe path component (scheme and slashes removed)."""
    s = re.sub(r"^https?://", "", (value or "").strip()).rstrip("/")
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    return s or "unknown"


def slugify(name: str, max_len: int = 50) -> str:
    """Filename-safe slug capped at max_len (Windows MAX_PATH).

    Longer names are truncated and suffixed with a 7-char MD5 of the slug, so
    two long names cannot collide. Same algorithm as
    app/utilities/file_utilities.slugify, so the two give identical names.
    """
    s = re.sub(r"[^\w\-\.]+", "_", (name or "").strip())
    s = re.sub(r"_+", "_", s).strip("_") or "unnamed"
    if len(s) <= max_len:
        return s
    h = hashlib.md5(s.encode("utf-8")).hexdigest()[:7]
    keep = max(1, max_len - len(h) - 1)
    return f"{s[:keep]}_{h}"


def short_id_filename(object_id: str) -> str:
    """Deterministic, short, collision-resistant filename stem for an id.

    Same algorithm as app/utilities/file_utilities.short_id_filename, so a
    file written through either one lands at the same name.
    """
    raw = (object_id or "").strip() or "unnamed"
    s = re.sub(r"[^\w\-\.]+", "_", raw)
    s = re.sub(r"_+", "_", s).strip("_") or "unnamed"
    h = hashlib.md5(raw.encode("utf-8")).hexdigest()[:8]
    if len(s) <= 10:
        return f"{s}-{h}"
    return f"{s[:5]}-{s[-5:]}-{h}"
