#!/usr/bin/env python3
# ./app/utilities/file_utilities.py
# Utilities for file operations

from typing import Any
import hashlib
import yaml
import json
from nsx.nsx_policy_client import NsxPolicyClient
from pathlib import Path
import re

from pathlib import Path

def ensure_dir(dir_path: Path) -> Path:
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path

def read_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def write_yaml(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

def manager_dirname(client: NsxPolicyClient) -> str:
    mgr = (client.NSX_MANAGER or "").strip()
    mgr = re.sub(r"^https?://", "", mgr).rstrip("/")
    mgr = re.sub(r"[^A-Za-z0-9._-]+", "_", mgr)
    return mgr or "unknown_manager"

def slugify(name: str, max_len: int = 50) -> str:
    """Filename-safe slug capped at max_len to keep Windows MAX_PATH happy.

    Names longer than max_len are truncated and suffixed with a 7-char
    MD5 hash of the original, so long display names can't collide and
    can't blow past the 260-char path limit on Windows.
    """
    s = re.sub(r"[^\w\-\.]+", "_", (name or "").strip())
    s = re.sub(r"_+", "_", s).strip("_") or "unnamed"
    if len(s) <= max_len:
        return s
    h = hashlib.md5(s.encode("utf-8")).hexdigest()[:7]
    keep = max(1, max_len - len(h) - 1)
    return f"{s[:keep]}_{h}"


def short_id_filename(nsx_id: str) -> str:
    """Deterministic, MAX_PATH-safe, collision-resistant filename stem.

    Format:
      - If slug <= 10 chars:  "<slug>-<8hex>"            (e.g. web-tier-c8d9e0f1)
      - Else:                 "<first5>-<last5>-<8hex>"  (e.g. App_0-s_-_2-bf57436c)

    The 8-hex MD5 of the original id makes collisions astronomically rare
    (~0.001% at 10K objects). Result is always <= ~22 chars before extension.
    Callers should append their own extension (e.g. ".yaml").
    """
    raw = (nsx_id or "").strip() or "unnamed"
    s = re.sub(r"[^\w\-\.]+", "_", raw)
    s = re.sub(r"_+", "_", s).strip("_") or "unnamed"
    h = hashlib.md5(raw.encode("utf-8")).hexdigest()[:8]
    if len(s) <= 10:
        return f"{s}-{h}"
    return f"{s[:5]}-{s[-5:]}-{h}"

def safe_filename(name: str) -> str:
    """
    Convert display_name into a filesystem-safe filename.
    """
    if not name:
        return "unnamed"

    name = name.strip()
    name = name.replace("/", "_")          # avoid directory traversal
    name = re.sub(r"[^\w\-.]+", "_", name) # keep sane chars
    name = re.sub(r"_+", "_", name)        # collapse repeats
    return name[:255]                      # filesystem-safe length