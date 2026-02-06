# ./app/utilities/file_utilities.py
# Utilities for file operations

from typing import Any
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

def slugify(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"[^\w\-\.]+", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    return name or "unnamed"