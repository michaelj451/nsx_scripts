# app/nsx/nsx_constants.py
import os
from pathlib import Path
from nsx.cli_bootstrap import load_dotenv

# Load .env exactly once, early
load_dotenv()

def _expand_path(raw: str | None) -> str | None:
    """
    Expand $VARS and ~ in paths, and normalize to an absolute path.
    """
    if not raw:
        return None
    expanded = os.path.expandvars(os.path.expanduser(raw))
    return str(Path(expanded).resolve())

# ---- NSX ----
nsx_lm1 = os.getenv("NSX_LM1")
nsx_lm2 = os.getenv("NSX_LM2")
nsx_lm3 = os.getenv("NSX_LM3")
nsx_lm4 = os.getenv("NSX_LM4")
nsx_gm1 = os.getenv("NSX_GM1")
nsx_gm2 = os.getenv("NSX_GM2")
nsx_username = os.getenv("NSX_USERNAME")
nsx_password = os.getenv("NSX_PASSWORD")
object_appendix = os.getenv("OBJECT_APPENDIX")

# Expand nested vars like $ROOT_DIR and $HOME
nsx_log_dir = _expand_path(os.getenv("NSX_LOG_DIR"))

# optional: safe fallback if NSX_LOG_DIR isn't set
if not nsx_log_dir:
    # repo-relative default, but don't import REPO_ROOT here if you want to keep constants lean
    nsx_log_dir = str(Path("nsx_logs").resolve())

# ---- domains ----
NSX_DOMAINS = [
    {
        "domain_id": "default",
        "display_name": "default",
        "path": "/infra/domains/default",
    }
]

def resolve_manager(choice: str) -> str:
    mapping = {
        "nsx-gm1": nsx_gm1,
        "nsx-gm2": nsx_gm2,
        "nsx-lm1": nsx_lm1,
        "nsx-lm2": nsx_lm2,
        "nsx-lm3": nsx_lm3,
        "nsx-lm4": nsx_lm4,
    }
    return mapping[choice]