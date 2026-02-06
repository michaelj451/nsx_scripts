import os
from nsx.cli_bootstrap import load_dotenv

# Load .env exactly once, early
load_dotenv()

# ---- NSX ----
nsx_lm1 = os.getenv("NSX_LM1")
nsx_lm2 = os.getenv("NSX_LM2")
nsx_gm1 = os.getenv("NSX_GM1")
nsx_username = os.getenv("NSX_USERNAME")
nsx_password = os.getenv("NSX_PASSWORD")

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
        "nsx-lm1": nsx_lm1,
        "nsx-lm2": nsx_lm2,
    }
    return mapping[choice]