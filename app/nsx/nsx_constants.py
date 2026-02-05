import os
from frontendFastapi.nsx.cli_bootstrap import load_dotenv

# Load .env exactly once, early
load_dotenv()

# ---- build / environment ----
build_env = os.getenv("BUILD_ENV")

# ---- Postgres ----
postgresuser = os.getenv("POSTGRES_USER")
postgrespass = os.getenv("POSTGRES_PASSWORD")
postgresserver = os.getenv("POSTGRES_HOST", "localhost")
postgresdb = os.getenv("POSTGRES_DB", "nsx")
postgresport = os.getenv("POSTGRES_PORT", "5432")

# ---- NSX ----
nsx_manager1 = os.getenv("NSX_HOST1")
nsx_manager2 = os.getenv("NSX_HOST2")
nsx_username = os.getenv("NSX_USERNAME")
nsx_password = os.getenv("NSX_PASSWORD")

# ---- schema ----
new_schema = os.getenv("NEW_SCHEMA")

# ---- domains ----
NSX_DOMAINS = [
    {
        "domain_id": "default",
        "display_name": "default",
        "path": "/infra/domains/default",
    }
]