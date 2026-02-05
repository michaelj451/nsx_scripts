# nsx_scripts


### 1) Clone the repository

```bash
git clone <YOUR_REPO_URL> fc_nsx
cd fc_nsx
```

### 2) Create and activate a virtual environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

### 3) Upgrade pip tooling

```bash
pip install --upgrade pip setuptools wheel
```

### 4) Install Python dependencies

Preferred:

```bash
pip install -r docker/requirements-pip.txt
```

### 5) Create the `.env` file

```bash
cp .env.example .env
```

### 6) Ensure required directories exist

```bash
mkdir -p app/frontendFastapi/static
```

## CLI Workflow (Primary Usage)

All CLI scripts must be run from the **repo root** with:

```bash
PYTHONPATH=app
```

You may export this once per session:

```bash
export PYTHONPATH="$PWD/app"
```

## Export Commands

### Export NSX Objects (Groups, Services, Policies, Rules)

```bash
PYTHONPATH=app python tools/nsx/export_nsx1_objects.py
```

### Export VM Inventory

```bash
PYTHONPATH=app python tools/nsx/export_nsx1_inventory.py
PYTHONPATH=app python tools/nsx/export_nsx2_inventory.py
```

With filtering:

```bash
PYTHONPATH=app python tools/nsx/export_nsx2_inventory.py --contains ubuntu
```

### Export VM Tags (Source NSX)

```bash
PYTHONPATH=app python tools/nsx/export_nsx1_vm_tags.py
```

## Import / Push Commands

### DRY-RUN (Always run first)

```bash
PYTHONPATH=app python tools/nsx/push_nsx_objects.py
PYTHONPATH=app python tools/nsx/push_nsx_vm_tags.py
```

These commands:
- do **not** modify NSX
- generate reports under `nsx_export/<source-manager>/`

### PRODUCTION APPLY (Explicit)

```bash
PYTHONPATH=app python tools/nsx/push_nsx_objects.py --apply
PYTHONPATH=app python tools/nsx/push_nsx_vm_tags.py --apply
```

⚠️ **Only run with `--apply` after reviewing dry-run output.**

## Notes

- All scripts are manager-scoped  
- All imports default to dry-run  
- YAML is the authoritative migration format  
- Reports are generated for traceability and audit
