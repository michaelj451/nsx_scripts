# Runbook VM Tags — Commands

## Step 0: Env — macOS / Linux

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

## Step 0: Env — Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

## Step 0: Env — Windows (Command Prompt)

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r docker\requirements-pip.txt
set PYTHONPATH=%CD%\app
```

## Step 1: Pre-change dry-run (single command)

```bash
PYTHONPATH="$PWD/app" python tools/vm_tags/dryrun_hostname_tags.py \
  --manager nsx-lm1 \
  --output-dir nsx_vm_logs/vm_tags_plan/nsx-lm1.lab.local \
  --overwrite
```

## Step 2a: (Optional alternative to Step 1) Export VM state

```bash
PYTHONPATH="$PWD/app" python tools/vm_tags/export_vm_tags.py \
  --manager nsx-lm1 \
  --base-dir nsx_vm_logs/vm_tags_export
```

## Step 2b: (Optional alternative to Step 1) Build plan from export

```bash
PYTHONPATH="$PWD/app" python tools/vm_tags/build_hostname_tag_plan.py \
  --vm-export nsx_vm_logs/vm_tags_export/nsx-lm1.lab.local/vms.json \
  --output-dir nsx_vm_logs/vm_tags_plan/nsx-lm1.lab.local \
  --overwrite
```

## Step 3: Push — dry-run

```bash
PYTHONPATH="$PWD/app" python tools/vm_tags/push_hostname_tags.py \
  --manager nsx-lm1 \
  --plan-dir nsx_vm_logs/vm_tags_plan/nsx-lm1.lab.local
```

## Step 4: Push — apply

```bash
PYTHONPATH="$PWD/app" python tools/vm_tags/push_hostname_tags.py \
  --manager nsx-lm1 \
  --plan-dir nsx_vm_logs/vm_tags_plan/nsx-lm1.lab.local \
  --apply
```

## Step 5: Validate live NSX state

```bash
PYTHONPATH="$PWD/app" python tools/vm_tags/validate_hostname_tags.py \
  --manager nsx-lm1 \
  --plan-dir nsx_vm_logs/vm_tags_plan/nsx-lm1.lab.local
```

## Step 6: Revert — dry-run

```bash
PYTHONPATH="$PWD/app" python tools/vm_tags/revert_hostname_tags.py \
  --manager nsx-lm1 \
  --manifest nsx_vm_logs/vm_tags_manifests/nsx-lm1.lab.local/<TS>_apply.json
```

## Step 7: Revert — apply

```bash
PYTHONPATH="$PWD/app" python tools/vm_tags/revert_hostname_tags.py \
  --manager nsx-lm1 \
  --manifest nsx_vm_logs/vm_tags_manifests/nsx-lm1.lab.local/<TS>_apply.json \
  --apply
```
