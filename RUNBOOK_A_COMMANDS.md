# Runbook A — Commands

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

## Step 1a: Export source — nsx-lm1

```bash
python tools/nsx/export_nsx_objects.py \
  --manager nsx-lm1 \
  --base-dir nsx_export \
  --domain-id default \
  --output-format yaml
```

## Step 1b: Export target — nsx-lm2 (pre-change snapshot)

```bash
python tools/nsx/export_nsx_objects.py \
  --manager nsx-lm2 \
  --base-dir nsx_export \
  --domain-id default \
  --output-format yaml
```

## Step 2: Resolve live VM membership — lm1 → lm2 additive tree

```bash
python tools/nsx/build_group_ip_additive_from_live_members.py \
  --source-manager nsx-lm1 \
  --domain-id default \
  --source-groups-dir nsx_export/nsx-lm1.lab.local/domains/default/groups \
  --output-groups-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \
  --output-format yaml \
  --copy-first \
  --continue-on-group-error
```

## Step 3a: (Optional) Affected-rule impact report

```bash
python tools/nsx/find_rules_affected_by_group_changes.py \
  --additive-root nsx_groups_additive_a \
  --export-root nsx_export \
  --output-dir nsx_logs/affected_rule_reports \
  --verbose
```

## Step 3b: (Optional) Segment reference inventory

```bash
PYTHONPATH="$PWD/app" python tools/nsx/find_segments_referenced.py \
  --export-root nsx_export \
  --source-manager nsx-lm1 \
  --output-dir nsx_logs/segment_inventory \
  --verbose
```

## Step 4: (Optional) Transform segment references — strip mode

```bash
PYTHONPATH="$PWD/app" python tools/nsx/transform_group_segments.py \
  --input-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \
  --output-dir nsx_groups_transformed/nsx-lm2.lab.local/domains/default/groups \
  --mode strip \
  --overwrite
```

## Step 4: (Optional) Transform segment references — convert mode

```bash
PYTHONPATH="$PWD/app" python tools/nsx/transform_group_segments.py \
  --input-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \
  --output-dir nsx_groups_transformed/nsx-lm2.lab.local/domains/default/groups \
  --mode convert \
  --source-manager nsx-lm1 \
  --overwrite
```

## Step 5: Assemble complete payload for nsx-lm2

```bash
python tools/nsx/build_complete_nsx_payload.py \
  --source-manager-dir nsx_export/nsx-lm1.lab.local \
  --additive-groups-dir nsx_groups_transformed/nsx-lm2.lab.local/domains/default/groups \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --overwrite
```

## Step 6: Dry-run push to nsx-lm2

```bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm2 \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --dry-run
```

## Step 7: Apply push to nsx-lm2

```bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm2 \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --apply
```

## Step 8: Validate live nsx-lm2 state

```bash
python tools/nsx/validate_nsx_groups_live.py \
  --target nsx-lm2 \
  --expected-root nsx_groups_transformed/nsx-lm2.lab.local \
  --domain-id default
```

## Sandbox: Dry-run push to nsx-lm3

```bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm3 \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --dry-run
```

## Sandbox: Apply push to nsx-lm3

```bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm3 \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --apply
```

## Rollback: Dry-run preview

```bash
PYTHONPATH="$PWD/app" python tools/nsx/push_complete_nsx_revert.py \
  --target nsx-lm2 \
  --export-root nsx_export/nsx-lm2.lab.local \
  --domain-id default
```

## Rollback: Apply

```bash
PYTHONPATH="$PWD/app" python tools/nsx/push_complete_nsx_revert.py \
  --target nsx-lm2 \
  --export-root nsx_export/nsx-lm2.lab.local \
  --domain-id default \
  --apply
```

## Rollback: Apply with services

```bash
PYTHONPATH="$PWD/app" python tools/nsx/push_complete_nsx_revert.py \
  --target nsx-lm2 \
  --export-root nsx_export/nsx-lm2.lab.local \
  --domain-id default \
  --include-services \
  --apply
```
