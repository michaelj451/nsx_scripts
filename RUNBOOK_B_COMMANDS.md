# Runbook B — Commands

## Step B.0: Env — macOS / Linux

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

## Step B.0: Env — Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

## Step B.0: Env — Windows (Command Prompt)

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r docker\requirements-pip.txt
set PYTHONPATH=%CD%\app
```

## Step B.1: Export nsx-lm1 (rollback snapshot)

```bash
python tools/nsx/export_nsx_objects.py \
  --manager nsx-lm1 \
  --base-dir nsx_export \
  --domain-id default \
  --output-format yaml
```

## Step B.2: Resolve live VM membership → additive tree

```bash
python tools/nsx/build_group_ip_additive_from_live_members.py \
  --source-manager nsx-lm1 \
  --domain-id default \
  --source-groups-dir nsx_export/nsx-lm1.lab.local/domains/default/groups \
  --output-groups-dir nsx_groups_additive_b/nsx-lm1.lab.local/domains/default/groups \
  --output-format yaml \
  --copy-first \
  --continue-on-group-error
```

## Step B.3: Apply CSV subnet remap (offline) — mapped-only

```bash
python tools/nsx/nsx_group_ip_remap_offline.py \
  --export-root nsx_groups_additive_b/nsx-lm1.lab.local/domains/default/groups \
  --prepared-root nsx_groups_remapped/nsx-lm1.lab.local/domains/default/groups \
  --mapping-csv data/nonprod_map.csv \
  --output-format yaml \
  --mapped-only
```

## Step B.4: (Optional) Affected-rule impact report

```bash
python tools/nsx/find_rules_affected_by_group_changes.py \
  --additive-root nsx_groups_remapped \
  --export-root nsx_export \
  --output-dir nsx_logs/affected_rule_reports \
  --verbose
```

## Step B.5: Dry-run push to nsx-lm1

```bash
python tools/nsx/push_additive_group_ips.py \
  --target nsx-lm1 \
  --groups-dir nsx_groups_remapped/nsx-lm1.lab.local/domains/default/groups \
  --domain-id default \
  --dry-run
```

## Step B.6: Apply push to nsx-lm1

```bash
python tools/nsx/push_additive_group_ips.py \
  --target nsx-lm1 \
  --groups-dir nsx_groups_remapped/nsx-lm1.lab.local/domains/default/groups \
  --domain-id default \
  --apply
```

## Step B.7: Validate live nsx-lm1 state

```bash
python tools/nsx/validate_nsx_groups_live.py \
  --target nsx-lm1 \
  --expected-root nsx_groups_remapped/nsx-lm1.lab.local \
  --domain-id default
```

## Rollback: Dry-run preview

```bash
python tools/nsx/push_nsx_groups_revert.py \
  --target nsx-lm1 \
  --export-root nsx_export/nsx-lm1.lab.local \
  --domain-id default
```

## Rollback: Apply

```bash
python tools/nsx/push_nsx_groups_revert.py \
  --target nsx-lm1 \
  --export-root nsx_export/nsx-lm1.lab.local \
  --domain-id default \
  --apply
```
