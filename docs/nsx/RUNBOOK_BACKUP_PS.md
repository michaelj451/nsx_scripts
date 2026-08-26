# Runbook BACKUP (PowerShell): read-only NSX configuration backup

PowerShell command variants for [RUNBOOK_BACKUP.md](RUNBOOK_BACKUP.md); read
that file for the concepts, bundle layout, and the backup-vs-capture table.

## Take a backup

```powershell
$env:PYTHONPATH = "$PWD\app"

# One or many managers in one run. GM aliases automatically use the
# Global Manager API surface (and skip VM tags: that API is LM-only).
python tools/nsx/backup_nsx_state.py --source nsx-gm1 nsx-lm1 nsx-lm2

# Scheduled use: keep the 14 newest bundles per host
python tools/nsx/backup_nsx_state.py --source nsx-lm1 nsx-lm2 --retain 14
```

Exit code `0` only when every requested manager backed up clean.

## Verify

```powershell
Get-Content nsx_backup/nsx-lm1.lab.local/latest/summary.txt
Get-Content nsx_backup/nsx-lm1.lab.local/latest/manifest.json | ConvertFrom-Json |
  Select-Object ok, backed_up_at, host
```

## Restore (dry-run first; add --apply to write)

```powershell
$B = "nsx_backup/nsx-lm1.lab.local/latest"

python tools/nsx/services.py push --target nsx-lm1 `
  --services-dir $B/nsx_export/nsx-lm1.lab.local/domains/default/services

python tools/nsx/groups.py push --target nsx-lm1 `
  --groups-dir $B/nsx_export/nsx-lm1.lab.local/domains/default/groups

python tools/nsx/policies.py push --target nsx-lm1 `
  --policies-dir $B/nsx_export/nsx-lm1.lab.local/domains/default/security-policies
```

Same safety notes as the main runbook: every apply captures a baseline,
group deletes stay blocked without `--allow-delete`, and a restore that would
remove IPs requires `--intentional-ip-removal` after reviewing the diff.
