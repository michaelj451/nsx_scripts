# EMERGENCY RESTORE (PowerShell) : back up now, put it back later

PowerShell variant of [EMERGENCY_RESTORE.md](EMERGENCY_RESTORE.md). Read that
file for the reasoning, the caveats, and what a restore cannot reach; this one
is the commands.

> **It does not wipe.** A restore pushes the backed-up definitions back over
> whatever is on the manager. Anything created after the backup is **still
> there** afterwards, because it is not in the bundle and nothing tells the
> push to remove it.

---

## 0) Env

`$S` is the manager alias, `$H` its hostname (bundles are keyed by hostname),
`$B` the bundle's object root, `$R` where this restore's reports go.

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\app"

$S = "nsx-lm1"
$H = "nsx-lm1.lab.local"
$B = "nsx_backup/$H/latest/nsx_export/$H/domains/default"
$R = "nsx_restore/$H/" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
New-Item -ItemType Directory -Force -Path $R | Out-Null
```

Replace `latest` with a timestamped directory name (for example
`20260910_185942`) to restore a specific point in time.

Windows has no symlink for `latest` in some checkouts. If `$B` does not
resolve, pick the newest bundle explicitly:

```powershell
$bundle = Get-ChildItem "nsx_backup/$H" -Directory |
          Where-Object { $_.Name -match '^\d{8}_\d{6}$' } |
          Sort-Object Name | Select-Object -Last 1
$B = "nsx_backup/$H/$($bundle.Name)/nsx_export/$H/domains/default"
```

---

## 1) Take a backup

```powershell
python tools/nsx/backup_nsx_state.py --source $S
```

Several managers at once, keeping the 14 newest bundles each:

```powershell
python tools/nsx/backup_nsx_state.py --source nsx-lm1 nsx-lm2 nsx-gm1 --retain 14
```

Exit code is 0 only when every requested manager backed up clean.

### Verify the backup before you rely on it

```powershell
Get-Content "nsx_backup/$H/latest/summary.txt"

(Get-ChildItem "$B/groups" -Filter *.yaml).Count
(Get-ChildItem "$B/services" -Filter *.yaml).Count
(Get-ChildItem "$B/security-policies" -Directory).Count
```

`summary.txt` must say `NSX BACKUP OK` with every step `OK`.

---

## 2) Restore

Order matters: services, groups, policies, rules.

### 2a. Dry run

```powershell
python tools/nsx/services.py push --target $S `
  --services-dir "$B/services"          --reports-dir "$R/services"

python tools/nsx/groups.py push --target $S `
  --groups-dir "$B/groups"              --reports-dir "$R/groups"

python tools/nsx/policies.py push --target $S `
  --policies-dir "$B/security-policies" --reports-dir "$R/policies"

python tools/nsx/rules.py push --target $S `
  --rules-dir "$B/security-policies"    --reports-dir "$R/rules"
```

### 2b. Apply

```powershell
python tools/nsx/services.py push --target $S `
  --services-dir "$B/services"          --reports-dir "$R/services" --apply

python tools/nsx/groups.py push --target $S `
  --groups-dir "$B/groups"              --reports-dir "$R/groups"   --apply

python tools/nsx/policies.py push --target $S `
  --policies-dir "$B/security-policies" --reports-dir "$R/policies" --apply

python tools/nsx/rules.py push --target $S `
  --rules-dir "$B/security-policies"    --reports-dir "$R/rules"    --apply
```

Each apply captures a baseline under `$R/<class>/baselines/` first, so the
restore itself is revertible.

---

## 3) Verify the restore

```powershell
python tools/nsx/capture_nsx_state.py --source $S --live-query

$live = (Get-ChildItem "nsx_groups_export/$H/groups" -Filter *.yaml).Count
$bund = (Get-ChildItem "$B/groups" -Filter *.yaml).Count
"groups on manager: $live   in bundle: $bund"
```

A manager count higher than the bundle count is expected when objects were
added after the backup: a restore does not remove them.

For a content-level comparison, save the Python block from
[EMERGENCY_RESTORE.md](EMERGENCY_RESTORE.md) section 3 as `compare.py` and run
it with the two paths as arguments (PowerShell has no heredoc, so the inline
form in that document does not paste here):

```powershell
python compare.py $B $H
```

---

## Three things that will bite you

**`--reports-dir` is not optional.** A push defaults its reports to
`<dir>/../push_report`, so aiming one straight at a backup bundle writes
baselines **inside the snapshot you are restoring from**. Every command above
sends them to `$R`.

**Rules need `_parent_policy_id`, and backup bundles lack it.** `rules.py push`
falls back to the folder name, which in a backup bundle is a slugified hash
rather than the policy id, so rules land in a policy that does not exist.
Restore rules from a tree that carries the field instead:

```powershell
python tools/nsx/rules.py push --target $S `
  --rules-dir "nsx_rules_export/$H/security-policies" `
  --reports-dir "$R/rules" --apply
```

Only when that tree matches the backup point; compare rule ids first.

**A restore can legitimately need to REMOVE IPs**, when the backup predates a
later addition. `groups.py push` refuses those rows as contract violations.
Read the per-row diff, then re-run that one class with
`--intentional-ip-removal`.

---

## If the restore itself goes wrong

```powershell
python tools/nsx/rules.py    revert --target $S --reports-dir "$R/rules"    --apply
python tools/nsx/policies.py revert --target $S --reports-dir "$R/policies" --apply
python tools/nsx/groups.py   revert --target $S --reports-dir "$R/groups"   --apply
python tools/nsx/services.py revert --target $S --reports-dir "$R/services" --apply
```

A revert that must DELETE a group it created is blocked unless you add
`--allow-delete`; without it those groups stay, are listed under
`deletes_blocked`, and the revert still exits 0. Check the summary rather than
the exit code:

```powershell
$f = Get-ChildItem "$R/groups/revert_summary_*.json" | Sort-Object Name | Select-Object -Last 1
(Get-Content $f.FullName | ConvertFrom-Json).totals
```

Each revert consumes one baseline and renames it `*.reverted`. If a class was
applied more than once, each invocation undoes one apply, newest first.
