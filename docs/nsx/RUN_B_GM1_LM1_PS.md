# Run card: Workflow B on `nsx-gm1.lab.local` and `nsx-lm1.lab.local` (PowerShell)

In-place CSV subnet remap, groups only, strict-additive. Bash variant:
[RUN_B_GM1_LM1.md](RUN_B_GM1_LM1.md). Concepts and the full option set:
[RUNBOOK_B.md](RUNBOOK_B.md).

> Line continuation in PowerShell is the backtick `` ` `` at end of line, not
> the backslash. Paths use forward slashes throughout; PowerShell and the Python
> tools both accept them on Windows.

## What this touches

| Surface | Population | Reached by | Domains |
|---|---|---|---|
| `nsx-gm1.lab.local` | GM-owned, `/global-infra/` | `--target nsx-gm1 --federation-global` | `default`, `nsx-lm1.lab.local`, `nsx-lm2.lab.local` |
| `nsx-lm1.lab.local` | LM-local, `/infra/` | `--target nsx-lm1` | `default` only |

**These are two independent group populations.** A GM run never sees LM-local
groups and an LM run never sees GM-owned ones, so both halves below have to run.
Doing only one reports `failed: 0` and silently leaves the other surface
unremapped.

Groups only. Services, policies, rules and segments are never touched. The
contract is strict-additive: mapped values are appended, originals are never
rewritten or removed, and a re-run with nothing left to add sends no API writes
at all.

---

## Before you start

**1. Back up both managers.** There is no undo for a bundle you never took.

```powershell
python tools/nsx/backup_nsx_state.py --source nsx-gm1 nsx-lm1 --retain 14
```

**2. Verify each bundle** before relying on it. Both must read `NSX BACKUP OK`
with every step `OK`.

```powershell
Get-Content nsx_backup/nsx-gm1.lab.local/latest/summary.txt
Get-Content nsx_backup/nsx-lm1.lab.local/latest/summary.txt
```

**3. Decide which CSV applies to which surface.** On 2026-09-18 the two surfaces
were dry-run with *different* maps: the GM with `data/subnet_map.csv` (subnet
level, `10.4.0.0/16 -> 10.14.0.0/16` style) and lm1 with
`data/nonprod_map.csv` (host level, `10.6.0.50/32 -> 10.7.0.50/32` style). That
was deliberate for the dry run, not a recommendation. Confirm the intended map
per surface before applying. A wrong map is still additive so nothing is
destroyed, but it puts addresses on groups that should not carry them and the
revert is the only way back.

---

## 0) Env

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH  = "$PWD\app"
$env:NSX_LOG_DIR = "$PWD\nsx_logs"

$TS     = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
$GM_CSV = "data/subnet_map.csv"
$LM_CSV = "data/nonprod_map.csv"
```

The Python tools read `.env` themselves, but your **shell** does not, which is
why `NSX_LOG_DIR` is set explicitly: the report paths below interpolate it.

Push reports live **outside** any capture bundle, because a re-capture wipes the
bundle and the revert baselines have to survive it. Every `--reports-dir` below
already points somewhere safe.

---

# Part 1: the Global Manager (`nsx-gm1`)

## 1.1 Confirm the domain list

The GM carries one location-scoped domain per site on top of `default`. Both
subcommands default to `--domain-id default`, so `--all-domains` is what makes
the run cover everything.

```powershell
python tools/nsx/list_domains.py nsx-gm1
```

Expected on this lab: `default`, `nsx-lm1.lab.local`, `nsx-lm2.lab.local`.

## 1.2 Export every domain (read-only)

```powershell
python tools/nsx/groups.py export --source nsx-gm1 --federation-global `
  --all-domains --output-dir "nsx_groups_export/nsx-gm1_alldom"
```

Confirm the bundle has one directory per domain:

```powershell
Get-ChildItem nsx_groups_export/nsx-gm1_alldom -Directory | Select-Object Name
```

## 1.3 Dry run

```powershell
python tools/nsx/groups.py push --target nsx-gm1 --federation-global `
  --all-domains --groups-dir "nsx_groups_export/nsx-gm1_alldom" `
  --csv-remap $GM_CSV --reports-dir "nsx_wfb_runs/nsx-gm1/$TS"
```

## 1.4 Review gate, per domain

```powershell
Get-ChildItem "nsx_wfb_runs/nsx-gm1/$TS" -Directory | ForEach-Object {
  $d = Get-Content "$($_.FullName)/summary.json" | ConvertFrom-Json
  "{0,-22} mode={1,-8} seen={2,3} changed={3,3} added={4,3} already={5,3} failed={6}" -f `
    $_.Name, $d.mode, $d.totals.files_seen, $d.totals.csv_groups_changed, `
    $d.totals.csv_total_added_values, $d.totals.csv_already_mapped_pairs, $d.totals.failed
}
```

All of these must hold before you go further:

| Gate | Requirement |
|---|---|
| `csv_invalid_rows` | empty, in every domain's `summary.json` |
| `additive_only_contract` | `pass` |
| `failed` | `0` |
| `remap_report.md` section 1 | every "Would add" row is an address you meant to add |
| `remap_report.md` section 3 | the generic-group candidates are ones you are content to leave alone |

Check the first two across every domain in one pass:

```powershell
Get-ChildItem "nsx_wfb_runs/nsx-gm1/$TS" -Directory | ForEach-Object {
  $d = Get-Content "$($_.FullName)/summary.json" | ConvertFrom-Json
  "{0,-22} invalid_rows={1} contract={2}" -f `
    $_.Name, $d.csv_invalid_rows.Count, $d.totals.additive_only_contract
}
```

Read the per-domain report itself, not just the counters:

```powershell
Get-Content "nsx_wfb_runs/nsx-gm1/$TS/default/remap_report.md"
```

## 1.5 Apply

Same command plus `--apply`. `--batch-size` defaults to 1, so you step through
every change; `Enter` continues at the current size, a number changes it, `n`
resets to 1, `x` exits cleanly. Every decision lands in `summary.json` as
`interactive_decisions`.

```powershell
python tools/nsx/groups.py push --target nsx-gm1 --federation-global `
  --all-domains --groups-dir "nsx_groups_export/nsx-gm1_alldom" `
  --csv-remap $GM_CSV --reports-dir "nsx_wfb_runs/nsx-gm1/$TS" --apply
```

Every apply starts at one; `--batch-size 0` is no longer supported. Increase
the size at a prompt. Lost input stops the run instead of auto-approving.

---

# Part 2: the Local Manager (`nsx-lm1`)

`nsx-lm1` has only the `default` domain and no federation flag, so neither
`--all-domains` nor `--federation-global` appears in this half.

## 2.1 Capture (read-only)

Re-run this before every push session so the bundle matches the manager.
Workflow B's default IP-only scope does not need `--live-query`.

```powershell
python tools/nsx/capture_nsx_state.py --source nsx-lm1
```

## 2.2 Dry run

```powershell
python tools/nsx/groups.py push --target nsx-lm1 `
  --groups-dir "nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups" `
  --csv-remap $LM_CSV `
  --reports-dir "nsx_remap_nsx-lm1/$TS"
```

## 2.3 Review gate

Same gate as 1.4, one domain instead of three:

```powershell
$dir = "nsx_remap_nsx-lm1/$TS"
if (-not (Test-Path "$dir/summary.json")) {
  throw "no summary.json under $dir. Check that TS still matches the dry run you are reviewing."
}
$d = Get-Content "$dir/summary.json" | ConvertFrom-Json
"seen={0} changed={1} added={2} already={3} failed={4}" -f `
  $d.totals.files_seen, $d.totals.csv_groups_changed, `
  $d.totals.csv_total_added_values, $d.totals.csv_already_mapped_pairs, $d.totals.failed
"invalid_rows={0} contract={1}" -f $d.csv_invalid_rows.Count, $d.totals.additive_only_contract

Get-Content "$dir/remap_report.md"
```

## 2.4 Apply

```powershell
python tools/nsx/groups.py push --target nsx-lm1 `
  --groups-dir "nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups" `
  --csv-remap $LM_CSV `
  --reports-dir "nsx_remap_nsx-lm1/$TS" --apply
```

To widen scope from IP-only groups to generic groups as well, add
`--remap-generic`. On 2026-09-18 that would have pulled in 30 further values on
lm1, so dry-run it separately before deciding.

---

## 3) Audit (read-only, scheduled-task safe)

Reconciles the live manager against the CSV. Exit `0` is clean, `1` means gaps
in section 1a/1c.

```powershell
python tools/nsx/audit_ip_remap.py --target nsx-gm1 --csv $GM_CSV
python tools/nsx/audit_ip_remap.py --target nsx-lm1 --csv $LM_CSV
```

Generic-group candidates are informational unless you pass `--include-generic`.
Reports land under `$env:NSX_LOG_DIR\reports\<host>\ip_remap_audit\<ts>\`.

---

## 4) Revert

Each `revert` pops the most recent unreverted baseline for that reports dir and
touches only the groups listed in that run's `<TS>_pushed_ids.json`. Dry-run
first, every time.

**The GM reverts per domain**, one command each. There is no `--all-domains` on
revert.

```powershell
# Dry run, then repeat with --apply
python tools/nsx/groups.py revert --target nsx-gm1 --federation-global `
  --domain-id "default" `
  --reports-dir "nsx_wfb_runs/nsx-gm1/$TS/default"

python tools/nsx/groups.py revert --target nsx-gm1 --federation-global `
  --domain-id "nsx-lm1.lab.local" `
  --reports-dir "nsx_wfb_runs/nsx-gm1/$TS/nsx-lm1.lab.local"

python tools/nsx/groups.py revert --target nsx-gm1 --federation-global `
  --domain-id "nsx-lm2.lab.local" `
  --reports-dir "nsx_wfb_runs/nsx-gm1/$TS/nsx-lm2.lab.local"
```

The LM is a single command:

```powershell
python tools/nsx/groups.py revert --target nsx-lm1 `
  --reports-dir "nsx_remap_nsx-lm1/$TS"
```

Confirm the baseline stack is drained afterwards (no output is what you want):

```powershell
$paths = @("nsx_wfb_runs/nsx-gm1/$TS", "nsx_remap_nsx-lm1/$TS") |
  Where-Object { Test-Path $_ }
Get-ChildItem -Recurse -Path $paths -Filter "*_target_baseline.json" `
  -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -notlike "*.reverted" } |
  Select-Object -ExpandProperty FullName
```

Notes:

- Group DELETEs are blocked unless `--allow-delete` is passed. Blocked ones are
  listed in the summary as `deletes_blocked` and the revert still exits 0, so
  read the summary rather than trusting the exit code.
- Baselines predating scoped revert need `--scope all --allow-delete`. That is a
  legacy full-baseline restore: dry-run it first.

---

## Traps specific to this run

**One surface is not the estate.** The single most likely failure here is
running Part 1 and calling it done. GM-owned and LM-local groups do not overlap.

**`--all-domains` on the GM, never on the LM.** Without it the GM run covers
`default` only and reports success while two domains go untouched.

**Reports must not land in a capture bundle.** `groups.py push` defaults
`--reports-dir` to `<groups-dir>/../push_report`, which for the lm1 command
would put baselines inside `nsx_capture/`, and the next capture wipes that
bundle. Every command above passes `--reports-dir` explicitly. Do not drop it.

**Re-running an apply is safe.** Rows with nothing to add come back as
`skipped_no_change` and nothing is sent to NSX, so no revisions are bumped.

**Do not paste bash blocks into PowerShell.** A `\` continuation makes
PowerShell swallow the next line as a separate command, and `export VAR=...`
is not a PowerShell statement. If `python` reports `ModuleNotFoundError: nsx`,
`$env:PYTHONPATH` was never set for this session.

---

## Measured baseline, 2026-09-18 dry run

Numbers from a clean dry run of both halves. Treat them as the shape to expect,
not as a pass condition: they move as soon as the managers or the CSVs change.

**GM (`data/subnet_map.csv`), 15 groups across 3 domains:**

| Domain | Seen | Changed | IPs added | Failed |
|---|---:|---:|---:|---:|
| `default` | 13 | 2 | 6 | 0 |
| `nsx-lm1.lab.local` | 1 | 1 | 2 | 0 |
| `nsx-lm2.lab.local` | 1 | 0 | 0 | 0 |

`csv_invalid_rows` empty, contract `pass`. Two generic groups (`segment-group-1`,
`super-nested-group`) held 5 further values that only `--remap-generic` would
reach.

**LM `nsx-lm1` (`data/nonprod_map.csv`), 13 groups:**

| Seen | Changed | IPs added | Already-remapped pairs | Generic candidates | Failed |
|---:|---:|---:|---:|---:|---:|
| 13 | 1 | 1 | 3 | 30 | 0 |

The single change was `ip-address-group`, adding `10.7.0.51` from `10.6.0.51`
(CSV row 3). The 3 already-remapped pairs are the detector confirming earlier
runs, not new work.

---

## If something goes wrong

Revert as in section 4. If the baselines are gone or the revert cannot reach
what you need, fall back to the backup taken in the preconditions and follow
[EMERGENCY_RESTORE_PS.md](EMERGENCY_RESTORE_PS.md). Read its rules caveat first:
backup bundles do not carry `_parent_policy_id`, though for a groups-only
Workflow B rollback that trap does not apply.

---

## Dry runs only (copy and paste)

In **PowerShell**, open the `nsx_scripts` folder and paste this. It uses the existing `.venv` on either macOS or Windows:

```powershell
$Python = if (Test-Path ".venv/Scripts/python.exe") {
    ".venv/Scripts/python.exe"
} else {
    ".venv/bin/python"
}

$env:PYTHONPATH  = Join-Path $PWD "app"
$env:NSX_LOG_DIR = Join-Path $PWD "nsx_logs"

$TS     = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmss")
$EXP    = "nsx_wfb_runs/_exports/$TS"
$GM_CSV = "data/subnet_map.csv"
$LM_CSV = "data/nonprod_map.csv"

& $Python tools/nsx/groups.py export `
    --source nsx-gm1 --federation-global --all-domains `
    --output-dir "$EXP/nsx-gm1"

if ($LASTEXITCODE -eq 0) {
    & $Python tools/nsx/groups.py push `
        --target nsx-gm1 --federation-global --all-domains `
        --groups-dir "$EXP/nsx-gm1" `
        --csv-remap $GM_CSV `
        --reports-dir "nsx_wfb_runs/nsx-gm1/$TS"
}

if ($LASTEXITCODE -eq 0) {
    & $Python tools/nsx/groups.py export `
        --source nsx-lm1 `
        --output-dir "$EXP/nsx-lm1"
}

if ($LASTEXITCODE -eq 0) {
    & $Python tools/nsx/groups.py push `
        --target nsx-lm1 `
        --groups-dir "$EXP/nsx-lm1/groups" `
        --csv-remap $LM_CSV `
        --reports-dir "nsx_remap_nsx-lm1/$TS"
}
```

This previews **GM1-owned groups across all GM domains**, then **LM1-local groups in the default domain**, proceeding only when the previous command succeeds. **No NSX configuration changes are applied.**

The CSV selections match this run card: `data/subnet_map.csv` for GM1 and `data/nonprod_map.csv` for LM1. Change `$GM_CSV` or `$LM_CSV` before running if you need a different map.

This block sets `$TS`, `$GM_CSV` and `$LM_CSV` and writes its reports to the
same paths as the numbered sections: `nsx_wfb_runs/nsx-gm1/$TS` for the GM and
`nsx_remap_nsx-lm1/$TS` for the LM. The review gates in 1.4 and 2.3 and the
per-domain revert commands in section 4 therefore work in this session without
redefining anything. Only the transient export bundles live under `$EXP`, away
from any capture bundle, so no revert baseline is ever written inside a
snapshot.

Reports:

```powershell
Get-ChildItem -Path "nsx_wfb_runs/nsx-gm1/$TS/*/remap_report.md", `
    "nsx_remap_nsx-lm1/$TS/remap_report.md" -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName
```

The default scope is **IP-Addresses-Only groups**. Generic-group candidates are listed in the reports but are not included in the proposed changes. Mapped addresses would be added alongside the originals.
