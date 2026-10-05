# Multivendor rollout (PowerShell): nsx-lm1 to nsx-lm2 or nsx-lm3, through Palo Alto dg-5

PowerShell variant of [RUNBOOK_MULTIVENDOR_ROLLOUT.md](RUNBOOK_MULTIVENDOR_ROLLOUT.md).
The reasoning, the site table and the caveats live there; this card carries the
same steps as PowerShell commands. Run from the repository root.

| Step | Adds to | Whose addresses | Suffix | Map | Run dir (under `$B`) |
|---|---|---|---|---|---|
| 2 | `nsx-lm3` | policy clone (Workflow A) | | | `nsx-lm3_A` |
| 3 | `nsx-lm3` | lm1, unmapped (Workflow C) | `_np_ips` | | `nsx-lm3_np_ips` |
| 4 | `nsx-lm1` | lm2 (mapped) | `_avs_ips` | `subnet_map_lm2.csv` | `nsx-lm1_avs_ips` |
| 5 | `nsx-lm1` | lm3 (mapped) | `_lm3_ips` | `subnet_map_lm3.csv` | `nsx-lm1_lm3_ips` |
| 6a | `nsx-lm2` | lm3 (mapped) | `_lm3_ips` | `subnet_map_lm3.csv` | `nsx-lm2_lm3_ips` |
| 6b | `nsx-lm3` | lm2 (mapped) | `_avs_ips` | `subnet_map_lm2.csv` | `nsx-lm3_avs_ips` |

Step 6 only if lm2 and lm3 workloads must talk to each other. A and C onto
lm2 come from [RUN_AC_LM2_PS.md](../nsx/RUN_AC_LM2_PS.md).

---

## 0) Env and map check

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH  = "$PWD\app"
$env:NSX_LOG_DIR = "$PWD\nsx_logs"
$env:PYTHONUTF8  = "1"

$S    = "nsx-lm1"
$SH   = "nsx-lm1.lab.local"
$MAP2 = "data/subnet_map_lm2.csv"
$MAP3 = "data/subnet_map_lm3.csv"
$B    = "nsx_avs_runs/rollout"
New-Item -ItemType Directory -Force -Path $B | Out-Null

# Each map must report "Map OK" and exit 0. A collision exits 2 and names the rows.
python tools/multisite/plan_multisite.py --map $MAP2 --check-map-only; "exit $LASTEXITCODE"
python tools/multisite/plan_multisite.py --map $MAP3 --check-map-only; "exit $LASTEXITCODE"
```

One function per step, with that step's target, run dir, suffix and map
filled in:

```powershell
function Step2  { python tools/nsx/run_workflow.py --source $S --target nsx-lm3 --run-dir "$B/nsx-lm3_A" @args }
function Step3  { python tools/nsx/run_workflow.py --source $S --target nsx-lm3 --run-dir "$B/nsx-lm3_np_ips" @args }
function Step4  { python tools/nsx/run_workflow.py --source $S --target nsx-lm1 --run-dir "$B/nsx-lm1_avs_ips" --appendix _avs_ips --csv-remap $MAP2 @args }
function Step5  { python tools/nsx/run_workflow.py --source $S --target nsx-lm1 --run-dir "$B/nsx-lm1_lm3_ips" --appendix _lm3_ips --csv-remap $MAP3 @args }
function Step6a { python tools/nsx/run_workflow.py --source $S --target nsx-lm2 --run-dir "$B/nsx-lm2_lm3_ips" --appendix _lm3_ips --csv-remap $MAP3 @args }
function Step6b { python tools/nsx/run_workflow.py --source $S --target nsx-lm3 --run-dir "$B/nsx-lm3_avs_ips" --appendix _avs_ips --csv-remap $MAP2 @args }
```

Every command below is a dry run unless it says `--apply`.

---

## 1) Capture lm1 (read only), then back up lm3

With `.env` holding **lm1** credentials (`Remove-Item Env:NSX_USERNAME, Env:NSX_PASSWORD -ErrorAction SilentlyContinue`
if your session overrides them):

```powershell
python tools/nsx/capture_nsx_state.py --source $S --live-query
Get-Content "nsx_capture/$SH/groups_additive/domains/default/groups/manifest.json" |
  ConvertFrom-Json |
  Select-Object ip_source, groups_seen, effective_ip_queries, groups_changed, ips_added_total, groups_errors
```

`ip_source` must be `effective`, `effective_ip_queries` must equal `groups_seen`,
`groups_errors` must be `0`.

Switch `.env` to **lm3** credentials and back lm3 up:

```powershell
python tools/nsx/backup_nsx_state.py --source nsx-lm3 --retain 14
Get-Content "nsx_backup/nsx-lm3.lab.local/latest/summary.txt"
```

---

## 2) Workflow A: clone lm1's policy onto lm3

```powershell
Step2 --phase a                     # dry run: read report/a/dryrun
Step2 --phase a --apply
Step2 --phase a --verify
```

lm3's older test copy may clash with lm1's object IDs; the dry run shows it.
After this step a default A rollback **on lm2** is refused (shared baseline
folder); name its baseline with `--from-baseline`.

Rollback: `Step2 --phase a --rollback`, then add `--apply`.

---

## 3) Workflow C: lm1's addresses onto lm3

```powershell
Step3 --phase c                     # dry run: read report/c/dryrun
Step3 --phase c --apply
Step3 --phase c --verify
```

Rollback: `Step3 --phase c --rollback`, then add `--apply`.

---

## 4) lm2's addresses onto lm1

Switch `.env` to **lm1** credentials. Window 4a adds siblings (nothing that
enforces traffic changes); window 4b makes the rules use them.

```powershell
Step4 --phase d2a                   # dry run: re-captures lm1 into its run dir
Step4 --phase d2a --apply

Step4 --phase d3
Step4 --phase d3 --apply
Step4 --phase d3 --verify
```

A `--verify` between 4a and 4b reports missing rule references until 4b runs.
If you re-ran an apply that sent nothing, roll back with `--from-baseline`.

Rollback: `Step4 --phase d3 --rollback --apply`, then `Step4 --phase d2a --rollback --apply`.

---

## 5) lm3's addresses onto lm1

lm1 credentials.

```powershell
Step5 --phase d2a
Step5 --phase d2a --apply
Step5 --phase d3
Step5 --phase d3 --apply
Step5 --phase d3 --verify
```

Rollback: `Step5 --phase d3 --rollback --apply`, then `Step5 --phase d2a --rollback --apply`.

---

## 6) Only if lm2 and lm3 must talk: each other's addresses

Capture lm1 by hand with lm1 credentials, then switch to the target's
credentials and reuse that capture.

### 6a: lm3's addresses onto lm2

```powershell
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$B/nsx-lm2_lm3_ips/capture/$SH"
python tools/nsx/capture_nsx_state.py --source $S --live-query `
  --output-dir "$B/nsx-lm2_lm3_ips/capture/$SH" --no-flat-exports
# switch .env to lm2 credentials
Step6a --phase d2a --no-capture
Step6a --phase d2a --apply
Step6a --phase d3
Step6a --phase d3 --apply
Step6a --phase d3 --verify
```

### 6b: lm2's addresses onto lm3

```powershell
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$B/nsx-lm3_avs_ips/capture/$SH"
python tools/nsx/capture_nsx_state.py --source $S --live-query `
  --output-dir "$B/nsx-lm3_avs_ips/capture/$SH" --no-flat-exports
# switch .env to lm3 credentials
Step6b --phase d2a --no-capture
Step6b --phase d2a --apply
Step6b --phase d3
Step6b --phase d3 --apply
Step6b --phase d3 --verify
```

Rollback for either: `--phase d3 --rollback --apply`, then
`--phase d2a --rollback --apply`, with the target's credentials.

---

## Full rollback order

Newest first: 6b, 6a, 5, 4, 3, 2.

## Palo Alto track (separate)

Mirrors NSX exactly (see [STATUS.md](STATUS.md) for the mapping). Never commits.

```powershell
# P1 plan: reads NSX only. Drop --groups to mirror every non-system group.
python tools/pan/nsx_pan_mirror.py plan --source nsx-lm1 `
  --groups seed-tag-net-10-6-0,ip-address-group,seed-nested-web
$P = (Get-ChildItem "pan_mirror_runs/nsx-lm1.lab.local" -Directory | Where-Object Name -match '^\d{8}_\d{6}$' | Sort-Object Name | Select-Object -Last 1).FullName
Get-Content "$P/plan.md"

# P2 push: dry run, then apply to candidate config (logs in as agent_user)
python tools/pan/nsx_pan_mirror.py push --plan "$P/plan.json" --no-tls-verify
python tools/pan/nsx_pan_mirror.py push --plan "$P/plan.json" --no-tls-verify --apply

# Undo exactly what that apply created
$M = (Get-ChildItem "$P/push_*_apply.json" | Sort-Object Name | Select-Object -Last 1).FullName
python tools/pan/nsx_pan_mirror.py revert --manifest $M --no-tls-verify
python tools/pan/nsx_pan_mirror.py revert --manifest $M --no-tls-verify --apply
```

The run folder is found by name rather than through `latest`, because Windows
often cannot create that symlink. Status: P1 and P2 working (REST API only); first
live push 2026-10-05 created 24 objects in dg-5.
