# Run card: Workflow D in place on `nsx-lm1.lab.local` (PowerShell)

Land IP-only sibling groups on a live manager, with their addresses mapped
through a CSV subnet map, so that tag-based membership can later be replaced by
literal IPs without traffic stopping. Source and target are the same manager.

Bash variant: [RUN_D_LM1.md](RUN_D_LM1.md). Concepts:
[RUNBOOK_D.md](RUNBOOK_D.md). Per-tool PowerShell commands:
[RUNBOOK_D_COMMANDS_PS.md](RUNBOOK_D_COMMANDS_PS.md).

> Line continuation in PowerShell is the backtick `` ` `` at end of line, not
> the backslash. Paths use forward slashes throughout; PowerShell and the Python
> tools both accept them on Windows.

## Change windows

Workflow D is deliberately **one change window per invocation**. There is no
phase that chains them, because each is separately approved, separately
revertible and carries different risk.

| Phase | Does | Required | Removes IPs |
|---|---|---|---|
| `d2a` | Create the `_avs_ips` sibling groups | **yes** | no |
| `d2b` | Add mapped IPs to pure-IP groups in place | no | no |
| `d3` | Amend rules to reference the siblings alongside the originals | no | no |

Only `d2a` is required to call a run "WF-D applied". **No phase removes an
IP.** The tag-side originals keep their addresses and their tag criteria;
the siblings carry the CSV-mapped equivalents alongside them.

---

## Before you start

**1. Back up the manager.** This is an in-place workflow on a live target.

```powershell
python tools/nsx/backup_nsx_state.py --source nsx-lm1 --retain 14
Get-Content nsx_backup/nsx-lm1.lab.local/latest/summary.txt
```

**2. Confirm the sibling suffix.** WF-D's siblings must not share WF-C's.

```powershell
Select-String -Path .env -Pattern '^OBJECT_APPENDIX' | ForEach-Object { $_.Line }
```

Expected: `OBJECT_APPENDIX=_np_ips` (WF-C) and `OBJECT_APPENDIX_AVS=_avs_ips`
(WF-D). WF-C siblings hold the **source** addresses and WF-D siblings hold the
**CSV-mapped** ones. A shared suffix merges mapped addresses into WF-C's
source-IP siblings, silently.

---

## 0) Env

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH  = "$PWD\app"
$env:NSX_LOG_DIR = "$PWD\nsx_logs"

$S   = "nsx-lm1"
$T   = "nsx-lm1"
$SH  = "nsx-lm1.lab.local"
$R   = "nsx_avs_runs/${S}_to_${T}"
$CSV = "data/nonprod_map.csv"
New-Item -ItemType Directory -Force -Path $R | Out-Null

$env:OBJECT_APPENDIX_AVS = ((Select-String -Path .env -Pattern '^OBJECT_APPENDIX_AVS=').Line -split '=',2)[1]
"WF-D sibling suffix: $env:OBJECT_APPENDIX_AVS"
```

That last line must print `_avs_ips` and not an empty string. The Python tools
read `.env` themselves, but your **shell** does not, and the step 5a rebuild
below interpolates the variable. `build_sibling_groups.py` treats an empty
`--appendix` as unset and falls back to `OBJECT_APPENDIX` (`_np_ips`), which is
WF-C's suffix.

`NSX_LOG_DIR` is set for the same reason: the gate commands interpolate it.

Define the driver as a **function**, with source and target both `nsx-lm1`:

```powershell
function wf { python tools/nsx/run_workflow.py --source $S --target $T --run-dir $R @args }
wf --help | Select-Object -First 3
```

The driver warns that source and target match. That is the supported in-place
mode, not a mistake.

> Use a function, not a string variable. `& $W --phase d2a` where `$W` holds the
> command line fails: PowerShell treats the whole string as one command name.

---

## 1) Capture the source (read-only)

Capture logs stream live with no quiet mode. Every apply and rollback starts at
one object; Enter continues, a positive number increases the next batch, `n`
resets to one, and `x` stops. Lost input stops the run. Dry runs never prompt.

**`--live-query` is mandatory.** Without it every tag-only group looks empty, the
build produces siblings only for groups that already held static IPs, and
nothing errors. Measured on lm1: 1 sibling without it, 7 with it.

```powershell
python tools/nsx/capture_nsx_state.py --source $S --live-query --ip-report-csv $CSV
```

### The gate: check all five fields yourself

```powershell
$glog = Get-ChildItem "$env:NSX_LOG_DIR/build_group_ip_additive_from_live_members_*.log" |
  Sort-Object LastWriteTime | Select-Object -Last 1
$line = (Select-String -Path $glog -Pattern "Summary:" | Select-Object -Last 1).Line
foreach ($k in "ip_source","effective_ip_queries","groups_changed","ips_added_total","groups_errors") {
  if ($line -match "${k}.: ([^,}]+)") { "{0,-20} {1}" -f $k, $Matches[1].Trim() }
}
```

| Field | Required |
|---|---|
| `ip_source` | `'effective'` |
| `effective_ip_queries` | non-zero and equal to `groups_seen` |
| `groups_changed` | non-zero |
| `ips_added_total` | non-zero |
| `groups_errors` | `0`. Non-zero means groups have not realized yet: wait, re-run |

The driver checks capture success, source/domain identity, effective IP mode,
zero group errors and a successful effective-IP query for every processed group.
The optional VM index can now be empty. Review the change counts yourself;
zero additions can mean those IPs were already present in the export.
The explicit `--ip-report-csv` above enables the optional coverage report.

Then review what the CSV does and does not cover:

```powershell
Get-Content "$env:NSX_LOG_DIR/groups_ip_report/$SH/summary.json"
Get-Content "$env:NSX_LOG_DIR/groups_ip_report/$SH/empty_groups.json"
```

Optional drift check against the last export:

```powershell
python tools/nsx/compare_group_ips.py `
  --reference "nsx_groups_export/$SH/groups" --target $S
```

---

## 2a) Siblings (mandatory window)

```powershell
# Dry run, then read the report
wf --phase d2a --csv-remap $CSV
Get-Content "$R/report/d2a/dryrun/avs_run_report.md"

# Apply
wf --phase d2a --csv-remap $CSV --apply

# Validate
wf --phase d2a --verify
```

### Review gate

```powershell
$m = Get-Content "$R/nsx_sibling_groups/$SH/sibling_map.json" | ConvertFrom-Json
"siblings: $($m.count)  appendix: $($m.appendix)"
$m.map | ForEach-Object { "  {0,-30} {1} ips" -f $_.sibling_id, $_.ips_source.Count }
```

| Check | Requirement |
|---|---|
| `appendix` | `_avs_ips`. `_np_ips` means the suffix fell back to WF-C's and the run must be rebuilt |
| Every sibling | non-zero IP count |
| "Addresses dropped for having no CSV mapping" | absent. If present, extend the CSV or rebuild with `--skip-uncovered` |
| Manual addresses copied verbatim | expected and listed per group. These are the group's own IPAddressExpression entries, carried across unmapped |
| `Failed` | 0 |

The baseline this apply captures is what the validator reads later:

```
$R/nsx_sibling_groups/nsx-lm1.lab.local/push_report/baselines/<ts>_target_baseline.json
```

Keep it.

---

## 2b) Pure-IP remap (optional, separate window)

Strict-additive: adds mapped IPs alongside existing ones, never removes.

```powershell
wf --phase d2b --csv-remap $CSV
Get-Content "$R/report/d2b/dryrun/avs_run_report.md"
wf --phase d2b --csv-remap $CSV --apply
```

---

## 3) Amend rules (optional, separate window)

Appends sibling references to `source_groups` and `destination_groups`. Strict
additive: a reference is never removed. Add `--include-scope` to the underlying
tool if scope also needs amending.

```powershell
wf --phase d3
Get-Content "$R/report/d3/dryrun/avs_run_report.md"
wf --phase d3 --apply
```

No `--csv-remap` is needed here: `d3` consumes the sibling map `d2a` produced.

---

## 4) Validate

Read-only. Runs G1 nothing deleted, G2 no IP removed, G3 criteria intact, S1/S2
siblings exist and are typed `IPAddress`, R1 amend completeness, R2 rules still
present. Exit `0` is all pass, `1` is at least one CRITICAL finding.

```powershell
wf --phase d2a --verify
```

By hand, if you want the flags explicit:

```powershell
$BASE = (Get-ChildItem -Recurse -Path "$R/nsx_sibling_groups/$SH/push_report/baselines" `
  -Filter "*_target_baseline.json" -ErrorAction SilentlyContinue |
  Sort-Object Name | Select-Object -Last 1).FullName
if (-not $BASE) { throw "no baseline yet: phase d2a has not been applied" }
$BASE

python tools/nsx/validate_wf_d.py --target $S `
  --baseline $BASE `
  --sibling-map "$R/nsx_sibling_groups/$SH/sibling_map.json"
```

Add `--rules-baseline <path>` for the R2 check.

---

## 5) Rollback, reverse order (LIFO)

Preview first, always. Run only the windows you actually applied.

```powershell
# 3: remove sibling refs from rules
wf --phase d3 --rollback
wf --phase d3 --rollback --apply

# 2b: remove mapped IPs from pure-IP groups
wf --phase d2b --rollback
wf --phase d2b --rollback --apply

# 2a: delete the sibling groups
wf --phase d2a --rollback
wf --phase d2a --rollback --apply
```

**Reverse order is not optional.** NSX returns 409 on a DELETE while a rule
still references the group, so removing the siblings before removing their rule
references fails.

---

## Measured baseline, 2026-09-18 dry run

Against `nsx-lm1` holding 13 groups / 5 policies / 15 rules / 4 services, with
`data/nonprod_map.csv`. Expect this shape, not these exact numbers.

| Phase | Objects | IPs | Detail |
|---|---:|---:|---|
| `d2a` | 7 created | +30 | `_avs_ips` siblings for `network-group-0/1/2/8`, `super-nested-group`, `vm-group-1/2`. 3 manually entered addresses copied verbatim |
| `d2b` | 1 changed | +1 | `ip-address-group`; 5 further groups had nothing to add |
| `d3` | 10 changed | n/a | 16 sibling references added across 10 rules |

All four reported `Failed: 0`. The 7 siblings match the figure the runbook
records for a correct `--live-query` capture on this source; 1 sibling would
mean the capture was wrong.

---

## Pasting traps

**Do not paste bash blocks into PowerShell.** A `\` continuation makes
PowerShell swallow the next line as a separate command, and `export VAR=...` is
not a PowerShell statement. If `python` reports `ModuleNotFoundError: nsx`,
`$env:PYTHONPATH` was never set for this session.

**`$BASE`, `$env:OBJECT_APPENDIX_AVS` and the `wf` function are per-session.**
Open a new tab or window and they are gone; re-run the env block first.

---

## If something goes wrong

Roll back as in section 5. If the baselines are gone, restore from the bundle
taken in the preconditions and follow
[EMERGENCY_RESTORE_PS.md](EMERGENCY_RESTORE_PS.md). Read its rules caveat first:
backup bundles do not carry `_parent_policy_id`, so restoring rules straight from
one lands them in a policy that does not exist. That doc has the working recipe.

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

$S   = "nsx-lm1"
$T   = "nsx-lm1"
$SH  = "nsx-lm1.lab.local"
$R   = "nsx_avs_runs/${S}_to_${T}"
$CSV = "data/nonprod_map.csv"
$Appendix = "_avs_ips"
New-Item -ItemType Directory -Force -Path $R | Out-Null

function wf {
    & $Python tools/nsx/run_workflow.py `
        --source $S `
        --target $T `
        --run-dir $R `
        --appendix $Appendix @args
}

wf --phase d2a --csv-remap $CSV

if ($LASTEXITCODE -eq 0) {
    wf --phase d2b --csv-remap $CSV --no-capture
}

if ($LASTEXITCODE -eq 0) {
    wf --phase d3 --no-capture
}
```

This previews **Workflow D in place on LM1**, proceeding only when the previous command succeeds. **No NSX configuration changes are applied.**

- **`d2a`** captures LM1 automatically with `--live-query`, builds the mapped siblings, and previews their creation or update.
- **`d2b`** previews mapped IP additions to pure-IP groups.
- **`d3`** previews sibling-reference additions to the rules currently on LM1.

This block sets the same variables as section 0, including `$SH` and
`$env:NSX_LOG_DIR`, and `$R` is the same stable run directory
(`nsx_avs_runs/nsx-lm1_to_nsx-lm1`). The review gates in sections 1 and 2a
and the rollback commands in section 5 therefore work in this session without
redefining anything. Do not swap `$R` for a timestamped directory: section 5
pops the revert baselines from the run dir, and a per-run name hides them.

All four use the same source capture. The CSV and suffix match this run card: `data/nonprod_map.csv` and `_avs_ips`.

Reports:

```powershell
"$R/report/d2a/dryrun/avs_run_report.md"
"$R/report/d2b/dryrun/avs_run_report.md"
"$R/report/d3/dryrun/avs_run_report.md"
```

Each preview compares against LM1's current live state; preceding dry runs do not change that state. No phase removes an IP, so the tag-side originals keep their addresses throughout.
