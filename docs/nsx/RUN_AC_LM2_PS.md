# Run card: Workflows A and C onto `nsx-lm2.lab.local` (PowerShell)

Clone the customer DFW config from `nsx-lm1` to `nsx-lm2` (Workflow A), then
decompose the tag-based groups on the target into IP-only siblings (Workflow C).
Both run through the driver, `tools/nsx/run_workflow.py`.

Use **two credential stages**: capture LM1 with its credentials, then manually
change the shared `NSX_USERNAME` / `NSX_PASSWORD` to LM2's credentials. All A/C
driver commands after that use saved source files and contact only LM2,
including verification. No second set of credential variables is needed.

Bash variant: [RUN_AC_LM2.md](RUN_AC_LM2.md). Concepts:
[RUNBOOK_A.md](RUNBOOK_A.md), [RUNBOOK_C.md](RUNBOOK_C.md),
[RUNBOOK_WORKFLOW.md](RUNBOOK_WORKFLOW.md).

> Line continuation in PowerShell is the backtick `` ` `` at end of line, not
> the backslash. Paths use forward slashes throughout; PowerShell and the Python
> tools both accept them on Windows.

## Roles

| Manager | Role | NSX impact |
|---|---|---|
| `nsx-lm1.lab.local` | Source | **Read only.** Never written to by either workflow |
| `nsx-lm2.lab.local` | Target | Services, groups, policies, rules created; then siblings added and originals stripped |

Workflow A pushes services, groups (segment references stripped), policies and
rules. Workflow C then adds one IP-only sibling group per tag-based group,
strips the IPs out of the originals, and amends the rules to reference both.
Run A first. C replaces WF-A Part 2 and Part 3, so do not run those as well.

---

## Before you start

Run these commands from the repository root. Set `NSX_LM1` and `NSX_LM2` in
`.env` to the correct managers and keep those addresses unchanged when switching
credentials. Back up and inspect LM2 after the credential switch below.

---

## 0) Env

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH  = "$PWD\app"
$env:NSX_LOG_DIR = "$PWD\nsx_logs"

$S  = "nsx-lm1"
$T  = "nsx-lm2"
$SH = "nsx-lm1.lab.local"
$TH = "nsx-lm2.lab.local"
$R  = "nsx_avs_runs/${S}_to_${T}"
New-Item -ItemType Directory -Force -Path $R | Out-Null
```

The Python tools read `.env` themselves, but your **shell** does not, which is
why `NSX_LOG_DIR` is set explicitly: the gate commands below interpolate it.

Define the driver as a **function**, with source, target and run dir filled in.
`@args` forwards whatever you pass through:

```powershell
function wf { python tools/nsx/run_workflow.py --source $S --target $T --run-dir $R @args }
wf --help | Select-Object -First 3
```

> Use a function, not a string variable. `$W = "python tools/nsx/run_workflow.py ..."`
> followed by `& $W --phase a` fails: PowerShell treats the whole string as a
> single command name. The same mistake bites in zsh, which is why both variants
> of this card use a function.

---

## 1) Capture the source (read-only)

Set `NSX_USERNAME` and `NSX_PASSWORD` in `.env` to the **LM1** credentials.
The driver does not capture for A/C: this is the only source-side stage.
If those credentials were previously exported in PowerShell, clear the shell
overrides so each new Python process reads the edited `.env`:

```powershell
Remove-Item Env:NSX_USERNAME, Env:NSX_PASSWORD -ErrorAction SilentlyContinue
```

**`--live-query` is mandatory.** It is what splices each group's effective IPs
into `groups_additive/`, which is the tree Workflow C builds siblings from.
Without it every tag-only group looks empty, you get siblings only for groups
that already held static IPs, and **nothing errors**. Measured on lm1: 1 sibling
without it, 7 with it.

```powershell
python tools/nsx/capture_nsx_state.py --source $S --live-query
if ($LASTEXITCODE -ne 0) { throw "LM1 capture failed; stop here." }
```

This now skips segment inventory, VM-tag export, VM attribution and optional
review reports by default. It keeps the configuration, effective-IP evidence
and flat exports that A/C consume. `vm_ip_index_count: 0` is expected;
the gate checks effective-IP queries instead. Optional collection flags are
listed in [RUNBOOK_WORKFLOW.md](RUNBOOK_WORKFLOW.md#1-capture-read-only-source-side).

### The gate: check all five fields yourself

```powershell
Get-Content "nsx_capture/$SH/groups_additive/domains/default/groups/manifest.json" |
  ConvertFrom-Json |
  Select-Object ip_source, effective_ip_queries, groups_changed, ips_added_total, groups_errors
```

| Field | Required |
|---|---|
| `ip_source` | `'effective'`. Anything else is a stale or legacy bundle |
| `effective_ip_queries` | non-zero and equal to `groups_seen` |
| `groups_changed` | Review against expected source membership; 0 may mean no enrichment was needed |
| `ips_added_total` | Review against expected source membership; 0 may mean IPs were already present |
| `groups_errors` | `0`. Non-zero means groups have not realized yet: wait, re-run |

The driver checks that this capture succeeded, matches the source/domain,
uses effective IPs, has zero group errors and queried effective IPs for every processed group.
Review the change counts yourself against the expected source configuration;
zero additions can also mean those IPs were already present in the export.

### Switch credentials once, then work only against LM2

Manually edit `.env`: replace `NSX_USERNAME` and `NSX_PASSWORD` with the **LM2**
credentials. Keep `NSX_LM1` / `NSX_LM2` unchanged. Clear any shell overrides:

```powershell
Remove-Item Env:NSX_USERNAME, Env:NSX_PASSWORD -ErrorAction SilentlyContinue
```

Each command below starts a new Python process and reads the updated credentials.
Keep `nsx_capture/$SH` and the four `nsx_*_export/$SH` source trees unchanged
through dry run, apply and verification. To refresh LM1 data later, repeat the
source capture with LM1 credentials, switch back to LM2, and review a new dry run.

Back up and inspect the target with its credentials before applying:

```powershell
python tools/nsx/backup_nsx_state.py --source $T --retain 14
if ($LASTEXITCODE -ne 0) { throw "LM2 backup failed; stop here." }
Get-Content "nsx_backup/$TH/latest/summary.txt"
python tools/nsx/list_domains.py $T
```

---

## 2) Workflow A: the clone

Logging is always live; capture has no quiet mode. Each apply step starts at
**one object**, then pauses before writing the next batch. Enter continues;
type `5` or `10` to increase the next batch, `n` to reset to one, or `x` to
stop. The same controls apply to C and rollback. Losing terminal input stops
the run, and dry runs never prompt. API request throttling stays unchanged.

```powershell
# Dry run, then read the report
wf --phase a
Get-Content "$R/report/a/dryrun/avs_run_report.md"

# Apply
wf --phase a --apply

# Verify
wf --phase a --verify
```

### Review gate

| Check | Where |
|---|---|
| Object counts per class match the source | "What changed" table |
| Nothing under `Failed` | "What changed" table |
| No "group references removed" warning block | report body |
| Every IP delta is an addition | "Change detail (audit)" |

In the first table, `Would create` is exact for group rows and a **lower bound**
everywhere else: services, policies and rules do not read the target on a dry
run, so a genuinely new one there counts as no measurable change. The report
says so in its own caveats block.

Dry-run and apply reports are separate paths (`report/a/dryrun/` and
`report/a/apply/`), so neither can overwrite or be mistaken for the other.

---

## 3) Workflow C: sibling decomposition

```powershell
# Dry run, then read the report
wf --phase c
Get-Content "$R/report/c/dryrun/avs_run_report.md"

# Apply
wf --phase c --apply

# Verify
wf --phase c --verify
```

The dry run rebuilds the sibling bundle from the **saved LM1 capture**, without
contacting LM1. The apply never rebuilds, so it pushes the bundle you previewed.

### Review gate

Check the build counters before approving:

```powershell
$m = Get-Content "$R/nsx_sibling_groups/$SH/sibling_map.json" | ConvertFrom-Json
"siblings: $($m.count)  appendix: $($m.appendix)"
$m.map | ForEach-Object { "  {0,-30} {1} ips" -f $_.sibling_id, $_.ips_source.Count }
```

| Check | Requirement |
|---|---|
| `appendix` | `_np_ips`. If it reads `_avs_ips` you are looking at a WF-D bundle |
| `files seen` | equals `siblings written + skipped: no Condition + skipped: empty IPs` |
| `skipped: empty IPs` | `0`. Non-zero means a tag group NSX resolves to nothing, which is also what a capture without `--live-query` produces. Confirm against the manager before continuing |
| every sibling | carries a plausible IP count, never 0 |

The four counters in that table come from the build log, not from
`sibling_map.json`:

```powershell
$blog = Get-ChildItem "$env:NSX_LOG_DIR/build_sibling_groups_*.log" |
  Sort-Object LastWriteTime | Select-Object -Last 1
Select-String -Path $blog -Pattern "files seen|siblings written|stripped originals|skipped: empty IPs|errors  " |
  ForEach-Object { ($_.Line -split "__main__: ")[-1] }
```

---

## 4) Verify

Read-only, both phases. `verify_avs_run.py` runs V1 object parity, V2 siblings
exist, V3 sibling IPs equal the source's **captured** effective IPs, V4 originals stripped,
V5 rules reference original or sibling, V6 membership resolves.
The driver passes `--source-capture` automatically. Only LM2 is queried live;
the report records the source capture path and timestamp. It does not detect
changes on LM1 made after capture.

```powershell
wf --phase a --verify
wf --phase c --verify
Get-Content "$R/report/c/verify/verify_avs_run.json"
```

**V3 is the one that matters most.** It catches a sibling that looks
structurally fine but is quietly missing addresses.

`--phase a --verify` runs V1 and V6 only, even if you already previewed C.
`--phase c --verify` requires C's sibling map and runs the sibling checks too;
run it after applying C.

---

## 5) Rollback

Preview first, always. The dry run takes no `--apply`; add it to execute.

```powershell
# C first
wf --phase c --rollback
wf --phase c --rollback --apply

# then A
wf --phase a --rollback
wf --phase a --rollback --apply
```

**Roll back C before A.** NSX refuses to delete a group while a rule still
references it, so unwinding the clone underneath live siblings fails.

| Phase | Reverts, in order |
|---|---|
| `c` | amend-refs, stripped originals, siblings |
| `a` | rules, policies, groups, services |

The driver passes `--allow-delete` for you, which matters: reverting a push that
*created* groups has to delete them, and without the flag they are left in place,
listed under `deletes_blocked`, while the revert still exits 0. Read the summary,
not the exit code.

---

## Measured baseline, 2026-09-18 dry run

Source `nsx-lm1` holding 13 groups / 5 policies / 15 rules / 4 services, target
`nsx-lm2` empty. Expect this shape, not these exact numbers, once either side
moves.

**Workflow A: 33 objects would be created, 22 IPs added, 0 failed.**

| Class | Count |
|---|---:|
| Services | 4 |
| Groups | 13 |
| Policies | 3 |
| Rules | 13 |

**Workflow C: 14 objects, 30 IPs in siblings, 0 errors.**

| Part | Count | Detail |
|---|---:|---|
| Siblings created (`_np_ips`) | 7 | `network-group-0/1/2/8`, `super-nested-group`, `vm-group-1/2` |
| Stripped originals | 7 | same seven groups, IPAddressExpression entries removed |

The 7 siblings match the figure the runbook records for a correct
`--live-query` capture on this source. One sibling would mean the capture was
wrong.

---

## Pasting traps

**Do not paste bash blocks into PowerShell.** A `\` continuation makes
PowerShell swallow the next line as a separate command, and `export VAR=...` is
not a PowerShell statement. If `python` reports `ModuleNotFoundError: nsx`,
`$env:PYTHONPATH` was never set for this session.

**The `wf` function is per-session.** Open a new tab or window and it is gone;
re-run the env block before the phase commands.

---

## If something goes wrong

Roll back as in section 5. If the baselines are gone, restore `nsx-lm2` from the
bundle taken in the preconditions and follow
[EMERGENCY_RESTORE_PS.md](EMERGENCY_RESTORE_PS.md). Read its rules caveat first:
backup bundles do not carry `_parent_policy_id`, so restoring rules straight from
one lands them in a policy that does not exist. The fix is in that doc.

## Copy/paste: two-stage A then C dry runs (PowerShell on macOS or Windows)

**Stage 1: pull LM1.** Open the `nsx_scripts` folder. Set `.env`'s
`NSX_USERNAME` / `NSX_PASSWORD` to **LM1** credentials, then run:

```powershell
$Python = if (Test-Path ".venv/Scripts/python.exe") {
    ".venv/Scripts/python.exe"
} else {
    ".venv/bin/python"
}

$env:PYTHONPATH = Join-Path $PWD "app"
$Stamp = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmss")
$R = "nsx_avs_runs/lm1_to_lm2_$Stamp"

Remove-Item Env:NSX_USERNAME, Env:NSX_PASSWORD -ErrorAction SilentlyContinue
& $Python tools/nsx/capture_nsx_state.py --source nsx-lm1 --live-query
if ($LASTEXITCODE -ne 0) { throw "LM1 capture failed; stop here." }
```

**Manual switch:** change only `NSX_USERNAME` and `NSX_PASSWORD` in `.env` to
**LM2** credentials. Keep the same PowerShell session and manager addresses.

**Stage 2: preview A, then C using the saved LM1 files.**

```powershell
Remove-Item Env:NSX_USERNAME, Env:NSX_PASSWORD -ErrorAction SilentlyContinue

function wf {
    & $Python tools/nsx/run_workflow.py `
        --source nsx-lm1 `
        --target nsx-lm2 `
        --run-dir $R @args
}

wf --phase a

if ($LASTEXITCODE -eq 0) {
    wf --phase c
}
```

This previews **LM1 → LM2**, running C only if A succeeds. **No NSX configuration changes are applied.**
A/C no longer capture automatically, so `--no-capture` is unnecessary. Normal
logs remain visible. Both dry runs use LM2 credentials and the saved LM1 capture.

Reports:

```powershell
"$R/report/a/dryrun/avs_run_report.md"
"$R/report/c/dryrun/avs_run_report.md"
```

C previews amendments to rules **currently on LM2**; it cannot preview amendments to rules that an unapplied A would create.

For the actual push, remain on LM2 credentials: back up LM2, review A's preview,
run `wf --phase a --apply`, then `wf --phase a --verify`. Next run a fresh
`wf --phase c` against the cloned LM2 rules, review it, run
`wf --phase c --apply`, then `wf --phase c --verify`. Stop on any non-zero exit.
