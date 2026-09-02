# Runbook: hostname tagging, plan to apply : Windows PowerShell

Operational path for applying VM hostname tags: take the plan directory a
read-only dry run already produced, push it, verify it, revert it if needed.
Variable-driven throughout, and it documents the crash-resume behaviour that
`push_hostname_tags.py` has but no runbook covered.

Bash/macOS variant with the same content:
[RUNBOOK_HOSTNAME_TAGGING.md](RUNBOOK_HOSTNAME_TAGGING.md).

Line continuation in PowerShell is the backtick `` ` `` at end of line.

Related docs, and what each is for:

| Doc | Use it for |
|---|---|
| [RUNBOOK_VM_TAGS.md](RUNBOOK_VM_TAGS.md) | Classification rules (what makes a VM eligible) and the long-form narrative |
| [RUNBOOK_INFO_GATHER_PS.md](RUNBOOK_INFO_GATHER_PS.md) | Step 4 produces the plan this runbook consumes, as part of a read-only evidence pack |
| **This doc** | Getting that plan applied safely, including resume after a crash |

---

## Safety properties

| Property | Behaviour |
|---|---|
| Default mode | `push` and `revert` are **dry-run unless `--apply`** is passed. Both. |
| Plan source | The same `eligible.json` a dry run wrote. `dryrun_hostname_tags.py` imports `classify_vm` from `build_hostname_tag_plan.py`, so the preview and the apply cannot disagree. |
| Write shape | Read-modify-write per VM. Push re-reads live tags first and **adds** the hostname tag; existing tags are preserved. |
| Tag cap guard | A VM whose live tag count has reached `VM_TAGS_MAX_TAGS_PER_VM` (default 30) since the plan was built is refused, not truncated. |
| Crash durability | Every VM decision is appended to a checkpoint and **flushed + fsynced**, so it survives a hard kill. |
| Resume | `--resume` skips work already done, but **re-verifies each VM against live NSX first** rather than trusting the file. |
| Wrong-plan guard | Resume validates manager host, plan dir, and a SHA256 of the plan. Mismatch stops the run unless `--force-plan-mismatch`. |
| Revert | Driven by the manifest the apply wrote, with its own `--resume` and `--force-manifest-mismatch`. |

---

## 0) Variables

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"

$M = "nsx-lm2"                  # manager alias from .env
$H = "nsx-lm2.lab.local"        # its hostname; plan dirs are keyed by hostname
$G = "nsx_info_tagging"         # session dir

# The tools read these from .env; your shell does not have them, so mirror
# them here for the lookups below. Match whatever .env says.
$LOGS    = "$PWD\nsx_logs"      # NSX_LOG_DIR    : push manifests + checkpoints
$VMFILES = "$PWD\nsx_vm_files"  # NSX_VM_LOG_DIR : validation reports
```

Hostname tagging is **Local Manager only**. A Global Manager has no VM
inventory; in a federation run this once per site LM.

---

## 1) Plan

Either reuse the plan from an evidence-pack run, or make a fresh one. Both
write the same directory shape.

Fresh:

```powershell
python tools\reports\dryrun_hostname_tags.py `
  --manager $M `
  --output-base $G `
  --overwrite
```

Then pin the newest plan directory rather than typing a timestamp:

```powershell
if (-not $G -or -not $H) {
    throw "`$G and `$H are not set. Run the step 0 variables block first."
}
$base = Join-Path (Join-Path $G $H) 'hostname_tags_dryrun'
if (-not (Test-Path -LiteralPath $base)) {
    throw "No dry-run output under '$base'. Run step 1 first."
}
$dirs = @(Get-ChildItem -LiteralPath $base -Directory | Sort-Object Name -Descending)
if ($dirs.Count -eq 0) { throw "No timestamped plan directory under '$base'." }
$PLAN = $dirs[0].FullName
if (-not (Test-Path -LiteralPath (Join-Path $PLAN 'eligible.json'))) {
    throw "'$PLAN' has no eligible.json, so it is not a valid --plan-dir."
}
$PLAN
```

> **Why the guards.** The obvious one-liner
> `$PLAN = (Get-ChildItem ... | Select-Object -First 1).FullName`
> fails **silently**: when the pipeline matches nothing, `.FullName` on `$null`
> returns empty rather than erroring, so `$PLAN` ends up blank with no message
> and the next command runs with no `--plan-dir` value. The usual cause is
> `$G`/`$H` not being set, since PowerShell variables do not survive a new
> session. The block above fails loudly instead, and confirms `eligible.json`
> is present in the same step.

---

## 2) Read the plan before pushing

```powershell
Get-Content "$PLAN\plan.md" -TotalCount 30
(Get-Content "$PLAN\eligible.json" | ConvertFrom-Json).count
```

`plan.md` carries the classification counts. Check two things:

- **`eligible`** is the set that will actually be written.
- **flagged for review** is where the classifier was not confident. Read those
  before applying, not after.

The skip buckets each have their own file (`skip_has_tag.json`,
`skip_excluded.json`, `skip_length_out_of_range.json`, `skip_invalid_name.json`,
`skip_edge.json`, `skip_other_type.json`, `skip_too_many_tags.json`) so you can
see exactly why any VM was left out:

```powershell
Get-ChildItem "$PLAN\skip_*.json" | ForEach-Object {
  "{0,-34} {1}" -f $_.Name, (Get-Content $_.FullName | ConvertFrom-Json).count
}
```

---

## 3) Push, dry-run

No `--apply`, so nothing is written:

```powershell
python tools\vm_tags\push_hostname_tags.py `
  --manager $M `
  --plan-dir $PLAN
```

This still contacts NSX read-only to compare the plan against live tags, so it
surfaces drift since the plan was built.

---

## 4) Push, apply

```powershell
python tools\vm_tags\push_hostname_tags.py `
  --manager $M `
  --plan-dir $PLAN `
  --apply
```

With `--apply` and no `--batch-size`, batch size defaults to **1**: it prompts
after every VM. At each prompt: `Y`/Enter continue, `n` reset to 1, `x` exit,
or a number to change the batch size. Pass `--batch-size 0` to disable prompts
for an unattended run.

Because prompts are on by default, **do not run this as a background job**
unless you pass `--batch-size 0`.

---

## 5) If it dies, resume where it stopped

Push appends every VM decision to a checkpoint and flushes plus fsyncs it, so
a hard kill loses nothing. Both live under:

```
$LOGS\reports\vm_tags_push\$H\
    <RUN_TS>_apply.progress.jsonl     incremental, while running
    <RUN_TS>_apply.done.jsonl         renamed on clean completion
    <RUN_TS>_apply.json               the manifest revert consumes
```

The rename matters: a `.progress.jsonl` still present means that run did not
finish. Find the newest interrupted one and resume it:

```powershell
$CP = (Get-ChildItem "$LOGS\reports\vm_tags_push\$H\*_apply.progress.jsonl" `
         -ErrorAction SilentlyContinue |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$CP

python tools\vm_tags\push_hostname_tags.py `
  --manager $M `
  --plan-dir $PLAN `
  --apply `
  --resume $CP
```

Resume does not blindly trust the checkpoint. It logs
`RESUME: N VM(s) already recorded as success ... Will verify each is still
tagged in live NSX before skipping`, so a tag removed between the crash and
the resume is re-applied rather than silently skipped.

It also refuses to resume onto different inputs: manager host, plan directory,
and a SHA256 of the plan must all match. If you rebuilt the plan, that guard
fires. Prefer resuming against the original plan; `--force-plan-mismatch`
exists but means you are applying a checkpoint to a plan it was not made from.

---

## 6) Validate, after the apply

This is a **post-push** check: for every eligible VM, does live NSX now carry
the expected hostname tag? Running it before the apply reports everything as
missing, which is correct but useless.

```powershell
python tools\vm_tags\validate_hostname_tags.py `
  --manager $M `
  --plan-dir $PLAN
```

Buckets: `match`, `mismatch_wrong_value`, `missing_hostname_tag`,
`missing_on_target`. A healthy result is everything in `match` and the rest
empty.

Report: `$VMFILES\vm_tags_validation\<TS>_<manager>\validation_report.json` and
`.md`

> Note: [RUNBOOK_VM_TAGS.md](RUNBOOK_VM_TAGS.md) section 5 states this lands
> under `nsx_logs\`. That is wrong. `validate_hostname_tags.py` builds the
> path from `nsx_vm_log_dir` (`NSX_VM_LOG_DIR`, i.e. `nsx_vm_files\`).

---

## 7) Revert

Revert is driven by the manifest the apply wrote, not by the plan, so it undoes
exactly what that run added.

```powershell
$MAN = (Get-ChildItem "$LOGS\reports\vm_tags_push\$H\*_apply.json" |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$MAN

# dry-run first (default)
python tools\vm_tags\revert_hostname_tags.py --manager $M --manifest $MAN

# then apply
python tools\vm_tags\revert_hostname_tags.py --manager $M --manifest $MAN --apply
```

**Revert is dry-run by default too.** Forgetting its `--apply` during an
incident is the common trap: it prints what it would undo and exits 0 having
changed nothing.

Revert has the same `--resume` and a `--force-manifest-mismatch` guard.

---

## 8) Caveats

| Caveat | Detail |
|---|---|
| LM only | A Global Manager has no fabric VM inventory. Run per site LM in a federation. |
| Plan is a snapshot | Push re-reads live tags and refuses VMs at the tag cap, but a plan built long before the change window can list VMs that no longer exist. Re-run step 1 if the gap is large. |
| Additive only | Push adds a hostname tag; it does not remove or rewrite existing tags. Changing an existing hostname tag means revert then re-push. |
| Prompts by default | `--apply` implies `--batch-size 1`. Unattended runs need `--batch-size 0`. |
| Interrupted run leaves a `.progress.jsonl` | That is the resume input, not an error. It is renamed to `.done.jsonl` only on clean completion. |
