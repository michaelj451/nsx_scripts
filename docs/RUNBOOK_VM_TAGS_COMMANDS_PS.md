# Runbook VM Tags - Commands (Windows PowerShell)

Compact command reference for the hostname-tagging workflow. Adds a
`scope=hostname` tag to every VM whose display name ends in 3-6 trailing
digits. Additive-only, never removes existing tags. Full narrative
lives in [RUNBOOK_VM_TAGS.md](RUNBOOK_VM_TAGS.md). Bash variant with
the same commands: [RUNBOOK_VM_TAGS_COMMANDS.md](RUNBOOK_VM_TAGS_COMMANDS.md).

Line continuation in PowerShell is the backtick `` ` `` at end of line.

---

## Step 0: Env setup (once per PowerShell session)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

Assumes `.env` is populated with NSX credentials and manager aliases.

---

## Step 1: Pre-change dry-run + classification (single command)

Read-only against NSX. Classifies every VM into eligible / skip_edge /
skip_other_type / skip_has_tag / skip_invalid_name / skip_too_many_tags.
Writes plan files under `nsx_vm_files\vm_tags_plan\<host>\<UTC_TS>\`.

```powershell
python tools/reports/dryrun_hostname_tags.py `
  --manager nsx-lm1 `
  --output-dir nsx_logs\reports\vm_tags_plan\nsx-lm1.lab.local `
  --overwrite
```

Discover the latest plan dir:

```powershell
$plan = (Get-ChildItem "nsx_logs\reports\vm_tags_plan\nsx-lm1.lab.local" -Directory `
         | Sort-Object Name -Descending | Select-Object -First 1).FullName
Write-Host "Plan: $plan"
```

Inspect what will be tagged:

```powershell
Get-Content "$plan\eligible.json" | ConvertFrom-Json | Select-Object -ExpandProperty vms `
  | Format-Table display_name, proposed_hostname_tag, existing_tag_count
```

Inspect what was skipped and why:

```powershell
foreach ($f in "skip_has_tag","skip_invalid_name","skip_edge","skip_other_type","skip_too_many_tags") {
    $j = Get-Content "$plan\$f.json" | ConvertFrom-Json
    Write-Host ("{0,-30} {1,3} VM(s)" -f $f, $j.count)
}
```

---

## Step 2a: (Optional alternative to Step 1) Export VM state

If you want to keep the raw NSX VM export separate from the plan:

```powershell
python tools/vm_tags/export_vm_tags.py `
  --manager nsx-lm1 `
  --base-dir nsx_vm_files\vm_tags_export
```

## Step 2b: (Optional alternative to Step 1) Build plan from export

```powershell
python tools/vm_tags/build_hostname_tag_plan.py `
  --vm-export nsx_vm_files\vm_tags_export\nsx-lm1.lab.local\vms.json `
  --output-dir nsx_logs\reports\vm_tags_plan\nsx-lm1.lab.local `
  --overwrite
```

---

## Step 3: Push - dry-run

Loads the plan, re-queries live NSX to catch races (new tags added
between plan and push), reports what WOULD be applied. No writes.

```powershell
python tools/reports/push_hostname_tags.py `
  --manager nsx-lm1 `
  --plan-dir $plan
```

---

## Step 4: Push - apply

Actually writes the hostname tag to each eligible VM. Existing tags
are always preserved (additive-only).

**Default behavior (interactive step-through, safest):**

```powershell
python tools/reports/push_hostname_tags.py `
  --manager nsx-lm1 `
  --plan-dir $plan `
  --apply
```

When `--apply` is set and `--batch-size` is not specified, the tool
auto-defaults to `--batch-size 1` and prompts after every apply. You
log-line confirmation:

```
Auto-defaulting --batch-size to 1 (step-through is safer for --apply).
Pass --batch-size 0 to disable prompts, or --batch-size N to start at N.
```

At each prompt the operator can:

| Response | Effect |
|---|---|
| `y` / `Y` / `<Enter>` | Continue at current batch size |
| `n` / `no` | Continue but reset batch size to 1 (paranoid mode) |
| `<positive number>` | Change batch size mid-run (e.g., `5` or `25` to ramp up) |
| `x` / `exit` / `quit` | Stop cleanly, write manifest of what was applied |

**Start at a higher batch size:**

```powershell
python tools/reports/push_hostname_tags.py `
  --manager nsx-lm1 `
  --plan-dir $plan `
  --apply --batch-size 5
```

**Fully-automated mode (no prompts, for CI or trusted bulk runs):**

```powershell
python tools/reports/push_hostname_tags.py `
  --manager nsx-lm1 `
  --plan-dir $plan `
  --apply --batch-size 0
```

Non-interactive stdin (piped input, cron) auto-approves each boundary
and logs a warning. Batch size only counts successful applies. Skips
(NOOP, RACE, MISSING) don't consume the batch slot.

---

## Step 5: Validate live NSX state

Reads live tag state and confirms every eligible VM in the plan now
has its proposed hostname tag.

```powershell
python tools/vm_tags/validate_hostname_tags.py `
  --manager nsx-lm1 `
  --plan-dir $plan
```

Success looks like `"match": <N>, "mismatch_wrong_value": 0, "missing_hostname_tag": 0`.

---

## Step 6: Revert - dry-run

Uses the push manifest (not the plan) to know exactly which
(external_id, hostname_tag_value) pairs to remove. Existing non-hostname
tags are always preserved.

Discover the latest apply manifest:

```powershell
$manifest = (Get-ChildItem "nsx_logs\reports\vm_tags_push\nsx-lm1.lab.local\*_apply.json" `
             | Sort-Object Name -Descending | Select-Object -First 1).FullName
Write-Host "Manifest: $manifest"

python tools/reports/revert_hostname_tags.py `
  --manager nsx-lm1 `
  --manifest $manifest
```

## Step 7: Revert - apply

**Default behavior (interactive step-through, safest):**

```powershell
python tools/reports/revert_hostname_tags.py `
  --manager nsx-lm1 `
  --manifest $manifest `
  --apply
```

Same `--batch-size` semantics as Step 4. When `--apply` is set and
`--batch-size` is not specified, auto-defaults to 1 (prompt after
each revert). At each prompt:

| Response | Effect |
|---|---|
| `y` / `Y` / `<Enter>` | Continue at current batch size |
| `n` / `no` | Continue but reset batch size to 1 |
| `<positive number>` | Change batch size mid-run |
| `x` / `exit` / `quit` | Stop cleanly, write audit manifest |

**Start at higher batch or ramp:**

```powershell
python tools/reports/revert_hostname_tags.py `
  --manager nsx-lm1 `
  --manifest $manifest `
  --apply --batch-size 5
```

**Fully-automated (no prompts):**

```powershell
python tools/reports/revert_hostname_tags.py `
  --manager nsx-lm1 `
  --manifest $manifest `
  --apply --batch-size 0
```

Only the hostname tags added by that specific push are removed. Any
other tags on those VMs (whether pre-existing or applied by other
runs) stay intact. Batch counter only advances on successful reverts;
`[GUARD]`, `[NOOP]`, `[MISSING]` skips don't consume a slot.

---

## Output locations at a glance

All report bundles now land under `$env:NSX_LOG_DIR\reports\` (default:
`nsx_logs\reports\`) with layout `<type>\<host>\<UTC_TS>\`.

| Tool | Location | Where output lands |
|---|---|---|
| `dryrun_hostname_tags.py` | `tools\reports\` | `nsx_logs\reports\vm_tags_plan\<host>\<UTC_TS>\` (contains `plan.md` + `plan.json` + per-bucket `.json`) |
| `push_hostname_tags.py` | `tools\reports\` | `nsx_logs\reports\vm_tags_push\<host>\<UTC_TS>_apply.json` + `.md` (or `_dryrun.*`) |
| `revert_hostname_tags.py` | `tools\reports\` | `nsx_logs\reports\vm_tags_revert\<host>\<UTC_TS>_revert_apply.json` (or `_dryrun.json`) |
| `report_rules_usage.py` | `tools\reports\` | `nsx_logs\reports\rules_usage\<host>\<UTC_TS>\` |
| `report_groups_usage.py` | `tools\reports\` | `nsx_logs\reports\groups_usage\<host>\<UTC_TS>\` |
| `build_hostname_tag_plan.py` | `tools\vm_tags\` | `nsx_vm_files\vm_tags_plan\<host>\<UTC_TS>\` (offline planner) |
| `export_vm_tags.py` | `tools\vm_tags\` | `nsx_vm_files\vm_tags_export\<host>\vms.json` |
| `validate_hostname_tags.py` | `tools\vm_tags\` | `nsx_vm_files\vm_tags_validation\<UTC_TS>_<alias>\validation_report.json` |
| Per-run log files (for tools in `tools\reports\`) | | `$env:NSX_LOG_DIR\vm_tags_<tool>_<UTC_TS>.log` |

---

## Safety refresher

- **Never removes existing tags.** Push and revert are strictly scoped
  to the `scope=hostname` tag they were asked to add.
- **Plan-time skip** for VMs with an existing hostname tag
  (`skip_has_tag`) means re-runs are safe.
- **Push-time re-check** catches races: if a hostname tag appeared
  between plan and push, that VM lands in
  `skipped_already_has_hostname_post_plan` and gets zero writes.
- **Idempotent no-op** if the exact `(hostname, value)` pair already
  exists (`skipped_already_has_exact_tag`).
- **Push cap defense** refuses to push to any VM already at
  `VM_TAGS_MAX_TAGS_PER_VM` (default 30).
- **Only `type=REGULAR` VMs are eligible.** All Edge, VC_SYSTEM, NSX
  Manager, and other VM types are structurally excluded from tagging
  (default-deny via `VM_TAGS_SUPPORTED_TYPES` env var).

---

## See also

- [RUNBOOK_VM_TAGS.md](RUNBOOK_VM_TAGS.md) - full narrative + rationale
- [RUNBOOK_VM_TAGS_COMMANDS.md](RUNBOOK_VM_TAGS_COMMANDS.md) - bash variant of this file
