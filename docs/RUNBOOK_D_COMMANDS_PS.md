# Runbook D — Commands (Windows PowerShell)

Bare commands only, PowerShell variant. See [RUNBOOK_D.md](RUNBOOK_D.md)
for explanations, or [RUNBOOK_D_COMMANDS.md](RUNBOOK_D_COMMANDS.md) for bash.

> **Live production target.** Each push command starts as a dry-run.
> Add `--apply` only after diff review. Each phase is a separate change
> window; revert in reverse order (Phase 5 → 3 → 2b → 2a).
> Line continuation in PowerShell is the backtick `` ` `` at end of line.

## Env

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

---

## 0. Capture + IP report (read-only)

```powershell
python tools/nsx/capture_nsx_state.py --source nsx-lm1 `
  --ip-report-csv data/nonprod_map.csv
```

Then review:

```powershell
Get-Content "$env:NSX_LOG_DIR\groups_ip_report\nsx-lm1.lab.local\summary.json"
Get-Content "$env:NSX_LOG_DIR\groups_ip_report\nsx-lm1.lab.local\empty_groups.json"
```

(Optional) drift check:

```powershell
python tools/nsx/compare_group_ips.py `
  --reference nsx_groups_export/nsx-lm1.lab.local/groups `
  --target nsx-lm1
```

---

## 1. Build (offline transform)

```powershell
python tools/nsx/build_sibling_groups.py `
  --source nsx-lm1 `
  --csv-remap data/nonprod_map.csv `
  --skip-segment-groups `
  --no-stripped-originals
```

Outputs:
- `nsx_sibling_groups\nsx-lm1.lab.local\groups\` — siblings (for tag+IP mixed groups)
- `nsx_sibling_groups\nsx-lm1.lab.local\sibling_map.json` — audit + input for amend-refs and validator
- `nsx_pure_ip_remap\nsx-lm1.lab.local\groups\` — pure-IP groups (for step 2b)

(Optional) skip any group with even one CSV-uncovered IP:

```powershell
python tools/nsx/build_sibling_groups.py `
  --source nsx-lm1 `
  --csv-remap data/nonprod_map.csv `
  --skip-segment-groups `
  --no-stripped-originals `
  --skip-uncovered
```

---

## 2a. Push siblings (MANDATORY)

```powershell
# Dry-run
python tools/nsx/groups.py push --target nsx-lm1 `
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups

# Apply
python tools/nsx/groups.py push --target nsx-lm1 `
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups `
  --apply
```

Baseline auto-captured at `nsx_sibling_groups\nsx-lm1.lab.local\push_report\baselines\<ts>_target_baseline.json`. Keep that path — step 4 uses it.

---

## 2b. Pure-IP remap (OPTIONAL — separate change window)

```powershell
# Dry-run
python tools/nsx/groups.py push --target nsx-lm1 `
  --groups-dir nsx_pure_ip_remap/nsx-lm1.lab.local/groups `
  --csv-remap data/nonprod_map.csv

# Apply
python tools/nsx/groups.py push --target nsx-lm1 `
  --groups-dir nsx_pure_ip_remap/nsx-lm1.lab.local/groups `
  --csv-remap data/nonprod_map.csv --apply
```

Strict-additive: adds mapped IPs alongside existing IPs; never removes anything.

---

## 3. Amend rules to reference siblings (OPTIONAL — separate change window)

```powershell
# Dry-run
python tools/nsx/rules.py amend-refs --target nsx-lm1 `
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json

# Apply
python tools/nsx/rules.py amend-refs --target nsx-lm1 `
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json `
  --apply
```

Strict-additive — appends sibling refs to `source_groups`/`destination_groups` only. Add `--include-scope` to also amend scope.

---

## 4. Validate (RECOMMENDED after each change window)

```powershell
python tools/nsx/validate_wf_d.py `
  --target nsx-lm1 `
  --baseline nsx_sibling_groups/nsx-lm1.lab.local/push_report/baselines/<ts>_target_baseline.json `
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json
```

Read-only. Runs G1/G2/G3/S1/S2/R1 checks. Exit code: `0` = all pass, `1` = at least one CRITICAL finding. Add `--phase-2-applied` after step 5 has run. Add `--rules-baseline <path>` for the R2 check.

---

## 5. Phase 2 forced strip (OPTIONAL, FORCED — separate change window)

**REMOVES IPs from tag-side originals.** Gated by `--intentional-ip-removal`. Run only after step 2a + 3 are validated and CAB approves the strip.

### 5a. Rebuild bundle WITH stripped originals (omit `--no-stripped-originals`)

```powershell
python tools/nsx/build_sibling_groups.py `
  --source nsx-lm1 `
  --csv-remap data/nonprod_map.csv `
  --skip-segment-groups
```

### 5b. Push stripped originals (force flag required)

```powershell
# Dry-run
python tools/nsx/groups.py push --target nsx-lm1 `
  --groups-dir nsx_stripped_groups/nsx-lm1.lab.local/groups `
  --intentional-ip-removal

# Apply
python tools/nsx/groups.py push --target nsx-lm1 `
  --groups-dir nsx_stripped_groups/nsx-lm1.lab.local/groups `
  --intentional-ip-removal --apply
```

### 5c. Re-validate with Phase-2 awareness

```powershell
python tools/nsx/validate_wf_d.py `
  --target nsx-lm1 `
  --baseline nsx_sibling_groups/nsx-lm1.lab.local/push_report/baselines/<ts>_target_baseline.json `
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json `
  --phase-2-applied
```

---

## REVERT — reverse order (LIFO)

Revert in reverse to avoid dangling rule refs (NSX 409s on DELETE if rules still reference the sibling).

```powershell
# 5 — restore IPs to tag-side originals
python tools/nsx/groups.py revert --target nsx-lm1 `
  --reports-dir nsx_stripped_groups/nsx-lm1.lab.local/push_report --apply

# 3 — remove sibling refs from rules
python tools/nsx/rules.py revert --target nsx-lm1 `
  --reports-dir nsx_rules_export/nsx-lm1.lab.local/push_report --apply

# 2b — remove mapped IPs from pure-IP groups
python tools/nsx/groups.py revert --target nsx-lm1 `
  --reports-dir nsx_pure_ip_remap/nsx-lm1.lab.local/push_report --apply

# 2a — delete the *_sibling groups
python tools/nsx/groups.py revert --target nsx-lm1 `
  --reports-dir nsx_sibling_groups/nsx-lm1.lab.local/push_report --apply
```

Each command pops the most recent unreverted baseline for that stack. Run only the steps you actually applied.
