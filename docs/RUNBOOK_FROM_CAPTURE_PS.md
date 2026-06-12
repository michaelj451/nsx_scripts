# Runbook — Single-capture clone + WF-D (Windows PowerShell)

PowerShell variant of [RUNBOOK_FROM_CAPTURE.md](RUNBOOK_FROM_CAPTURE.md).
See that file for narrative + lab validation details.

## Env

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"

# Aliases used throughout:
$SRC = "nsx-lm1"        # the production source
$DST = "nsx-lm2"        # the target you are pushing to (test/lab manager)
$SRC_HOST = "nsx-lm1.lab.local"
```

---

## 1. Capture (read-only, all-in-one)

```powershell
python tools/nsx/capture_nsx_state.py --source $SRC `
  --ip-report-csv data/nonprod_map.csv
```

Produces in one command:
- `nsx_capture\$SRC_HOST\` — full capture bundle
- `nsx_groups_export\$SRC_HOST\groups\`
- `nsx_services_export\$SRC_HOST\services\`
- `nsx_policies_export\$SRC_HOST\security-policies\`
- `nsx_rules_export\$SRC_HOST\security-policies\` (with `_parent_policy_id` injected)
- `$env:NSX_LOG_DIR\groups_ip_report\$SRC_HOST\` — IP-coverage report

To skip the flat-exports step:

```powershell
python tools/nsx/capture_nsx_state.py --source $SRC `
  --ip-report-csv data/nonprod_map.csv `
  --no-flat-exports
```

---

## 2. Review IP coverage

```powershell
Get-Content "$env:NSX_LOG_DIR\groups_ip_report\$SRC_HOST\summary.json"
Get-Content "$env:NSX_LOG_DIR\groups_ip_report\$SRC_HOST\empty_groups.json"
```

---

## 3. WF-A clone → target (Part 1 only by default)

### Part 1 — services + groups (strip) + policies + rules

**This is the only WF-A step you should run when WF-D is the goal.**
After Part 1, tag groups on the target are `Condition`-only with zero
IPs — the prerequisite for WF-D to add IP-only siblings alongside.

```powershell
python tools/nsx/services.py push --target $DST `
  --services-dir nsx_services_export/$SRC_HOST/services --apply

python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_groups_export/$SRC_HOST/groups `
  --segments-mode strip --apply

python tools/nsx/policies.py push --target $DST `
  --policies-dir nsx_policies_export/$SRC_HOST/security-policies --apply

python tools/nsx/rules.py push --target $DST `
  --rules-dir nsx_rules_export/$SRC_HOST/security-policies --apply
```

**STOP here and proceed to step 4 (WF-D build).** See the bash variant
([RUNBOOK_FROM_CAPTURE.md](RUNBOOK_FROM_CAPTURE.md)) for the full
explanation of why Parts 2 and 3 are NOT part of the WF-D path.

### ⚠️  Parts 2 + 3 (alternative — NOT compatible with WF-D's goal)

These steps push IPs INTO the tag groups' expression on the target,
producing mixed `Condition + IPAddressExpression` groups — exactly
what WF-D is trying to avoid. Only run them if you want a full
functional clone of the source's mixed state (rare).

```powershell
# Part 2 — segment paths → CIDRs (creates mixed groups, NOT WF-D-friendly)
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_groups_export/$SRC_HOST/groups `
  --segments-mode convert `
  --segments-from nsx_capture/$SRC_HOST/segment_inventory/segment_details.json `
  --apply

# Part 3 — additive VM IPs (worsens the mixing)
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_capture/$SRC_HOST/groups_additive/domains/default/groups `
  --segments-mode convert `
  --segments-from nsx_capture/$SRC_HOST/segment_inventory/segment_details.json `
  --apply
```

---

## 4. WF-D — build mapped-IP siblings + pure-IP remap bundle (offline)

```powershell
python tools/nsx/build_sibling_groups.py `
  --source $SRC `
  --csv-remap data/nonprod_map.csv `
  --skip-segment-groups `
  --no-stripped-originals `
  --label $SRC_HOST
```

> `--include-pure-ip` is **deprecated**. Pure-IP groups are no longer
> decomposed into siblings (that left an empty original after the
> Phase-2 strip). They are written to a separate `nsx_pure_ip_remap\<host>\groups\`
> bundle for in-place CSV-remap push (step 5b).

Outputs:
- `nsx_sibling_groups\$SRC_HOST\groups\` — IP-only siblings for
  tag-based mixed groups only
- `nsx_sibling_groups\$SRC_HOST\sibling_map.json` — per-row audit
- `nsx_pure_ip_remap\$SRC_HOST\groups\` — **NEW** — pure-IP groups
  ready for in-place CSV-remap push
- `reports\skipped_segments.json` / `reports\empty_groups.json`

---

## 5. WF-D — push to target

### 5a. Siblings (required) — dry-run + apply

```powershell
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_sibling_groups/$SRC_HOST/groups
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_sibling_groups/$SRC_HOST/groups --apply
```

### 5b. Pure-IP remap (**OPTIONAL** — separate change window)

> Optional. Skip if your CSV doesn't cover pure-IP groups' IPs, or if
> you want to land siblings first and run the pure-IP remap later.
> Strict-additive: adds mapped IPs alongside existing IPs; removes nothing.

```powershell
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_pure_ip_remap/$SRC_HOST/groups `
  --csv-remap data/nonprod_map.csv
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_pure_ip_remap/$SRC_HOST/groups `
  --csv-remap data/nonprod_map.csv --apply
```

---

## 6. (optional, separate change window) Rule amendment — strict additive, never removes

```powershell
python tools/nsx/rules.py amend-refs --target $DST `
  --sibling-map nsx_sibling_groups/$SRC_HOST/sibling_map.json
# dry-run, then:
python tools/nsx/rules.py amend-refs --target $DST `
  --sibling-map nsx_sibling_groups/$SRC_HOST/sibling_map.json --apply
```

Appends sibling refs to `source_groups` and `destination_groups` of
every rule that references an original. **Never removes any reference
or rule.** Add `--include-scope` to also amend `scope` (default OFF).

---

## 6.5 (recommended after step 6) Validate the additive contracts

```powershell
python tools/nsx/validate_wf_d.py `
  --target $DST `
  --baseline nsx_sibling_groups/$SRC_HOST/push_report/baselines/<ts>_target_baseline.json `
  --sibling-map nsx_sibling_groups/$SRC_HOST/sibling_map.json
```

Read-only. Runs G1/G2/G3/S1/S2/R1 checks. Exit 0 = PASS, 1 = FAIL.
Add `--phase-2-applied` after step 7 has run. Add `--rules-baseline <path>`
for R2 rule-preservation check. See [RUNBOOK_FROM_CAPTURE.md](RUNBOOK_FROM_CAPTURE.md)
for full check descriptions.

---

## 7. (optional, FORCED, separate change window) Phase 2 — move IPs from originals to siblings

> ⚠️  This is the only flow that REMOVES IPs from existing groups.
> Gated behind `--intentional-ip-removal`. Groups themselves are NEVER
> deleted — only their `IPAddressExpression` entries are stripped.
> Group deletion is only possible via `groups.py revert`.

### 7a. Rebuild the bundle WITH stripped originals (omit `--no-stripped-originals`)

```powershell
python tools/nsx/build_sibling_groups.py `
  --source $SRC `
  --csv-remap data/nonprod_map.csv `
  --include-pure-ip `
  --skip-segment-groups `
  --label $SRC_HOST
  # NOTE: --no-stripped-originals deliberately OMITTED so the stripped bundle is produced
```

### 7b. Push the stripped originals — REQUIRES `--intentional-ip-removal`

```powershell
# DRY RUN
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_stripped_groups/$SRC_HOST/groups `
  --intentional-ip-removal

# APPLY
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_stripped_groups/$SRC_HOST/groups `
  --intentional-ip-removal `
  --apply
```

### 7c. Revert Phase 2

```powershell
python tools/nsx/groups.py revert --target $DST `
  --reports-dir nsx_stripped_groups/$SRC_HOST/push_report --apply
```

---

## Revert

### Revert WF-D siblings (single step)

```powershell
python tools/nsx/groups.py revert --target $DST `
  --reports-dir nsx_sibling_groups/$SRC_HOST/push_report --apply
```

### Revert rule amendment (if step 6 was applied)

```powershell
python tools/nsx/rules.py revert --target $DST `
  --reports-dir nsx_rules_export/$DST.lab.local/push_report --apply
```

### Revert the WF-A clone (LIFO, reverse order)

```powershell
python tools/nsx/rules.py revert --target $DST `
  --reports-dir nsx_rules_export/$SRC_HOST/push_report --apply

python tools/nsx/policies.py revert --target $DST `
  --reports-dir nsx_policies_export/$SRC_HOST/push_report --apply

python tools/nsx/groups.py revert --target $DST `
  --reports-dir nsx_capture/$SRC_HOST/groups_additive/domains/default/push_report --apply

python tools/nsx/groups.py revert --target $DST `
  --reports-dir nsx_groups_export/$SRC_HOST/push_report --apply

python tools/nsx/groups.py revert --target $DST `
  --reports-dir nsx_groups_export/$SRC_HOST/push_report --apply

python tools/nsx/services.py revert --target $DST `
  --reports-dir nsx_services_export/$SRC_HOST/push_report --apply
```
