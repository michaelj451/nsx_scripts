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

The explicit `--ip-report-csv` above opts into the IP report. Without it, review
reports are off by default. Segment inventory, VM tags and VM attribution are
also skipped unless requested. Add `--live-query` for effective IPs used by C/D.

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

Capture with `--live-query --with-segments` using the source credentials before
this alternative path. Segment details are no longer collected by default.

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

## 4. WF-D: build mapped-IP siblings (offline)

```powershell
python tools/nsx/build_sibling_groups.py `
  --source $SRC `
  --csv-remap data/nonprod_map.csv `
  --skip-segment-groups `
  --label $SRC_HOST
```

> Every group that is not segment-based and has at least one IP with a CSV
> mapping gets a sibling holding only the mapped IPs: tag-based, IP-only, or
> nesting other groups by path. Originals are never modified. Hand-typed IPs
> are not copied; they stay on the original, which every rule keeps
> referencing.

Outputs:
- `nsx_sibling_groups\$SRC_HOST\groups\`: IP-only siblings carrying the
  CSV-mapped IPs
- `nsx_sibling_groups\$SRC_HOST\sibling_map.json`: per-row audit, plus
  `no_sibling` listing every group without a sibling and why
- `reports\skipped_segments.json` / `reports\empty_groups.json`

No `nsx_pure_ip_remap\` bundle is produced any more; an old one is left in
place and nothing reads it.

---

## 5. WF-D — push to target

### 5a. Siblings (required) — dry-run + apply

```powershell
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_sibling_groups/$SRC_HOST/groups
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_sibling_groups/$SRC_HOST/groups --apply
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
The apply adds only siblings already on the target; missing ones are skipped
and listed in `amend_refs_summary.json` as `siblings_not_on_target`. The dry
run flags them, which is normal before step 5a has been applied.

---

## 6.5 (recommended after step 6) Validate the additive contracts

```powershell
python tools/nsx/validate_wf_d.py `
  --target $DST `
  --baseline nsx_sibling_groups/$SRC_HOST/push_report/baselines/<ts>_target_baseline.json `
  --sibling-map nsx_sibling_groups/$SRC_HOST/sibling_map.json
```

Read-only. Runs G1/G2/G3/S1/S2/R1 checks. Exit 0 = PASS, 1 = FAIL.
for R2 rule-preservation check. See [RUNBOOK_FROM_CAPTURE.md](RUNBOOK_FROM_CAPTURE.md)
for full check descriptions.

---

## Revert

### Revert rule amendment first (if step 6 was applied)

```powershell
python tools/nsx/rules.py revert --target $DST `
  --reports-dir nsx_rules_export/$DST.lab.local/push_report --apply
```

### Revert WF-D siblings (single step)

```powershell
python tools/nsx/groups.py revert --target $DST `
  --reports-dir nsx_sibling_groups/$SRC_HOST/push_report --apply
```

Run it after the rule amendment revert: NSX refuses to delete a group a
rule still references.

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
