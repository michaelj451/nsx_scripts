# Runbook — Single-capture clone + WF-D (Windows PowerShell)

PowerShell variant of [RUNBOOK_FROM_CAPTURE.md](RUNBOOK_FROM_CAPTURE.md).
See that file for narrative + lab validation details.

## Env

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
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

## 3. WF-A clone → target (Parts 1 + 2 + 3)

### Part 1 — services + groups (strip) + policies + rules

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

### Part 2 — segment paths → CIDRs

```powershell
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_groups_export/$SRC_HOST/groups `
  --segments-mode convert `
  --segments-from nsx_capture/$SRC_HOST/segment_inventory/segment_details.json `
  --apply
```

### Part 3 — additive VM IPs

```powershell
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_capture/$SRC_HOST/groups_additive/domains/default/groups `
  --segments-mode convert `
  --segments-from nsx_capture/$SRC_HOST/segment_inventory/segment_details.json `
  --apply
```

---

## 4. WF-D — build mapped-IP siblings (offline)

```powershell
python tools/nsx/build_sibling_groups.py `
  --source $SRC `
  --csv-remap data/nonprod_map.csv `
  --include-pure-ip `
  --skip-segment-groups `
  --no-stripped-originals `
  --label $SRC_HOST
```

Outputs at `nsx_sibling_groups\$SRC_HOST\` with `sibling_map.json` and
`reports\skipped_segments.json` / `reports\empty_groups.json`.

To label by the **target** manager instead:

```powershell
python tools/nsx/build_sibling_groups.py `
  --source $SRC `
  --csv-remap data/nonprod_map.csv `
  --include-pure-ip --skip-segment-groups --no-stripped-originals `
  --label "$DST.lab.local"
```

---

## 5. WF-D — push siblings to target

### 5a. Dry-run

```powershell
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_sibling_groups/$SRC_HOST/groups
```

Confirm `mode: DRY-RUN`, `additive_only_contract: pass`,
`total_ips_removed: 0`, `contract_violations: 0`.

### 5b. Apply

```powershell
python tools/nsx/groups.py push --target $DST `
  --groups-dir nsx_sibling_groups/$SRC_HOST/groups --apply
```

---

## 6. (optional, separate change window) Rule amendment

```powershell
python tools/nsx/rules.py amend-refs --target $DST `
  --sibling-map nsx_sibling_groups/$SRC_HOST/sibling_map.json
# dry-run, then:
python tools/nsx/rules.py amend-refs --target $DST `
  --sibling-map nsx_sibling_groups/$SRC_HOST/sibling_map.json --apply
```

Add `--include-scope` to also amend the rule's `scope` field.

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
