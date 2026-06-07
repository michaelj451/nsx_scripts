# Runbook D — Commands (Windows PowerShell)

Bare commands only, PowerShell variant. See [RUNBOOK_D.md](RUNBOOK_D.md)
for explanations, or [RUNBOOK_D_COMMANDS.md](RUNBOOK_D_COMMANDS.md) for bash.

> **Live production target.** Defaults are designed to never modify
> existing groups on lm1. Each push command starts as a dry-run (no
> `--apply`). Add `--apply` only after diff review.
> Line continuation in PowerShell is the backtick `` ` `` at end of line.

## Env

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\app"
```

---

## 0. Pre-flight (read-only)

### 0a. Fresh capture of lm1 (auto-runs the IP report with CSV coverage)

```powershell
python tools/nsx/capture_nsx_state.py --source nsx-lm1 `
  --ip-report-csv data/nonprod_map.csv
```

Reports land in:
- `nsx_capture\nsx-lm1.lab.local\` (capture bundle)
- `$env:NSX_LOG_DIR\groups_ip_report\nsx-lm1.lab.local\` (IP report)

### 0b. Spot-check IP-report coverage

```powershell
Get-Content "$env:NSX_LOG_DIR\groups_ip_report\nsx-lm1.lab.local\summary.json"
```

Look for:
- `groups_uncovered_by_csv` == 0 (or acceptable to you per group)
- `decomposable_by_wf_c` matches your expected sibling count
- `with_nested_expression` reflects orchestrator-built groups

### 0c. (optional) Source-drift detection on lm1

```powershell
python tools/nsx/compare_group_ips.py `
  --reference nsx_groups_export/nsx-lm1.lab.local/groups `
  --target nsx-lm1
```

Should report 0 drift on a freshly-captured manager.

---

## 1. Build siblings (offline transform)

```powershell
python tools/nsx/build_sibling_groups.py `
  --source nsx-lm1 `
  --csv-remap data/nonprod_map.csv `
  --include-pure-ip `
  --skip-segment-groups `
  --no-stripped-originals
```

Outputs:
- `nsx_sibling_groups\nsx-lm1.lab.local\groups\` — sibling YAMLs (mapped IPs only)
- `nsx_sibling_groups\nsx-lm1.lab.local\sibling_map.json` — audit trail for later amend-refs phase
- `nsx_sibling_groups\nsx-lm1.lab.local\reports\skipped_segments.json` — every group that was skipped because it has a PathExpression
- `nsx_sibling_groups\nsx-lm1.lab.local\reports\empty_groups.json` — every group skipped because it has no IPs to remap
- No `nsx_stripped_groups\...` output (suppressed by `--no-stripped-originals`)

Optional: also skip groups whose IPs are only partially covered by the CSV:

```powershell
python tools/nsx/build_sibling_groups.py `
  --source nsx-lm1 `
  --csv-remap data/nonprod_map.csv `
  --include-pure-ip `
  --skip-segment-groups `
  --no-stripped-originals `
  --skip-uncovered
```

---

## 2. Push siblings to lm1

### 2a. Dry-run (default — no `--apply`)

```powershell
python tools/nsx/groups.py push --target nsx-lm1 `
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups
```

Review the JSON output's `"mode": "DRY_RUN"`, per-file diff, and
`additive_only_contract: "pass"`.

### 2b. Apply (after operator + peer review)

```powershell
python tools/nsx/groups.py push --target nsx-lm1 `
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups `
  --apply
```

Baseline auto-captured at `nsx_sibling_groups\nsx-lm1.lab.local\push_report\baselines\`.

---

## REVERT (single step — deletes the newly-created siblings)

```powershell
python tools/nsx/groups.py revert --target nsx-lm1 `
  --reports-dir nsx_sibling_groups/nsx-lm1.lab.local/push_report `
  --apply
```

Restores lm1 to its exact pre-WF-D state. No originals were touched, so
nothing else needs to roll back.

---

## (Optional, separate change window) Amend rules to reference siblings

Not part of WF-D itself. Run when CAB approves the rule-side activation:

```powershell
python tools/nsx/rules.py amend-refs --target nsx-lm1 `
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json
# review dry-run output, then:
python tools/nsx/rules.py amend-refs --target nsx-lm1 `
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json `
  --apply
```

Default behavior (post-2026-06-03): appends sibling refs to
`source_groups` and `destination_groups` only. Add `--include-scope` if
you also want the rule's `scope` field amended.

### Revert the rule amendment (if needed)

```powershell
python tools/nsx/rules.py revert --target nsx-lm1 `
  --reports-dir nsx_rules_export/nsx-lm1.lab.local/push_report `
  --apply
```
