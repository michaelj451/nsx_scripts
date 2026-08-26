# NSX Toolkit - PowerShell Quick Reference

Compact command reference for the three most-used NSX workflows on
Windows. For narrative, safety properties, and full flag tables see the
per-workflow runbooks linked below each section.

Every push tool starts as **dry-run**. Add `--apply` only after the
dry-run summary looks right.

Line continuation in PowerShell is the backtick at end of line.

---

## Setup (once per PowerShell session)

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\app"
```

Assumes `.env` is populated with NSX credentials and manager aliases
(same file the rest of the toolkit uses).

---

## a. Duplicate Infrastructure rules from nsx-lm1 to nsx-lm3

Read-only capture of lm1, offline filter to the `Infrastructure`
category (with all transitively-referenced groups + services), then
apply the filtered bundle to lm3.

```powershell
# 1. Capture lm1 (read-only against source)
python tools/nsx/capture_nsx_state.py --source nsx-lm1

# 2. Filter to Infrastructure category (offline, writes new bundle)
python tools/nsx/filter_policy_bundle.py `
  --source nsx-lm1 `
  --categories Infrastructure

# 3. Discover the newly-written bundle
$bundle = (Get-ChildItem "nsx_filtered_bundle\*\nsx-lm1.lab.local" -Directory `
           | Sort-Object Name -Descending | Select-Object -First 1).FullName

# 4. Push chain to lm3 (dry-run each stage first)
python tools/nsx/services.py push --target nsx-lm3 `
  --services-dir "$bundle\services\services"
python tools/nsx/groups.py push --target nsx-lm3 `
  --groups-dir "$bundle\groups\groups" `
  --segments-mode strip
python tools/nsx/policies.py push --target nsx-lm3 `
  --policies-dir "$bundle\policies\security-policies"
python tools/nsx/rules.py push --target nsx-lm3 `
  --rules-dir "$bundle\rules\security-policies"

# 5. Re-run each with --apply once the dry-run looks clean
python tools/nsx/services.py push --target nsx-lm3 `
  --services-dir "$bundle\services\services" --apply
python tools/nsx/groups.py push --target nsx-lm3 `
  --groups-dir "$bundle\groups\groups" `
  --segments-mode strip --apply
python tools/nsx/policies.py push --target nsx-lm3 `
  --policies-dir "$bundle\policies\security-policies" --apply
python tools/nsx/rules.py push --target nsx-lm3 `
  --rules-dir "$bundle\rules\security-policies" --apply
```

Full detail: [RUNBOOK_FILTER_COPY_PS.md](RUNBOOK_FILTER_COPY_PS.md).

---

## b. Duplicate Application rules with hits from nsx-lm1 to nsx-lm4 (VDI Ctrix)

Live-query lm1 rule statistics, keep only Application-category rules
with `hit_count > 0`, re-parent them under a single new policy called
`vdi-ctrix` on lm4. Duplicated groups and services carry original names
because lm4 is the empty sandbox.

```powershell
# 1. Capture lm1 (read-only - filter step needs the flat exports on disk)
python tools/nsx/capture_nsx_state.py --source nsx-lm1

# 2. Consolidate hot rules into a single new policy
python tools/nsx/consolidate_hot_rules.py `
  --source nsx-lm1 `
  --categories Application `
  --min-hits 0 `
  --new-policy-id vdi-ctrix `
  --new-policy-display "VDI Ctrix" `
  --new-policy-category Application

# 3. Discover the bundle
$bundle = (Get-ChildItem "nsx_filtered_bundle\*\nsx-lm1.lab.local" -Directory `
           | Sort-Object Name -Descending | Select-Object -First 1).FullName

# 4. Dry-run push chain
python tools/nsx/services.py push --target nsx-lm4 `
  --services-dir "$bundle\services\services"
python tools/nsx/groups.py push --target nsx-lm4 `
  --groups-dir "$bundle\groups\groups" `
  --segments-mode strip
python tools/nsx/policies.py push --target nsx-lm4 `
  --policies-dir "$bundle\policies\security-policies"
python tools/nsx/rules.py push --target nsx-lm4 `
  --rules-dir "$bundle\rules\security-policies"

# 5. Apply
python tools/nsx/services.py push --target nsx-lm4 `
  --services-dir "$bundle\services\services" --apply
python tools/nsx/groups.py push --target nsx-lm4 `
  --groups-dir "$bundle\groups\groups" `
  --segments-mode strip --apply
python tools/nsx/policies.py push --target nsx-lm4 `
  --policies-dir "$bundle\policies\security-policies" --apply
python tools/nsx/rules.py push --target nsx-lm4 `
  --rules-dir "$bundle\rules\security-policies" --apply

# 6. Verify manifest (what got kept vs skipped, per-rule hits)
Get-Content "$bundle\manifest.json" | ConvertFrom-Json | Select-Object -ExpandProperty kept_rules `
  | Format-Table sequence, orig_id, orig_policy, hit_count
```

### Common tweaks

| To do this | Add this flag |
|---|---|
| Include `default-layer3-section` rules (16M+ hits from the L3 default drop) | `--include-default-sections` |
| Raise the hit-count threshold to say 100 | `--min-hits 100` |
| Also include Infrastructure rules | `--categories Application,Infrastructure` |
| Use a different consolidated-policy id or display | `--new-policy-id my-policy --new-policy-display "My Policy"` |

Full detail: [RUNBOOK_FILTER_COPY_PS.md](RUNBOOK_FILTER_COPY_PS.md) (same push chain, this workflow is a variant of the filter-copy pattern).

---

## c. Run the rules-usage report

Read-only live query. Every rule classified as HOT / USED / STALE /
UNUSED / DORMANT with hit / byte / packet / session counters, then
written to a bundle with a Markdown summary you can open directly.

```powershell
# Simplest: single-LM run
python tools/reports/report_rules_usage.py --target nsx-lm1

# Include L2/L3 default sections (surfaces catch-all rules like the L3 default DROP)
python tools/reports/report_rules_usage.py --target nsx-lm1 --include-defaults

# GM run with federation domain walk (per-DG breakdown appears in summary.json)
python tools/reports/report_rules_usage.py --target nsx-gm1 --federation-global --all-domains

# Compare against a prior snapshot to see hit-count deltas
$prior = "$env:NSX_LOG_DIR\rules_usage_report\nsx-lm1.lab.local\<prior-UTC-TS>"
python tools/reports/report_rules_usage.py --target nsx-lm1 --compare-to $prior

# Only include rules with no hits in the past 365 days (cleanup candidates)
python tools/reports/report_rules_usage.py --target nsx-lm1 --min-days-since-hit 365
```

### View the results

```powershell
# Latest bundle for lm1
$latest = (Get-ChildItem "$env:NSX_LOG_DIR\rules_usage_report\nsx-lm1.lab.local" -Directory `
           | Sort-Object Name -Descending | Select-Object -First 1).FullName

# Human-readable Markdown summary (this is the one you probably want)
Get-Content "$latest\report.md"

# Structured summary
Get-Content "$latest\summary.json" | ConvertFrom-Json | Format-List

# Full per-rule detail
Get-Content "$latest\rules_usage.json" | ConvertFrom-Json | `
  Select-Object -ExpandProperty rules | `
  Sort-Object hit_count -Descending | `
  Select-Object policy_id, rule_display, classification, hit_count, byte_count -First 20 | `
  Format-Table

# Only the HOT rules
Get-Content "$latest\hot_rules.jsonl" | ForEach-Object { ConvertFrom-Json $_ } | `
  Format-Table policy_id, rule_display, hit_count, byte_count

# DORMANT rules (candidates for cleanup)
Get-Content "$latest\dormant_rules.jsonl" | ForEach-Object { ConvertFrom-Json $_ } | `
  Format-Table policy_id, rule_display, rule_age_days
```

Full detail: [RUNBOOK_RULES_USAGE_PS.md](RUNBOOK_RULES_USAGE_PS.md).

---

## Bundle locations at a glance

| Tool | Where output lands |
|---|---|
| `capture_nsx_state.py` | `nsx_capture\<host>\` and `nsx_{policies,rules,groups,services}_export\<host>\` |
| `filter_policy_bundle.py` | `nsx_filtered_bundle\<UTC_TS>\<host>\` |
| `consolidate_hot_rules.py` | `nsx_filtered_bundle\<UTC_TS>\<host>\` (same layout as filter, ready for push chain) |
| `report_rules_usage.py` | `$env:NSX_LOG_DIR\rules_usage_report\<host>\<UTC_TS>\` |
| Any push tool | Adds `push_report\baselines\<UTC_TS>_target_baseline.json` under its input dir |

---

## Safety refresher

- Every push tool is dry-run by default. `--apply` is required to write.
- Every push captures a pre-write baseline for LIFO revert.
- Source managers are never written to.
- `wipe_target_manager.py` also dry-runs by default (see [RUNBOOK_FILTER_COPY_PS.md](RUNBOOK_FILTER_COPY_PS.md) for wipe usage).

## See also

- [RUNBOOK_A_COMMANDS_PS.md](RUNBOOK_A_COMMANDS_PS.md) - full-manager clone (Workflow A)
- [RUNBOOK_B_COMMANDS_PS.md](RUNBOOK_B_COMMANDS_PS.md) - CSV subnet remap in place
- [RUNBOOK_C_COMMANDS_PS.md](RUNBOOK_C_COMMANDS_PS.md) - lab sibling-group decomposition
- [RUNBOOK_D_COMMANDS_PS.md](RUNBOOK_D_COMMANDS_PS.md) - production in-place sibling remap
- [RUNBOOK_FILTER_COPY_PS.md](RUNBOOK_FILTER_COPY_PS.md) - selective category copy (this workflow)
- [RUNBOOK_RULES_USAGE_PS.md](RUNBOOK_RULES_USAGE_PS.md) - rules-usage report deep dive
