# Runbook — Clone Commands (PowerShell)

Bare commands only. See `RUNBOOK_CLONE.md` for explanations.

> `--source` / `--target` are `.env` aliases. Examples assume source = `nsx-lm1` and target = `nsx-lm2`.
> Paths use forward slashes — PowerShell accepts both `/` and `\` for filesystem paths.

## Env

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\app"
```

---

## EXPORT — source-side, read-only (run once)

```sh
# Source: nsx-lm1 -> https://nsx-lm1.lab.local
python tools/nsx/capture_nsx_state.py --source nsx-lm1
python tools/nsx/services.py    export --source nsx-lm1
python tools/nsx/groups.py      export --source nsx-lm1
python tools/nsx/policies.py    export --source nsx-lm1
python tools/nsx/rules.py       export --source nsx-lm1
python tools/nsx/segments.py    export --source nsx-lm1
python tools/nsx/membership.py  export --source nsx-lm1
```

---

## PUSH — target-side

> All pushes default to **dry-run**. Add `--apply` to actually write. Baselines for revert are captured automatically.

### Part 1 — 1-for-1 clone with segments stripped

```sh
# Target: nsx-lm2 -> https://nsx-lm2.lab.local

python tools/nsx/services.py push `
  --target nsx-lm2 `
  --services-dir nsx_services_export/nsx-lm1.lab.local/services `
  --apply

python tools/nsx/groups.py push `
  --target nsx-lm2 `
  --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups `
  --segments-mode strip `
  --apply

python tools/nsx/policies.py push `
  --target nsx-lm2 `
  --policies-dir nsx_policies_export/nsx-lm1.lab.local/security-policies `
  --apply

python tools/nsx/rules.py push `
  --target nsx-lm2 `
  --rules-dir nsx_rules_export/nsx-lm1.lab.local/security-policies `
  --apply
```

### Part 2 — replace segment refs with segment CIDRs

```sh
python tools/nsx/groups.py push `
  --target nsx-lm2 `
  --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups `
  --segments-mode convert `
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json `
  --apply
```

### Part 3 — add live VM IPs to dynamic groups

```sh
python tools/nsx/groups.py push `
  --target nsx-lm2 `
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups `
  --segments-mode convert `
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json `
  --apply
```

---

## REVERT — reverse dependency order

Each `revert` pops the most recent unreverted baseline for that tool's reports_dir.

```sh
# Target: nsx-lm2 -> https://nsx-lm2.lab.local

# 1. rules
python tools/nsx/rules.py revert --target nsx-lm2 `
  --reports-dir nsx_rules_export/nsx-lm1.lab.local/push_report `
  --apply

# 2. policies
python tools/nsx/policies.py revert --target nsx-lm2 `
  --reports-dir nsx_policies_export/nsx-lm1.lab.local/push_report `
  --apply

# 3. groups Part 3 (additive baseline)
python tools/nsx/groups.py revert --target nsx-lm2 `
  --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report `
  --apply

# 4. groups Part 2 (pops the convert baseline from the export reports stack)
python tools/nsx/groups.py revert --target nsx-lm2 `
  --reports-dir nsx_groups_export/nsx-lm1.lab.local/push_report `
  --apply

# 5. groups Part 1 (pops the strip baseline -- captured empty target, so deletes all groups)
python tools/nsx/groups.py revert --target nsx-lm2 `
  --reports-dir nsx_groups_export/nsx-lm1.lab.local/push_report `
  --apply

# 6. services
python tools/nsx/services.py revert --target nsx-lm2 `
  --reports-dir nsx_services_export/nsx-lm1.lab.local/push_report `
  --apply
```

---

## SEGMENTS — optional, push only when target has matching transport zones

```sh
python tools/nsx/segments.py push `
  --target nsx-lm2 `
  --segments-dir nsx_segments_export/nsx-lm1.lab.local/segments `
  --apply

# Revert if needed
python tools/nsx/segments.py revert --target nsx-lm2 `
  --reports-dir nsx_segments_export/nsx-lm1.lab.local/push_report `
  --apply
```
