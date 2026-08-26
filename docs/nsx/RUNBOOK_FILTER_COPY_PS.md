# Runbook - Selective Category Copy (Windows PowerShell)

Copy DFW policies (and only their transitive dependencies) from one NSX
Local Manager to another, filtered by policy category.

Bash/macOS variant with full narrative: [RUNBOOK_FILTER_COPY.md](RUNBOOK_FILTER_COPY.md).

Line continuation in PowerShell is the backtick `` ` `` at end of line.

---

## Overview

Three stages:

1. **Capture** (read-only against source): `capture_nsx_state.py`
2. **Filter** (offline): `filter_policy_bundle.py` keeps only requested categories plus their transitive dependencies
3. **Push** (write to target): four standard push tools consume the filtered bundle

The filter never touches NSX. Reads YAML on disk, writes YAML on disk.

---

## Prerequisites

### Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

---

## Step 1 - Capture the source

```powershell
python tools/nsx/capture_nsx_state.py --source nsx-lm1
```

Produces the four flat-export trees the filter and push tools consume:

```
nsx_capture\nsx-lm1.lab.local\
nsx_policies_export\nsx-lm1.lab.local\security-policies\
nsx_rules_export\nsx-lm1.lab.local\security-policies\
nsx_groups_export\nsx-lm1.lab.local\groups\
nsx_services_export\nsx-lm1.lab.local\services\
```

---

## Step 2 - Filter to the target categories (offline)

```powershell
python tools/nsx/filter_policy_bundle.py `
  --source nsx-lm1 `
  --categories Application
```

Output:

```
nsx_filtered_bundle\<UTC_TS>\nsx-lm1.lab.local\
├── services\services\*.yaml
├── groups\groups\*.yaml
├── policies\security-policies\
├── rules\security-policies\
├── manifest.json
└── logs\
```

### Flag reference

| Flag | Default | Purpose |
|---|---|---|
| `--source <alias>` | required | NSX manager alias whose flat exports to read |
| `--categories <list>` | required | Comma-separated categories to KEEP. Valid: `Ethernet, Emergency, Infrastructure, Environment, Application` |
| `--include-default-sections` | off | Also keep policies with `is_default: true` |
| `--output-base <path>` | `.\nsx_filtered_bundle` | Output root |
| `--source-host-override <host>` | (auto) | Override the resolved hostname |

### Reading the manifest

```powershell
$bundle = (Get-ChildItem "nsx_filtered_bundle\*\nsx-lm1.lab.local" -Directory `
           | Sort-Object Name -Descending | Select-Object -First 1).FullName
$m = Get-Content "$bundle\manifest.json" | ConvertFrom-Json

# Kept policies
$m.kept.policies | Select-Object display_name, category | Format-Table

# Skipped policies
$m.skipped_policies | Select-Object display_name, category, reason | Format-Table

# Unresolved refs (usually built-in NSX services, safe to ignore)
$m.unresolved

# Segments referenced by groups (target must have them, or use --segments-mode strip)
$m.segments_referenced_by_groups

# Counts
$m.counts
```

### Caveats

Same as the bash variant:

1. Unresolved service refs are typically built-in NSX services (HTTP, ICMP-ALL, DHCP-*) that exist on every manager. Not a real problem.
2. Segment paths inside groups won't exist on a fresh target manager. Use `--segments-mode strip` on the groups push (default when there's no matching segment inventory).
3. Filtering is by policy category. Groups shared across categories get included if any kept policy references them.

---

## Step 3 - Push the filtered bundle to the target

Four stages, in order. Each is dry-run by default; add `--apply` to write.

### 3a. Services

```powershell
$bundle = (Get-ChildItem "nsx_filtered_bundle\*\nsx-lm1.lab.local" -Directory `
           | Sort-Object Name -Descending | Select-Object -First 1).FullName

python tools/nsx/services.py push --target nsx-lm4 `
  --services-dir "$bundle\services\services"

python tools/nsx/services.py push --target nsx-lm4 `
  --services-dir "$bundle\services\services" --apply
```

### 3b. Groups

```powershell
python tools/nsx/groups.py push --target nsx-lm4 `
  --groups-dir "$bundle\groups\groups" `
  --segments-mode strip

python tools/nsx/groups.py push --target nsx-lm4 `
  --groups-dir "$bundle\groups\groups" `
  --segments-mode strip --apply
```

`--segments-mode` options: `keep` (leave segment paths as-is), `strip`
(remove them), `convert` (materialize CIDRs from segment_inventory). Fresh
target with no matching segments: use `strip`.

### 3c. Policies

```powershell
python tools/nsx/policies.py push --target nsx-lm4 `
  --policies-dir "$bundle\policies\security-policies"

python tools/nsx/policies.py push --target nsx-lm4 `
  --policies-dir "$bundle\policies\security-policies" --apply
```

### 3d. Rules

```powershell
python tools/nsx/rules.py push --target nsx-lm4 `
  --rules-dir "$bundle\rules\security-policies"

python tools/nsx/rules.py push --target nsx-lm4 `
  --rules-dir "$bundle\rules\security-policies" --apply
```

---

## Step 4 - Verify

```powershell
python tools/nsx/capture_nsx_state.py --source nsx-lm4
python tools/reports/report_rules_usage.py --target nsx-lm4
```

---

## Revert (LIFO order)

```powershell
python tools/nsx/rules.py    revert --target nsx-lm4 `
  --reports-dir "$bundle\rules\push_report" --apply

python tools/nsx/policies.py revert --target nsx-lm4 `
  --reports-dir "$bundle\policies\push_report" --apply

python tools/nsx/groups.py   revert --target nsx-lm4 `
  --reports-dir "$bundle\groups\push_report" --apply

python tools/nsx/services.py revert --target nsx-lm4 `
  --reports-dir "$bundle\services\push_report" --apply
```

---

## Safety properties

| Property | Behavior |
|---|---|
| Source manager | Never written to |
| Filter tool | No network calls at all |
| Push tools | Default dry-run; `--apply` required to write |
| Per-run baseline | Captured before each push, for revert |
| Idempotent push | Handles "already exists" and 412 revision conflicts automatically |

---

## Full flag reference

### `filter_policy_bundle.py`

| Flag | Default | Purpose |
|---|---|---|
| `--source <alias>` | required | NSX manager alias |
| `--categories <list>` | required | Categories to KEEP |
| `--include-default-sections` | off | Include `is_default: true` policies |
| `--output-base <path>` | `.\nsx_filtered_bundle` | Output root |
| `--source-host-override <host>` | (auto) | Override resolved hostname |

For the four push tools, see [RUNBOOK_A_PS.md](RUNBOOK_A_COMMANDS_PS.md).
