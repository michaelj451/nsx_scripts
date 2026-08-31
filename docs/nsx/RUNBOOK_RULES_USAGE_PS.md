# Runbook — Rules Usage Report (Windows PowerShell)

Operational guide for `tools/reports/report_rules_usage.py` — a **read-only**
report that snapshots per-rule traffic counters from any NSX manager (LM or
GM), classifies each rule (HOT / USED / STALE / UNUSED / DORMANT), and —
given a snapshot history — surfaces rules that haven't matched traffic in
N days.

Bash/macOS variant with full narrative + caveats: [RUNBOOK_RULES_USAGE.md](RUNBOOK_RULES_USAGE.md).

> **Read-only against NSX, enforced two ways.**
>
> 1. **Source-level:** only `list_*` and `get_*` methods on `NsxPolicyClient` are called.
> 2. **Runtime guard:** the client instance is monkey-patched at startup so that
>    `_post`, `_put`, `_patch`, `_delete` raise `ReadOnlyViolationError` before
>    any HTTP request is dispatched. The log line `Read-only lockdown engaged on
>    NsxPolicyClient instance` appears on every run.
>
> Safe to run against production at any time, including during change windows.
> Line continuation in PowerShell is the backtick `` ` `` at end of line.

---

## What it answers

| Question | How |
|---|---|
| What rules exist on this manager, and what's their classification? | Single snapshot — see `summary.json` + `rules_usage.json` |
| Which rules carry the most traffic? | `hot_rules.json` (top-N by hit_count) |
| Which rules have never been hit? | `unused_rules.json` (UNUSED + DORMANT) |
| Which rules used to enforce but no longer do? | `stale_rules.json` (had hits, none in `--stale-days`) |
| Which rules haven't been hit in the past N days (e.g., year)? | `--min-days-since-hit 365` → `no_hits_in_n_days.json` |
| Did anything change between two snapshots? | `--compare-to <prior>` → `diff.json` |
| What's the picture across the full federation, not just Global? | `--all-domains` on a GM target |

---

## Conventions used (same as the rest of the toolkit)

| Convention | Value |
|---|---|
| Target selection | `--target nsx-lm1` (aliases from `app\nsx\nsx_constants.py`) |
| Federation Global Manager | add `--federation-global` (for nsx-gm1 / nsx-gm2) |
| Multi-domain (GM federation) | add `--all-domains` to walk every domain in one run |
| Log directory | `$env:NSX_LOG_DIR` from `.env` |
| Report location | `$env:NSX_LOG_DIR\rules_usage_report\<host>\<UTC_TS>\` |
| Auth + session | Reuses `NsxPolicyClient` — same `.env` credentials as every other tool |
| Domain | `--domain-id default` (override only if your NSX uses a non-default domain; ignored under `--all-domains`) |

Read-only — no `--apply` flag, no `--dry-run` flag, no revert workflow.
Every run is independent and idempotent.

---

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

---

## 1. One-shot snapshot — single LM

```powershell
python tools/reports/report_rules_usage.py --target nsx-lm1
```

Lands at:

```
$env:NSX_LOG_DIR\rules_usage_report\nsx-lm1.lab.local\<UTC_TS>\
├── summary.json
├── rules_usage.json
├── rules_usage.jsonl
├── hot_rules.json
├── unused_rules.json
├── dormant_rules.json
├── stale_rules.json
└── logs\
```

Inspect the headline counters:

```powershell
Get-Content "$env:NSX_LOG_DIR\rules_usage_report\nsx-lm1.lab.local\<UTC_TS>\summary.json"
```

---

## 2. Multi-domain mode (`--all-domains`)

On an **LM** there is only one domain (`default`), so `--all-domains` is a
no-op there — it discovers one domain and walks it.

On a **GM** the federation API exposes a `default` (Global) domain *and* one
domain per federation member (e.g., `nsx-lm1.lab.local`,
`nsx-lm2.lab.local`). Without `--all-domains`, you only see policies under
the one domain named by `--domain-id`. With it, the tool fetches the domain
list and runs the full collection loop against each one, then emits a
single combined report.

### Run against a Global Manager (walks every domain)

```powershell
python tools/reports/report_rules_usage.py --target nsx-gm1 `
  --federation-global `
  --all-domains
```

Each rule record gets a `domain_id` field so you can filter post-run.
`summary.json` adds a `per_domain` breakdown:

```json
{
  "all_domains_mode": true,
  "domains_queried":  ["default", "nsx-lm1.lab.local", "nsx-lm2.lab.local"],
  "per_domain": {
    "default":              {"rules": 12, "HOT": 1, "USED": 8, "STALE": 0, ...},
    "nsx-lm1.lab.local":    {"rules":  5, "HOT": 0, "USED": 3, "STALE": 1, ...},
    "nsx-lm2.lab.local":    {"rules":  4, "HOT": 0, "USED": 2, "STALE": 0, ...}
  }
}
```

### Run against a GM but only one domain

```powershell
python tools/reports/report_rules_usage.py --target nsx-gm1 `
  --federation-global `
  --domain-id nsx-lm1.lab.local
```

---

## 3. Filter — rules with no hits in the past N days

```powershell
python tools/reports/report_rules_usage.py --target nsx-lm1 `
  --min-days-since-hit 365
```

Tune `--stale-days` and `--fresh-days` to change the classification splits:

```powershell
python tools/reports/report_rules_usage.py --target nsx-lm1 `
  --min-days-since-hit 180 --stale-days 180 --fresh-days 14
```

Combine with `--all-domains` to filter across the full federation:

```powershell
python tools/reports/report_rules_usage.py --target nsx-gm1 `
  --federation-global --all-domains `
  --min-days-since-hit 365
```

Additional output:

```
no_hits_in_n_days.json     rules whose hit_count hasn't increased in >= N days
                           (includes DORMANT rules where rule_age_days >= N too)
```

---

## 4. Recurring snapshots (build history for accurate dormancy)

The NSX policy API does **not** return a "last hit time" — only cumulative
counters. To answer "haven't been hit in 365 days" with confidence, the tool
needs a year of snapshots to walk.

**Recommendation: weekly scheduled task.**

```powershell
$action = New-ScheduledTaskAction `
  -Execute "C:\path\to\.venv\Scripts\python.exe" `
  -Argument "tools\reports\report_rules_usage.py --target nsx-lm1" `
  -WorkingDirectory "C:\path\to\nsx_scripts"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am
Register-ScheduledTask -TaskName "NSX-RulesUsage-lm1" `
  -Action $action -Trigger $trigger
```

History grows in place — each weekly run lands a new timestamped subdirectory
under `$env:NSX_LOG_DIR\rules_usage_report\nsx-lm1.lab.local\`. The tool
automatically discovers all prior runs in that directory and computes
`days_since_hit_changed` per rule from them.

History keys include `domain_id`, so adding `--all-domains` mid-history-stream
does not collide identically-named rules across domains.

---

## 5. Diff mode — compare two snapshots

```powershell
python tools/reports/report_rules_usage.py --target nsx-lm1 `
  --compare-to "nsx_logs\rules_usage_report\nsx-lm1.lab.local\<prior-UTC_TS>\"
```

Adds `diff.json` with one row per rule:

| Transition | Meaning | What to do |
|---|---|---|
| `unchanged` | hit_count same in both snapshots | Nothing |
| `delta` | hit_count went up (or down) | Normal traffic accumulation |
| `lit_up` | was 0, now > 0 | Rule started matching — confirms enforcement |
| `went_dormant` | was > 0, now 0 | Counter reset OR rule stopped matching — investigate |
| `new_on_target` | rule didn't exist in prior snapshot | Rule was just created |
| `removed_from_target` | rule was in prior, not now | Rule was deleted |

---

## 6. Reading the outputs

### `summary.json` — headline counters + per-domain breakdown

```json
{
  "all_domains_mode": false,
  "domains_queried":  ["default"],
  "federation_global": false,
  "read_only": true,
  "per_domain": { "default": { ... } },
  "counters": {
    "customer_policies":  3,
    "customer_rules":     9,
    "HOT": 0, "USED": 5, "STALE": 0, "UNUSED": 4, "DORMANT": 0,
    "total_hit_count":    234,
    "total_byte_count":   6435724578,
    "total_packet_count": 6519190,
    "rules_filtered_by_min_days_since_hit": null
  }
}
```

### `rules_usage.json` / `rules_usage.jsonl` — full per-rule records

Each entry includes the NSX-side stats, the rule definition, the
history-derived fields, and now `domain_id`. The `.jsonl` form is one rule
per line — usable with PowerShell:

```powershell
# Top 5 rules by byte_count
Get-Content "$env:NSX_LOG_DIR\rules_usage_report\nsx-lm1.lab.local\<UTC_TS>\rules_usage.jsonl" |
  ForEach-Object { ConvertFrom-Json $_ } |
  Sort-Object byte_count -Descending |
  Select-Object -First 5 domain_id,rule_id,byte_count,hit_count

# All STALE rules across every domain
Get-Content "$env:NSX_LOG_DIR\rules_usage_report\nsx-gm1.lab.local\<UTC_TS>\rules_usage.jsonl" |
  ForEach-Object { ConvertFrom-Json $_ } |
  Where-Object { $_.classification -eq "STALE" }

# Per-domain HOT counts (from the federation walk)
(Get-Content "$env:NSX_LOG_DIR\rules_usage_report\nsx-gm1.lab.local\<UTC_TS>\summary.json" |
  ConvertFrom-Json).per_domain.PSObject.Properties |
  ForEach-Object { [PSCustomObject]@{ domain = $_.Name; HOT = $_.Value.HOT } }
```

### Filter files

| File | Contents |
|---|---|
| `hot_rules.json` | Top-N rules by hit_count |
| `unused_rules.json` | Every rule with `hit_count == 0` (UNUSED + DORMANT) |
| `dormant_rules.json` | Never-hit rules older than `--fresh-days` |
| `stale_rules.json` | Rules that had hits but not within `--stale-days` |
| `no_hits_in_n_days.json` | Only with `--min-days-since-hit N` — combined STALE + DORMANT view |
| `diff.json` | Only with `--compare-to` |

---

## 7. Classification thresholds — when to tune them

| Threshold | Default | When to raise | When to lower |
|---|---|---|---|
| `--hot-threshold` | 1000 hits | Quiet environments (lab, dev) where 1000 is noise | Very high-traffic prod where everything is HOT and you want a tighter top-of-list |
| `--fresh-days` | 30 days | If you don't deploy rules often and want stricter "too new to judge" gating | Fast-moving environments where 30 days is too generous |
| `--stale-days` | 365 days | Audit-driven environments (annual cycle) | If you want quarterly visibility into stalling rules |
| `--top-n` | 20 | Lots of rules; want a wider hot list | Tighter focus |

---

## 8. Federation Global Manager — recommended pattern

| Scenario | Command |
|---|---|
| Single-LM enforcement audit | `--target nsx-lm1` |
| All federation enforcement (per-LM) | run separately for each LM and concatenate |
| Global-policy inventory (declarative side) | `--target nsx-gm1 --federation-global --all-domains` |
| GM-side Global domain only | `--target nsx-gm1 --federation-global` (no `--all-domains`) |

**Where stats actually accumulate matters.** GM is the policy declaration layer;
enforcement happens on the LMs. For accurate "is this rule matching traffic"
data, query the **LM that's enforcing**. Use GM mode for global-policy
inventory and federation compliance reporting.

A `--federation-global` run against a GM talks to the GM only: statistics
are requested through the GM per site (`enforcement_point_path`) and the
tool never opens a session to a Local Manager (the closing log line
`Managers contacted:` shows exactly one host). On NSX 3.2.x the GM endpoint
fails with a NullPointerException; affected rules are then classified
`NO_STATS` rather than shown as 0 hits, and the per-LM runs are the source
of hit counts on that version.

---

## 9. Read-only guarantee — what's enforced

| Layer | Behavior |
|---|---|
| Source code | Only `list_*` / `get_*` methods are called |
| NsxPolicyClient instance | `_post`, `_put`, `_patch`, `_delete` patched at startup to raise `ReadOnlyViolationError` |
| HTTP wire | Only `GET` requests dispatched |
| Local filesystem | Writes only under `$env:NSX_LOG_DIR\rules_usage_report\<host>\<UTC_TS>\`; never modifies capture bundles or any other tool's output |

If a future edit (intentional or accidental) attempts a write, you get:

```
ReadOnlyViolationError: report_rules_usage.py is read-only;
  NsxPolicyClient._put() is blocked. Only GET methods (list_*/get_*) are permitted.
```

Confirmed live on all four methods (POST/PUT/PATCH/DELETE) — read methods
unaffected.

---

## 10. Caveats — what affects accuracy

1. **NSX has no native "last hit time" field.** Everything in `days_since_hit_changed` is derived from snapshot history. Accuracy = snapshot frequency. Weekly snapshots → ~7-day accuracy.
2. **Counter resets distort dormancy.** ESXi host reboot, NSX manager upgrade, transport-node re-prep, and section recreate all reset `hit_count` to zero. The tool flags `history_counter_reset_observed=true` when seen so you can disregard those rules' last-change inference.
3. **First-run filters use rule_age_days as a fallback.** Until you have history, `--min-days-since-hit N` only matches rules that have `hit_count=0` AND `rule_age_days >= N`. Active rules with no comparison baseline aren't matched on the first run.
4. **Per-enforcement-point aggregation.** The tool sums counters across all enforcement points in `results[]`. Per-EP detail is available in raw NSX responses if you need it.
5. **Default L2/L3 section rules excluded by default.** Add `--include-defaults` if you actually want them reported.
6. **NSX Intelligence (separate, paid) is better for flow-level analysis.** This tool is the right answer when Intelligence isn't deployed.
7. **GM stats depend on federation sync.** If you're querying a GM's stats and federation sync is degraded, numbers may lag. Query the LMs directly for the freshest data.

---

## 11. Common operational recipes

### Find rules to clean up before a major refactor

```powershell
python tools/reports/report_rules_usage.py --target nsx-lm1 --min-days-since-hit 180
Get-Content "$env:NSX_LOG_DIR\rules_usage_report\nsx-lm1.lab.local\<UTC_TS>\no_hits_in_n_days.json"
```

### Federation-wide dormancy sweep (one command across every domain on the GM)

```powershell
python tools/reports/report_rules_usage.py --target nsx-gm1 `
  --federation-global --all-domains `
  --min-days-since-hit 365
```

### Pre-WF-D scoping — separate hot rules from stale ones for risk-banding

```powershell
Get-Content "$env:NSX_LOG_DIR\rules_usage_report\nsx-lm1.lab.local\<UTC_TS>\rules_usage.jsonl" |
  ForEach-Object { ConvertFrom-Json $_ } |
  Where-Object { $_.classification -in @("HOT","STALE") } |
  Sort-Object classification, @{Expression="hit_count";Descending=$true} |
  Select-Object classification, domain_id, rule_id, hit_count, days_since_hit_changed
```

### Confirm `amend-refs` broadened enforcement (before/after diff)

```powershell
# Before amend-refs
python tools/reports/report_rules_usage.py --target nsx-lm1
$snapBefore = (Get-ChildItem "$env:NSX_LOG_DIR\rules_usage_report\nsx-lm1.lab.local" `
  -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName

# (run amend-refs, let traffic flow for a few hours)

# After
python tools/reports/report_rules_usage.py --target nsx-lm1 --compare-to $snapBefore
$snapAfter = (Get-ChildItem "$env:NSX_LOG_DIR\rules_usage_report\nsx-lm1.lab.local" `
  -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName

(Get-Content "$snapAfter\diff.json" | ConvertFrom-Json).transitions |
  Where-Object { $_.transition -eq "lit_up" }
```

`lit_up` transitions confirm that rules previously matching only via the
original groups are now also matching via the new sibling refs.

### Compare two LMs

```powershell
python tools/reports/report_rules_usage.py --target nsx-lm1
python tools/reports/report_rules_usage.py --target nsx-lm2

$lm1 = Get-Content "$env:NSX_LOG_DIR\rules_usage_report\nsx-lm1.lab.local\<ts>\summary.json" | ConvertFrom-Json
$lm2 = Get-Content "$env:NSX_LOG_DIR\rules_usage_report\nsx-lm2.lab.local\<ts>\summary.json" | ConvertFrom-Json
Compare-Object ($lm1.counters.PSObject.Properties) ($lm2.counters.PSObject.Properties) `
  -Property Name, Value
```

---

## 12. Full flag reference

| Flag | Default | Purpose |
|---|---|---|
| `--target <alias>` | required | NSX manager alias (`nsx-lm1`, `nsx-gm1`, etc.) |
| `--domain-id <id>` | `default` | Single-domain mode. **Ignored under `--all-domains`.** |
| `--all-domains` | off | Discover every domain on the target and walk all of them in one run. Each rule gets a `domain_id`; summary gets `per_domain` breakdown. |
| `--federation-global` | off | Required for `nsx-gm1` / `nsx-gm2` (routes to `/policy/api/v1/global-infra/...`) |
| `--include-defaults` | off | Include `default-layer3-section` + `default-layer2-section` |
| `--hot-threshold <int>` | 1000 | HOT classification cutoff (hit_count >= N) |
| `--fresh-days <int>` | 30 | UNUSED vs DORMANT split for never-hit rules |
| `--stale-days <int>` | 365 | USED vs STALE split — days of inactivity that flip an active rule to STALE |
| `--top-n <int>` | 20 | Rows in `hot_rules.json` |
| `--history-dir <path>` | `$env:NSX_LOG_DIR\rules_usage_report\<host>\` | Override history scan root |
| `--min-days-since-hit <int>` | (off) | Emit `no_hits_in_n_days.json` filter |
| `--compare-to <path>` | (off) | Diff against a prior snapshot directory |
| `--output-base <path>` | `$env:NSX_LOG_DIR` | Override report root (testing) |
