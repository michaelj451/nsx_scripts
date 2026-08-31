# Runbook INFO GATHER : read-only pre-change evidence : Windows PowerShell

Five read-only reports collected into one session directory you can review
or hand over, every one at `$G/<manager-host>/<report>/<ts>/` so LM and GM
runs sit side by side under their own hostnames. Nothing here writes to
NSX. Every step has a **Local Manager**
block and a **Global Manager (federation)** block; run whichever applies, or
both. Where DFW policy is GM-owned, the LM blocks show only the default rules
and zero customer groups, and the GM blocks carry the real answer.

| Step | Report | Tool | LM | GM |
|---|---|---|---|---|
| 1 | VM rule membership: every DFW rule touching the VMs in your list | `tools/reports/report_vms_in_rules.py` | yes | yes (GM only, no LM access needed) |
| 2 | Group membership: every customer group, its type, and evaluated VM members | `tools/reports/report_groups_usage.py` | yes | yes |
| 3 | Rule hit counts, last 30 days: HOT / USED / STALE / UNUSED / DORMANT plus the 30-day window | `tools/reports/report_rules_usage.py` | yes | yes |
| 4 | Hostname tag dry run: who would be tagged, who is skipped and why | `tools/reports/dryrun_hostname_tags.py` | yes | no (VM inventory is LM-only; run per site LM) |
| 5 | IP remap dry run: what the CSV remap would add, already-remapped pairs, gaps | `capture_nsx_state.py` + `groups.py push` (dry-run) | yes | yes |

Bash/macOS variant: [RUNBOOK_INFO_GATHER.md](RUNBOOK_INFO_GATHER.md).
Background: [RUNBOOK_VM_RULE_MEMBERSHIP.md](RUNBOOK_VM_RULE_MEMBERSHIP.md),
[RUNBOOK_REPORTS.md](RUNBOOK_REPORTS.md), [RUNBOOK_RULES_USAGE.md](RUNBOOK_RULES_USAGE.md),
[RUNBOOK_VM_TAGS.md](RUNBOOK_VM_TAGS.md), [RUNBOOK_B.md](RUNBOOK_B.md).

## 0) Env

Set the variables once per session; every command below follows them.
`$M`/`$H` are the Local Manager alias (from `.env`) and its hostname;
`$GM`/`$GH` the same for the Global Manager; `$G` the session directory;
`$T` the VM target list; `$CSV` the subnet map. Capture bundles are keyed by
hostname, which is why `$H` and `$GH` exist.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"

$M = "nsx-lm1"
$H = "nsx-lm1.lab.local"
$GM = "nsx-gm1"
$GH = "nsx-gm1.lab.local"
$G = "nsx_info_$M"
$T = "vm_rule_report_targets.txt"
$CSV = "data/nonprod_map.csv"
New-Item -ItemType Directory -Force -Path $G | Out-Null
```

The target list is one VM display name per line, optionally `name,ip`
(explicit IPs are matched against group IP sets too). Blank lines and `#`
comments are ignored.

---

## 1) VM rule membership report

Local Manager:

```powershell
python tools/reports/report_vms_in_rules.py `
  --manager $M `
  --vm-list $T `
  --output-base $G `
  --overwrite
```

Global Manager (talks to the GM only; membership is proxied per site):

```powershell
python tools/reports/report_vms_in_rules.py `
  --manager $GM `
  --federation-global `
  --vm-list $T `
  --output-base $G `
  --overwrite
```

Review: `$G/<host>/vm_rule_membership/<ts>/report.md` (matched VMs with Site column on the
GM run, then rules per VM with how each hit: Src / Dst / Scope) and
`report.json`. Add `--members-cache-minutes 30` when iterating on the target
list; add `--with-vm-inventory` to the GM run to enrich with fabric VM IPs
when the site LMs are reachable.

---

## 2) Group membership report

Local Manager:

```powershell
python tools/reports/report_groups_usage.py `
  --target $M `
  --output-base $G
```

Global Manager (all domains, members aggregated per site):

```powershell
python tools/reports/report_groups_usage.py `
  --target $GM `
  --federation-global `
  --all-domains `
  --output-base $G
```

Review: `$G/<host>/group_membership/<ts>/report.md`, plus `groups_usage.jsonl`
(one row per group: type TAG / IP / SEGMENT / VM_PATH / NESTED, member
count, members), `tag_based_groups.jsonl`, and `empty_groups.jsonl`.

---

## 3) Rule hit counts, last 30 days

Local Manager:

```powershell
python tools/reports/report_rules_usage.py `
  --target $M `
  --hits-in-last-days 30 `
  --output-base $G
```

Global Manager (all domains, full federation walk):

```powershell
python tools/reports/report_rules_usage.py `
  --target $GM `
  --federation-global `
  --all-domains `
  --hits-in-last-days 30 `
  --output-base $G
```

Review: `$G/<host>/rules_usage/<ts>/report.md` classifies every
rule HOT / USED / STALE / UNUSED / DORMANT with its hit count;
`hits_in_last_n_days.jsonl` is the 30-day window; `hot_rules.jsonl`,
`stale_rules.jsonl`, `unused_rules.jsonl`, `dormant_rules.jsonl` are the
per-class lists.

NSX exposes cumulative hit counts, not timestamps, so the 30-day window is
computed from this tool's own snapshot history: the first run records the
baseline and the window fills in as scheduled runs accumulate (daily is
plenty). Keep `--history-dir` at its default so every run lands in the same
history.

---

## 4) Hostname tag dry run (Local Manager only)

```powershell
python tools/reports/dryrun_hostname_tags.py `
  --manager $M `
  --output-base $G `
  --overwrite
```

Review: `$G/<host>/hostname_tags_dryrun/<ts>/plan.md` plus one JSON per classification
(`eligible`, `skip_has_tag`, `skip_excluded`, `skip_length_out_of_range`,
`skip_invalid_name`, `skip_edge`, `skip_other_type`). Nothing is tagged. The
exclusion list is `hostname_tag_exclude.txt` at the repo root unless
`--exclude-file` overrides it. A Global Manager has no VM inventory: in a
federated environment run this once per site LM.

---

## 5) IP remap dry run

Fresh capture first so the bundle matches the manager, then the dry run.

Local Manager:

```powershell
python tools/nsx/capture_nsx_state.py --source $M

python tools/nsx/groups.py push `
  --target $M `
  --groups-dir nsx_capture/$H/groups_additive/domains/default/groups `
  --csv-remap $CSV `
  --reports-dir $G/$H/ip_remap_dryrun
```

Global Manager:

```powershell
python tools/nsx/capture_nsx_state.py --source $GM --federation-global

python tools/nsx/groups.py push `
  --target $GM `
  --federation-global `
  --groups-dir nsx_capture/$GH/groups_additive/domains/default/groups `
  --csv-remap $CSV `
  --reports-dir $G/$GH/ip_remap_dryrun
```

Review: `$G/<host>/ip_remap_dryrun/remap_report.md`: the Result line, section 1 "Would
add" (value, source original, CSV row), section 2 already-remapped pairs,
then generic-group candidates, never-remapped ranges/IPv6, and CSV coverage
misses. `summary.json` must show `csv_invalid_rows: []`.

Optional reconciliation of the live manager against the CSV (read-only, exit
code 1 when gaps exist):

```powershell
python tools/nsx/audit_ip_remap.py --target $M --csv $CSV --output-base $G
python tools/nsx/audit_ip_remap.py --target $GM --federation-global --csv $CSV --output-base $G
```

---

## 6) Package the evidence

```powershell
Get-ChildItem -Recurse $G -Include report.md, remap_report.md, plan.md, ip_remap_audit.md | Select-Object FullName
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
Compress-Archive -Path $G -DestinationPath "$G-$stamp.zip" -Force
```

Everything under `$G` is regenerable: re-run any step to refresh it.

---

## Safety characteristics

| Step | Touches NSX? | Rate |
|---|---|---|
| 1 to 5, audit | GET only | client default 2 req/s (`NSX_API_MAX_RPS` in `.env` to change) |

No `--apply` appears anywhere in this runbook.
