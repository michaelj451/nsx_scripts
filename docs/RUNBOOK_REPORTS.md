# Runbook - Reports (macOS / Linux, bash)

Reference for the five report tools under `tools/reports/`. All emit
markdown alongside JSON so results are readable both as raw text and in
a markdown viewer.

Windows PowerShell variant: [RUNBOOK_REPORTS_PS.md](RUNBOOK_REPORTS_PS.md).

---

## What's in `tools/reports/`

| Tool | Read/Write | Purpose |
|---|---|---|
| `report_rules_usage.py` | Read-only | Per-rule hit_count / bytes / packets classification (HOT/USED/UNUSED/DORMANT) + time-window filtering via snapshot history |
| `report_groups_usage.py` | Read-only | Per-group VM member count, tag conditions, segment refs, IP CIDR entries (per-site aggregated for federation) |
| `dryrun_hostname_tags.py` | Read-only | Classify every VM into eligible / skip buckets for hostname-tag workflow. Produces the plan a push would apply. |
| `push_hostname_tags.py` | Writes (with `--apply`) | Apply the hostname-tag plan to VMs. Interactive step-through by default. |
| `revert_hostname_tags.py` | Writes (with `--apply`) | Undo a specific push manifest. Only removes hostname tags this manifest added. |

All output lands under `$NSX_LOG_DIR/reports/` (default `nsx_logs/reports/`).

---

## Step 0: Env setup (once per shell session)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

Assumes `.env` is populated with NSX credentials and manager aliases.

---

## 1. Rules usage report

### Basic

```bash
python tools/reports/report_rules_usage.py --target nsx-lm1
```

### Federation view (GM)

```bash
python tools/reports/report_rules_usage.py --target nsx-gm1 \
  --federation-global --all-domains
```

`--all-domains` iterates every federation domain (default, plus per-site).
`--federation-global` queries the federated ruleset; required when the
target is a GM or when you want the federated view from an LM.

### Time-window filter (positive)

Show rules whose `hit_count` went up within the last N days. Requires
prior snapshots covering the window.

```bash
python tools/reports/report_rules_usage.py --target nsx-gm1 \
  --federation-global --all-domains \
  --hits-in-last-days 7
```

Adds a `Rules with hits in the last 7d` counter to the summary and
emits `hits_in_last_n_days.jsonl` with the matching rows.

### Time-window filter (negative)

Show rules with NO hits in the last N days (cleanup candidates).

```bash
python tools/reports/report_rules_usage.py --target nsx-gm1 \
  --federation-global --all-domains \
  --min-days-since-hit 365
```

Emits `no_hits_in_n_days.jsonl`.

### Diff mode (compare two runs)

```bash
prior=nsx_logs/reports/rules_usage/nsx-gm1.lab.local/20260807_035735
python tools/reports/report_rules_usage.py --target nsx-gm1 \
  --federation-global --all-domains \
  --compare-to "$prior"
```

Emits `diff.json` showing per-rule hit_count deltas, transitions
(unchanged / lit-up / went-dormant / added / removed).

### View the results

```bash
# Latest bundle path
latest=$(ls -1dt nsx_logs/reports/rules_usage/nsx-gm1.lab.local/*/ | head -1)
latest=${latest%/}

# Human-readable markdown
cat "$latest/report.md"
# or open in your default markdown viewer
open "$latest/report.md"

# Structured counters
jq . "$latest/summary.json"

# Top hot rules
cat "$latest/hot_rules.jsonl" | jq -c '{policy: .policy_display, rule: .rule_display, hits: .hit_count, bytes: .byte_count}'
```

### Report sections at a glance

| Section | When shown | Notes |
|---|---|---|
| Summary | Always | Counters + stats source provenance |
| Policy-API stats query errors | When any policy's `/statistics` failed | Fed-GM will always have all 3 here (NSX bug); tool falls back to old firewall API |
| Per-rule breakdown | Always | **Grouped by NSX category** (Ethernet -> Emergency -> Infrastructure -> Environment -> Application), sorted by hit_count DESC within each |
| Top 20 rules | When any rules present | Flat across categories |
| Rules with hits in the last Nd | With `--hits-in-last-days` | |
| DORMANT rules callout | When any DORMANT (0 hits, older than fresh-days) exist | |
| Diff vs prior snapshot | With `--compare-to` | |
| Per-domain breakdown | With `--all-domains` when >1 domain | |

### Federation stats-fallback (important)

NSX 3.2.x has a bug where `/policy/api/v1/global-infra/.../statistics`
returns HTTP 500 on federated policies (LM side) or HTTP 400 "Enforcement
point is mandatory" on GM side. When this happens, the tool automatically
falls back to `/api/v1/firewall/sections/<id>/rules/stats` on each site's
LM and aggregates. Look for `Stats source (per policy): old_firewall_api=N`
in the report header; failed Policy-API queries are listed in the
"Policy-API stats query errors" section for transparency.

### Building snapshot history

`--hits-in-last-days`, `--min-days-since-hit`, and the `Days since hit`
column all read from the per-host snapshot directory. Every run creates
a new UTC-timestamped subdir which becomes tomorrow's history. To get
meaningful `--hits-in-last-days 7`, you need snapshots at least 7 days
old.

Automate a daily snapshot via cron:

```cron
# 03:00 UTC daily
0 3 * * *  cd /path/to/nsx_scripts && PYTHONPATH=./app .venv/bin/python tools/reports/report_rules_usage.py --target nsx-gm1 --federation-global --all-domains >/tmp/rules_usage_cron.log 2>&1
```

---

## 2. Groups usage report

### Basic (LM local scope)

```bash
python tools/reports/report_groups_usage.py --target nsx-lm1
```

### Federation view (GM, per-site aggregated)

```bash
python tools/reports/report_groups_usage.py --target nsx-gm1 \
  --federation-global --all-domains
```

The tool auto-discovers federation sites and queries each LM directly
for VM member counts (GM's own `/members/virtual-machines` endpoint
returns HTTP 400 without an enforcement point). Per-site columns are
added to the table so you can see membership breakdown per LM.

### View the results

```bash
latest=$(ls -1dt nsx_logs/reports/groups_usage/nsx-gm1.lab.local/*/ | head -1)
latest=${latest%/}
cat "$latest/report.md"

jq . "$latest/summary.json"

# Only tag-based groups
cat "$latest/tag_based_groups.jsonl" | jq -c '{id, display_name, vm_count}'
```

### Report sections

| Section | Notes |
|---|---|
| Summary | Groups, VM members, tag conditions, segment refs, IPs totals |
| Groups by classification | TAG / IP / SEGMENT / VM_PATH / NESTED / MIXED / EMPTY |
| Per-domain breakdown | With `--all-domains` |
| All groups | One row per group with counts of tag conds, segments, IPs |
| Tag-based groups only | Focused on membership-by-tag groups + their conditions |
| Groups with segment references | Only shown if any group references a segment |
| Groups with IP address / CIDR entries | Only shown if any group has IPAddressExpression |

### Output files

| File | Contents |
|---|---|
| `report.md` | Human-readable markdown |
| `summary.json` | Headline counters + per-domain + per-class |
| `groups_usage.json` / `.jsonl` | Full per-group detail |
| `tag_based_groups.jsonl` | Filter: groups with any Tag condition |
| `empty_groups.jsonl` | Filter: groups with 0 VM members |

---

## 3. Hostname tag dryrun

### Basic

```bash
python tools/reports/dryrun_hostname_tags.py --manager nsx-lm1 --overwrite
```

Read-only. Classifies every VM on the manager into:

| Bucket | Meaning |
|---|---|
| `eligible` | Will be tagged on push |
| `skip_has_tag` | Already has a hostname-scope tag |
| `skip_invalid_name` | Name does not end in 3-6 digits |
| `skip_edge` | NSX Edge VM (always skipped) |
| `skip_other_type` | VC_SYSTEM / MANAGER / other non-REGULAR (per `VM_TAGS_SUPPORTED_TYPES`) |
| `skip_too_many_tags` | VM at NSX 30-tag cap |

### View the results

```bash
latest=$(ls -1dt nsx_logs/reports/vm_tags_plan/nsx-lm1.lab.local/*/ | head -1)
latest=${latest%/}
cat "$latest/plan.md"

# Just the eligible VMs and their proposed tags
jq '.vms[] | {display_name, proposed_hostname_tag, existing_tag_count}' "$latest/eligible.json"
```

### Output files

| File | Contents |
|---|---|
| `plan.md` | Human-readable markdown - eligible + per-skip-bucket tables |
| `plan.json` | Full classification + summary |
| `eligible.json` | VMs that would be tagged |
| `skip_*.json` | One file per skip bucket |
| `vm_tag_inventory.jsonl` | Every VM regardless of classification |

---

## 4. Hostname tag push

### Default (interactive step-through)

```bash
plan=$(ls -1dt nsx_logs/reports/vm_tags_plan/nsx-lm1.lab.local/*/ | head -1)
plan=${plan%/}

python tools/reports/push_hostname_tags.py \
  --manager nsx-lm1 --plan-dir "$plan" --apply
```

When `--apply` is set and `--batch-size` is not specified, the tool
auto-defaults to `--batch-size 1` and prompts after every apply. At
each prompt:

| Response | Effect |
|---|---|
| `y` / `<Enter>` | Continue at current batch size |
| `n` | Reset batch size to 1 (paranoid mode) |
| `<number>` | Change batch size mid-run (e.g., `5`, `25`) |
| `x` | Stop cleanly, write manifest of what was applied |

### Faster (start at N)

```bash
python tools/reports/push_hostname_tags.py \
  --manager nsx-lm1 --plan-dir "$plan" --apply --batch-size 5
```

### Fully-automated (no prompts)

```bash
python tools/reports/push_hostname_tags.py \
  --manager nsx-lm1 --plan-dir "$plan" --apply --batch-size 0
```

### Dry-run (no writes)

```bash
python tools/reports/push_hostname_tags.py \
  --manager nsx-lm1 --plan-dir "$plan"
```

### View the results

```bash
md=$(ls -1t nsx_logs/reports/vm_tags_push/nsx-lm1.lab.local/*.md | head -1)
cat "$md"
```

### Safety gates

- **Additive only.** Never removes existing tags.
- **`skip_has_tag`** at plan time keeps re-runs safe.
- **Race re-check** at push time (`[RACE]`) skips VMs that acquired a
  hostname tag between plan and push.
- **Idempotent no-op** (`[NOOP]`) skips VMs that already have the exact
  `(hostname, value)` we would add.
- **Tag-cap defense** refuses to push to a VM at `VM_TAGS_MAX_TAGS_PER_VM`.
- **Batch counter** only advances on successful applies; skips do not
  consume a slot.
- **Type filter** via `.env`'s `VM_TAGS_SUPPORTED_TYPES` (default
  `REGULAR`). All system VM types are excluded by default.

---

## 5. Hostname tag revert

Undo the additions from a specific push manifest. Only removes hostname
tags this manifest added; every other tag on those VMs is preserved.

### Default (interactive step-through)

```bash
manifest=$(ls -1t nsx_logs/reports/vm_tags_push/nsx-lm1.lab.local/*_apply.json | head -1)

python tools/reports/revert_hostname_tags.py \
  --manager nsx-lm1 --manifest "$manifest" --apply
```

Same `--batch-size` semantics as push (auto-defaults to 1 under `--apply`).

### Dry-run

```bash
python tools/reports/revert_hostname_tags.py \
  --manager nsx-lm1 --manifest "$manifest"
```

Produces `<TS>_revert_dryrun.json` with per-VM before/after tag lists.

### Safety gates

- **Additive-only reverse.** Only removes the exact `(scope=hostname,
  tag=<value>)` pair recorded in the push manifest for each VM.
- **`[GUARD]`** skip: if a VM's current hostname tag value differs from
  what the manifest says was added (someone else changed it), the tool
  refuses to touch that VM.
- **`[NOOP]`** skip: VM no longer has the hostname tag.
- **`[MISSING]`** skip: VM no longer exists on target.

---

## Output locations at a glance

All report bundles land under `$NSX_LOG_DIR/reports/` (default:
`nsx_logs/reports/`) with layout `<report-type>/<host>/<UTC_TS>/`.

| Report type | Path pattern |
|---|---|
| Rules usage | `nsx_logs/reports/rules_usage/<host>/<UTC_TS>/` |
| Groups usage | `nsx_logs/reports/groups_usage/<host>/<UTC_TS>/` |
| VM tag plan (dryrun) | `nsx_logs/reports/vm_tags_plan/<host>/<UTC_TS>/` |
| VM tag push | `nsx_logs/reports/vm_tags_push/<host>/<UTC_TS>_apply.{json,md}` |
| VM tag revert | `nsx_logs/reports/vm_tags_revert/<host>/<UTC_TS>_revert_apply.json` |
| Per-run process logs | `$NSX_LOG_DIR/<tool_name>_<UTC_TS>.log` |

---

## Git tracking of report markdowns

Per `.gitignore` rules, `.md` files under `nsx_logs/reports/` are
tracked but their sibling `.json` / `.jsonl` / `logs/` are ignored.
Committed markdown reports serve as historical human-readable audit;
raw JSON stays local (fresh on every run).

---

## Read-only guarantee for the two report-only tools

`report_rules_usage.py` and `report_groups_usage.py` are strictly
read-only against NSX. Additionally `report_rules_usage.py` monkey-
patches its `NsxPolicyClient` instance at startup so that `_post`,
`_put`, `_patch`, `_delete` raise `ReadOnlyViolationError` before any
HTTP request is dispatched. The log line `Read-only lockdown engaged`
appears on every run.

Safe to run against production at any time, including during change
windows.

---

## See also

- [REPORTS_DATA_SOURCES.md](REPORTS_DATA_SOURCES.md) - where each tool reads/writes (NSX endpoints + disk paths)
- [RUNBOOK_VM_TAGS.md](RUNBOOK_VM_TAGS.md) - VM-tags workflow narrative
- [RUNBOOK_VM_TAGS_COMMANDS.md](RUNBOOK_VM_TAGS_COMMANDS.md) - bash command reference
- [RUNBOOK_RULES_USAGE.md](RUNBOOK_RULES_USAGE.md) - deeper dive on the rules report
- [RUNBOOK_REPORTS_PS.md](RUNBOOK_REPORTS_PS.md) - Windows PowerShell mirror of this doc
