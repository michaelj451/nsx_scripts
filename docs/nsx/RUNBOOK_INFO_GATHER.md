# Runbook INFO GATHER : read-only pre-change evidence : macOS / Linux / bash

Five read-only reports collected into one session directory you can review
or hand over, every one at `$G/<manager-host>/<report>/<ts>/` so LM and GM
runs sit side by side under their own hostnames. Nothing here writes to
NSX. Every step has a **Local Manager**
block and a **Global Manager (federation)** block; run whichever applies, or
both. A Global Manager block talks to the GM first: member and statistics
queries are proxied through the GM per site. The one exception is step 3
statistics when the GM cannot answer (NSX 3.2.x): the tool then opens
read-only sessions to each site LM, at addresses taken from the GM's own
site registry, never from `.env`. Where DFW policy is GM-owned, the LM blocks show only the default rules
and zero customer groups, and the GM blocks carry the real answer.

| Step | Report | Tool | LM | GM |
|---|---|---|---|---|
| 1 | VM rule membership: every DFW rule touching the VMs in your list | `tools/reports/report_vms_in_rules.py` | yes | yes (GM only, no LM access needed) |
| 2 | Group membership: every customer group, its type, and evaluated VM members | `tools/reports/report_groups_usage.py` | yes | yes (GM only, members proxied per site) |
| 3 | Rule hit counts, last 30 days: HOT / USED / STALE / UNUSED / DORMANT plus the 30-day window | `tools/reports/report_rules_usage.py` | yes | yes (GM first; on NSX 3.2.x stats come from site LMs discovered via the GM, see step 3) |
| 4 | Hostname tag dry run: who would be tagged, who is skipped and why | `tools/reports/dryrun_hostname_tags.py` | yes | no (VM inventory is LM-only; run per site LM) |
| 5 | IP remap dry run: what the CSV remap would add, already-remapped pairs, gaps | `capture_nsx_state.py` + `groups.py push` (dry-run) | yes | yes |

PowerShell variant: [RUNBOOK_INFO_GATHER_PS.md](RUNBOOK_INFO_GATHER_PS.md).
Background: [RUNBOOK_VM_RULE_MEMBERSHIP.md](RUNBOOK_VM_RULE_MEMBERSHIP.md),
[RUNBOOK_REPORTS.md](RUNBOOK_REPORTS.md), [RUNBOOK_RULES_USAGE.md](RUNBOOK_RULES_USAGE.md),
[RUNBOOK_VM_TAGS.md](RUNBOOK_VM_TAGS.md), [RUNBOOK_B.md](RUNBOOK_B.md).

## 0) Env

The first line makes pasted `#` comments safe in zsh; it is a no-op in bash.
Set the variables once per session; every command below follows them.
`M`/`H` are the Local Manager alias (from `.env`) and its hostname; `GM`/`GH`
the same for the Global Manager; `G` the session directory; `T` the VM
target list; `CSV` the subnet map. Capture bundles are keyed by hostname,
which is why `H` and `GH` exist.

```bash
setopt interactive_comments 2>/dev/null || true

python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"

M=nsx-lm2
H=nsx-lm2.lab.local
GM=nsx-gm1
GH=nsx-gm1.lab.local
G=nsx_info_$M
T=vm_rule_report_targets.txt
CSV=data/nonprod_map.csv
mkdir -p $G
```

The target list is one VM display name per line, optionally `name,ip`
(explicit IPs are matched against group IP sets too). Blank lines and `#`
comments are ignored.

---

## 1) VM rule membership report

Local Manager:

```bash
python tools/reports/report_vms_in_rules.py \
  --manager $M \
  --vm-list $T \
  --output-base $G \
  --overwrite
```

Global Manager (talks to the GM only; membership is proxied per site):

```bash
python tools/reports/report_vms_in_rules.py \
  --manager $GM \
  --federation-global \
  --vm-list $T \
  --output-base $G \
  --overwrite
```

Review: `$G/<host>/vm_rule_membership/<ts>/report.md` (matched VMs with Site column on the
GM run, then rules per VM with how each hit: Src / Dst / Scope) and
`report.json`. Add `--members-cache-minutes 30` when iterating on the target
list. The GM run never contacts a site LM, so fabric-sourced VM IPs are not
included; targets with explicit IPs in the list keep them.

---

## 2) Group membership report

Local Manager:

```bash
python tools/reports/report_groups_usage.py \
  --target $M \
  --output-base $G
```

Global Manager (all domains; members proxied through the GM per site, no LM sessions):

```bash
python tools/reports/report_groups_usage.py \
  --target $GM \
  --federation-global \
  --all-domains \
  --output-base $G
```

Review: `$G/<host>/group_membership/<ts>/report.md`, plus `groups_usage.jsonl`
(one row per group: type TAG / IP / SEGMENT / VM_PATH / NESTED, member
count, members), `tag_based_groups.jsonl`, and `empty_groups.jsonl`.

---

## 3) Rule hit counts, last 30 days

Local Manager:

```bash
python tools/reports/report_rules_usage.py \
  --target $M \
  --hits-in-last-days 30 \
  --output-base $G
```

Global Manager (all domains; statistics through the GM per enforcement point, with automatic read-only site-LM fallback, addresses from the GM):

```bash
python tools/reports/report_rules_usage.py \
  --target $GM \
  --federation-global \
  --all-domains \
  --hits-in-last-days 30 \
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

On NSX 3.2.x the GM statistics endpoint fails with a NullPointerException
(per-policy and per-rule variants alike). The run then falls back by
default to a direct read-only session on each site LM and sums the
per-site counters; the LM addresses are discovered from the GM's own site
registry (`site_connection_info`), never taken from `.env`. Rules are
`NO_STATS` only when no site LM could answer either. The log line
`Managers contacted:` at the end of every run shows exactly which managers
were reached, and `summary.json` records `lm_stats_fallback_sites`.

---

## 4) Hostname tag dry run (Local Manager only)

```bash
python tools/reports/dryrun_hostname_tags.py \
  --manager $M \
  --output-base $G \
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

```bash
python tools/nsx/capture_nsx_state.py --source $M

python tools/nsx/groups.py push \
  --target $M \
  --groups-dir nsx_capture/$H/groups_additive/domains/default/groups \
  --csv-remap $CSV \
  --reports-dir $G/$H/ip_remap_dryrun
```

Global Manager:

```bash
python tools/nsx/capture_nsx_state.py --source $GM --federation-global

python tools/nsx/groups.py push \
  --target $GM \
  --federation-global \
  --groups-dir nsx_capture/$GH/groups_additive/domains/default/groups \
  --csv-remap $CSV \
  --reports-dir $G/$GH/ip_remap_dryrun
```

Review: `$G/<host>/ip_remap_dryrun/remap_report.md`: the Result line, section 1 "Would
add" (value, source original, CSV row), section 2 already-remapped pairs,
then generic-group candidates, never-remapped ranges/IPv6, and CSV coverage
misses. `summary.json` must show `csv_invalid_rows: []`.

Optional reconciliation of the live manager against the CSV (read-only, exit
code 1 when gaps exist):

```bash
python tools/nsx/audit_ip_remap.py --target $M --csv $CSV --output-base $G
python tools/nsx/audit_ip_remap.py --target $GM --federation-global --csv $CSV --output-base $G
```

---

## 6) Package the evidence

```bash
find $G -name "report.md" -o -name "remap_report.md" -o -name "plan.md" -o -name "ip_remap_audit.md" | sort
tar -czf $G-$(date -u +%Y%m%d_%H%M%S).tgz $G
```

Everything under `$G` is regenerable: re-run any step to refresh it.

---

## Safety characteristics

| Step | Touches NSX? | Rate |
|---|---|---|
| 1 to 5, audit | GET only | client default 2 req/s (`NSX_API_MAX_RPS` in `.env` to change) |
| Global Manager blocks | GET only; one session to the GM, plus read-only site-LM sessions in step 3 when the GM cannot return statistics (LM addresses from the GM site registry, never `.env`) | same |

No `--apply` appears anywhere in this runbook.
