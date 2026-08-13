# Reports - Data Sources

Reference for where each tool under `tools/reports/` (read-only reports)
and `tools/vm_tags/` (write-capable action tools) sources its data.
Covers NSX endpoints hit, local files read, and files written. Use this
when planning federation deployments, debugging missing data, or
understanding read/write blast radius.

Runbook counterparts: [RUNBOOK_REPORTS.md](RUNBOOK_REPORTS.md) (bash),
[RUNBOOK_REPORTS_PS.md](RUNBOOK_REPORTS_PS.md) (PowerShell).

---

## Tool-by-tool breakdown

### 1. `report_rules_usage.py` - Policy + Fabric APIs + disk history

| Data | Source |
|---|---|
| Policy list per domain | **NSX API** `GET /policy/api/v1/infra/domains/<d>/security-policies` (or `/global-infra/` on federation) |
| Rules per policy | **NSX API** `GET .../security-policies/<p>/rules` |
| Stats - primary attempt | **NSX API** `GET .../security-policies/<p>/statistics` |
| Stats - fallback | **NSX API (old firewall API)** `GET /api/v1/firewall/sections/<id>/rules/stats` per site LM |
| Federation site discovery (when target is GM) | **NSX API** `GET /policy/api/v1/global-infra/sites` |
| `days_since_hit_changed`, `--hits-in-last-days`, `--min-days-since-hit` | **Local disk**: prior `rules_usage.json` files under `nsx_logs/reports/rules_usage/<host>/*/` |
| `--compare-to` diff | **Local disk**: a specific prior report bundle you name |

Live NSX queries are strictly `GET`. The client instance is monkey-
patched at startup to reject any `_post/_put/_patch/_delete` call
(`ReadOnlyViolationError`).

### 2. `report_groups_usage.py` - Policy API + per-site VM member queries

| Data | Source |
|---|---|
| Group list per domain | **NSX API** `GET /policy/api/v1/infra/domains/<d>/groups` |
| Group expression tree (tag conds, IPs, segment refs) | Same GET as above (embedded in group payload) |
| Federation site list (when target is GM) | **NSX API** `GET /policy/api/v1/global-infra/sites` |
| VM member count per group (single LM) | **NSX API** `GET .../groups/<g>/members/virtual-machines` on that LM |
| VM member count per group (GM federation) | **NSX API on each site's LM directly** (GM's own endpoint returns HTTP 400 without an enforcement point). Tool connects to each LM and aggregates per-site. |

No disk reads, no snapshot history. Every run is fresh live-query.

### 3. `report_tag_map.py` - Fabric VM inventory + Policy API groups (three-way correlation)

| Data | Source |
|---|---|
| VM inventory + current tags (single LM) | **NSX API** `GET /api/v1/fabric/virtual-machines` on that LM |
| VM inventory + current tags (GM federation) | **NSX API on each site's LM directly** (fabric API is LM-scoped). Auto-aggregated. |
| Customer groups per domain | **NSX API** `GET /policy/api/v1/infra/domains/<d>/groups` |
| Tag conditions per group | Same GET as above (embedded in group expression tree) |
| Live member lookup for complex groups | **NSX API** `GET .../groups/<g>/members/virtual-machines` on the appropriate LM |

Simple groups (single Condition or OR-only Conditions) have their
matching VMs computed offline from the tag inventory. Complex groups
(NestedExpression, AND joins, mixed with IP/segment) fall back to the
live `/members/virtual-machines` endpoint.

Read-only. Same VM data source as `dryrun_hostname_tags.py`, plus Policy
API groups.

### 4. `dryrun_hostname_tags.py` - Fabric VM inventory + local classification

| Data | Source |
|---|---|
| VM inventory + current tags | **NSX API** `GET /api/v1/fabric/virtual-machines` (via `client.list_virtual_machines()`) |
| Classification thresholds (`VM_TAGS_SUPPORTED_TYPES`, `VM_TAGS_MAX_TAGS_PER_VM`) | **Environment variables** from `.env` |
| Trailing-digit regex (3-6 digits eligible) | **Hard-coded** in `build_hostname_tag_plan.py` |

Read-only. Nothing loaded from disk (each run reclassifies from live
VM state).

### 5. `push_hostname_tags.py` (in `tools/vm_tags/`) - plan on disk + live tag state at write time

| Data | Source |
|---|---|
| The plan (what to tag) | **Local disk**: `eligible.json` from the `--plan-dir` you pass (produced by dryrun) |
| Live VM state (race detection at push time) | **NSX API** `GET /api/v1/fabric/virtual-machines` |
| Writes (tag additions) | **NSX API** `PUT /api/v1/fabric/virtual-machines?action=update_tags` (via `client.update_vm_tags()`) |

Reads plan file first, then does a live check against NSX before
writing each tag. That's how `[RACE]` and `[NOOP]` skips are detected.

### 6. `revert_hostname_tags.py` (in `tools/vm_tags/`) - push manifest on disk + live tag state

| Data | Source |
|---|---|
| What was previously applied | **Local disk**: `<TS>_apply.json` manifest from a prior push run |
| Live VM tag state (guard check) | **NSX API** `GET /api/v1/fabric/virtual-machines` |
| Writes (tag removals) | **NSX API** `PUT /api/v1/fabric/virtual-machines?action=update_tags` |

Reads the specific manifest you name, verifies each VM's current
hostname tag value still matches what was recorded before removing.
Mismatch triggers `[GUARD]` skip.

---

## Data flow diagram

```
                     NSX Manager (LM or GM)
                            ▲
                            │ GET only    (report_rules_usage, report_groups_usage, dryrun)
                            │ GET + PUT   (push, revert)
                            │
       ┌────────────────────────────────────────┐
       │  tools/reports/*.py                    │
       │                                        │
       │  Also reads:                           │
       │  • .env for creds + config             │
       │  • prior snapshots on disk             │
       │    (report_rules_usage only)           │
       │  • plan/manifest files on disk         │
       │    (push, revert)                      │
       └────────────────────────────────────────┘
                            │
                            ▼ writes reports here
       nsx_logs/reports/<type>/<host>/<UTC_TS>/
       nsx_vm_tags_manifests/<host>/<UTC_TS>_apply.{json,md}
       nsx_vm_tags_manifests/<host>/<UTC_TS>_revert_apply.json
```

---

## NSX API surfaces used

NSX has three API prefixes; the report tools use all three:

| Prefix | Purpose | Which tools use it |
|---|---|---|
| `/policy/api/v1/...` | Policy Manager (declarative DFW policies, groups, security rules) | report_rules_usage, report_groups_usage |
| `/api/v1/fabric/...` | Fabric Manager (VMs, hosts, transport nodes) | dryrun, push, revert |
| `/api/v1/firewall/sections/...` | Legacy pre-Policy DFW API. Fallback for stats on federation | report_rules_usage (fallback only) |

### Federation prefix auto-switching

When `federation_global=True` in `NsxPolicyClient`:

| Target manager | Effective `POLICY_ROOT` |
|---|---|
| LM (nsx-lm1 etc.) | `/policy/api/v1/global-infra` (federated view visible from that LM) |
| GM (nsx-gm1 etc.) | `/global-manager/api/v1/global-infra` (native GM path) |

The client picks the right prefix based on whether the target hostname
matches an `nsx_gm*` alias.

---

## Snapshot history mechanics (rules_usage only)

`report_rules_usage.py` derives `days_since_hit_changed` per rule by
walking every prior `rules_usage.json` file under
`nsx_logs/reports/rules_usage/<host>/` in timestamp order and finding
the most recent snapshot where `hit_count` went UP for that rule.

Implications:

- **History is scoped per-host directory.** gm1 snapshots don't help
  when reporting on lm1 (each has its own tree).
- **Move a bundle out of the tree and the tool won't see it.** Only
  timestamped subdirs directly under `nsx_logs/reports/rules_usage/<host>/`
  are scanned.
- **First run has no history**, so `days_since_hit_changed` is `-` for
  every rule until a second snapshot exists.
- **Meaningful `--hits-in-last-days N` requires snapshots at least N
  days old.** Daily cron/Task Scheduler recommended.
- **Counter reset detection**: if a hit_count goes DOWN between two
  snapshots (host reboot, section recreate, NSX upgrade), the tool
  records `counter_reset_observed=true` and doesn't treat the reset
  as a hit. The next real increase resumes as normal.

---

## What's NOT sourced from these tools

- **Network fabric** (T0/T1, transport nodes, edge clusters, IP pools)
  is not read by any report tool. That's `tools/nsx/capture_fabric_state.py`,
  a separate read-only capture.
- **vCenter metrics** (VM CPU, RAM, storage). Reports only see NSX's
  model of the VM, populated via NSX↔vCenter sync. VM inventory does
  include display_name, external_id, tags, IPs, but not utilization.
- **Traffic samples / flow records**. Rule hit counts are cumulative
  counters, not per-flow records. IPFIX or NSX Intelligence is
  required for full flow visibility.
- **Segment inventory beyond references**. The report tools note
  segment paths inside group expressions but don't fetch segment
  details. That's captured by `capture_fabric_state.py` and
  `find_segments_referenced.py`.

---

## Cross-tool relationships

- **push consumes what dryrun produces.** Push reads `eligible.json`
  from the plan dir dryrun wrote to.
- **revert consumes what push produces.** Revert reads a specific
  push apply manifest (`<TS>_apply.json`) and reverses only what that
  push added.
- **rules_usage snapshots are self-consuming.** Today's rules_usage
  run becomes tomorrow's history for the next run.
- **rules_usage and groups_usage do not share any input files.** They
  hit different Policy API paths and produce independent bundles.

---

## Read/write scope summary

| Tool | Reads NSX | Reads disk | Writes NSX | Writes disk |
|---|:---:|:---:|:---:|:---:|
| report_rules_usage | Yes (GET) | Yes (snapshots) | **No** (locked) | Yes (bundle) |
| report_groups_usage | Yes (GET) | No | **No** | Yes (bundle) |
| report_tag_map | Yes (GET) | No | **No** | Yes (bundle) |
| dryrun_hostname_tags | Yes (GET) | No | **No** | Yes (bundle) |
| push_hostname_tags | Yes (GET + PUT with `--apply`) | Yes (plan) | Yes with `--apply` | Yes (manifest) |
| revert_hostname_tags | Yes (GET + PUT with `--apply`) | Yes (manifest) | Yes with `--apply` | Yes (audit manifest) |

The four read-only tools are safe to run against production during
change windows. The two write tools default to dry-run unless
`--apply` is set, and even under `--apply` the default `--batch-size 1`
prompts before each write.
