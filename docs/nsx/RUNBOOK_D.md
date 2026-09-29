# Runbook D — In-place remap-to-siblings on a live production NSX manager

## Summary

**Workflow D** is the production-grade flow for landing IP-only AVS sibling
groups (`<original>_avs_ips`, holding only the CSV-mapped IPs) on a **live,
in-service** NSX manager and then adding them to rules next to their
originals. WF-D never modifies an existing group. Each phase is strict-additive
unless an explicit force flag is used. Group deletion is impossible via
any push command — only via `groups.py revert` against a "didn't-exist"
baseline.

WF-D is the production counterpart to WF-C, which decomposes in place
on a lab/non-prod target. WF-D's blast radius is bounded so it can run
during business hours against a manager carrying real traffic, with
per-phase revert available.

### Why a new workflow vs. extending WF-C

| Concern | WF-C (lab) | WF-D (live prod) |
|---|---|---|
| Strips IPs from tagged-side originals | No longer offered by either workflow | Never. The originals keep their IPs; the sibling carries the mapped equivalents alongside them |
| Amends live rules to OR-reference siblings | Yes (step 5) | **Optional, separate change window.** Strict-additive — never removes refs. |
| IP-only groups (no tag Condition) | Skipped | **Get a sibling** when at least one IP has a CSV mapping, like any other group. The original is not modified. |
| Groups that nest other groups by path | Skipped (no Condition) | **Get a sibling** when at least one IP has a CSV mapping. A path to another group is not a segment. |
| Pure-segment groups | Skipped | **Skipped** (unchanged). |
| Tag+segment+IP hybrids | Decomposed (sibling=IPs, original keeps Condition+PathExpression) | **Skipped: a group with a segment-type `PathExpression` member (segment, segment port, VIF) gets no sibling.** |
| Source of IPs in the sibling | Same IPs as original (no remap) | **CSV-mapped IPs only** — the prod IPs stay on the original. |
| Post-push validation | None built in | **`validate_wf_d.py`** runs G1/G2/G3/S1/S2/R1/R2 checks against the live target. |

### The end state on lm1 after WF-D

```text
BEFORE:                             AFTER:
  vm1                                 vm1                                 (unchanged)
    expression:                         expression:
      Condition(Tag=app|web)              Condition(Tag=app|web)
                                      vm1_avs_ips                         (NEW)
                                        expression:
                                          IPAddressExpression([
                                            10.7.0.101,  ← mapped from 10.6.0.101
                                            10.7.1.101,
                                            10.7.2.101,
                                          ])
                                        group_type: [IPAddress]

  ip-address-group                    ip-address-group                    (unchanged)
    expression:                         expression:
      IPAddressExpression([             IPAddressExpression([
        10.6.0.50,                        10.6.0.50,
        10.6.0.51,                        10.6.0.51,
        10.6.0.52-10.6.0.53,              10.6.0.52-10.6.0.53,
        10.6.1.0/24                       10.6.1.0/24
      ])                                ])
                                      ip-address-group_avs_ips            (NEW)
                                        expression:
                                          IPAddressExpression([
                                            10.7.0.50,   ← mapped from 10.6.0.50
                                            10.7.0.51,
                                            10.7.1.0/24
                                          ])
                                        (the range has no CSV mapping, so it
                                         stays on the original only)
```

No existing group is modified: every group WF-D handles, tag-based or
IP-only, gets a new `_avs_ips` sibling and the original stays exactly as it
was. Rules are not touched unless amend-refs runs in its own change window.
No groups are ever deleted.

---

## Production safety stance

**The contract in six sentences:**

1. **Groups are never deleted by any push command** — only `groups.py revert` against a "didn't-exist" baseline can DELETE a group.
2. **Rules are never deleted** by any push or amend command.
3. **IPs are never removed** from any existing group. There is no flag, phase or option that removes one.
4. **Rule refs are never removed** by `amend-refs` — it is strict-additive and only appends sibling refs.
5. **Segment-based groups get no sibling.** A group with a `PathExpression` member that is not another group (a segment, segment port, VIF and so on), at any depth, is skipped entirely.
6. **Existing groups are never modified by WF-D.** It only creates new `_avs_ips` groups (D2a) and adds rule references (D3).

| Constraint | How WF-D enforces it |
|---|---|
| **No existing group is modified** | D2a pushes only the new `_avs_ips` groups, and D3 only adds references to rules. No phase writes to an original group. |
| **No groups are EVER deleted** | Push uses CREATE / PUT-on-new-ID or PATCH only. No DELETE operations are issued by any push command. The only deletion path is `groups.py revert` against the baseline (which captures "group did not exist") — and that's an operator-initiated explicit step. |
| **No IPs are removed from any group, ever** | `groups.py push` sends the union of the payload and the IPs the group already holds on the target, so an address the source no longer reports is kept (and listed as kept in the run report). A row whose diff would still remove an IP is rejected, and there is no override. |
| **No tags altered on any VM or group** | No tagging operation in this workflow. VM tags + group object-level `tags:` metadata untouched. |
| **No rules modified unless `amend-refs` runs** | Rule amendment is its own change-controlled phase. When it runs, the default behavior is strict-additive — appends sibling refs to `source_groups` and `destination_groups` only, never removes anything. |
| **No segment paths modified, no segment-based group gets a sibling** | Any group with a `PathExpression` member that is not another group (at any depth) is skipped entirely. Pure-segment, tag+segment, and tag+segment+IP hybrids ALL skip. A group that only nests other groups by path is not segment-based and gets a sibling. |
| **Every change is revertible** | Each push captures its own baseline. LIFO revert in reverse order restores any intermediate state. |
| **Strict-additive contract enforced** | The push sends the union, and any row whose diff would still remove an IP is rejected before anything reaches NSX. |
| **Dry-run is the default** | Every push command starts without `--apply`. The operator reviews the diff, then re-runs with `--apply`. |
| **Post-push validator confirms the contracts held** | `validate_wf_d.py` checks G1/G2/G3/S1/S2/R1/R2 against the live target after each push window. CRITICAL findings = the contract was violated. |

### What CAN change on lm1 during each WF-D phase

| Phase | What changes |
|---|---|
| 2a (push siblings) | New `_avs_ips` group objects appear (a re-run can add IPs to the `_avs_ips` groups an earlier 2a created). No other group changes. |
| 3 (amend-refs) | Existing rules get sibling refs appended to `source_groups`/`destination_groups`. No ref is ever removed. |
| 4 (validator) | Read-only — no NSX writes. |

---

## Pipeline (5 phases; phase 2a is the only mandatory one)

```text
0)  capture_nsx_state.py --source nsx-lm1                              (read-only, GET-only)
                                                                       + auto-runs IP report w/ CSV coverage
        ↓
1)  build_sibling_groups.py --source nsx-lm1 \                         (offline transform)
        --csv-remap data/nonprod_map.csv \
        --skip-segment-groups
        produces nsx_sibling_groups/<host>/groups/                     (one _avs_ips sibling per group with a mapped IP)
                 nsx_sibling_groups/<host>/sibling_map.json
        ↓
2a) groups.py push                                                     (MANDATORY — DRY-RUN first)
        --target nsx-lm1 \
        --groups-dir nsx_sibling_groups/<host>/groups
        ↓
3)  rules.py amend-refs                                                (OPTIONAL — separate change window)
        --target nsx-lm1 \
        --sibling-map nsx_sibling_groups/<host>/sibling_map.json
        ↓
4)  validate_wf_d.py                                                   (RECOMMENDED after each window)
        --target nsx-lm1 \
        --baseline nsx_sibling_groups/<host>/push_report/baselines/<ts>_target_baseline.json \
        --sibling-map nsx_sibling_groups/<host>/sibling_map.json
```

Only **2a** is strictly required to call this run "WF-D applied." Every
other phase is independent, deferrable, and revertible. The phasing maps
to change-window cadence: operators typically space 2a and 3 across days
or weeks based on how much risk they want to absorb per window.

The former phase 2b (D2b), which added mapped IPs in place to existing
IP-only groups, is retired: those groups now get an `_avs_ips` sibling in 2a
like every other group, so WF-D never modifies an existing group.

---

## Tools

| Tool | Phase | Purpose |
|---|---|---|
| [tools/nsx/capture_nsx_state.py](../../tools/nsx/capture_nsx_state.py) | 0 | Pre-flight capture + auto-IP-report + flat-export bundles |
| [tools/nsx/report_groups_with_ips.py](../../tools/nsx/report_groups_with_ips.py) | 0 | CSV coverage analysis (auto-fires from capture) |
| [tools/nsx/build_sibling_groups.py](../../tools/nsx/build_sibling_groups.py) | 1 | Offline transform: emits the `_avs_ips` siblings and `sibling_map.json` |
| [tools/nsx/groups.py](../../tools/nsx/groups.py) `push` | 2a | Push the siblings |
| [tools/nsx/rules.py](../../tools/nsx/rules.py) `amend-refs` | 3 | Append sibling refs to rules' source/destination groups (strict-additive). On an apply, only siblings already on the target are added |
| [tools/nsx/validate_wf_d.py](../../tools/nsx/validate_wf_d.py) | 4 | Post-push validator — G1/G2/G3/S1/S2/R1/R2 checks against live target |

### Key flags on `build_sibling_groups.py`

| Flag | Effect |
|---|---|
| `--csv-remap <path>` | Apply CSV mapping to each collected IP. Sibling's `IPAddressExpression.ip_addresses` carries the MAPPED values only. It also drops the tag-Condition requirement, so IP-only groups and groups that nest other groups get a sibling too. A group with no mapped IP gets none. |
| `--skip-segment-groups` | Skip a segment-based group: one with a `PathExpression` member that is not another group (a segment, segment port, VIF and so on). A group that only nests other groups by path is not skipped. Recorded in `reports/skipped_segments.json` and under `no_sibling` in `sibling_map.json`. |
| `--skip-uncovered` | If a group has ANY IP without a CSV mapping, skip the group entirely. Default: emit a partial sibling with the mapped IPs only, and surface the uncovered addresses in `sibling_map.json` and the run report. |
| `--include-pure-ip` | Not needed for WF-D: with `--csv-remap` the tag-Condition requirement is already off. Without a CSV map it lets IP-only groups produce siblings. |

---

## Prerequisites

| | Required state |
|---|---|
| `data/nonprod_map.csv` | Populated with all IP mappings in scope. Coverage verified via the IP report (no `groups_partially_covered_by_csv` or `groups_uncovered_by_csv` for in-scope groups). |
| `nsx_capture/nsx-lm1.lab.local/` | Fresh capture taken **on the day of the push** (re-capture is free, eliminates source-drift risk). |
| `tools/nsx/build_sibling_groups.py` | Updated with the WF-D flags above (`--csv-remap`, `--skip-segment-groups`). |
| Operator credentials | NSX manager creds with policy/write permissions on lm1. |
| Change window | Off-peak preferred. The push is strict-additive (only CREATE operations), but each create triggers an effective-member recompute. |
| Rollback rehearsed | Step 3 revert tested against a lab-equivalent state first. |
| `OBJECT_APPENDIX_AVS` set in `.env` | WF-D siblings must not share WF-C's suffix. See below. |

---

## Sibling suffix: WF-D must not share WF-C's

WF-C and WF-D both create sibling groups named `<original_id><suffix>`, but
their contents are **different**:

| Workflow | Sibling holds | Suffix | `.env` variable |
|---|---|---|---|
| C | the SOURCE addresses, copied | `_np_ips` | `OBJECT_APPENDIX` |
| D | the CSV-REMAPPED addresses | `_avs_ips` | `OBJECT_APPENDIX_AVS` |

Sharing one suffix is the failure this split exists to prevent. The ids would
collide, and the push is strict-additive, so a WF-D push would **merge** mapped
`10.7.x` addresses into a WF-C sibling already holding source `10.6.x`
addresses. Both sets end up wrong, the push reports success, and every rule
referencing that sibling then permits both ranges.

```bash
OBJECT_APPENDIX=_np_ips
OBJECT_APPENDIX_AVS=_avs_ips
```

`run_workflow.py` picks the right one per phase, so the WF-D phases need no
`--appendix` argument. It refuses to run when `OBJECT_APPENDIX_AVS` is unset,
and refuses again if you force the WF-C suffix onto a WF-D phase.

Running `build_sibling_groups.py` by hand does **not** get that protection: it
defaults to `OBJECT_APPENDIX`, so a WF-D build has to pass `--appendix` itself.

```bash
python tools/nsx/build_sibling_groups.py --source nsx-lm1 \
  --appendix "$OBJECT_APPENDIX_AVS" \
  --csv-remap data/nonprod_map.csv \
  --skip-segment-groups
```

**Do not change either suffix between runs against the same target.** A changed
suffix renames nothing, because NSX ids are immutable: it creates a second,
parallel sibling set and leaves the first in place, still rule-referenced.

---

## Step 0 — Pre-flight (read-only)

### 0a. Fresh capture of lm1

```bash
python tools/nsx/capture_nsx_state.py --source nsx-lm1 --live-query \
  --ip-report-csv data/nonprod_map.csv
```

This GETs lm1's current state, runs the IP-additive enrichment (so
sub-step 6's IP report sees the spliced VM IPs), and writes the report
with CSV coverage to `$NSX_LOG_DIR/groups_ip_report/nsx-lm1.lab.local/`.

> **`--live-query` is mandatory and its absence is silent.** The enrichment is
> what splices each group's effective IPs into `groups_additive/`. Without the
> flag that tree is a plain copy of the export, every tag-only group appears to
> have no IPs, and step 1 emits siblings only for groups that already carried
> static IPs. No error, no warning in the summary, a success report. Measured
> on lm1 2026-09-11: **1 sibling without it, 7 with it.**
>
> Gate on the additive step's summary before building: `ip_source: 'effective'`,
> non-zero `effective_ip_queries` / `groups_changed` / `ips_added_total`, and
> `groups_errors: 0`. A non-zero error count means groups that have not
> realized yet: wait and re-run rather than proceeding.

### 0b. Review IP-report counters before designing the push

Read `$NSX_LOG_DIR/groups_ip_report/nsx-lm1.lab.local/summary.json` and
make sure:

- `with_ips` > 0 (there's actually something to remap)
- `groups_uncovered_by_csv` == 0 for in-scope groups (otherwise extend the CSV first)
- `groups_partially_covered_by_csv` is acceptable to you (each partial means the sibling will only carry mapped IPs; uncovered IPs stay only on the original)
- The `shape_pure_segment` count is whatever you expect — those will be skipped
- `with_nested_expression` count is reflected in `decomposable_by_wf_c` (the recursive walker catches them)

### 0c. (optional but recommended) Drift detection on lm1

If lm1 has been live with prior WF-A or other tooling, snapshot drift first:

```bash
python tools/nsx/compare_group_ips.py \
  --reference nsx_groups_export/nsx-lm1.lab.local/groups \
  --target nsx-lm1
```

Should report 0 drift for a freshly-captured lm1. Non-zero means something
edited lm1 between when you exported and now — investigate before pushing.

---

## Step 1 — Build (offline)

```bash
python tools/nsx/build_sibling_groups.py \
  --source nsx-lm1 \
  --appendix "$OBJECT_APPENDIX_AVS" \
  --csv-remap data/nonprod_map.csv \
  --skip-segment-groups
```

Outputs:

```text
nsx_sibling_groups/nsx-lm1.lab.local/
├── groups/<gid>_avs_ips.yaml    ← one per group that gets a sibling
├── sibling_map.json             ← for amend-refs (step 3), validator (step 4) and the report;
│                                  no_sibling lists every group without one, with the reason
├── manifest.json
├── push_report/                 ← written by the push (step 2a); kept on a rebuild
└── reports/
    ├── skipped_segments.json    ← every segment-based group (skipped)
    ├── empty_groups.json        ← every group with no IPs to remap
    └── skipped_uncovered.json   ← (with --skip-uncovered) any group skipped for incomplete coverage
```

No `nsx_stripped_groups/...` directory is created: this tool no longer
produces one. Nor is `nsx_pure_ip_remap/<host>/`: one left over from an
earlier run is not touched (it may hold an old revert baseline), and nothing
reads it.

A rebuild clears the previous build output but keeps `push_report/`, so
re-running the build (or the C / D2a dry run, which rebuilds) never costs an
earlier apply its revert baselines.

### What goes where, by group shape

| Group shape | Action | Where |
|---|---|---|
| **Tag-based** (Condition, with or without static IPs, no segment member) | Sibling, if at least one IP maps | `nsx_sibling_groups/<host>/groups/` |
| **IP-only** (IPAddressExpression only) | Sibling, if at least one IP maps | `nsx_sibling_groups/<host>/groups/` |
| **Nests other groups by path** (PathExpression to `/groups/` only) | Sibling, if at least one IP maps | `nsx_sibling_groups/<host>/groups/` |
| **No IP has a CSV mapping** | No sibling | `no_sibling` in sibling_map.json |
| **Pure-tag resolving to no IPs** | No sibling: no members | reports/empty_groups.json |
| **Pure-segment** (PathExpression to a segment, port, VIF) | No sibling: segment-based | reports/skipped_segments.json |
| **Tag + segment + IP hybrid** | No sibling: segment-based | reports/skipped_segments.json |
| **Tag + segment hybrid (no IPs)** | No sibling: segment-based | reports/skipped_segments.json |
| **Completely empty** (no expression entries) | No sibling: no members | reports/empty_groups.json |

Every group without a sibling is also listed, with its reason, under
`no_sibling` in `sibling_map.json`, and in the D2a report's "Groups with no
AVS group" table. The original group is never modified in any row above.

### Hand-typed addresses stay on the original

A group's own `IPAddressExpression` entries (addresses an operator typed in)
are treated like every other current IP: the sibling gets the CSV-mapped
equivalent if there is one, and nothing otherwise. They are no longer copied
into the sibling verbatim. They stay on the original group, which every rule
keeps referencing, so no coverage is lost.

```text
network-6-0        tag criteria  +  hand-typed 10.50.20.20
  -> network-6-0_avs_ips :  10.7.0.101, 10.7.0.102, 10.7.0.103,
                            10.7.1.102, 10.7.2.101      (mapped)
     10.50.20.20 has no CSV mapping: it stays on network-6-0 only
```

### What happens to IPs that have no CSV mapping

An address the CSV cannot map does **not** reach the sibling. It stays on the
original group, and D3 adds the sibling next to the original in each rule,
never in its place, so the rule still matches that address.

Per-row `ips_uncovered` in `sibling_map.json` records exactly which addresses
have no mapping. The D2a report counts them per group in the "No AVS mapping"
column and lists each one as "no AVS mapping" in its IP mapping table. A group
where no address maps gets no sibling at all and is listed under `no_sibling`.

With `--skip-uncovered`: any group with even one uncovered IP is skipped
entirely, emitting no sibling at all rather than a partial one, with an audit
row in `skipped_uncovered.json`. Use it when a partial sibling would be worse
than none.

---

## The run report

Every push writes `avs_run_report.md` and `avs_run_report.json`. Driving the
phases with [RUNBOOK_WORKFLOW.md](RUNBOOK_WORKFLOW.md) generates it in the same
invocation, into `<run-dir>/report/<phase>/<mode>/`, so a dry-run report and an
apply report can never overwrite each other. By hand:

```bash
python tools/nsx/report_avs_run.py \
  --report-root nsx_sibling_groups/nsx-lm1.lab.local \
  --out-dir nsx_avs_runs/d2a_report --workflow d \
  --label "WF-D2a: siblings to nsx-lm1"
```

`--workflow d` is what produces the WF-D layout and the `D2a` / `D3` phase
labels. Without it the rows are labelled as WF-C, because both workflows push
from the same bundle directories and the path alone cannot tell them apart.

The WF-D report is laid out around original group, AVS group and rule:

- **D2a**: a Summary table; an "AVS groups" table (Original group | AVS group
  | Result | AVS IPs | No AVS mapping); an "IP mapping" section with one table
  per group (Current IP | AVS IP, reading "no AVS mapping" for an unmapped
  IP); and a "Groups with no AVS group" table (Group | Reason | Current IPs).
- **D3**: a Summary table and a "Rules to update" table (Policy | Rule |
  Source gains | Destination gains).

See [RUNBOOK_WORKFLOW.md](RUNBOOK_WORKFLOW.md#4b-reading-the-report) for the
verdicts and the WF-A / WF-C layout.

---

## Step 2a — Push siblings to lm1 (MANDATORY)

### 2a-i. Dry-run

```bash
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups
```

Review:
- `mode: DRY-RUN`
- `totals.files_seen` matches step 1's `siblings_written`
- `totals.failed = 0`
- `additive_only_contract: pass`
- `total_ips_removed = 0`

If any row shows `would_remove_ips > 0`, **STOP** — likely a sibling-ID
collision with an existing lm1 group from a prior partial run.

### 2a-ii. Operator review

1. Eyeball 3-5 sibling YAMLs — confirm IP lists are mapped values
2. Spot-check `sibling_map.json` — confirm original→sibling correspondence
3. Eyeball the dry-run `per_file_report` for anomalies
4. Peer review before adding `--apply`

### 2a-iii. Apply

```bash
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups \
  --apply
```

Baseline captured at `nsx_sibling_groups/<host>/push_report/baselines/<ts>_target_baseline.json`.
**Keep that path** — step 4 (validator) consumes it as the "before snapshot."

---

## Step 3 — Rule amendment (OPTIONAL, separate change window)

Strict-additive — appends sibling refs to `source_groups` and
`destination_groups` of every rule that references an original. Never
removes any existing ref. Never deletes a rule.

```bash
setopt interactive_comments 2>/dev/null || true

# Dry-run
python tools/nsx/rules.py amend-refs --target nsx-lm1 \
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json

# Apply
python tools/nsx/rules.py amend-refs --target nsx-lm1 \
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json \
  --apply
```

Default excludes `scope`. Add `--include-scope` to also broaden the
applied-to field (rarely wanted on prod).

An apply adds only the siblings that exist on the target at that moment. A
missing one is skipped and listed in `amend_refs_summary.json` as
`siblings_not_on_target`. A dry run previews all of them and flags the missing
ones, which is normal before step 2a has been applied.

Baseline at `nsx_rules_export/<target-host>/push_report/baselines/`.

---

## Step 4 — Validate (RECOMMENDED after each window)

Read-only. Confirms WF-D's contracts held against the live target.

```bash
python tools/nsx/validate_wf_d.py \
  --target nsx-lm1 \
  --baseline nsx_sibling_groups/nsx-lm1.lab.local/push_report/baselines/<ts>_target_baseline.json \
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json
```

Checks run:

| Code | Confirms |
|---|---|
| **G1** | No customer group present in the baseline was deleted |
| **G2** | No IP present in any baseline group was removed. Absolute: nothing in the toolkit removes one |
| **G3** | Every Condition / PathExpression in baseline groups is still present |
| **S1** | Every (original, sibling) pair from `sibling_map.json` exists on the target |
| **S2** | Every sibling carries `group_type: [IPAddress]` |
| **R1** | Every rule referencing an original-with-sibling also references the sibling (amend-refs completeness) |
| **R2** | (with `--rules-baseline`) Every customer rule in baseline still exists |

Exit code: `0` = all pass; `1` = at least one CRITICAL finding.

Re-run after each step (2a / 3) for full coverage. G2 is absolute: any
IP that disappears from a group is a CRITICAL finding, because no phase of
this workflow removes one.

---

## Revert (LIFO — reverse order)

Each phase has its own baseline. Revert in reverse order to avoid
dangling rule refs (if amend-refs ran, revert it before deleting any
sibling — NSX 409s on DELETE for groups still referenced by rules).

```bash
setopt interactive_comments 2>/dev/null || true

# Phase 3 revert (restores rules to pre-amend state — removes sibling refs)
python tools/nsx/rules.py revert --target nsx-lm1 \
  --reports-dir nsx_rules_export/nsx-lm1.lab.local/push_report --apply

# Phase 2a revert (deletes the _avs_ips groups it created)
python tools/nsx/groups.py revert --target nsx-lm1 \
  --reports-dir nsx_sibling_groups/nsx-lm1.lab.local/push_report --apply
```

Each command pops the most recent unreverted baseline for that stack.

With the driver: `wf --phase d3 --rollback` (then `--apply`), then
`wf --phase d2a --rollback` (then `--apply`). The d2a rollback deletes the
siblings it created.

---

## Per-row record format (sibling_map.json)

Each entry under `map[]`:

```json
{
  "original_id": "vm1",
  "original_display_name": "vm-group-1",
  "sibling_id": "vm1_sibling",
  "sibling_display_name": "vm-group-1_sibling",
  "ip_count_source": 3,
  "ip_count_sibling": 3,
  "ips_source": ["10.6.0.101", "10.6.1.101", "10.6.2.101"],
  "ips_sibling_mapped": ["10.7.0.101", "10.7.1.101", "10.7.2.101"],
  "ips_uncovered": []
}
```

For partial coverage:

```json
{
  "original_id": "super-nested-group",
  "sibling_id": "super-nested-group_sibling",
  "ip_count_source": 3,
  "ip_count_sibling": 1,
  "ips_source": ["10.2.3.0/24", "10.5.20.5", "10.6.1.101"],
  "ips_sibling_mapped": ["10.7.1.101"],
  "ips_uncovered": ["10.2.3.0/24", "10.5.20.5"]
}
```

The `ips_uncovered` field is CAB-grade audit trail: "these IPs from the
original group were intentionally not transferred to the sibling because
the CSV had no mapping."

---

## Open decisions

These are inputs the operator gives at design time. Defaults shown below
are what the current draft assumes; flag adjustments to the script if you
want different.

| Decision | Default | Alternative |
|---|---|---|
| Pure-segment groups | Skipped via `--skip-segment-groups` | — |
| **Segment-based groups** (a `PathExpression` member that is not another group) | **Skipped via `--skip-segment-groups`** (recommended for prod; the driver always passes it) | Omit the flag to allow tag+segment+IP hybrids to decompose (NOT recommended for prod). A group that only nests other groups by path gets a sibling either way |
| **IP-only groups** | **Get a sibling** like any other group with a mapped IP; the original is not modified | n/a |
| CSV-uncovered IPs | Sibling emitted with the mapped IPs; uncovered ones noted in the audit and named in the run report | `--skip-uncovered` to skip the whole group |
| Hand-typed IPs | **Mapped like any other IP.** With no mapping they stay on the original only, where the rule still matches them | n/a |
| Appendix | `OBJECT_APPENDIX_AVS` from `.env` (`_avs_ips`), NOT `OBJECT_APPENDIX`. See [Sibling suffix](#sibling-suffix-wf-d-must-not-share-wf-cs) | Override with `--appendix` per run |
| `group_type` on siblings | `[IPAddress]` (consistent with WF-C) | — |
| Rule amendment (step 3) | **Optional, separate change window** — strict-additive | Skip; rules continue to reference originals only |
| Empty-groups handling | Reported in `empty_groups.json` and under `no_sibling` in `sibling_map.json`; no sibling | n/a |
| Post-push validator (step 4) | **Recommended** after each change window | Skip (not recommended — leaves contract violations undetected) |

---

## Common questions

**Why are originals left untouched on lm1?**
Live production. Touching them risks removing IPs that are actively in
use. WF-D's purpose is to create the new IP-mapped destination groups so
they're available for rule references when a future change-controlled
amendment activates them — not to modify what's running today.

**What if a sibling ID collides with an existing group on lm1?**
The dry-run will surface it as `would_replace > 0` or via the per-row
diff. STOP and rename — likely a leftover from a prior partial run. Run
`groups.py revert` against any old WF-D baselines first.

**Can we re-run WF-D to pick up new groups added on lm1 since the last run?**
Yes — fully idempotent. Re-running Step 1 + Step 2:
- Existing siblings already on lm1 → PATCH-no-change for any whose mapped IPs match
- New decomposable groups → new sibling YAMLs → new siblings created on lm1

The baseline stack still allows clean revert of just-this-run additions.
A rebuild keeps `push_report/`, so the earlier apply's revert baselines
survive it.

**What about lm2?**
WF-D isn't designed for lm2 (lab/non-prod target). For that, WF-C
self-loop (pattern b) gives you a full decomposition including the
strip-originals step. WF-D's strictly-additive stance is overkill for a
non-prod target.

**Can WF-D run on a target other than the source it was captured from?**
Yes — `--target nsx-lm1` is a flag. The build step's input is the source
capture; the push step's target is whatever you pass. For cross-manager
deployments (capture from lm1, push siblings to lm3), it's a one-line
change to `--target nsx-lm3`.

---

## Status

| | State |
|---|---|
| `RUNBOOK_D.md` (this doc) | shipped 2026-06-06, refined 2026-06-07 |
| `RUNBOOK_D_COMMANDS.md` / `_PS.md` | shipped 2026-06-06 |
| `tools/nsx/build_sibling_groups.py` flag additions (`--csv-remap`, `--include-pure-ip`, `--no-stripped-originals`, `--skip-uncovered`, `--skip-segment-groups`) | **shipped 2026-06-07** |
| Audit reports (`skipped_segments.json`, `empty_groups.json`, `skipped_uncovered.json`) in build output | **shipped 2026-06-07** |
| Enriched `sibling_map.json` per-row audit (`ips_source` / `ips_sibling_mapped` / `ips_uncovered`) | **shipped 2026-06-07** |
| `data/nonprod_map.csv` | populated 2026-06-06: 17 mappings, /16-/32, covering all in-scope 10.6.x.x → 10.7.x.x |
| Pre-flight IP-report integration | shipped 2026-06-06 (sub-step 6 in `capture_nsx_state.py`) |
| **End-to-end lab validation on lm3** | **PASSED 2026-06-07** — 7 siblings created with mapped 10.7.x.x IPs only, 0 prod IP leakage, 0 collateral group changes, 0 contract violations, clean LIFO revert via single command. See "Lab validation" section below. |
| **End-to-end "clone + WF-D" lab validation on lm3** | **PASSED 2026-06-08** — single-capture flow via [RUNBOOK_FROM_CAPTURE.md](RUNBOOK_FROM_CAPTURE.md) clones lm1 to lm3 (WF-A Part 1 only — NOT Parts 2/3, which would create mixed-mode originals) and then runs WF-D. End state: 5 tag-only originals (zero IPs) + 7 IP-only siblings (mapped 10.7.x.x). **Crucial correction: WF-A Parts 2 and 3 must be skipped when WF-D is the goal.** They inject IPs into the tag groups' expression on the target — the exact mixed state WF-D is designed to eliminate. RUNBOOK_FROM_CAPTURE.md now makes Part 1 the default with a prominent warning against Parts 2+3. |
| Range-in-CIDR matching in `PrefixMappingTable` | optional follow-up — would let CIDR mappings cover range-form source IPs (e.g. `10.6.0.52/31` would auto-cover `10.6.0.52-10.6.0.53`) |
| **Pure-IP remap bundle + `--include-pure-ip` deprecation** | **shipped 2026-06-09, retired 2026-09-25.** Pure-IP groups went to a separate bundle for an in-place additive push (the former D2b). Superseded by the last row below. |
| **`validate_wf_d.py`** | **shipped 2026-06-09** — read-only G1/G2/G3/S1/S2/R1/R2 validator. Lab-tested on lm3 with positive and negative cases (G2 IP-removal and R1 missing-sibling-ref failures both caught). |
| **End-to-end re-validation on lm3 with new pure-IP-remap design + validator** | **PASSED 2026-06-09** — full pipeline 5a → 5b → 6 → validator green; rules cleanly reference siblings; no empty groups; `ip-address-group` carries both prod + mapped IPs in place. |
| **D2b retired: one sibling per non-segment group with a mapped IP** | **shipped 2026-09-25.** IP-only groups and groups that nest other groups get an `_avs_ips` sibling in D2a; no existing group is modified; hand-typed IPs are no longer copied verbatim; every group without a sibling is listed under `no_sibling`; amend-refs adds only siblings present on the target; new WF-D report layout. |

## Lab validation (2026-06-07)

End-to-end test of the full WF-D pipeline against `nsx-lm3` (blank target,
mirrors the "fresh prod manager" scenario for banks lab):

### Phase 1 — build (offline)

```bash
python tools/nsx/build_sibling_groups.py --source nsx-lm1 \
  --csv-remap data/nonprod_map.csv \
  --skip-segment-groups --no-stripped-originals \
  --label nsx-lm3.lab.local
```

> Note: this lab log also predates the removal of the Phase 2 IP strip. Any
> `nsx_stripped_groups/` bundle or stripped-original count below is a record of
> what the tool did then; it no longer produces either.
>
> Note: this lab test predates the 2026-06-09 pure-IP-remap split. At the time, `--include-pure-ip` was used and one of the 7 siblings was `ip-address-group_sibling`. That split was retired on 2026-09-25, so the current build again gives `ip-address-group` (and any other IP-only or group-nesting group with a mapped IP) a sibling.

Result: 7 siblings written, 0 stripped (suppressed), 1 segment skipped
(`segment-group-1`), 3 groups skipped as no-mapped-IPs (out-of-scope IPs
like 1.1.1.1, 10.2.1.0/24, 10.0.0.0/8), 16 mapped IPs total in siblings,
8 uncovered IPs surfaced in audit. No `nsx_stripped_groups/` directory on
disk.

### Phase 2 — dry-run

```bash
python tools/nsx/groups.py push --target nsx-lm3 \
  --groups-dir nsx_sibling_groups/nsx-lm3.lab.local/groups
```

Mode `DRY-RUN`, files_seen=7, dry_run=7, ok=0, failed=0,
contract_violations=0, additive_only_contract=`pass`,
total_ips_removed=0. No baseline captured (dry-run only).

### Phase 3 — apply

```bash
python tools/nsx/groups.py push --target nsx-lm3 \
  --groups-dir nsx_sibling_groups/nsx-lm3.lab.local/groups --apply
```

Mode `APPLY`, ok=7, failed=0, contract_violations=0,
additive_only_contract=`pass`, total_ips_removed=0. Baseline captured at
`nsx_sibling_groups/nsx-lm3.lab.local/push_report/baselines/<ts>_target_baseline.json`.

### Phase 4 — post-apply audit

| Check | Expected | Actual |
|---|---|---|
| Total customer groups on lm3 | 7 (siblings only) | **7** ✓ |
| Non-sibling customer groups (collateral) | 0 | **0** ✓ |
| All siblings carry `group_type: [IPAddress]` | yes | **yes** ✓ |
| All IPs in siblings are 10.7.x.x (mapped) | yes | **16/16** ✓ |
| Prod IPs (10.6.x.x) leaked into any sibling | none | **0** ✓ |

Per-sibling content (all confirmed live on lm3):

| Sibling | IPs |
|---|---|
| `network-6-0_sibling` | 10.7.0.101, 10.7.0.102 |
| `network-6-1_sibling` | 10.7.1.101, 10.7.1.102 |
| `network-2_sibling` | 10.7.2.101, 10.7.2.102 |
| `vm1_sibling` | 10.7.0.101, 10.7.1.101, 10.7.2.101 |
| `vm2_sibling` | 10.7.0.102, 10.7.1.102, 10.7.2.102 |
| `ip-address-group_sibling` | 10.7.0.50, 10.7.0.51, 10.7.1.0/24 |
| `super-nested-group_sibling` | 10.7.1.101 (partial — 10.2.3.0/24 and 10.5.20.5 were out of scope) |

### Phase 5 — revert

```bash
python tools/nsx/groups.py revert --target nsx-lm3 \
  --reports-dir nsx_sibling_groups/nsx-lm3.lab.local/push_report --apply
```

Result: deleted_ok=7, deleted_failed=0, restored_ok=0 (baseline captured
"no customer groups present", so revert correctly deletes-all rather than
restoring anything). Baseline file renamed to `*.reverted`.

Post-revert lm3 inventory: 0 customer groups, 3 NSX system-owned only —
exact same state as before the WF-D push.

### Backward-compatibility sanity check (same session)

Running `build_sibling_groups.py --source nsx-lm1` with **no WF-D flags**
produced an unchanged WF-C bundle: 6 siblings + 6 stripped originals + 5
skipped_no_condition + `nsx_stripped_groups/` bundle present on disk —
identical counts to pre-WF-D code.
