# Runbook D — In-place remap-to-siblings on a live production NSX manager

## Summary

**Workflow D** is the production-grade flow for landing IP-only siblings
(for tag-based mixed groups) and adding mapped IPs in place (for pure-IP
groups) on a **live, in-service** NSX manager. Each phase is strict-additive
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
| Strips IPs from tagged-side originals | Yes (step 4 with `--intentional-ip-removal`) | **Optional, separate change window with `--intentional-ip-removal`** (Phase 2). Default flow never strips. |
| Amends live rules to OR-reference siblings | Yes (step 5) | **Optional, separate change window.** Strict-additive — never removes refs. |
| Pure-IP groups | Skipped | **NOT decomposed into siblings.** Instead emitted to a separate `nsx_pure_ip_remap/<host>/groups/` bundle and pushed back with `--csv-remap` so mapped IPs are added in place. No sibling, no empty group. |
| Pure-segment groups | Skipped | **Skipped** (unchanged). |
| Tag+segment+IP hybrids | Decomposed (sibling=IPs, original keeps Condition+PathExpression) | **Skipped — any group with a PathExpression is left alone.** |
| Source of IPs in the sibling | Same IPs as original (no remap) | **CSV-mapped IPs only** — the prod IPs stay on the original. |
| Post-push validation | None built in | **`validate_wf_d.py`** runs G1/G2/G3/S1/S2/R1/R2 checks against the live target. |

### The end state on lm1 after WF-D (default — no Phase 2)

```text
BEFORE:                             AFTER:
  vm1                                 vm1                                 (unchanged)
    expression:                         expression:
      Condition(Tag=app|web)              Condition(Tag=app|web)
                                      vm1_sibling                         (NEW)
                                        expression:
                                          IPAddressExpression([
                                            10.7.0.101,  ← mapped from 10.6.0.101
                                            10.7.1.101,
                                            10.7.2.101,
                                          ])
                                        group_type: [IPAddress]

  ip-address-group                    ip-address-group                    (PATCHed in place)
    expression:                         expression:
      IPAddressExpression([             IPAddressExpression([
        10.6.0.50,                        10.6.0.50,         ← preserved
        10.6.0.51,                        10.6.0.51,
        10.6.0.52-10.6.0.53,              10.6.0.52-10.6.0.53,
        10.6.1.0/24                       10.6.1.0/24,
      ])                                  10.7.0.50,         ← NEW (mapped)
                                          10.7.0.51,
                                          10.7.1.0/24
                                        ])
                                        (no sibling — pure-IP groups
                                         are updated in place, never
                                         empty after this run)
```

No existing group has IPs removed or condition stripped. Tag groups get
new sibling objects; pure-IP groups get mapped IPs added alongside their
existing IPs. Rules are not touched unless amend-refs runs in its own
change window. No groups are ever deleted.

---

## Production safety stance

**The contract in five sentences:**

1. **Groups are never deleted by any push command** — only `groups.py revert` against a "didn't-exist" baseline can DELETE a group.
2. **Rules are never deleted** by any push or amend command.
3. **IPs are never removed** from any existing group unless `--intentional-ip-removal` is explicitly passed in the optional Phase 2 step.
4. **Rule refs are never removed** by `amend-refs` — it is strict-additive and only appends sibling refs.
5. **Segment-related groups are never touched** — any group containing a `PathExpression` (at any depth) is skipped entirely.

| Constraint | How WF-D enforces it |
|---|---|
| **No groups are EVER deleted** | Push uses CREATE / PUT-on-new-ID or PATCH only. No DELETE operations are issued by any push command. The only deletion path is `groups.py revert` against the baseline (which captures "group did not exist") — and that's an operator-initiated explicit step. |
| **No IPs are removed from any group during the default flow** | The strict-additive contract on `groups.py push` rejects any row that would remove an IP. Phase 2 is the **only** flow that can remove IPs, and it requires `--intentional-ip-removal` — an explicit force flag that gates an opt-in, separate change window. |
| **No tags altered on any VM or group** | No tagging operation in this workflow. VM tags + group object-level `tags:` metadata untouched. |
| **No rules modified unless `amend-refs` runs** | Rule amendment is its own change-controlled phase. When it runs, the default behavior is strict-additive — appends sibling refs to `source_groups` and `destination_groups` only, never removes anything. |
| **No segment paths modified, no segment-related groups touched** | Any group containing a `PathExpression` (at any depth) is skipped entirely. Pure-segment, tag+segment, and tag+segment+IP hybrids ALL skip. WF-D operates exclusively on non-segment groups. |
| **Every change is revertible** | Each push captures its own baseline. LIFO revert in reverse order restores any intermediate state. |
| **Strict-additive contract enforced** | `groups.py push` runs without `--intentional-ip-removal` in the default flow. Any row that would remove an IP is rejected. |
| **Dry-run is the default** | Every push command starts without `--apply`. The operator reviews the diff, then re-runs with `--apply`. |
| **Post-push validator confirms the contracts held** | `validate_wf_d.py` checks G1/G2/G3/S1/S2/R1/R2 against the live target after each push window. CRITICAL findings = the contract was violated. |

### What CAN change on lm1 during each WF-D phase

| Phase | What changes |
|---|---|
| 2a (push siblings) | New `*_sibling` group objects appear |
| 2b (pure-IP remap) | Existing pure-IP groups get mapped IPs added (`csv_total_added_values` rows in the report). No IP is ever removed. |
| 3 (amend-refs) | Existing rules get sibling refs appended to `source_groups`/`destination_groups`. No ref is ever removed. |
| 4 (validator) | Read-only — no NSX writes. |
| 5 (Phase 2 forced strip) | IPs are removed from tag-side originals whose siblings exist. **Only path with removal**, gated by `--intentional-ip-removal`. |

---

## Pipeline (7 phases — phase 2a is the only mandatory one)

```text
0)  capture_nsx_state.py --source nsx-lm1                              (read-only, GET-only)
                                                                       + auto-runs IP report w/ CSV coverage
        ↓
1)  build_sibling_groups.py --source nsx-lm1 \                         (offline transform)
        --csv-remap data/nonprod_map.csv \
        --skip-segment-groups \
        --no-stripped-originals
        produces nsx_sibling_groups/<host>/groups/                     (siblings for tag+IP mixed groups)
                 nsx_sibling_groups/<host>/sibling_map.json
                 nsx_pure_ip_remap/<host>/groups/                      (NEW — pure-IP groups for in-place remap)
        ↓
2a) groups.py push                                                     (MANDATORY — DRY-RUN first)
        --target nsx-lm1 \
        --groups-dir nsx_sibling_groups/<host>/groups
        ↓
2b) groups.py push                                                     (OPTIONAL — separate change window)
        --target nsx-lm1 \
        --groups-dir nsx_pure_ip_remap/<host>/groups \
        --csv-remap data/nonprod_map.csv
        ↓
3)  rules.py amend-refs                                                (OPTIONAL — separate change window)
        --target nsx-lm1 \
        --sibling-map nsx_sibling_groups/<host>/sibling_map.json
        ↓
4)  validate_wf_d.py                                                   (RECOMMENDED after each window)
        --target nsx-lm1 \
        --baseline nsx_sibling_groups/<host>/push_report/baselines/<ts>_target_baseline.json \
        --sibling-map nsx_sibling_groups/<host>/sibling_map.json
        ↓
5)  groups.py push --intentional-ip-removal                            (OPTIONAL, FORCED, separate window)
        --target nsx-lm1 \
        --groups-dir nsx_stripped_groups/<host>/groups
```

Only **2a** is strictly required to call this run "WF-D applied." Every
other phase is independent, deferrable, and revertible. The phasing maps
to change-window cadence — operators typically space 2a → 2b → 3 → 5
across days or weeks based on how much risk they want to absorb per
window.

---

## Tools

| Tool | Phase | Purpose |
|---|---|---|
| [tools/nsx/capture_nsx_state.py](../tools/nsx/capture_nsx_state.py) | 0 | Pre-flight capture + auto-IP-report + flat-export bundles |
| [tools/nsx/report_groups_with_ips.py](../tools/nsx/report_groups_with_ips.py) | 0 | CSV coverage analysis (auto-fires from capture) |
| [tools/nsx/build_sibling_groups.py](../tools/nsx/build_sibling_groups.py) | 1 | Offline transform — emits siblings + pure-IP remap bundle |
| [tools/nsx/groups.py](../tools/nsx/groups.py) `push` | 2a, 2b, 5 | Push siblings (2a) / pure-IP remap with `--csv-remap` (2b) / forced strip with `--intentional-ip-removal` (5) |
| [tools/nsx/rules.py](../tools/nsx/rules.py) `amend-refs` | 3 | Append sibling refs to rules' source/destination groups (strict-additive) |
| [tools/nsx/validate_wf_d.py](../tools/nsx/validate_wf_d.py) | 4 | Post-push validator — G1/G2/G3/S1/S2/R1/R2 checks against live target |

### Key flags on `build_sibling_groups.py`

| Flag | Effect |
|---|---|
| `--csv-remap <path>` | Apply CSV mapping to each collected IP. Sibling's `IPAddressExpression.ip_addresses` carries the MAPPED values only. Pure-IP groups emitted to remap bundle (not decomposed). |
| `--skip-segment-groups` | Skip any group with a `PathExpression` anywhere. Recorded in `reports/skipped_segments.json`. |
| `--no-stripped-originals` | Skip writing the `nsx_stripped_groups/...` bundle entirely (default in WF-D). Add Phase 2 by rebuilding without this flag. |
| `--skip-uncovered` | If a group has ANY IP without a CSV mapping, skip the group entirely. Default: emit a partial sibling containing only the mapped IPs and surface the uncovered ones in `sibling_map.json`. |
| `--include-pure-ip` | **Deprecated, ignored.** Pure-IP groups now always go to the `nsx_pure_ip_remap/` bundle instead of producing siblings. |

---

## Prerequisites

| | Required state |
|---|---|
| `data/nonprod_map.csv` | Populated with all IP mappings in scope. Coverage verified via the IP report (no `groups_partially_covered_by_csv` or `groups_uncovered_by_csv` for in-scope groups). |
| `nsx_capture/nsx-lm1.lab.local/` | Fresh capture taken **on the day of the push** (re-capture is free, eliminates source-drift risk). |
| `tools/nsx/build_sibling_groups.py` | Updated with the WF-D flags above (`--csv-remap`, `--include-pure-ip`, `--no-stripped-originals`). |
| Operator credentials | NSX manager creds with policy/write permissions on lm1. |
| Change window | Off-peak preferred. The push is strict-additive (only CREATE operations), but each create triggers an effective-member recompute. |
| Rollback rehearsed | Step 3 revert tested against a lab-equivalent state first. |

---

## Step 0 — Pre-flight (read-only)

### 0a. Fresh capture of lm1

```bash
python tools/nsx/capture_nsx_state.py --source nsx-lm1 \
  --ip-report-csv data/nonprod_map.csv
```

This GETs lm1's current state, runs the IP-additive enrichment (so
sub-step 6's IP report sees the spliced VM IPs), and writes the report
with CSV coverage to `$NSX_LOG_DIR/groups_ip_report/nsx-lm1.lab.local/`.

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
  --csv-remap data/nonprod_map.csv \
  --skip-segment-groups \
  --no-stripped-originals
```

Outputs:

```text
nsx_sibling_groups/nsx-lm1.lab.local/
├── groups/<gid>_sibling.yaml    ← one per tag+IP mixed group (sibling)
├── sibling_map.json             ← for amend-refs (step 3) and validator (step 4)
├── manifest.json
└── reports/
    ├── skipped_segments.json    ← every group skipped because PathExpression present
    ├── empty_groups.json        ← every group with no IPs to remap
    └── skipped_uncovered.json   ← (with --skip-uncovered) any group skipped for incomplete coverage

nsx_pure_ip_remap/nsx-lm1.lab.local/
├── groups/<gid>.yaml            ← NEW — pure-IP groups, copies of source YAMLs
├── manifest.json                ← per-group audit + suggested push command
└── push_report/                 ← created by step 2b
```

No `nsx_stripped_groups/...` directory is created (the
`--no-stripped-originals` flag suppresses it; remove the flag if you
plan to run Phase 2 in step 5).

### What goes where, by group shape

| Group shape | Action | Where |
|---|---|---|
| **Tag + IP hybrid** (Condition + IPAddressExpression, NO PathExpression) | Decompose into sibling | `nsx_sibling_groups/<host>/groups/` |
| **Pure-IP** (IPAddressExpression only, NO PathExpression) | Emit copy to remap bundle for in-place `--csv-remap` push | `nsx_pure_ip_remap/<host>/groups/` |
| **Pure-tag** (Condition only, no IPs) | Skipped — no IPs to remap | reports/empty_groups.json |
| **Pure-segment** (PathExpression only) | Skipped — never touched | reports/skipped_segments.json |
| **Tag + segment + IP hybrid** | Skipped — has PathExpression | reports/skipped_segments.json |
| **Tag + segment hybrid (no IPs)** | Skipped — has PathExpression | reports/skipped_segments.json |
| **Completely empty** (no expression entries) | Skipped | reports/empty_groups.json |

### What happens to IPs that have no CSV mapping

Default (without `--skip-uncovered`): the sibling is emitted with only
the mapped IPs; uncovered IPs are NOT in the sibling (they stay only
on the original). Per-row `ips_uncovered` in `sibling_map.json` audits
exactly which IPs were left behind.

With `--skip-uncovered`: any group with even one uncovered IP is
skipped entirely (no sibling, audit row in `skipped_uncovered.json`).

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

## Step 2b — Pure-IP remap (OPTIONAL, separate change window)

Pushes the source's pure-IP groups back to lm1 with `--csv-remap`. The
push is **strict-additive**: mapped IPs are added alongside existing
IPs; no IP is ever removed. Pure-IP groups end up holding both the
source IPs and their CSV-mapped equivalents.

When to **run** 2b:
- Your CSV covers IPs in pure-IP groups (e.g. `ip-address-group` has
  `10.6.0.50` which is mapped to `10.7.0.50`)
- You want rules referencing pure-IP groups to match the non-prod IP
  range too

When to **skip** 2b:
- Your CSV doesn't cover any IPs in your pure-IP groups (the push
  would be a no-op)
- You want a phased rollout: land siblings first (step 2a), validate,
  run 2b later in its own change window

```bash
# Dry-run
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_pure_ip_remap/nsx-lm1.lab.local/groups \
  --csv-remap data/nonprod_map.csv

# Apply
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_pure_ip_remap/nsx-lm1.lab.local/groups \
  --csv-remap data/nonprod_map.csv --apply
```

Confirm: `additive_only_contract: "pass"`, `total_ips_removed: 0`,
`csv_groups_changed > 0`. Baseline at
`nsx_pure_ip_remap/<host>/push_report/baselines/`.

---

## Step 3 — Rule amendment (OPTIONAL, separate change window)

Strict-additive — appends sibling refs to `source_groups` and
`destination_groups` of every rule that references an original. Never
removes any existing ref. Never deletes a rule.

```bash
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
| **G2** | No IP present in any baseline group was removed (or, with `--phase-2-applied`, only tag-side originals were stripped and their siblings carry the mapped values) |
| **G3** | Every Condition / PathExpression in baseline groups is still present |
| **S1** | Every (original, sibling) pair from `sibling_map.json` exists on the target |
| **S2** | Every sibling carries `group_type: [IPAddress]` |
| **R1** | Every rule referencing an original-with-sibling also references the sibling (amend-refs completeness) |
| **R2** | (with `--rules-baseline`) Every customer rule in baseline still exists |

Exit code: `0` = all pass; `1` = at least one CRITICAL finding.

Re-run after each step (2a / 2b / 3 / 5) for full coverage. After step
5, add `--phase-2-applied` so the validator downgrades the expected
IP-removal findings on tag-side originals from CRITICAL to INFO.

---

## Step 5 — Phase 2 forced strip (OPTIONAL, FORCED, separate change window)

> ⚠️ **The only flow that REMOVES IPs from existing groups.** Gated by
> `--intentional-ip-removal`. Use only when:
>
> 1. Steps 2a + 3 have been applied and validated
> 2. You have CAB approval to strip IPs from tag-side originals so
>    enforcement migrates fully to the sibling groups
> 3. The siblings have been observed matching expected traffic in
>    production for some validation period
>
> **Groups themselves are never deleted by this step.** Only
> `IPAddressExpression` entries inside existing tag-side originals are
> removed. The groups stay (Condition-only afterward).

### 5a. Rebuild the bundle WITH stripped originals

The default WF-D build uses `--no-stripped-originals`. For Phase 2,
rebuild without that flag so `nsx_stripped_groups/<host>/groups/` is
produced:

```bash
python tools/nsx/build_sibling_groups.py \
  --source nsx-lm1 \
  --csv-remap data/nonprod_map.csv \
  --skip-segment-groups
  # NOTE: --no-stripped-originals deliberately OMITTED
```

### 5b. Push stripped originals — REQUIRES `--intentional-ip-removal`

```bash
# Dry-run
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_stripped_groups/nsx-lm1.lab.local/groups \
  --intentional-ip-removal

# Apply
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_stripped_groups/nsx-lm1.lab.local/groups \
  --intentional-ip-removal \
  --apply
```

Without `--intentional-ip-removal`, every row is rejected as a
`contract_violation`. The flag must be passed explicitly.

### 5c. Re-validate with Phase-2 awareness

```bash
python tools/nsx/validate_wf_d.py \
  --target nsx-lm1 \
  --baseline nsx_sibling_groups/nsx-lm1.lab.local/push_report/baselines/<ts>_target_baseline.json \
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json \
  --phase-2-applied
```

---

## Revert (LIFO — reverse order)

Each phase has its own baseline. Revert in reverse order to avoid
dangling rule refs (if amend-refs ran, revert it before deleting any
sibling — NSX 409s on DELETE for groups still referenced by rules).

```bash
# Phase 5 revert (restores IPs to tag-side originals)
python tools/nsx/groups.py revert --target nsx-lm1 \
  --reports-dir nsx_stripped_groups/nsx-lm1.lab.local/push_report --apply

# Phase 3 revert (restores rules to pre-amend state — removes sibling refs)
python tools/nsx/rules.py revert --target nsx-lm1 \
  --reports-dir nsx_rules_export/nsx-lm1.lab.local/push_report --apply

# Phase 2b revert (restores pure-IP groups to pre-remap state — removes mapped IPs)
python tools/nsx/groups.py revert --target nsx-lm1 \
  --reports-dir nsx_pure_ip_remap/nsx-lm1.lab.local/push_report --apply

# Phase 2a revert (deletes the *_sibling groups)
python tools/nsx/groups.py revert --target nsx-lm1 \
  --reports-dir nsx_sibling_groups/nsx-lm1.lab.local/push_report --apply
```

Each command pops the most recent unreverted baseline for that stack.

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
| **Any group with a PathExpression** | **Skipped via `--skip-segment-groups`** (recommended for prod) | Omit the flag to allow tag+segment+IP hybrids to decompose (NOT recommended for prod) |
| **Pure-IP groups** | **Emitted to `nsx_pure_ip_remap/` for in-place additive CSV-remap push (step 2b)** | Skip step 2b entirely if no mapped IPs are wanted on pure-IP groups |
| CSV-uncovered IPs | Sibling emitted with only mapped IPs; uncovered noted in audit | `--skip-uncovered` to skip the whole group |
| Appendix | `_sibling` (from `.env` `OBJECT_APPENDIX`) | Override with `--appendix` per run |
| `group_type` on siblings | `[IPAddress]` (consistent with WF-C) | — |
| Rule amendment (step 3) | **Optional, separate change window** — strict-additive | Skip; rules continue to reference originals only |
| Empty-groups handling | Reported in `empty_groups.json`; no sibling, no remap entry | — |
| Phase 2 forced strip (step 5) | **Optional, FORCED, separate change window** — requires `--intentional-ip-removal` | Skip; tag-side originals keep their IPs alongside the new siblings |
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
| **Pure-IP remap bundle + `--include-pure-ip` deprecation** | **shipped 2026-06-09** — pure-IP groups now go to `nsx_pure_ip_remap/<host>/groups/` for in-place additive CSV-remap push instead of being decomposed into siblings (which left empty originals after a Phase 2 strip). |
| **`validate_wf_d.py`** | **shipped 2026-06-09** — read-only G1/G2/G3/S1/S2/R1/R2 validator. Lab-tested on lm3 with positive and negative cases (G2 IP-removal and R1 missing-sibling-ref failures both caught). |
| **End-to-end re-validation on lm3 with new pure-IP-remap design + validator** | **PASSED 2026-06-09** — full pipeline 5a → 5b → 6 → validator green; rules cleanly reference siblings; no empty groups; `ip-address-group` carries both prod + mapped IPs in place. |

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

> Note: this lab test predates the 2026-06-09 pure-IP-remap split — at the time, `--include-pure-ip` was used and one of the 7 siblings was `ip-address-group_sibling`. The current build produces 6 siblings + a 4-entry pure-IP remap bundle (see "End-to-end re-validation on lm3" row in the Status table above for the updated counts).

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
