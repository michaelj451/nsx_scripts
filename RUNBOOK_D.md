# Runbook D — In-place remap-to-siblings on a live production NSX manager

## Summary

**Workflow D** lands new IP-only sibling groups on a **live, in-service** NSX
manager. Each sibling carries the CSV-mapped equivalents of an original
group's IPs. The originals are **left completely untouched** — no IP
removal, no payload modification, no rule changes. The only NSX side
effect is the creation of new `<original_id>_sibling` group objects.

This is the production counterpart to WF-C, which decomposes in place on
a lab/non-prod target. WF-D's blast radius is bounded by "create new
objects only" so it can run during business hours against a manager
carrying real traffic, with per-step revert (delete-on-revert) available.

### Why a new workflow vs. extending WF-C

| Concern | WF-C (lab) | WF-D (live prod) |
|---|---|---|
| Strips IPs from tagged-side originals | Yes (step 4 with `--intentional-ip-removal`) | **Never.** Originals are untouched. |
| Amends live rules to OR-reference siblings | Yes (step 5) | **Not in this workflow.** Done as a separate, change-controlled phase. |
| Pure-IP groups | Skipped | **Decomposed** — sibling carries the mapped IPs, original kept. |
| Pure-segment groups | Skipped | **Skipped** (unchanged). |
| Tag+segment+IP hybrids | Decomposed (sibling=IPs, original keeps Condition+PathExpression) | **Skipped — any group with a PathExpression is left alone.** WF-D never touches segment-related groups in any form. |
| Source of IPs in the sibling | Same IPs as original (no remap) | **CSV-mapped IPs only** — the prod IPs stay on the original. |

### The end state on lm1 after WF-D

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

  ip-address-group                    ip-address-group                    (unchanged)
    expression:                         expression:
      IPAddressExpression([             IPAddressExpression([
        10.6.0.50,                        10.6.0.50,
        10.6.0.51,                        10.6.0.51,
        10.6.0.52-10.6.0.53,              10.6.0.52-10.6.0.53,
        10.6.1.0/24                       10.6.1.0/24
      ])                                ])
                                      ip-address-group_sibling            (NEW)
                                        expression:
                                          IPAddressExpression([
                                            10.7.0.50,
                                            10.7.0.51,
                                            10.7.0.52-10.7.0.53,
                                            10.7.1.0/24
                                          ])
                                        group_type: [IPAddress]
```

No existing group on lm1 is modified. Rules continue to reference the
originals exactly as they do today. The siblings sit alongside, dormant,
until a separate change activates them.

---

## Production safety stance

**The contract in one sentence:** WF-D **only** creates new
`<original_id>_sibling` group objects on lm1. It never PATCHes an
existing group, never DELETEs anything, never alters tags, never edits
rules, never touches segments.

| Constraint | How WF-D enforces it |
|---|---|
| **No IPs are EVER removed from any existing group on lm1** | Step 2 (offline build) produces siblings only — no stripped-original YAMLs. Step 3 (push) only writes new group IDs. No `--intentional-ip-removal` is ever invoked. The strict-additive contract on `groups.py push` rejects any row that would remove. |
| **No existing groups are EVER deleted** | Push uses CREATE / PUT-on-new-ID only. No DELETE operations are issued. The only thing this workflow can delete is a sibling **it just created**, and only via the explicit revert against this run's baseline. |
| **No tags altered on any VM or group** | No tagging operation in this workflow. VM tags + group object-level `tags:` metadata untouched. |
| **No rules modified on lm1** | No `rules.py amend-refs` call in WF-D. Amendment is its own change-controlled phase, scheduled separately. |
| **No segment paths modified, no segment-related groups touched** | Any group containing a `PathExpression` (at any depth) is skipped entirely. Pure-segment, tag+segment, and tag+segment+IP hybrids ALL skip. WF-D operates exclusively on non-segment groups. |
| **Every change is delete-revertible** | Step 3's baseline captures the pre-push state (= no siblings present). Revert deletes the siblings cleanly — restoring lm1 to its exact pre-WF-D state. |
| **Strict-additive contract enforced** | `groups.py push` runs without `--intentional-ip-removal`. Any row that would remove an IP is rejected. |
| **Dry-run is the default** | Every push command starts without `--apply`. The operator reviews the diff, then re-runs with `--apply`. |

### What CAN change on lm1 during WF-D

Only one thing: **new `*_sibling` group objects appear.** Nothing else.
Even rule references to those new siblings only get added in a
**separate, change-controlled** amend-refs phase that is NOT part of WF-D.

---

## Pipeline (3 steps + pre-flight)

```text
0) capture_nsx_state.py --source nsx-lm1                          (read-only, GET-only)
                                                                  + auto-runs the IP report
                                                                  + (optional) CSV coverage report
        ↓
1) build_sibling_groups.py --source nsx-lm1 \                     (offline transform)
        --csv-remap data/nonprod_map.csv \
        --include-pure-ip \
        --no-stripped-originals
        produces nsx_sibling_groups/<host>/groups/                (mapped-IP-only siblings)
                 nsx_sibling_groups/<host>/sibling_map.json
        (no nsx_stripped_groups/ output — we don't strip on prod)
        ↓
2) groups.py push                                                 (DRY-RUN first)
        --target nsx-lm1 \
        --groups-dir nsx_sibling_groups/<host>/groups
        (adds --apply when diff looks right)
```

That's it. Three steps. No WF-A Part 1/2/3. No WF-C-style strip. No rule
amendment. Each step is independently revertible.

### When you eventually want rules to reference the new siblings

That's a **separate** workflow run with its own CAB approval. The
`rules.py amend-refs` tool already exists from WF-C; you'd invoke it
against lm1's siblings in a scheduled change window:

```bash
python tools/nsx/rules.py amend-refs --target nsx-lm1 \
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json \
  --apply
```

Default still excludes `scope` (same as the post-2026-06-03 default).

---

## Tools

| Tool | Phase | Purpose | Status |
|---|---|---|---|
| [tools/nsx/capture_nsx_state.py](tools/nsx/capture_nsx_state.py) | 0 | Pre-flight capture + auto-IP-report | exists |
| [tools/nsx/report_groups_with_ips.py](tools/nsx/report_groups_with_ips.py) | 0 | CSV coverage analysis (auto-fires from capture) | exists |
| [tools/nsx/build_sibling_groups.py](tools/nsx/build_sibling_groups.py) | 1 | Offline transform | **needs WF-D-specific flags** |
| [tools/nsx/groups.py](tools/nsx/groups.py) `push` | 2 | Push siblings to lm1 | exists |

### Required script changes (before first prod run)

`build_sibling_groups.py` needs three new flags:

| Flag | Effect |
|---|---|
| `--csv-remap <path>` | Apply CSV mapping to each collected IP. Sibling's `IPAddressExpression.ip_addresses` carries the MAPPED values, not the originals. |
| `--include-pure-ip` | Relax gate 1 (the no-Condition check) so pure-IP groups also produce siblings. |
| `--no-stripped-originals` | Skip writing the `nsx_stripped_groups/...` bundle entirely. WF-D never pushes the strip step. |

Optional supporting flag:

| Flag | Effect |
|---|---|
| `--skip-uncovered` | If a group has ANY IP without a CSV mapping, skip the group entirely. Default: emit a partial sibling containing only the mapped IPs and surface the uncovered ones in `sibling_map.json` per-row as a `csv_uncovered` field for CAB review. |

These changes don't touch the existing WF-C code paths — current behavior
(decomposition without remap, with strip) stays the default.

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

## Step 1 — Build siblings (offline)

```bash
python tools/nsx/build_sibling_groups.py \
  --source nsx-lm1 \
  --csv-remap data/nonprod_map.csv \
  --include-pure-ip \
  --skip-segment-groups \
  --no-stripped-originals
```

Outputs:

```text
nsx_sibling_groups/nsx-lm1.lab.local/
├── groups/
│   ├── <gid>_sibling.yaml    ← one per decomposable group
│   └── ...
├── sibling_map.json          ← for the (later) amend-refs phase
├── manifest.json
└── reports/
    ├── csv_coverage.json     ← per-group: mapped IPs, uncovered IPs
    ├── skipped_segments.json ← every group skipped because it has a PathExpression
    └── empty_groups.json     ← every group skipped because it has no IPs to remap
```

No `nsx_stripped_groups/...` directory is created (the `--no-stripped-originals`
flag suppresses it).

### What gets decomposed

| Group shape | Sibling produced? | Why / sibling IPs |
|---|---|---|
| **Tag + IP hybrid** (Condition + IPAddressExpression, NO PathExpression) | Yes | CSV-mapped equivalents of the IPs |
| **Pure-IP** (IPAddressExpression only, NO PathExpression) | Yes (via `--include-pure-ip`) | CSV-mapped equivalents of the IPs |
| **Pure-tag** (Condition only, no IPs) | No | No IPs to remap — reported in `empty_groups.json` |
| **Pure-segment** (PathExpression only) | **No** | Has PathExpression — reported in `skipped_segments.json` |
| **Tag + segment + IP hybrid** | **No** | Has PathExpression — reported in `skipped_segments.json`. We never touch segment-related groups in WF-D. |
| **Tag + segment hybrid (no IPs)** | **No** | Has PathExpression — reported in `skipped_segments.json` |
| **Completely empty** (no expression entries) | **No** | Reported in `empty_groups.json` |

### What happens to IPs that have no CSV mapping

Default behavior (without `--skip-uncovered`): the sibling is emitted
with **only the mapped IPs**. The uncovered IPs are NOT included in the
sibling (they remain only on the original). The per-row report records
the uncovered IPs explicitly so they're auditable.

If you want any group with even one uncovered IP to be skipped entirely,
use `--skip-uncovered`.

---

## Step 2 — Push siblings to lm1 (DRY-RUN first, then APPLY)

### 2a. Dry-run

```bash
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups
```

This runs without `--apply`. The JSON output's `"mode": "DRY_RUN"` confirms
nothing was written. Review:

- `totals.files_seen` — should match Step 1's `siblings_written` count
- `totals.dry_run` — should match `files_seen` (every row would have been created)
- `totals.failed` — should be 0
- `additive_only_contract` — should be `"pass"`
- `total_ips_removed` — should be 0 (this isn't a strip push)

If any row shows `would_remove_ips > 0`, **STOP** and investigate — that's
a sign of a sibling-ID collision with an existing lm1 group.

### 2b. Operator review

For lm1 prod, recommended:

1. Eyeball 3-5 sibling YAMLs in `nsx_sibling_groups/<host>/groups/` —
   confirm the IP lists are the mapped values you expect
2. Spot-check `sibling_map.json` — confirm original→sibling correspondence
3. Eyeball the dry-run report's `per_file_report` for any anomalies
4. Have a peer review the diff before adding `--apply`

### 2c. Apply

```bash
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups \
  --apply
```

Baseline captured at `nsx_sibling_groups/<host>/push_report/baselines/`.
Pre-state of lm1 (no siblings) is now snapshotted on disk for revert.

---

## Revert sequence (if you need to back out)

Single step — delete every `*_sibling` group that this run created.

```bash
python tools/nsx/groups.py revert --target nsx-lm1 \
  --reports-dir nsx_sibling_groups/nsx-lm1.lab.local/push_report --apply
```

Since the baseline captured "no siblings present on target," the revert
**deletes** every sibling group. lm1 returns to its exact pre-WF-D state.

No downstream cleanup needed because we never modified originals or
amended rules.

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
| Pure-segment groups | Skipped (no Condition gate fails) | — |
| **Any group with a PathExpression (segment-related)** | **Skipped via `--skip-segment-groups` (default ON for WF-D)** | Omit the flag to allow tag+segment+IP hybrids to decompose (NOT recommended for prod) |
| Pure-IP groups | Decomposed via `--include-pure-ip` | Skip them by omitting the flag |
| CSV-uncovered IPs | Sibling emitted with only mapped IPs; uncovered noted in audit | `--skip-uncovered` to skip the whole group |
| Appendix | `_sibling` (from `.env` `OBJECT_APPENDIX`) | Override with `--appendix` per run |
| `group_type` on siblings | `[IPAddress]` (consistent with WF-C) | — |
| Rule amendment | **Not part of WF-D** — separate change | Run `rules.py amend-refs` in a subsequent window |
| Empty-groups handling | Reported in `empty_groups.json` for audit; no sibling produced | — |

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
| Range-in-CIDR matching in `PrefixMappingTable` | optional follow-up — would let CIDR mappings cover range-form source IPs (e.g. `10.6.0.52/31` would auto-cover `10.6.0.52-10.6.0.53`) |

## Lab validation (2026-06-07)

End-to-end test of the full WF-D pipeline against `nsx-lm3` (blank target,
mirrors the "fresh prod manager" scenario for banks lab):

### Phase 1 — build (offline)

```bash
python tools/nsx/build_sibling_groups.py --source nsx-lm1 \
  --csv-remap data/nonprod_map.csv --include-pure-ip \
  --skip-segment-groups --no-stripped-originals \
  --label nsx-lm3.lab.local
```

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
