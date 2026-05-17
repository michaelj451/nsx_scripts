# NSX Local Manager Clone — `nsx-lm1` (live) → `nsx-lm2` (new)

## Summary

Clone the policy configuration from the **original live** NSX Local Manager
(`nsx-lm1` — has the real VMs and evaluated group memberships) onto the
**new** NSX Local Manager (`nsx-lm2`). Live VM IPs from `nsx-lm1` are
captured as static `IPAddressExpression` entries and pushed to `nsx-lm2`
as-is.

Manager roles:

| Manager | Role | NSX impact |
|---|---|---|
| `nsx-lm1` | Original live — read-only source | Read-only |
| `nsx-lm2` | New manager — apply target | PATCH/POST via file payload |
| `nsx-lm3` | Throwaway sandbox — optional testing only | None unless you choose to test against it |

Properties:

- Zero changes to the source manager (`nsx-lm1` is read-only throughout)
- Tag/dynamic group membership is resolved through NSX's evaluator — no Python tag parsing
- Every transform is offline and reviewable before push
- Dry-run is the default safe mode on every write step

Safe to repeat. Suitable for CAB-reviewed execution.

---

## 0) Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

---

## 1) Export Both Managers

Snapshot non-system NSX Policy objects (groups, services, security policies, rules) to `nsx_export/`.

### Source — original live manager

```bash
python tools/nsx/export_nsx_objects.py \
  --manager nsx-lm1 \
  --base-dir nsx_export \
  --domain-id default \
  --output-format yaml
```

### Target — new manager (captures pre-change state for rollback)

```bash
python tools/nsx/export_nsx_objects.py \
  --manager nsx-lm2 \
  --base-dir nsx_export \
  --domain-id default \
  --output-format yaml
```

Read-only against NSX. GETs are throttled (5 req/sec).

---

## 2) Resolve Live VM Membership — `nsx-lm1` → `nsx-lm2` Additive Tree

For each group on `nsx-lm1`, ask NSX *who its evaluated VM members are right
now*, look up each VM's IPs via fabric VIFs, and append them as a static
`IPAddressExpression` block (with a `ConjunctionOperator: OR` so existing
tag/condition expressions remain intact).

```bash
python tools/nsx/build_group_ip_additive_from_live_members.py \
  --source-manager nsx-lm1 \
  --domain-id default \
  --source-groups-dir nsx_export/nsx-lm1.lab.local/domains/default/groups \
  --output-groups-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \
  --output-format yaml \
  --copy-first \
  --continue-on-group-error
```

Read-only against NSX. Writes group files locally.

Result:

```text
nsx_groups_additive/
└── nsx-lm2.lab.local/
    └── domains/default/groups/
```

---

## 3) (Optional) Pre-Push Analysis

### 3a) Affected-Rule Impact Report

Generate a human-readable report listing every rule affected by the changed
groups and which subnets drive each match — useful for review and for
post-change troubleshooting.

```bash
python tools/nsx/find_rules_affected_by_group_changes.py \
  --additive-root nsx_groups_additive_a \
  --export-root nsx_export \
  --output-dir nsx_logs/affected_rule_reports \
  --verbose
```

Key output: `nsx_logs/affected_rule_reports/affected_rules_impact.json` — one
entry per rule, with the affected groups and the new subnets driving each
match.

### 3b) Segment Reference Inventory

If you only have **DFW access** on `nsx-lm2`, you cannot create segments
there. Any rule or group on `nsx-lm1` that references a segment path
(`/infra/segments/<id>`) requires the same segment to already exist on
`nsx-lm2`, or the reference will land dead.

Generate the inventory of every segment path the export depends on:

```bash
PYTHONPATH="$PWD/app" python tools/nsx/find_segments_referenced.py \
  --export-root nsx_export \
  --output-dir nsx_logs/segment_inventory \
  --verbose
```

Outputs:

| File | Purpose |
|---|---|
| `segments_inventory.json` | Full report with per-segment references — which rule/group/policy uses each segment, and which field |
| `segment_paths.txt` | Flat one-path-per-line list, suitable for handing to the network team to confirm presence on `nsx-lm2` |

**Note:** Groups that reference segments are largely mitigated by step 2 —
the live-member resolution already snapshotted resolved VM IPs into a
static `IPAddressExpression`, so the group still has the right members on
`nsx-lm2` even if the segment ref dies. The hard cases are **rules that
reference segments directly** in `source_groups`, `destination_groups`, or
`scope` — those have no IP fallback. Look at the
`referenced_by_rules` count in the inventory to spot them.

---

## 4) Assemble Complete Payload for `nsx-lm2`

Combine `nsx-lm1`'s services/policies/rules with the additive group tree
from step 2 into a self-contained build directory.

```bash
python tools/nsx/build_complete_nsx_payload.py \
  --source-manager-dir nsx_export/nsx-lm1.lab.local \
  --additive-groups-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --overwrite
```

Offline file assembly. No NSX calls.

Result:

```text
nsx_build/nsx-lm2.lab.local/
├── domains/default/
│   ├── groups/             (from additive tree — lm1 live IPs)
│   ├── services/           (from lm1)
│   └── security-policies/  (from lm1, includes rules)
```

---

## 5) Dry-Run Push to `nsx-lm2`

Preview every PATCH/POST against `nsx-lm2`. No writes.

```bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm2 \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --dry-run
```

---

## 6) Apply Push to `nsx-lm2`

Real write requires `--yes`. Pushes services, groups, policies, and rules.

```bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm2 \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --apply
```

---

## 7) Validate Live `nsx-lm2` State

Read-only comparison of live `nsx-lm2` groups against the prepared payload.

```bash
python tools/nsx/validate_nsx_groups_live.py \
  --target nsx-lm2 \
  --expected-root nsx_groups_additive/nsx-lm2.lab.local \
  --domain-id default
```

Outputs `nsx_logs/nsx_validation/<ts>_nsx-lm2_validate_live_groups/`:

- `validation_report.json` — master report
- `payload_diff_groups.json` — groups with non-IP differences
- `ip_diff_groups.json` — groups with missing/extra IPs
- `missing_groups.json` — groups expected but absent in NSX
- `extra_live_groups.json` — groups in NSX but absent from prepared payload

---

## Workflow Diagram

```text
nsx-lm1 (original live)                       nsx-lm2 (new manager)
        │                                              ▲
        │  1) export_nsx_objects.py                    │  6) push --target nsx-lm2 --yes
        ▼                                              │
nsx_export/nsx-lm1.lab.local/                          │
        │                                              │
        │  2) build_group_ip_additive_from_live_members.py
        ▼                                              │
nsx_groups_additive/nsx-lm2.lab.local/                 │
        │                                              │
        │  3) (optional) impact report                 │
        │  4) build_complete_nsx_payload.py            │
        ▼                                              │
nsx_build/nsx-lm2.lab.local/  ─────────────────────────┤
        │                                              │
        │  5) push --target nsx-lm2 --dry-run          │
        │                                              ▼
        │                                       7) validate_nsx_groups_live.py
        ▼
nsx-lm3 (sandbox) ← optional throwaway target — see below
```

---

## Safety Characteristics

| Step | NSX impact |
|---|---|
| 1 — Export | Read-only |
| 2 — Live member resolution | Read-only (policy + fabric GETs on `nsx-lm1`) |
| 3 — Impact report | Offline |
| 4 — Build payload | Offline |
| 5 — Dry-run push | Read-only (preview only) |
| 6 — Apply push | PATCH/POST to `nsx-lm2` only; `nsx-lm1` untouched |
| 7 — Validate | Read-only |

**Source manager (`nsx-lm1`) is never written to.** All mutation happens on `nsx-lm2`.

---

## Optional: Test Against `nsx-lm3` Sandbox

`nsx-lm3` is a throwaway manager — safe to break, experiment on, or wipe.
If you want to exercise the payload against it before touching `nsx-lm2`,
point `--target` at `nsx-lm3` for either dry-run or apply. The build dir
stays the same — `--target` only chooses where the API calls land.

Dry-run against the sandbox:

```bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm3 \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --dry-run
```

Real apply against the sandbox (for end-to-end testing — not production):

```bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm3 \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --yes
```

---

## Rollback

`nsx-lm2`'s pre-change state is captured at `nsx_export/nsx-lm2.lab.local/`
in step 1. If a revert is needed:

```bash
python tools/nsx/push_nsx_groups_revert.py \
  --target nsx-lm2 \
  --export-root nsx_export/nsx-lm2.lab.local \
  --domain-id default \
  --apply
```

---

# Workflow B — Live-Member Resolution + CSV Remap on `nsx-lm1`

A workflow that takes `nsx-lm1`'s groups, flattens any dynamic/tag-based
membership into static IPs by asking NSX for evaluated VM members, then
applies a CSV subnet remap and pushes the result back to `nsx-lm1`.

Groups-only push. Services, policies, and rules are not touched.

With `--mapped-only` (used here), unmapped IPs are **dropped** from the
result — only the CSV-mapped values are kept. Use this when you're staging
a remapped configuration on `nsx-lm1` for testing, not as a production
network-extension exercise.

## B.1) Export `nsx-lm1`

Captures the current state (also serves as the rollback snapshot for this workflow).

```bash
python tools/nsx/export_nsx_objects.py \
  --manager nsx-lm1 \
  --base-dir nsx_export \
  --domain-id default \
  --output-format yaml
```

## B.2) Resolve Live VM Membership → Additive Tree

For each group on `nsx-lm1`, ask NSX who its evaluated VM members are right
now, look up each VM's IPs via fabric VIFs, and append them as a static
`IPAddressExpression` block. This flattens tag/condition expressions into
static IP lists so the CSV remap in B.3 has concrete IPs to operate on.

```bash
python tools/nsx/build_group_ip_additive_from_live_members.py \
  --source-manager nsx-lm1 \
  --domain-id default \
  --source-groups-dir nsx_export/nsx-lm1.lab.local/domains/default/groups \
  --output-groups-dir nsx_groups_additive_b/nsx-lm1.lab.local/domains/default/groups \
  --output-format yaml \
  --copy-first \
  --continue-on-group-error
```

Read-only against NSX. Writes group files locally.

## B.3) Apply CSV Subnet Remap (Offline)

Read the additive tree from B.2, apply the CSV mapping
(`old_subnet,new_subnet` — longest-prefix match wins), and write the result
to a separate tree. `--mapped-only` replaces each `IPAddressExpression` IP
list with only the mapped values, dropping unmapped entries.

```bash
python tools/nsx/nsx_group_ip_remap_offline.py \
  --export-root nsx_groups_additive_b/nsx-lm1.lab.local/domains/default/groups \
  --prepared-root nsx_groups_remapped/nsx-lm1.lab.local/domains/default/groups \
  --mapping-csv data/nonprod_map.csv \
  --output-format yaml \
  --mapped-only
```

Offline only. No NSX calls.

Result:

```text
nsx_groups_remapped/
└── nsx-lm1.lab.local/
    └── domains/default/
        ├── groups/
        └── reports/
            └── group-ip-remap/
                ├── summary_update.json
                ├── groups_changed.json
                ├── groups_unchanged.json
                └── mapping_invalid_rows.json
```

## B.4) Review Reports (Optional)

```text
nsx_groups_remapped/nsx-lm1.lab.local/domains/default/reports/group-ip-remap/
```

| File | Purpose |
|---|---|
| `summary_update.json` | High-level counts: groups changed, IPs added, IPs dropped |
| `groups_changed.json` | Per-group before/after listing |
| `groups_unchanged.json` | Groups with no matching mapping rows |
| `mapping_invalid_rows.json` | CSV rows that failed validation |

Optionally generate the affected-rules impact report:

```bash
python tools/nsx/find_rules_affected_by_group_changes.py \
  --additive-root nsx_groups_remapped \
  --export-root nsx_export \
  --output-dir nsx_logs/affected_rule_reports \
  --verbose
```

## B.5) Dry-Run Push to `nsx-lm1`

Groups-only PATCH. Preview against the live `nsx-lm1`.

```bash
python tools/nsx/push_additive_group_ips.py \
  --target nsx-lm1 \
  --groups-dir nsx_groups_remapped/nsx-lm1.lab.local/domains/default/groups \
  --domain-id default \
  --dry-run
```

## B.6) Apply Push to `nsx-lm1`

```bash
python tools/nsx/push_additive_group_ips.py \
  --target nsx-lm1 \
  --groups-dir nsx_groups_remapped/nsx-lm1.lab.local/domains/default/groups \
  --domain-id default \
  --apply
```

## B.7) Validate

```bash
python tools/nsx/validate_nsx_groups_live.py \
  --target nsx-lm1 \
  --expected-root nsx_groups_remapped/nsx-lm1.lab.local \
  --domain-id default
```

## B Rollback

Revert `nsx-lm1` from the step B.1 snapshot:

```bash
python tools/nsx/push_nsx_groups_revert.py \
  --target nsx-lm1 \
  --export-root nsx_export/nsx-lm1.lab.local \
  --domain-id default \
  --apply
```

---

## Workflow A vs Workflow B

| | Workflow A — Clone `nsx-lm1` → `nsx-lm2` | Workflow B — In-place subnet add on `nsx-lm1` |
|---|---|---|
| Goal | Stand up a new manager with the same policy | Extend existing groups with additional subnets |
| Source | `nsx-lm1` (live VMs resolved via API) | `nsx-lm1` exported group files |
| Target | `nsx-lm2` (new manager) | `nsx-lm1` (same manager, in-place) |
| Scope of push | Services + groups + policies + rules | Groups only (PATCH) |
| Subnet remap | None (live IPs passed through as-is) | CSV-driven (`data/nonprod_map.csv`) |
| Behaviour | Replaces target | Additive — originals preserved |
| Push tool | `push_complete_nsx_payload.py` | `push_additive_group_ips.py` |

