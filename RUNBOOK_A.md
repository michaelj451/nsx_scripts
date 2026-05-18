# Runbook A — Clone `nsx-lm1` (live) → `nsx-lm2` (new)

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
nsx_groups_additive_a/
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

To also pull live segment details (subnets, VLAN IDs, transport zone, type, gateway address) from `nsx-lm1`, add `--source-manager`. The live-fetch is wrapped in try/except — if you lack segment-read permission, the tool logs a warning and still produces the path-only inventory:

```bash
python tools/nsx/find_segments_referenced.py \
  --export-root nsx_export \
  --source-manager nsx-lm1 \
  --output-dir nsx_logs/segment_inventory \
  --verbose
```

Outputs:

| File | Purpose |
|---|---|
| `segments_inventory.json` | Full report with per-segment references — which rule/group/policy uses each segment, and which field. Includes `details` block when `--source-manager` succeeded (subnets, VLANs, TZ path, gateway). |
| `segment_paths.txt` | Flat one-path-per-line list, suitable for handing to the network team to confirm presence on `nsx-lm2`. |
| `segment_details.json` | Flat list of fetched segment objects with subnet/VLAN/TZ info. Only written when `--source-manager` succeeds. |

**Note:** Groups that reference segments are largely mitigated by step 2 —
the live-member resolution already snapshotted resolved VM IPs into a
static `IPAddressExpression`, so the group still has the right members on
`nsx-lm2` even if the segment ref dies. The hard cases are **rules that
reference segments directly** in `source_groups`, `destination_groups`, or
`scope` — those have no IP fallback. Look at the
`referenced_by_rules` count in the inventory to spot them.

---

## 4) (Optional) Transform Segment References

If you have DFW-only access on `nsx-lm2` and segments referenced in groups
will not exist on the target, run `transform_group_segments.py` against the
additive tree from step 2. The transformed output is written to a separate
directory so you can diff/review before it goes into the build dir.

Two modes:

**Mode `strip`** — offline. Remove `/infra/segments/*` and
`/global-infra/segments/*` from every `PathExpression.paths` list, drop any
PathExpression that ends up empty, and clean up adjacent
`ConjunctionOperator` entries so the expression list stays NSX-valid.

```bash
PYTHONPATH="$PWD/app" python tools/nsx/transform_group_segments.py \
  --input-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \
  --output-dir nsx_groups_transformed/nsx-lm2.lab.local/domains/default/groups \
  --mode strip \
  --overwrite
```

**Mode `convert`** — fetches each segment from `nsx-lm1` and replaces the
segment reference with an `IPAddressExpression` containing the segment's
subnet CIDR(s). Groups become IP-address groups that resolve on `nsx-lm2`
without the segments existing there.

```bash
PYTHONPATH="$PWD/app" python tools/nsx/transform_group_segments.py \
  --input-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \
  --output-dir nsx_groups_transformed/nsx-lm2.lab.local/domains/default/groups \
  --mode convert \
  --source-manager nsx-lm1 \
  --overwrite
```

Behavior per `PathExpression` in `convert` mode:

| Case | Result |
|---|---|
| Paths contain only segments, all resolved | Replace the `PathExpression` in-place with an `IPAddressExpression` containing the union of those subnets |
| Paths contain only segments, some/all unresolved | Drop only the unresolved segments. If anything resolved, use those; otherwise drop the expression (same as `strip` mode) |
| Paths contain a mix of segments and non-segment paths | Keep the modified `PathExpression` with non-segment paths intact; append a new `IPAddressExpression` (joined by `OR`) for the resolved subnets |

The live fetch in `convert` mode is wrapped in try/except — if the API
call fails (no permission, network, etc.), the run automatically falls
back to plain `strip` behavior and logs the reason.

**Report**: `nsx_logs/transform_group_segments/<ts>/segments_stripped.json`
contains per-group `paths_stripped`, `segments_converted` (with resolved
subnets), `unresolved_segment_paths`, and `path_expressions_dropped`.

**Review tip**: diff the input and output trees before moving on:

```bash
diff -r \
  nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \
  nsx_groups_transformed/nsx-lm2.lab.local/domains/default/groups
```

If you don't run this step, point step 5 at the original additive tree
from step 2 (no transformation).

---

## 5) Assemble Complete Payload for `nsx-lm2`

Combine `nsx-lm1`'s services/policies/rules with the (optionally
transformed) additive group tree into a self-contained build directory.

```bash
python tools/nsx/build_complete_nsx_payload.py \
  --source-manager-dir nsx_export/nsx-lm1.lab.local \
  --additive-groups-dir nsx_groups_transformed/nsx-lm2.lab.local/domains/default/groups \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --overwrite
```

If you skipped step 4, use the un-transformed tree instead:

```bash
  --additive-groups-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \
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

## 6) Dry-Run Push to `nsx-lm2`

Preview every PATCH/POST against `nsx-lm2`. No writes.

```bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm2 \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --dry-run
```

---

## 7) Apply Push to `nsx-lm2`

Real write requires `--apply`. Pushes services, groups, policies, and rules.

```bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm2 \
  --build-dir nsx_build/nsx-lm2.lab.local \
  --domain-id default \
  --apply
```

---

## 8) Validate Live `nsx-lm2` State

Read-only comparison of live `nsx-lm2` groups against the prepared payload.

```bash
python tools/nsx/validate_nsx_groups_live.py \
  --target nsx-lm2 \
  --expected-root nsx_groups_transformed/nsx-lm2.lab.local \
  --domain-id default
```

If you skipped step 4, point `--expected-root` at `nsx_groups_additive_a/nsx-lm2.lab.local` instead.

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
        │  1) export_nsx_objects.py                    │  7) push --target nsx-lm2 --apply
        ▼                                              │
nsx_export/nsx-lm1.lab.local/                          │
        │                                              │
        │  2) build_group_ip_additive_from_live_members.py
        ▼                                              │
nsx_groups_additive_a/nsx-lm2.lab.local/               │
        │                                              │
        │  3) (optional) impact + segment reports      │
        │  4) (optional) transform_group_segments.py   │
        ▼                                              │
nsx_groups_transformed/nsx-lm2.lab.local/              │
        │                                              │
        │  5) build_complete_nsx_payload.py            │
        ▼                                              │
nsx_build/nsx-lm2.lab.local/  ─────────────────────────┤
        │                                              │
        │  6) push --target nsx-lm2 --dry-run          │
        │                                              ▼
        │                                       8) validate_nsx_groups_live.py
        ▼
nsx-lm3 (sandbox) ← optional throwaway target — see below
```

---

## Safety Characteristics

| Step | NSX impact |
|---|---|
| 1 — Export | Read-only |
| 2 — Live member resolution | Read-only (policy + fabric GETs on `nsx-lm1`) |
| 3 — Pre-push analysis | Read-only (optional segment-detail fetch from `nsx-lm1`) |
| 4 — Transform segments | Read-only (optional fetch from `nsx-lm1` for `convert` mode) |
| 5 — Build payload | Offline |
| 6 — Dry-run push | Read-only (preview only) |
| 7 — Apply push | PATCH/POST to `nsx-lm2` only; `nsx-lm1` untouched |
| 8 — Validate | Read-only |

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
  --apply
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
