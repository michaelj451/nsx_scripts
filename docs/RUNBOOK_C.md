# Runbook C — Sibling-group decomposition

## Summary

After Workflow A (clone) has landed customer policy on the target manager,
Workflow C **decomposes** tag-based groups into two siblings so the tag
criterion and the IP criterion live in independent groups, OR'd together at
the **rule** level rather than mixed inside one group's expression.

### Why

| Before (additive Workflow A Part 3) | After (Workflow C) |
|---|---|
| Group `vm1` has both a `Condition` (Tag=`1\|vm`) AND an `IPAddressExpression` ([10.6.0.101, ...]) | Group `vm1` has **only** the `Condition`. Group `vm1_sibling` has **only** the IPs. |
| Mixed-mode group — harder to reason about; changing the IP list edits the same object that the tag criterion lives on | One-criterion-per-group. The original is canonical, the sibling is the IP snapshot |
| To remap IPs, you risk editing the tag side | Remap the sibling without ever touching the tag group |
| Rule says "match vm1" | Rule says "match vm1 OR match vm1_sibling" — both groups appear in `source_groups` / `destination_groups` (and optionally `scope` via `--include-scope`) |

The sibling name is `<original_id><OBJECT_APPENDIX>` where `OBJECT_APPENDIX`
is read from `.env` (e.g. `_sibling`). Override per run with `--appendix`.

Everything is **strict-additive** except the explicit "strip IPs out of
tagged originals" step, which is gated behind `--intentional-ip-removal`
on `groups.py push`.

---

## Drift detection (pre-flight & post-flight)

If Workflow A Part 3 has been live on the target for a while, IPs may have
been added/removed by other actors (UI edits, other tools, vCenter
inventory changes flowing through dynamic-group evaluation, etc.).
**[tools/nsx/compare_group_ips.py](../tools/nsx/compare_group_ips.py)** is a
read-only diff between a REFERENCE bundle and the TARGET's live state.

```bash
# Compare lm1's groups_additive bundle against what's currently on lm2
python tools/nsx/compare_group_ips.py \
  --reference-source nsx-lm1 \
  --target nsx-lm2
```

Output goes to `nsx_drift_report/<target-host>/`:
- `drift_report.json`    — per-group rows + summary
- `drift_report.jsonl`   — one row per line (greppable)
- `drift_summary.json`   — totals only

Each row carries the full `reference_ips`, `current_ips`, `ips_added`
(on target but not in reference), `ips_removed` (in reference but not on
target), and `has_drift` boolean. Exit code is non-zero when any drift is
detected — useful for CI gates.

### Which reference to compare against

| Question | Reference to use |
|---|---|
| "Has anything changed on lm2 since the original WF-A Part 3 push?" | The groups_additive bundle from the original capture: `--reference-source nsx-lm1` |
| "Does lm2 match a specific point-in-time export?" | A saved export bundle: `--reference nsx_groups_export/.../groups` |
| "Is lm2 in sync with whatever lm1 looks like right now?" | Capture lm1 fresh, then compare: `capture_nsx_state.py --source nsx-lm1` then `--reference-source nsx-lm1` |

### Two patterns for what to do with detected drift

| Intent | Approach |
|---|---|
| **(a) Realign lm2 to current lm1** | Capture lm1 fresh → run WF-C normally with `--source nsx-lm1`. Any drift on lm2 gets overwritten with whatever's on lm1 now |
| **(b) Preserve lm2's current IPs, just decompose them** | Export lm2 fresh (`groups.py export --source nsx-lm2`), then transform from that: `build_sibling_groups.py --groups-dir nsx_groups_export/nsx-lm2.lab.local/groups`. The siblings end up with whatever IPs lm2 already has, regardless of lm1 |

## Pipeline (5 steps)

```text
1) capture_nsx_state.py                                     (read-only, GET-only)
        ↓
2) build_sibling_groups.py                                  (offline transform)
        produces nsx_sibling_groups/<host>/groups/         (new IP-only groups)
                 nsx_stripped_groups/<host>/groups/        (originals minus IPs)
                 nsx_sibling_groups/<host>/sibling_map.json
        ↓
3) groups.py push   (sibling groups → target, additive)
        ↓
4) groups.py push   (stripped originals → target, --intentional-ip-removal)
        ↓
5) rules.py amend-refs   (per rule, append sibling alongside the original)
```

Steps 3, 4, and 5 each capture a baseline and are independently revertible.

---

## Tools

| Tool | Phase | Purpose |
|---|---|---|
| [tools/nsx/capture_nsx_state.py](../tools/nsx/capture_nsx_state.py) | 1 | Standard capture (existing). Produces `groups_additive/` and `segment_inventory/` which the transform reads |
| [tools/nsx/build_sibling_groups.py](../tools/nsx/build_sibling_groups.py) | 2 | **NEW** — offline transform. Decomposes tag+IP groups into IP-only sibling + stripped original. Outputs two bundles + sibling_map.json |
| [tools/nsx/groups.py](../tools/nsx/groups.py) `push` | 3, 4 | Existing push tool. Step 3 is plain additive. Step 4 requires `--intentional-ip-removal` to allow IPs being removed from the originals |
| [tools/nsx/rules.py](../tools/nsx/rules.py) `amend-refs` | 5 | **NEW** subcommand. For every customer rule on the target, appends sibling-group paths alongside any matching original-group path in `source_groups` / `destination_groups` (and optionally `scope` via `--include-scope`). Strict-additive |

---

## Prerequisites

Workflow A Part 1 (`services.py push` + `groups.py push --segments-mode strip` + `policies.py push` + `rules.py push`) must already be applied to the target. Workflow C is the **replacement for Part 3** (additive); skip Part 2 and Part 3 of Workflow A and run Workflow C instead.

A complete Workflow A + Workflow C migration looks like:

```
EXPORT      capture + 6 per-tool exports against source
PUSH P1     services + groups (strip) + policies + rules → target     (WF-A Part 1)
TRANSFORM   build_sibling_groups.py                                    (WF-C step 2)
PUSH P3'    push siblings → target                                     (WF-C step 3)
PUSH P3''   push stripped originals → target  (--intentional-ip-removal)  (WF-C step 4)
AMEND       rules.py amend-refs → target                               (WF-C step 5)
```

WF-A Part 2 (segment-convert) is **not used** with Workflow C — segments are not part of this design.

---

## Step 2 — `build_sibling_groups.py`

Offline transform. **No NSX calls.** Reads the capture bundle, emits two bundles and one map file.

```bash
python tools/nsx/build_sibling_groups.py --source nsx-lm1
```

Outputs:

```text
nsx_sibling_groups/<host>/
├── groups/<sibling-id>.yaml          # one IP-only group per tagged-with-IPs source
├── sibling_map.json                  # { original_id → sibling_id } map for step 5
├── manifest.json
├── reports/

nsx_stripped_groups/<host>/
├── groups/<original-id>.yaml         # original groups with IPAddressExpression entries removed
└── manifest.json
```

### What gets a sibling

The transform creates a sibling **only** when the source group has BOTH:
- At least one `Condition` expression (tag-based criterion), AND
- At least one IPAddressExpression with non-empty `ip_addresses`

Groups that don't have a Condition (pure-IP, pure-segment) are skipped — there's nothing to decompose.

Sibling payload contains:
- `id`: `<original_id><OBJECT_APPENDIX>`
- `display_name`: `<original_display_name><OBJECT_APPENDIX>`
- `description`: `"IP-only sibling of <original_id>; generated <ts> by build_sibling_groups.py"`
- `expression`: a single `IPAddressExpression` with the captured IPs

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--source <alias>` | (required, or `--capture`) | NSX manager alias. Resolves to `nsx_capture/<host>/` |
| `--capture <path>` | (or `--source`) | Explicit path to a capture bundle |
| `--appendix <str>` | `OBJECT_APPENDIX` from `.env` | Override the sibling-id suffix |
| `--include-empty` | off | Also emit siblings for tagged groups with empty IP lists. Off by default — pointless siblings are skipped |
| `--domain-id` | `default` | NSX domain |
| `--output-base <dir>` | repo root | Where the two output bundles land |

---

## Step 3 — Push siblings

These are **new objects**. Plain additive — no special flags. Default batch behaviour applies (no prompting unless you pass `--batch-size N`).

```bash
python tools/nsx/groups.py push --target nsx-lm2 \
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups \
  --apply
```

Baseline is captured under `nsx_sibling_groups/<host>/push_report/baselines/` so this step is independently revertible.

### Optional — CSV-remap the sibling IPs in the same step

The sibling bundle is just a directory of plain group YAMLs with one
`IPAddressExpression` each, so the existing `--csv-remap` flag works
against it without any new code. Pass `--csv-remap` and the strict-additive
contract automatically applies:

- Originals (source IPs from the capture) are kept
- Mapped IPs from the CSV are appended
- `--mapped-only` is refused (would violate the contract)
- `--batch-size` defaults to **1** so you step through every change
- Per-row report carries `ips_before`, `ips_after`, `ips_added`, `ips_removed: []`

```bash
# Land siblings with both source IPs and CSV-mapped equivalents in one push
python tools/nsx/groups.py push --target nsx-lm2 \
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups \
  --csv-remap data/nonprod_map.csv \
  --apply
```

If you'd rather decouple — land the bare siblings first, validate, then
remap — run the same command **without** `--csv-remap` first (step 3 as
documented above), then re-run with `--csv-remap` later as a separate
phase. The auto-baseline at each push gives you independent revertibility
for each.

---

## Step 4 — Push stripped originals

Replaces each tagged-original group's payload with the stripped version. Removes any IPAddressExpression entries that were on the original. **Requires `--intentional-ip-removal`** — without it, the push refuses any row that would drop IPs.

```bash
python tools/nsx/groups.py push --target nsx-lm2 \
  --groups-dir nsx_stripped_groups/nsx-lm1.lab.local/groups \
  --intentional-ip-removal \
  --apply
```

### What `--intentional-ip-removal` does

- Allows `ips_removed` to be non-empty without failing the row.
- Defaults `--batch-size` to **1** (step-through) so the operator approves each strip individually. Bump higher at any prompt as confidence grows; type `n` to reset to 1; `x` for clean exit.
- Each row in the push report records `ips_before`, `ips_after`, and `ips_removed` (the dropped IPs) for full audit replayability.
- Cannot be combined with `--csv-remap` — those workflows have opposite intents (CSV remap is strict-additive).

Summary block records:

```json
"totals": {
  ...
  "intentional_ip_removal": true,
  "total_ips_removed": 12,
  "additive_only_contract": "n/a (intentional-ip-removal)"
}
```

---

## Step 5 — `rules.py amend-refs`

For every customer rule on the target, walks the rule's **match-criteria** fields (`source_groups` and `destination_groups` by default). For each entry that matches an `original_id` in `sibling_map.json`, **appends** the corresponding `sibling_id` to the same field. Idempotent: if the sibling is already listed, the rule is reported `no_change` and no PATCH is sent.

The rule's `scope` field (the applied-to / enforcement target) is **opt-in** via `--include-scope`. By default it is **not** amended — broadening enforcement to IP-only siblings usually isn't wanted, since the sibling carries IPs from the tag group but the rule was originally scoped to be enforced wherever the tag dynamically matches.

```bash
python tools/nsx/rules.py amend-refs --target nsx-lm2 \
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json \
  --apply
```

Add `--include-scope` if you want the sibling appended to the rule's `scope` field too:

```bash
python tools/nsx/rules.py amend-refs --target nsx-lm2 \
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json \
  --include-scope \
  --apply
```

Strict-additive — never removes a reference. Captures a baseline at `nsx_rules_export/<target-host>/push_report/baselines/` so the rule changes are independently revertible.

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--target <alias>` | required | The manager whose rules to amend |
| `--sibling-map <path>` | required | Path to `sibling_map.json` from step 2 |
| `--domain-id` | from sibling_map | NSX domain |
| `--batch-size N` | `1` when `--apply` | Step through every rule update. Same prompt vocabulary as `groups.py push`: Y/Enter/n/x/<number> |
| `--include-scope` | off | Also append sibling refs to the rule's `scope` (applied-to) field. Default off — see note above. |
| `--apply` | off (dry-run) | Required to actually PATCH rules |

### Per-row record

Each rule gets one row in `amend_refs.json` / `amend_refs.jsonl`. With the default (no `--include-scope`), only `source_groups` and `destination_groups` show up in `per_field_diff`:

```json
{
  "policy_id": "Start_Policy",
  "rule_id": "allow-icmp-network-0",
  "status": "success_patch",
  "refs_added_total": 2,
  "per_field_diff": {
    "source_groups": {
      "before": ["/infra/.../groups/hardware-subnet", "/infra/.../groups/network-6-0"],
      "after":  ["/infra/.../groups/hardware-subnet", "/infra/.../groups/network-6-0",
                 "/infra/.../groups/network-6-0_sibling"],
      "added":  ["/infra/.../groups/network-6-0_sibling"]
    },
    "destination_groups": {...}
  }
}
```

With `--include-scope`, a third `scope` entry appears in `per_field_diff` for any rule whose `scope` references an original-group that has a sibling.

---

## Revert sequence (if you need to unwind Workflow C)

In reverse order, each phase pops its baseline cleanly:

```bash
# 5. amend-refs revert — restores each rule's pre-amend payload
python tools/nsx/rules.py revert --target nsx-lm2 \
  --reports-dir nsx_rules_export/nsx-lm2.lab.local/push_report --apply

# 4. stripped-originals revert — restores the original group payloads
python tools/nsx/groups.py revert --target nsx-lm2 \
  --reports-dir nsx_stripped_groups/nsx-lm1.lab.local/push_report --apply

# 3. siblings revert — deletes the sibling groups
python tools/nsx/groups.py revert --target nsx-lm2 \
  --reports-dir nsx_sibling_groups/nsx-lm1.lab.local/push_report --apply
```

Then continue with the standard Workflow A revert chain for the underlying WF-A Part 1 (rules → policies → groups → services).

---

## Common questions

**What happens if WF-C was already run and I run it again?**
Step 5 is idempotent — rules already carrying the sibling reference become `no_change`. Step 3 will see the sibling already exists and PATCH it (additive). Step 4 will see the originals already stripped and PATCH them (no-op since target = source). Re-running is safe.

**Can I run WF-C against the same manager I captured from (in-place)?**
Yes. Pass `--target <source>` for steps 3, 4, 5. Same idempotency applies.

**Does this break anything for rules that already use `ANY`?**
No. `ANY` never matches a sibling map entry — only specific group paths trigger the amend.

**What if a rule references a group that doesn't have a sibling (e.g., a pure-IP group like `ip-address-group`)?**
The amend step ignores it — only references that map to a sibling are touched. Rules that don't reference any tagged-with-IPs group get reported `no_change`.

**Why the appendix in display_name as well as id?**
So the sibling is visually distinguishable in the NSX UI without having to compare IDs character-by-character. Matches the id pattern: `vm1` → `vm-group-1` (display) → `vm-group-1_sibling` (sibling display).
