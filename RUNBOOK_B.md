# Runbook B — In-place on `nsx-lm1` (broken-out scripts)

## Summary

Workflow B operates **in-place against `nsx-lm1`** — no clone happens.
It's used to mutate `nsx-lm1`'s groups in two complementary ways:

| Pattern | What it does | Workflow B use case |
|---|---|---|
| **CSV IP remap** | Rewrite IPs inside existing `IPAddressExpression` entries via a subnet-mapping CSV | Stand up a nonprod copy by re-IPing prod groups (`--mapped-only`) or augment with the new IP space (default additive) |
| **`add-mapped` segment CIDRs** | For each segment path in a group's `PathExpression`, look up the segment's native CIDR, run it through the CSV, splice the mapped CIDR as an OR'd `IPAddressExpression` alongside the original ref | Make `nsx-lm1`'s groups also recognise the lm2-equivalent subnet ranges without removing the existing segment membership |

Both patterns are exposed by the **same** broken-out tool — `groups.py push` — and can be combined in a single run. Groups-only; services, policies, rules, and segments themselves are not touched.

The workflow is **two steps** with one human-review gate between them:

```text
1) capture_nsx_state.py                            (touches nsx-lm1, GET only)
        ↓  review the capture bundle
2) groups.py push --target nsx-lm1 ...             (in-place PATCH on nsx-lm1)
        ↓  review the push report
3) groups.py revert --target nsx-lm1 ... (optional, if you need to roll back)
```

Manager roles:

| Manager   | Role | NSX impact |
|-----------|------|------------|
| `nsx-lm1` | Source AND target — read for capture, PATCH at push | Read + groups-only PATCH (no services/policies/rules) |

Properties:

- **Source manager is only touched in two phases: capture, then push.** Everything between (`groups_additive` synthesis, CSV remap, segment lookup) is offline.
- Live VM membership is resolved by NSX at capture time and frozen to disk in `groups_additive/`.
- All transformations are deterministic and reviewable in the bundle before push.
- Dry-run is the default safe mode. `--apply` is required to actually mutate.
- Every push writes a `summary.json` + per-class JSON + log files into a `push_report/` directory and **captures a baseline** of the target's pre-push state for revert.

---

## Tools

| Tool | Used in | Purpose |
|---|---|---|
| [tools/nsx/capture_nsx_state.py](tools/nsx/capture_nsx_state.py) | CAPTURE | Orchestrator: produces `groups_additive/` + `segment_details.json` |
| [tools/nsx/groups.py](tools/nsx/groups.py) | PUSH, REVERT | `push` with `--csv-remap` and/or `--segments-mode add-mapped`. `revert` pops the captured baseline. |

That's it. Workflow B is groups-only by design.

---

## Env

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

PowerShell equivalent:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\app"
```

---

## B.1) Capture — read-only snapshot of `nsx-lm1`

```bash
python tools/nsx/capture_nsx_state.py --source nsx-lm1
```

Output bundle (everything Workflow B needs lives here):

```text
nsx_capture/nsx-lm1.lab.local/
├── manifest.json
├── summary.txt
├── nsx_export/<host>/                   ← raw NSX policy state
├── groups_additive/                     ← groups with captured (snapshot-at-export-time) VM IPs
│   └── domains/default/groups/<short>.yaml
├── segment_inventory/                   ← path → CIDR map (required by add-mapped)
│   └── segment_details.json
├── affected_rule_reports/                ← rules ↔ groups impact reference
├── vm_tag_inventory/
└── logs/
```

### Review gate after CAPTURE

- `summary.txt` — all sub-steps OK
- `manifest.json` — `"ok": true`
- `affected_rule_reports/affected_rules_impact.json` — which rules touch which groups you're about to mutate

---

## B.2) Push — in-place against `nsx-lm1`

### Pattern 1 — CSV IP remap (re-IP existing static IPs)

Rewrites every IP in `IPAddressExpression` entries using the CSV. Default
behavior is **additive** (mapped values appended alongside originals).
With `--mapped-only`, only the mapped values are kept (true re-IP, drops
originals).

```bash
# Dry-run (default — safe, no writes)
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --csv-remap data/nonprod_map.csv \
  --mapped-only

# Apply
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --csv-remap data/nonprod_map.csv \
  --mapped-only \
  --apply
```

### Pattern 2 — `add-mapped` segment CIDRs

For each segment path in a group's `PathExpression`, look up the segment's
CIDR (from `segment_details.json`), run it through the CSV, and **add**
the mapped CIDR as a new `IPAddressExpression` after the PathExpression
(joined by `OR`). The original PathExpression is left intact.

Requires both `--segments-from` and `--csv-remap`.

```bash
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --segments-mode add-mapped \
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json \
  --csv-remap data/nonprod_map.csv \
  --apply
```

What the group looks like after:

```yaml
# Before:
expression:
  - resource_type: PathExpression
    paths: [/infra/segments/<id-A>]    # native CIDR 10.6.1.0/24

# After add-mapped:
expression:
  - resource_type: PathExpression
    paths: [/infra/segments/<id-A>]    # unchanged — still matches lm1-side VMs
  - resource_type: ConjunctionOperator
    conjunction_operator: OR
  - resource_type: IPAddressExpression
    ip_addresses: [10.7.1.0/24]        # NEW — CSV-mapped equivalent of the segment's CIDR
```

**Unmapped segments** (CIDR not covered by any CSV row, or segment not in `segment_details.json`) are skipped — no IPAddressExpression is added for them — and recorded in `<push_report>/segments_unmapped.json` for operator follow-up. The original PathExpression entry stays.

### Pattern 3 — Both at once

CSV remap of existing IP expressions AND add-mapped for segment-referencing groups in one push:

```bash
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --segments-mode add-mapped \
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json \
  --csv-remap data/nonprod_map.csv \
  --mapped-only \
  --apply
```

### Push flags (Workflow B)

| Flag | Default | Purpose |
|---|---|---|
| `--target nsx-lm1` | (required) | Push target — for Workflow B, same as the capture source |
| `--groups-dir <bundle>` | (required) | Path to the groups directory inside the capture bundle |
| `--csv-remap <csv>` | off | Apply CSV subnet mapping to `IPAddressExpression` IPs |
| `--mapped-only` | off | With `--csv-remap`: replace each IPAddressExpression with only the mapped values; drop unmapped originals |
| `--bidirectional` | off | With `--csv-remap`: treat each CSV row as a bidirectional mapping |
| `--segments-mode {keep,strip,convert,add-mapped}` | `keep` | `add-mapped` is the Workflow B mode that splices CSV-mapped CIDRs after `PathExpression` |
| `--segments-from <json>` | (required for convert / add-mapped) | Path to `segment_details.json` from the capture bundle |
| `--apply` | off | Required to actually mutate. Default is dry-run. |

### Review gates after push

- `<push_report>/summary.json` — totals: ok / failed / skipped / dry_run / `csv_groups_changed` / `add_mapped_groups_affected` / `add_mapped_unmapped_lookups` / `retry_rounds`
- `<push_report>/groups.jsonl` — per-group rows
- `<push_report>/<tool>_push_<ts>.log` — interleaved INFO log
- `<push_report>/<tool>_push_<ts>.errors.log` — ERROR-only filtered file
- `<push_report>/segments_unmapped.json` — present only when `add-mapped` couldn't resolve a CSV mapping for some segment
- `<push_report>/fabric_paths_stripped.json` — present only if any group had host/edge-TN refs auto-stripped
- `<push_report>/baselines/<RUN_TS>_target_baseline.json` — pre-push snapshot used by revert

---

## CSV format

Each row: `old_subnet,new_subnet`. Longest-prefix match wins.

```csv
old_subnet,new_subnet
10.6.0.101/32,10.7.0.101/32
10.6.1.0/24,10.7.1.0/24
10.6.0.0/16,10.7.0.0/16
```

See `data/nonprod_map.csv` for the lab example.

- More-specific rows beat less-specific rows (the `/32` beats the `/24` which beats the `/16` when an IP is covered by all three).
- A token (IP or CIDR) that doesn't fall inside any row is **not mapped**. With `--mapped-only` it's dropped; without it, the original is kept.

---

## B.3) Revert — restore `nsx-lm1` to its pre-push state

```bash
python tools/nsx/groups.py revert --target nsx-lm1 \
  --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report \
  --apply
```

Each revert pops the most recent unreverted baseline file
(`<RUN_TS>_target_baseline.json`) and PUTs the captured payload back, plus
deletes anything that exists on the target but wasn't in the baseline.
After success, the baseline file is renamed `<RUN_TS>_target_baseline.json.reverted`.

If you've stacked multiple Workflow B pushes, each `revert` undoes the
latest. Repeat until you're back where you want to be:

```bash
# How many unreverted Workflow B baselines exist?
find nsx_capture/nsx-lm1.lab.local/groups_additive -path "*/baselines/*.json" -not -name "*.reverted"
```

---

## Workflow diagram

```text
nsx-lm1 (source AND target)
      ▲          │
      │          │  B.1) capture_nsx_state.py
      │          ▼
      │     nsx_capture/nsx-lm1.lab.local/
      │        nsx_export/, groups_additive/, segment_inventory/, ...
      │          │
      │          │  B.2) groups.py push --target nsx-lm1
      │          │       [--csv-remap | --segments-mode add-mapped | both]
      │          │       [--apply]
      └──────────┤
                 ▼
            <push_report>/
               summary.json, groups.jsonl, push.log, push.errors.log
               baselines/<ts>_target_baseline.json
               segments_unmapped.json   (if add-mapped had unresolved CIDRs)
               fabric_paths_stripped.json  (if any host/edge-TN refs auto-stripped)
                 │
                 │  B.3) groups.py revert --target nsx-lm1 (optional)
                 ▼
            <push_report>/baselines/<ts>_target_baseline.json.reverted
            + revert_summary_<ts>.json
```

---

## Safety characteristics

| Phase | Touches NSX? | What's touched |
|---|---|---|
| Capture | Yes — lm1, GET only | Policy + fabric GETs |
| Push (dry-run) | Yes — lm1, GET only | Reads baseline + reads files; logs every PATCH it would issue, doesn't send them |
| Push (apply) | Yes — lm1, PATCH | PATCH only the changed groups; services/policies/rules untouched |
| Revert (apply) | Yes — lm1, PUT/DELETE | Restores baseline payloads + deletes new groups; services/policies/rules untouched |

---

## Common questions

**Why is `--segments-mode keep` the default?**
Workflow B operates in-place on the source manager. Stripping or converting segment paths there would lose useful membership criteria. The default `keep` leaves segment references untouched. Use `add-mapped` to **add** mapped CIDRs alongside.

**Can I combine Workflow A and Workflow B style transforms?**
Yes — `groups.py push` doesn't care about the labels. You can target lm2 with `--segments-mode convert --csv-remap …` for a re-IP at clone time. CSV runs after segment-convert, so segment-derived CIDRs get remapped.

**What if a CSV mapping conflicts (e.g., `10.6.0.0/16` and `10.6.0.0/24` both present)?**
Longest-prefix match wins. The `/24` is more specific, so a token like `10.6.0.50` matches the `/24` row, not the `/16`.

**Does `add-mapped` work with `--mapped-only`?**
The `--mapped-only` flag applies to the CSV-remap step (Pattern 1). `add-mapped` always produces only the mapped CIDR — it doesn't add the native one, so `--mapped-only` is a no-op for the add-mapped pass.

**What if the CSV doesn't cover one of the segment CIDRs?**
The path is skipped — no IPAddressExpression is added for it — and the segment's native CIDR is logged to `segments_unmapped.json`. The original PathExpression stays so the group still resolves to its lm1-side segment members.

**Are nested-group dependency 404s and fabric-path strips still handled in Workflow B?**
Yes — same `groups.py push` code path. The retry trap for missing-dep 404s and the fabric-path auto-strip with forensic JSON both apply.

---

## File layout reference

```
nsx_capture/nsx-lm1.lab.local/                     ← capture bundle
├── nsx_export/nsx-lm1.lab.local/                  ← raw policy dump
├── groups_additive/                               ← Workflow B input
│   └── domains/default/groups/<short>.yaml
│       └── push_report/                           ← created on first B push
│           ├── baselines/<RUN_TS>_target_baseline.json[.reverted]
│           ├── groups_push_<ts>.log
│           ├── groups_push_<ts>.errors.log
│           ├── summary.json, groups.json, groups.jsonl
│           ├── failures.json                      ← only if real failures
│           ├── fabric_paths_stripped.json         ← only if any host/edge-TN refs auto-stripped
│           └── segments_unmapped.json             ← only if add-mapped had unresolved CIDRs
├── segment_inventory/segment_details.json        ← required by --segments-mode add-mapped
├── affected_rule_reports/
├── vm_tag_inventory/
├── logs/, manifest.json, summary.txt
```
