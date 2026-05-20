# Runbook B — In-Place CSV Subnet Remap on `nsx-lm1`

## Summary

Take `nsx-lm1`'s groups, flatten any dynamic/tag-based membership into static
IPs by asking NSX for evaluated VM members, then apply a CSV subnet remap
and PATCH the result back to `nsx-lm1`. Groups-only push. Services,
policies, and rules are not touched.

The workflow uses the same **three commands** as Runbook A, just with
different flags on transform and push:

```text
1) capture_nsx_state.py                            (touches nsx-lm1, GET only)
        ↓  review the capture bundle
2) transform_capture.py  --csv-remap CSV [--mapped-only]   (offline)
        ↓  review the transformed bundle (changed groups only)
3) push_from_capture.py  --target nsx-lm1 --groups-only [--dry-run|--apply]
```

With `--mapped-only`, unmapped IPs are **dropped** from each
`IPAddressExpression` — only the CSV-mapped values are kept. Use this
when you're staging a remapped configuration on `nsx-lm1` for testing.

Manager roles:

| Manager   | Role                                                | NSX impact                                |
|-----------|------------------------------------------------------|-------------------------------------------|
| `nsx-lm1` | Source AND target — read membership, PATCH groups   | Read + groups-only PATCH (no services/policies/rules) |

Properties:

- **Source manager (`nsx-lm1`) is touched in exactly two phases: capture, then push.** Transform is fully offline.
- Live VM membership is resolved by NSX (not by Python tag parsing).
- CSV remap is fully offline and reviewable before any push.
- Dry-run is the default safe mode on the push step. `--apply` is required to actually mutate.
- Every phase writes a `manifest.json` + `summary.txt` + per-step log files into its bundle directory.

---

## B.0) Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

---

## B.1) Capture — read-only snapshot of `nsx-lm1`

```bash
python tools/nsx/capture_nsx_state.py \
  --source nsx-lm1 \
  --domain-id default
```

This is the same capture step Runbook A uses. The capture bundle also
serves as Workflow B's rollback baseline — the pre-remap state of
`nsx-lm1` lives in `nsx_export/nsx-lm1.lab.local/` inside the bundle.

Output bundle:

```text
nsx_capture/nsx-lm1.lab.local/<UTC_TS>/
├── manifest.json
├── summary.txt
├── nsx_export/<host>/             ← raw NSX state (also serves as rollback baseline)
├── groups_additive/               ← live-member-enriched groups (input for the CSV remap)
├── segment_inventory/             ← optional; not used by Workflow B but harmless
├── affected_rule_reports/         ← useful to gauge blast radius before push
├── vm_tag_inventory/              ← VM tags (LM only)
└── logs/
```

### Review gate

- `summary.txt` — all steps OK
- `manifest.json` — `"ok": true`
- `affected_rule_reports/affected_rules_impact.json` — which rules touch the groups you're about to mutate

---

## B.2) Transform — offline CSV subnet remap

```bash
python tools/nsx/transform_capture.py \
  --capture nsx_capture/nsx-lm1.lab.local/<UTC_TS> \
  --csv-remap data/nonprod_map.csv \
  --mapped-only
```

**This step never contacts NSX.** Reads only files from the capture bundle.

What it does:

- When `--csv-remap` is given and `--segment-mode` is not specified, segment-mode defaults to `skip` (Workflow B doesn't transform segments).
- Runs `nsx_group_ip_remap_offline.py` against the capture's `groups_additive/` tree using the provided CSV.
- Writes both:
  - `groups_transformed/` — the full groups tree with CSV changes layered on top
  - `groups_changed_only/` — only the groups that actually changed (Workflow B's push uses this subset by default)

### CSV format

Each row: `old_subnet,new_subnet`. Longest-prefix match wins. See `data/nonprod_map.csv` for the lab example.

```csv
old_subnet,new_subnet
10.6.0.101/32,10.7.0.101/32
10.6.1.0/24,10.7.1.0/24
10.6.0.0/16,10.7.0.0/16
```

### Transform flags (Workflow B)

| Flag                            | Default   | Purpose                                                                |
|---------------------------------|-----------|------------------------------------------------------------------------|
| `--capture <bundle>`            | (required)| Path to a capture bundle                                               |
| `--csv-remap <csv>`             | (required for B) | Path to CSV mapping file                                        |
| `--mapped-only`                 | off       | Drop unmapped IPs; keep only the CSV-mapped values                     |
| `--bidirectional`               | off       | Treat each CSV row as a bidirectional mapping                          |
| `--segment-mode {convert,strip,skip}` | skip (when --csv-remap is set) | Whether to also do a segment transform        |
| `--source-groups {additive,raw}`| additive  | Use live-member-enriched groups (recommended) or raw export            |

### Output bundle

```text
nsx_transformed/nsx-lm1.lab.local/<UTC_TS>/
├── manifest.json                  ← transform metadata + link back to capture
├── summary.txt                    ← per-step status, CSV remap counts
├── groups_transformed/
│   └── domains/default/groups/    ← full groups tree with CSV overlay (validation reference)
├── groups_changed_only/
│   └── domains/default/groups/    ← ONLY the changed groups (what gets pushed)
├── transform_report/
│   ├── csv_remap_manifest.json    ← per-group changes
│   └── group-ip-remap/            ← summary/changed/unchanged/invalid CSV rows
└── logs/
```

### Review gate

- `summary.txt` — counts of groups changed, IPs added/dropped
- `transform_report/group-ip-remap/summary_update.json` — high-level stats
- `transform_report/group-ip-remap/groups_changed.json` — per-group before/after
- `transform_report/group-ip-remap/mapping_invalid_rows.json` — CSV rows that didn't parse
- Diff the changed groups against the capture's additive tree if you want byte-level visibility:
  ```bash
  diff -r \
    nsx_capture/nsx-lm1.lab.local/<TS>/groups_additive/domains/default/groups \
    nsx_transformed/nsx-lm1.lab.local/<TS>/groups_transformed/domains/default/groups
  ```

---

## B.3) Push — groups-only PATCH to `nsx-lm1`

### B.3a) Dry-run (default — safe, no writes)

```bash
python tools/nsx/push_from_capture.py \
  --target nsx-lm1 \
  --transformed nsx_transformed/nsx-lm1.lab.local/<UTC_TS> \
  --groups-only
```

What this does, against `nsx-lm1`:

1. **Baseline export of the target** (GET-only) — captures pre-push state for rollback. Lives at `<push bundle>/target_baseline/`.
2. **Skipped** — groups-only mode does not assemble a complete payload.
3. **Dry-run push using `push_additive_group_ips`** — every PATCH is logged but not sent. Pushes only the groups in `groups_changed_only/` (if CSV remap ran) or the full transformed tree.

Output bundle:

```text
nsx_push/nsx-lm1.lab.local/<UTC_TS>/
├── manifest.json
├── summary.txt
├── target_baseline/               ← pre-push GET-only export of nsx-lm1 (rollback baseline)
├── push_report/<ts>/              ← push_additive_group_ips' per-row results
└── logs/
```

### Review gate

- `summary.txt` — step-by-step status, dry-run counts
- `push_report/<ts>/summary.json` — full push tool output
- `push_report/<ts>/groups.json` (or `.jsonl`) — per-group dry-run records

### B.3b) Apply

When the dry-run looks clean, re-run with `--apply`:

```bash
python tools/nsx/push_from_capture.py \
  --target nsx-lm1 \
  --transformed nsx_transformed/nsx-lm1.lab.local/<UTC_TS> \
  --groups-only \
  --apply
```

After `--apply`:

- The push actually PATCHes the changed groups on `nsx-lm1`
- A live validation runs automatically (`validate_nsx_groups_live`) and mirrors its report into `<push bundle>/validate_report/`

### Push flags (Workflow B)

| Flag                       | Default     | Purpose                                                                |
|----------------------------|-------------|------------------------------------------------------------------------|
| `--target nsx-lm1`         | (required)  | Push target (Workflow B: same as the capture's source)                 |
| `--transformed <bundle>`   | (required)  | Path to a transformed bundle                                           |
| `--groups-only`            | (required for B) | Skip services/policies/rules; PATCH only changed groups            |
| `--apply`                  | off         | Actually push (otherwise dry-run)                                      |
| `--skip-baseline`          | off         | Skip the pre-push target export (NOT recommended)                      |
| `--skip-validate`          | off         | Skip the post-apply live validation                                    |

---

## Workflow Diagram

```text
nsx-lm1 (source AND target)
      ▲          │
      │          │  B.1) capture_nsx_state.py
      │          ▼
      │     nsx_capture/nsx-lm1.lab.local/<TS>/
      │        nsx_export/, groups_additive/, ...
      │          │
      │          │  B.2) transform_capture.py --csv-remap CSV [--mapped-only]  (OFFLINE)
      │          ▼
      │     nsx_transformed/nsx-lm1.lab.local/<TS>/
      │        groups_transformed/, groups_changed_only/, transform_report/
      │          │
      │          │  B.3) push_from_capture.py --target nsx-lm1 --groups-only [--apply]
      └──────────┘
                 │
                 ▼
            nsx_push/nsx-lm1.lab.local/<TS>/
               target_baseline/, push_report/, validate_report/
```

---

## Safety Characteristics

| Phase     | Touches NSX?           | What's touched                                |
|-----------|------------------------|-----------------------------------------------|
| Capture   | Yes — lm1, GET only    | Policy + fabric GETs                          |
| Transform | **No**                 | Reads/writes local files only                 |
| Push (dry-run)  | Yes — lm1, GET only | Read-only against `nsx-lm1`                  |
| Push (apply)    | Yes — lm1, PATCH    | PATCH only the changed groups; services/policies/rules untouched |

---

## Rollback

Workflow B only writes groups (PATCH), so the **groups-only revert** is the
complete rollback. The push bundle's `target_baseline/` holds the pre-push
GET-only export of `nsx-lm1` — pair it with `push_nsx_groups_revert.py`:

Dry-run preview:

```bash
PYTHONPATH="$PWD/app" python tools/nsx/push_nsx_groups_revert.py \
  --target nsx-lm1 \
  --export-root nsx_push/nsx-lm1.lab.local/<TS>/target_baseline/nsx-lm1.lab.local \
  --domain-id default
```

Apply rollback:

```bash
PYTHONPATH="$PWD/app" python tools/nsx/push_nsx_groups_revert.py \
  --target nsx-lm1 \
  --export-root nsx_push/nsx-lm1.lab.local/<TS>/target_baseline/nsx-lm1.lab.local \
  --domain-id default \
  --apply
```

> **Why not `push_complete_nsx_revert.py`?** That's for Runbook A's full clone, which writes services/policies/rules onto a target. Workflow B only PATCHes groups, so the groups-only revert is sufficient and faster.

---

## Inner Tools (Advanced)

Workflow B reuses Runbook A's three wrappers; the underlying primitives are:

| Inner tool                                  | Phase     | Purpose                                                   |
|---------------------------------------------|-----------|-----------------------------------------------------------|
| `tools/nsx/export_nsx_objects.py`           | Capture   | Raw NSX state export                                      |
| `tools/nsx/build_group_ip_additive_from_live_members.py` | Capture | Live VM-IP enrichment of groups            |
| `tools/nsx/nsx_group_ip_remap_offline.py`   | Transform | The actual CSV subnet remap                               |
| `tools/nsx/push_additive_group_ips.py`      | Push      | Groups-only PATCH                                         |
| `tools/nsx/validate_nsx_groups_live.py`     | Push      | Compare live NSX state to expected files                  |
| `tools/nsx/push_nsx_groups_revert.py`       | Rollback  | Groups-only revert to a snapshot                          |
