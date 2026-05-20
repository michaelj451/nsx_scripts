# Runbook A — Clone `nsx-lm1` (live) → `nsx-lm2` (new)

## Summary

Clone the policy configuration from the **original live** NSX Local Manager
(`nsx-lm1` — has the real VMs and evaluated group memberships) onto the
**new** NSX Local Manager (`nsx-lm2`).

The workflow is **three commands** with two human-review gates between them:

```text
1) capture_nsx_state.py      → bundle of read-only artifacts        (touches nsx-lm1, GET only)
        ↓  review the capture bundle
2) transform_capture.py      → bundle of push-ready artifacts       (offline, never touches NSX)
        ↓  review the transformed bundle
3) push_from_capture.py      → push to nsx-lm2  (dry-run, then apply)  (touches nsx-lm2 only)
```

Manager roles:

| Manager   | Role                                  | NSX impact                                   |
|-----------|---------------------------------------|----------------------------------------------|
| `nsx-lm1` | Original live — read-only source      | Read-only (only in step 1)                   |
| `nsx-lm2` | New manager — apply target            | PATCH/POST via file payload (only in step 3) |
| `nsx-lm3` | Throwaway sandbox — optional testing  | None unless you choose to test against it    |

Properties:

- **Source manager (`nsx-lm1`) is touched in exactly one phase: capture.** Every other step works from the on-disk bundle.
- Transform is **fully offline** — uses segment data cached by capture. You can re-transform with different options as many times as you want without re-hitting NSX.
- Dry-run is the default safe mode on push. `--apply` is required to actually mutate the target.
- Every phase writes a `manifest.json` + `summary.txt` + per-step log files into its bundle directory.

Safe to repeat. Suitable for CAB-reviewed execution.

---

## 0) Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

`$NSX_LOG_DIR` (from `.env`) is where global log files land. Bundle artifacts always also live inside the bundle directory itself.

---

## 1) Capture — read-only snapshot of `nsx-lm1`

```bash
python tools/nsx/capture_nsx_state.py \
  --source nsx-lm1 \
  --domain-id default
```

What this does, in order, against `nsx-lm1` (every call is GET-only):

1. **`export_nsx_objects`** — raw groups, services, policies, rules
2. **`build_group_ip_additive_from_live_members`** — snapshots evaluated VM IPs into static `IPAddressExpression` entries (so dynamic-membership groups still resolve correctly on `nsx-lm2`)
3. **`find_segments_referenced`** — lists every referenced segment path **and fetches each segment's live details (subnet CIDRs, VLAN, transport zone)** so transform can later run offline
4. **`find_rules_affected_by_group_changes`** — offline impact report
5. **`export_vm_tags`** — VM tag state (LM only)

Output bundle:

```text
nsx_capture/nsx-lm1.lab.local/<UTC_TS>/
├── manifest.json                  ← captured-at, options, per-step status
├── summary.txt                    ← human-readable summary
├── nsx_export/<host>/             ← raw NSX state
├── groups_additive/               ← live-member-enriched groups
├── segment_inventory/             ← segments_inventory.json, segment_details.json, segment_paths.txt
├── affected_rule_reports/         ← impact report
├── vm_tag_inventory/              ← VM tag JSONL + summary
└── logs/                          ← per-step log files
```

### Capture flags

| Flag                           | Default | Purpose                                                      |
|--------------------------------|---------|--------------------------------------------------------------|
| `--source nsx-lm1`             | (required) | Which manager to capture from                            |
| `--domain-id default`          | default | NSX policy domain                                            |
| `--federation-global`          | off     | Use the Global Manager API surface (for GM source)           |
| `--no-live-members`            | off     | Skip live VM-IP enrichment (groups stay as raw export)       |
| `--no-segment-inventory`       | off     | Skip the segment inventory (transform's `convert` won't work)|
| `--no-vm-tags`                 | off     | Skip VM tag capture                                          |
| `--no-impact-report`           | off     | Skip the affected-rules impact report                        |
| `--output-dir <path>`          | auto    | Override the default `nsx_capture/<host>/<UTC_TS>/` path     |

### Review gate

Before moving on, look at:

- `summary.txt` — eyeball each step's status
- `manifest.json` — confirm `"ok": true`
- `affected_rule_reports/affected_rules_impact.json` — rules touched by the changed groups
- `segment_inventory/segment_paths.txt` — segment paths your export depends on (hand to the network team to confirm presence on `nsx-lm2`)

---

## 2) Transform — offline conversion of the capture into a push-ready bundle

```bash
python tools/nsx/transform_capture.py \
  --capture nsx_capture/nsx-lm1.lab.local/<UTC_TS> \
  --segment-mode convert
```

**This step never contacts NSX.** It reads only files from the capture bundle and writes a new transformed bundle.

What it does:

- Runs `transform_group_segments.py` against the capture's `groups_additive/` tree
- For `--segment-mode convert`, the transform uses the **cached `segment_details.json`** from the capture, so segment paths get replaced with `IPAddressExpression` CIDRs without a single NSX call
- Writes a fresh, dated bundle so you can re-run with different options without overwriting anything

### Segment modes

| Mode        | Behavior                                                                                           | Needs `segment_inventory`? |
|-------------|----------------------------------------------------------------------------------------------------|----------------------------|
| `convert`   | Replace each `/infra/segments/<id>` reference with an `IPAddressExpression` of the segment's CIDRs | Yes (from capture)         |
| `strip`     | Remove segment references entirely, drop empty `PathExpression` nodes, clean up operators          | No                         |
| `skip`      | Leave segment references untouched (groups will still need those segments to exist on the target)  | No                         |

If `convert` is requested but the capture didn't include segment details, the transform falls back to `strip` and logs why.

### Output bundle

```text
nsx_transformed/nsx-lm1.lab.local/<UTC_TS>/
├── manifest.json                  ← transform metadata + link back to capture
├── summary.txt                    ← per-step status, transform counts
├── groups_transformed/
│   └── domains/default/groups/    ← transformed group files
├── transform_report/
│   └── segments_stripped.json     ← per-group strip/convert detail
└── logs/                          ← per-step log files
```

### Transform flags

| Flag                            | Default   | Purpose                                                              |
|---------------------------------|-----------|----------------------------------------------------------------------|
| `--capture <bundle>`            | (required)| Path to a capture bundle                                             |
| `--segment-mode {convert,strip,skip}` | convert | How to handle segment references                                |
| `--source-groups {additive,raw}`| additive  | Use the live-member-enriched groups (recommended) or raw export      |
| `--domain-id <id>`              | from manifest | Override the domain (rarely needed)                              |
| `--output-dir <path>`           | auto      | Override the default `nsx_transformed/<host>/<UTC_TS>/` path         |

### Review gate

Before moving on:

- `summary.txt` — counts of files modified, segments converted, unresolved paths
- `transform_report/segments_stripped.json` — per-group detail of what got transformed
- Diff the transformed groups against the input if you want byte-level visibility:
  ```bash
  diff -r \
    nsx_capture/nsx-lm1.lab.local/<TS>/groups_additive/domains/default/groups \
    nsx_transformed/nsx-lm1.lab.local/<TS>/groups_transformed/domains/default/groups
  ```

---

## 3) Push — apply the transformed bundle to `nsx-lm2`

### 3a) Dry-run (default — safe, no writes)

```bash
python tools/nsx/push_from_capture.py \
  --target nsx-lm2 \
  --transformed nsx_transformed/nsx-lm1.lab.local/<UTC_TS>
```

What this does, against `nsx-lm2`:

1. **Baseline export of the target** (GET-only) — captures pre-push state for rollback. Lives at `<push bundle>/target_baseline/`.
2. **Assemble the complete payload** offline — combines `nsx-lm1`'s services/policies/rules from the capture with the transformed groups from step 2 into `<push bundle>/nsx_build/`.
3. **Dry-run push** — every PATCH/POST is logged but not sent. Output mirrored into `<push bundle>/push_report/`.

Output bundle:

```text
nsx_push/nsx-lm2.lab.local/             ← always reflects the LATEST push
├── manifest.json                  ← push metadata + links back to capture + transformed
├── summary.txt                    ← step status, push counts
├── target_baseline/               ← pre-push GET-only export of nsx-lm2
├── nsx_build/nsx-lm2.lab.local/   ← assembled push payload
├── push_report/<ts>/              ← push tool's JSON/JSONL summary + per-row results
└── logs/                          ← per-step log files
```

### Review gate

- `summary.txt` — step-by-step status, dry-run counts
- `push_report/<ts>/summary.json` — full push tool output
- `push_report/<ts>/rules.json`, `groups.json`, `services.json`, `policies.json` — per-object dry-run records

### 3b) Apply

When the dry-run looks clean, re-run with `--apply`:

```bash
python tools/nsx/push_from_capture.py \
  --target nsx-lm2 \
  --transformed nsx_transformed/nsx-lm1.lab.local/<UTC_TS> \
  --apply
```

After `--apply`:

- The push step actually PATCHes/POSTs to `nsx-lm2`
- A live validation runs automatically (`validate_nsx_groups_live`) and mirrors its report into `<push bundle>/validate_report/`

### Push flags

| Flag                       | Default     | Purpose                                                                |
|----------------------------|-------------|------------------------------------------------------------------------|
| `--target nsx-lm2`         | (required)  | Which manager to push to                                               |
| `--transformed <bundle>`   | (required)  | Path to a transformed bundle                                           |
| `--apply`                  | off         | Actually push (otherwise dry-run)                                      |
| `--federation-global`      | off         | Target is a Global Manager                                             |
| `--domain-id <id>`         | from manifest | Override the domain (rarely needed)                                  |
| `--skip-baseline`          | off         | Skip the pre-push target export (NOT recommended)                      |
| `--skip-validate`          | off         | Skip the post-apply live validation                                    |
| `--output-dir <path>`      | auto        | Override the default `nsx_push/<target>/` path. The default path is wiped at the start of every run; pass `--output-dir` to preserve specific bundles. |

---

## Workflow Diagram

```text
nsx-lm1 (live)                                                  nsx-lm2 (target)
      │                                                                   ▲
      │  1) capture_nsx_state.py                                          │  3b) push_from_capture.py --apply
      │                                                                   │
      ▼                                                                   │
nsx_capture/nsx-lm1.lab.local/<TS>/                                       │
   nsx_export/, groups_additive/, segment_inventory/, vm_tag_inventory/   │
      │                                                                   │
      │  2) transform_capture.py  (OFFLINE — never touches NSX)           │
      ▼                                                                   │
nsx_transformed/nsx-lm1.lab.local/<TS>/                                   │
   groups_transformed/, transform_report/                                 │
      │                                                                   │
      │  3a) push_from_capture.py            (dry-run, talks to nsx-lm2)  │
      ▼                                                                   │
nsx_push/nsx-lm2.lab.local/      ─────────────────────────────────────── ┤  (wiped & rewritten each run)
   target_baseline/, nsx_build/, push_report/, validate_report/           │
```

---

## Safety Characteristics

| Phase     | Touches NSX?           | What's touched                                |
|-----------|------------------------|-----------------------------------------------|
| Capture   | Yes — source only      | GET-only on `nsx-lm1` (policy + fabric)       |
| Transform | **No**                 | Reads/writes local files only                 |
| Push (dry-run) | Yes — target only | Read-only against `nsx-lm2`; no PATCH/POST    |
| Push (apply)   | Yes — target only | PATCH/POST against `nsx-lm2` only             |

**Source manager (`nsx-lm1`) is touched only by `capture_nsx_state.py`.** Once the capture bundle is on disk, every subsequent operation is either offline or aimed at the target.

---

## Sandbox testing against `nsx-lm3`

`nsx-lm3` is a throwaway manager — safe to break, experiment on, or wipe.
Re-aim the push wrapper at it for end-to-end testing before touching `nsx-lm2`:

```bash
python tools/nsx/push_from_capture.py \
  --target nsx-lm3 \
  --transformed nsx_transformed/nsx-lm1.lab.local/<TS>
```

Same transformed bundle, different target. The push bundle lands at `nsx_push/nsx-lm3.lab.local/`.

---

## Rollback

The push bundle's `target_baseline/` directory holds the pre-push GET-only export of the target. Pair it with `push_complete_nsx_revert.py` to roll back:

Dry-run preview:

```bash
PYTHONPATH="$PWD/app" python tools/nsx/push_complete_nsx_revert.py \
  --target nsx-lm2 \
  --export-root nsx_push/nsx-lm2.lab.local/target_baseline/nsx-lm2.lab.local \
  --domain-id default
```

Apply rollback:

```bash
PYTHONPATH="$PWD/app" python tools/nsx/push_complete_nsx_revert.py \
  --target nsx-lm2 \
  --export-root nsx_push/nsx-lm2.lab.local/target_baseline/nsx-lm2.lab.local \
  --domain-id default \
  --apply
```

Add `--include-services` if the original push created services on the target that weren't there before (e.g., pushing to a brand-new manager). System-owned NSX objects are always preserved.

> **Why not `push_nsx_groups_revert.py`?** That script is groups-only and can't delete groups that are still referenced by the policies/rules from a Workflow-A push. It's the correct tool for Runbook B's groups-only rollback. Use `push_complete_nsx_revert.py` here.

---

## Inner Tools (Advanced)

The three wrappers compose a set of underlying scripts. Most operators never need to invoke these directly, but they are the primitives — if you need a non-standard flow (e.g., transforming an existing capture from a year ago, or re-running just the segment inventory), call them directly:

| Inner tool                                  | What it does                                                | Phase     |
|---------------------------------------------|-------------------------------------------------------------|-----------|
| `tools/nsx/export_nsx_objects.py`           | Raw NSX state export                                        | Capture   |
| `tools/nsx/build_group_ip_additive_from_live_members.py` | Live VM-IP enrichment of groups                | Capture   |
| `tools/nsx/find_segments_referenced.py`     | Segment reference inventory (with live detail fetch)        | Capture   |
| `tools/nsx/find_rules_affected_by_group_changes.py` | Offline rule-impact report                          | Capture   |
| `tools/vm_tags/export_vm_tags.py`           | VM tag inventory                                            | Capture   |
| `tools/nsx/transform_group_segments.py`     | Strip/convert segment references in group files             | Transform |
| `tools/nsx/build_complete_nsx_payload.py`   | Assemble services + policies + rules + groups into one tree | Push      |
| `tools/nsx/push_complete_nsx_payload.py`    | The actual push to NSX                                      | Push      |
| `tools/nsx/validate_nsx_groups_live.py`     | Compare live NSX state to expected files                    | Push      |
| `tools/nsx/push_complete_nsx_revert.py`     | Roll back to a captured baseline                            | Rollback  |

`transform_group_segments.py` accepts `--segments-from <path>` to consume the capture's cached `segment_details.json` — this is how `transform_capture.py` keeps the transform fully offline.
