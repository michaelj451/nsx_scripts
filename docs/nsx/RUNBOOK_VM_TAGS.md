# Runbook — VM Hostname Tagging

## Summary

For every regular VM on an NSX Local Manager, ensure it carries an NSX tag
with `scope = hostname` and `tag = <trailing 3–6 digit run from the VM
name>`. Leading zeros are preserved exactly.

Existing hostname tags are **never modified**. VMs that already have one
are flagged for review and skipped. The push only ever **adds** new tag
associations — it never removes or replaces any other tag on any VM.

Revert un-assigns precisely and only the (scope=hostname, tag=value)
pairs that the matching push added — verified against the run manifest.
Nothing else is ever removed.

## Classification rules

| Class | Definition | Action |
|---|---|---|
| `eligible` | `type == REGULAR`, no existing hostname tag, name ends with 3–6 digits | Tag with that digit run |
| `skip_has_tag` | already carries any `scope=hostname` tag | Skip + flag for review |
| `skip_invalid_name` | name does not end with 3–6 trailing digits | Skip + flag for review |
| `skip_edge` | `type == EDGE` (NSX Edge VM) | Always skipped |
| `skip_other_type` | type is something other than REGULAR or EDGE (e.g. `VC_SYSTEM` for vCLS) | Always skipped |

## Safety properties

- Read-modify-write on every push and revert call (re-fetches current
  tags before mutating)
- Push never removes any existing tag — only appends the hostname tag
- Race-guard: if a VM acquires a hostname tag between plan-build and
  push, it is logged and skipped
- Revert guard: if the current hostname tag value differs from what the
  manifest says we added, the script leaves it alone (defends against
  third-party changes between push and revert)
- Dry-run is the default on every write tool; real writes require
  explicit `--apply`
- UTC timestamps everywhere

---

## 0) Environment setup

Same env as the rest of the toolkit — see [README.md](README.md) for the
macOS/Linux/Windows variants. Shorthand:

```bash
source .venv/bin/activate
export PYTHONPATH="$PWD/app"
```

---

## 1) Pre-change dry-run (single-command)

Read live VM state from the NSX LM, classify every VM, produce a complete
pre-change report. Makes no NSX writes.

```bash
python tools/reports/dryrun_hostname_tags.py \
  --manager nsx-lm1 \
  --output-dir nsx_vm_files/vm_tags_plan/nsx-lm1.lab.local \
  --overwrite
```

Outputs under `vm_tags_plan/<host>/<TIMESTAMP>/` — each run gets its own
timestamped subdir so successive runs accumulate side-by-side instead of
overwriting each other. The timestamp format is `YYYYMMDD_HHMMSS` (UTC).
`push` and `validate` auto-pick the latest timestamped subdir when you
point them at the host-level dir; pass an explicit timestamped path if
you need a specific historical run.

Per-run output files:

| File | Purpose |
|---|---|
| `plan.json` | Full classification of every VM + summary |
| `eligible.json` | VMs that WILL be tagged on apply |
| `skip_has_tag.json` | Operator review — already carry a hostname tag |
| `skip_invalid_name.json` | Operator review — name lacks 3–6 trailing digits |
| `skip_edge.json` | NSX Edge VMs (always skipped) |
| `skip_other_type.json` | Other non-REGULAR types (vCLS, NSX manager appliances, etc.) |
| `vm_tag_inventory.jsonl` | Per-VM tag inventory — one JSON object per line for EVERY VM (regardless of classification), with `display_name`, `external_id`, `type`, `tag_count`, and full `tags` list. Good for ad-hoc `grep` / `jq` queries. |

The `flagged_for_review` count in the printed summary tells you whether
any VM needs operator attention before pushing.

### Sample queries against `vm_tag_inventory.jsonl`

```bash
# How many tags does each VM have, sorted descending?
jq -r '.display_name + "\t" + (.tag_count|tostring)' \
  nsx_vm_files/vm_tags_plan/nsx-lm1.lab.local/vm_tag_inventory.jsonl \
  | sort -k2 -n -r

# Which VMs carry a tag with scope 'env'?
jq -c 'select(.tags[]?.scope == "env") | {display_name, tags}' \
  nsx_vm_files/vm_tags_plan/nsx-lm1.lab.local/vm_tag_inventory.jsonl

# All distinct (scope, tag) pairs in use across the manager
jq -r '.tags[] | [.scope, .tag] | @tsv' \
  nsx_vm_files/vm_tags_plan/nsx-lm1.lab.local/vm_tag_inventory.jsonl \
  | sort -u
```

---

## 2) Optional: separate export + build-plan steps

The dry-run above bundles export + classify. If you prefer the two-step
flow (so the export is reused across runs / fed into reports), use:

### 2a) Export VM state

```bash
python tools/vm_tags/export_vm_tags.py \
  --manager nsx-lm1 \
  --base-dir nsx_vm_files/vm_tags_export
```

Output: `vm_tags_export/<host>/vms.json`

### 2b) Build the plan from the export

```bash
python tools/vm_tags/build_hostname_tag_plan.py \
  --vm-export nsx_vm_files/vm_tags_export/nsx-lm1.lab.local/vms.json \
  --output-dir nsx_vm_files/vm_tags_plan/nsx-lm1.lab.local \
  --overwrite
```

Same `vm_tags_plan/<host>/<TIMESTAMP>/` outputs as step 1 (each invocation gets its own timestamped subdir).

---

## 3) Push — dry-run

Re-reads live VM state (read-modify-write defense) and previews exactly
what would be PATCHed for each eligible VM.

```bash
python tools/vm_tags/push_hostname_tags.py \
  --manager nsx-lm1 \
  --plan-dir nsx_vm_files/vm_tags_plan/nsx-lm1.lab.local
```

Dry-run is the default — no `--apply` flag means no NSX writes.

A dry-run manifest is written to:
`nsx_vm_tags_manifests/<host>/<TS>_dryrun.json`

---

## 4) Push — apply

```bash
python tools/vm_tags/push_hostname_tags.py \
  --manager nsx-lm1 \
  --plan-dir nsx_vm_files/vm_tags_plan/nsx-lm1.lab.local \
  --apply
```

For each eligible VM:

1. Fetch live current tags
2. Race-guard: skip if any hostname tag has appeared since plan-build
3. Append `{"scope": "hostname", "tag": "<digits>"}` to the existing tag list
4. POST the FULL combined list back via the fabric `update_tags` action

The apply manifest is written to `nsx_vm_tags_manifests/<host>/<TS>_apply.json`
with the exact (external_id, hostname_value) pairs that were added.
**Keep this file** — it's the input to revert.

---

## 5) Validate

Read-only: for every eligible VM in the plan, confirm the live NSX state
now carries the expected hostname tag.

```bash
python tools/vm_tags/validate_hostname_tags.py \
  --manager nsx-lm1 \
  --plan-dir nsx_vm_files/vm_tags_plan/nsx-lm1.lab.local
```

Buckets in the report: `match`, `mismatch_wrong_value`,
`missing_hostname_tag`, `missing_on_target`. Healthy result: all VMs in
`match`, others empty.

Report path: `nsx_logs/vm_tags_validation/<TS>_<manager>/validation_report.json`

---

## 6) Revert — dry-run

Reads the apply manifest from step 4 and previews exactly which
(VM, hostname tag) pairs would be removed. Other tags on the same VM are
preserved.

```bash
python tools/vm_tags/revert_hostname_tags.py \
  --manager nsx-lm1 \
  --manifest nsx_vm_tags_manifests/nsx-lm1.lab.local/<TS>_apply.json
```

A revert dry-run audit is written to
`nsx_vm_tags_manifests/<host>/<TS>_revert_dryrun.json`.

---

## 7) Revert — apply

```bash
python tools/vm_tags/revert_hostname_tags.py \
  --manager nsx-lm1 \
  --manifest nsx_vm_tags_manifests/nsx-lm1.lab.local/<TS>_apply.json \
  --apply
```

For each manifest entry with `status=success`:

1. Re-fetch live current tags
2. Guard: if the VM's current hostname tag value differs from what the
   manifest added, leave it alone (logged as `skipped_value_changed`)
3. Build a new tag list with only the matching hostname tag removed
4. POST that list back via `update_tags`

A revert apply audit is written to
`nsx_vm_tags_manifests/<host>/<TS>_revert_apply.json`.

---

## Workflow diagram

```text
nsx-lm1 fabric (live VM tags)
        │
        │  1) dryrun_hostname_tags.py  (OR  2a) export + 2b) build-plan)
        ▼
vm_tags_plan/<host>/<TIMESTAMP>/
  ├── eligible.json
  ├── skip_has_tag.json          ← flagged for operator review
  ├── skip_invalid_name.json     ← flagged for operator review
  ├── skip_too_many_tags.json    ← flagged for operator review
  ├── skip_edge.json
  ├── skip_other_type.json
  ├── vm_tag_inventory.jsonl
  └── plan.json
        │
        │  3) push --dry-run
        │  4) push --apply
        ▼
nsx_vm_tags_manifests/<host>/<TS>_apply.json   ← revert input
        │
        │  5) validate
        │  6) revert --dry-run
        │  7) revert --apply
        ▼
nsx_vm_tags_manifests/<host>/<TS>_revert_apply.json
```

---

## Safety characteristics

| Step | NSX impact | What it does NOT do |
|---|---|---|
| 1 / 2 — Plan / export | Read-only fabric GETs | Never writes |
| 3 — Push dry-run | Read-only (re-fetch for safety) | Never writes |
| 4 — Push apply | Appends one tag per eligible VM via fabric `update_tags` | Never removes any existing tag; never modifies skipped VMs |
| 5 — Validate | Read-only | Never writes |
| 6 — Revert dry-run | Read-only | Never writes |
| 7 — Revert apply | Removes ONLY the hostname tag from VMs in the manifest, IF the value still matches what was added | Never deletes a VM; never removes any other tag; never touches VMs not in the manifest |

**Nothing is ever deleted.** Tag associations are appended on push and
the specific tag association is removed on revert (only if it still
matches the manifest). The fabric `update_tags` API uses
read-modify-write semantics throughout — at no point is a VM's full tag
set replaced based on stale data.
