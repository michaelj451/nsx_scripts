# Runbook B — Commands (in-place against `nsx-lm1`)

Bare commands only. See [RUNBOOK_B.md](RUNBOOK_B.md) for explanations.

> Workflow B operates **in-place on `nsx-lm1`**. No clone happens.
> Two patterns are supported via `groups.py push`:
> - **CSV IP remap** — rewrite IPs inside existing `IPAddressExpression` entries (re-IP)
> - **`add-mapped` segment CIDRs** — keep segment refs; add an OR'd `IPAddressExpression` containing the CSV-mapped equivalent of each segment's native CIDR
> Both patterns can be combined in a single push run.

## Env

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\app"
```

```bash
# bash/zsh equivalent
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

---

## CAPTURE — read-only baseline of `nsx-lm1` (run once)

```sh
python tools/nsx/capture_nsx_state.py --source nsx-lm1
```

Produces (consumed by every Workflow B push below):

```
nsx_capture/nsx-lm1.lab.local/
├── groups_additive/domains/default/groups/...      ← Workflow B push input
├── segment_inventory/segment_details.json          ← required by add-mapped
└── manifest.json, summary.txt, logs/
```

---

## PUSH — in-place on `nsx-lm1`

> All pushes default to **dry-run**. Add `--apply` to actually write. Baseline captured for revert.

### Pattern 1 — CSV IP remap (re-IP existing static IPs)

Rewrites every IP in `IPAddressExpression` entries via the CSV mapping.
`--mapped-only` keeps only the mapped values (re-IP); without it, mapped
values are appended alongside the originals (additive).

```sh
python tools/nsx/groups.py push `
  --target nsx-lm1 `
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups `
  --csv-remap data/nonprod_map.csv `
  --mapped-only `
  --apply
```

### Pattern 2 — add-mapped segment CIDRs

For each segment path in a group's `PathExpression`, look up the segment's
native CIDR, run it through the CSV, and **add** the mapped CIDR as a
new `IPAddressExpression` (joined by OR). Original `PathExpression` is
preserved unchanged.

```sh
python tools/nsx/groups.py push `
  --target nsx-lm1 `
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups `
  --segments-mode add-mapped `
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json `
  --csv-remap data/nonprod_map.csv `
  --apply
```

Unmapped segments (CIDR not covered by any CSV row) are skipped and
logged to `<push_report>/segments_unmapped.json` for operator follow-up.

### Pattern 3 — both at once

CSV remap on existing IP expressions **and** add-mapped on segment-referencing groups.

```sh
python tools/nsx/groups.py push `
  --target nsx-lm1 `
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups `
  --segments-mode add-mapped `
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json `
  --csv-remap data/nonprod_map.csv `
  --mapped-only `
  --apply
```

---

## REVERT — restore `nsx-lm1` to its pre-push state

Each `revert` pops the most recent unreverted baseline. Workflow B
typically runs one push at a time, so one revert undoes that push.

```sh
python tools/nsx/groups.py revert --target nsx-lm1 `
  --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report `
  --apply
```

Multiple stacked B pushes? Each revert pops the latest. Repeat as needed.

To confirm the revert stack is fully drained:

```sh
find nsx_capture/nsx-lm1.lab.local/groups_additive -path "*/baselines/*.json" -not -name "*.reverted"
# (empty output = all baselines consumed)
```
