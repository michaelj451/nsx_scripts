# Runbook B — Commands (in-place against `nsx-lm1`) — Windows PowerShell

Bare commands only, PowerShell variant. See [RUNBOOK_B.md](RUNBOOK_B.md) for explanations,
or [RUNBOOK_B_COMMANDS.md](RUNBOOK_B_COMMANDS.md) for the bash/zsh equivalent.

> Workflow B operates **in-place on `nsx-lm1`**. No clone happens.
> Use `groups.py push --csv-remap` to rewrite IPs in existing `IPAddressExpression` entries (re-IP).
> Line continuation in PowerShell is the backtick `` ` `` at end of line.

## Env

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

---

## CAPTURE — read-only baseline of `nsx-lm1` (run once)

```powershell
python tools/nsx/capture_nsx_state.py --source nsx-lm1
```

Produces (consumed by the Workflow B push below):

```
nsx_capture/nsx-lm1.lab.local/
├── groups_additive/domains/default/groups/...      ← Workflow B push input
└── manifest.json, summary.txt, logs/
```

---

## PUSH — in-place CSV IP remap on `nsx-lm1`

> All pushes default to **dry-run**. Add `--apply` to actually write. Baseline captured for revert.

Rewrites every IP in `IPAddressExpression` entries via the CSV mapping —
**strict-additive**: originals are kept, mapped values are appended,
**no IP is ever removed**. `--mapped-only` is refused with `--csv-remap`.
`--batch-size` defaults to **1** when `--csv-remap` is set (step-through
every change; bump higher at any prompt).

```powershell
python tools/nsx/groups.py push `
  --target nsx-lm1 `
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups `
  --csv-remap data/nonprod_map.csv `
  --apply
```

### Interactive batch mode (`--batch-size N`)

When `--csv-remap` is set, `--batch-size` defaults to **1** automatically.
Pass `--batch-size N` to start at a different size. At each prompt:
`Y`/Enter (continue same size), `n` (reset to 1), `x` (clean exit), or
`<number>` (change size). See [RUNBOOK_B.md](RUNBOOK_B.md) for full details.

```powershell
# Start at 10 instead of the default 1
python tools/nsx/groups.py push `
  --target nsx-lm1 `
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups `
  --csv-remap data/nonprod_map.csv `
  --batch-size 10 `
  --apply
```

---

## REVERT — restore `nsx-lm1` to its pre-push state

Each `revert` pops the most recent unreverted baseline. Workflow B
typically runs one push at a time, so one revert undoes that push.

```powershell
python tools/nsx/groups.py revert --target nsx-lm1 `
  --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report `
  --apply
```

Multiple stacked B pushes? Each revert pops the latest. Repeat as needed.

To confirm the revert stack is fully drained:

```powershell
Get-ChildItem -Recurse `
  -Path nsx_capture/nsx-lm1.lab.local/groups_additive `
  -Filter "*_target_baseline.json" -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -like "*\baselines\*" } |
  Select-Object FullName
# (no output = all baselines consumed)
```
