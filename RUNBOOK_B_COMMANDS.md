# Runbook B — Commands (in-place against `nsx-lm1`)

Bare commands only. See [RUNBOOK_B.md](RUNBOOK_B.md) for explanations.

> Workflow B operates **in-place on `nsx-lm1`**. No clone happens.
> Use `groups.py push --csv-remap` to rewrite IPs in existing `IPAddressExpression` entries (re-IP).

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

Produces (consumed by the Workflow B push below):

```
nsx_capture/nsx-lm1.lab.local/
├── groups_additive/domains/default/groups/...      ← Workflow B push input
└── manifest.json, summary.txt, logs/
```

---

## PUSH — in-place CSV IP remap on `nsx-lm1`

> All pushes default to **dry-run**. Add `--apply` to actually write. Baseline captured for revert.

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
