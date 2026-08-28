# Runbook B Commands (in-place against `nsx-lm1`) : macOS / Linux / bash

Bare commands only. See [RUNBOOK_B.md](RUNBOOK_B.md) for explanations,
or [RUNBOOK_B_COMMANDS_PS.md](RUNBOOK_B_COMMANDS_PS.md) for the Windows PowerShell variant.

> Workflow B operates **in-place on `nsx-lm1`**. No clone happens.
> `groups.py push --csv-remap` idempotently ADDS mapped IPs to
> `IPAddressExpression` entries. Strict-additive: no IP is ever removed.
> Default scope is IP-Addresses-Only groups; `--remap-generic` widens it.

## 0) Env

The first line makes pasted `#` comments safe in zsh (the macOS default
shell parses them as commands otherwise); it is a no-op elsewhere.

Set `M` and `H` once per session; every command below follows them. `M` is
the manager alias from `.env`; `H` is the hostname it resolves to (capture
bundles are keyed by hostname). Push reports live OUTSIDE the capture bundle
because re-captures wipe the bundle and the revert baselines must survive.

```bash
setopt interactive_comments 2>/dev/null || true

python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"

M=nsx-gm1
H=nsx-gm1.lab.local
R=nsx_remap_$M
```

---

## 1) CAPTURE : read-only snapshot of `nsx-lm1`

Re-run this before every push session so the bundle matches the manager.

```bash
python tools/nsx/capture_nsx_state.py --source $M
```

Input for the push below:
`nsx_capture/$H/groups_additive/domains/default/groups/`

---

## 2) DRY RUN : see the plan, write nothing

```bash
python tools/nsx/groups.py push \
  --target $M \
  --groups-dir nsx_capture/$H/groups_additive/domains/default/groups \
  --csv-remap data/nonprod_map.csv \
  --reports-dir $R/dryrun
```

Review gates before going any further:

- `$R/dryrun/remap_report.md` : header Result line, section 1 "Would add"
  (value, source original, CSV row), already-remapped pairs, generic-group
  candidates, never-remapped ranges/IPv6, CSV coverage misses
- `$R/dryrun/summary.json` : `csv_invalid_rows` must be empty

---

## 3) APPLY : step-through at batch size 1, ramp as confidence grows

```bash
python tools/nsx/groups.py push \
  --target $M \
  --groups-dir nsx_capture/$H/groups_additive/domains/default/groups \
  --csv-remap data/nonprod_map.csv \
  --reports-dir $R/push_report \
  --apply
```

At each prompt: `Enter` continue at current size, `<number>` change size
(e.g. `25`), `n` reset to 1, `x` clean exit. Every decision lands in
`summary.json` as `interactive_decisions`. Start at a different size with
`--batch-size N`; `--batch-size 0` disables prompts (automation).

Re-running the same apply is a no-op by design: rows with nothing to add are
`skipped_no_change` and NOTHING is sent to NSX (no revision bumps). Review
after: `$R/push_report/remap_report.md`.

To also remap generic groups (off by default):

```bash
python tools/nsx/groups.py push \
  --target $M \
  --groups-dir nsx_capture/$H/groups_additive/domains/default/groups \
  --csv-remap data/nonprod_map.csv \
  --remap-generic \
  --reports-dir $R/push_report \
  --apply
```

---

## 4) AUDIT : reconcile the manager against the CSV (read-only, cron-safe)

```bash
python tools/nsx/audit_ip_remap.py --target $M --csv data/nonprod_map.csv
```

Exit `0` = clean; `1` = gaps in section 1a/1c. Generic-group candidates are
informational unless you audit with `--include-generic`. Report lands under
`$NSX_LOG_DIR/reports/ip_remap_audit/$H/<ts>/`.

---

## 5) REVERT : undo a push (scoped to what that push wrote)

Each `revert` pops the most recent unreverted baseline. By default it touches
ONLY the groups listed in `<RUN_TS>_pushed_ids.json` next to the baseline;
everything else on the manager is left alone. Dry-run first.

```bash
python tools/nsx/groups.py revert --target $M \
  --reports-dir $R/push_report

python tools/nsx/groups.py revert --target $M \
  --reports-dir $R/push_report \
  --apply
```

Notes:

- Group DELETEs are blocked unless `--allow-delete` is given (blocked ones
  are listed in the summary as `deletes_blocked`).
- Baselines from before scoped revert existed need `--scope all
  --allow-delete` (legacy full-baseline restore; dry-run it first).

Stacked pushes? Each revert pops the latest. Confirm the stack is drained:

```bash
setopt interactive_comments 2>/dev/null || true

find $R/push_report/baselines -name "*_target_baseline.json" -not -name "*.reverted"
# (empty output = all baselines consumed)
```
