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

---

## 0b) Global Manager and multi-domain scope

Sections 1 to 5 below target a single Local Manager. On a federated estate read
[RUNBOOK_B.md](RUNBOOK_B.md#b0-which-surfaces-and-domains-are-in-scope) first.
Two things differ:

- **GM-owned groups** (`/global-infra/`) and **LM-local groups** (`/infra/`) are
  separate populations. A GM run never sees LM-local groups, and GM-owned groups
  do not appear on the LM surface. Run once per surface.
- A GM carries one location-scoped domain per site. Both subcommands default to
  `--domain-id default`, so pass **`--all-domains`** to cover every domain.

```bash
setopt interactive_comments 2>/dev/null || true

python tools/nsx/list_domains.py nsx-gm1
```

### GM: dry run every domain

```bash
M=nsx-gm1
CSV=data/subnet_map.csv
TS=$(date -u +%Y%m%d_%H%M%S)

python tools/nsx/groups.py export --source $M --federation-global \
  --all-domains --output-dir nsx_groups_export/${M}_alldom

python tools/nsx/groups.py push --target $M --federation-global \
  --all-domains --groups-dir nsx_groups_export/${M}_alldom \
  --csv-remap $CSV --reports-dir nsx_wfb_runs/$M/$TS
```

Review each domain, then add `--apply` to the push:

```bash
for f in nsx_wfb_runs/$M/$TS/*/summary.json; do
  python -c "
import json,sys
d=json.load(open(sys.argv[1])); t=d['totals']
print(f\"{sys.argv[1].split('/')[-2]:28} mode={d['mode']} seen={t['files_seen']:3} \"
      f\"changed={t['csv_groups_changed']} added={t['csv_total_added_values']} \"
      f\"failed={t['failed']}\")" $f
done
```

### Then each LM, for its own local groups

```bash
for M in nsx-lm1 nsx-lm2 nsx-lm3; do
  python tools/nsx/groups.py export --source $M --output-dir nsx_groups_export/${M}_local
  python tools/nsx/groups.py push --target $M \
    --groups-dir nsx_groups_export/${M}_local/groups \
    --csv-remap $CSV --reports-dir nsx_wfb_runs/$M/${TS}_local
done
```

No `--federation-global`, and an LM has only the `default` domain, so no
`--all-domains` either.

### Revert is per domain

```bash
python tools/nsx/groups.py revert --target nsx-gm1 --federation-global \
  --domain-id nsx-lm1.lab.local \
  --reports-dir nsx_wfb_runs/nsx-gm1/$TS/nsx-lm1.lab.local --apply
```

### A standalone Local Manager

None of this applies. Use sections 1 to 5 as written.


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
`summary.json` as `interactive_decisions`. Every apply starts at one; increase
the size at a checkpoint. Disabling prompts with `--batch-size 0` or starting
above one is rejected. Closed input stops further writes.

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
`$NSX_LOG_DIR/reports/$H/ip_remap_audit/<ts>/`.

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
