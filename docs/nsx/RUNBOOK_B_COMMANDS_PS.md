# Runbook B Commands (in-place against `nsx-lm1`) : Windows PowerShell

Bare commands only, PowerShell variant. See [RUNBOOK_B.md](RUNBOOK_B.md) for
explanations, or [RUNBOOK_B_COMMANDS.md](RUNBOOK_B_COMMANDS.md) for macOS/Linux bash.

> Workflow B operates **in-place on `nsx-lm1`**. No clone happens.
> `groups.py push --csv-remap` idempotently ADDS mapped IPs to
> `IPAddressExpression` entries. Strict-additive: no IP is ever removed.
> Default scope is IP-Addresses-Only groups; `--remap-generic` widens it.

## 0) Env

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"

# Set ONCE per session; every command below follows.
$M = "nsx-gm1"
$H = "nsx-gm1.lab.local"

# Keep push reports OUTSIDE the capture bundle: re-captures wipe the bundle,
# and the revert baselines + pushed_ids.json must survive them.
$R = "nsx_remap_$M"
```

---

---

## 0b) Global Manager and multi-domain scope

Read [RUNBOOK_B.md](RUNBOOK_B.md#b0-which-surfaces-and-domains-are-in-scope)
first. Two things bite on a federated estate:

- **GM-owned groups** (`/global-infra/`) and **LM-local groups** (`/infra/`) are
  separate populations. A GM run never sees LM-local groups. Run once per
  surface.
- `groups.py export` and `push` default to `--domain-id default`. A GM carries
  one location-scoped domain per site, so pass **`--all-domains`** to cover them
  all in one command.

List the domains and count them against the sites you expect:

```powershell
python tools/nsx/list_domains.py nsx-gm1
```

### Dry run every GM domain

Read-only. Each domain gets its own bundle under `<output-dir>/<domain>/` and
its own reports under `<reports-dir>/<domain>/`, so per-domain revert baselines
never collide.

```powershell
$M   = "nsx-gm1"
$CSV = "data/subnet_map.csv"
$TS  = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")

python tools/nsx/groups.py export --source $M --federation-global `
  --all-domains --output-dir "nsx_groups_export/${M}_alldom"

python tools/nsx/groups.py push --target $M --federation-global `
  --all-domains --groups-dir "nsx_groups_export/${M}_alldom" `
  --csv-remap $CSV --reports-dir "nsx_wfb_runs/$M/$TS"
```

The run prints a per-domain summary at the end. Review each domain before
applying:

```powershell
Get-ChildItem "nsx_wfb_runs/$M/$TS" -Directory | ForEach-Object {
  $d = Get-Content "$($_.FullName)/summary.json" | ConvertFrom-Json
  "{0,-28} mode={1} seen={2} changed={3} added={4} failed={5}" -f `
    $_.Name, $d.mode, $d.totals.files_seen, `
    $d.totals.csv_groups_changed, $d.totals.csv_total_added_values, $d.totals.failed
}
```

Add `--apply` to the push to write. One domain failing does not abandon the
rest, and the exit code is non-zero if any did.

**Revert stays per domain:**

```powershell
python tools/nsx/groups.py revert --target $M --federation-global `
  --domain-id "nsx-lm1.lab.local" `
  --reports-dir "nsx_wfb_runs/$M/$TS/nsx-lm1.lab.local" --apply
```

### Then each Local Manager, for its own local groups

```powershell
foreach ($M in @("nsx-lm1","nsx-lm2","nsx-lm3")) {
  python tools/nsx/groups.py export --source $M --output-dir "nsx_groups_export/${M}_local"
  python tools/nsx/groups.py push --target $M `
    --groups-dir "nsx_groups_export/${M}_local/groups" `
    --csv-remap $CSV --reports-dir "nsx_wfb_runs/$M/${TS}_local"
}
```

No `--federation-global`. An LM normally has only the `default` domain; confirm
with `list_domains.py`.

### A standalone Local Manager

None of the above applies. Use the commands in the following sections as
written: one surface, one domain, no federation flag.


## 1) CAPTURE : read-only snapshot of `nsx-lm1`

Re-run this before every push session so the bundle matches the manager.

```powershell
python tools/nsx/capture_nsx_state.py --source $M
```

Input for the push below:
`nsx_capture/$H/groups_additive/domains/default/groups/`

---

## 2) DRY RUN : see the plan, write nothing

```powershell
python tools/nsx/groups.py push `
  --target $M `
  --groups-dir nsx_capture/$H/groups_additive/domains/default/groups `
  --csv-remap data/nonprod_map.csv `
  --reports-dir $R/dryrun
```

Review gates before going any further:

- `$R/dryrun/remap_report.md` : header Result line, section 1 "Would add"
  (value, source original, CSV row), already-remapped pairs, generic-group
  candidates, never-remapped ranges/IPv6, CSV coverage misses
- `$R/dryrun/summary.json` : `csv_invalid_rows` must be empty

---

## 3) APPLY : step-through at batch size 1, ramp as confidence grows

```powershell
python tools/nsx/groups.py push `
  --target $M `
  --groups-dir nsx_capture/$H/groups_additive/domains/default/groups `
  --csv-remap data/nonprod_map.csv `
  --reports-dir $R/push_report `
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

```powershell
python tools/nsx/groups.py push `
  --target $M `
  --groups-dir nsx_capture/$H/groups_additive/domains/default/groups `
  --csv-remap data/nonprod_map.csv `
  --remap-generic `
  --reports-dir $R/push_report `
  --apply
```

---

## 4) AUDIT : reconcile the manager against the CSV (read-only, cron-safe)

```powershell
python tools/nsx/audit_ip_remap.py --target $M --csv data/nonprod_map.csv
```

Exit `0` = clean; `1` = gaps in section 1a/1c. Generic-group candidates are
informational unless you audit with `--include-generic`. Report lands under
`$env:NSX_LOG_DIR/reports/$H/ip_remap_audit/<ts>/`.

---

## 5) REVERT : undo a push (scoped to what that push wrote)

Each `revert` pops the most recent unreverted baseline. By default it touches
ONLY the groups listed in `<RUN_TS>_pushed_ids.json` next to the baseline;
everything else on the manager is left alone. Dry-run first.

```powershell
python tools/nsx/groups.py revert --target $M `
  --reports-dir $R/push_report

python tools/nsx/groups.py revert --target $M `
  --reports-dir $R/push_report `
  --apply
```

Notes:

- Group DELETEs are blocked unless `--allow-delete` is given (blocked ones
  are listed in the summary as `deletes_blocked`).
- Baselines from before scoped revert existed need `--scope all
  --allow-delete` (legacy full-baseline restore; dry-run it first).

Stacked pushes? Each revert pops the latest. Confirm the stack is drained:

```powershell
Get-ChildItem -Recurse -Path $R/push_report/baselines `
  -Filter "*_target_baseline.json" -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -notlike "*.reverted" }
# (empty output = all baselines consumed)
```
