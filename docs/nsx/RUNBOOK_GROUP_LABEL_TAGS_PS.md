# Runbook - Group Label-Tag Sync (Windows PowerShell)

Compact command reference for mirroring a group's tag-based **membership
criteria** into the group's own **label tags**. For every Tag condition
whose **tag value** is in the configured list (default `network,vm`),
that `{scope, tag}` is added to the group's `tags`. Additive-only; never
removes existing label tags. Full narrative lives in
[RUNBOOK_GROUP_LABEL_TAGS.md](RUNBOOK_GROUP_LABEL_TAGS.md).

Line continuation in PowerShell is the backtick `` ` `` at end of line.

---

## Step 0: Env setup (once per PowerShell session)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

Assumes `.env` is populated with NSX credentials and manager aliases.
Set the scope list once in `.env` (already added by default):

```
NSX_GROUP_LABEL_MATCH_TAGS=network,vm
```

These are TAG VALUES (the criterion's "Tag" field), not scopes. Override
per-run with `--match-tags network,vm`.

---

## Step 1: Dry-run (the default)

Read-only against NSX. Reads every group, walks each membership
expression (recursing into `NestedExpression`), and writes a per-group
diff. No writes.

```powershell
python tools/nsx/sync_group_label_tags.py --target nsx-lm1
```

Federated view / Global Manager:

```powershell
# Local Manager, federated view
python tools/nsx/sync_group_label_tags.py --target nsx-lm1 --federation-global

# Global Manager, native
python tools/nsx/sync_group_label_tags.py --target nsx-gm1 --federation-global
```

Outputs under `$env:NSX_LOG_DIR\reports\group_label_tags\<host>\<UTC_TS>\`:

| File | Purpose |
|---|---|
| `plan.md` | Human-readable per-group diff |
| `results.json` / `results.jsonl` | Full per-group outcome |
| `summary.json` | Counters (`by_status`, `tag_additions`) |
| `apply_manifest.json` | What was (or would be) added - the revert input |

Discover the latest plan dir and review it:

```powershell
$plan = (Get-ChildItem "$env:NSX_LOG_DIR\reports\group_label_tags\nsx-lm1.lab.local" -Directory `
         | Sort-Object Name -Descending | Select-Object -First 1).FullName
Write-Host "Plan: $plan"
Get-Content "$plan\plan.md"
```

Which groups would gain a label tag, and which tags:

```powershell
Get-Content "$plan\results.json" | ConvertFrom-Json `
  | Where-Object { $_.status -eq "dry_run" } `
  | ForEach-Object {
      $tags = ($_.to_add | ForEach-Object { "$($_.scope)|$($_.tag)" }) -join ", "
      "{0,-40} {1}" -f $_.group_id, $tags
    }
```

---

## Step 2: Apply

Re-reads each group live (read-modify-write defense) and PATCHes only the
groups that need additions.

```powershell
python tools/nsx/sync_group_label_tags.py --target nsx-lm1 --apply
```

The apply manifest lands at `$plan\apply_manifest.json` with the exact
`{group_id, added_tags, prior_tags}` per group. **Keep this file** - it
is the input to revert.

---

## Step 3: Revert - dry-run

Uses the apply manifest to know exactly which label tags to remove.
Every other label tag is preserved.

Discover the latest apply manifest:

```powershell
$manifest = (Get-ChildItem "$env:NSX_LOG_DIR\reports\group_label_tags\nsx-lm1.lab.local\*\apply_manifest.json" `
             | Sort-Object FullName -Descending | Select-Object -First 1).FullName
Write-Host "Manifest: $manifest"

python tools/nsx/revert_group_label_tags.py `
  --target nsx-lm1 `
  --manifest $manifest
```

Outputs under `$env:NSX_LOG_DIR\reports\group_label_tags_revert\<host>\<UTC_TS>\`.
Per-group status: `dry_run`, `reverted`, `guard` (recorded tags already
absent), `skipped`, `failed`.

---

## Step 4: Revert - apply

```powershell
python tools/nsx/revert_group_label_tags.py `
  --target nsx-lm1 `
  --manifest $manifest `
  --apply
```

For each manifest entry: re-fetch live tags, remove a recorded tag only
if still present, PATCH back the reduced list. The manifest carries
`domain_id` and `federation_global`, so revert targets the same scope the
apply used; override with `--domain-id` / `--federation-global` if needed.

---

## Output locations at a glance

All bundles land under `$env:NSX_LOG_DIR\reports\` (default
`nsx_logs\reports\`) with layout `<type>\<host>\<UTC_TS>\`.

| Tool | Location | Where output lands |
|---|---|---|
| `sync_group_label_tags.py` | `tools\nsx\` | `nsx_logs\reports\group_label_tags\<host>\<UTC_TS>\` (`plan.md`, `results.json`, `summary.json`, `apply_manifest.json`) |
| `revert_group_label_tags.py` | `tools\nsx\` | `nsx_logs\reports\group_label_tags_revert\<host>\<UTC_TS>\` |
| Per-run log files | | inside each run's `logs\` subdir |

---

## Safety refresher

- **Never removes existing label tags.** Sync only appends in-scope
  criteria tags; revert only removes what its manifest recorded.
- **Membership criteria are never modified.** The `expression` is read,
  not written.
- **`system_owned` groups are skipped** structurally.
- **Read-modify-write** on every apply/revert PATCH: the group is
  re-fetched before mutating, so out-of-band changes are detected
  (`[NOOP]` / `[GUARD]`) rather than clobbered.
- **Dry-run is the default** on both tools; real writes require `--apply`.
- **Tag-value-driven** via `NSX_GROUP_LABEL_MATCH_TAGS` (or `--match-tags`);
  matches the criterion's "Tag" field (the value after the `|`), not the scope.

---

## See also

- [RUNBOOK_GROUP_LABEL_TAGS.md](RUNBOOK_GROUP_LABEL_TAGS.md) - full narrative + bash variant
- [REPORTS_DATA_SOURCES.md](REPORTS_DATA_SOURCES.md) - where tag/group data comes from
