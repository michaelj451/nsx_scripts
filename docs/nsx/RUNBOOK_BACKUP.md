# Runbook BACKUP: read-only NSX configuration backup

## Summary

`backup_nsx_state.py` saves each manager's configuration exactly as it is, so
it can be restored. It is a separate workflow from the migration/remap capture
and must not be confused with it:

| | **backup_nsx_state.py** (this runbook) | **capture_nsx_state.py** (Workflows A/B/C/D) |
|---|---|---|
| Purpose | Restorable snapshot of definitions | Input bundle for clone / remap workflows |
| Contents | Groups, services, policies+rules, segments, VM tags (LM) as held | Same raw export PLUS `groups_additive/` (evaluated VM IPs frozen into groups), rule-impact reports, flat export refresh |
| History | Timestamped bundles under `nsx_backup/<host>/<UTC ts>/`, KEPT (optional `--retain N`) | One bundle per host, WIPED on every run |
| Restore | Push the bundle back (dry-run first) | Pushing `groups_additive` back is NOT a faithful restore (it materializes VM IPs into definitions) |
| NSX impact | GET-only | GET-only |

## Take a backup

```bash
setopt interactive_comments 2>/dev/null || true

export PYTHONPATH="$PWD/app"

# One or many managers in one run. GM aliases automatically use the
# Global Manager API surface (and skip VM tags: that API is LM-only).
python tools/nsx/backup_nsx_state.py --source nsx-gm1 nsx-lm1 nsx-lm2

# Scheduled use: keep the 14 newest bundles per host
python tools/nsx/backup_nsx_state.py --source nsx-lm1 nsx-lm2 --retain 14
```

Exit code is `0` only when every requested manager backed up clean, so the
command is cron-safe. A failed bundle is kept for inspection but is never
marked `latest`.

## Bundle layout

```text
nsx_backup/<host>/<UTC_TS>/
├── manifest.json        ok flag + per-step records (cmd, rc, timing, log path)
├── summary.txt          human-readable result
├── nsx_export/<host>/domains/<domain>/
│   ├── groups/                       one YAML per group (group_type preserved)
│   ├── services/
│   └── security-policies/            policy.yaml + nested rules
├── segments/                         segment definitions
├── vm_tag_inventory/                 LM sources only
└── logs/                             per-step logs
nsx_backup/<host>/latest -> <UTC_TS>  symlink to newest clean bundle
```

### Review gates

- run output ends with per-manager `OK` / `FAILED` and a JSON run summary
- `<bundle>/manifest.json` has `"ok": true`
- `<bundle>/summary.txt` lists every step `OK`

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--source M [M ...]` | (required) | Managers to back up in this run |
| `--domain-id` | `default` | Domain to export |
| `--all-domains` | off | Export every domain |
| `--no-vm-tags` | off | Skip VM tag inventory on LM sources |
| `--output-root` | `nsx_backup/` | Where bundles land |
| `--retain N` | `0` (keep all) | After a clean backup, prune to the N newest bundles for that host |
| `--quiet` | off | Less per-step console output |

## Restore

Restore is the existing per-class push tooling pointed at a bundle. Everything
defaults to dry-run; `--apply` is required to write, every apply captures a
baseline first, and group revert deletes stay blocked unless `--allow-delete`
is given.

```bash
setopt interactive_comments 2>/dev/null || true

B=nsx_backup/nsx-lm1.lab.local/latest

# Order: services -> groups -> policies (policies carry their rules)
python tools/nsx/services.py push --target nsx-lm1 \
  --services-dir $B/nsx_export/nsx-lm1.lab.local/domains/default/services            # + --apply
python tools/nsx/groups.py   push --target nsx-lm1 \
  --groups-dir   $B/nsx_export/nsx-lm1.lab.local/domains/default/groups              # + --apply
python tools/nsx/policies.py push --target nsx-lm1 \
  --policies-dir $B/nsx_export/nsx-lm1.lab.local/domains/default/security-policies   # + --apply
```

Notes:

- A restore push can legitimately need to REMOVE IPs (the backup predates a
  later addition). `groups.py push` will refuse such rows unless
  `--intentional-ip-removal` is given; that refusal is the additive contract
  doing its job, so read the per-row diff before overriding.
- For a GM target add `--federation-global` to each push.
- VM tags restore via `tools/vm_tags/` (`build_hostname_tag_plan.py` /
  `push_hostname_tags.py`) if ever needed; the inventory in the bundle is the
  reference.

## Safety characteristics

| Phase | Touches NSX? | Notes |
|---|---|---|
| Backup | GET-only | Zero writes; only local files under `nsx_backup/` |
| Restore (dry-run) | GET-only | Prints the plan |
| Restore (apply) | PUT/PATCH | Baseline captured first; group deletes blocked without `--allow-delete` |
