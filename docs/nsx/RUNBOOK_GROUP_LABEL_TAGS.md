# Runbook - Group Label-Tag Sync

## Summary

For every NSX Group on the target manager, mirror the group's tag-based
**membership criteria** into the group's own **label tags** (the "Tags"
you see when editing a group in the UI).

For each VM Tag condition in a group's membership expression whose **tag
value** is in the configured match list (default `network,vm`), the tool
ensures the same `{scope, tag}` also appears on the group's `tags` field.

The sync is **additive and surgical**:

- Existing label tags (ANY scope) are preserved untouched.
- Only `{scope, tag}` pairs found in the criteria for the configured
  scopes are added, and only if not already present.
- Groups with no matching criteria are a no-op.
- `_system_owned` groups are skipped.

Revert removes precisely and only the label tags the matching apply run
added, verified against that run's manifest. Nothing else is touched.

Works against a Local Manager (local view), a Local Manager in federated
view (`--federation-global`), or a Global Manager (`--target nsx-gm1
--federation-global`). The client follows the correct
`/policy` vs `/global-infra` vs `/global-manager` root automatically.

## How a matching tag is detected

NSX stores a Tag condition's value as `scope|tag` (scope BEFORE the pipe,
tag after). In the UI criterion
`Virtual Machine | Tag | Equals | network | Scope Equals | 0`, the stored
value is `0|network`: scope `0`, tag `network`. The tool walks the full
expression tree, **recursing into `NestedExpression`** so compound/
API-authored groups are handled (not just GUI-flattened ones), matches on
the **tag value** (the "Tag" field, not the scope), and mirrors the full
`{scope, tag}` onto the label.

| Example condition `value` | Parsed scope | Parsed tag | Mirrored when match-tags = network,vm? |
|---|---|---|---|
| `0\|network` | `0` | `network` | Yes -> label `{scope:0, tag:network}` |
| `1\|vm` | `1` | `vm` | Yes -> label `{scope:1, tag:vm}` |
| `2\|db` | `2` | `db` | No (tag value not in list) |
| `\|Edge_NSGroup` | `` (empty) | `Edge_NSGroup` | No (tag value not in list) |

## Safety properties

- Read-modify-write on every apply: the group is re-fetched (GET)
  immediately before PATCH, so a tag added out-of-band since planning is
  detected (`[NOOP]`) rather than clobbered.
- PATCH sends the full existing tag list plus the additions; no other
  label tag is ever dropped.
- Dry-run is the default on both tools; real writes require explicit
  `--apply`.
- Revert only removes tags recorded in the apply manifest, and only if
  they are still present (`[GUARD]` otherwise).
- UTC timestamps everywhere; env-driven log dirs.

---

## 0) Environment setup

Same env as the rest of the toolkit - see [README.md](../../README.md).
Shorthand:

```bash
source .venv/bin/activate
export PYTHONPATH="$PWD/app"
```

Set the match-tag list once in `.env` (already added by default):

```bash
NSX_GROUP_LABEL_MATCH_TAGS=network,vm
```

These are TAG VALUES (the criterion's "Tag" field), not scopes. Override
per-run with `--match-tags network,vm` if you need something else.

---

## 1) Dry-run (the default)

Reads every group from the target, computes the label additions, and
writes a per-group diff. Makes no NSX writes.

```bash
python tools/nsx/sync_group_label_tags.py --target nsx-lm1
```

Federated view / Global Manager:

```bash
# Local Manager, federated view
python tools/nsx/sync_group_label_tags.py --target nsx-lm1 --federation-global

# Global Manager, native
python tools/nsx/sync_group_label_tags.py --target nsx-gm1 --federation-global
```

Outputs under `$NSX_LOG_DIR/reports/group_label_tags/<host>/<UTC_TS>/`:

| File | Purpose |
|---|---|
| `plan.md` | Human-readable per-group diff (status, tags added, existing label tags) |
| `results.json` / `results.jsonl` | Full per-group outcome |
| `summary.json` | Counters (`by_status`, `tag_additions`) |
| `apply_manifest.json` | What was (or would be) added per group - the revert input |

Per-group `status` values: `dry_run`, `applied`, `no_change`, `noop`
(already present at apply time), `skipped` (`system_owned` / no id),
`failed`.

Inspect the diff:

```bash
plan_dir=$(ls -dt "$NSX_LOG_DIR"/reports/group_label_tags/nsx-lm1.lab.local/*/ | head -1)
cat "$plan_dir/plan.md"

# Which groups would gain a label tag, and which?
jq -r '.[] | select(.status=="dry_run")
        | .group_id + "\t" + ([.to_add[] | .scope+"|"+.tag] | join(", "))' \
  "$plan_dir/results.json"
```

---

## 2) Apply

Re-reads each group live (read-modify-write defense) and PATCHes only the
groups that need additions.

```bash
python tools/nsx/sync_group_label_tags.py --target nsx-lm1 --apply
```

The apply manifest is written to
`$NSX_LOG_DIR/reports/group_label_tags/<host>/<UTC_TS>/apply_manifest.json`
with the exact `{group_id, added_tags, prior_tags}` per group.
**Keep this file** - it is the input to revert.

---

## 3) Revert - dry-run

Reads the apply manifest and previews exactly which label tags would be
removed from which groups. Every other label tag is preserved.

```bash
python tools/nsx/revert_group_label_tags.py \
  --target nsx-lm1 \
  --manifest "$NSX_LOG_DIR/reports/group_label_tags/nsx-lm1.lab.local/<UTC_TS>/apply_manifest.json"
```

Outputs under `$NSX_LOG_DIR/reports/group_label_tags_revert/<host>/<UTC_TS>/`.
Per-group status: `dry_run`, `reverted`, `guard` (recorded tags already
absent), `skipped`, `failed`.

---

## 4) Revert - apply

```bash
python tools/nsx/revert_group_label_tags.py \
  --target nsx-lm1 \
  --manifest "$NSX_LOG_DIR/reports/group_label_tags/nsx-lm1.lab.local/<UTC_TS>/apply_manifest.json" \
  --apply
```

For each manifest entry:

1. Re-fetch the group's live tags.
2. Guard: only remove a recorded tag if it is still present.
3. PATCH the group back with the reduced tag list.

The revert audit is written under the revert output dir. The manifest
carries `domain_id` and `federation_global`, so revert targets the same
scope the apply used; override with `--domain-id` / `--federation-global`
if needed.

---

## Workflow diagram

```text
target manager (live group objects)
        │
        │  1) sync --dry-run   (reads every group, walks expression tree)
        ▼
$NSX_LOG_DIR/reports/group_label_tags/<host>/<UTC_TS>/
  ├── plan.md            ← per-group diff, review this
  ├── results.json
  ├── summary.json
  └── apply_manifest.json
        │
        │  2) sync --apply     (read-modify-write PATCH per group)
        ▼
apply_manifest.json  ← revert input (added_tags + prior_tags per group)
        │
        │  3) revert --dry-run
        │  4) revert --apply
        ▼
$NSX_LOG_DIR/reports/group_label_tags_revert/<host>/<UTC_TS>/
```

---

## Safety characteristics

| Step | NSX impact | What it does NOT do |
|---|---|---|
| 1 - Sync dry-run | Read-only group GETs | Never writes |
| 2 - Sync apply | Adds only in-scope criteria tags to each group's label via PATCH | Never removes any existing label tag; never touches `system_owned` groups; never modifies membership expressions |
| 3 - Revert dry-run | Read-only | Never writes |
| 4 - Revert apply | Removes ONLY the label tags in the manifest, IF still present | Never deletes a group; never removes any other label tag; never touches groups not in the manifest |

**Membership criteria are never modified.** The tool only reads the
`expression` to decide what belongs on the label; the group's actual
membership is left exactly as-is.

---

## See also

- [RUNBOOK_GROUP_LABEL_TAGS_PS.md](RUNBOOK_GROUP_LABEL_TAGS_PS.md) - Windows PowerShell variant
- [REPORTS_DATA_SOURCES.md](../reference/REPORTS_DATA_SOURCES.md) - where tag/group data comes from
- [RUNBOOK_VM_TAGS.md](RUNBOOK_VM_TAGS.md) - the sibling workflow that tags the VMs those criteria match
