# EMERGENCY RESTORE : back up now, put it back later : macOS / Linux / bash

Break-glass procedure. Two halves: take a backup **before** you need one, and
push that backup back when something has gone wrong. Read-only until you type
`--apply`.

PowerShell variant: [EMERGENCY_RESTORE_PS.md](EMERGENCY_RESTORE_PS.md).
Concepts and bundle layout: [RUNBOOK_BACKUP.md](RUNBOOK_BACKUP.md).

> ## What this does NOT do
>
> **It does not wipe.** A restore pushes the backed-up definitions back over
> whatever is on the manager. It does not delete objects created after the
> backup was taken, because they are not in the bundle and nothing tells the
> push to remove them. After a restore:
>
> - everything in the bundle is back, with its backed-up content
> - anything added since the backup is **still there**
>
> That is usually what you want in an emergency: put the known-good config
> back without destroying whatever else is running. If you need the target to
> match the bundle exactly, that is a different and far more dangerous
> operation. See [the deliberate gaps](#what-a-restore-cannot-reach).

---

## 0) Env

The first line makes pasted `#` comments safe in zsh; it is a no-op in bash.
`S` is the manager alias, `H` its hostname (bundles are keyed by hostname),
`B` the bundle's object root, `R` where this restore's reports go.

```bash
setopt interactive_comments 2>/dev/null || true

source .venv/bin/activate
export PYTHONPATH="$PWD/app"

S=nsx-lm1
H=nsx-lm1.lab.local
B=nsx_backup/$H/latest/nsx_export/$H/domains/default
R=nsx_restore/$H/$(date -u +%Y%m%d_%H%M%S)
mkdir -p $R
```

To restore a specific point in time instead of the newest, replace `latest`
with the timestamped directory name, for example `20260910_185942`.

---

## 1) Take a backup

Do this before any change window, and on a schedule. It is GET-only and
cannot alter the manager.

```bash
python tools/nsx/backup_nsx_state.py --source $S
```

Several managers in one run, keeping the 14 newest bundles each:

```bash
python tools/nsx/backup_nsx_state.py --source nsx-lm1 nsx-lm2 nsx-gm1 --retain 14
```

Exit code is 0 only when every requested manager backed up clean. GM aliases
switch to the Global Manager API surface automatically and skip VM tags,
because that API is LM-only.

### Verify the backup before you rely on it

```bash
cat nsx_backup/$H/latest/summary.txt
ls $B/groups | wc -l
ls $B/services | wc -l
ls -d $B/security-policies/*/ | wc -l
```

`summary.txt` must say `NSX BACKUP OK` and every step must read `OK`. A bundle
you have not verified is not a backup.

---

## 2) Restore

Order matters: services, then groups, then policies, then rules. Each object
class depends on the ones before it.

### 2a. Dry run

```bash
python tools/nsx/services.py push --target $S --services-dir $B/services            --reports-dir $R/services
python tools/nsx/groups.py   push --target $S --groups-dir   $B/groups              --reports-dir $R/groups
python tools/nsx/policies.py push --target $S --policies-dir $B/security-policies   --reports-dir $R/policies
python tools/nsx/rules.py    push --target $S --rules-dir    $B/security-policies   --reports-dir $R/rules
```

Read the output before going further. Every push reads the target first, so
the dry run tells you which objects already exist and which would be created.

### 2b. Apply

Same four commands with `--apply`:

```bash
python tools/nsx/services.py push --target $S --services-dir $B/services            --reports-dir $R/services --apply
python tools/nsx/groups.py   push --target $S --groups-dir   $B/groups              --reports-dir $R/groups   --apply
python tools/nsx/policies.py push --target $S --policies-dir $B/security-policies   --reports-dir $R/policies --apply
python tools/nsx/rules.py    push --target $S --rules-dir    $B/security-policies   --reports-dir $R/rules    --apply
```

Each apply captures its own baseline under `$R/<class>/baselines/` first, so
the restore itself is revertible.

---

## 3) Verify the restore

Compare the manager against the bundle, ignoring NSX-managed metadata:

`$B` and `$H` are passed as arguments, not read from the environment: the
variables in section 0 are shell variables, and a child process does not
inherit them unless they are exported.

```bash
python - "$B" "$H" <<'PY'
import yaml, glob, json, sys
VOL = {"_revision","_create_time","_last_modified_time","_create_user",
       "_last_modified_user","_protection","_system_owned","path","relative_path",
       "parent_path","realization_id","unique_id","origin_site_id","owner_id",
       "remote_path","_schema","id"}
def strip(o):
    if isinstance(o, dict): return {k: strip(v) for k, v in sorted(o.items()) if k not in VOL}
    if isinstance(o, list): return [strip(x) for x in o]
    return o
def load(pat):
    out = {}
    for f in glob.glob(pat, recursive=True):
        d = yaml.safe_load(open(f))
        if isinstance(d, dict) and d.get("id") and d.get("id") != "index":
            out[d["id"]] = json.dumps(strip(d), sort_keys=True)
    return out
B, H = sys.argv[1], sys.argv[2]
live = load(f"nsx_groups_export/{H}/groups/*.yaml")
bund = load(f"{B}/groups/*.yaml")
missing = sorted(set(bund) - set(live))
differs = sorted(k for k in set(live) & set(bund) if live[k] != bund[k])
extra   = sorted(set(live) - set(bund))
print(f"groups  live={len(live)} bundle={len(bund)}")
print(f"  missing from manager : {missing or 'none'}")
print(f"  content differs      : {differs or 'none'}")
print(f"  on manager, not in bundle (added since the backup, NOT removed by a restore): {extra or 'none'}")
PY
```

Re-export first if the local tree is stale:

```bash
python tools/nsx/capture_nsx_state.py --source $S --live-query
```

---

## Three things that will bite you

**`--reports-dir` is not optional here.** A push defaults its reports to
`<dir>/../push_report`, so pointing one straight at a backup bundle writes
`push_report/` and its baselines **inside the snapshot you are restoring
from**, contaminating it. Every command above sends them to `$R` instead.

**Rules need `_parent_policy_id`, and backup bundles do not have it.** Backups
are written by `export_nsx_objects.py`, which does not inject that field.
`rules.py push` then falls back to the containing folder name, which in a
backup bundle is a slugified hash (`test--icy-2-3ad2a1f6`) rather than the real
policy id (`test-policy-2`), so the rules land in a policy that does not exist.
Until that is fixed in the tool, restore rules from a tree that carries the
field, which `capture_nsx_state.py` produces:

```bash
python tools/nsx/rules.py push --target $S \
  --rules-dir nsx_rules_export/$H/security-policies \
  --reports-dir $R/rules --apply
```

Only do this when that tree matches the backup point; check the rule ids and
payloads between the two trees first.

**A restore can legitimately need to REMOVE IPs**, when the backup predates a
later addition. `groups.py push` refuses any row that would drop an IP and
marks it a contract violation. That refusal is the additive contract working.
Read the per-row diff, and only then re-run that one class with
`--intentional-ip-removal`.

---

## What a restore cannot reach

A backup holds policy-layer definitions. These are outside it, and a restore
will not bring them back:

| Not restored | Why |
|---|---|
| VM tags | Live on the VMs in the fabric. The bundle's `vm_tag_inventory/` is a read-only record, not a restore source. Use `tools/vm_tags/` |
| Segments and fabric | Transport zones, transport nodes, compute managers are per-manager |
| DFW exclusion list | Different endpoint, not exported. See NSX_TOOLKIT_GAPS 2.4 |
| Context profiles, time ranges | Not exported. Rules referencing them will 404 on push |
| Objects created after the backup | Not in the bundle, and no wipe happens, so they survive untouched |

Tag-based group membership re-evaluates on its own once the definitions are
back, provided the VMs and their tags still exist.

---

## If the restore itself goes wrong

Every apply captured a baseline, so the restore can be undone in reverse order:

```bash
python tools/nsx/rules.py    revert --target $S --reports-dir $R/rules    --apply
python tools/nsx/policies.py revert --target $S --reports-dir $R/policies --apply
python tools/nsx/groups.py   revert --target $S --reports-dir $R/groups   --apply
python tools/nsx/services.py revert --target $S --reports-dir $R/services --apply
```

A revert that needs to DELETE a group it created is blocked unless you add
`--allow-delete`. Without the flag those groups are left in place, reported
under `deletes_blocked`, and the revert still exits 0. Always read the summary
rather than trusting the exit code:

```bash
python -c "
import json, glob
f = sorted(glob.glob('$R/groups/revert_summary_*.json'))[-1]
t = json.load(open(f))['totals']; print(t)
assert not t.get('deletes_blocked'), 'BLOCKED: ' + str(t['deletes_blocked'])"
```

Each revert consumes one baseline and renames it `*.reverted`. If a class was
applied more than once, each revert invocation undoes one apply, newest first.
