# RUNBOOK: Wipe customer DFW objects from a target manager

`tools/test/wipe_target_manager.py` deletes customer DFW objects from an NSX
Local Manager in dependency order (rules -> policies -> groups -> services) so
referential integrity is never violated.

Two modes:

| Mode | Flag | Deletes |
|---|---|---|
| Full wipe | (none) | every customer service, group, policy, and every non-`is_default` rule, including customer-added rules inside the Default sections |
| Scoped wipe | `--id-prefix PREFIX` | only objects whose NSX id starts with PREFIX. The Default sections are not touched at all |

**Dry-run is the default.** `--apply` is required to write. Every run captures
`pre_wipe_state.json` before deleting.

---

## 1. Read this before a full wipe

The full wipe's rule guard skips only rules with `is_default=true`. NSX ships
`default_rule_NDP` and `default_rule_DHCP` inside the Default Layer3 Section
with `is_default=false` and `_system_owned=false`, so a **full wipe deletes
them**. That is usually not what you want when you are only clearing test data.

Use `--id-prefix` whenever the objects you want gone share a naming prefix.
Under a prefix scope the Default sections are excluded from rule collection
entirely, so their NDP/DHCP rules survive.

## 2. Back up first

The wipe's own `pre_wipe_state.json` is an audit record, not a push-ready
bundle. For a restorable snapshot, run the backup workflow first:

```bash
export PYTHONPATH="$PWD/app"
python tools/nsx/backup_nsx_state.py --source nsx-lm2
```

Bundle lands at `nsx_backup/<host>/<UTC_TS>/`. Confirm it is non-empty before
deleting anything:

```bash
B=nsx_backup/nsx-lm2.lab.local/<UTC_TS>/nsx_export/nsx-lm2.lab.local/domains/default
ls $B/groups | wc -l
ls $B/security-policies | wc -l
```

## 3. Dry run

```bash
python tools/test/wipe_target_manager.py --target nsx-lm2 --id-prefix tagload-
```

Read the per-phase counts in the summary, then verify the plan contains only
what you expect. The plan is `pre_wipe_state.json` in the run's bundle:

```bash
python - <<'PY'
import json
s = json.load(open("nsx_wipe_bundle/<UTC_TS>/<host>/pre_wipe_state.json"))
print("prefixes:", s["id_prefixes"])
for k in ("customer_services", "customer_groups", "customer_policies"):
    bad = [o["id"] for o in s[k] if not o["id"].startswith("tagload-")]
    print(k, len(s[k]), "out-of-scope:", bad[:5])
print("kept sections:", [d["id"] for d in s["default_sections"]])
PY
```

`customer_services: 0` is expected when the prefix matches no service names:
phase 4 becomes a no-op rather than needing a separate flag.

## 4. Apply

```bash
python tools/test/wipe_target_manager.py --target nsx-lm2 --id-prefix tagload- --apply
```

Repeat `--id-prefix` for multiple families:

```bash
python tools/test/wipe_target_manager.py --target nsx-lm2 \
    --id-prefix tagload- --id-prefix loadtest- --apply
```

### Pacing

One DELETE call per object. At the default `NSX_API_MAX_RPS=2` a 6500-object
wipe takes roughly 55 minutes. On a lab manager being emptied of test data,
raise it for the run:

```bash
NSX_API_MAX_RPS=10 python tools/test/wipe_target_manager.py \
    --target nsx-lm2 --id-prefix tagload- --apply
```

That brings the same wipe to about 11 minutes. Do not raise the rate against a
production manager without agreement.

## 5. Verify

```bash
python - <<'PY'
import sys; sys.path.insert(0, "app")
from nsx.nsx_policy_client import NsxPolicyClient
c = NsxPolicyClient("nsx-lm2")
print("policies:", len(c.list_security_policies()))
print("groups  :", len(c.list_groups()))
print("services:", len(c.list_services()))
PY
```

## 6. Getting the objects back

For load-test objects, **regenerate, do not restore**. They were created by a
generator, so re-running it is faster, has no 4500-file bundle to babysit, and
is deterministic with the same `--seed`:

```bash
python tools/test/create_tag_load_objects.py --mode lm --host nsx-lm2.lab.local \
    --prefix tagload- --seed <same seed> [--groups N --policies N --rules-per-policy N]
```

This is why there is no paired revert for the wipe, and why one should not be
built: a revert that replays a backup would be strictly worse than the generator
that already produces the same objects.

Restoring from the step-2 backup is only for objects that were **not**
generated (real customer config that landed on the manager). The push tools
discover files with `rglob`, so the backup's flat per-object YAML layout is
consumable directly. Push in creation order, dry-run first, then `--apply`:

```bash
B=nsx_backup/<host>/<UTC_TS>/nsx_export/<host>/domains/default
python tools/nsx/services.py push --target nsx-lm2 --services-dir $B/services
python tools/nsx/groups.py   push --target nsx-lm2 --groups-dir   $B/groups
python tools/nsx/policies.py push --target nsx-lm2 --policies-dir $B/security-policies
python tools/nsx/rules.py    push --target nsx-lm2 --rules-dir    $B/security-policies
```

That push-back path has not been exercised round-trip on real gear.

## 7. Safety properties

1. Dry-run default; `--apply` required to write.
2. `_system_owned` objects are never deleted.
3. Default sections are preserved as policies. Under `--id-prefix` their rules
   are preserved too.
4. Rules with `is_default=true` are skipped (NSX rejects deleting them).
5. Delete order is rules -> policies -> groups -> services, so nothing is
   deleted while still referenced.
6. Every run writes `pre_wipe_state.json` (what was there) and `manifest.json`
   (per-object action and result) under `nsx_wipe_bundle/<UTC_TS>/<host>/`.
7. The manifest records the `id_prefixes` used, so a run's scope is auditable
   after the fact.

## 8. Known gaps

* No paired revert, by design: load-test objects are regenerated (section 6),
  not restored. Step 2's backup is the safety net for anything on the manager
  that was NOT generated, and that push-back path is untested.
* The prefix match is on the NSX **id**, not the display name. Objects whose id
  and display name diverge will not match on what you see in the UI.
* Overlaps with `tools/test/wipe_by_prefix.py`, which also deletes by id prefix
  and is faster for pure load-test cleanup: it deletes policies first and lets
  the rules go with them (no separate per-rule phase) and runs concurrent
  workers. Use that one for routine `create_*_load_objects.py` cleanup. Use
  this one when you want the `pre_wipe_state.json` audit snapshot, service
  handling, or the Default-section rule protection described in section 1.
