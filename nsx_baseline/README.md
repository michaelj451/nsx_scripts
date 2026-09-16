# nsx_baseline

Permanent, version-controlled NSX configuration baselines.

This directory exists because `nsx_backup/` is **gitignored**: every baseline
taken before 2026-09-15 lived only on one laptop, and a rotating `--retain`
prune could remove it. Anything in here is committed and survives.

## What is here

| Bundle | Manager | Content |
|---|---|---|
| `nsx-gm1.lab.local/20260915_174058` | Global Manager | All 3 domains. `default` holds lm1's pre-wipe config (13 groups, 4 services, 3 policies, 13 rules); the two location-scoped domains are empty, which is their real state |
| `nsx-lm1.lab.local/20260915_174058` | Local Manager | The same configuration, LM-shaped (`/infra/` paths), ready to push back to an LM |

`_BASELINES/*.txt` names each bundle and what state it captures, matching the
convention in `nsx_backup/_BASELINES/`.

## Restoring from one of these

Follow [EMERGENCY_RESTORE.md](../docs/nsx/EMERGENCY_RESTORE.md). Point `B` at
the bundle's object root and keep `--reports-dir` **outside** this directory,
so a restore never writes its own push reports and baselines into the snapshot
it is reading:

```bash
B=nsx_baseline/nsx-lm1.lab.local/20260915_174058/nsx_export/nsx-lm1.lab.local/domains/default
R=nsx_restore/nsx-lm1.lab.local/$(date -u +%Y%m%d_%H%M%S)
```

Order is services, groups, policies, rules. Dry run first; `--apply` to write.

## Two things these bundles get right that a raw export does not

**Rules carry `_parent_policy_id`.** Bundles produced by
`export_nsx_objects.py` (which includes every `nsx_backup/` bundle and every
`nsx_build/` payload) do not. Without it `rules.py push` falls back to the
containing folder name, which is a slugified hash such as
`Start-olicy-1bbe902d` rather than the real policy id `Start_Policy`, and every
rule 404s. That failure was reproduced on 2026-09-15 and the field is injected
here.

**The GM bundle covers every domain.** `--all-domains` now defaults on for
`nsx-gm*` sources. A GM backup restricted to `default` can be nearly empty on a
federated manager and still report `NSX BACKUP OK`.

## Provenance

lm1 was wiped on 2026-09-15 at 17:07 UTC. Its configuration was recovered from
the `nsx_build/nsx-lm1_to_gm1` payload, pushed to gm1's `default` domain, and
verified object-for-object against
`nsx_wipe_bundle/20260915_170727/nsx-lm1.lab.local/pre_wipe_state.json`: 13
groups, 4 services, 3 policies, 13 rules, **zero content differences** once
read-only fields (`policy_id`, `_revision`) and list ordering are normalised.
NSX returns group-reference lists as sets, so order carries no meaning.
