# NSX Global Manager – Parallel Datacenter Migration Runbook

This runbook documents the **safe, additive migration process** for introducing a new datacenter
(IP space) into NSX using **Global Manager**, while keeping the existing datacenter active.

Key principles:
- **Groups are duplicated, not modified**
- **Rules are updated additively (old_group + new_group)**
- **No Local Manager–only objects are pushed**
- **Only the Global Manager default domain is modified**
- **Changes can be planned (dry-run) or committed**
- **Rules are updated using PATCH (not PUT) to avoid conflicts**
- **Publishing/enforcement can be done manually in the UI if required**

---

## Directory Overview

| Directory | Purpose |
|---------|--------|
| `nsx_export/` | Read-only export from Global Manager |
| `nsx_remapped_groups/` | Newly created IP-based groups (e.g. `_m2`) |
| `nsx_updated_rules/` | Updated rule files referencing both old and new groups |
| `nsx_logs/` | Log output from all scripts |

---

## 1) Set Python Path (repo root)

```bash
export PYTHONPATH="$PWD/app"
```

---

## 2) Export NSX Objects from Global Manager (YAML)

### Export everything (all domains)
```bash
python tools/nsx/export_nsx_objects.py   --federation-global   --output-format yaml   --all-domains   --manager nsx-gm1
```

### OR export only the default domain
```bash
python tools/nsx/export_nsx_objects.py   --federation-global   --output-format yaml   --manager nsx-gm1   --domain default
```

---

## 3) Create New (Remapped) IP-Based Groups

Generate new IP-based groups from a subnet mapping CSV.
These groups represent the **new datacenter IP space**.

```bash
python tools/nsx/create_new_group_files.py   --csv data/subnet_map.csv
```

Output:
- `nsx_remapped_groups/`
- New groups use a deterministic suffix (example: `_m2`)
- Original groups are untouched

---

## 4) Plan Group Push to Global Manager (Dry Run)

```bash
python tools/nsx/push_nsx_groups.py   --target nsx-gm1   --domain-id default   --federation-global
```

No changes are applied.

---

## 5) Apply Group Push to Global Manager

```bash
python tools/nsx/push_nsx_groups.py   --target nsx-gm1   --domain-id default   --federation-global   --apply
```

At this point:
- New `_m2` groups exist in GM
- No rules reference them yet

---

## 6) Create Updated Rule Files (Dry Run)

This step **adds new groups to rules only when the new group actually exists**.
Rules are updated additively:

```
old_group  →  old_group + new_group
```

Dry run:
```bash
python tools/nsx/create_new_rule_files.py   --in-dir nsx_export/nsx-gm1.lab.local   --remapped-groups-dir nsx_remapped_groups   --dry-run
```

Review output in console and logs:
- `nsx_logs/create_new_rule_files.log`

---

## 7) Create Updated Rule Files (Write Output)

```bash
python tools/nsx/create_new_rule_files.py   --in-dir nsx_export/nsx-gm1.lab.local   --remapped-groups-dir nsx_remapped_groups
```

Output:
- `nsx_updated_rules/`

Only rules that reference existing new groups are modified.

---

## 8) Plan Rule Push to Global Manager (PLAN)

Reads from `nsx_updated_rules` by default.

```bash
python tools/nsx/push_nsx_rules.py   --target nsx-gm1   --federation-global   --strip-keys
```

This prints exactly which rules **would** be updated.

---

## 9) Commit Rule Push to Global Manager (PATCH)

```bash
python tools/nsx/push_nsx_rules.py   --target nsx-gm1   --federation-global   --strip-keys   --commit
```

Important behavior:
- Uses **PATCH**, not PUT
- Existing rules are **updated in place**
- No duplicate rule creation errors
- Only default-domain GM rules are touched

---

## Enforcement / Publish Notes

Depending on your NSX GM configuration:
- Changes may remain in **Draft** state
- A manual **Publish** action in the UI may be required
- This is intentional and allows controlled rollout

---

## Safety Guarantees

- ❌ No Local Manager–only objects pushed
- ❌ No group IDs reused
- ❌ No phantom groups referenced
- ❌ No rule deletions
- ✅ Fully additive
- ✅ Deterministic and repeatable
- ✅ Auditable via logs and YAML diffs

---

## Logs

All scripts log to:
```
nsx_logs/
```

Key files:
- `create_new_rule_files.log`
- `push_nsx_groups.log`
- `push_nsx_rules.log`

---

## Summary

This workflow enables a **parallel datacenter migration** in NSX Global Manager with:
- zero downtime
- zero destructive changes
- full rollback capability (simply stop publishing)

This runbook is safe to repeat and suitable for CAB-reviewed production execution.

1)  Export All Objects
python tools/nsx/export_nsx_objects.py --federation-global --manager nsx-gm1 --output-format yaml --all-domains

2)  Remap Groups
python tools/nsx/add_mapped_ips_to_groups_files.py      

3)  Push Groups to GM

python tools/nsx/push_nsx_groups.py --federation-global --target nsx-gm1

python tools/nsx/push_nsx_groups.py --federation-global --target nsx-gm1 --apply

4) Push Groups to LM

python tools/nsx/push_nsx_groups.py \
  --target nsx-gm1 \
  --federation-global \
  --input-dir nsx_groups_additive \
  --domain-id nsx-lm1.lab.local \
  --apply