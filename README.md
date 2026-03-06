# NSX Global Manager – Parallel Datacenter Migration Runbook

# NSX Global Manager -- Parallel Datacenter Migration Runbook

## Summary

This workflow enables a **parallel datacenter migration** in NSX Global
Manager with:

-   Zero downtime\
-   Zero destructive changes\
-   Full rollback capability (simply stop publishing)

This runbook is safe to repeat and suitable for CAB-reviewed production
execution.

------------------------------------------------------------------------

## 0) Set Python Path

``` bash
export PYTHONPATH="$PWD/app"
```

------------------------------------------------------------------------

## 1) Export All Objects (GM Global)

``` bash
python tools/nsx/export_nsx_objects.py --federation-global --manager nsx-gm1 --output-format yaml --all-domains
```

``` bash
python tools/nsx/export_nsx_objects.py --federation-global --manager nsx-gm2 --output-format yaml --all-domains
```

------------------------------------------------------------------------

## 2) Remap Groups (Build Additive Groups)

``` bash
python tools/nsx/add_mapped_ips_to_groups_files.py
```

------------------------------------------------------------------------

## 3) Push Remapped Groups to GM (Additive / Remapped)

Preview:

``` bash
python tools/nsx/push_remapped_groups.py --federation-global --target nsx-gm1
```

Apply:

``` bash
python tools/nsx/push_remapped_groups.py --federation-global --target nsx-gm1 --apply
```
``` bash
python tools/nsx/push_remapped_groups.py --federation-global --target nsx-gm2 --apply
```
------------------------------------------------------------------------

## 4) Push Remapped Groups to LM

``` bash
python tools/nsx/push_remapped_groups.py --target nsx-gm1 --federation-global --input-dir nsx_groups_additive --domain-id nsx-lm1.lab.local --apply
```
``` bash
python tools/nsx/push_remapped_groups.py --target nsx-gm2 --federation-global --input-dir nsx_groups_additive --domain-id nsx-lm3.lab.local --apply
```
``` bash
python tools/nsx/push_remapped_groups.py --target nsx-gm2 --federation-global --input-dir nsx_groups_additive --domain-id nsx-lm4.lab.local --apply
```

------------------------------------------------------------------------

## 5) Export All Local Manager Objects (LM1 example)

``` bash
python tools/nsx/export_nsx_objects.py --federation-global --manager nsx-gm1 --output-format yaml --base-dir nsx_export_promote --all-domains
```
``` bash
python tools/nsx/export_nsx_objects.py --federation-global --manager nsx-gm2 --output-format yaml --base-dir nsx_export_promote --all-domains
```

------------------------------------------------------------------------

## 6) Promote Local Groups to Global

Dry Run:

``` bash
python tools/nsx/promote_local_groups.py
```

Apply:

``` bash
python tools/nsx/promote_local_groups.py  --all-lm-domains
```

------------------------------------------------------------------------

## 7) Push Promoted Groups (Global-Infra)

Dry Run:

``` bash
python tools/nsx/push_promoted_lm_groups.py \
  --manager gm1 \
  --federation-global \
  --dry-run
```

Apply:

``` bash
python tools/nsx/push_promoted_lm_groups.py \
  --manager gm1 \
  --federation-global
```
``` bash
python tools/nsx/push_promoted_lm_groups.py \
  --manager gm2 \
  --federation-global
```

------------------------------------------------------------------------

## 8) Generate Updated Rule Files (From Promoted Groups)

Dry Run:

``` bash
python tools/nsx/update_rules_from_promoted_groups.py \
  --gm-name nsx-gm1.lab.local \
  --rules-domain default \
  --dst-domain default \
  --suffix _svb_m3 \
  --dry-run
```

Write Changed Files Only:

``` bash
python tools/nsx/update_rules_from_promoted_groups.py \
  --gm-name nsx-gm1.lab.local \
  --rules-domain default \
  --dst-domain default \
  --suffix _svb_m3
```
``` bash
python tools/nsx/update_rules_from_promoted_groups.py \
  --gm-name nsx-gm2.lab.local \
  --rules-domain default \
  --dst-domain default \
  --suffix _svb_m3
```



------------------------------------------------------------------------

## 9) Push Rules

``` bash
python tools/nsx/push_updated_rules.py \
  --manager gm1 \
  --federation-global \
  --rules-domain default
```

``` bash
python tools/nsx/push_updated_rules.py \
  --manager gm1 \
  --federation-global \
  --rules-domain default \
  --apply
```
``` bash
python tools/nsx/push_updated_rules.py \
  --manager gm2 \
  --federation-global \
  --rules-domain default \
  --apply
```

------------------------------------------------------------------------

Write Complete Ruleset Tree:

``` bash
python tools/nsx/update_rules_from_promoted_groups.py \
  --gm-name nsx-gm1.lab.local \
  --rules-domain default \
  --dst-domain default \
  --suffix _to_gm \
  --write-all --copy-unchanged
```

Push Updated Ruleset Tree:

python tools/nsx/push_updated_rules.py --federation-global


------------------------------------------------------------------------

## Operational Notes

-   Group matching is performed using **NSX object IDs**, not display
    names.

-   Promoted groups are expected to follow the ID pattern:

        <original_id>_to_gm

-   Rule updates are deterministic and reversible.

-   Rollback is achieved by simply not publishing updated rules.

-   All steps support dry-run validation before execution.



------------------------------------------------------------------------

## Validation Checklist

-   ✅ Promoted groups exist in `/global-infra/domains/default/groups`
-   ✅ Updated rule files generated correctly
-   ✅ Dry-run shows expected rule modifications
-   ✅ Change logs generated under `nsx_logs/`

------------------------------------------------------------------------

## Safety Model

This workflow is:

-   Non-destructive
-   Idempotent
-   Repeatable
-   Suitable for production CAB execution
