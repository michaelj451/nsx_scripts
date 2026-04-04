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
python3 -m venv .venv
source .venv/bin/activate
pip install -r docker/requirements-pip.txt 
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

``` bash
python tools/nsx/export_nsx_objects.py --manager nsx-lm3 --output-format yaml
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
python tools/nsx/push_remapped_groups.py --federation-global --target nsx-gm2
```

Apply:

``` bash
python tools/nsx/push_remapped_groups.py --federation-global --target nsx-gm1 --apply
```
``` bash
python tools/nsx/push_remapped_groups.py --federation-global --target nsx-gm2 --apply
```


## 4) Push Remapped Groups to LM

``` bash
python tools/nsx/push_remapped_groups.py --target nsx-gm1 --federation-global --input-dir nsx_groups_additive --domain-id nsx-lm1.lab.local --apply
```
``` bash
python tools/nsx/push_remapped_groups.py --target nsx-gm1 --federation-global --input-dir nsx_groups_additive --domain-id nsx-lm2.lab.local --apply
```
``` bash
python tools/nsx/push_remapped_groups.py --target nsx-gm2 --federation-global --input-dir nsx_groups_additive --domain-id nsx-lm3.lab.local --apply
```
``` bash
python tools/nsx/push_remapped_groups.py --target nsx-gm2 --federation-global --input-dir nsx_groups_additive --domain-id nsx-lm4.lab.local --apply
```


python tools/nsx/push_remapped_groups.py --target nsx-lm3 --input-dir nsx_groups_additive --domain-id default --apply

## 5a) REVERT Global managaers

Credentials are read from `.env` — no username/password args required.

Dry run (nsx-gm2):

``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm2 --export-root nsx_export/nsx-gm2.lab.local --domain-id default --federation-global
```

Dry run (nsx-gm1):

``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm1 --export-root nsx_export/nsx-gm1.lab.local --domain-id default --federation-global
```

Apply (nsx-gm2):

``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm2 --export-root nsx_export/nsx-gm2.lab.local --domain-id default --federation-global --apply
```

Apply (nsx-gm1):

``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm1 --export-root nsx_export/nsx-gm1.lab.local --domain-id default --federation-global --apply
```

## 5b) Revert non-default domains (LM domains)

LM1 and LM2 are imported under GM1; LM3 and LM4 under GM2.

Dry run:

``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm1 --export-root nsx_export/nsx-gm1.lab.local --domain-id nsx-lm1.lab.local --federation-global
```
``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm1 --export-root nsx_export/nsx-gm1.lab.local --domain-id nsx-lm2.lab.local --federation-global
```
``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm2 --export-root nsx_export/nsx-gm2.lab.local --domain-id nsx-lm3.lab.local --federation-global
```
``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm2 --export-root nsx_export/nsx-gm2.lab.local --domain-id nsx-lm4.lab.local --federation-global
```

Apply:

``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm1 --export-root nsx_export/nsx-gm1.lab.local --domain-id nsx-lm1.lab.local --federation-global --apply
```
``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm1 --export-root nsx_export/nsx-gm1.lab.local --domain-id nsx-lm2.lab.local --federation-global --apply
```
``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm2 --export-root nsx_export/nsx-gm2.lab.local --domain-id nsx-lm3.lab.local --federation-global --apply
```
``` bash
python tools/nsx/push_nsx_groups_revert.py --target nsx-gm2 --export-root nsx_export/nsx-gm2.lab.local --domain-id nsx-lm4.lab.local --federation-global --apply
```

python tools/nsx/push_nsx_groups_revert.py --target nsx-lm3 --export-root nsx_export/nsx-lm3.lab.local --domain-id default --apply


------------------------------------------------------------------------

## 5a) Push Validation

``` bash
python tools/nsx/validate_nsx_groups.py --target nsx-gm2 --expected-root nsx_groups_additive/nsx-gm2.lab.local --baseline-root nsx_export/nsx-gm2.lab.local --domain-id default --federation-global
```

``` bash
python tools/nsx/validate_nsx_groups.py --target nsx-gm2 --expected-root nsx_groups_additive/nsx-gm2.lab.local --baseline-root nsx_export/nsx-gm2.lab.local --domain-id nsx-lm3.lab.local --federation-global
```


``` bash
python tools/nsx/validate_nsx_groups.py --target nsx-gm2 --expected-root nsx_groups_additive/nsx-gm2.lab.local --baseline-root nsx_export/nsx-gm2.lab.local --domain-id nsx-lm4.lab.local --federation-global
```

## 5b) Rollback Validation

``` bash
python tools/nsx/validate_nsx_groups.py --target nsx-gm2 --expected-root nsx_export/nsx-gm2.lab.local --domain-id default --federation-global
```

``` bash
python tools/nsx/validate_nsx_groups.py --target nsx-gm2 --expected-root nsx_export/nsx-gm2.lab.local --domain-id nsx-lm3.lab.local --federation-global
```

python tools/nsx/validate_nsx_groups.py --target nsx-gm2 --expected-root nsx_export/nsx-gm2.lab.local --domain-id nsx-lm3.lab.local --federation-global


``` bash
python tools/nsx/validate_nsx_groups.py --target nsx-gm2 --expected-root nsx_export/nsx-gm2.lab.local --domain-id nsx-lm4.lab.local --federation-global
```

## FINAL - LIVE VALIDATE

``` bash
python tools/nsx/validate_nsx_groups_live.py --target nsx-gm2 --expected-root nsx_groups_additive/nsx-gm2.lab.local --domain-id default --federation-global
```

``` bash
python tools/nsx/validate_nsx_groups_live.py --target nsx-gm2 --expected-root nsx_groups_additive/nsx-gm2.lab.local --domain-id nsx-lm3.lab.local --federation-global
```

``` bash
python tools/nsx/validate_nsx_groups_live.py --target nsx-lm3 --expected-root nsx_export/nsx-lm3.lab.local --domain-id default
```

## Safety Model

This workflow is:

-   Non-destructive
-   Idempotent
-   Repeatable
-   Suitable for production CAB execution
