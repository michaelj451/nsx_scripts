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
python tools/nsx/export_nsx_objects.py --manager nsx-lm1 --output-format yaml
```

``` bash
python tools/nsx/export_nsx_objects.py --manager nsx-lm2 --output-format yaml
```

``` bash
python tools/nsx/export_nsx_objects.py \
  --manager nsx-gm1 \
  --base-dir nsx_export \
  --domain-id default \
  --federation-global \
  --output-format yaml
```

``` bash
python tools/nsx/export_nsx_objects.py \
  --manager nsx-lm1 \
  --base-dir nsx_export \
  --domain-id default \
  --output-format yaml
```



-----------------------------------------------------------------

``` bash
python tools/nsx/build_group_ip_additive_from_live_members.py \
  --source-manager nsx-lm1 \
  --domain-id default \
  --source-groups-dir nsx_export/nsx-lm1.lab.local/domains/default/groups \
  --output-groups-dir nsx_groups_additive/nsx-lm3.lab.local/domains/default/groups \
  --output-format yaml \
  --copy-first \
  --continue-on-group-error
```


------------------------------------------------------------------------


``` bash
python tools/nsx/build_complete_nsx_payload.py \
  --source-manager-dir nsx_export/nsx-lm1.lab.local \
  --additive-groups-dir nsx_groups_additive/nsx-lm3.lab.local/domains/default/groups \
  --build-dir nsx_build/nsx-lm3.lab.local \
  --domain-id default \
  --overwrite

```

------------------------------------------------------------------------

## 2) Push New NSX Configuration (Dry Run)

``` bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm3 \
  --build-dir nsx_build/nsx-lm3.lab.local \
  --domain-id default \
  --dry-run
```

------------------------------------------------------------------------

## 3) Push New NSX Configuration

Preview:

``` bash
python tools/nsx/push_complete_nsx_payload.py \
  --target nsx-lm3 \
  --build-dir nsx_build/nsx-lm3.lab.local \
  --domain-id default \
  --yes
```
