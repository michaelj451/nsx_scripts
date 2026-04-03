python tools/test/create_load_objects.py \
  --mode gm \
  --host nsx-gm2.lab.local \
  --domain-id default \
  --user "$NSX_USER" \
  --password "$NSX_PASS" \
  --groups 1000 \
  --policies 10 \
  --rules-per-policy 20 \
  --groups-per-side 3 \
  --single-ips-per-group 5 \
  --subnets-per-group 5 \
  --subnet-prefix 30 \
  --ranges-per-group 5 \
  --range-width 2 \
  --throttle-rps 0 \
  --prefix loadtest-gm1 \
  --base-cidr 10.4.0.0/16

python tools/test/create_load_objects.py \
  --mode gm \
  --host nsx-gm2.lab.local \
  --domain-id nsx-lm3.lab.local \
  --user "$NSX_USER" \
  --password "$NSX_PASS" \
  --groups 100 \
  --policies 10 \
  --rules-per-policy 20 \
  --groups-per-side 3 \
  --single-ips-per-group 5 \
  --subnets-per-group 5 \
  --subnet-prefix 30 \
  --ranges-per-group 5 \
  --range-width 2 \
  --throttle-rps 0 \
  --prefix loadtest-lm3 \
  --base-cidr 10.5.0.0/16

python tools/test/create_load_objects.py \
  --mode gm \
  --host nsx-gm2.lab.local \
  --domain-id nsx-lm4.lab.local \
  --user "$NSX_USER" \
  --password "$NSX_PASS" \
  --groups 100 \
  --policies 10 \
  --rules-per-policy 20 \
  --groups-per-side 3 \
  --single-ips-per-group 5 \
  --subnets-per-group 5 \
  --subnet-prefix 30 \
  --ranges-per-group 5 \
  --range-width 2 \
  --throttle-rps 0 \
  --prefix loadtest-lm4 \
  --base-cidr 10.6.0.0/16

### ADD GROUPS TO RULES

python tools/test/add_groups_to_rules.py \
  --mode gm \
  --host nsx-gm2.lab.local \
  --domain-id default \
  --group-domain-id nsx-lm3.lab.local \
  --group-prefix laodtest-lm3 \
  --group-start 1 \
  --group-end 10 \
  --add-to both \
  --apply

python tools/test/add_groups_to_rules.py \
  --mode gm \
  --host nsx-gm2.lab.local \
  --domain-id default \
  --group-domain-id nsx-lm4.lab.local \
  --group-prefix loadtest-lm4 \
  --group-start 1 \
  --group-end 10 \
  --add-to both \
  --apply

### FOR TESTING ONLY ---- DESTRUCTIVE ----- ###

python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-gm2 \
  --federation-global \
  --domain-id nsx-lm3.lab.local \
  --apply

python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-gm2 \
  --federation-global \
  --domain-id nsx-lm4.lab.local \
  --apply

python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-gm2 \
  --federation-global \
  --domain-id default \
  --apply



python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-lm3 \
  --domain-id default \
  --apply


## BUILD NSX IMPORT TREE ##

python tools/test/build_nsx_import_tree.py \
  --source nsx-gm1 \
  --target nsx-gm2 \
  --export-base nsx_export \
  --import-base nsx_import \
  --input-format yaml \
  --federation-global \
  --force


python tools/test/build_nsx_import_tree.py \
  --source nsx-gm1 \
  --target nsx-lm3 \
  --export-base nsx_export \
  --import-base nsx_import \
  --input-format yaml \
  --force


## COMPILE POLICY TREE ##

python tools/test/compile_nsx_policies.py \
  --target nsx-gm2 \
  --import-base nsx_import \
  --input-format yaml \
  --output-format yaml \
  --force


python tools/test/compile_nsx_policies.py \
  --target nsx-lm3 \
  --import-base nsx_import \
  --input-format yaml \
  --output-format yaml \
  --force

## PUSH OBJECTS FROM ONE GM TO ANOTHER ##

# existing behavior
python tools/test/push_nsx_object_tree.py \
  --target nsx-gm2 \
  --import-base nsx_import \
  --domain-id default \
  --federation-global \
  --apply \
  --push-type all

python tools/test/push_nsx_object_tree.py \
  --target nsx-lm3 \
  --import-base nsx_import \
  --domain-id default \
  --apply \
  --push-type all


# only services
python tools/test/push_nsx_object_tree.py \
  --target nsx-gm2 \
  --import-base nsx_import \
  --domain-id default \
  --apply \
  --push-type services

  # only groups
python tools/test/push_nsx_object_tree.py \
  --target nsx-gm2 \
  --import-base nsx_import \
  --domain-id default \
  --federation-global \
  --apply \
  --push-type groups

# only rules / compiled policies
python tools/test/push_nsx_object_tree.py \
  --target nsx-gm2 \
  --import-base nsx_import \
  --domain-id default \
  --apply \
  --push-type rules