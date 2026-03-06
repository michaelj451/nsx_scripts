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
  --prefix laodtest-lm3 \
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