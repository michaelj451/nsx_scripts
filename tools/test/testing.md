python create_load_objects.py \
  --mode gm \
  --host nsx-gm2.lab.local \
  --domain-id default \
  --groups 1000 \
  --policies 500 \
  --rules-per-policy 20 \
  --groups-per-side 5 \
  --prefix chg123457 \
  --base-cidr 10.4.0.0/16




python tools/test/create_load_objects.py \
  --mode gm \
  --host nsx-gm2.lab.local \
  --domain-id nsx-lm4.lab.local \
  --groups 200 \
  --policies 10 \
  --rules-per-policy 20 \
  --groups-per-side 5 \
  --prefix loadtest2 \
  --base-cidr 10.6.0.0/16