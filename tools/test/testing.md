python create_load_objects.py \
  --mode gm \
  --host nsx-gm1.lab.local \
  --domain-id default \
  --groups 200 \
  --policies 10 \
  --rules-per-policy 20 \
  --groups-per-side 5 \
  --prefix chg123456 \
  --base-cidr 10.250.0.0/16




python create_load_objects.py \
  --mode lm \
  --host nsx-lm1.lab.local \
  --domain-id default \
  --groups 200 \
  --policies 10 \
  --rules-per-policy 20 \
  --groups-per-side 5 \
  --prefix loadtest1