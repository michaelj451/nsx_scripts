# Runbook B — Commands

See `RUNBOOK_B.md` for explanations and variants.

## Env

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

## 1. Capture

```bash
python tools/nsx/capture_nsx_state.py --source nsx-lm1 --domain-id default
```

## 2. Transform

```bash
python tools/nsx/transform_capture.py --capture nsx_capture/nsx-lm1.lab.local --csv-remap data/nonprod_map.csv --mapped-only
```

## 3. Push — dry-run

```bash
python tools/nsx/push_from_capture.py --target nsx-lm1 --transformed nsx_transformed/nsx-lm1.lab.local --groups-only
```

## 3. Push — apply

```bash
python tools/nsx/push_from_capture.py --target nsx-lm1 --transformed nsx_transformed/nsx-lm1.lab.local --groups-only --apply
```

## Rollback

```bash
yes y | python tools/nsx/push_nsx_groups_revert.py \
  --target nsx-lm1 \
  --export-root nsx_capture/nsx-lm1.lab.local/nsx_export/nsx-lm1.lab.local \
  --domain-id default \
  --apply
```
