# Runbook B — Commands

Three commands, same as Runbook A — different flags. See `RUNBOOK_B.md` for the full explanation.

## Step 0: Env

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

---

## B.1) Capture nsx-lm1 (read-only)

```bash
python tools/nsx/capture_nsx_state.py \
  --source nsx-lm1 \
  --domain-id default
```

Output: `nsx_capture/nsx-lm1.lab.local/` (overwritten each run). Review `summary.txt` and `affected_rule_reports/affected_rules_impact.json` before continuing.

---

## B.2) Transform — CSV subnet remap (offline)

```bash
python tools/nsx/transform_capture.py \
  --capture nsx_capture/nsx-lm1.lab.local \
  --csv-remap data/nonprod_map.csv \
  --mapped-only
```

Output: `nsx_transformed/nsx-lm1.lab.local/`. Review `summary.txt` and `transform_report/group-ip-remap/summary_update.json` before pushing.

### Transform variants

Without `--mapped-only` (append CSV-mapped IPs, keep originals):

```bash
python tools/nsx/transform_capture.py --capture <capture> --csv-remap data/nonprod_map.csv
```

Bidirectional mapping:

```bash
python tools/nsx/transform_capture.py --capture <capture> --csv-remap data/nonprod_map.csv --mapped-only --bidirectional
```

---

## B.3a) Dry-run groups-only push to nsx-lm1

```bash
python tools/nsx/push_from_capture.py \
  --target nsx-lm1 \
  --transformed nsx_transformed/nsx-lm1.lab.local \
  --groups-only
```

Output: `nsx_push/nsx-lm1.lab.local/` (overwritten each run). Review `summary.txt` and `push_report/summary_*.json`.

---

## B.3b) Apply groups-only push to nsx-lm1

```bash
python tools/nsx/push_from_capture.py \
  --target nsx-lm1 \
  --transformed nsx_transformed/nsx-lm1.lab.local \
  --groups-only \
  --apply
```

Live validation runs automatically after `--apply`.

---

## Rollback (groups-only)

The pre-push baseline of nsx-lm1 lives at `nsx_capture/nsx-lm1.lab.local/` (full capture taken automatically by the push step).

```bash
# Dry-run preview
PYTHONPATH="$PWD/app" python tools/nsx/push_nsx_groups_revert.py \
  --target nsx-lm1 \
  --export-root nsx_capture/nsx-lm1.lab.local/nsx_export/nsx-lm1.lab.local \
  --domain-id default

# Apply rollback
PYTHONPATH="$PWD/app" python tools/nsx/push_nsx_groups_revert.py \
  --target nsx-lm1 \
  --export-root nsx_capture/nsx-lm1.lab.local/nsx_export/nsx-lm1.lab.local \
  --domain-id default \
  --apply
```
