# Runbook A — Commands

Three commands. See `RUNBOOK_A.md` for the full explanation.

## Step 0: Env — macOS / Linux

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

## Step 0: Env — Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

## Step 0: Env — Windows (Command Prompt)

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r docker\requirements-pip.txt
set PYTHONPATH=%CD%\app
```

---

## Step 1: Capture nsx-lm1 (read-only)

```bash
python tools/nsx/capture_nsx_state.py \
  --source nsx-lm1 \
  --domain-id default
```

Output: `nsx_capture/nsx-lm1.lab.local/<UTC_TS>/`. Review `summary.txt` and `manifest.json` before continuing.

### Optional capture variants

Skip the live VM-IP enrichment (groups stay as raw export):

```bash
python tools/nsx/capture_nsx_state.py --source nsx-lm1 --no-live-members
```

GM source:

```bash
python tools/nsx/capture_nsx_state.py --source nsx-gm1 --federation-global
```

---

## Step 2: Transform the capture (offline)

```bash
python tools/nsx/transform_capture.py \
  --capture nsx_capture/nsx-lm1.lab.local/<UTC_TS> \
  --segment-mode convert
```

Output: `nsx_transformed/nsx-lm1.lab.local/<UTC_TS>/`. Review `summary.txt` and `transform_report/segments_stripped.json` before pushing.

### Transform variants

Strip segment refs instead of converting them to CIDRs:

```bash
python tools/nsx/transform_capture.py --capture <capture-bundle> --segment-mode strip
```

Leave segment refs untouched (target must have the same segments):

```bash
python tools/nsx/transform_capture.py --capture <capture-bundle> --segment-mode skip
```

Use the raw exported groups instead of the live-member-enriched ones:

```bash
python tools/nsx/transform_capture.py --capture <capture-bundle> --source-groups raw
```

---

## Step 3a: Push dry-run to nsx-lm2

```bash
python tools/nsx/push_from_capture.py \
  --target nsx-lm2 \
  --transformed nsx_transformed/nsx-lm1.lab.local/<UTC_TS>
```

Output: `nsx_push/nsx-lm2.lab.local/` (overwritten each run). Review `summary.txt` and `push_report/summary_*.json`.

---

## Step 3b: Apply push to nsx-lm2

```bash
python tools/nsx/push_from_capture.py \
  --target nsx-lm2 \
  --transformed nsx_transformed/nsx-lm1.lab.local/<UTC_TS> \
  --apply
```

A live validation runs automatically after `--apply` and its report is mirrored into the push bundle's `validate_report/`.

---

## Sandbox: Dry-run / Apply to nsx-lm3

Same transformed bundle, different target:

```bash
python tools/nsx/push_from_capture.py --target nsx-lm3 --transformed <transformed-bundle>
python tools/nsx/push_from_capture.py --target nsx-lm3 --transformed <transformed-bundle> --apply
```

---

## Rollback

The push bundle's `target_baseline/` directory holds the pre-push GET-only export of the target.

```bash
# Dry-run preview
PYTHONPATH="$PWD/app" python tools/nsx/push_complete_nsx_revert.py \
  --target nsx-lm2 \
  --export-root nsx_push/nsx-lm2.lab.local/target_baseline/nsx-lm2.lab.local \
  --domain-id default

# Apply rollback
PYTHONPATH="$PWD/app" python tools/nsx/push_complete_nsx_revert.py \
  --target nsx-lm2 \
  --export-root nsx_push/nsx-lm2.lab.local/target_baseline/nsx-lm2.lab.local \
  --domain-id default \
  --apply

# Apply rollback including custom services
PYTHONPATH="$PWD/app" python tools/nsx/push_complete_nsx_revert.py \
  --target nsx-lm2 \
  --export-root nsx_push/nsx-lm2.lab.local/target_baseline/nsx-lm2.lab.local \
  --domain-id default \
  --include-services \
  --apply
```
