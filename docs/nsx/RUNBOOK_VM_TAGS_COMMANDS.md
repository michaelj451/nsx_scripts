# Runbook VM Tags - Commands (macOS / Linux)

> **This runbook is for macOS / Linux shells only (bash, zsh).**
> Windows users, see [RUNBOOK_VM_TAGS_COMMANDS_PS.md](RUNBOOK_VM_TAGS_COMMANDS_PS.md).
> Do NOT paste Windows `set VAR=%CD%\...` or backslash paths into bash/zsh:
> the backslash silently corrupts filenames and `set` is a no-op, so tools
> then fail with `ModuleNotFoundError: No module named 'nsx'`.

## Step 0: Env

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

## Step 1: Pre-change dry-run (single command)

```bash
python tools/reports/dryrun_hostname_tags.py \
  --manager nsx-lm1 \
  --output-dir nsx_logs/reports/vm_tags_plan/nsx-lm1.lab.local \
  --overwrite
```

Discover the latest plan dir (used as `--plan-dir` for the push):

```bash
PLAN=$(ls -1t nsx_logs/reports/vm_tags_plan/nsx-lm1.lab.local/ | head -1)
PLAN_DIR="nsx_logs/reports/vm_tags_plan/nsx-lm1.lab.local/$PLAN"
echo "Plan: $PLAN_DIR"
```

## Step 2a: (Optional alternative to Step 1) Export VM state

```bash
python tools/vm_tags/export_vm_tags.py \
  --manager nsx-lm1 \
  --base-dir nsx_vm_files/vm_tags_export
```

## Step 2b: (Optional alternative to Step 1) Build plan from export

```bash
python tools/vm_tags/build_hostname_tag_plan.py \
  --vm-export nsx_vm_files/vm_tags_export/nsx-lm1.lab.local/vms.json \
  --output-dir nsx_logs/reports/vm_tags_plan/nsx-lm1.lab.local \
  --overwrite
```

## Step 3: Push — dry-run

```bash
python tools/vm_tags/push_hostname_tags.py \
  --manager nsx-lm1 \
  --plan-dir "$PLAN_DIR"
```

## Step 4: Push — apply

```bash
python tools/vm_tags/push_hostname_tags.py \
  --manager nsx-lm1 \
  --plan-dir "$PLAN_DIR" \
  --apply
```

Writes an incremental checkpoint next to the manifest at
`nsx_logs/reports/vm_tags_push/nsx-lm1.lab.local/<TS>_apply.progress.jsonl`
that is flushed + fsynced after every VM. On clean completion it is renamed
to `<TS>_apply.progress.done.jsonl`. Any `.progress.jsonl` still present
without a matching `.json` manifest = orphaned run, resume candidate (see Step 4b).

## Step 4b: Resume a crashed / early-exited push

Find orphan checkpoints (any `.progress.jsonl` without a sibling `.json`):

```bash
find nsx_logs/reports/vm_tags_push -name '*.progress.jsonl' -not -name '*.done.jsonl' | while read cp; do
  manifest="${cp%.progress.jsonl}.json"
  [ ! -f "$manifest" ] && echo "ORPHAN: $cp"
done
```

Resume from a specific checkpoint (STRICT: manager and plan sha256 must match
the crashed run's checkpoint):

```bash
python tools/vm_tags/push_hostname_tags.py \
  --manager nsx-lm1 \
  --plan-dir "$PLAN_DIR" \
  --apply \
  --resume nsx_logs/reports/vm_tags_push/nsx-lm1.lab.local/<TS>_apply.progress.jsonl
```

VMs recorded as `status=success` in the checkpoint are skipped IF live NSX
confirms the tag is present. If live disagrees with the checkpoint, the VM
is skipped and logged as `checkpoint_vs_live_mismatch` for manual review.

## Step 5: Validate live NSX state

```bash
python tools/vm_tags/validate_hostname_tags.py \
  --manager nsx-lm1 \
  --plan-dir "$PLAN_DIR"
```

## Step 6: Revert — dry-run

Discover the latest push manifest:

```bash
MANIFEST=$(ls -1t nsx_logs/reports/vm_tags_push/nsx-lm1.lab.local/*_apply.json | head -1)
echo "Manifest: $MANIFEST"

python tools/vm_tags/revert_hostname_tags.py \
  --manager nsx-lm1 \
  --manifest "$MANIFEST"
```

## Step 7: Revert — apply

```bash
python tools/vm_tags/revert_hostname_tags.py \
  --manager nsx-lm1 \
  --manifest "$MANIFEST" \
  --apply
```

Same incremental-checkpoint + `--resume` semantics as push. Orphan revert
checkpoints live at
`nsx_logs/reports/vm_tags_revert/nsx-lm1.lab.local/<TS>_revert_apply.progress.jsonl`.
Resume with:

```bash
python tools/vm_tags/revert_hostname_tags.py \
  --manager nsx-lm1 \
  --manifest "$MANIFEST" \
  --apply \
  --resume nsx_logs/reports/vm_tags_revert/nsx-lm1.lab.local/<TS>_revert_apply.progress.jsonl
```
