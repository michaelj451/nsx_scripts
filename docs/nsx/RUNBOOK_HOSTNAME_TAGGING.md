# Runbook: hostname tagging, plan to apply : macOS / Linux / bash

Operational path for applying VM hostname tags: take the plan directory a
read-only dry run already produced, push it, verify it, revert it if needed.
Variable-driven throughout, and it documents the crash-resume behaviour that
`push_hostname_tags.py` has but no runbook covered.

Related docs, and what each is for:

| Doc | Use it for |
|---|---|
| [RUNBOOK_VM_TAGS.md](RUNBOOK_VM_TAGS.md) | Classification rules (what makes a VM eligible), the long-form narrative, and the separate export + build-plan variant |
| [RUNBOOK_INFO_GATHER.md](RUNBOOK_INFO_GATHER.md) | Step 4 produces the plan this runbook consumes, as part of a read-only evidence pack |
| **This doc** | Getting that plan applied safely, including resume after a crash |

---

## Safety properties

| Property | Behaviour |
|---|---|
| Default mode | `push` and `revert` are **dry-run unless `--apply`** is passed. Both. |
| Plan source | The same `eligible.json` a dry run wrote. `dryrun_hostname_tags.py` imports `classify_vm` from `build_hostname_tag_plan.py`, so the preview and the apply cannot disagree. |
| Write shape | Read-modify-write per VM. Push re-reads live tags first and **adds** the hostname tag; existing tags are preserved. |
| Tag cap guard | A VM whose live tag count has reached `VM_TAGS_MAX_TAGS_PER_VM` (default 30) since the plan was built is refused, not truncated. |
| Crash durability | Every VM decision is appended to a checkpoint and **flushed + fsynced**, so it survives `kill -9`. |
| Resume | `--resume` skips work already done, but **re-verifies each VM against live NSX first** rather than trusting the file. |
| Wrong-plan guard | Resume validates manager host, plan dir, and a SHA256 of the plan. Mismatch stops the run unless `--force-plan-mismatch`. |
| Revert | Driven by the manifest the apply wrote, with its own `--resume` and `--force-manifest-mismatch`. |

---

## 0) Variables

```bash
setopt interactive_comments 2>/dev/null || true

python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"

M=nsx-lm2                    # manager alias from .env
H=nsx-lm2.lab.local          # its hostname; plan dirs are keyed by hostname
G=nsx_info_tagging           # session dir

# The tools read these from .env; your shell does not have them, so mirror
# them here for the globs below. Match whatever .env says.
LOGS=$PWD/nsx_logs           # NSX_LOG_DIR    : push manifests + checkpoints
VMFILES=$PWD/nsx_vm_files    # NSX_VM_LOG_DIR : validation reports
```

Hostname tagging is **Local Manager only**. A Global Manager has no VM
inventory; in a federation run this once per site LM.

---

## 1) Plan

Either reuse the plan from an evidence-pack run, or make a fresh one. Both
write the same directory shape.

Fresh:

```bash
python tools/reports/dryrun_hostname_tags.py \
  --manager $M \
  --output-base $G \
  --overwrite
```

Then pin the newest plan directory rather than typing a timestamp:

```bash
: "${G:?set G first (step 0)}" "${H:?set H first (step 0)}"
PLAN=$(ls -dt "$G/$H"/hostname_tags_dryrun/*/ 2>/dev/null | head -1); PLAN=${PLAN%/}
[ -n "$PLAN" ] || { echo "No plan dir under $G/$H/hostname_tags_dryrun - run step 1 first" >&2; }
[ -f "$PLAN/eligible.json" ] || { echo "$PLAN has no eligible.json - not a valid --plan-dir" >&2; }
echo "$PLAN"
```

---

## 2) Read the plan before pushing

```bash
head -30 "$PLAN/plan.md"
python3 -c "import json;d=json.load(open('$PLAN/eligible.json'));print(d['count'],'eligible')"
```

`plan.md` carries the classification counts. Check two things:

- **`eligible`** is the set that will actually be written.
- **flagged for review** is where the classifier was not confident. Read those
  before applying, not after.

The skip buckets each have their own file (`skip_has_tag.json`,
`skip_excluded.json`, `skip_length_out_of_range.json`, `skip_invalid_name.json`,
`skip_edge.json`, `skip_other_type.json`, `skip_too_many_tags.json`) so you can
see exactly why any VM was left out.

---

## 3) Push, dry-run

No `--apply`, so nothing is written:

```bash
python tools/vm_tags/push_hostname_tags.py \
  --manager $M \
  --plan-dir $PLAN
```

This still contacts NSX read-only to compare the plan against live tags, so it
surfaces drift since the plan was built.

---

## 4) Push, apply

```bash
python tools/vm_tags/push_hostname_tags.py \
  --manager $M \
  --plan-dir $PLAN \
  --apply
```

With `--apply` and no `--batch-size`, batch size defaults to **1**: it prompts
after every VM. At each prompt: `Y`/Enter continue, `n` reset to 1, `x` exit,
or a number to change the batch size. Pass `--batch-size 0` to disable prompts
for an unattended run.

Because prompts are on by default, **do not background or pipe this command**
unless you pass `--batch-size 0`.

---

## 5) If it dies, resume where it stopped

Push appends every VM decision to a checkpoint and flushes plus fsyncs it, so
a hard kill loses nothing. Both live under:

```
$LOGS/reports/vm_tags_push/$H/
    <RUN_TS>_apply.progress.jsonl     incremental, while running
    <RUN_TS>_apply.done.jsonl         renamed on clean completion
    <RUN_TS>_apply.json               the manifest revert consumes
```

The rename matters: a `.progress.jsonl` still present means that run did not
finish. Find the newest interrupted one and resume it:

```bash
CP=$(ls -t "$LOGS"/reports/vm_tags_push/$H/*_apply.progress.jsonl 2>/dev/null | head -1)
echo "$CP"

python tools/vm_tags/push_hostname_tags.py \
  --manager $M \
  --plan-dir $PLAN \
  --apply \
  --resume "$CP"
```

Resume does not blindly trust the checkpoint. It logs
`RESUME: N VM(s) already recorded as success ... Will verify each is still
tagged in live NSX before skipping`, so a tag removed between the crash and
the resume is re-applied rather than silently skipped.

It also refuses to resume onto different inputs: manager host, plan directory,
and a SHA256 of the plan must all match. If you rebuilt the plan, that guard
fires. Prefer resuming against the original plan; `--force-plan-mismatch`
exists but means you are applying a checkpoint to a plan it was not made from.

---

## 6) Validate, after the apply

This is a **post-push** check: for every eligible VM, does live NSX now carry
the expected hostname tag? Running it before the apply reports everything as
missing, which is correct but useless.

```bash
python tools/vm_tags/validate_hostname_tags.py \
  --manager $M \
  --plan-dir $PLAN
```

Buckets: `match`, `mismatch_wrong_value`, `missing_hostname_tag`,
`missing_on_target`. A healthy result is everything in `match` and the rest
empty.

Report: `$VMFILES/vm_tags_validation/<TS>_<manager>/validation_report.{json,md}`

> Note: [RUNBOOK_VM_TAGS.md](RUNBOOK_VM_TAGS.md) section 5 states this lands
> under `nsx_logs/`. That is wrong. `validate_hostname_tags.py` builds the
> path from `nsx_vm_log_dir` (`NSX_VM_LOG_DIR`, i.e. `nsx_vm_files/`).

---

## 7) Revert

Revert is driven by the manifest the apply wrote, not by the plan, so it undoes
exactly what that run added.

```bash
MAN=$(ls -t "$LOGS"/reports/vm_tags_push/$H/*_apply.json | head -1)
echo "$MAN"

# dry-run first (default)
python tools/vm_tags/revert_hostname_tags.py --manager $M --manifest "$MAN"

# then apply
python tools/vm_tags/revert_hostname_tags.py --manager $M --manifest "$MAN" --apply
```

**Revert is dry-run by default too.** Forgetting its `--apply` during an
incident is the common trap: it prints what it would undo and exits 0 having
changed nothing.

Revert has the same `--resume` and a `--force-manifest-mismatch` guard.

---

## 8) Caveats

| Caveat | Detail |
|---|---|
| LM only | A Global Manager has no fabric VM inventory. Run per site LM in a federation. |
| Plan is a snapshot | Push re-reads live tags and refuses VMs at the tag cap, but a plan built long before the change window can list VMs that no longer exist. Re-run step 1 if the gap is large. |
| Additive only | Push adds a hostname tag; it does not remove or rewrite existing tags. Changing an existing hostname tag means revert then re-push. |
| Prompts by default | `--apply` implies `--batch-size 1`. Unattended runs need `--batch-size 0`. |
| Interrupted run leaves a `.progress.jsonl` | That is the resume input, not an error. It is renamed to `.done.jsonl` only on clean completion. |
