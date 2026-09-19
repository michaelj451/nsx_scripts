# Run card: Workflow D in place on `nsx-lm1.lab.local`

Land IP-only sibling groups on a live manager, with their addresses mapped
through a CSV subnet map, so that tag-based membership can later be replaced by
literal IPs without traffic stopping. Source and target are the same manager.

Concepts and the full option set: [RUNBOOK_D.md](RUNBOOK_D.md). Per-tool
commands: [RUNBOOK_D_COMMANDS.md](RUNBOOK_D_COMMANDS.md). The driver:
[RUNBOOK_WORKFLOW.md](RUNBOOK_WORKFLOW.md).

PowerShell variant of this card: [RUN_D_LM1_PS.md](RUN_D_LM1_PS.md).

## Change windows

Workflow D is deliberately **one change window per invocation**. There is no
phase that chains them, because each is separately approved, separately
revertible and carries different risk.

| Phase | Does | Required | Removes IPs |
|---|---|---|---|
| `d2a` | Create the `_avs_ips` sibling groups | **yes** | no |
| `d2b` | Add mapped IPs to pure-IP groups in place | no | no |
| `d3` | Amend rules to reference the siblings alongside the originals | no | no |
| `d5` | Strip IPs out of the tag-side originals | no | **yes** |

Only `d2a` is required to call a run "WF-D applied". Run `d5` last, and only
once `d2a` and `d3` are applied, validated and the strip is approved.

---

## Before you start

**1. Back up the manager.** This is an in-place workflow on a live target.

```bash
python tools/nsx/backup_nsx_state.py --source nsx-lm1 --retain 14
cat nsx_backup/nsx-lm1.lab.local/latest/summary.txt
```

**2. Confirm the sibling suffix.** WF-D's siblings must not share WF-C's.

```bash
grep -E '^OBJECT_APPENDIX' .env
```

Expected: `OBJECT_APPENDIX=_np_ips` (WF-C) and `OBJECT_APPENDIX_AVS=_avs_ips`
(WF-D). WF-C siblings hold the **source** addresses and WF-D siblings hold the
**CSV-mapped** ones. A shared suffix merges mapped addresses into WF-C's
source-IP siblings, silently.

---

## 0) Env

The first line makes pasted `#` comments safe in zsh; it is a no-op in bash.

```bash
setopt interactive_comments 2>/dev/null || true

python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
export NSX_LOG_DIR="$PWD/nsx_logs"

S=nsx-lm1
T=nsx-lm1
SH=nsx-lm1.lab.local
R=nsx_avs_runs/${S}_to_${T}
CSV=data/nonprod_map.csv
export OBJECT_APPENDIX_AVS=$(grep -E '^OBJECT_APPENDIX_AVS=' .env | cut -d= -f2-)
echo "WF-D sibling suffix: $OBJECT_APPENDIX_AVS"
mkdir -p $R
```

That echo must print `_avs_ips` and not an empty string. The Python tools read
`.env` themselves, but your shell does not, and the step 5a rebuild below
interpolates the variable.

Define the driver as a **function**, with source and target both `nsx-lm1`:

```bash
wf() { python tools/nsx/run_workflow.py --source $S --target $T --run-dir $R "$@"; }
wf --help | head -3
```

The driver warns that source and target match. That is the supported in-place
mode, not a mistake.

> Use a function, not a variable. A variable holding the command string works in
> bash but fails in zsh, which does not word-split an unquoted parameter.

---

## 1) Capture the source (read-only)

**`--live-query` is mandatory.** Without it every tag-only group looks empty, the
build produces siblings only for groups that already held static IPs, and
nothing errors. Measured on lm1: 1 sibling without it, 7 with it.

```bash
python tools/nsx/capture_nsx_state.py --source $S --live-query --ip-report-csv $CSV
```

### The gate: check all five fields yourself

```bash
grep "Summary:" $NSX_LOG_DIR/build_group_ip_additive_from_live_members_*.log | tail -1
```

| Field | Required |
|---|---|
| `ip_source` | `'effective'` |
| `effective_ip_queries` | non-zero and equal to `groups_seen` |
| `groups_changed` | non-zero |
| `ips_added_total` | non-zero |
| `groups_errors` | `0`. Non-zero means groups have not realized yet: wait, re-run |

The driver checks capture success, source/domain identity, effective IP mode,
zero group errors and a successful effective-IP query for every processed group.
The optional VM index can now be empty. Review the change counts yourself;
zero additions can mean those IPs were already present in the export.
The explicit `--ip-report-csv` above enables the optional coverage report.

Then review what the CSV does and does not cover:

```bash
cat $NSX_LOG_DIR/groups_ip_report/$SH/summary.json
cat $NSX_LOG_DIR/groups_ip_report/$SH/empty_groups.json
```

Optional drift check against the last export:

```bash
python tools/nsx/compare_group_ips.py \
  --reference nsx_groups_export/$SH/groups --target $S
```

---

## 2a) Siblings (mandatory window)

```bash
# Dry run, then read the report
wf --phase d2a --csv-remap $CSV
cat $R/report/d2a/dryrun/avs_run_report.md

# Apply
wf --phase d2a --csv-remap $CSV --apply

# Validate
wf --phase d2a --verify
```

### Review gate

```bash
python -c "
import json
m = json.load(open('$R/nsx_sibling_groups/$SH/sibling_map.json'))
print('siblings:', m['count'], ' appendix:', m['appendix'])
[print(' ', e['sibling_id'], len(e.get('ips_source') or []), 'ips') for e in m['map']]"
```

| Check | Requirement |
|---|---|
| `appendix` | `_avs_ips`. `_np_ips` means the suffix fell back to WF-C's and the run must be rebuilt |
| Every sibling | non-zero IP count |
| "Addresses dropped for having no CSV mapping" | absent. If present, extend the CSV or rebuild with `--skip-uncovered` |
| Manual addresses copied verbatim | expected and listed per group. These are the group's own IPAddressExpression entries, carried across unmapped |
| `Failed` | 0 |

The baseline this apply captures is what `d5` and the validator read later:

```
$R/nsx_sibling_groups/nsx-lm1.lab.local/push_report/baselines/<ts>_target_baseline.json
```

Keep it.

---

## 2b) Pure-IP remap (optional, separate window)

Strict-additive: adds mapped IPs alongside existing ones, never removes.

```bash
wf --phase d2b --csv-remap $CSV
cat $R/report/d2b/dryrun/avs_run_report.md
wf --phase d2b --csv-remap $CSV --apply
```

---

## 3) Amend rules (optional, separate window)

Appends sibling references to `source_groups` and `destination_groups`. Strict
additive: a reference is never removed. Add `--include-scope` to the underlying
tool if scope also needs amending.

```bash
wf --phase d3
cat $R/report/d3/dryrun/avs_run_report.md
wf --phase d3 --apply
```

No `--csv-remap` is needed here: `d3` consumes the sibling map `d2a` produced.

---

## 4) Validate

Read-only. Runs G1 nothing deleted, G2 no IP removed, G3 criteria intact, S1/S2
siblings exist and are typed `IPAddress`, R1 amend completeness, R2 rules still
present. Exit `0` is all pass, `1` is at least one CRITICAL finding.

```bash
wf --phase d2a --verify
```

By hand, if you want the flags explicit:

```bash
BASE=$(find $R/nsx_sibling_groups/$SH/push_report/baselines \
  -name '*_target_baseline.json' 2>/dev/null | sort | tail -1)
echo "${BASE:?no baseline yet: phase d2a has not been applied}"

python tools/nsx/validate_wf_d.py --target $S \
  --baseline "$BASE" \
  --sibling-map $R/nsx_sibling_groups/$SH/sibling_map.json
```

Add `--phase-2-applied` after step 5 has run, and `--rules-baseline <path>` for
the R2 check.

---

## 5) Forced strip (optional, last, removes IPs)

**This is the only step that takes IPs away from a group**, and it is gated
behind `--intentional-ip-removal`, which the driver passes for this phase. Run
it only after `d2a` and `d3` are applied and validated, and the strip is
approved.

### 5a. Rebuild the bundle with stripped originals

`d2a` builds with `--no-stripped-originals`, so the stripped bundle does not
exist yet and `d5` refuses rather than rebuilding one. Produce it deliberately:

```bash
python tools/nsx/build_sibling_groups.py \
  --source $S \
  --output-base $R \
  --domain-id default \
  --appendix "$OBJECT_APPENDIX_AVS" \
  --csv-remap $CSV \
  --skip-segment-groups
```

> **`--output-base $R` is what makes this work with the driver.** RUNBOOK_D's
> step 5a omits it, because it documents the standalone path, which writes to
> the repo-root `nsx_stripped_groups/`. The driver looks inside the run dir, so
> without `--output-base` it still reports the bundle missing. Note also that
> this rebuilds the sibling bundle alongside the stripped one, which is why it
> belongs before the strip window and not between a dry run and its apply.

Confirm both halves were written:

```bash
grep -E "files seen|siblings written|stripped originals|skipped: empty IPs|errors  " \
  $(ls -t $NSX_LOG_DIR/build_sibling_groups_*.log | head -1) | sed 's/.*__main__: //'
```

`stripped originals` must be non-zero, and `files seen` must equal
`siblings written + skipped: no Condition + skipped: empty IPs`.

### 5b. Push the stripped originals

```bash
wf --phase d5
cat $R/report/d5/dryrun/avs_run_report.md
wf --phase d5 --apply
```

Read the audit block carefully. Removals print **first and in capitals**. Every
address listed there stops being matched by that group the moment this applies,
so each one must already be covered by a sibling that the rules reference, which
is what `d3` was for.

### 5c. Re-validate with phase-2 awareness

```bash
python tools/nsx/validate_wf_d.py --target $S \
  --baseline "$BASE" \
  --sibling-map $R/nsx_sibling_groups/$SH/sibling_map.json \
  --phase-2-applied
```

---

## 6) Rollback, reverse order (LIFO)

Preview first, always. Run only the windows you actually applied.

```bash
# 5: restore IPs to the tag-side originals
wf --phase d5 --rollback
wf --phase d5 --rollback --apply

# 3: remove sibling refs from rules
wf --phase d3 --rollback
wf --phase d3 --rollback --apply

# 2b: remove mapped IPs from pure-IP groups
wf --phase d2b --rollback
wf --phase d2b --rollback --apply

# 2a: delete the sibling groups
wf --phase d2a --rollback
wf --phase d2a --rollback --apply
```

**Reverse order is not optional.** NSX returns 409 on a DELETE while a rule
still references the group, so removing the siblings before removing their rule
references fails.

---

## Measured baseline, 2026-09-18 dry run

Against `nsx-lm1` holding 13 groups / 5 policies / 15 rules / 4 services, with
`data/nonprod_map.csv`. Expect this shape, not these exact numbers.

| Phase | Objects | IPs | Detail |
|---|---:|---:|---|
| `d2a` | 7 created | +30 | `_avs_ips` siblings for `network-group-0/1/2/8`, `super-nested-group`, `vm-group-1/2`. 3 manually entered addresses copied verbatim |
| `d2b` | 1 changed | +1 | `ip-address-group`; 5 further groups had nothing to add |
| `d3` | 10 changed | n/a | 16 sibling references added across 10 rules |
| `d5` | 2 changed | **-3** | `network-group-0` (-1), `super-nested-group` (-2) |

All four reported `Failed: 0`. The 7 siblings match the figure the runbook
records for a correct `--live-query` capture on this source; 1 sibling would
mean the capture was wrong.

---

## If something goes wrong

Roll back as in section 6. If the baselines are gone, restore from the bundle
taken in the preconditions and follow
[EMERGENCY_RESTORE.md](EMERGENCY_RESTORE.md). Read its rules caveat first: backup
bundles do not carry `_parent_policy_id`, so restoring rules straight from one
lands them in a policy that does not exist. That doc has the working recipe.
