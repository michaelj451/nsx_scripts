# Runbook WORKFLOW : one command per phase for A, C and D : macOS / Linux / bash

`tools/nsx/run_workflow.py` runs a whole workflow phase as a single command and
writes that phase's report in the same invocation. Four verbs, identical shape
for every phase: **dry run, apply, verify, rollback**.

| Verb | Command | Writes to NSX |
|---|---|---|
| Dry run | `wf --phase a` | no |
| Apply | `wf --phase a --apply` | yes |
| Verify | `wf --phase a --verify` | no |
| Rollback | `wf --phase a --rollback` then `--rollback --apply` | only with `--apply` |

| `--phase` | Runs | Needs |
|---|---|---|
| `a` | WF-A Part 1: services, groups (segments stripped), policies, rules | a capture |
| `c` | WF-C: push siblings, strip originals, amend rules | a capture |
| `d2a` | WF-D siblings, the only mandatory WF-D window | `$CSV` |
| `d2b` | WF-D pure-IP in-place remap | `$CSV` |
| `d3` | WF-D rule amendment | `d2a` applied |
| `d5` | WF-D forced strip of tag-side originals, the only step that removes IPs | a stripped bundle |

WF-D is deliberately **one change window per invocation**: 2a, 2b, 3 and 5 are
separately approved and spaced by how much risk you will absorb at a time.
There is no `--phase d` that chains them.

Background: [RUNBOOK_A.md](RUNBOOK_A.md), [RUNBOOK_C.md](RUNBOOK_C.md),
[RUNBOOK_D.md](RUNBOOK_D.md), [RUNBOOK_AVS.md](RUNBOOK_AVS.md).

---

## 0) Env

The first line makes pasted `#` comments safe in zsh; it is a no-op in bash.
Set the variables once per session; every command below follows them. `S`/`T`
are the source and target manager aliases (from `.env`), `SH`/`TH` their
hostnames, `R` the run directory, `CSV` the subnet map used by WF-D. Bundles
are keyed by **hostname**, not alias, which is why `SH` and `TH` exist.

```bash
setopt interactive_comments 2>/dev/null || true

python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"

S=nsx-lm1
T=nsx-lm2
SH=nsx-lm1.lab.local
TH=nsx-lm2.lab.local
R=nsx_avs_runs/${S}_to_${T}
CSV=data/nonprod_map.csv
mkdir -p $R
```

Then define `wf`, which is the driver with source, target and run directory
already filled in:

```bash
wf() { python tools/nsx/run_workflow.py --source $S --target $T --run-dir $R "$@"; }
```

> **Use the function, not a variable.** `W="python tools/nsx/run_workflow.py …"`
> followed by `$W --phase a` works in bash but **fails in zsh**, which does not
> word-split an unquoted parameter: zsh tries to run the whole string as one
> command name and reports `command not found`. A function behaves the same in
> both shells.

Check it before relying on it:

```bash
wf --help | head -3
```

---

## 1) Capture (read-only, source side)

The driver does not capture. Do it first, and **`--live-query` is mandatory**:
it is what splices each group's effective IPs into `groups_additive/`, the tree
WF-C and WF-D build siblings from. Without it every tag-only group looks empty,
you get siblings only for groups that already held static IPs, and nothing
errors. Measured on lm1 2026-09-11: 1 sibling without it, **7 with it**.

```bash
python tools/nsx/capture_nsx_state.py --source $S --live-query
```

Gate before going further:

```bash
grep "Summary:" $NSX_LOG_DIR/build_group_ip_additive_from_live_members_*.log | tail -1
```

| Field | Required |
|---|---|
| `ip_source` | `'effective'`, anything else is a stale or legacy bundle |
| `vm_ip_index_count` | non-zero |
| `groups_changed` | non-zero |
| `ips_added_total` | non-zero |
| `groups_errors` | **0**. Non-zero means groups have not realized yet: wait, re-run |

---

## 2) Workflow A : clone

```bash
wf --phase a
wf --phase a --apply
wf --phase a --verify
```

Review `$R/report/a/dryrun/avs_run_report.md` before the apply, then
`$R/report/a/apply/avs_run_report.md` after. They are separate paths, so
neither overwrites the other.

In the report's first table, `Would create` is exact for group rows and a
**lower bound** everywhere else: services, policies and rules never read the
target on a dry run, so a new one there counts as no measurable change. The
report states this in its own caveats block.

---

## 3) Workflow C : sibling decomposition

```bash
wf --phase c
wf --phase c --apply
wf --phase c --verify
```

The dry run builds the sibling bundle if it is missing; the apply never
rebuilds, so it pushes exactly what you previewed. Check the build counters
before approving:

```bash
python -c "
import json
m = json.load(open('$R/nsx_sibling_groups/$SH/sibling_map.json'))
print('siblings:', m['count'], ' appendix:', m['appendix'])
[print(' ', e['sibling_id'], len(e.get('ips_source') or []), 'ips') for e in m['map']]"
```

`files_seen` must equal `siblings_written + skipped_no_condition +
skipped_empty_ips`. A non-zero `skipped_empty_ips` means a tag group NSX
resolves to nothing: confirm that against the manager, since it is also what a
capture without `--live-query` produces.

---

## 4) Workflow D : one change window per invocation

```bash
wf --phase d2a --csv-remap $CSV
wf --phase d2a --csv-remap $CSV --apply
wf --phase d2a --verify

wf --phase d2b --csv-remap $CSV --apply
wf --phase d3 --apply
wf --phase d5 --apply
```

Only `d2a` is required to call a run "WF-D applied". `d2b`, `d3` and `d5` are
independent, deferrable and separately revertible, and they consume bundles an
earlier window produced: each refuses rather than rebuilding if one is missing,
because a rebuild could hand a different payload to a target whose siblings are
already live. `d5` needs a build without `--no-stripped-originals`
(RUNBOOK_D step 5a) and is the only step that removes IPs.

For an in-place WF-D run, set `T=$S` in step 0. The driver warns that source
and target match, which is the supported in-place mode.

---

## 5) Verify

```bash
wf --phase a --verify
wf --phase c --verify
wf --phase d2a --verify
```

Read-only. `a` and `c` run `verify_avs_run.py`; the WF-D phases run
`validate_wf_d.py` against the baseline that phase's push captured.

| Phase | Checks |
|---|---|
| `a`, `c` | V1 object parity, V2 siblings exist, V3 sibling IPs equal the source's effective IPs, V4 originals stripped, V5 rules reference original OR sibling, V6 membership resolves |
| `d*` | G1 nothing deleted, G2 no IP removed, G3 criteria intact, S1/S2 siblings exist and typed `IPAddress`, R1 amend completeness, R2 rules still present |

After a plain WF-A clone there is no sibling bundle, and the verifier runs V1
and V6 alone rather than refusing. **V3 is the one that matters most**: it
catches a sibling that looks structurally fine but is quietly missing
addresses.

Review `$R/report/<phase>/verify/verify_avs_run.json`.

---

## 6) Rollback

Preview first, always:

```bash
wf --phase c --rollback
wf --phase c --rollback --apply
```

| Phase | Reverts, in order |
|---|---|
| `a` | rules, policies, groups, services |
| `c` | amend-refs, stripped originals, siblings |
| `d2a` | siblings |
| `d2b` | pure-IP remap |
| `d3` | amend-refs |
| `d5` | stripped originals |

Roll back **C before A**: NSX refuses to delete a group a rule still
references.

> **`--allow-delete` is passed for you, and it matters.** Reverting a push that
> CREATED groups has to delete them. Without the flag those groups are left in
> place, listed under `deletes_blocked`, and the revert still exits 0, so a
> forgotten flag gives a silent half-rollback. The driver passes it only for
> bundles whose push created objects (siblings, pure-IP); a revert that merely
> restores payloads never gets it.

Confirm nothing was blocked:

```bash
python -c "
import json, glob
f = sorted(glob.glob('$R/nsx_sibling_groups/$SH/push_report/revert_summary_*.json'))[-1]
t = json.load(open(f))['totals']; print(t)
assert not t.get('deletes_blocked'), 'BLOCKED: ' + str(t['deletes_blocked'])"
```

---

## Where things land

```text
$R/
├── logs/<ts>_<phase>_<mode>/       one log per step, plus manifest.json
├── report/<phase>/<mode>/          scoped by BOTH, so nothing overwrites
│   ├── avs_run_report.md           operator-facing
│   └── avs_run_report.json         every row, with verdicts
├── nsx_sibling_groups/$SH/         built by phase c / d2a
├── nsx_stripped_groups/$SH/
└── nsx_pure_ip_remap/$SH/
```

Keep `$R` distinct per run: each run's siblings, stripped originals, push
reports and baselines live in their own tree, so a later rollback cannot pick
up an older run's baseline.

---

## Flags

| Flag | Purpose |
|---|---|
| `--source` / `--target` | Manager aliases. The same alias for both is the supported in-place mode, and warns |
| `--phase` | `a`, `c`, `d2a`, `d2b`, `d3`, `d5` |
| `--apply` | Write. Default is a dry run |
| `--verify` | Read-only check instead of pushing |
| `--rollback` | Undo the phase. Combine with `--apply` to write |
| `--csv-remap` | Required for `d2a` / `d2b`. Not needed for verify or rollback |
| `--run-dir` | Default `nsx_avs_runs/<source>_to_<target>` |
| `--appendix` | Sibling suffix. Default: `OBJECT_APPENDIX` (`_np_ips`) for phase `c`, `OBJECT_APPENDIX_AVS` (`_avs_ips`) for the `d*` phases. The driver picks per phase and refuses if WF-D would share WF-C's suffix. **Do not change either between runs**: a different suffix creates a second, parallel sibling set rather than renaming anything |
| `--domain-id` | Default `default` |
| `--continue-on-error` | Keep going after a failed step. Default is to stop, so a broken push does not cascade into the next dependency level |

Exit code is 0 only when every step succeeded. The report is written even when
a step fails, so a failed run is still auditable.

---

## Known behaviours worth knowing before you run

**Re-running A onto a target that already has C applied.** The rules push
preserves group refs that exist only on the target, so WF-C / WF-D sibling refs
survive a re-clone. This is the default; `rules.py push --replace-refs` opts
back into overwriting them. Verified on lm2 2026-09-11: a WF-A re-run kept all
14 sibling refs, shown in the report as `target-only refs kept: 14`.

**A re-run also re-adds IPs that C stripped.** WF-A pushes the raw export, so a
tag-side original that C stripped comes back with its static IPs, and C's strip
step removes them again on the next C run. Visible in the report as a positive
IP delta on those groups.

**The step-through gate does not gate when driven.** `--intentional-ip-removal`
auto-sets `--batch-size 1`, and through the driver that prompt gets non-TTY
stdin and is auto-approved. Each decision is recorded in `summary.json` as
`auto_approve_non_tty`, so it stays auditable, but if you want a real operator
gate on a production strip, run that step from your own terminal.

**Group expressions are replaced wholesale.** The IP list is protected by the
additive contract, but a tag criterion added by hand on the target would be
overwritten by a push.
