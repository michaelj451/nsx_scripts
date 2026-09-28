# Runbook WORKFLOW : one command per phase for A, C and D : macOS / Linux / bash

`tools/nsx/run_workflow.py` runs a whole workflow phase as a single command and
writes that phase's report in the same invocation. Four verbs, identical shape
for every phase: **dry run, apply, verify, rollback**.

Every phase shows its child scripts' output live in the terminal and also saves
it under `<run-dir>/logs/<timestamp>_<phase>_<mode>/`. Capture also runs with its
normal verbose output; no extra logging flag is needed. Capture and backup no
longer accept `--quiet`. Output is unbuffered and written to the log file while
the step runs, including interactive prompts without a trailing newline.

Every services/groups/policies/rules push, rule amendment and rollback starts
with **one object per batch**. Before another batch is written, the terminal
shows the completed objects and asks how to continue:

| Input | Next action |
|---|---|
| Enter / `y` | Continue at the current batch size |
| `5`, `10`, or another positive integer | Apply that many objects before the next checkpoint |
| `n` | Reset to one object per batch |
| `x` | Stop and save the partial-run reports |

Each tool invocation starts at one again. Batch size controls how many objects
are applied between reviews; the API request throttle is unchanged. Dry runs
never prompt. A closed input stream stops the apply instead of approving it.
Stopping also stops remaining domains/workflow steps, even with
`--continue-on-error`, and a partial rollback keeps its baseline available.

**A/C use two credential stages:** capture LM1 using its credentials, then
manually change the shared `NSX_USERNAME` / `NSX_PASSWORD` to LM2 credentials.
A/C dry run, apply, verify and rollback use saved source files and contact only
the target. The [PowerShell run card](RUN_AC_LM2_PS.md) includes both stages.

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
| `d3` | WF-D rule amendment | `d2a` applied |

WF-D is deliberately **one change window per invocation**: 2a and 3 are
separately approved and spaced by how much risk you will absorb at a time.
There is no `--phase d` that chains them. The former `--phase d2b` is retired
and no longer accepted: IP-only groups now get a sibling in `d2a`.

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

A/C require a separate capture with the source credentials. WF-D captures for
itself on the `d2a` dry run only, into `<run-dir>/capture/<host>/` with no flat
exports, so it never replaces the capture A/C read; `d3` never captures, and
`--no-capture` makes `d2a` reuse the saved one.
For the source capture, **`--live-query` is mandatory**:
it is what splices each group's effective IPs into `groups_additive/`, the tree
WF-C and WF-D build siblings from. Without it every tag-only group looks empty,
you get siblings only for groups that already held static IPs, and nothing
errors. Measured on lm1 2026-09-11: 1 sibling without it, **7 with it**.

```bash
python tools/nsx/capture_nsx_state.py --source $S --live-query
```

This collects the raw configuration and effective group IPs, then writes the
flat exports used by the push commands. The following extras are **off by
default**; add a flag only when that output is needed:

| Optional collection | Enable with |
|---|---|
| Segment inventory/details for segment-to-CIDR conversion | `--with-segments` |
| VM tag export | `--with-vm-tags` |
| VM IP index and per-group VM attribution | `--with-vm-attribution` (with `--live-query`) |
| Groups-with-IPs classification report | `--with-ip-report` |
| Affected-rule impact report | `--impact-report` |

`--ip-report-csv <path>` also explicitly enables the classification/coverage
report, unless `--no-ip-report` is set. Effective-IP evidence for verification
is always saved with `--live-query`, independently of those optional reports.
`vm_ip_index_count: 0` is normal when VM attribution is skipped; check the
effective-IP query count below. Legacy `--ip-source vm-vif` still requires VM
inventory queries and is not accepted by the A/C validation gate.

Gate before going further:

```bash
cat "nsx_capture/$SH/groups_additive/domains/default/groups/manifest.json"
```

| Field | Required |
|---|---|
| `ip_source` | `'effective'`, anything else is a stale or legacy bundle |
| `effective_ip_queries` | non-zero and equal to `groups_seen` |
| `groups_changed` | Review against expected source membership; 0 may mean no enrichment was needed |
| `ips_added_total` | Review against expected source membership; 0 may mean IPs were already present |
| `groups_errors` | **0**. Non-zero means groups have not realized yet: wait, re-run |

For A/C, now edit `.env`'s `NSX_USERNAME` and `NSX_PASSWORD` to the target's
credentials. Keep manager addresses unchanged. If credentials were exported in
the shell, run `unset NSX_USERNAME NSX_PASSWORD` so subsequent Python commands
read the edited `.env`. Keep the source capture and the four flat-export trees
unchanged through preview, apply and verification. To refresh source data,
repeat the source capture using source credentials before switching back.

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

The dry run rebuilds the sibling bundle from the saved source capture without
contacting the source; the apply never rebuilds. A rebuild (here or in `d2a`)
keeps the bundle's `push_report/`, so an earlier apply's revert baselines
survive it. Check the build counters before approving:

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

wf --phase d3
wf --phase d3 --apply
```

`d2a` gives an `_avs_ips` sibling, holding only the CSV-mapped IPs, to every
group that is not segment-based and has at least one mapped IP: tag-based,
IP-only, or nesting other groups. Groups with no members, no mapped IP, or a
segment member get none, and are listed with the reason in the report.

Only `d2a` is required to call a run "WF-D applied". `d3` is independent,
deferrable and separately revertible, and it consumes the sibling map an
earlier window produced: it refuses rather than rebuilding if the map is
missing, because a rebuild could hand a different payload to a target whose
siblings are already live. An apply adds only the siblings already on the
target; a dry run flags any that are not there yet. No phase removes an IP,
and no phase modifies an existing group.

For an in-place WF-D run, set `T=$S` in step 0. The driver warns that source
and target match, which is the supported in-place mode.

---

## 4b) Reading the report

Every push run writes `avs_run_report.md` (operator-facing) and
`avs_run_report.json` (every row, with verdicts) into
`$R/report/<phase>/<mode>/`. A WF-A or WF-C report has four sections, in this
order (WF-D has its own layout, [below](#the-wf-d-report)):

| Section | Answers |
|---|---|
| **What changed** | How many objects were created, changed, failed, or pushed with no measurable change, then one table per object class naming them |
| **Change detail (audit)** | What actually moved, value by value, for every created or changed object. Removals print first and in capitals |
| **Read this before trusting the counts** | Where the numbers are weaker than they look |
| **Appendix** | Every object touched, including the untouched majority |

A verdict of `created` means the object was not on the target beforehand, which
the push knows because it reads the target first. `changed` means it existed
and something measurable moved. `unknown` appears only when a run was told not
to read the target (`--no-diff-target`), and means exactly that: nobody checked.

**Objects the target already holds identically are skipped, not pushed.** That
is the default. The push compares the payload against the live object with
NSX-managed metadata set aside (`_revision`, timestamps, the per-manager
`rule_id`, the toolkit's own `_parent_policy_id`) and treats reference lists
such as `scope` and `source_groups` as sets, because NSX returns them in
arbitrary order. When nothing meaningful differs the row is
`skipped_unchanged` and no API write is made, so no `_revision` bumps and no
realization cycle. A re-run of a workflow that is already applied touches
nothing.

`--force-push` turns the skip off and writes every object, for the case where
the write itself is the point, such as forcing a re-realization after an
NSX-side problem.

Two things the report will shout about, because each one costs traffic:

- **Group references removed.** A clone push that drops a target-only sibling
  reference gets a warning block plus a per-rule table. Should never appear:
  the rules push merges those by default.
- **IPs removed** from any group, printed first in its audit block and in
  capitals.

### The WF-D report

WF-D's report is laid out around original group, AVS group and rule instead.

**D2a**: a Summary table, then:

| Section | Shows |
|---|---|
| **AVS groups** | Original group, AVS group, Result, AVS IPs, No AVS mapping (count) |
| **IP mapping** | One table per group: each Current IP and its AVS IP, or "no AVS mapping" |
| **Groups with no AVS group** | Group, Reason, Current IPs, for every group that got no sibling |

An IP with no AVS mapping stays on its original group, where the rule still
matches it.

**D3**: a Summary table and a **Rules to update** table (Policy, Rule, Source
gains, Destination gains). Before `d2a` is applied, the dry run notes that the
AVS groups are not on the target yet; an apply adds only those that are.

---

## 5) Verify

```bash
wf --phase a --verify
wf --phase c --verify
wf --phase d2a --verify
```

Read-only. `a` and `c` run `verify_avs_run.py --source-capture <saved-capture>`
and query only the target, comparing it against the captured source state.
The report records the capture path and timestamp; later source changes are
not checked. The WF-D phases run
`validate_wf_d.py` against the baseline that phase's push captured.

| Phase | Checks |
|---|---|
| `a` | V1 object parity against the capture, V6 target membership resolves |
| `c` | V1 object parity, V2 siblings exist, V3 sibling IPs equal the source's captured effective IPs, V5 rules reference original OR sibling, V6 target membership resolves |
| `d*` | G1 nothing deleted, G2 no IP removed, G3 criteria intact, S1/S2 siblings exist and typed `IPAddress`, R1 amend completeness, R2 rules still present |

A verification runs V1 and V6 even if a C preview already created a sibling map.
C verification requires that map. **V3 is the one that matters most**: it
catches a sibling that looks structurally fine but is quietly missing
addresses.

Review `$R/report/<phase>/verify/verify_avs_run.json`.

---

## 6) Rollback

**Every rollback writes a report**, preview and apply alike:
`$R/report/<phase>/rollback_dryrun/rollback_report.md` and
`$R/report/<phase>/rollback_apply/rollback_report.md` (plus a `.json` beside each).
Read the preview's report before applying. It says:

- **which apply it undoes**: the baseline timestamp per class, and how many older
  applies stay stacked underneath. One rollback undoes one apply; run it again,
  preview first, to go further back
- **what happens to each object, by display name** (rules also show their
  policy): *revert* (changed back), *recreate* (gone, comes back), *delete*
  (the undone apply created it), or *unchanged*
- **exactly what a revert changes**, with anything the rollback REMOVES listed
  first: group refs, and for groups any IPs the undone push had added

A restore whose target already matches the baseline is skipped and listed as
unchanged, the same rule pushes follow; `--force-push` on the revert tools
writes it anyway. An apply that stops early or fails is flagged at the top, and
its baseline is left unconsumed so the next rollback retries it.

Preview first, always:

```bash
wf --phase c --rollback
wf --phase c --rollback --apply
```

| Phase | Reverts, in order |
|---|---|
| `a` | rules, policies, groups, services |
| `c` | amend-refs, then siblings |
| `d3` | amend-refs |
| `d2a` | siblings (deletes the ones it created) |

Roll back **C before A**, and **`d3` before `d2a`**: NSX refuses to delete a
group a rule still references.

**A rollback only ever uses its own manager's baseline.** Every apply writes,
beside each baseline, the manager it was taken from
(`<ts>_target_meta.json`). Every rollback checks it before sending anything,
and refuses (exit 2) a baseline from another manager, even one named with
`--from-baseline`. A baseline with no record, from before 2026-09-28, is used
only when you name it with `--from-baseline`. This matters because a rollback
takes the newest baseline in its folder: WF-A's rules folder is keyed by A's
source host, and before this check a D3 baseline for lm1 once sat in it on top
of A's lm2 baseline.

**C's and D3's rule amendments keep their baselines in the run directory**,
`$R/rules_amend/<target-host>/push_report/`, not in `nsx_rules_export/`,
which is WF-A's alone.

**A rules rollback deletes only rules its push created.** A rules push records
them (`<ts>_pushed_ids.json`, as groups already did). A rule the baseline lacks
that the push did not create was put there by something else, so the rollback
leaves it and lists it under `deletes_blocked`. An amend-refs rollback never
deletes a rule: amend-refs creates none.

> **`--allow-delete` is passed for you, and it matters.** Reverting a push that
> CREATED groups has to delete them. Without the flag those groups are left in
> place, listed under `deletes_blocked`, and the revert still exits 0, so a
> forgotten flag gives a silent half-rollback. The driver passes it only for
> bundles whose push created objects (the clone, the siblings); a revert that merely
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
├── capture/$SH/                    WF-D only: the d2a dry run's own capture
├── rules_amend/$TH/push_report/    C5 / D3 rule amendments: reports + revert baselines
└── nsx_sibling_groups/$SH/         built by phase c / d2a; a rebuild keeps its push_report/
```

Keep `$R` distinct per run: each run's siblings, push reports and baselines
live in their own tree, so a later rollback cannot pick up an older run's
baseline.

---

## Flags

| Flag | Purpose |
|---|---|
| `--source` / `--target` | Manager aliases. The same alias for both is the supported in-place mode, and warns |
| `--phase` | `a`, `c`, `d2a`, `d3` |
| `--apply` | Write. Default is a dry run |
| `--verify` | Read-only check instead of pushing |
| `--rollback` | Undo the phase. Combine with `--apply` to write |
| `--csv-remap` | Required for `d2a`. Not needed for `d3`, verify or rollback |
| `--run-dir` | Default `nsx_avs_runs/<source>_to_<target>` |
| `--capture` / `--no-capture` | The `d2a` dry run captures by default, into `<run-dir>/capture/<host>/`; `--no-capture` reuses that saved capture. `d3` never captures. A/C require a separate capture and reject `--capture`; `--no-capture` is accepted but unnecessary for A/C |
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

**Interactive checkpoints work through the driver.** Child scripts inherit
your terminal input and their prompts stream live. Input loss or `x` stops
the run. Decisions and the initial/final batch sizes are recorded in each
tool's summary; checkpoints also cover dependency retries.

**Group expressions are replaced wholesale.** The IP list is protected by the
additive contract, but a tag criterion added by hand on the target would be
overwritten by a push.
