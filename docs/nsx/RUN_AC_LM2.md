# Run card: Workflows A and C onto `nsx-lm2.lab.local`

Clone the customer DFW config from `nsx-lm1` to `nsx-lm2` (Workflow A), then
decompose the tag-based groups on the target into IP-only siblings (Workflow C).
Both run through the driver, `tools/nsx/run_workflow.py`, which executes a whole
phase and writes that phase's report in the same invocation.

Use two credential stages: capture LM1 with its credentials, then manually
change the shared `NSX_USERNAME` / `NSX_PASSWORD` to LM2's credentials. A/C
dry run, apply, verify and rollback use saved source files and contact only LM2.

Concepts: [RUNBOOK_A.md](RUNBOOK_A.md), [RUNBOOK_C.md](RUNBOOK_C.md), and the
driver itself in [RUNBOOK_WORKFLOW.md](RUNBOOK_WORKFLOW.md). Per-tool commands,
if you need to run a step by hand:
[RUNBOOK_A_COMMANDS.md](RUNBOOK_A_COMMANDS.md) /
[RUNBOOK_C_COMMANDS.md](RUNBOOK_C_COMMANDS.md).

PowerShell variant of this card: [RUN_AC_LM2_PS.md](RUN_AC_LM2_PS.md).

## Roles

| Manager | Role | NSX impact |
|---|---|---|
| `nsx-lm1.lab.local` | Source | **Read only.** Never written to by either workflow |
| `nsx-lm2.lab.local` | Target | Services, groups, policies, rules created; then siblings added and originals stripped |

Workflow A pushes services, groups (segment references stripped), policies and
rules. Workflow C then adds one IP-only sibling group per tag-based group,
strips the IPs out of the originals, and amends the rules to reference both.
Run A first. C replaces WF-A Part 2 and Part 3, so do not run those as well.

---

## Before you start

Run from the repository root. Set `NSX_LM1` and `NSX_LM2` in `.env` to the
correct managers. Back up and inspect LM2 after switching credentials below.

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
T=nsx-lm2
SH=nsx-lm1.lab.local
TH=nsx-lm2.lab.local
R=nsx_avs_runs/${S}_to_${T}
mkdir -p $R
```

Define the driver as a **function**, with source, target and run dir filled in:

```bash
wf() { python tools/nsx/run_workflow.py --source $S --target $T --run-dir $R "$@"; }
wf --help | head -3
```

> Use a function, not a variable. `W="python tools/nsx/run_workflow.py ..."`
> followed by `$W --phase a` works in bash but **fails in zsh**, which does not
> word-split an unquoted parameter and tries to run the whole string as one
> command name.

---

## 1) Capture the source (read-only)

Set `.env`'s `NSX_USERNAME` and `NSX_PASSWORD` to LM1 credentials. Clear shell
overrides with `unset NSX_USERNAME NSX_PASSWORD` so Python reads `.env`.
A/C do not capture automatically; this is the only source-side stage.

**`--live-query` is mandatory.** It is what splices each group's effective IPs
into `groups_additive/`, which is the tree Workflow C builds siblings from.
Without it every tag-only group looks empty, you get siblings only for groups
that already held static IPs, and **nothing errors**. Measured on lm1: 1 sibling
without it, 7 with it.

```bash
python tools/nsx/capture_nsx_state.py --source $S --live-query
```

Segment inventory, VM tags, VM attribution and optional review reports are
skipped by default. The configuration, effective-IP evidence and flat exports
remain. `vm_ip_index_count: 0` is expected; use the effective-IP query gate below.
See [optional collection flags](RUNBOOK_WORKFLOW.md#1-capture-read-only-source-side).

### The gate: check all five fields yourself

```bash
cat "nsx_capture/$SH/groups_additive/domains/default/groups/manifest.json"
```

| Field | Required |
|---|---|
| `ip_source` | `'effective'`. Anything else is a stale or legacy bundle |
| `effective_ip_queries` | non-zero and equal to `groups_seen` |
| `groups_changed` | Review against expected source membership; 0 may mean no enrichment was needed |
| `ips_added_total` | Review against expected source membership; 0 may mean IPs were already present |
| `groups_errors` | `0`. Non-zero means groups have not realized yet: wait, re-run |

The driver checks capture success, source/domain identity, effective IP mode,
zero group errors and a successful effective-IP query for every processed group. Review the change counts yourself.

### Switch credentials once, then work only against LM2

After capture succeeds, manually change `.env`'s `NSX_USERNAME` and
`NSX_PASSWORD` to LM2 credentials. Keep manager addresses unchanged. Run
`unset NSX_USERNAME NSX_PASSWORD` again if shell overrides were set.
Keep `nsx_capture/$SH` and the four `nsx_*_export/$SH` source trees unchanged
through preview, apply and verification. Refreshing LM1 requires repeating
the capture with LM1 credentials, then switching back to LM2.

Back up and inspect LM2 with its credentials before applying:

```bash
python tools/nsx/backup_nsx_state.py --source "$T" --retain 14
cat "nsx_backup/$TH/latest/summary.txt"
python tools/nsx/list_domains.py "$T"
```

---

## 2) Workflow A: the clone

Logging is always live; capture has no quiet mode. Each apply step starts with
one object and pauses before the next batch. Enter continues, a positive number
increases the batch, `n` resets to one, and `x` stops. C and rollback use the
same controls. Lost input stops the run; dry runs never prompt.

```bash
# Dry run, then read the report
wf --phase a
cat $R/report/a/dryrun/avs_run_report.md

# Apply
wf --phase a --apply

# Verify
wf --phase a --verify
```

### Review gate

| Check | Where |
|---|---|
| Object counts per class match the source | "What changed" table |
| Nothing under `Failed` | "What changed" table |
| No "group references removed" warning block | report body |
| Every IP delta is an addition | "Change detail (audit)" |

In the first table, `Would create` is exact for group rows and a **lower bound**
everywhere else: services, policies and rules do not read the target on a dry
run, so a genuinely new one there counts as no measurable change. The report
says so in its own caveats block.

Dry-run and apply reports are separate paths (`report/a/dryrun/` and
`report/a/apply/`), so neither can overwrite or be mistaken for the other.

---

## 3) Workflow C: sibling decomposition

```bash
# Dry run, then read the report
wf --phase c
cat $R/report/c/dryrun/avs_run_report.md

# Apply
wf --phase c --apply

# Verify
wf --phase c --verify
```

The dry run rebuilds siblings from the saved LM1 capture without contacting
LM1. The apply never rebuilds, so it pushes the bundle you previewed.

### Review gate

Check the build counters before approving:

```bash
python -c "
import json
m = json.load(open('$R/nsx_sibling_groups/$SH/sibling_map.json'))
print('siblings:', m['count'], ' appendix:', m['appendix'])
[print(' ', e['sibling_id'], len(e.get('ips_source') or []), 'ips') for e in m['map']]"
```

| Check | Requirement |
|---|---|
| `appendix` | `_np_ips`. If it reads `_avs_ips` you are looking at a WF-D bundle |
| `files_seen` | equals `siblings_written + skipped_no_condition + skipped_empty_ips` |
| `skipped_empty_ips` | `0`. Non-zero means a tag group NSX resolves to nothing, which is also what a capture without `--live-query` produces. Confirm against the manager before continuing |
| every sibling | carries a plausible IP count, never 0 |

The four counters in that table come from the build log, not from
`sibling_map.json`:

```bash
grep -E "files seen|siblings written|stripped originals|skipped: empty IPs|errors  " \
  $(ls -t $NSX_LOG_DIR/build_sibling_groups_*.log | head -1) | sed 's/.*__main__: //'
```

---

## 4) Verify

Read-only, both phases. `verify_avs_run.py` runs V1 object parity, V2 siblings
exist, V3 sibling IPs equal the source's captured effective IPs, V4 originals stripped,
V5 rules reference original or sibling, V6 membership resolves.
Only LM2 is queried live. The driver supplies `--source-capture`; the report
records the source capture path and timestamp. Later LM1 changes are not checked.

```bash
wf --phase a --verify
wf --phase c --verify
cat $R/report/c/verify/verify_avs_run.json
```

**V3 is the one that matters most.** It catches a sibling that looks
structurally fine but is quietly missing addresses.

`--phase a --verify` runs V1 and V6 only, even if you already previewed C.
`--phase c --verify` requires C's sibling map and runs the sibling checks too;
run it after applying C.

---

## 5) Rollback

Preview first, always. The dry run takes no `--apply`; add it to execute.

```bash
# C first
wf --phase c --rollback
wf --phase c --rollback --apply

# then A
wf --phase a --rollback
wf --phase a --rollback --apply
```

**Roll back C before A.** NSX refuses to delete a group while a rule still
references it, so unwinding the clone underneath live siblings fails.

| Phase | Reverts, in order |
|---|---|
| `c` | amend-refs, stripped originals, siblings |
| `a` | rules, policies, groups, services |

The driver passes `--allow-delete` for you, which matters: reverting a push that
*created* groups has to delete them, and without the flag they are left in place,
listed under `deletes_blocked`, while the revert still exits 0. Read the summary,
not the exit code.

---

## Measured baseline, 2026-09-18 dry run

Source `nsx-lm1` holding 13 groups / 5 policies / 15 rules / 4 services, target
`nsx-lm2` empty. Expect this shape, not these exact numbers, once either side
moves.

**Workflow A: 33 objects would be created, 22 IPs added, 0 failed.**

| Class | Count |
|---|---:|
| Services | 4 |
| Groups | 13 |
| Policies | 3 |
| Rules | 13 |

**Workflow C: 14 objects, 30 IPs in siblings, 0 errors.**

| Part | Count | Detail |
|---|---:|---|
| Siblings created (`_np_ips`) | 7 | `network-group-0/1/2/8`, `super-nested-group`, `vm-group-1/2` |
| Stripped originals | 7 | same seven groups, IPAddressExpression entries removed |

The 7 siblings match the figure the runbook records for a correct
`--live-query` capture on this source. One sibling would mean the capture was
wrong.

---

## If something goes wrong

Roll back as in section 5. If the baselines are gone, restore `nsx-lm2` from the
bundle taken in the preconditions and follow
[EMERGENCY_RESTORE.md](EMERGENCY_RESTORE.md). Read its rules caveat first: backup
bundles do not carry `_parent_policy_id`, so restoring rules straight from one
lands them in a policy that does not exist. The fix is in that doc.
