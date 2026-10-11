# Runbook - Unused rule cleanup (PowerShell, nsx-ws1)

Clean up one NSX Local Manager in two steps, with a soak period between them.
One script per step under `tools/nsx/rule_cleanup/`, each with its own undo:

| Step | Script | Writes |
|---|---|---|
| 1. Disable rules that have never been hit | `step1_disable.py` | plan: read only; `--apply` disables |
| Soak period | (wait; watch for breakage) | nothing |
| 2. Delete the unused rules, then empty policies, then unreferenced groups | `step2_delete.py` | plan: read only; `--apply` deletes |
| Undo step 1 | `step1_undo.py` | re-enables (all, or one with `--rule`) |
| Undo step 2 | `step2_undo.py` | re-creates what step 2 deleted |

A rule is unused when NSX returned a counter row for it and every counter is 0
(no row: `NO_STATS`, never touched). Step 2 deletes the rules step 1 disabled
that are still disabled, unchanged and without hits, then every customer
policy left with no rules, then every customer group nothing references
(DFW, gateway, IDS, redirection, forwarding and endpoint policies, the
exclusion list, load balancers, nested groups). **Services are never
touched.** NSX's own objects (default sections, built-in groups, anything
`is_default`, `_system_owned` or created by NSX) are never changed.

Each step runs twice: first without `--apply` (the plan, read only), then with
`--apply`, which carries out only the reviewed plan and re-checks every object
live right before writing it. Runs live in `$RUNS/<target>/<UTC_TS>/`; step 1's
plan starts one, every other command uses the newest run for the target (or
`--run <folder>`).

Bash variant, with the background ("Read this first"):
[RUNBOOK_RULE_CLEANUP.md](RUNBOOK_RULE_CLEANUP.md). Read it before a first
run. In short: counters start at 0 after a reset (check rule ages,
`--min-age-days`); NSX 3.2.x statistics fall back to the older firewall API;
disabling a never-hit DROP/REJECT rule can let traffic through later (`CHECK:`
lines, `--keep-deny`); rules already disabled before step 1 are left out of
step 2 unless `--include-pre-disabled`; already-empty policies and
already-unreferenced groups are deleted too.

---

## Setup

```powershell
$REPO = "$HOME/dev/nsx_scripts"           # the toolkit checkout
$RUNS = "$REPO/nsx_cleanup_runs"          # where every run is stored (any folder)
$TGT  = "nsx-lm2"                         # the Local Manager to clean up

Set-Location $REPO
git pull
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force   # this window only; Windows blocks Activate.ps1 otherwise
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH  = "$REPO/app"
$env:NSX_LOG_DIR = "$REPO/nsx_logs"
$env:PYTHONUTF8  = "1"
```

Instead of `--runs-dir` on every command you can set `$env:NSX_CLEANUP_RUNS_DIR = $RUNS`;
the commands below pass it explicitly so it is visible.

Backup first (read only):

```powershell
python tools/nsx/backup_nsx_state.py --source $TGT
```

## Step 1 - Disable rules that have never been hit

```powershell
python tools/nsx/rule_cleanup/step1_disable.py --target $TGT --runs-dir "$RUNS"            # plan
python tools/nsx/rule_cleanup/step1_disable.py --target $TGT --runs-dir "$RUNS" --apply    # write
```

Read the plan first: the count per class (`DISABLE`, `ALREADY_DISABLED`,
`KEEP_DENY`, `TOO_NEW`, `NO_STATS`, `USED`), every rule it would disable,
every `CHECK:` line about a DROP/REJECT rule, any `NO_STATS` warning. Full
table in the run's `step1\plan.md`. Plan options: `--min-age-days N`,
`--keep-deny`.

Run `--apply` in the PowerShell window yourself: it asks before every batch
(`Enter` continue, a number sets the batch size, `n` back to 1, `x` stops),
and without a terminal it is refused. `--piped-answers` lets answers come from
a pipe, only with the operator's approval. A stopped apply can be rerun.

## Soak period

If something breaks, re-enable the rule that carried it:

```powershell
python tools/nsx/rule_cleanup/step1_undo.py --target $TGT --runs-dir "$RUNS" --rule "<policy_id>/<rule_id>"           # dry run
python tools/nsx/rule_cleanup/step1_undo.py --target $TGT --runs-dir "$RUNS" --rule "<policy_id>/<rule_id>" --apply   # write
```

Without `--rule`, every rule step 1 disabled is re-enabled. A re-enabled rule
is left alone by step 2.

## Step 2 - Delete the unused rules, policies and groups

```powershell
python tools/nsx/rule_cleanup/step2_delete.py --target $TGT --runs-dir "$RUNS"            # plan
python tools/nsx/rule_cleanup/step2_delete.py --target $TGT --runs-dir "$RUNS" --apply    # write
```

The plan prints how long the rules have been disabled, then every rule,
policy and group it would delete (groups in delete order), the candidate rules
it keeps and why, and the other group consumers it read. Full detail in
`step2\plan.md`. Option: `--include-pre-disabled`.

Order: rules, policies, groups. Before the first delete it saves policies,
rules and groups to `step2\before_<ts>.json`, and each object's full JSON goes
into `step2\deleted.json` right before it is deleted.

## Undo step 2

```powershell
python tools/nsx/rule_cleanup/step2_undo.py --target $TGT --runs-dir "$RUNS"            # dry run
python tools/nsx/rule_cleanup/step2_undo.py --target $TGT --runs-dir "$RUNS" --apply    # write
```

Re-creates every deleted object with its original id (groups, then policies,
then rules). Rules come back disabled; `step1_undo.py` re-enables them if
wanted.
