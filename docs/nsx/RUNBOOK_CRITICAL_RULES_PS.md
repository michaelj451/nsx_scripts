# Runbook - Critical rules copy (rules with hits) (PowerShell, nsx-ws1)

Copy only the firewall rules that matter from one NSX Local Manager to a
new, empty one. One script per step, under `tools/nsx/critical_rules/`:

| Step | Script | Touches |
|---|---|---|
| 1. Gather hit stats | `step1_stats.py` | source, read only |
| 2. Pull those objects | `step2_pull.py` | source, read only; writes two bundles locally |
| 3. Push them to the new manager | `step3_push.py` | target; dry run unless `--apply` |
| 4. Verify | `step4_verify.py` | target, read only |
| Undo step 3 | `revert.py` | target; dry run unless `--apply` |

Policies and rules are copied exactly as they are on the source (same ids,
names, sequence numbers, settings; nothing renamed, merged or reordered). All
Infrastructure policies with every rule; every Application policy that holds
at least one active (hot) rule, with only its hot rules; every group and
service they need. NSX's system defaults
are never copied: the Default Layer2/Layer3 sections and their rules, built-in
groups and services, anything `is_default`, `_system_owned` or created by NSX
itself. Step 2 enforces both and stops if either fails. The target must
already be empty; step 3 checks that.

Every run lives under `$RUNS` (set in Setup; any folder you choose), in
`$RUNS/<source>_to_<target>/<UTC_TS>/`, and everything it produces stays there:
the report, the source capture and its exports, both bundles (with their push
reports and revert baselines), `run.json` and all logs. Nothing is written to
the repo. Step 1 starts a run; the other scripts use the newest run for the
same source and target under `$RUNS` (or `--run <folder>`).

Bash variant, with the background ("Read this first"):
[RUNBOOK_CRITICAL_RULES.md](RUNBOOK_CRITICAL_RULES.md). Read it before a first
run. In short: lab hit counts are thin and lag 5 to 30 minutes; NSX 3.2.x
statistics fall back to the older firewall API; DROP/REJECT rules with no hits
are not copied, so check every one step 2 flags with `CHECK:`; `_np_ips`
siblings copy stale port bindings as is.

---

## Setup

```powershell
$REPO = "$HOME/dev/nsx_scripts"           # the toolkit checkout
$RUNS = "$REPO/nsx_critical_runs"         # where every run is stored (any folder)
$SRC  = "nsx-lm2"                         # read only
$TGT  = "nsx-lm3"                         # new, empty manager

Set-Location $REPO
git pull
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force   # this window only; Windows blocks Activate.ps1 otherwise
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH  = "$REPO/app"
$env:NSX_LOG_DIR = "$REPO/nsx_logs"
$env:PYTHONUTF8  = "1"
```

Instead of `--runs-dir` on every command you can set `$env:NSX_CRITICAL_RUNS_DIR = $RUNS`;
the commands below pass it explicitly so it is visible.

One set of credentials (`NSX_USERNAME` / `NSX_PASSWORD` in `.env`) is used for
both managers. If the target's differ, run steps 1 and 2 with the source's and
switch before step 3.

## Step 1 - Gather hit stats

```powershell
python tools/nsx/critical_rules/step1_stats.py --source $SRC --target $TGT --runs-dir "$RUNS"
```

## Step 2 - Pull those objects

```powershell
python tools/nsx/critical_rules/step2_pull.py --source $SRC --target $TGT --runs-dir "$RUNS"
```

Check: `Infrastructure copied whole: all N policies`, `Hot rules copied: N of
N`, `System defaults in the bundles: none`, and every `CHECK:` line about a
DROP/REJECT rule not copied. Step 2 stops with `STOP:` if an Infrastructure
policy or rule is missing, a hot rule is missing, or a system default got into
a bundle.

## Step 3 - Push them to the new manager

```powershell
python tools/nsx/critical_rules/step3_push.py --source $SRC --target $TGT --runs-dir "$RUNS"            # dry run
python tools/nsx/critical_rules/step3_push.py --source $SRC --target $TGT --runs-dir "$RUNS" --apply    # write
```

Read the dry run's table (`failed=0` everywhere) before `--apply`. Run
`--apply` in the PowerShell window yourself: every push tool asks before each
batch (`Enter` continue, a number sets the batch size, `x` stops), and without
a terminal the script refuses `--apply`. `--piped-answers` lets answers come
from a pipe, only with the operator's approval. After a partial apply, rerun
with `--apply --allow-non-empty` to continue. When the target is not empty, step 3 lists every customer object already there. Steps 3 and 4 and `revert.py` stop if the target alias now resolves (in `.env`) to a different host than the run recorded at step 1.

## Step 4 - Verify

```powershell
python tools/nsx/critical_rules/step4_verify.py --source $SRC --target $TGT --runs-dir "$RUNS"
```

Expect `VERIFY PASS`: nothing missing, nothing extra.

## Revert

```powershell
python tools/nsx/critical_rules/revert.py --source $SRC --target $TGT --runs-dir "$RUNS"            # dry run
python tools/nsx/critical_rules/revert.py --source $SRC --target $TGT --runs-dir "$RUNS" --apply    # write
```

Undoes every push step 3 made, newest first, including an earlier apply that
stopped partway, so one `--apply` returns the target to empty. The dry run
shows each pending push; classes with nothing left show `already reverted` or
`never applied`. Like step 3, `--apply` asks before each batch and needs the
PowerShell window (or `--piped-answers`).

---

## Lab test traffic

Generating and grading test traffic (so step 1 has a known right answer) runs
from the Mac, not nsx-ws1: it uses the Mac's SSH keys and pings from the Mac.
See Appendix A of [RUNBOOK_CRITICAL_RULES.md](RUNBOOK_CRITICAL_RULES.md).
