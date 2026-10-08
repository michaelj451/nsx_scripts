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

Infrastructure policies are copied whole; Application rules with hits go
into one new policy, `critical-rules`, busiest first; every group and
service they need comes along. The target must already be empty; step 3
checks that.

Every run lives in `nsx_critical_runs/<source>_to_<target>/<UTC_TS>/`. Step 1
starts a run; the other scripts use the newest run for the same source and
target (or `--run <folder>`).

Bash variant, with the background ("Read this first"):
[RUNBOOK_CRITICAL_RULES.md](RUNBOOK_CRITICAL_RULES.md). Read it before a first
run. In short: lab hit counts are thin and lag 5 to 30 minutes; NSX 3.2.x
statistics fall back to the older firewall API; the new policy reorders rules
by hit count, so check every DROP/REJECT step 2 flags; `_np_ips` siblings copy
stale port bindings as is.

---

## Setup

```powershell
Set-Location $HOME\dev\nsx_scripts
git pull
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH  = "$PWD/app"
$env:NSX_LOG_DIR = "$PWD/nsx_logs"
$env:PYTHONUTF8  = "1"

$SRC = "nsx-lm2"      # read only
$TGT = "nsx-lm3"      # new, empty manager
```

One set of credentials (`NSX_USERNAME` / `NSX_PASSWORD` in `.env`) is used for
both managers. If the target's differ, run steps 1 and 2 with the source's and
switch before step 3.

## Step 1 - Gather hit stats

```powershell
python tools/nsx/critical_rules/step1_stats.py --source $SRC --target $TGT
```

## Step 2 - Pull those objects

```powershell
python tools/nsx/critical_rules/step2_pull.py --source $SRC --target $TGT
```

Check: `kept rules match step 1`, statistics came from an API for every
policy, and every `CHECK:` line about a DROP/REJECT in the new order.

## Step 3 - Push them to the new manager

```powershell
python tools/nsx/critical_rules/step3_push.py --source $SRC --target $TGT            # dry run
python tools/nsx/critical_rules/step3_push.py --source $SRC --target $TGT --apply    # write
```

Read the dry run's table (`failed=0` everywhere) before `--apply`. After a
partial apply, rerun with `--apply --allow-non-empty` to continue.

## Step 4 - Verify

```powershell
python tools/nsx/critical_rules/step4_verify.py --source $SRC --target $TGT
```

Expect `VERIFY PASS`: nothing missing, nothing extra.

## Revert

```powershell
python tools/nsx/critical_rules/revert.py --source $SRC --target $TGT            # dry run
python tools/nsx/critical_rules/revert.py --source $SRC --target $TGT --apply    # write
```

Returns the target to empty. Classes step 3 never applied are skipped.

---

## Lab test traffic

Generating and grading test traffic (so step 1 has a known right answer) runs
from the Mac, not nsx-ws1: it uses the Mac's SSH keys and pings from the Mac.
See Appendix A of [RUNBOOK_CRITICAL_RULES.md](RUNBOOK_CRITICAL_RULES.md).
