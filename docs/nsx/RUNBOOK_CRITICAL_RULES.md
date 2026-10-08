# Runbook - Critical rules copy (rules with hits) (macOS / Linux / bash)

Copy only the firewall rules that matter from one NSX Local Manager to a
new, empty one. One script per step, under `tools/nsx/critical_rules/`:

| Step | Script | Touches |
|---|---|---|
| 1. Gather hit stats | `step1_stats.py` | source, read only |
| 2. Pull those objects | `step2_pull.py` | source, read only; writes two bundles locally |
| 3. Push them to the new manager | `step3_push.py` | target; dry run unless `--apply` |
| 4. Verify | `step4_verify.py` | target, read only |
| Undo step 3 | `revert.py` | target; dry run unless `--apply` |

What gets copied:

- every **Infrastructure** policy, whole, with its rules in their original order;
- every **Application** rule that has **hits**, collected into **one new
  policy** (`critical-rules`), busiest rule first;
- every group and service those rules need (nested ones too, and the
  `_np_ips` siblings a rule references).

The target must already be empty (only NSX's two default sections); step 3
checks that and refuses to apply otherwise.

Every run lives in its own folder,
`nsx_critical_runs/<source>_to_<target>/<UTC_TS>/`: the report, the two
bundles, `run.json` (what each step did, with paths) and one log per tool.
Step 1 starts a run; steps 2 to 4 and `revert.py` use the newest run for the
same source and target (or `--run <folder>`).

PowerShell variant (nsx-ws1): [RUNBOOK_CRITICAL_RULES_PS.md](RUNBOOK_CRITICAL_RULES_PS.md).

---

## Read this first

1. **Hit counts are cumulative since the last counter reset** (host reboot,
   upgrade, section recreate). A lab manager carries little traffic, so most
   rules show 0; [Appendix A](#appendix-a---lab-only-test-traffic) generates
   known traffic. Your own SSH and pings into the lab VMs count too.
2. **NSX 3.2.x answers rule statistics with HTTP 500** on the Policy API, even
   for local policies. The report and the consolidator fall back to the older
   firewall API; if a policy that has rules gets no counters from either API,
   step 2 stops instead of treating its rules as unused.
3. **Counters lag 5 to 30 minutes.** An ALLOW rule counts sessions; a DROP
   rule counts packets. Traffic between two VMs on the same manager is counted
   at both VMs.
4. **The new policy changes rule order.** Step 2 prints the new order with each
   rule's action and flags every DROP/REJECT; compare each one with the ALLOW
   rules below it before step 3.
5. **Stale port bindings.** NSX keeps old IPs on a VM port long after the VM
   changed address, and `_np_ips` siblings copy them as literal IPs. Decision
   2026-10-08: copy as is.
6. **Credentials.** One set (`NSX_USERNAME` / `NSX_PASSWORD` in `.env`) is used
   for both managers. If the target's differ, run steps 1 and 2 with the
   source's and switch before step 3: steps 1 and 2 talk only to the source,
   steps 3 and 4 and `revert.py` only to the target.

---

## Setup

```bash
cd ~/dev/nsx_scripts
source .venv/bin/activate
export PYTHONPATH="$PWD/app"
export NSX_LOG_DIR="$PWD/nsx_logs"

SRC=nsx-lm2      # read only
TGT=nsx-lm3      # new, empty manager
```

## Step 1 - Gather hit stats

```bash
python tools/nsx/critical_rules/step1_stats.py --source $SRC --target $TGT
```

Lists every rule with hits. The Application rules in the list are the ones
step 2 keeps.

## Step 2 - Pull those objects

```bash
python tools/nsx/critical_rules/step2_pull.py --source $SRC --target $TGT
```

Captures the source, builds the Infrastructure bundle and the hit-rules
bundle, and prints the new policy's rule order. Check: `kept rules match step 1`,
statistics came from an API for every policy, and every `CHECK:` line about a
DROP/REJECT (Read this first, item 4).

Options: `--min-hits N` (keep rules with more than N hits), `--policy-id`,
`--policy-name`, `--whole-categories`, `--hit-categories`, `--no-capture`.

## Step 3 - Push them to the new manager

```bash
python tools/nsx/critical_rules/step3_push.py --source $SRC --target $TGT            # dry run
python tools/nsx/critical_rules/step3_push.py --source $SRC --target $TGT --apply    # write
```

Checks the target is empty, then runs services, groups (segment references
stripped), policies and rules for the Infrastructure bundle, then the
hit-rules bundle. Stops at the first failure. Read the dry run's table
(`failed=0` everywhere) before `--apply`. After a partial apply, rerun with
`--apply --allow-non-empty` to continue.

## Step 4 - Verify

```bash
python tools/nsx/critical_rules/step4_verify.py --source $SRC --target $TGT
```

Compares every object in the two bundles with the target. Expect
`VERIFY PASS`: nothing missing, nothing extra.

## Revert

```bash
python tools/nsx/critical_rules/revert.py --source $SRC --target $TGT            # dry run
python tools/nsx/critical_rules/revert.py --source $SRC --target $TGT --apply    # write
```

Hit-rules bundle first, then Infrastructure; rules, policies, groups,
services. Each class is undone from the baseline its own push wrote (classes
never applied are skipped), which returns the target to empty. Groups are
reverted with `--allow-delete`; without that flag `groups.py revert` keeps the
groups its push created and still reports success.

---

## Appendix A - Lab only: test traffic

Skip in production. In the lab this gives step 1 a known right answer: the
rules you send traffic to must be kept, the rules you leave cold must not.
Run from the Mac (it uses the Mac's SSH keys and pings from the Mac).

| Tool | What it does |
|---|---|
| `tools/test/predict_dfw_hits.py` | Offline model of which rule a flow hits at each VM vNIC (source's flat exports plus a read-only snapshot of group IPs and members). `--search` finds a flow for every rule and lists the rules no flow can reach; without it, checks a plan (exit 1 on any mismatch). |
| `tools/test/generate_lab_traffic.py` | Runs a YAML flow plan from the Mac, aidev or lab VMs (lm1/lm2 VMs through `aidev.lab.local`). `--run --grade` does the whole cycle: report before, send, wait for the counters, grade. |

Plans: `tools/test/traffic_plans/lm1_hit_subset.yaml`, `lm2_hit_subset.yaml`.

```bash
P=tools/test/traffic_plans/lm2_hit_subset.yaml
python tools/test/predict_dfw_hits.py --source $SRC --plan $P --search \
  --extra-dst 10.21.250.10,10.21.4.10,10.21.2.20,10.21.10.20,8.8.8.8   # what can be hit
python tools/test/predict_dfw_hits.py --source $SRC --plan $P             # check the plan
python tools/test/generate_lab_traffic.py --plan $P                       # list
python tools/test/generate_lab_traffic.py --plan $P --run --grade         # send, wait, grade
```

Go on to step 1 only with `Result: PASS`. Exit codes of single flows in the
run output are informational: a dropped flow still hits its rule.

---

## Run record

| Date | Source -> target | Result |
|---|---|---|
| 2026-10-08 | `nsx-lm1 -> nsx-lm4` (rehearsal, before the scripts) | Traffic graded PASS; kept 11 Application rules, exactly the expected set; dry run clean. Not applied |
| 2026-10-08 | `nsx-lm2 -> nsx-lm3`, run `nsx_critical_runs/nsx-lm2_to_nsx-lm3/20261008_151911` (Mac) | Traffic graded PASS (`nsx_logs/traffic_runs/20261008_113718`). Steps 1 and 2: 9 Application rules with hits, kept set matches; step 3 dry run 2/7/2/4 and 2/17/1/9 (services/groups/policies/rules), 0 failed; step 4 expects 4 services, 22 groups, 3 policies, 13 rules. Not applied |
