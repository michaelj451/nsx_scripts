# Runbook - Critical rules copy (rules with hits) (macOS / Linux / bash)

Copy only the firewall rules that matter from one NSX Local Manager to a
new, empty one, **exactly as they are on the source**: same policy and rule
ids, names, sequence numbers and settings. Nothing is renamed, merged or
reordered. One script per step, under `tools/nsx/critical_rules/`:

| Step | Script | Touches |
|---|---|---|
| 1. Gather hit stats | `step1_stats.py` | source, read only |
| 2. Pull those objects | `step2_pull.py` | source, read only; writes the two bundles into the run |
| 3. Push them to the new manager | `step3_push.py` | target; dry run unless `--apply` |
| 4. Verify | `step4_verify.py` | target, read only |
| Undo step 3 | `revert.py` | target; dry run unless `--apply` |

What gets copied:

- **all Infrastructure** policies, with every rule, hits or not;
- every **Application** policy that holds at least one **active (hot)** rule,
  with **only its hot rules** (hit count above `--min-hits`, default 0). Cold
  rules are left out; a policy with no hot rule is not copied at all;
- every group and service those rules need (nested ones too, a policy's own
  Applied To, and the `_np_ips` siblings a rule references).

Each kept policy and rule is the source's own export file, copied unchanged.

Never copied: **NSX's system defaults**, meaning the Default Layer2/Layer3
sections and their rules (including NSX's own NDP/DHCP rules), built-in
groups and services, and anything else marked `is_default` or
`_system_owned`, or created by NSX itself (`_create_user: system`). The
default sections are not marked `_system_owned`, so all three markers are
checked. Step 2 enforces both rules and stops if either fails.

The target must already be empty (only NSX's two default sections); step 3
checks that and refuses to apply otherwise.

Every run lives in its own folder under `$RUNS` (set in Setup; any folder you
choose), and everything a run produces stays there; nothing is written to the
repo:

```
$RUNS/<source>_to_<target>/<UTC_TS>/
    run.json                 what each step did, with paths
    stats/  hits.json        step 1: rules-usage report, rules with hits
    capture/  nsx_*_export/  step 2: source capture and the exports the bundle tools read
    infra/  hits/            step 2: the two bundles (push reports and revert baselines land inside)
    logs/                    each script's log, one log per tool, logs/tools/ for tool logs
```

Step 1 starts a run; steps 2 to 4 and `revert.py` use the newest run for the
same source and target under `$RUNS` (or `--run <folder>`).

PowerShell variant (nsx-ws1): [RUNBOOK_CRITICAL_RULES_PS.md](RUNBOOK_CRITICAL_RULES_PS.md).

---

## Read this first

1. **Hit counts are cumulative since the last counter reset** (host reboot,
   upgrade, section recreate). A lab manager carries little traffic, so most
   rules show 0; [Appendix A](#appendix-a---lab-only-test-traffic) generates
   known traffic. Your own SSH and pings into the lab VMs count too.
2. **NSX 3.2.x answers rule statistics with HTTP 500** on the Policy API, even
   for local policies. Step 1's report falls back to the older firewall API.
   Step 2 takes the hot rules from step 1's report, so what step 1 lists is
   exactly what is copied.
3. **Counters lag 5 to 30 minutes.** An ALLOW rule counts sessions; a DROP
   rule counts packets. Traffic between two VMs on the same manager is counted
   at both VMs.
4. **Leaving out cold rules changes what the target does for traffic nobody
   has sent yet.** A DROP or REJECT rule with no hits is not copied, so traffic
   it would have blocked reaches the next rule (or the target's default rule)
   instead. Step 2 lists every such rule with a `CHECK:` line; decide on each
   before step 3.
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
REPO=~/dev/nsx_scripts               # the toolkit checkout
RUNS="$REPO/nsx_critical_runs"       # where every run is stored (any folder)
SRC=nsx-lm2                          # read only
TGT=nsx-lm3                          # new, empty manager

cd "$REPO"
source .venv/bin/activate
export PYTHONPATH="$REPO/app"
export NSX_LOG_DIR="$REPO/nsx_logs"
```

Instead of `--runs-dir` on every command you can `export NSX_CRITICAL_RUNS_DIR="$RUNS"`;
the commands below pass it explicitly so it is visible.

## Step 1 - Gather hit stats

```bash
python tools/nsx/critical_rules/step1_stats.py --source $SRC --target $TGT --runs-dir "$RUNS"
```

Lists every rule with hits. The Application rules in the list are the hot
rules step 2 copies.

## Step 2 - Pull those objects

```bash
python tools/nsx/critical_rules/step2_pull.py --source $SRC --target $TGT --runs-dir "$RUNS"
```

Captures the source, builds the Infrastructure bundle (every rule) and the
Application bundle (hot rules only), and prints every policy as it will land:
id, display name, sequence number, and each rule with its sequence number,
action and hits, plus the rules and policies not copied. Check:

- `Infrastructure copied whole: all N policies`
- `Hot rules copied: N of N`
- `System defaults in the bundles: none` (the ones left out are listed)
- every `CHECK:` line about a DROP/REJECT rule not copied (Read this first, item 4)

It stops with `STOP:` if an Infrastructure policy or rule is missing, a hot
rule is missing, or a system default got into a bundle.

Options: `--min-hits N` (a rule is hot when it has more than N hits),
`--whole-categories`, `--hit-categories`.

## Step 3 - Push them to the new manager

```bash
python tools/nsx/critical_rules/step3_push.py --source $SRC --target $TGT --runs-dir "$RUNS"            # dry run
python tools/nsx/critical_rules/step3_push.py --source $SRC --target $TGT --runs-dir "$RUNS" --apply    # write
```

Checks the target is empty, then runs services, groups (segment references
stripped), policies and rules for the Infrastructure bundle, then the
hot-rules bundle. Stops at the first failure. Read the dry run's table
(`failed=0` everywhere) before `--apply`.

`--apply` must run in a terminal: every push tool starts at batch size 1 and
asks before each next batch (`Enter` continue, a number sets the batch size,
`x` stops). Without a terminal the script refuses `--apply` instead of letting
the first prompt read end-of-input and stop after one object. To drive it from
a script, add `--piped-answers` and feed the answers yourself (for example
`yes "" | ...`), only with the operator's approval. After a partial apply,
rerun with `--apply --allow-non-empty` to continue.

## Step 4 - Verify

```bash
python tools/nsx/critical_rules/step4_verify.py --source $SRC --target $TGT --runs-dir "$RUNS"
```

Compares every object in the two bundles with the target. Expect
`VERIFY PASS`: nothing missing, nothing extra.

## Revert

```bash
python tools/nsx/critical_rules/revert.py --source $SRC --target $TGT --runs-dir "$RUNS"            # dry run
python tools/nsx/critical_rules/revert.py --source $SRC --target $TGT --runs-dir "$RUNS" --apply    # write
```

Hot-rules bundle first, then Infrastructure; rules, policies, groups,
services. Every push step 3 made is undone, newest first, including an earlier
apply that stopped partway, so one run of `--apply` returns the target to
empty. Each push left a baseline under `<bundle>/<class>/push_report/baselines/`,
and the push tool renames it to `*.reverted` once a revert completes; the
dry run shows the plan for every pending baseline, and a class shows
`already reverted` or `never applied` when nothing is left. Groups are reverted
with `--allow-delete`; without that flag `groups.py revert` keeps the groups
its push created and still reports success. Like step 3, `--apply` needs a
terminal (or `--piped-answers`, only with the operator's approval).

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
| 2026-10-08 | `nsx-lm2 -> nsx-lm3`, run `nsx_critical_runs/nsx-lm2_to_nsx-lm3/20261008_160929` (Mac, exact copy) | Infrastructure: 2 policies, 4 rules. Application: `Start_Policy` (7 of 9 rules hot) and `seed-policy-app` (2 of 13), original ids, names and sequence numbers; `test-policy-2` not copied (no hot rules); default sections left out. Step 3 dry run 2/7/2/4 and 2/17/2/9 (services/groups/policies/rules), 0 failed. Not applied |
