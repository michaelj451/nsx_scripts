# Runbook - Unused rule cleanup (macOS / Linux / bash)

Clean up one NSX Local Manager in two steps, with a soak period between them.
One script per step under `tools/nsx/rule_cleanup/`, each with its own undo:

| Step | Script | Writes |
|---|---|---|
| 1. Disable rules not hit for more than N days | `step1_disable.py` | plan: read only; `--apply` disables |
| Soak period | (wait; watch for breakage) | nothing |
| 2. Delete those rules, then empty policies, then unreferenced groups | `step2_delete.py` | plan: read only; `--apply` deletes |
| Undo step 1 | `step1_undo.py` | re-enables (all, or one with `--rule`) |
| Undo step 2 | `step2_undo.py` | re-creates what step 2 deleted |

What counts as unused:

- **Rule (step 1):** not hit for **more than N days**. N is
  `NSX_CLEANUP_NO_HIT_DAYS` in `.env`, **90 by default**;
  `--no-hit-days N` overrides it. A rule with no counter row is `NO_STATS` and
  is never touched.
- **Rule (step 2):** a rule step 1 disabled that is still disabled, unchanged
  since step 1, and whose counters have not moved since step 1 recorded them.
- **Policy (step 2):** a customer DFW policy with no rules left once those rules
  are gone, including policies that were already empty.
- **Group (step 2):** a customer group nothing references once those rules and
  policies are gone. References are looked for in every remaining DFW rule and
  policy (Applied To included, default sections included), gateway, IDS,
  redirection, forwarding and endpoint policies and their rules, the DFW
  exclusion list, load-balancer pools and virtual servers, and other groups. A
  group nested only inside a group being deleted goes too, after its parent.

**Services are never touched.** NSX's own objects are never changed: the
Default Layer2/Layer3 sections and their rules, built-in groups, anything
`is_default`, `_system_owned` or created by NSX itself.

Each step runs twice: first without `--apply` (the plan: read only, the client
is locked against writes), then with `--apply`, which carries out **only the
reviewed plan** and re-checks every object live right before writing it.

Every run lives in its own folder under `$RUNS`:

```
$RUNS/<target>/<UTC_TS>/
    run.json                 what each script did
    step1/plan.json, plan.md every customer rule: counters, last hit, class, full JSON
    step1/disabled.json      rules step 1 disabled (full JSON and counters after the write)
    step2/plan.json, plan.md what step 2 deletes, in order
    step2/before_<ts>.json   policies, rules and groups before each step 2 apply
    step2/deleted.json       every deleted object's full JSON (step2_undo.py reads it)
    logs/
```

Step 1's plan starts a run; every other command uses the newest run for the
target under `$RUNS` (or `--run <folder>`).

PowerShell variant (nsx-ws1): [RUNBOOK_RULE_CLEANUP_PS.md](RUNBOOK_RULE_CLEANUP_PS.md).

---

## How the last hit is found

**NSX keeps no last-hit time.** A rule's statistics are running totals only
(hits, packets, bytes, sessions, popularity). Checked 2026-10-11: the NSX REST
API reference `RuleStatistics` schema (4.2 and 9.0.2) has no time field, the
Broadcom KB 412847 on DFW rule statistics lists only the counters, and on
nsx-lm2 the old firewall API row and the single-rule call carry no timestamp
(the Policy-API statistics call returns HTTP 500 on lm1, lm2 and lm3). Third-party
tools that show "not hit in the last 90 days" collect the counters on a
schedule and compare them. So the last hit is worked out the same way, from
**counter snapshots taken over time**:

- `report_rules_usage.py` saves a snapshot every time it runs, under
  `$NSX_LOG_DIR/reports/<host>/rules_usage/<UTC_TS>/`. That folder is the
  history. Every step 1 plan runs the report once first, so each plan adds a
  snapshot; the live counters are the newest reading.
- The rule was last hit **between the last snapshot where any of its counters
  moved and the snapshot before it**. Bytes count as well as hits: a
  long-lived session keeps a rule busy without new hits.
- If the counters have not moved since the oldest snapshot, the last hit was
  **before** that snapshot.
- If the counters are all 0 and never went down, the rule has **never** been
  hit since it was created, so its creation date is enough; no history needed.
- If a counter went down (statistics reset by an operator, or the rule
  re-created), the readings before the reset are ignored. Per KB 412847,
  rebooting hosts, Edges or Managers and upgrading NSX do not reset them.

So:

| Rule | Can step 1 select it today? |
|---|---|
| never hit, created more than N days ago | yes, no history needed |
| never hit, created within the last N days | no: `TOO_NEW` |
| hit at some point, counters unchanged in a snapshot more than N days old | yes |
| hit at some point, history shorter than N days | no: `RECENT` until the history reaches back N days |

**Build the history now.** With N = 90, a rule that was ever hit can only
qualify once there is a snapshot more than 90 days old. Schedule the report
daily (cron, or Task Scheduler on Windows):

```bash
python tools/reports/report_rules_usage.py --target $TGT
```

The precision of "last hit" is the snapshot interval: with daily snapshots,
to the day. Snapshots already taken by the INFO GATHER or rules-usage
runbooks count, if they are under the same `--history-root`.

---

## Read this first

1. **A statistics reset hides old traffic.** NSX resets rule counters only
   when someone resets them (or the rule is re-created); reboots and upgrades
   keep them (KB 412847). A reset before the first snapshot is invisible: a
   rule that carried traffic before it shows 0 and looks never hit, and the
   creation-date rule above then trusts the counter. Do not reset DFW rule
   statistics on a manager you plan to clean up.
2. **NSX 3.2.x answers rule statistics with HTTP 500** on the Policy API, even
   for local policies. The scripts and the report fall back to the older
   firewall API on the same manager. The plan says which source each policy's
   counters came from.
3. **Counters lag 5 to 30 minutes.** An ALLOW rule counts sessions; a DROP rule
   counts packets.
4. **Disabling a DROP or REJECT rule changes what the manager does for traffic
   nobody has sent lately:** if that traffic arrives it reaches the next rule
   (or the default rule) instead. Step 1 lists every such rule with a `CHECK:`
   line. `--keep-deny` leaves them enabled.
5. **The soak period is the test.** A disabled rule enforces nothing, so if
   anything needed it, it breaks while the rule is disabled. Re-enable that one
   rule with `step1_undo.py --rule <policy_id>/<rule_id> --apply`; step 2 then
   leaves it alone. The scripts do not enforce a soak length: step 2's plan
   prints how long the rules have been disabled.
6. **Rules that were already disabled before step 1 are left out of step 2 by
   default:** rules are often staged disabled ahead of a change window. Add
   `--include-pre-disabled` to step 2 to delete them too (only ones that
   qualified in step 1's plan).
7. **Empty policies and unreferenced groups that existed before this run are
   deleted too.** The plan marks them `already empty` / `already unreferenced`,
   apart from those this run frees (`emptied by this run` / `freed by this run`).
   Review those lines.
8. **`--apply` writes only what the reviewed plan lists.** Anything that became
   unused after the plan was made is reported, not deleted; plan again to
   review it. A rule that changed, was re-enabled, or whose counters moved since
   the plan is skipped.
9. **Applies are interactive.** `--apply` asks before every batch (`Enter`
   continue, a number sets the batch size, `n` back to 1, `x` stops), so it
   must run in a terminal; without one it is refused. `--piped-answers` lets
   answers come from a pipe, only with the operator's approval. A stopped
   apply can be rerun; it continues where it left off.
10. **Writes are guarded.** Step 1 and `step1_undo.py` send the rule back with
    only `disabled` changed and its `_revision`, so NSX refuses the write
    (HTTP 412, reported as skipped) if anyone edited the rule in between. NSX
    also refuses to delete a group that is still referenced; step 2 then keeps
    that group and reports it.

---

## Setup

```bash
REPO=~/dev/nsx_scripts               # the toolkit checkout
RUNS="$REPO/nsx_cleanup_runs"        # where every run is stored (any folder)
TGT=nsx-lm2                          # the Local Manager to clean up

cd "$REPO"
source .venv/bin/activate
export PYTHONPATH="$REPO/app"
export NSX_LOG_DIR="$REPO/nsx_logs"  # the counter history lives under $NSX_LOG_DIR/reports
```

Instead of `--runs-dir` on every command you can `export NSX_CLEANUP_RUNS_DIR="$RUNS"`;
the commands below pass it explicitly so it is visible.

The window is in `.env`:

```
NSX_CLEANUP_NO_HIT_DAYS=90
```

Unset, it is 90. `--no-hit-days N` on the step 1 plan overrides it for that
run. A shell variable of the same name wins over `.env`. The plan prints the
window and where it came from (`Window: ... (from NSX_CLEANUP_NO_HIT_DAYS)`)
and how far back the history reaches.

Take a backup first (read only), so there is a restore point outside this
workflow too:

```bash
python tools/nsx/backup_nsx_state.py --source $TGT
```

## Step 1 - Disable rules not hit for more than N days

Plan (read only; starts a new run and takes a counter snapshot):

```bash
python tools/nsx/rule_cleanup/step1_disable.py --target $TGT --runs-dir "$RUNS"
```

It prints the window, the history it used (snapshots, how far back), the
count per class, and every rule it would disable with its last hit. Classes:

| Class | Meaning | Step 1 |
|---|---|---|
| `DISABLE` | not hit for more than N days, enabled | disables it |
| `ALREADY_DISABLED` | the same, already disabled | nothing (step 2 only with `--include-pre-disabled`) |
| `KEEP_DENY` | would be `DISABLE`, but DROP/REJECT and `--keep-deny` | nothing |
| `TOO_NEW` | never hit, created within the last N days | nothing |
| `RECENT` | hit within the last N days, or the history does not reach back N days | nothing |
| `NO_STATS` | NSX returned no counter row | nothing |

Check every `CHECK:` line (Read this first, item 4), any `WARNING` about
`NO_STATS`, and the `NOTE` when the history is shorter than N days. The full
table (counters, last hit, days without a hit, age) is in the run's
`step1/plan.md`.

Apply (in your terminal):

```bash
python tools/nsx/rule_cleanup/step1_disable.py --target $TGT --runs-dir "$RUNS" --apply
```

Right before each write it re-reads the rule and its policy's counters and
skips the rule if it is gone, already disabled, changed since the plan, or its
counters moved since the plan. Every rule it disabled is recorded, with its
counters at that moment, in `step1/disabled.json`.

Options (plan only; `--apply` refuses them and carries out the reviewed plan):
`--no-hit-days N`, `--history-root DIR` (default `$NSX_LOG_DIR/reports`),
`--keep-deny`.

## Soak period

Leave the rules disabled for the period your change process sets. If
something breaks, re-enable the rule that carried it:

```bash
python tools/nsx/rule_cleanup/step1_undo.py --target $TGT --runs-dir "$RUNS" --rule <policy_id>/<rule_id>           # dry run
python tools/nsx/rule_cleanup/step1_undo.py --target $TGT --runs-dir "$RUNS" --rule <policy_id>/<rule_id> --apply   # write
```

`--rule` takes `<policy_id>/<rule_id>`, a rule id or a rule display name, and
can be repeated. Without `--rule` every rule step 1 disabled is re-enabled. A
re-enabled rule is never disabled again by this run and step 2 leaves it alone.

## Step 2 - Delete the unused rules, policies and groups

Plan (read only), on the same run:

```bash
python tools/nsx/rule_cleanup/step2_delete.py --target $TGT --runs-dir "$RUNS"
```

It prints how long the rules have been disabled, then every rule, policy and
group it would delete (groups in delete order, with what each nests), every
candidate rule it keeps and why, and which other group consumers it read.
Full detail in `step2/plan.md`. Option: `--include-pre-disabled` (Read this
first, item 6).

Apply (in your terminal):

```bash
python tools/nsx/rule_cleanup/step2_delete.py --target $TGT --runs-dir "$RUNS" --apply
```

Order: rules, then policies, then groups. Before the first delete it saves
policies, rules and groups to `step2/before_<ts>.json`; each object's full
JSON goes into `step2/deleted.json` right before it is deleted. A policy is
deleted only if it has no rules at that moment. Groups are re-checked against
the live manager after the rules and policies are gone.

## Undo step 2

```bash
python tools/nsx/rule_cleanup/step2_undo.py --target $TGT --runs-dir "$RUNS"            # dry run
python tools/nsx/rule_cleanup/step2_undo.py --target $TGT --runs-dir "$RUNS" --apply    # write
```

Re-creates every deleted object with its original id: groups (nested ones
first), then policies, then rules with their original sequence numbers.
Rules come back **disabled**, as they were when deleted; then
`step1_undo.py` re-enables them if wanted. Objects already on the manager are
left alone. The undo cannot bring back a rule's old hit counters (NSX starts a
re-created rule at 0).

## Choices

| Choice | Default | Change with |
|---|---|---|
| Disable only rules not hit for more than N days | 90 | `NSX_CLEANUP_NO_HIT_DAYS` in `.env`; `--no-hit-days N` (step 1 plan) overrides |
| Counter history | `$NSX_LOG_DIR/reports/<host>/rules_usage/` | `--history-root DIR` (step 1 plan) |
| Disable DROP/REJECT rules | yes | `--keep-deny` (step 1 plan) |
| Delete qualifying rules disabled before step 1 | no | `--include-pre-disabled` (step 2) |
| Where runs are stored | `<repo>/nsx_cleanup_runs` | `--runs-dir`, or `NSX_CLEANUP_RUNS_DIR` |
| Services | never touched | (not configurable) |

## Lab run record

2026-10-11 17:39 UTC, nsx-lm2, plan only, default now 90 days (Mike: selected
when never hit and older than 90 days, or last hit more than 90 days ago), run
`20261011_173916` (the newest, so a plain `--apply` does nothing): 0 `DISABLE`,
19 `TOO_NEW` (never hit, 8 days old), 10 `RECENT` (hits; history 0 days deep).

2026-10-11 17:28 UTC, nsx-lm2, plans only (nothing applied). Every lm2 rule was
created 2026-10-02 18:09 UTC (8 days old); the counter history started with
these plans (`nsx_logs/reports/nsx-lm2.lab.local/rules_usage/`):

- `--no-hit-days 730` (from `.env`), runs `20261011_172818` and
  `20261011_172933` (the newest, so a plain `--apply` does nothing): 0
  `DISABLE`, 19 `TOO_NEW`, 10 `RECENT`, and the NOTE that the history reaches
  back 0 days.
- `--no-hit-days 7`, run `20261011_172843`: 18 `DISABLE` (all `last hit:
  never`; 2 deny rules: `seed-infra-deny-block` DROP, `seed-empty-src` REJECT),
  1 `ALREADY_DISABLED` (`seed-disabled`), 10 `RECENT`.
- Hit-age check, read only, in the session scratchpad: a copy of the real
  17:28 snapshot backdated to 2024-09-01 as the only history, 730 days: the 10
  rules with hits came out `DISABLE`, `last hit: before 2024-09-01 (oldest
  reading)`; the 19 never-hit rules `TOO_NEW`.

2026-10-11 04:25 UTC (before the window existed), run `20261011_042514`:
Policy API HTTP 500 on all 5 customer policies, old firewall API answered with
a row for every rule. Step 2 found nothing to delete (all 48 customer groups
referenced). Preview of step 2 after disabling the 18 (planner run in memory
on live data): 18 rules, 2 policies (`test-infrastructure-policy`,
`test-policy-2`), 29 of 48 groups; 19 groups stay. Other group consumers on
lm2: 4 gateway policies/4 rules, 1 redirection policy/1 rule, empty exclusion
list, no load balancer; endpoint policies not on this manager (404).
