# Runbook - Unused rule cleanup (macOS / Linux / bash)

Clean up one NSX Local Manager in two steps, with a soak period between them.
One script per step under `tools/nsx/rule_cleanup/`, each with its own undo:

| Step | Script | Writes |
|---|---|---|
| 1. Disable rules that have never been hit | `step1_disable.py` | plan: read only; `--apply` disables |
| Soak period | (wait; watch for breakage) | nothing |
| 2. Delete the unused rules, then empty policies, then unreferenced groups | `step2_delete.py` | plan: read only; `--apply` deletes |
| Undo step 1 | `step1_undo.py` | re-enables (all, or one with `--rule`) |
| Undo step 2 | `step2_undo.py` | re-creates what step 2 deleted |

What counts as unused:

- **Rule (step 1):** NSX returned a counter row for it and its hit, packet,
  byte and session counts are all 0. A rule with no counter row is `NO_STATS`
  and is never touched.
- **Rule (step 2):** a rule step 1 disabled that is still disabled, unchanged
  since step 1, and still has no hits.
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
    step1/plan.json, plan.md every customer rule: counters, class, full JSON
    step1/disabled.json      rules step 1 disabled (full JSON after the write)
    step2/plan.json, plan.md what step 2 deletes, in order
    step2/before_<ts>.json   policies, rules and groups before each step 2 apply
    step2/deleted.json       every deleted object's full JSON (step2_undo.py reads it)
    logs/
```

Step 1's plan starts a run; every other command uses the newest run for the
target under `$RUNS` (or `--run <folder>`).

PowerShell variant (nsx-ws1): [RUNBOOK_RULE_CLEANUP_PS.md](RUNBOOK_RULE_CLEANUP_PS.md).

---

## Read this first

1. **Hit counts are cumulative since the last counter reset** (host reboot,
   upgrade, section recreate). A rule that carried traffic before a reset shows
   0 now. The plan shows each rule's age; `--min-age-days N` leaves rules
   younger than N days alone. A lab manager carries little traffic, so most lab
   rules show 0, and your own SSH and pings into the lab VMs count.
2. **NSX 3.2.x answers rule statistics with HTTP 500** on the Policy API, even
   for local policies. The scripts fall back to the older firewall API on the
   same manager (the same fallback `report_rules_usage.py` uses). The plan says
   which source each policy's counters came from.
3. **Counters lag 5 to 30 minutes.** An ALLOW rule counts sessions; a DROP rule
   counts packets.
4. **Disabling a never-hit DROP or REJECT rule changes what the manager does
   for traffic nobody has sent yet:** if that traffic ever arrives it reaches
   the next rule (or the default rule) instead. Step 1 lists every such rule
   with a `CHECK:` line. `--keep-deny` leaves them enabled.
5. **The soak period is the test.** A disabled rule enforces nothing, so if
   anything needed it, it breaks while the rule is disabled. Re-enable that one
   rule with `step1_undo.py --rule <policy_id>/<rule_id> --apply`; step 2 then
   leaves it alone. The scripts do not enforce a soak length: step 2's plan
   prints how long the rules have been disabled.
6. **Rules that were already disabled before step 1 are left out of step 2 by
   default:** rules are often staged disabled ahead of a change window. Add
   `--include-pre-disabled` to step 2 to delete them too (only never-hit ones).
7. **Empty policies and unreferenced groups that existed before this run are
   deleted too.** The plan marks them `already empty` / `already unreferenced`,
   apart from those this run frees (`emptied by this run` / `freed by this run`).
   Review those lines.
8. **`--apply` writes only what the reviewed plan lists.** Anything that became
   unused after the plan was made is reported, not deleted; plan again to
   review it. A rule that changed, was re-enabled, or got hits since the plan is
   skipped.
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
export NSX_LOG_DIR="$REPO/nsx_logs"
```

Instead of `--runs-dir` on every command you can `export NSX_CLEANUP_RUNS_DIR="$RUNS"`;
the commands below pass it explicitly so it is visible.

Take a backup first (read only), so there is a restore point outside this
workflow too:

```bash
python tools/nsx/backup_nsx_state.py --source $TGT
```

## Step 1 - Disable rules that have never been hit

Plan (read only; starts a new run):

```bash
python tools/nsx/rule_cleanup/step1_disable.py --target $TGT --runs-dir "$RUNS"
```

It prints the count per class and every rule it would disable. Classes:

| Class | Meaning | Step 1 |
|---|---|---|
| `DISABLE` | never hit, enabled | disables it |
| `ALREADY_DISABLED` | never hit, already disabled | nothing (step 2 only with `--include-pre-disabled`) |
| `KEEP_DENY` | never-hit DROP/REJECT, with `--keep-deny` | nothing |
| `TOO_NEW` | never hit, younger than `--min-age-days` | nothing |
| `NO_STATS` | NSX returned no counter row | nothing |
| `USED` | has hits | nothing |

Check every `CHECK:` line (Read this first, item 4) and any `WARNING` about
`NO_STATS`. The full table, with ages and counters, is in the run's
`step1/plan.md`.

Apply (in your terminal):

```bash
python tools/nsx/rule_cleanup/step1_disable.py --target $TGT --runs-dir "$RUNS" --apply
```

Right before each write it re-reads the rule and its policy's counters and
skips the rule if it is gone, already disabled, changed since the plan, or
has hits now. Every rule it disabled is recorded in `step1/disabled.json`.

Options (plan only): `--min-age-days N`, `--keep-deny`.

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
| Disable never-hit DROP/REJECT rules | yes | `--keep-deny` (step 1 plan) |
| Minimum rule age | none | `--min-age-days N` (step 1 plan) |
| Delete never-hit rules disabled before step 1 | no | `--include-pre-disabled` (step 2) |
| Where runs are stored | `<repo>/nsx_cleanup_runs` | `--runs-dir`, or `NSX_CLEANUP_RUNS_DIR` |
| Services | never touched | (not configurable) |

## Lab run record

2026-10-11 04:25 UTC, nsx-lm2, plans only (nothing applied), run
`nsx_cleanup_runs/nsx-lm2/20261011_042514`:

- Counters: Policy API HTTP 500 on all 5 customer policies, old firewall API
  answered for all 5, with a row for every rule.
- Step 1: 29 customer rules: 18 `DISABLE` (2 of them deny rules:
  `seed-infra-deny-block` DROP, `seed-empty-src` REJECT), 1 `ALREADY_DISABLED`
  (`seed-disabled`), 10 `USED`.
- Step 2 (before step 1 is applied): nothing to delete; all 48 customer groups
  are referenced today. Other consumers read: 4 gateway policies/4 rules, 1
  redirection policy/1 rule, empty exclusion list, no load balancer; endpoint
  policies not on this manager (404).
- Preview of step 2 after step 1 (planner run in memory on live data): 18
  rules, 2 policies (`test-infrastructure-policy`, `test-policy-2`), 29 of 48
  groups; 19 groups stay (used by the 10 rules with hits).
