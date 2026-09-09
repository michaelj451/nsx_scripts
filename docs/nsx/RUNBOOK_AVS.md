# Runbook AVS - Federation teardown to IP-based groups on a target manager

## Summary

The AVS path moves customer DFW config off a Global Manager onto a Local
Manager, then decomposes every tag-based group into an IP-only sibling so the
target no longer depends on VM tags or on dynamic membership evaluation. That
matters for Azure VMware Solution because the destination has neither the
source's VM inventory nor its tag scheme: a group whose membership is "whatever
VMs carry tag `network|10.6.0.0`" evaluates to nothing after the move, while a
group holding literal IPs keeps matching.

```text
Phase 1  GM to LM copy      export GM, rewrite /global-infra/ refs, push to LM
Phase 2  WF-A Part 1        clone LM to target LM (definitions, segments stripped)
Phase 3  WF-C               decompose tag groups into IP-only siblings
Phase 4  Report + Verify    consolidated change report, then live verification
Phase 5  Revert             per-phase unwind, reverse order
```

Every phase is dry-run first. Nothing writes without `--apply`.

> ## THE FIVE THINGS THAT SILENTLY GO WRONG
>
> 1. **`--live-query` missing on the capture.** `groups_additive/` becomes a
>    copy of the plain export, every tag group looks empty, and WF-C produces
>    no siblings. The run reports success.
>    [Details](#failure-mode-the-silent-empty-capture)
> 2. **The wrong API for group IPs.** Fixed 2026-09-08 (`--ip-source
>    effective`, now the default), but any bundle captured before that is a
>    lower bound. [Details](#failure-mode-ip-source)
> 3. **`--allow-delete` missing on revert.** Groups the push created are left
>    behind, listed in `deletes_blocked`, and the revert still reports success.
>    [Details](#phase-5---revert)
> 4. **A group created moments ago is not yet realized.** NSX answers HTTP 400
>    for its effective IPs. The client now retries; if it still fails the run
>    errors rather than recording an empty IP list.
>    [Details](#failure-mode-unrealized-groups)
> 5. **A dry run without `--diff-target` is blind.** It never contacts the
>    target, so it reports 0 IPs added and 0 removed no matter what the apply
>    would do. Always pass `--diff-target` on the group pushes before approving.
>    [Details](#the-dry-run-pass)

---

## Variables

Set these once. Every command below uses them, so a different pair of managers
means editing only this block.

```bash
source .venv/bin/activate
export PYTHONPATH="$PWD/app"

# --- identity -------------------------------------------------------------
export GM=nsx-gm1                      # Global Manager alias (Phase 1 only)
export SRC=nsx-lm1                     # source Local Manager
export TGT=nsx-lm3                     # target Local Manager
export DOMAIN=default

# --- derived hostnames (bundles are keyed by host, not alias) -------------
export GM_HOST=nsx-gm1.lab.local
export SRC_HOST=nsx-lm1.lab.local
export TGT_HOST=nsx-lm3.lab.local      # amend-refs writes its baseline here

# --- run directories ------------------------------------------------------
export RUN=nsx_avs_runs/v2             # bump per run: v1, v2, ...
export GM2LM=nsx_gm_to_lm/$GM_HOST     # Phase 1 transformed bundles
export SIB=$RUN/nsx_sibling_groups/$SRC_HOST
export STRIP=$RUN/nsx_stripped_groups/$SRC_HOST
export DRY=$RUN/dryrun
export REPORT=$RUN/report

# --- source-side export bundles (written by capture step 7) ---------------
export EXP_SVC=nsx_services_export/$SRC_HOST/services
export EXP_GRP=nsx_groups_export/$SRC_HOST/groups
export EXP_POL=nsx_policies_export/$SRC_HOST/security-policies
export EXP_RUL=nsx_rules_export/$SRC_HOST/security-policies

mkdir -p "$RUN" "$DRY" "$REPORT"
export RUN_START=$(date -u +%Y-%m-%dT%H:%M:%S)   # scopes the change report
echo "run starts $RUN_START -> $RUN"
```

Keeping `$RUN` distinct per run matters: `build_sibling_groups.py
--output-base "$RUN"` puts each run's siblings, stripped originals, push
reports and baselines in their own tree, so a later revert cannot pick up an
older run's baseline.

---

## Prerequisites

| Requirement | Why |
|---|---|
| Fresh backup of every manager you will write to | `backup_nsx_state.py`; the wipe has no paired revert |
| Target state known (empty, or a prior run) | See [re-running onto a v1 system](#re-running-onto-a-system-that-already-had-a-run) |
| `OBJECT_APPENDIX` in `.env` unchanged between runs | A changed suffix creates a second, parallel sibling set |
| Source LM has the VMs, tagged | Phase 3 freezes what NSX resolves each group to |

```bash
python tools/nsx/backup_nsx_state.py --source "$TGT"
python tools/test/wipe_target_manager.py --target "$TGT"          # dry-run first
```

---

## Phase 1 - Global Manager to Local Manager

Skip if the config already lives on `$SRC`. A GM export references everything
through `/global-infra/...`, which an LM rejects.

```bash
# 1a. Export the GM (read-only). --federation-global is REQUIRED for a GM.
for t in services groups policies rules; do
  python tools/nsx/$t.py export --source "$GM" --federation-global
done

# 1b. Rewrite /global-infra/ to /infra/ (offline, no NSX calls)
python tools/nsx/transform_gm_export_to_lm.py \
  --input-root nsx_services_export/$GM_HOST/services  --output-root $GM2LM/services
python tools/nsx/transform_gm_export_to_lm.py \
  --input-root nsx_groups_export/$GM_HOST/groups      --output-root $GM2LM/groups
python tools/nsx/transform_gm_export_to_lm.py \
  --input-root nsx_policies_export/$GM_HOST/security-policies --output-root $GM2LM/policies
python tools/nsx/transform_gm_export_to_lm.py \
  --input-root nsx_rules_export/$GM_HOST/security-policies    --output-root $GM2LM/rules

# 1c. Must print "clean"
grep -rl "global-infra" $GM2LM/ || echo "clean"

# 1d. Push (drop --apply for the dry run)
python tools/nsx/services.py push --target "$SRC" --services-dir $GM2LM/services --apply
python tools/nsx/groups.py   push --target "$SRC" --groups-dir  $GM2LM/groups --segments-mode strip --apply
python tools/nsx/policies.py push --target "$SRC" --policies-dir $GM2LM/policies --apply
python tools/nsx/rules.py    push --target "$SRC" --rules-dir    $GM2LM/rules --apply
```

Add `--source-domain <gm-domain> --target-domain "$DOMAIN"` to the transform if
the GM uses a location domain. Check with:

```bash
grep -rhoE "/global-infra/domains/[^/\"' ]+" nsx_groups_export/$GM_HOST | sort -u
```

### Wiping the GM afterwards

`wipe_target_manager.py` auto-selects the GM surface for `nsx-gm*` aliases.
**Confirm the header line reads `GLOBAL MANAGER` before trusting a zero
result**: an LM-surface query against a GM finds nothing and reports a clean
no-op wipe.

```bash
python tools/nsx/backup_nsx_state.py --source "$GM"        # mandatory, no paired revert
python tools/test/wipe_target_manager.py --target "$GM"    # dry-run
python tools/test/wipe_target_manager.py --target "$GM" --apply
```

---

## Phase 2 - Capture and WF-A Part 1

WF-A Parts 2 and 3 are **skipped**: Phase 3 replaces Part 3, and segments are
not part of this design.

```bash
# 2a. Capture. --live-query is MANDATORY; --ip-source defaults to 'effective'.
python tools/nsx/capture_nsx_state.py --source "$SRC" --live-query

# 2b. GATE. All three must be non-zero, and errors must be zero.
grep -E '"ip_source"|"vm_ip_index_count"|"groups_changed"|"ips_added_total"|"groups_errors"' \
  nsx_capture/$SRC_HOST/logs/2_build_group_ip_additive_from_live_members.log
```

| Field | Required |
|---|---|
| `ip_source` | `"effective"`. Anything else means a stale or legacy bundle |
| `vm_ip_index_count` | non-zero |
| `groups_changed` | non-zero |
| `ips_added_total` | non-zero |
| `groups_errors` | **0**. Non-zero means unrealized groups; see [below](#failure-mode-unrealized-groups) |

Capture step 7 writes the flat export bundles that `$EXP_*` point at.

```bash
# 2c. WF-A Part 1 push, dependency order (drop --apply for the dry run)
python tools/nsx/services.py push --target "$TGT" --services-dir "$EXP_SVC" --apply
python tools/nsx/groups.py   push --target "$TGT" --groups-dir  "$EXP_GRP" --segments-mode strip --apply
python tools/nsx/policies.py push --target "$TGT" --policies-dir "$EXP_POL" --apply
python tools/nsx/rules.py    push --target "$TGT" --rules-dir    "$EXP_RUL" --apply
```

**New objects are created, not just updated.** The push tools PUT and fall back
to PATCH, so services, groups, policies and rules added on `$SRC` since the
last run land on `$TGT` as new objects. Verified 2026-09-09: a new service,
tag group, pure-IP group, policy and 2 rules all created cleanly on a target
that already held a prior run.

The two default sections and their rules are always skipped
(`SKIP_POLICIES` in `policies.py` / `rules.py`), so `$TGT` keeps its own.

---

## Phase 3 - WF-C decomposition

```bash
# 3a. Ground truth: what does NSX itself say each group resolves to?
python - <<'PY'
import sys, json, os, logging; sys.path.insert(0, "app"); logging.disable(logging.INFO)
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_constants import resolve_manager
c = NsxPolicyClient(nsxmanager=resolve_manager(os.environ["SRC"]), federation_global=False)
truth = {}
for g in c.list_groups(domain_id=os.environ.get("DOMAIN", "default")):
    if g.get("_system_owned"): continue
    truth[g["id"]] = c.get_group_effective_ips(g["id"])
    print(f"  {g['id']:34} {len(truth[g['id']])} ips")
json.dump(truth, open(os.environ["REPORT"] + "/source_effective_ips.json", "w"), indent=2)
PY

# 3b. Build siblings offline, into this run's own tree
python tools/nsx/build_sibling_groups.py --source "$SRC" --output-base "$RUN"

# 3c. Review BEFORE pushing
python -c "
import json, os
m=json.load(open(os.environ['SIB']+'/sibling_map.json'))
print('siblings:', m['count'], 'appendix:', m['appendix'])
[print(' ', e['sibling_id'], e['ips_source']) for e in m['map']]"
```

Expect `siblings_written + skipped_no_condition + skipped_empty_ips` to equal
`files_seen`. A non-zero `skipped_empty_ips` means a tag group NSX resolves to
nothing; confirm against 3a rather than assuming.

```bash
# 3d. Push siblings (additive, creates new objects)
python tools/nsx/groups.py push --target "$TGT" --groups-dir "$SIB/groups" --apply

# 3e. Strip IPs from tag-side originals (the only destructive step)
python tools/nsx/groups.py push --target "$TGT" --groups-dir "$STRIP/groups" \
  --intentional-ip-removal --apply

# 3f. Amend rules: original OR sibling
python tools/nsx/rules.py amend-refs --target "$TGT" \
  --sibling-map "$SIB/sibling_map.json" --apply
```

**Ordering matters for 3f.** `amend-refs` walks the rules that exist on `$TGT`,
so it must run after 2c. Its dry run before the rules push undercounts: on the
reference run it saw 12 rules in the dry run and 14 after the push landed the
new ones.

---

## Phase 4 - Dry run, report, verify

### The dry-run pass

Run the whole sequence with `--apply` removed, capturing each report:

```bash
python tools/nsx/services.py push --target "$TGT" --services-dir "$EXP_SVC"  > $DRY/1_services.json 2>$DRY/1_services.log
python tools/nsx/groups.py   push --target "$TGT" --groups-dir  "$EXP_GRP" --segments-mode strip --diff-target > $DRY/2_groups.json 2>$DRY/2_groups.log
python tools/nsx/policies.py push --target "$TGT" --policies-dir "$EXP_POL" > $DRY/3_policies.json 2>$DRY/3_policies.log
python tools/nsx/rules.py    push --target "$TGT" --rules-dir    "$EXP_RUL" > $DRY/4_rules.json 2>$DRY/4_rules.log
python tools/nsx/groups.py   push --target "$TGT" --groups-dir  "$SIB/groups" --diff-target > $DRY/5_siblings.json 2>$DRY/5_siblings.log
python tools/nsx/groups.py   push --target "$TGT" --groups-dir  "$STRIP/groups" --intentional-ip-removal --diff-target > $DRY/6_stripped.json 2>$DRY/6_stripped.log
python tools/nsx/rules.py    amend-refs --target "$TGT" --sibling-map "$SIB/sibling_map.json" > $DRY/7_amend.json 2>$DRY/7_amend.log

for f in $DRY/*.json; do
  echo "--- $(basename $f)"
  grep -oE '"(files_seen|dry_run|ok|failed|skipped|rules_seen|no_change|total_ips_removed)": *[0-9]+' $f | tr '\n' ' '; echo
done
```

**`--diff-target` is what makes a dry run worth reading.** A plain dry run is
fully offline: it never contacts the target, so it cannot know which IPs it
would add or remove and reports `total_ips_removed: 0` even when the apply
removes some. `--diff-target` adds one read-only pass over the target and fills
in `ips_before` / `ips_after` / `ips_added` / `ips_removed` on every row, makes
the summary total truthful, and logs a warning for any group that would lose
IPs without `--intentional-ip-removal`.

Measured on the reference run, same bundle and same target:

| Dry run | `total_ips_removed` | Apply actually removed |
|---|---|---|
| offline (default) | 0 | 2 |
| `--diff-target` | **2** | 2 |

> **The dry run overwrites the apply's report, and vice versa.** Both write to
> the same `<bundle>/push_report/<class>.json`. Run
> `report_avs_run.py` immediately after each pass, into separate
> `--out-dir`s (`$REPORT/dryrun` and `$REPORT/apply`); the aggregated report is
> the only durable record. Baselines under `push_report/baselines/` are
> unaffected, so revert still works either way.

### Consolidated change report

Run this **twice**: once on the dry-run pass to review before approving, and
again after the apply to record what happened. Only `--out-dir` and `--label`
change.

```bash
# Pre-apply review (after the dry-run pass above)
python tools/nsx/report_avs_run.py \
  --report-root nsx_services_export/$SRC_HOST \
  --report-root nsx_groups_export/$SRC_HOST \
  --report-root nsx_policies_export/$SRC_HOST \
  --report-root nsx_rules_export/$SRC_HOST \
  --report-root nsx_rules_export/$TGT_HOST \
  --report-root "$SIB" --report-root "$STRIP" \
  --out-dir "$REPORT/dryrun" --since "$RUN_START" \
  --label "PRE-APPLY dry run: $SRC to $TGT"
```

Everything lands in the `planned` column. Review `IPs added` / `IPs removed`
and the per-object table, then apply. Afterwards:

```bash
python tools/nsx/report_avs_run.py \
  --report-root nsx_services_export/$SRC_HOST \
  --report-root nsx_groups_export/$SRC_HOST \
  --report-root nsx_policies_export/$SRC_HOST \
  --report-root nsx_rules_export/$SRC_HOST \
  --report-root nsx_rules_export/$TGT_HOST \
  --report-root "$SIB" --report-root "$STRIP" \
  --out-dir "$REPORT/apply" --since "$RUN_START" \
  --label "APPLIED: $SRC to $TGT"
```

Offline; reads the push reports only. Writes `avs_run_report.md` (operator
table) and `avs_run_report.json` (every row). `--since "$RUN_START"` keeps
older rows in the same bundle out. Exit code 1 if any row failed, so it gates
a pipeline.

### Live verification

```bash
python tools/nsx/verify_avs_run.py --source "$SRC" --target "$TGT" \
  --sibling-map "$SIB/sibling_map.json" --report-dir "$REPORT"
```

Read-only, six checks, exit 0 only when all pass:

| Check | What it proves |
|---|---|
| V1 | every source object exists on the target (groups, services, policies, rules) |
| V2 | every sibling in `sibling_map.json` exists on the target |
| V3 | each sibling's IPs equal the **source group's effective IPs**, exactly |
| V4 | each stripped original has no `IPAddressExpression` left |
| V5 | every rule referencing an original also references its sibling |
| V6 | every target group's membership resolves (nothing left unrealized) |

V3 is the one that catches a sibling built from reconstructed VM IPs: it looks
structurally fine and is quietly missing addresses.

---

## Phase 5 - Revert

Reverse order. Each phase pops its own baseline, so run these against the
`push_report` of the bundle that wrote them.

```bash
# 5a. amend-refs (restores each rule's pre-amend payload)
python tools/nsx/rules.py revert --target "$TGT" \
  --reports-dir nsx_rules_export/$TGT_HOST/push_report --apply

# 5b. stripped originals (restores the mixed tag+IP payload)
python tools/nsx/groups.py revert --target "$TGT" \
  --reports-dir "$STRIP/push_report" --apply

# 5c. siblings. --allow-delete IS REQUIRED, see below.
python tools/nsx/groups.py revert --target "$TGT" \
  --reports-dir "$SIB/push_report" --allow-delete --apply
```

> ### `--allow-delete` is required and its absence is silent
>
> Without it, any group the push **created** is left in place, reported under
> `deletes_blocked` in the revert summary, and the revert still exits 0.
>
> Reference run: reverting 7 siblings restored 5 and blocked 2
> (`avs2-new-tag-group_np_ips`, `network-2_np_ips`, both created by this run).
> Re-running with `--allow-delete` deleted them: `restored ok=5/5 deleted
> ok=2/2`. Always read the summary:
>
> ```bash
> python -c "
> import json, glob, os
> f=sorted(glob.glob(os.environ['SIB']+'/push_report/revert_summary_*.json'))[-1]
> t=json.load(open(f))['totals']; print(t)
> assert not t.get('deletes_blocked'), 'BLOCKED: ' + str(t['deletes_blocked'])"
> ```

A consumed baseline is renamed `*.reverted`. To act on it again, pass
`--from-baseline <path-to-the-.reverted-file>`.

Then the WF-A Part 1 chain (rules, policies, groups, services); see
[RUNBOOK_A_COMMANDS.md](RUNBOOK_A_COMMANDS.md).

A wiped GM has no revert. Restore means pushing its backup bundle back, and
that path has not been exercised round-trip on real gear.

---

## Re-running onto a system that already had a run

The common case: v1 already landed, and you are re-running with the corrected
IP source, possibly with new objects added since.

| Concern | Behaviour |
|---|---|
| **Same `OBJECT_APPENDIX`** | Sibling ids match, so the push PATCHes them. IP sets **merge additively**, filling in what a v1 bug missed. This is the wanted path |
| **Changed `OBJECT_APPENDIX`** | Creates a second, parallel sibling set. The v1 groups stay and stay rule-referenced. **Do not change the suffix between runs** |
| New groups / services / policies / rules on `$SRC` | Created on `$TGT` by Phase 2c |
| Originals already stripped on `$TGT` | Phase 3e is a no-op for them; harmless |
| **Source itself previously stripped** | If WF-C was ever run in place against `$SRC`, its groups no longer resolve to the moved IPs, so 3a returns an incomplete truth. Union with the existing sibling's contents before rebuilding |
| Revert after an upgrade run | Lands on the **v1 state**, not on empty: restores prior siblings to their v1 IPs and deletes only what this run created |

Additive merge never removes, so a wrong IP written by v1 persists. Compare
against 3a's `source_effective_ips.json` and clean up explicitly if needed.

Inventory the target before starting:

```bash
python - <<'PY'
import sys, os, logging; sys.path.insert(0, "app"); logging.disable(logging.INFO)
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_constants import resolve_manager
c = NsxPolicyClient(nsxmanager=resolve_manager(os.environ["TGT"]), federation_global=False)
gs = [g["id"] for g in c.list_groups(domain_id=os.environ.get("DOMAIN","default"))
      if not g.get("_system_owned")]
sib = [g for g in gs if g.endswith(os.environ.get("OBJECT_APPENDIX", "_np_ips"))]
print(f"target groups: {len(gs)}, existing siblings: {len(sib)}")
[print("  ", s) for s in sorted(sib)]
PY
```

---

## Failure mode: the silent empty capture

`build_group_ip_additive_from_live_members.py` defaults to **offline copy**.
`capture_nsx_state.py` forwards `--live-query` only when you pass it, so a bare
capture produces a `groups_additive/` tree identical to the plain export.
Nothing errors; every step reports `ok: true`. The only signal is a WARNING in
the step log:

```
--no-live-query set: skipping VM IP index build and per-group evaluated-member
lookups. Output is the source export copied as-is
vm_ip_index_count: 0   groups_skipped: 12   ips_added_total: 0
```

WF-C then reports `skipped_empty_ips` for every dynamic group and builds
siblings only for statically authored IPs.

**Verified 2026-09-08:** bare capture produced 1 sibling with 2 IPs; the same
capture with `--live-query` produced 5 siblings with 13 IPs.

---

## Failure mode: IP source

The toolkit used to reconstruct group IPs from evaluated VM members looked up
in the fabric VIF index. That path sees only running VMs' VIF IPs and drops
static `IPAddressExpression` entries, IP ranges, segment-derived subnets,
nested-group contributions, and stopped VMs' last-known bindings.

**Measured 2026-09-08 on nsx-lm1: 10 of 12 groups under-reported.**

Fixed by `NsxPolicyClient.get_group_effective_ips()`, which calls
`.../groups/<id>/members/ip-addresses`, the list the UI's Effective Members tab
shows. `--ip-source effective` is now the default; `vm-vif` reproduces the old
behaviour and exists only to regenerate a pre-2026-09-08 bundle.

Full writeup: [NSX_TOOLKIT_GAPS.md](../reference/NSX_TOOLKIT_GAPS.md) section 2.0.

A stopped VM's binding is NSX's **last known** value and can be stale. On lm1,
`network-2`'s members are the VMs named `10.6.2.101/102` while NSX reports
`10.6.1.101/102`. Reconcile stopped-VM addresses against vCenter before
cutover.

---

## Nested groups: what is and is not handled

Tested 2026-09-09 on lm1 against NSX ground truth. Every NestedExpression shape
decomposed correctly; group-to-group references did not.

| Shape | Example | Sibling built | Matches NSX |
|---|---|---|---|
| Nested AND | `Nested(Tag a AND Tag b)` | yes | yes |
| Nested ORs of ANDs | `Nested(a AND b) OR Nested(c AND d)` | yes | yes |
| Nested AND + static IPs | `Nested(a AND b) OR IPAddressExpression` | yes | yes |
| Three conditions in one nested block | `Nested(a AND b AND c)` | yes | yes |
| Nested + group-ref + static IPs | all three at once | yes | yes (9 IPs) |
| **Group reference only** | `PathExpression -> /groups/vm1` | **NO** | n/a |
| **Group reference chain** | `A -> B -> vm1` (3 levels) | **NO** | n/a |

`build_sibling_groups.py` recurses properly (`_has_condition_anywhere`,
`_collect_ips`), and because siblings are built from NSX's effective IP list
rather than by re-evaluating criteria, even the mixed shape lands exactly right.

**The gap is group-to-group references.** A group whose only expression is a
`PathExpression` at another group has no `Condition`, so it gets no sibling,
and no `IPAddressExpression`, so it misses the `pure_ip_remap` bundle too. It
lands in **no output bundle at all**. On the source it resolves fine and
transitively (a 3-level chain returned exactly the leaf group's IPs), but on a
target with no VM inventory the chain evaluates to nothing and rules using it
silently stop matching. Detection script and remediation:
[NSX_TOOLKIT_GAPS.md](../reference/NSX_TOOLKIT_GAPS.md) section 2.0c.

A group-ref **alongside** a Condition is safe: the Condition makes it eligible
and the effective-IP list already includes the referenced group's contribution.

### NSX schema limits worth knowing

| Attempted | NSX response |
|---|---|
| `NestedExpression` inside a `NestedExpression` | **rejected**: "NestedExpression is not allowed in nested expression. Allowed are Condition and ConjunctionOperator." Nesting is capped at one level |
| Tag `NOTEQUALS` on a VirtualMachine | **rejected**: "The property Tag.notequals is not supported for the member type VirtualMachine" |

So the recursive walkers can never see depth greater than one. The recursion is
correct defensive coding, not a live requirement.

---

## Failure mode: stale realized port bindings

NSX group membership counts a segment port's **realized** address bindings, not
only its **discovered** ones, so a leftover manual binding attaches an address
to every group that port's VM belongs to.

Measured on lm1 2026-09-09: **5 of 6 VM ports had realized-only bindings**, and
one stray address appeared in **14 groups**. A group whose only member VM is
`10.6.0.101` resolved to `['10.6.0.101', '10.6.1.102']`.

This is environment data, not a tool defect, and the effective-IP endpoint
remains the right source since it is what the firewall enforces. But each stale
binding is copied verbatim into a sibling and becomes a permanent literal IP on
the target. **Audit ports before Phase 3**; script in
[NSX_TOOLKIT_GAPS.md](../reference/NSX_TOOLKIT_GAPS.md) section 2.0d.

---

## Failure mode: unrealized groups

A group created moments ago has no realized membership, and the effective-IP
endpoint answers **HTTP 400** (`error_code 500141`, "Error while getting
membership ... INVALID_ARGUMENT") until the enforcement point catches up. That
window is exactly when a re-run touches a source that just gained new groups.

Verified 2026-09-09: a newly created group 400'd immediately, then resolved on
the next attempt.

`get_group_effective_ips()` retries (4 attempts, 15s apart) and then raises
rather than returning an empty list, so this cannot silently become "this group
has no IPs". If it does raise, `groups_errors` in the capture summary is
non-zero: **do not proceed**, wait for realization and re-run Phase 2a.

---

## Reference run, 2026-09-09 (nsx-lm1 to nsx-lm3)

Full rehearsal: simulate v1, add drift, upgrade to v2, verify, revert,
re-apply, re-verify.

| Stage | Result |
|---|---|
| Wipe `$TGT` | 12 rules, 3 policies, 18 groups, 3 services deleted; confirmed empty |
| v1 simulation (`--ip-source vm-vif`) | 5 siblings, 13 IPs, 2 IPs stripped, 7 rules amended |
| Drift added on `$SRC` | 1 service, 2 groups (1 tag-based, 1 pure-IP), 1 policy, 2 rules |
| v2 capture (`effective`) | 14 groups seen, `groups_changed: 7`, `ips_added_total: 18`, 0 errors |
| v2 siblings built | **7 siblings, 20 IPs**, `skipped_empty_ips: 0` |
| Dry-run pass | 4 services, 14 groups, 4 policies, 14 rules, 7 siblings, 7 stripped, all planned, 0 failures |
| v2 apply | 61 rows applied, 0 failed, IPs +11/-2, 16 rule refs added |
| **Verify** | **42 checks, 0 failed** |
| Revert | 5 siblings restored to v1 IPs, 2 v2-created siblings deleted (needed `--allow-delete`) |
| Re-apply + re-verify | **42 checks, 0 failed** |

New objects all created on the target: `avs2-new-service`,
`avs2-new-tag-group`, `avs2-new-ip-group`, `avs2-new-policy`, `avs2-rule-1/2`,
plus the sibling `avs2-new-tag-group_np_ips` with 3 IPs.

Of 14 groups: 7 got siblings, 7 had no tag Condition (pure-IP, routed to the
`pure_ip_remap` bundle). `super-nested-group` carries a `NestedExpression` and
`build_sibling_groups.py` recursed into it correctly, building the sibling
while leaving the nested structure intact in the stripped original.
