# Run card: duplicate `nsx-lm2` onto `nsx-lm3`, then keep lm3 current from `nsx-lm1`

Two jobs, both through the driver `tools/nsx/run_workflow.py`, every step a
dry run first:

1. **Duplicate** (done 2026-10-06): Workflow A from `nsx-lm2` to `nsx-lm3`.
2. **Update** (each time lm1 changes): Workflows A then C from `nsx-lm1` to
   `nsx-lm3`.

PowerShell variant: not written yet. Lab layout of the three managers:
[LAB_TOPOLOGY.md](../reference/LAB_TOPOLOGY.md). Concepts:
[RUN_AC_LM2.md](RUN_AC_LM2.md), [RUNBOOK_A.md](RUNBOOK_A.md),
[RUNBOOK_C.md](RUNBOOK_C.md), [RUNBOOK_WORKFLOW.md](RUNBOOK_WORKFLOW.md).

## Roles

| Manager | Duplicate (part 1) | Update (part 2) |
|---|---|---|
| `nsx-lm1` | not used | **Source, read only** |
| `nsx-lm2` | **Source, read only** | Reference, compared read-only |
| `nsx-lm3` | Target | Target |

Object ids on lm3 are the same as on lm1 and lm2. That is by design: each
manager is its own namespace, and matching ids are what make later runs update
objects in place instead of duplicating them.

## Why this works: lm2 is lm1 plus A and C

Compared object by object on 2026-10-05, lm2 differs from lm1 only by what
Workflows A and C put there:

| On lm2, not on lm1 | Put there by |
|---|---|
| 16 `_np_ips` sibling groups | Workflow C |
| Sibling references in 6 rules | Workflow C (amend-refs) |
| Segment `PathExpression` removed from `seed-seg-10-6-1` and `seed-seg-mixed` | Workflow A (segment ids do not exist on another manager) |

No object exists only on lm2 and nothing on lm2 was edited by hand. So a copy
of lm2, updated later from lm1 with the same A and C, stays consistent with
how lm2 itself was built. If anyone edits lm2 directly, that stops being
true: re-run the comparison in section 5 before relying on it.

---

## 0) Env

```bash
setopt interactive_comments 2>/dev/null || true
source .venv/bin/activate
export PYTHONPATH="$PWD/app"
export NSX_LOG_DIR="$PWD/nsx_logs"
```

Each part has its own run directory, so baselines and reports never mix:
`nsx_avs_runs/nsx-lm2_to_nsx-lm3` (part 1) and
`nsx_avs_runs/nsx-lm1_to_nsx-lm3` (part 2). Define the driver as a function
(zsh does not word-split `$W`).

---

## Part 1: duplicate lm2 onto lm3

### 1.1 Preconditions

- lm3's fabric is built ([LAB_TOPOLOGY.md](../reference/LAB_TOPOLOGY.md)
  section 4).
- lm3 holds no customer DFW objects. On 2026-10-05 it was wiped with
  `tools/test/wipe_target_manager.py` ([RUNBOOK_WIPE.md](../tools/test/RUNBOOK_WIPE.md));
  pre-wipe backup `nsx_backup/nsx-lm3.lab.local/20261005_190125`.
- lm1 had 24 orphan `_avs_ips` groups left by Workflow D. lm2 never had them,
  so they do not affect part 1, but part 2 would copy them to lm3. They were
  deleted from lm1 on 2026-10-06 (section 6).

### 1.2 Capture lm2 and back up lm3 (read-only)

```bash
S=nsx-lm2; T=nsx-lm3; SH=nsx-lm2.lab.local; TH=nsx-lm3.lab.local
R=nsx_avs_runs/${S}_to_${T}; mkdir -p $R
wf() { python tools/nsx/run_workflow.py --source $S --target $T --run-dir $R "$@"; }

python tools/nsx/capture_nsx_state.py --source $S --live-query
python -c "
import json
m = json.load(open('nsx_capture/$SH/groups_additive/domains/default/groups/manifest.json'))
print({k: m.get(k) for k in ('ip_source','effective_ip_queries','groups_seen','groups_errors')})"
python tools/nsx/backup_nsx_state.py --source $T --retain 14
```

Gate: `ip_source` is `effective`, `effective_ip_queries` equals
`groups_seen`, `groups_errors` is 0. The driver refuses a capture without
`--live-query`.

The capture writes lm2's live member IPs into its own working tree. On
2026-10-06 it added 39 IPs to 11 groups there (lm2's 10.7.x VMs and
others), but **none of them reached lm3**: the pushed groups carry exactly
the IPs lm2's groups define (section 5 proved it field by field). Re-check
this on any future run before assuming it.

The capture keeps the `push_report/baselines/` folders under
`nsx_*_export/nsx-lm2.lab.local/`; only the data subfolders are replaced.

### 1.3 Workflow A

```bash
wf --phase a                                   # dry run
cat $R/report/a/dryrun/avs_run_report.md
```

| Check | Requirement |
|---|---|
| `Failed` | 0 |
| Class counts | match lm2 |
| IP deltas | additions only |
| "group references removed" block | absent |

```bash
wf --phase a --apply
wf --phase a --verify
```

The apply is interactive: one object first, then a pause before each batch
(Enter continues, a number sets the batch size, `n` resets to one, `x`
stops). Each answer is logged as an operator decision, so the operator runs
it, not an agent.

### 1.4 Result, 2026-10-06

| Step | Result |
|---|---|
| Dry run | 92 would be created (10 services, 48 groups, 5 policies, 29 rules), 0 failed, no removals |
| Apply | 92 created, 0 failed |
| Verify | V1 object parity OK (48 groups, 10 services, 5 policies, all rules); V6 every group resolves |
| Section 5 comparison | lm3 identical to lm2: services 10, policies 7, rules 31, groups 48 including the 16 siblings, 29 sibling references in rules |

The 16 siblings on lm3 are copies of lm2's, holding the IP lists Workflow C
built from lm1 on 2026-10-02. Nothing on lm3 recalculated them; part 2 does.

---

## Part 2: keep lm3 current from lm1

Repeat each time lm1 changes. Dry run first every time.

```bash
S=nsx-lm1; T=nsx-lm3; SH=nsx-lm1.lab.local; TH=nsx-lm3.lab.local
R=nsx_avs_runs/${S}_to_${T}; mkdir -p $R
wf() { python tools/nsx/run_workflow.py --source $S --target $T --run-dir $R "$@"; }

python tools/nsx/capture_nsx_state.py --source $S --live-query   # same gate as 1.2
python tools/nsx/backup_nsx_state.py --source $T --retain 14

wf --phase a                                   # dry run, review as in 1.3
wf --phase a --apply
wf --phase a --verify

wf --phase c                                   # dry run AFTER the A apply
cat $R/report/c/dryrun/avs_run_report.md
grep -E "files seen|siblings written|skipped: empty IPs|errors  " \
  $(ls -t $NSX_LOG_DIR/build_sibling_groups_*.log | head -1) | sed 's/.*__main__: //'
cat $R/nsx_sibling_groups/$SH/reports/empty_groups.json
wf --phase c --apply
wf --phase c --verify
```

C review gate: `appendix` is `_np_ips` (the same as the siblings already on
lm3; any other value creates a second sibling set), every group in
`empty_groups.json` is explained, and the refs added match the rules.

**Run the C dry run after the A apply.** Before A is on lm3 the target has
no rules, so amend-refs shows `refs +0` and warns that the siblings are
missing, which tells you nothing.

What re-runs do to lm3, by contract:

- Groups are pushed as the union of source and target IPs. **An IP on lm3 is
  never removed**, including one that has left lm1. Removing it is a manual
  change on lm3.
- A rules push keeps group references that exist only on the target, so A
  does not strip the sibling references C added (or that came from lm2).
- C rebuilds siblings from lm1's current membership and updates the existing
  `_np_ips` groups in place.
- Unchanged objects are skipped. Known exception (open, not yet in
  NSX_TOOLKIT_GAPS): C re-sends identical sibling groups every run because
  the built payload never matches the stored object exactly (timestamped
  description, NSX-assigned expression ids). Shows as changed rows with no IP
  delta.
- Every apply writes a rollback baseline, including an apply that sent
  nothing (open, not yet in NSX_TOOLKIT_GAPS). That newer baseline shadows
  the real one, so a default rollback after a no-op re-run undoes nothing.
  Name the right one with `--from-baseline <ts>`.

The lm1 capture at `nsx_capture/nsx-lm1.lab.local` is shared with the lm2
run. A fresh capture means a later `--verify` of the lm1-to-lm2 run compares
lm2 against today's lm1, not the capture lm2 was built from.

### Dry run against lm3 before the duplicate, for reference

Taken 2026-10-06 against an empty lm3, after the `_avs_ips` cleanup:
A 76 would be created (10 services, 32 groups, 5 policies, 29 rules), 0
failed; C 14 siblings, 35 IPs, 0 errors (32 groups seen, 3 empty:
`network-group-8`, `seed-tag-net-10-8-0`, `seed-tag-nomatch`). Now that lm3
holds lm2's copy, expect mostly unchanged rows instead of creates.

The two 10.8 groups are empty on lm1 because their VMs moved to lm3 on
2026-10-03. lm2's copies of their siblings (`network-group-8_np_ips`,
`seed-tag-net-10-8-0_np_ips`) are on lm3 and, by the union rule, stay as they
are. On lm3 the tag groups themselves can match those VMs only if the VMs
carry the tags there.

---

## 5) Compare lm3 with lm2 (read-only)

Field by field, ignoring NSX metadata and the order of reference lists
(group criteria order is kept, since it changes meaning). Expected after part 1:
no differences. After part 2, differences are lm1 changes: review them.

```bash
python - <<'PY'
import json, sys; sys.path.insert(0, "app")
from nsx.cli_bootstrap import init_cli; init_cli()
from nsx.nsx_policy_client import NsxPolicyClient
D = "/policy/api/v1/infra/domains/default"
SKIP = {"_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
        "_revision", "_protection", "_system_owned", "realization_id", "unique_id",
        "rule_id", "path", "parent_path", "relative_path", "_links", "_self", "_schema",
        "marked_for_delete", "overridden", "owner_id", "origin_site_id", "remote_path"}
EXPR = {"Condition", "IPAddressExpression", "ConjunctionOperator", "NestedExpression",
        "PathExpression", "ExternalIDExpression", "MACAddressExpression"}
def norm(o):
    if isinstance(o, dict):
        return {k: norm(v) for k, v in o.items()
                if k not in SKIP and not (k == "id" and o.get("resource_type") in EXPR)}
    if isinstance(o, list):   # sort plain-string lists (group refs, services); keep criteria order
        return sorted(o) if all(isinstance(x, str) for x in o) else [norm(x) for x in o]
    return o
def pull(h):
    c = NsxPolicyClient(nsxmanager=h)
    out = {"services": {x["id"]: norm(x) for x in c._get("/policy/api/v1/infra/services").get("results", []) if not x.get("_system_owned")},
           "groups": {x["id"]: norm(x) for x in c._get(D + "/groups").get("results", []) if not x.get("_system_owned")},
           "policies": {}, "rules": {}}
    for p in c._get(D + "/security-policies").get("results", []):
        out["policies"][p["id"]] = norm(p)
        for r in c._get(f"{D}/security-policies/{p['id']}/rules").get("results", []):
            out["rules"][f"{p['id']}/{r['id']}"] = norm(r)
    return out
a, b = pull("nsx-lm2.lab.local"), pull("nsx-lm3.lab.local")
for k in a:
    diff = sorted(i for i in set(a[k]) & set(b[k])
                  if json.dumps(a[k][i], sort_keys=True) != json.dumps(b[k][i], sort_keys=True))
    print(f"{k:9} lm2 {len(a[k]):3}  lm3 {len(b[k]):3}  lm2-only {sorted(set(a[k]) - set(b[k]))}"
          f"  lm3-only {sorted(set(b[k]) - set(a[k]))}  differ {diff}")
PY
```

## 6) Record: `_avs_ips` cleanup on lm1 (2026-10-06)

lm1 carried 24 `_avs_ips` groups from Workflow D, created 2026-10-02 after
lm2's build. No rule, policy or other group referenced them, and each held
only IP addresses. Workflow D's rollback could not be used from the Mac (its
baselines are on nsx-ws1), so they were deleted directly after a live
reference re-check. Record: `nsx_logs/delete_avs_ips_apply_20261006_001230.log`.
Restore point: `nsx_backup/nsx-lm1.lab.local/20261006_000737` (push the 24
group files back with `groups.py push`, dry run first). lm1 went from 56 to
32 groups. Workflow D state on nsx-ws1 is now stale; re-running D on lm1
recreates the groups, and the next part 2 run would copy them to lm3.

## 7) Rollback

Preview each one and read its report before `--apply`. One rollback undoes
one apply.

```bash
# Part 2 (lm1 -> lm3): C first, then A
S=nsx-lm1; R=nsx_avs_runs/nsx-lm1_to_nsx-lm3
wf --phase c --rollback;  wf --phase c --rollback --apply
wf --phase a --rollback;  wf --phase a --rollback --apply

# Part 1 (lm2 -> lm3): A only
S=nsx-lm2; R=nsx_avs_runs/nsx-lm2_to_nsx-lm3
wf --phase a --rollback;  wf --phase a --rollback --apply
```

Redefine `wf` after changing `S` and `R`, or it keeps the old values. To
return lm3 to empty instead, wipe it as in 1.1.
