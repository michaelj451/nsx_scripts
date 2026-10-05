# Multivendor rollout: nsx-lm1 to nsx-lm2 or nsx-lm3, through Palo Alto dg-5

VMs leave `nsx-lm1` one at a time for **either** `nsx-lm2` or `nsx-lm3`, and
traffic must keep flowing between all three sites and through the Palo Alto
device group `dg-5` that sits between them. This runbook breaks that into
separate steps. Each step is its own dry run, apply, verify and rollback, and
none depends on code beyond the existing, tested workflow driver
(`tools/nsx/run_workflow.py`). The Palo Alto work is a separate track at the end.

PowerShell variant: [RUNBOOK_MULTIVENDOR_ROLLOUT_PS.md](RUNBOOK_MULTIVENDOR_ROLLOUT_PS.md).
Background: [RUNBOOK_WORKFLOW.md](../nsx/RUNBOOK_WORKFLOW.md) (the driver),
[RUN_AC_LM2.md](../nsx/RUN_AC_LM2.md) (A and C onto lm2),
[RUN_D_LM1.md](../nsx/RUN_D_LM1.md) (D on lm1). Design and reasoning:
the "Three-Site Migration Design" note.

## Sites and roles

| Manager | Role | Address space (lab) |
|---|---|---|
| `nsx-lm1` | Source. Read only for steps 1 to 3; steps 4 and 5 add siblings to it | 10.6.0.0/16 |
| `nsx-lm2` | Target site 2 (AVS) | 10.7.0.0/16 |
| `nsx-lm3` | Target site 3 (new site) | 10.8.0.0/16 |
| Panorama `pano4`, device group `dg-5` | Firewall between the managers | |

## The idea in one table

A tag-based group only matches VMs on its own manager. Once a VM moves, the
rules elsewhere must still match it by address, so every manager holds the
addresses of the other two sites as IP-only **sibling** groups. The sibling
suffix names whose addresses it holds.

| Step | Adds to | Whose addresses | Suffix | Map | Run dir (under `$B`) |
|---|---|---|---|---|---|
| 2 | `nsx-lm3` | policy clone (Workflow A) | | | `nsx-lm3_A` |
| 3 | `nsx-lm3` | lm1, unmapped (Workflow C) | `_np_ips` | | `nsx-lm3_np_ips` |
| 4 | `nsx-lm1` | lm2 (mapped) | `_avs_ips` | `subnet_map_lm2.csv` | `nsx-lm1_avs_ips` |
| 5 | `nsx-lm1` | lm3 (mapped) | `_lm3_ips` | `subnet_map_lm3.csv` | `nsx-lm1_lm3_ips` |
| 6a | `nsx-lm2` | lm3 (mapped) | `_lm3_ips` | `subnet_map_lm3.csv` | `nsx-lm2_lm3_ips` |
| 6b | `nsx-lm3` | lm2 (mapped) | `_avs_ips` | `subnet_map_lm2.csv` | `nsx-lm3_avs_ips` |

A and C onto `nsx-lm2` (lm2 holding lm1's addresses) are already covered by
[RUN_AC_LM2.md](../nsx/RUN_AC_LM2.md); run that card first if lm2 is empty.
Step 6 is needed **only if lm2 and lm3 workloads must talk to each other**.

Every step has its own run directory, so no two steps share a sibling bundle or
a revert baseline. Never point two steps at one run directory.

## Before you start

- **One map per target**, both two-column files the existing tools read as is:
  - `data/subnet_map_lm2.csv`: `nonprod_map.csv` without its 10.8 rows (10.8 is
    lm3's own space now, and those rows held a known collision).
    `nonprod_map.csv` itself is unchanged for the two-site runs.
  - `data/subnet_map_lm3.csv`: 10.6 to 10.8, 10.4 to 10.24, 10.5 to 10.25,
    10.10 to 10.30, 10.21 to 10.41, 10.250 to 10.252.
- **Known and accepted (lab):** lm3 already runs six VMs at `.101`/`.102` on
  10.8.0, 10.8.1 and 10.8.2. The lm3 map keeps the host part, so 6 of lm1's 8
  VMs map onto those addresses. Those lm3 VMs are treated as placeholders. On a
  real site this would hand a moved VM's rules to a different machine.
- **Addresses at the site a VM did not go to stay reserved.** Siblings are
  additive only, so a VM's lm3 address stays in every rule even if it moved to
  lm2. Do not give mapped addresses to unrelated machines until the migration ends.
- lm1 groups that still hold 10.8 addresses (left over from before the 10.8 VMs
  moved to lm3) show those addresses as **unmapped** in steps 4 to 6. Expected.
- Every VM has `hostname` and `asl_id` NSX tags (needed by the Palo track).

---

## 0) Env and map check

```bash
setopt interactive_comments 2>/dev/null || true
source .venv/bin/activate
export PYTHONPATH="$PWD/app"
export NSX_LOG_DIR="$PWD/nsx_logs"

S=nsx-lm1
SH=nsx-lm1.lab.local
MAP2=data/subnet_map_lm2.csv
MAP3=data/subnet_map_lm3.csv
B=nsx_avs_runs/rollout
mkdir -p $B

# Each map must report "Map OK" (exit 0). A collision exits 2 and names the rows.
python tools/multisite/plan_multisite.py --map $MAP2 --check-map-only
python tools/multisite/plan_multisite.py --map $MAP3 --check-map-only
```

One driver function per step, with that step's target, run dir, suffix and
map filled in. Use functions, not variables (zsh does not word-split a variable).

```bash
step2()  { python tools/nsx/run_workflow.py --source $S --target nsx-lm3 --run-dir $B/nsx-lm3_A "$@"; }
step3()  { python tools/nsx/run_workflow.py --source $S --target nsx-lm3 --run-dir $B/nsx-lm3_np_ips "$@"; }
step4()  { python tools/nsx/run_workflow.py --source $S --target nsx-lm1 --run-dir $B/nsx-lm1_avs_ips --appendix _avs_ips --csv-remap $MAP2 "$@"; }
step5()  { python tools/nsx/run_workflow.py --source $S --target nsx-lm1 --run-dir $B/nsx-lm1_lm3_ips --appendix _lm3_ips --csv-remap $MAP3 "$@"; }
step6a() { python tools/nsx/run_workflow.py --source $S --target nsx-lm2 --run-dir $B/nsx-lm2_lm3_ips --appendix _lm3_ips --csv-remap $MAP3 "$@"; }
step6b() { python tools/nsx/run_workflow.py --source $S --target nsx-lm3 --run-dir $B/nsx-lm3_avs_ips --appendix _avs_ips --csv-remap $MAP2 "$@"; }
```

Every command below is a dry run unless it says `--apply`. Read each report
before its apply.

---

## 1) Capture lm1 (read only), then back up lm3

With `.env` holding **lm1** credentials (`unset NSX_USERNAME NSX_PASSWORD` if
your shell overrides them):

```bash
python tools/nsx/capture_nsx_state.py --source $S --live-query
cat "nsx_capture/$SH/groups_additive/domains/default/groups/manifest.json"
```

Check the same five fields as [RUN_AC_LM2.md section 1](../nsx/RUN_AC_LM2.md):
`ip_source` is `effective`, `effective_ip_queries` equals `groups_seen`,
`groups_errors` is `0`. `--live-query` is mandatory: without it every tag-only
group looks empty and nothing errors.

Then switch `.env` to **lm3** credentials and back lm3 up:

```bash
python tools/nsx/backup_nsx_state.py --source nsx-lm3 --retain 14
cat "nsx_backup/nsx-lm3.lab.local/latest/summary.txt"
```

---

## 2) Workflow A: clone lm1's policy onto lm3

Creates services, groups (segment references stripped), policies and rules on
lm3. Nothing on lm1 changes.

```bash
step2 --phase a                     # dry run: read report/a/dryrun
step2 --phase a --apply
step2 --phase a --verify
```

- lm3 still carries an older test copy (12 groups, 3 services, a few test
  policies). The dry run shows any ID clash with lm1's objects; resolve it
  before applying.
- **Rollback caveat.** Workflow A keeps its undo baselines under the *source*
  host's folders (`nsx_*_export/nsx-lm1.lab.local/push_report`), shared with A
  onto lm2. Each rollback refuses another manager's baseline, which is safe, but
  after this step a default A rollback **on lm2** is refused: name its baseline
  with `--from-baseline`.

Rollback: `step2 --phase a --rollback` (preview), then add `--apply`.

---

## 3) Workflow C: lm1's addresses onto lm3

Adds one `_np_ips` sibling per tag-based group, holding the source addresses,
and makes lm3's rules reference original **and** sibling. Builds from the
step 1 capture; contacts only lm3.

```bash
step3 --phase c                     # dry run: read report/c/dryrun
step3 --phase c --apply
step3 --phase c --verify
```

Rollback: `step3 --phase c --rollback`, then add `--apply` (rule references
first, then the siblings).

---

## 4) lm2's addresses onto lm1

So lm1 VMs keep reaching VMs that moved to lm2. Same mechanism as
[RUN_D_LM1.md](../nsx/RUN_D_LM1.md), with the clean lm2 map. If lm1 already
carries `_avs_ips` siblings from a two-site run, this step adds to them (union);
it never removes an address. Two separate change windows. Switch `.env` to
**lm1** credentials; source and target are the same manager.

Window 4a, siblings (changes nothing that enforces traffic):

```bash
step4 --phase d2a                   # dry run: re-captures lm1 into its run dir
step4 --phase d2a --apply
```

Window 4b, rules start using them:

```bash
step4 --phase d3
step4 --phase d3 --apply
step4 --phase d3 --verify
```

- A `--verify` right after 4a reports missing rule references as CRITICAL until
  4b runs (pending item #10). Verify after 4b.
- An apply that sends nothing still writes a newer baseline (pending item #11).
  If you re-ran an apply, roll back with `--from-baseline <the real one>`.

Rollback, reverse order: `step4 --phase d3 --rollback --apply`, then
`step4 --phase d2a --rollback --apply` (preview each without `--apply` first).

---

## 5) lm3's addresses onto lm1

So lm1 VMs reach VMs that moved to lm3. Identical to step 4 with the lm3 map
and the `_lm3_ips` suffix. lm1 credentials.

```bash
step5 --phase d2a
step5 --phase d2a --apply
step5 --phase d3
step5 --phase d3 --apply
step5 --phase d3 --verify
```

Rollback: `step5 --phase d3 --rollback --apply`, then
`step5 --phase d2a --rollback --apply`.

---

## 6) Only if lm2 and lm3 must talk: each other's addresses

Here the target is **not** the source, and `.env` holds one credential set at a
time, so capture lm1 by hand first (lm1 credentials), then switch to the
target's credentials and tell the driver to reuse that capture.

### 6a: lm3's addresses onto lm2

```bash
rm -rf "$B/nsx-lm2_lm3_ips/capture/$SH"
python tools/nsx/capture_nsx_state.py --source $S --live-query \
  --output-dir "$B/nsx-lm2_lm3_ips/capture/$SH" --no-flat-exports
# switch .env to lm2 credentials
step6a --phase d2a --no-capture
step6a --phase d2a --apply
step6a --phase d3
step6a --phase d3 --apply
step6a --phase d3 --verify
```

lm2 must already have lm1's policy (A onto lm2) for 6a's rule step to find
anything to amend.

### 6b: lm2's addresses onto lm3

```bash
rm -rf "$B/nsx-lm3_avs_ips/capture/$SH"
python tools/nsx/capture_nsx_state.py --source $S --live-query \
  --output-dir "$B/nsx-lm3_avs_ips/capture/$SH" --no-flat-exports
# switch .env to lm3 credentials
step6b --phase d2a --no-capture
step6b --phase d2a --apply
step6b --phase d3
step6b --phase d3 --apply
step6b --phase d3 --verify
```

Rollback for either: `--phase d3 --rollback --apply`, then
`--phase d2a --rollback --apply`, with the target's credentials.

---

## Before each migration wave

Siblings come from a capture of lm1. As VMs change, re-run the `d2a` dry run
and apply for steps 4 to 6 from a fresh capture before the wave. Pushes are
additive, so addresses from earlier waves are kept. lm1 stays the system of
record for groups and tags until the migration ends; workloads created new on
lm2 or lm3 are not in anyone's siblings.

## Full rollback order

Newest first: 6b, 6a, 5, 4, 3, 2. Within a D step, `d3` before `d2a`; within C,
the driver handles the order.

---

## Palo Alto track (separate)

Run on its own, never mixed into an NSX step. Palo objects mirror NSX
exactly: VM objects named by hostname with the VM's NSX tags, address objects
named by the address, dynamic groups for tag groups, static groups for address
and nested groups. Mapping table: [STATUS.md](STATUS.md).

```bash
# P1 plan: reads NSX only. Drop --groups to mirror every non-system group.
python tools/pan/nsx_pan_mirror.py plan --source nsx-lm1 \
  --groups seed-tag-net-10-6-0,ip-address-group,seed-nested-web
P=pan_mirror_runs/nsx-lm1.lab.local/latest
cat $P/plan.md

# P2 push: dry run (reads Panorama only), then apply to CANDIDATE config.
# REST API only. Logs in as agent_user from .env. Never commits; you review and commit.
# --no-tls-verify: pano4 presents the PAN-OS default self-signed certificate.
python tools/pan/nsx_pan_mirror.py push --plan $P/plan.json --no-tls-verify
python tools/pan/nsx_pan_mirror.py push --plan $P/plan.json --no-tls-verify --apply

# Undo exactly what that apply created (dry run, then --apply)
python tools/pan/nsx_pan_mirror.py revert --manifest $P/push_<ts>_apply.json --no-tls-verify
python tools/pan/nsx_pan_mirror.py revert --manifest $P/push_<ts>_apply.json --no-tls-verify --apply
```

A plan with errors (for example a VM without a hostname tag) is refused by
`push` unless you pass `--allow-plan-errors`. **Status: P1 and P2 working;
first live push 2026-10-05 created 24 objects in dg-5, all read back exactly.**

| Piece | What it does | Status |
|---|---|---|
| P1 Object plan | Exact mirror of NSX groups, VMs and tags (`nsx_pan_mirror.py plan`). Read only. | built |
| P2 Push to `pano4` dg-5 | Candidate configuration only (never commits), creates only missing objects, revert removes only what it created. You commit. | working (first live test 2026-10-05) |
| P3 Rules | dg-5 rules that reference the dynamic groups | not built |

Prerequisite: every VM carries an NSX `hostname` tag (no fallback to the VM name).
