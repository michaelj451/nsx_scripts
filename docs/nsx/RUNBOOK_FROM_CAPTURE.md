# Runbook — Single-capture clone + WF-D (bash)

The "one capture, then run everything else off it" path. PowerShell
variant: [RUNBOOK_FROM_CAPTURE_PS.md](RUNBOOK_FROM_CAPTURE_PS.md).

## What this runbook does

In **one** capture command, lm1 is read fully and its data is also written
to the standalone-export paths that the WF-A and WF-D push commands
already use. After that, **no further `export` step is needed**. The push
commands run verbatim out of the existing paths, and `build_sibling_groups.py`
reads the same capture for WF-D.

Phases:

1. **Capture** lm1 (read-only) — produces capture bundle, IP report with
   CSV coverage, and flat-export bundles (`nsx_groups_export/`,
   `nsx_services_export/`, `nsx_policies_export/`, `nsx_rules_export/`)
2. **Clone structure** lm1 → target (WF-A Part 1 ONLY — services, tag groups stripped of IPs,
   policies, rules)
3. **WF-D additive** — build mapped-IP siblings, dry-run, apply (groups stay untouched)
4. **(separate change window)** Amend rules to reference siblings alongside originals — strict additive, never removes
6. **Revert** any phase via a single command per phase

**Contracts the toolkit enforces:**

- **Rules amend is strict additive.** Sibling refs are appended; existing refs are never removed; rules themselves are never deleted.
- **Groups are never deleted by any push command.** Group deletion happens only via `groups.py revert` against a baseline that captured "group did not exist." There is no other DELETE path in any push tool.

> **WF-D end state.** Tag groups on the target carry only their
> `Condition` (zero IPs); the new `*_sibling` groups carry only the
> CSV-mapped IPs (zero conditions). **No group ends up with both** —
> that's the whole point of this process. To preserve that property,
> only WF-A Part 1 is run; Parts 2 and 3 would bake IPs back into the
> tag groups and break the separation.

> **Segments are not pushed.** WF-D's `--skip-segment-groups` gives no
> sibling to a segment-based group (one with a `PathExpression` member that
> is not another group). Part 1's `--segments-mode strip`
> removes segment refs from the target's tag-group payloads. No segment
> objects are pushed.

---

## Env

```bash
setopt interactive_comments 2>/dev/null || true

python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"

# Aliases used throughout:
SRC=nsx-lm1        # the production source
DST=nsx-lm2        # the target you are pushing to (test/lab manager)
SRC_HOST=nsx-lm1.lab.local
```

---

## 1. Capture (read-only, all-in-one)

```bash
python tools/nsx/capture_nsx_state.py --source $SRC \
  --ip-report-csv data/nonprod_map.csv
```

After this single command:

| Path | Purpose |
|---|---|
| `nsx_capture/$SRC_HOST/` | Configuration bundle (`nsx_export/`, `groups_additive/`, manifest and logs); segment inventory requires `--with-segments` |
| `nsx_groups_export/$SRC_HOST/groups/` | Used by WF-A Part 1/2 group pushes |
| `nsx_services_export/$SRC_HOST/services/` | Used by WF-A services push |
| `nsx_policies_export/$SRC_HOST/security-policies/` | Used by WF-A policies push |
| `nsx_rules_export/$SRC_HOST/security-policies/` | Used by WF-A rules push (`_parent_policy_id` auto-injected) |
| `$NSX_LOG_DIR/groups_ip_report/$SRC_HOST/` | IP-coverage report — CSV match per group |

The explicit `--ip-report-csv` above opts into the IP report. Without it, review
reports are off by default. Segment inventory, VM tags and VM attribution are
also skipped unless requested. Add `--live-query` for effective IPs used by C/D.

Disable the flat-exports step if needed:

```bash
python tools/nsx/capture_nsx_state.py --source $SRC \
  --ip-report-csv data/nonprod_map.csv \
  --no-flat-exports
```

---

## 2. Review IP coverage (read-only, optional)

```bash
cat $NSX_LOG_DIR/groups_ip_report/$SRC_HOST/summary.json
cat $NSX_LOG_DIR/groups_ip_report/$SRC_HOST/empty_groups.json
```

Inspect:
- `decomposable_by_wf_c`: tag-based groups WF-C would decompose. WF-D can
  create more siblings: IP-only and group-nesting groups with a mapped IP get
  one too
- `groups_uncovered_by_csv` — groups whose IPs are not in your CSV
- `empty_groups.json` — groups with no IPs at all (no sibling produced)

---

## 3. WF-A clone → target (Part 1 only by default — see warning before doing more)

### Part 1 — services + groups (strip) + policies + rules

This is the **only WF-A step you should run when WF-D is the goal.**
It lands services, groups (Condition-only after strip), policies, and
rules on the target. Tag groups arrive with **zero IPs in their
expression** — exactly the state WF-D needs to add IP-only siblings
alongside.

```bash
python tools/nsx/services.py push --target $DST \
  --services-dir nsx_services_export/$SRC_HOST/services --apply

python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_groups_export/$SRC_HOST/groups \
  --segments-mode strip --apply

python tools/nsx/policies.py push --target $DST \
  --policies-dir nsx_policies_export/$SRC_HOST/security-policies --apply

python tools/nsx/rules.py push --target $DST \
  --rules-dir nsx_rules_export/$SRC_HOST/security-policies --apply
```

**STOP here and proceed to step 4 (WF-D build).** Do NOT run Parts 2
or 3 unless you have a specific reason — see the warning below.

### ⚠️  WARNING: Do NOT run Parts 2 or 3 when WF-D is the goal

> **The whole point of WF-D is to eliminate `Condition + IPAddressExpression`
> mixing inside groups.** Parts 2 and 3 of WF-A do the opposite: they
> bake IPs INTO the tag groups' expression on the target. After Parts
> 2+3 run, the originals carry both a `Condition` AND an
> `IPAddressExpression` — the exact mixed state WF-D is trying to
> avoid. WF-D faithfully **adds** IP-only siblings, but it does not
> (and on prod cannot) strip IPs from existing originals. The result
> is "tag-only + IP-only siblings + still-mixed originals" — not the
> clean separation you wanted.

| WF-A step | Effect on target tag groups | Compatible with WF-D's intent? |
|---|---|---|
| Part 1 (`--segments-mode strip`) | Condition only, zero IPs | ✓ this is the correct state for WF-D |
| Part 2 (`--segments-mode convert`) | `Condition + IPAddressExpression(segment-CIDRs)` | ✗ creates mixing |
| Part 3 (additive, from `groups_additive/`) | `Condition + IPAddressExpression(segment-CIDRs + VM-IPs)` | ✗ creates worse mixing |

### When you DO want Parts 2 + 3 (alternative mode — not the WF-D path)

Capture with `--live-query --with-segments` using the source credentials before
this alternative path. Segment details are no longer collected by default.

If you want the target to be a **full functional clone** of the source
(useful for some lab tests where you need rules to actually match
something without first migrating those rules to use siblings), run
Parts 2 and 3. But understand: the target's tag groups will then be
in mixed mode, and any subsequent WF-D run will produce siblings
**alongside** that mixed state — not a clean separation.

```bash
setopt interactive_comments 2>/dev/null || true

# Part 2 — segment paths → CIDRs (inside group payloads, no segment objects pushed)
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_groups_export/$SRC_HOST/groups \
  --segments-mode convert \
  --segments-from nsx_capture/$SRC_HOST/segment_inventory/segment_details.json \
  --apply

# Part 3 — additive VM IPs (from the additive bundle)
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_capture/$SRC_HOST/groups_additive/domains/default/groups \
  --segments-mode convert \
  --segments-from nsx_capture/$SRC_HOST/segment_inventory/segment_details.json \
  --apply
```

---

## 4. WF-D: build mapped-IP siblings (offline)

```bash
python tools/nsx/build_sibling_groups.py \
  --source $SRC \
  --csv-remap data/nonprod_map.csv \
  --skip-segment-groups \
  --label $SRC_HOST
```

Every group that is not segment-based and has at least one IP with a CSV
mapping gets a sibling holding only the mapped IPs: tag-based, IP-only
(no `Condition`), or nesting other groups by path. The original is never
modified, so an IP-only original keeps its IPs and is never emptied.
Hand-typed IPs are not copied into the sibling; they stay on the original,
which every rule keeps referencing.

Outputs land at:
- `nsx_sibling_groups/$SRC_HOST/groups/<id><suffix>.yaml`: IP-only
  siblings carrying the CSV-mapped IPs
- `nsx_sibling_groups/$SRC_HOST/sibling_map.json`: per-row audit
  (`ips_source`, `ips_sibling_mapped`, `ips_uncovered`), plus `no_sibling`
  listing every group without a sibling and why
- `reports/skipped_segments.json`: segment-based groups, left alone
- `reports/empty_groups.json`: groups with no IPs (no sibling, left
  untouched)

No `nsx_pure_ip_remap/` bundle is produced any more; an old one is left in
place and nothing reads it.

To label the bundle by the **target** manager instead of the source:

```bash
python tools/nsx/build_sibling_groups.py \
  --source $SRC \
  --csv-remap data/nonprod_map.csv \
  --skip-segment-groups \
  --label $DST.lab.local
```

---

## 5. WF-D — push to target

### 5a. Siblings (required for WF-D) — dry-run + apply

```bash
setopt interactive_comments 2>/dev/null || true

# Dry-run
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_sibling_groups/$SRC_HOST/groups
# Apply
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_sibling_groups/$SRC_HOST/groups --apply
```

Confirm: `additive_only_contract: "pass"`, `total_ips_removed: 0`,
`contract_violations: 0`. Baseline captured at
`nsx_sibling_groups/$SRC_HOST/push_report/baselines/`.

After step 5a, every group that qualified has its sibling with the mapped
IPs. No original group changed, segment groups included.

---

## 6. (optional, separate change window) Amend rules to reference siblings — **strict additive, never removes**

NOT part of WF-D itself. Run when CAB approves the rule-side activation:

```bash
setopt interactive_comments 2>/dev/null || true

python tools/nsx/rules.py amend-refs --target $DST \
  --sibling-map nsx_sibling_groups/$SRC_HOST/sibling_map.json
# dry-run output should look right; then:
python tools/nsx/rules.py amend-refs --target $DST \
  --sibling-map nsx_sibling_groups/$SRC_HOST/sibling_map.json --apply
```

Default behavior is **strict-additive** — appends sibling refs to
`source_groups` and `destination_groups` of every rule that references
an original. **Never removes any existing reference, never removes
any rule, never touches `scope` unless `--include-scope` is set.**

The apply adds only the siblings that exist on the target at that moment;
a missing one is skipped and listed in `amend_refs_summary.json` as
`siblings_not_on_target`. The dry run previews them all and flags the missing
ones, which is normal before step 5a has been applied.

After this step, rules continue to match via the tag groups AND also
match via the IP-only siblings — the "match anything that hits either
path" behavior. This is the recommended steady state for production.

---

## 6.5 (recommended after step 6) Validate the additive contracts

`validate_wf_d.py` is a read-only check that confirms WF-D's strict-additive
contracts held end-to-end. It compares the live target against the sibling
push baseline (the "before snapshot" captured by step 5a) and walks the
sibling_map.json from step 4 to verify rule amendments landed.

```bash
python tools/nsx/validate_wf_d.py \
  --target $DST \
  --baseline nsx_sibling_groups/$SRC_HOST/push_report/baselines/<ts>_target_baseline.json \
  --sibling-map nsx_sibling_groups/$SRC_HOST/sibling_map.json
```

the expected IP-removal findings on tag-side originals from CRITICAL to
INFO. Add `--rules-baseline <path>` to also check that no rule was deleted.

Checks run (CRITICAL fails the validation):

| Code | What it confirms |
|---|---|
| **G1** | No customer group present in the baseline was deleted. |
| **G2** | No IP present in any baseline group was removed. Absolute: nothing in the toolkit removes one. |
| **G3** | Every `Condition` and `PathExpression` in baseline groups is still present (no tag-match or segment-ref silently dropped). |
| **S1** | Every (original, sibling) pair in `sibling_map.json` exists on the target. |
| **S2** | Every sibling carries `group_type: [IPAddress]`. |
| **R1** | Every rule that references an original-with-sibling also references that sibling. (amend-refs ran completely.) |
| **R2** | (with `--rules-baseline`) Every rule in baseline is still present. |

Exit code: `0` = all checks pass; `1` = at least one CRITICAL finding.
Report at `$NSX_LOG_DIR/wf_d_validation/<target-host>/validation_report.json`.

---

## Revert

### Revert rule amendment first (if step 6 was applied)

```bash
python tools/nsx/rules.py revert --target $DST \
  --reports-dir nsx_rules_export/$DST.lab.local/push_report --apply
```

### Revert WF-D siblings (single step)

```bash
python tools/nsx/groups.py revert --target $DST \
  --reports-dir nsx_sibling_groups/$SRC_HOST/push_report --apply
```

Deletes only the siblings this WF-D run created. Originals untouched. Run it
after the rule amendment revert: NSX refuses to delete a group a rule still
references.

### Revert the WF-A clone (LIFO, reverse order)

```bash
setopt interactive_comments 2>/dev/null || true

# 1. rules
python tools/nsx/rules.py revert --target $DST \
  --reports-dir nsx_rules_export/$SRC_HOST/push_report --apply

# 2. policies
python tools/nsx/policies.py revert --target $DST \
  --reports-dir nsx_policies_export/$SRC_HOST/push_report --apply

# 3. groups Part 3 (additive)
python tools/nsx/groups.py revert --target $DST \
  --reports-dir nsx_capture/$SRC_HOST/groups_additive/domains/default/push_report --apply

# 4. groups Part 2 (pops convert baseline from same stack as Part 1)
python tools/nsx/groups.py revert --target $DST \
  --reports-dir nsx_groups_export/$SRC_HOST/push_report --apply

# 5. groups Part 1 (pops strip baseline)
python tools/nsx/groups.py revert --target $DST \
  --reports-dir nsx_groups_export/$SRC_HOST/push_report --apply

# 6. services
python tools/nsx/services.py revert --target $DST \
  --reports-dir nsx_services_export/$SRC_HOST/push_report --apply
```

---

## What this gets you for banks lab

A single capture command → drives every push command in this runbook
verbatim. No separate `groups.py export`, `services.py export`, etc.
needed. Operators paste these commands into a change ticket; the only
variable they substitute is `$DST`.

Lab-validated 2026-06-07 end-to-end on nsx-lm3:
- Capture produced all 4 flat-export bundles + IP report + segment
  inventory in 12 seconds
- WF-A Part 1 (services, groups-strip, policies, rules) — all 4 pushes
  green from the flat exports
- WF-A Part 2 (convert) + Part 3 (additive) — both green
- WF-D build → dry-run → apply — 7 siblings, 16 mapped IPs, 0 prod IPs
  leaked, 0 contract violations
- Revert chain available end-to-end

Existing runbooks ([RUNBOOK_A.md](RUNBOOK_A.md),
[RUNBOOK_D.md](RUNBOOK_D.md)) still work for the multi-export pattern if
you prefer that flow. This runbook is the single-capture optimization.
