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
5. **(optional, FORCED separate change window)** Phase 2 — move IPs from originals to siblings via `--intentional-ip-removal`
6. **Revert** any phase via a single command per phase

**Contracts the toolkit enforces:**

- **Rules amend is strict additive.** Sibling refs are appended; existing refs are never removed; rules themselves are never deleted.
- **Groups are never deleted by any push command.** Group deletion happens only via `groups.py revert` against a baseline that captured "group did not exist." There is no other DELETE path in any push tool.
- **IP removal from group payloads requires `--intentional-ip-removal`.** The strict-additive contract rejects any row that would remove an IP. The flag is the explicit force gate.

> **WF-D end state.** Tag groups on the target carry only their
> `Condition` (zero IPs); the new `*_sibling` groups carry only the
> CSV-mapped IPs (zero conditions). **No group ends up with both** —
> that's the whole point of this process. To preserve that property,
> only WF-A Part 1 is run; Parts 2 and 3 would bake IPs back into the
> tag groups and break the separation.

> **Segments are not pushed.** WF-D's `--skip-segment-groups` skips any
> group that has a `PathExpression`. Part 1's `--segments-mode strip`
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
| `nsx_capture/$SRC_HOST/` | Full capture bundle (`nsx_export/`, `groups_additive/`, `segment_inventory/`, etc.) |
| `nsx_groups_export/$SRC_HOST/groups/` | Used by WF-A Part 1/2 group pushes |
| `nsx_services_export/$SRC_HOST/services/` | Used by WF-A services push |
| `nsx_policies_export/$SRC_HOST/security-policies/` | Used by WF-A policies push |
| `nsx_rules_export/$SRC_HOST/security-policies/` | Used by WF-A rules push (`_parent_policy_id` auto-injected) |
| `$NSX_LOG_DIR/groups_ip_report/$SRC_HOST/` | IP-coverage report — CSV match per group |

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
- `decomposable_by_wf_c` — number of siblings WF-D will create
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

## 4. WF-D — build mapped-IP siblings + pure-IP remap bundle (offline)

```bash
python tools/nsx/build_sibling_groups.py \
  --source $SRC \
  --csv-remap data/nonprod_map.csv \
  --skip-segment-groups \
  --no-stripped-originals \
  --label $SRC_HOST
```

> **Note: `--include-pure-ip` is deprecated.** Pure-IP groups (no
> `Condition`) are NEVER decomposed into siblings any more. Doing so
> would empty the original group after a Phase-2 strip, which violates
> the "no empty groups" contract. Instead, the build now writes pure-IP
> groups to a separate `nsx_pure_ip_remap/<host>/groups/` bundle, ready
> for `groups.py push --csv-remap` which adds the mapped IPs in place
> (strict-additive).

Outputs land at:
- `nsx_sibling_groups/$SRC_HOST/groups/<id>_sibling.yaml` — IP-only
  siblings for **tag-based mixed groups only** (Condition + IPs).
  Carries CSV-mapped IPs.
- `nsx_sibling_groups/$SRC_HOST/sibling_map.json` — per-row audit
  (`ips_source`, `ips_sibling_mapped`, `ips_uncovered`)
- `nsx_pure_ip_remap/$SRC_HOST/groups/<id>.yaml` — **NEW** — pure-IP
  groups, ready for in-place CSV-remap push (step 5b)
- `nsx_pure_ip_remap/$SRC_HOST/manifest.json` — per-group audit
- `reports/skipped_segments.json` — segment-related groups left alone
- `reports/empty_groups.json` — groups with no IPs (no sibling, no
  remap entry — left untouched)

To label the bundle by the **target** manager instead of the source:

```bash
python tools/nsx/build_sibling_groups.py \
  --source $SRC \
  --csv-remap data/nonprod_map.csv \
  --skip-segment-groups --no-stripped-originals \
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

### 5b. Pure-IP remap (**OPTIONAL** — separate change window)

> This step is **optional**. Skip it if you don't want mapped IPs added
> to your pure-IP groups on the target right now — the bundle on disk
> is harmless if unused. The step is meant to be its own change window
> so it can be staged separately from the sibling push.

When to **run** 5b:

- Your CSV covers IPs that appear in pure-IP groups (e.g.,
  `ip-address-group` has `10.6.0.50` which the CSV maps to `10.7.0.50`)
- You want rules referencing pure-IP groups to match the non-prod IP
  range too
- You want all WF-D scope changes in a single window

When to **skip** 5b:

- Your CSV doesn't cover any IPs in your pure-IP groups (5b would be
  a no-op anyway)
- You want a phased rollout: land siblings first, validate, run 5b
  later in its own change window
- The non-prod target's rules don't need to match against mapped IPs

Pushes the source's pure-IP groups (like `ip-address-group`,
`hardware-subnet`) back to the target with `--csv-remap`. **Strict
additive**: mapped IPs added alongside existing IPs; nothing removed.

```bash
setopt interactive_comments 2>/dev/null || true

# Dry-run
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_pure_ip_remap/$SRC_HOST/groups \
  --csv-remap data/nonprod_map.csv
# Apply
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_pure_ip_remap/$SRC_HOST/groups \
  --csv-remap data/nonprod_map.csv --apply
```

Confirm: `additive_only_contract: "pass"`, `total_ips_removed: 0`,
`csv_groups_changed > 0`. Baseline at
`nsx_pure_ip_remap/$SRC_HOST/push_report/baselines/`.

### Summary of post-push states

| After step 5a only | After step 5a + 5b |
|---|---|
| Siblings created with mapped IPs | Siblings created with mapped IPs |
| Pure-IP groups: original IPs only | Pure-IP groups: original IPs + mapped IPs |
| Segment groups: untouched | Segment groups: untouched |

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

Add `--phase-2-applied` after step 7 has run, so the validator downgrades
the expected IP-removal findings on tag-side originals from CRITICAL to
INFO. Add `--rules-baseline <path>` to also check that no rule was deleted.

Checks run (CRITICAL fails the validation):

| Code | What it confirms |
|---|---|
| **G1** | No customer group present in the baseline was deleted. |
| **G2** | No IP present in any baseline group was removed (or, with `--phase-2-applied`, only tag-side originals had IPs removed and the corresponding sibling holds the mapped values). |
| **G3** | Every `Condition` and `PathExpression` in baseline groups is still present (no tag-match or segment-ref silently dropped). |
| **S1** | Every (original, sibling) pair in `sibling_map.json` exists on the target. |
| **S2** | Every sibling carries `group_type: [IPAddress]`. |
| **R1** | Every rule that references an original-with-sibling also references that sibling. (amend-refs ran completely.) |
| **R2** | (with `--rules-baseline`) Every rule in baseline is still present. |

Exit code: `0` = all checks pass; `1` = at least one CRITICAL finding.
Report at `$NSX_LOG_DIR/wf_d_validation/<target-host>/validation_report.json`.

---

## 7. (optional, FORCED, separate change window) Phase 2 — move IPs from originals to siblings

> ⚠️  **This is the only flow in the toolkit that REMOVES IPs from
> existing groups.** It is gated behind an explicit `--intentional-ip-removal`
> force flag. The strict-additive contract is **deliberately overridden**
> for this one push. Use only when:
>
> 1. WF-D additive (steps 4–5) has been applied and validated
> 2. amend-refs (step 6) has been applied and rules are matching via siblings
> 3. You have CAB approval to strip IPs from the tag-side originals so that
>    enforcement migrates fully to the sibling groups
>
> **Groups are never deleted by this step.** Only `IPAddressExpression`
> entries inside existing group payloads are removed. The groups
> themselves stay (Condition-only after the strip). To delete a group,
> use `groups.py revert` against a baseline that captured "group did
> not exist" — that is the **only** path the toolkit offers to delete
> a group.

### 7a. Rebuild the bundle WITH stripped originals

The default WF-D build uses `--no-stripped-originals` to suppress the
strip bundle. For Phase 2, rebuild **without** that flag so
`nsx_stripped_groups/<host>/groups/` is produced:

```bash
setopt interactive_comments 2>/dev/null || true

python tools/nsx/build_sibling_groups.py \
  --source $SRC \
  --csv-remap data/nonprod_map.csv \
  --include-pure-ip \
  --skip-segment-groups \
  --label $SRC_HOST
  # NOTE: --no-stripped-originals deliberately OMITTED so the stripped
  # bundle is produced alongside the sibling bundle.
```

### 7b. Push the stripped originals — REQUIRES `--intentional-ip-removal`

```bash
setopt interactive_comments 2>/dev/null || true

# DRY RUN first — confirm the per-row IP-removal counts look right
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_stripped_groups/$SRC_HOST/groups \
  --intentional-ip-removal

# Then apply
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_stripped_groups/$SRC_HOST/groups \
  --intentional-ip-removal \
  --apply
```

Without `--intentional-ip-removal`, every row would be rejected as a
`contract_violation` — that is the strict-additive contract refusing
the push. The flag must be passed explicitly to override it.

### 7c. Net effect

| Object | Before Phase 2 | After Phase 2 |
|---|---|---|
| Tag-side original (`vm1`) | `Condition + IPAddressExpression([10.6.0.101, ...])` (mixed if Parts 2+3 had run, or already Condition-only from Part 1) | `Condition` only — IPs removed |
| Sibling (`vm1_sibling`) | `IPAddressExpression([10.7.0.101, ...])` (mapped IPs) | unchanged — still holds mapped IPs |
| Rules referencing `vm1` | match via tag + (optionally via sibling if amend-refs ran) | match via tag (members empty if no realized) + sibling IPs |
| Group `vm1` itself | exists | **still exists** — only its IP entries were stripped |

### 7d. Revert Phase 2 — single command

```bash
python tools/nsx/groups.py revert --target $DST \
  --reports-dir nsx_stripped_groups/$SRC_HOST/push_report --apply
```

Restores the pre-Phase-2 IP content to the originals.

---

## Revert

### Revert WF-D siblings (single step)

```bash
python tools/nsx/groups.py revert --target $DST \
  --reports-dir nsx_sibling_groups/$SRC_HOST/push_report --apply
```

Deletes only the siblings this WF-D run created. Originals untouched.

### Revert rule amendment (if step 6 was applied)

```bash
python tools/nsx/rules.py revert --target $DST \
  --reports-dir nsx_rules_export/$DST.lab.local/push_report --apply
```

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
