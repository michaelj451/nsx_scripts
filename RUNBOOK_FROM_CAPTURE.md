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
2. **Clone** lm1 → target (WF-A Parts 1+2+3) using the flat exports
3. **WF-D** — build mapped-IP siblings, dry-run, apply
4. **Revert** if needed — single command deletes the siblings

> **Segments are not pushed.** WF-D's `--skip-segment-groups` skips any
> group that has a `PathExpression`. WF-A Part 2's `--segments-mode
> convert` materializes segment paths into CIDRs *inside* the group
> payloads on the target — no segment objects are pushed.

---

## Env

```bash
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

## 3. WF-A clone → target (Parts 1 + 2 + 3)

### Part 1 — services + groups (strip) + policies + rules

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

### Part 2 — segment paths → CIDRs (inside group payloads, no segment objects pushed)

```bash
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_groups_export/$SRC_HOST/groups \
  --segments-mode convert \
  --segments-from nsx_capture/$SRC_HOST/segment_inventory/segment_details.json \
  --apply
```

### Part 3 — additive VM IPs (from the additive bundle)

```bash
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_capture/$SRC_HOST/groups_additive/domains/default/groups \
  --segments-mode convert \
  --segments-from nsx_capture/$SRC_HOST/segment_inventory/segment_details.json \
  --apply
```

After this, the target should mirror the source's mixed (`Condition + IPAddressExpression`) state.

### Skip Part 2 + Part 3 if you don't want a full clone

If you only want WF-D mapped siblings (no IP materialization on the
target's tag groups), run Part 1 only and proceed to step 4.

---

## 4. WF-D — build mapped-IP siblings (offline)

```bash
python tools/nsx/build_sibling_groups.py \
  --source $SRC \
  --csv-remap data/nonprod_map.csv \
  --include-pure-ip \
  --skip-segment-groups \
  --no-stripped-originals \
  --label $SRC_HOST
```

Outputs land at `nsx_sibling_groups/$SRC_HOST/` with:
- `groups/<id>_sibling.yaml` — IP-only siblings carrying CSV-mapped IPs
- `sibling_map.json` — per-row audit (`ips_source`, `ips_sibling_mapped`, `ips_uncovered`)
- `reports/skipped_segments.json` — segment-related groups left alone
- `reports/empty_groups.json` — groups with no IPs

To label the bundle by the **target** manager instead of the source
(useful when planning runs against multiple targets):

```bash
python tools/nsx/build_sibling_groups.py \
  --source $SRC \
  --csv-remap data/nonprod_map.csv \
  --include-pure-ip --skip-segment-groups --no-stripped-originals \
  --label $DST.lab.local
```

(Then the bundle is at `nsx_sibling_groups/$DST.lab.local/`.)

---

## 5. WF-D — push siblings to target

### 5a. Dry-run (always first)

```bash
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_sibling_groups/$SRC_HOST/groups
```

Confirm in the JSON output:
- `"mode": "DRY-RUN"`
- `additive_only_contract: "pass"`
- `total_ips_removed: 0`
- `contract_violations: 0`
- `dry_run` count matches the number of siblings you expect

### 5b. Apply

```bash
python tools/nsx/groups.py push --target $DST \
  --groups-dir nsx_sibling_groups/$SRC_HOST/groups --apply
```

Baseline captured at `nsx_sibling_groups/$SRC_HOST/push_report/baselines/`.

---

## 6. (optional, separate change window) Amend rules to reference siblings

NOT part of WF-D itself. Run when CAB approves the rule-side activation:

```bash
python tools/nsx/rules.py amend-refs --target $DST \
  --sibling-map nsx_sibling_groups/$SRC_HOST/sibling_map.json
# dry-run output should look right; then:
python tools/nsx/rules.py amend-refs --target $DST \
  --sibling-map nsx_sibling_groups/$SRC_HOST/sibling_map.json --apply
```

Default: appends sibling refs to `source_groups` and `destination_groups`
only (NOT `scope`). Add `--include-scope` if you want enforcement
broadened too.

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
