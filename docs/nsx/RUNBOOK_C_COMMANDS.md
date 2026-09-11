# Runbook C — Commands (sibling-group decomposition)

Bare commands only. See [RUNBOOK_C.md](RUNBOOK_C.md) for explanations,
or [RUNBOOK_C_COMMANDS_PS.md](RUNBOOK_C_COMMANDS_PS.md) for PowerShell.

> Replaces Workflow A Part 2 + Part 3. Run **after** WF-A Part 1
> (services + groups-strip + policies + rules).

## Env

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

---

## 0a. (recommended) Detect IP drift on the SOURCE since last capture

Before re-pushing from an existing capture bundle, verify lm1 itself
hasn't drifted in production since the bundle was generated. **Reference
the raw `nsx_groups_export/...` bundle, not `groups_additive/`** — the
additive bundle contains injected VM IPs that don't appear in the static
live GET, so it produces false positives. If drift is detected, re-capture
(`capture_nsx_state.py --source nsx-lm1` + per-tool exports) before
proceeding.

```bash
python tools/nsx/compare_group_ips.py \
  --reference nsx_groups_export/nsx-lm1.lab.local/groups \
  --target nsx-lm1
```

Report lands in `$NSX_LOG_DIR/nsx_drift_report/nsx-lm1.lab.local/`.

## 0b. (optional) Detect IP drift on the TARGET

After WF-A Part 3 has been live on the target, IPs may have been added/
removed by other actors. Reference the `groups_additive` bundle here
(that's what Part 3 pushed) and target lm2.

```bash
python tools/nsx/compare_group_ips.py \
  --reference-source nsx-lm1 \
  --target nsx-lm2
```

Report lands in `$NSX_LOG_DIR/nsx_drift_report/<target-host>/`.

## 1. Capture (read-only, source side)

**`--live-query` is mandatory.** Without it the capture is a plain copy of the
export, every tag group looks empty, and step 2 builds siblings only for groups
that already hold static IPs. Nothing errors; the run reports success. Measured
on lm1 2026-09-11: 1 sibling without it, **7 with it**.

```bash
python tools/nsx/capture_nsx_state.py --source nsx-lm1 --live-query
```

Gate before going further. All must hold, or the siblings will be wrong:

```bash
grep "Summary:" $NSX_LOG_DIR/build_group_ip_additive_from_live_members_*.log | tail -1
#   ip_source: 'effective'      anything else means a stale or legacy bundle
#   vm_ip_index_count: non-zero
#   groups_changed:    non-zero
#   ips_added_total:   non-zero
#   groups_errors:     0        non-zero means unrealized groups: wait, re-run
```

## 2. Transform: build siblings + stripped originals (offline)

```bash
setopt interactive_comments 2>/dev/null || true

# (a) Read from lm1's capture bundle — siblings reflect lm1's view
python tools/nsx/build_sibling_groups.py --source nsx-lm1

# (b) Read from lm2's live exported state instead — siblings reflect lm2's IPs
#     (useful when drift exists and you want to preserve what's on lm2)
python tools/nsx/groups.py export --source nsx-lm2
python tools/nsx/build_sibling_groups.py \
  --groups-dir nsx_groups_export/nsx-lm2.lab.local/groups
```

Produces:
- `nsx_sibling_groups/<host>/groups/` — new IP-only sibling groups
- `nsx_stripped_groups/<host>/groups/` — originals with IPAddressExpression entries removed
- `nsx_sibling_groups/<host>/sibling_map.json` — used by step 5

## 3. Push siblings → target (additive, new groups)

```bash
python tools/nsx/groups.py push --target nsx-lm2 \
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups \
  --apply
```

### 3a. (optional) Same push but also CSV-remap the sibling IPs

Adds CSV-mapped equivalents alongside the original IPs (strict-additive
contract enforced). `--batch-size` defaults to 1 — step through every
change, bump higher at any prompt.

```bash
python tools/nsx/groups.py push --target nsx-lm2 \
  --groups-dir nsx_sibling_groups/nsx-lm1.lab.local/groups \
  --csv-remap data/nonprod_map.csv \
  --apply
```

## 4. Push stripped originals → target (--intentional-ip-removal)

```bash
python tools/nsx/groups.py push --target nsx-lm2 \
  --groups-dir nsx_stripped_groups/nsx-lm1.lab.local/groups \
  --intentional-ip-removal \
  --apply
```

`--batch-size` defaults to **1** here (step through every removal). Bump higher at any prompt.

## 5. Amend rules to reference siblings alongside originals

```bash
python tools/nsx/rules.py amend-refs --target nsx-lm2 \
  --sibling-map nsx_sibling_groups/nsx-lm1.lab.local/sibling_map.json \
  --apply
```

Strict-additive — never removes a ref. Same prompt vocabulary as `groups.py push`.

---

## Revert sequence (reverse order)

```bash
setopt interactive_comments 2>/dev/null || true

# 5. amend-refs revert
python tools/nsx/rules.py revert --target nsx-lm2 \
  --reports-dir nsx_rules_export/nsx-lm2.lab.local/push_report --apply

# 4. stripped-originals revert
python tools/nsx/groups.py revert --target nsx-lm2 \
  --reports-dir nsx_stripped_groups/nsx-lm1.lab.local/push_report --apply

# 3. siblings revert
python tools/nsx/groups.py revert --target nsx-lm2 \
  --reports-dir nsx_sibling_groups/nsx-lm1.lab.local/push_report --apply
```
