# Runbook B — Live-Member Resolution + CSV Remap on `nsx-lm1`

## Summary

Take `nsx-lm1`'s groups, flatten any dynamic/tag-based membership into
static IPs by asking NSX for evaluated VM members, then apply a CSV subnet
remap and push the result back to `nsx-lm1`.

Groups-only push. Services, policies, and rules are not touched.

With `--mapped-only` (used here), unmapped IPs are **dropped** from the
result — only the CSV-mapped values are kept. Use this when you're staging
a remapped configuration on `nsx-lm1` for testing, not as a production
network-extension exercise.

Manager roles:

| Manager | Role | NSX impact |
|---|---|---|
| `nsx-lm1` | Source AND target — read membership, then PATCH groups back | Read + groups-only PATCH |

Properties:

- Groups-only push (PATCH). Services, policies, rules untouched.
- Live VM membership is resolved by NSX (not by Python tag parsing).
- CSV remap is fully offline and reviewable before any push.
- Dry-run is the default safe mode on the push step.

---

## B.0) Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

---

## B.1) Export `nsx-lm1`

Captures the current state (also serves as the rollback snapshot for this workflow).

```bash
python tools/nsx/export_nsx_objects.py \
  --manager nsx-lm1 \
  --base-dir nsx_export \
  --domain-id default \
  --output-format yaml
```

Read-only against NSX. GETs are throttled (5 req/sec).

---

## B.2) Resolve Live VM Membership → Additive Tree

For each group on `nsx-lm1`, ask NSX who its evaluated VM members are right
now, look up each VM's IPs via fabric VIFs, and append them as a static
`IPAddressExpression` block. This flattens tag/condition expressions into
static IP lists so the CSV remap in B.3 has concrete IPs to operate on.

```bash
python tools/nsx/build_group_ip_additive_from_live_members.py \
  --source-manager nsx-lm1 \
  --domain-id default \
  --source-groups-dir nsx_export/nsx-lm1.lab.local/domains/default/groups \
  --output-groups-dir nsx_groups_additive_b/nsx-lm1.lab.local/domains/default/groups \
  --output-format yaml \
  --copy-first \
  --continue-on-group-error
```

Read-only against NSX. Writes group files locally.

---

## B.3) Apply CSV Subnet Remap (Offline)

Read the additive tree from B.2, apply the CSV mapping
(`old_subnet,new_subnet` — longest-prefix match wins), and write the result
to a separate tree. `--mapped-only` replaces each `IPAddressExpression` IP
list with only the mapped values, dropping unmapped entries.

```bash
python tools/nsx/nsx_group_ip_remap_offline.py \
  --export-root nsx_groups_additive_b/nsx-lm1.lab.local/domains/default/groups \
  --prepared-root nsx_groups_remapped/nsx-lm1.lab.local/domains/default/groups \
  --mapping-csv data/nonprod_map.csv \
  --output-format yaml \
  --mapped-only
```

Offline only. No NSX calls.

Result:

```text
nsx_groups_remapped/
└── nsx-lm1.lab.local/
    └── domains/default/
        ├── groups/
        └── reports/
            └── group-ip-remap/
                ├── summary_update.json
                ├── groups_changed.json
                ├── groups_unchanged.json
                └── mapping_invalid_rows.json
```

---

## B.4) Review Reports (Optional)

```text
nsx_groups_remapped/nsx-lm1.lab.local/domains/default/reports/group-ip-remap/
```

| File | Purpose |
|---|---|
| `summary_update.json` | High-level counts: groups changed, IPs added, IPs dropped |
| `groups_changed.json` | Per-group before/after listing |
| `groups_unchanged.json` | Groups with no matching mapping rows |
| `mapping_invalid_rows.json` | CSV rows that failed validation |

Optionally generate the affected-rules impact report:

```bash
python tools/nsx/find_rules_affected_by_group_changes.py \
  --additive-root nsx_groups_remapped \
  --export-root nsx_export \
  --output-dir nsx_logs/affected_rule_reports \
  --verbose
```

---

## B.5) Dry-Run Push to `nsx-lm1`

Groups-only PATCH. Preview against the live `nsx-lm1`.

```bash
python tools/nsx/push_additive_group_ips.py \
  --target nsx-lm1 \
  --groups-dir nsx_groups_remapped/nsx-lm1.lab.local/domains/default/groups \
  --domain-id default \
  --dry-run
```

---

## B.6) Apply Push to `nsx-lm1`

Real write requires `--apply`. Pushes only group PATCHes.

```bash
python tools/nsx/push_additive_group_ips.py \
  --target nsx-lm1 \
  --groups-dir nsx_groups_remapped/nsx-lm1.lab.local/domains/default/groups \
  --domain-id default \
  --apply
```

---

## B.7) Validate

Read-only comparison of live `nsx-lm1` groups against the prepared
remapped payload.

```bash
python tools/nsx/validate_nsx_groups_live.py \
  --target nsx-lm1 \
  --expected-root nsx_groups_remapped/nsx-lm1.lab.local \
  --domain-id default
```

---

## Workflow Diagram

```text
nsx-lm1 (source AND target)
        │
        │  B.1) export_nsx_objects.py
        ▼
nsx_export/nsx-lm1.lab.local/
        │
        │  B.2) build_group_ip_additive_from_live_members.py
        ▼
nsx_groups_additive_b/nsx-lm1.lab.local/
        │
        │  B.3) nsx_group_ip_remap_offline.py --mapped-only
        ▼
nsx_groups_remapped/nsx-lm1.lab.local/
        │
        │  B.4) (optional) review reports + impact analysis
        │  B.5) push_additive_group_ips.py --dry-run
        │  B.6) push_additive_group_ips.py --apply
        │  B.7) validate_nsx_groups_live.py
        ▼
nsx-lm1 (live, updated)
```

---

## Safety Characteristics

| Step | NSX impact |
|---|---|
| B.1 — Export | Read-only |
| B.2 — Live member resolution | Read-only (policy + fabric GETs on `nsx-lm1`) |
| B.3 — CSV remap | Offline |
| B.4 — Review reports | Offline |
| B.5 — Dry-run push | Read-only (preview only) |
| B.6 — Apply push | PATCH groups on `nsx-lm1` only — no services/policies/rules touched |
| B.7 — Validate | Read-only |

---

## Rollback

Revert `nsx-lm1` from the step B.1 snapshot using the groups-only revert
script. It PATCHes each group's payload back to the snapshot state — which
for Workflow B undoes the additive IPs added in B.2 + B.3.

Dry-run preview first:

```bash
python tools/nsx/push_nsx_groups_revert.py \
  --target nsx-lm1 \
  --export-root nsx_export/nsx-lm1.lab.local \
  --domain-id default
```

Then apply:

```bash
python tools/nsx/push_nsx_groups_revert.py \
  --target nsx-lm1 \
  --export-root nsx_export/nsx-lm1.lab.local \
  --domain-id default \
  --apply
```

> Workflow B only writes groups (PATCH), so the groups-only revert is the
> complete rollback. Use `push_complete_nsx_revert.py` instead if you ever
> push services/policies/rules — see Runbook A.
