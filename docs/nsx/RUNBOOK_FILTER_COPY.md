# Runbook - Selective Category Copy (macOS / Linux / bash)

Copy DFW policies (and only their transitive dependencies) from one NSX
Local Manager to another, filtered by policy category.

Use case: your source manager has policies across every category
(Ethernet, Emergency, Infrastructure, Environment, Application), but you
only want to migrate the `Application` policies (plus every group and
service they reference) to a new manager. This runbook chains three
existing tools with one new offline transform.

PowerShell variant: [RUNBOOK_FILTER_COPY_PS.md](RUNBOOK_FILTER_COPY_PS.md).

---

## Overview

```
   nsx-lm1                            (offline)                            nsx-lm4
+-----------+   capture_nsx_state.py +---------+   push tools     +-----------+
|  source   |----------------------->|  flat   |----------------->|  target   |
|  manager  |                        | exports |    +-----+       |  manager  |
+-----------+                        +----+----+    |     |       +-----------+
                                          |         |  4  | filtered push chain
                                          v         |     |
                                     +----+----+    |     |
                                     | filter  |----+     |
                                     | bundle  |          |
                                     +---------+          |
                                                          v
                                          services -> groups -> policies -> rules
```

Three stages, all offline for the middle one:

1. **Capture** (read-only against source): pull every DFW object using `capture_nsx_state.py`
2. **Filter** (offline, no NSX access): use `filter_policy_bundle.py` to keep only policies of the requested categories, plus transitively-referenced groups and services
3. **Push** (write to target): four standard push tools consume the filtered bundle

The filter step never touches NSX. It only reads flat-export YAML files
on disk and writes a new YAML tree in the same layout.

---

## When to use this workflow

| Situation | Best runbook |
|---|---|
| Full clone (every DFW object) | [RUNBOOK_A.md](RUNBOOK_A.md) |
| Filtered copy of only certain categories | **This runbook** |
| In-place remap (rewriting group IPs on the same manager) | [RUNBOOK_B.md](RUNBOOK_B.md) |
| Decompose tag+IP mixed groups into siblings | [RUNBOOK_C.md](RUNBOOK_C.md) / [RUNBOOK_D.md](RUNBOOK_D.md) |

---

## Prerequisites

### Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

### `.env` requirements

Standard NSX credentials that the rest of the toolkit uses. No new
configuration needed for the filter tool. See any other NSX runbook for
the base set.

---

## Step 1 - Capture the source manager

Read-only. Creates `nsx_capture/<source-host>/` plus the four flat-export
trees the push tools consume.

```bash
python tools/nsx/capture_nsx_state.py --source nsx-lm1
```

After this step, you should have:

```
nsx_capture/nsx-lm1.lab.local/
nsx_policies_export/nsx-lm1.lab.local/security-policies/
nsx_rules_export/nsx-lm1.lab.local/security-policies/
nsx_groups_export/nsx-lm1.lab.local/groups/
nsx_services_export/nsx-lm1.lab.local/services/
```

These are the four inputs to the filter step.

---

## Step 2 - Filter to the target categories (offline)

Read the flat exports, keep policies whose `category` matches the filter,
walk every reference (rules, groups, service, nested groups,
service-groups), and emit a new bundle in the same layout.

```bash
python tools/nsx/filter_policy_bundle.py \
  --source nsx-lm1 \
  --categories Application
```

Output lands at:

```
nsx_filtered_bundle/<UTC_TS>/nsx-lm1.lab.local/
├── services/services/*.yaml            (only referenced by kept rules, recursive)
├── groups/groups/*.yaml                (only referenced by kept rules + nested)
├── policies/security-policies/         (only matching-category policies)
├── rules/security-policies/            (only rules of kept policies)
├── manifest.json                       (what was included, why, what was skipped)
└── logs/
```

### Flag reference

| Flag | Default | Purpose |
|---|---|---|
| `--source <alias>` | required | NSX manager alias whose flat exports to read (e.g., `nsx-lm1`) |
| `--categories <list>` | required | Comma-separated categories to KEEP. Valid values: `Ethernet, Emergency, Infrastructure, Environment, Application` |
| `--include-default-sections` | off | Also include policies with `is_default: true` (the L2/L3 default sections). Off by default because those are the system-supplied default sections. |
| `--output-base <path>` | `./nsx_filtered_bundle` | Where to land the filtered bundle |
| `--source-host-override <host>` | (auto) | Manually override the derived hostname if the alias resolution is wrong |

### What gets kept and why

| Object type | Rule for inclusion |
|---|---|
| Security policy | `category` matches `--categories` list AND (`is_default: false` OR `--include-default-sections`) |
| Rule | Belongs to a kept policy |
| Group | Referenced by a kept rule's `source_groups`/`destination_groups`/`scope`, OR referenced by another kept group's `PathExpression` (recursive) |
| Service | Referenced by a kept rule's `services`, OR referenced by another kept service-group's members (recursive) |

### Reading the manifest

`manifest.json` records exactly what the filter kept and what it skipped:

```bash
setopt interactive_comments 2>/dev/null || true

BUNDLE=$(ls -1dt nsx_filtered_bundle/*/nsx-lm1.lab.local | head -1)

# Which policies were kept?
jq '.kept.policies[] | {display_name, category}' "$BUNDLE/manifest.json"

# Which policies were skipped, and why?
jq '.skipped_policies[] | {display_name, category, reason}' "$BUNDLE/manifest.json"

# Any references that couldn't be resolved from the source bundle?
jq '.unresolved' "$BUNDLE/manifest.json"

# Any segment paths referenced by groups (need to exist on target OR be stripped)?
jq '.segments_referenced_by_groups[]' "$BUNDLE/manifest.json"

# Top-level counts
jq '.counts' "$BUNDLE/manifest.json"
```

### Common caveats

1. **Unresolved service refs are usually fine.** The source capture
   filters `_system_owned=true` services. Every NSX manager ships with
   built-in services like `/infra/services/HTTP`, `/infra/services/ICMP-ALL`,
   `/infra/services/DHCP-Server`. Rules that reference those will show as
   "unresolved" here, but the target manager already has them, so the
   rule push will succeed.
2. **Segment paths inside groups need a plan.** If any of your kept
   groups reference segments (`/infra/segments/<uuid>`), those segments
   won't exist on the target unless you migrated them separately. The
   groups push has three modes: `keep`, `strip`, `convert`. For a fresh
   target with no matching segments, `--segments-mode strip` is the
   simplest option (strips the PathExpression from each group but keeps
   the rest of the group intact).
3. **Filtering is by policy category.** If a group is referenced by both
   an Application policy and an Infrastructure policy, and you filter to
   Application, that group is included. That's correct: you need it for
   the Application rules to work.

---

## Step 3 - Push the filtered bundle to the target

Four standard push tools consume the bundle in the correct order:
services first (no deps), groups next (may reference other groups),
policies (create empty containers), then rules (references everything).

Each push tool starts as **dry-run** and requires `--apply` to write.

### 3a. Services (dry-run then apply)

```bash
BUNDLE=$(ls -1dt nsx_filtered_bundle/*/nsx-lm1.lab.local | head -1)

python tools/nsx/services.py push --target nsx-lm4 \
  --services-dir "$BUNDLE/services/services"

python tools/nsx/services.py push --target nsx-lm4 \
  --services-dir "$BUNDLE/services/services" --apply
```

### 3b. Groups (choose a `--segments-mode` if manifest.json flagged segment refs)

Options are `keep` (preserve segment paths as-is), `strip` (remove them),
`convert` (materialize the segment CIDRs into IPAddressExpression using
segment_inventory data captured in step 1).

For a fresh target with no matching segments:

```bash
python tools/nsx/groups.py push --target nsx-lm4 \
  --groups-dir "$BUNDLE/groups/groups" \
  --segments-mode strip

python tools/nsx/groups.py push --target nsx-lm4 \
  --groups-dir "$BUNDLE/groups/groups" \
  --segments-mode strip --apply
```

For a target that already has matching segments (same UUIDs), use
`--segments-mode keep`. For a target with matching subnets but different
segment UUIDs, use `--segments-mode convert`.

### 3c. Policies (empty containers)

```bash
python tools/nsx/policies.py push --target nsx-lm4 \
  --policies-dir "$BUNDLE/policies/security-policies"

python tools/nsx/policies.py push --target nsx-lm4 \
  --policies-dir "$BUNDLE/policies/security-policies" --apply
```

### 3d. Rules

```bash
python tools/nsx/rules.py push --target nsx-lm4 \
  --rules-dir "$BUNDLE/rules/security-policies"

python tools/nsx/rules.py push --target nsx-lm4 \
  --rules-dir "$BUNDLE/rules/security-policies" --apply
```

---

## Step 4 - Verify

```bash
setopt interactive_comments 2>/dev/null || true

python tools/nsx/capture_nsx_state.py --source nsx-lm4
# Then inspect nsx_capture/nsx-lm4.lab.local/ and compare counts against
# the filter manifest to make sure everything landed.
```

Or use the rules-usage report to see hit counts once real traffic starts flowing:

```bash
python tools/reports/report_rules_usage.py --target nsx-lm4
```

---

## Revert (LIFO order)

If you need to back out, revert in reverse push order. Each push tool
captured a per-run baseline for you.

```bash
python tools/nsx/rules.py    revert --target nsx-lm4 \
  --reports-dir "$BUNDLE/rules/push_report" --apply

python tools/nsx/policies.py revert --target nsx-lm4 \
  --reports-dir "$BUNDLE/policies/push_report" --apply

python tools/nsx/groups.py   revert --target nsx-lm4 \
  --reports-dir "$BUNDLE/groups/push_report" --apply

python tools/nsx/services.py revert --target nsx-lm4 \
  --reports-dir "$BUNDLE/services/push_report" --apply
```

Each command pops the most recent unreverted baseline for that stack.

---

## Safety properties

| Property | Behavior |
|---|---|
| Source manager | Never written to (capture and filter are both read-only) |
| Filter tool | Never opens a network socket. Reads YAML, writes YAML. |
| Push tools | Default is dry-run. `--apply` is required to write. |
| Per-run baseline | Every push captures a baseline before writing, for revert |
| Idempotent push | Push tools handle "already exists" and 412 revision-conflict by falling back from PUT to PATCH |
| Object ordering | Services, then groups, then policies, then rules. Enforced by running them in that order. |

---

## Example - full end-to-end run against the lab

Source: nsx-lm1 (11 groups, 2 services, 3 policies, 9 rules across all categories).
Target: nsx-lm4 (empty sandbox).
Filter: Application category only.

```bash
setopt interactive_comments 2>/dev/null || true

# 1. Capture (about 5 seconds against a small lab)
python tools/nsx/capture_nsx_state.py --source nsx-lm1

# 2. Filter (about 0.1 seconds - offline)
python tools/nsx/filter_policy_bundle.py \
  --source nsx-lm1 --categories Application

# Result:
# Policies kept:  2  (skipped 3)
# Rules kept:     8
# Groups kept:    11 (recursive)
# Services kept:  1  (recursive; 5 built-in refs auto-present on target)

# 3. Push (dry-run each, then apply each)
BUNDLE=$(ls -1dt nsx_filtered_bundle/*/nsx-lm1.lab.local | head -1)

python tools/nsx/services.py push --target nsx-lm4 --services-dir "$BUNDLE/services/services"
python tools/nsx/services.py push --target nsx-lm4 --services-dir "$BUNDLE/services/services" --apply

python tools/nsx/groups.py push --target nsx-lm4 --groups-dir "$BUNDLE/groups/groups" --segments-mode strip
python tools/nsx/groups.py push --target nsx-lm4 --groups-dir "$BUNDLE/groups/groups" --segments-mode strip --apply

python tools/nsx/policies.py push --target nsx-lm4 --policies-dir "$BUNDLE/policies/security-policies"
python tools/nsx/policies.py push --target nsx-lm4 --policies-dir "$BUNDLE/policies/security-policies" --apply

python tools/nsx/rules.py push --target nsx-lm4 --rules-dir "$BUNDLE/rules/security-policies"
python tools/nsx/rules.py push --target nsx-lm4 --rules-dir "$BUNDLE/rules/security-policies" --apply

# 4. Verify
python tools/nsx/capture_nsx_state.py --source nsx-lm4
```

Expected on lm4 after apply: 1 service, 11 groups (with segment refs
stripped), 2 policies, 8 rules. Infrastructure and Ethernet policies from
lm1 stay only on lm1.

---

## Full flag reference

### `filter_policy_bundle.py`

| Flag | Default | Purpose |
|---|---|---|
| `--source <alias>` | required | NSX manager alias whose flat exports to filter |
| `--categories <list>` | required | Comma-separated policy categories to KEEP |
| `--include-default-sections` | off | Also keep policies where `is_default: true` |
| `--output-base <path>` | `./nsx_filtered_bundle` | Output root |
| `--source-host-override <host>` | (auto) | Override the resolved hostname |

### The four push tools

Each accepts standard `--target <alias>`, per-tool `--*-dir <path>`, and
`--apply`. See [RUNBOOK_A.md](RUNBOOK_A.md) for the complete flag
reference on each.
