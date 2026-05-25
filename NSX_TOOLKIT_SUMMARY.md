# NSX Migration Toolkit — How It Works

A summary of the cross-manager NSX firewall migration toolkit: what it does, why,
and the mechanics behind every safety feature. Structured for slide adaptation.

---

## 1. Why this exists

VMware NSX has no native way to clone a firewall configuration from one Local
Manager (LM) to another. SDDC migrations, lab refreshes, and DR rehearsals all
need to:

- **Lift** an entire firewall configuration off a source NSX manager.
- **Land** it byte-faithfully on a target NSX manager that has a completely
  different fabric (different hosts, different segment UUIDs, different IPs).
- **Roll back** any step at any time, independently.
- **Survive** the awkward edges: special-character object IDs, deeply nested
  service references, vRNI auto-generated groups, IPs that need to change
  during the migration.

The toolkit is a set of small, single-purpose Python scripts that decompose
that problem into reversible, auditable phases.

---

## 2. Two workflows, same scripts

| | **Workflow A — Clone** | **Workflow B — In-place CSV remap** |
|---|---|---|
| Purpose | Migrate firewall config from `nsx-lm1` → `nsx-lm2` | Re-IP groups on `nsx-lm1` (typically nonprod-from-prod) without touching the source |
| Source manager | nsx-lm1 (read-only after capture) | nsx-lm1 (read-only after capture) |
| Target manager | nsx-lm2 (writes) | nsx-lm1 (writes, in-place) |
| Driver | Object-class push tools | `groups.py push --csv-remap …` |
| Reversible | Yes — 6-step LIFO revert stack | Yes — single-step revert |

Both workflows use the **same per-object scripts**. Only the flags differ.

---

## 3. The 7 export scripts (read-only against the source)

All seven are GET-only. Run any order, run in parallel if you want — they
write to independent output directories and never touch each other.

| Script | What it captures | Output bundle |
|---|---|---|
| `capture_nsx_state.py` | Orchestrator: raw policy export + groups-with-captured-VM-IPs snapshot + segment inventory + rule-impact report + VM tag inventory | `nsx_capture/<host>/` |
| `services.py export` | Customer L4/nested services (system-owned skipped) | `nsx_services_export/<host>/services/` |
| `groups.py export` | Customer groups (dynamic + static), system groups skipped | `nsx_groups_export/<host>/groups/` |
| `policies.py export` | Customer security policies (one folder per policy with a `policy.yaml` + `rules_order.yaml`) | `nsx_policies_export/<host>/security-policies/` |
| `rules.py export` | Rules nested under each customer policy | `nsx_rules_export/<host>/security-policies/<policy>/rules/` |
| `segments.py export` | Segment definitions + cross-reference of which groups reference which segments | `nsx_segments_export/<host>/` |
| `membership.py export` | VM ↔ group correlation: per-group VM list with IPs, per-VM groups membership, flat VM-IP index | `nsx_membership_export/<host>/` |

Each one writes its own `manifest.json`, `summary.txt`, `logs/`, and a
machine-readable `<type>.json` / `<type>.jsonl` for downstream consumption.

---

## 4. The 5 push scripts (one per object class)

Each pushes a single object class to a target manager. Default mode is
**dry-run**; `--apply` is required to mutate.

| Script | Pushes to NSX endpoint | Reverts what |
|---|---|---|
| `services.py push` | `/policy/api/v1/infra/services/<id>` | Services it created; restores any pre-push customer services it overwrote |
| `groups.py push` | `/policy/api/v1/infra/domains/<d>/groups/<id>` | Groups it created; restores any it overwrote |
| `policies.py push` | `/policy/api/v1/infra/domains/<d>/security-policies/<id>` | Policies it created (cascades rule deletion via DELETE on the parent) |
| `rules.py push` | `/policy/api/v1/infra/domains/<d>/security-policies/<p>/rules/<r>` | Individual rules (parent policy left untouched) |
| `segments.py push` | `/policy/api/v1/infra/segments/<id>` | Segments it created (optional — usually skipped in cross-manager migration) |

Every push command runs a uniform pipeline:

```
1. Find the export bundle and walk every YAML object file
2. Capture target baseline (full GET of current customer objects)  ← ONLY when --apply
3. For each object:
     - Sanitize (strip volatile fields like _revision, _create_time)
     - Apply any transforms (segment strip/convert, CSV remap, fabric strip)
     - PUT → on "already exists" → PATCH       ← idempotent fallback
     - On "dep missing" 404 → silently queue for retry
     - On any other error → log full traceback
4. Retry loop: re-attempt queued dep-404 rows until no progress or 5 rounds
5. Promote leftover pending rows to "failed"
6. Write summary.json + <type>.json + push_log + errors_log + baseline_file
```

---

## 5. Segments: three handling modes

Segments are the single most environment-coupled object in NSX. The same
segment has different policy paths (`/infra/segments/<uuid>`) on every NSX
manager because the UUID is generated when the segment is created in that
manager's database.

This means **direct segment-path references in a cloned group will 404 on the
target**. `groups.py push` exposes three modes for what to do with them:

| `--segments-mode` | What it does | When to use it |
|---|---|---|
| **`keep`** (default for Workflow B) | Pushes group expressions verbatim, segment paths included | Source = target (Workflow B in-place remap) |
| **`strip`** | Drops segment paths from each `PathExpression`. If the PathExpression becomes empty, drops the expression. Group lands with whatever non-segment membership it had. | Workflow A Part 1 — fast initial clone |
| **`convert`** | Replaces each segment path with an `IPAddressExpression` containing the segment's CIDR list, looked up from `segment_details.json` captured at export time | Workflow A Part 2 — restores IP-level membership without depending on the target having matching segments |

Workflow A runs **strip first, then convert** so the group lands on the target
even if Part 2's lookup misses a few segments — Part 1 already deposited the
group's other expressions.

---

## 6. VM IP address handling

NSX groups can be **dynamic** (membership computed from VM tags or properties
at evaluation time). Dynamic groups don't store IPs in their definition — NSX
resolves them by querying the inventory.

But once cloned to a different manager, the inventory is different. The same
VM tag query might match different VMs (or no VMs) on the target manager,
producing different IPs.

The toolkit handles this by **snapshotting** evaluated VM IPs at capture time:

1. `capture_nsx_state.py` calls each customer group's *live-evaluated
   members* endpoint on the source manager (ONCE, at capture time).
2. For each evaluated VM, it records the VM's IPs.
3. Those IPs are written into a separate copy of each group called the
   **additive** bundle: `groups_additive/domains/<d>/groups/<id>.yaml`. The
   additive group has an extra `IPAddressExpression` containing the captured IPs.
4. The push tools read **from disk** — they never re-resolve VM membership
   at push time. The IPs are frozen at the moment of capture.

This means **Workflow A Part 3** (`groups.py push --groups-dir nsx_capture/.../groups_additive/...`)
PATCHes the captured VM IPs into each group on the target, regardless of the
target's own VM inventory.

### CSV subnet remap (Workflow B)

`groups.py push` also supports `--csv-remap <csv> [--mapped-only]`:

```csv
old_subnet,new_subnet
10.6.0.101/32,10.7.0.101/32
10.6.1.0/24,10.7.1.0/24
10.6.0.0/16,10.7.0.0/16
```

- **Longest-prefix match wins** — `10.6.0.101/32` beats `10.6.0.0/16`.
- **`--mapped-only`** drops IPs that don't match any CSV row. Without it,
  mapped IPs are added alongside the originals (additive remap).
- Bidirectional mode (`--bidirectional`) treats each row as a two-way mapping
  for round-trip migrations.

This is how nonprod environments get stood up from prod snapshots with a
clean re-IP, without ever touching the source manager.

---

## 7. Fabric paths (host transport nodes, edge TNs) — auto-strip with log

Some NSX groups (especially vRealize Network Insight auto-generated ones)
reference **fabric-layer** objects in their expressions — host transport nodes,
edge transport nodes, edge clusters, transport zones. These objects are tied
to physical/virtual hardware and are bound to a specific NSX manager's
database. They **cannot be cloned** — even if the target manages the same
vCenter, the prepared host gets a different NSX-assigned UUID.

Without intervention, a group that references `/infra/sites/default/enforcement-points/default/host-transport-nodes/<UUID>` will fail to push with:

```
HTTP 400 BAD_REQUEST
The path=[/infra/sites/default/enforcement-points/default/host-transport-nodes/<UUID>] is invalid
```

`groups.py push` detects any path matching the fabric-path pattern and:

1. **Strips** the path from the group's expression.
2. **Logs** each strip to a forensic JSON report: `<reports_dir>/fabric_paths_stripped.json`.
3. **Pushes the group anyway** — with the remaining (non-fabric) membership,
   or as an empty group if fabric refs were its only membership.
4. **Dependent groups** that reference the stripped group succeed normally
   because the group itself does land on the target.

The forensic report names every group affected, every path stripped, and
includes operator notes explaining how to manually reproduce the membership
on the target side if needed:

```json
{
  "ran_at": "2026-05-25T13:28:12+00:00",
  "target": "nsx-lm2.lab.local",
  "summary": { "groups_affected": 1, "paths_stripped_total": 1 },
  "groups": [{
    "id": "vRNI-Node_Group_Profile_TN_...",
    "fabric_paths_stripped": ["/infra/sites/.../host-transport-nodes/..."],
    "empty_after_strip": false,
    "status": "success_put"
  }],
  "notes": "These groups referenced fabric objects... operator must add equivalent..."
}
```

---

## 8. Dependency-404 trap + retry loop

NSX validates **every path inside the payload** at PUT time. If a service
nests another service that doesn't exist on the target yet, or a group
references another group that hasn't been pushed yet, NSX returns:

```
HTTP 404 NOT_FOUND
The requested object : /infra/services/TCP_Range_(50000-50100) could not be found.
Object identifiers are case sensitive.
```

This is **expected** when objects are pushed in filename order rather than
dependency order. The toolkit handles it without operator intervention:

1. The 404 is **trapped silently** — no traceback dump to console.
2. The row is marked `failed_pending_retry` with a clean one-line log:
   ```
   [17/803  ok=16 fail=1 skip=0] FCB_Commvault_(Intra_Media_Agent) —
   nested dep missing (404); PENDING RETRY (queued=1)
   ```
3. Main loop continues to the next object (its leaf may be later in the iteration).
4. After the main pass, a **retry round** picks up every `failed_pending_retry`
   row and re-attempts it. By then, leaves pushed earlier in the same run
   have landed and the dep lookups succeed.
5. Loop terminates on: no pending rows, no progress in a round, or 5 rounds.
   Any leftover pending rows promote to `failed` with full traceback.

This makes the push **dependency-order agnostic**. You don't need to topologically
sort 4,000 services before pushing — the retry handles it.

Same pattern is implemented identically in services, groups, policies, rules,
and segments push tools.

---

## 9. Filename scheme — short, collision-resistant, Windows-safe

Every exported object gets a deterministic filename:

| ID length | Filename format | Example |
|---|---|---|
| ≤ 10 chars | `<slug>-<8hex>.yaml` | `web-tier-abbd7ae4.yaml` |
| > 10 chars | `<first5>-<last5>-<8hex>.yaml` | `App_0-rs_-_2-bf57436c.yaml` |

The 8-hex MD5 of the original ID ensures:
- **Determinism** — same input → same filename → clean git diffs across re-exports.
- **Collision resistance** — 4.3B combinations; ~0.001% collision risk at 10K objects.
- **Windows MAX_PATH safety** — total path stays well under 260 chars even
  in deeply-nested production folder structures.

**Filenames are not load-bearing.** Push tools find files by glob and read the
NSX `id` from inside the YAML, so renaming a file doesn't break anything. The
filename only exists to be human-recognizable and writable on any filesystem.

---

## 10. Revert — LIFO baseline stack

Every `*.py push --apply` does this **before** sending any PUT/PATCH:

1. GETs the current state of every customer object of its class on the target.
2. Writes that snapshot as `<reports_dir>/baselines/<RUN_TS>_target_baseline.json`.
3. Pushes.

Every `*.py revert --apply` does this:

1. Finds the most recent `_target_baseline.json` (not `.reverted`) in the
   reports directory — a **LIFO pop**.
2. For each object in the current target state:
   - **In baseline** → PUT the baseline payload back (restore to pre-push state).
   - **Not in baseline** → DELETE (we created it; it shouldn't exist).
3. Renames the consumed file `*.json.reverted` so the next revert pops the
   prior baseline.

This means **each push phase is independently revertible**, and a stack of
pushes can be unwound in any order by repeatedly running the matching revert.

A typical 6-phase Workflow A clone has 6 baselines stacked. Reverting in
reverse dependency order (rules → policies → groups Part 3 → Part 2 → Part 1 →
services) unwinds the entire migration in ~30 seconds.

---

## 11. Logging — 4-handler layout for every push

Every push and revert run writes:

| Handler | Destination | Level |
|---|---|---|
| `StreamHandler` | console (stdout) | INFO |
| `FileHandler` | `<reports_dir>/<tool>_<action>_<ts>.log` | INFO |
| `FileHandler` | `$NSX_LOG_DIR/<tool>_<action>_<ts>.log` (env-driven global archive) | INFO |
| `FileHandler` | `<reports_dir>/<tool>_<action>_<ts>.errors.log` | ERROR |

Plus:

- **Full Python tracebacks** on every unexpected failure via `log.exception(...)`.
- **Silent trapping** for known-expected patterns (dep-404, already-exists fallback).
- **Forensic JSON reports** for anything operators might need to act on later:
  `fabric_paths_stripped.json`, `failures.json`, `summary.json`, `<type>.jsonl`.

---

## 12. Safety guarantees

| Guarantee | Mechanism |
|---|---|
| No unintended writes during testing | All push tools default to dry-run; `--apply` required to mutate |
| No silent corruption | Every PUT goes through the typed `NsxPolicyClient` with `_q()` URL-encoding on every interpolated ID (parens, spaces, commas, etc.) |
| No filesystem collision | `short_id_filename()` with 8-hex MD5 suffix |
| No Windows MAX_PATH crash | Same — filenames always ≤ ~22 chars before extension |
| Reversibility | Per-tool LIFO baseline stack; `*.py revert --apply` |
| Audit trail | Bundle + global log + errors-only log + JSON reports; every push and revert timestamped to the millisecond |
| Cross-manager portability | Segments: strip/convert; VM IPs: snapshot at capture; Fabric paths: auto-strip with forensic log |
| Dependency robustness | Silent dep-404 trap + bounded retry loop |
| Source manager protection (Workflow A) | After capture, source is never touched again |
| Target manager protection (Workflow A) | Baseline captured before every push; revert always available |

---

## 13. Operational shape of a typical migration

### Workflow A — clone lm1 → lm2

```bash
# EXPORT — read-only against nsx-lm1, run once
python tools/nsx/capture_nsx_state.py --source nsx-lm1
python tools/nsx/services.py    export --source nsx-lm1
python tools/nsx/groups.py      export --source nsx-lm1
python tools/nsx/policies.py    export --source nsx-lm1
python tools/nsx/rules.py       export --source nsx-lm1
python tools/nsx/segments.py    export --source nsx-lm1
python tools/nsx/membership.py  export --source nsx-lm1

# PUSH Part 1 — 1-for-1 clone with segments stripped
python tools/nsx/services.py push --target nsx-lm2 --services-dir nsx_services_export/nsx-lm1.lab.local/services --apply
python tools/nsx/groups.py   push --target nsx-lm2 --groups-dir   nsx_groups_export/nsx-lm1.lab.local/groups   --segments-mode strip --apply
python tools/nsx/policies.py push --target nsx-lm2 --policies-dir nsx_policies_export/nsx-lm1.lab.local/security-policies --apply
python tools/nsx/rules.py    push --target nsx-lm2 --rules-dir    nsx_rules_export/nsx-lm1.lab.local/security-policies    --apply

# PUSH Part 2 — replace segment refs with their CIDRs
python tools/nsx/groups.py push --target nsx-lm2 \
  --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups \
  --segments-mode convert \
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json \
  --apply

# PUSH Part 3 — add captured VM IPs (snapshot from capture, NOT re-fetched)
python tools/nsx/groups.py push --target nsx-lm2 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --segments-mode convert \
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json \
  --apply

# REVERT — reverse dependency order, LIFO-pops each phase's baseline
python tools/nsx/rules.py    revert --target nsx-lm2 --reports-dir nsx_rules_export/nsx-lm1.lab.local/push_report    --apply
python tools/nsx/policies.py revert --target nsx-lm2 --reports-dir nsx_policies_export/nsx-lm1.lab.local/push_report --apply
python tools/nsx/groups.py   revert --target nsx-lm2 --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report --apply  # Part 3
python tools/nsx/groups.py   revert --target nsx-lm2 --reports-dir nsx_groups_export/nsx-lm1.lab.local/push_report   --apply  # Part 2 (LIFO from same stack)
python tools/nsx/groups.py   revert --target nsx-lm2 --reports-dir nsx_groups_export/nsx-lm1.lab.local/push_report   --apply  # Part 1 (LIFO from same stack)
python tools/nsx/services.py revert --target nsx-lm2 --reports-dir nsx_services_export/nsx-lm1.lab.local/push_report --apply
```

### Workflow B — in-place CSV remap on lm1

```bash
# CAPTURE (read-only)
python tools/nsx/capture_nsx_state.py --source nsx-lm1

# PUSH groups-only with CSV subnet remap (writes back to lm1)
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --csv-remap data/nonprod_map.csv \
  --mapped-only \
  --segments-mode strip \
  --apply

# REVERT (restores original group definitions on lm1)
python tools/nsx/groups.py revert --target nsx-lm1 \
  --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report \
  --apply
```

---

## 14. Validation footprint at end of a clean migration

Workflow A end-to-end produces:

- Source (`nsx-lm1`): **unchanged** — pure read after capture.
- Target (`nsx-lm2`): **N-for-N parity** of customer services, groups, policies, rules.
  Groups have segment paths converted to CIDRs + the snapshot of VM IPs frozen at capture.
- On disk: 7 export bundles + 6 push bundles + 6 baselines (one per push phase).
- Operator can roll back any phase or the entire migration with the revert chain.
- Forensic JSON reports for any unusual handling: fabric paths stripped,
  CSV-mapped IPs, missing segment lookups, dependency-retry events.

---

## 15. Glossary

| Term | Meaning |
|---|---|
| **LM** | NSX Local Manager — a single NSX instance |
| **GM** | NSX Global Manager — multi-LM federation controller |
| **TN** | Transport Node — a hypervisor (or edge VM) prepared as an NSX dataplane endpoint |
| **TZ** | Transport Zone — a logical scope for which TNs see which segments |
| **PathExpression** | Group membership criterion that selects objects by their policy path (e.g. another group, a segment, a TN) |
| **IPAddressExpression** | Group membership criterion that is a literal list of IPs/CIDRs/ranges |
| **NestedServiceServiceEntry** | A service that contains other services by path reference |
| **vRNI** | vRealize Network Insight — VMware's NSX-aware visibility/monitoring product; auto-creates `vRNI-*` groups |
| **Baseline** | A snapshot of the target manager's customer-object state, captured immediately before a push, used for revert |
| **LIFO stack** | Last-In-First-Out — the order in which baselines pop on revert (newest push reverted first) |
| **Sanitize** | Stripping volatile/read-only fields (`_revision`, `_create_time`, etc.) from a payload before re-PUTting it |
