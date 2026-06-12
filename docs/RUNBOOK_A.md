# Runbook A — Clone `nsx-lm1` → `nsx-lm2` (broken-out scripts, 3 push phases)

## Summary

Clone the customer-defined NSX firewall configuration from a source Local
Manager (`nsx-lm1`) onto a target Local Manager (`nsx-lm2`). One-time
read-only **export** off the source, then **push in three phases**, each
of which is independently revertible.

| Phase | What it does | Why split |
|---|---|---|
| **EXPORT** | 7 read-only commands against the source — captures every object class + the segment / VM-IP snapshots needed by later phases | Source is never written to after this |
| **PUSH Part 1** | 1-for-1 copy of services, groups, policies, rules — **with segment refs stripped from groups** | Confirms the structure landed cleanly without cross-manager dependencies muddying the result |
| **PUSH Part 2** | Re-push groups with **segment refs replaced by IPAddressExpression CIDRs** | Resolves segment dependencies the target doesn't have natively |
| **PUSH Part 3** | Re-push groups with **captured VM IPs added** — IPs snapshotted on the source at export time, NOT re-fetched at push | Freezes dynamic/tag-based membership that only resolves on the source |

Each push step **auto-captures a baseline** of the target's pre-push state.
Reverts are independent and LIFO — the full clone can be unwound in reverse
dependency order, or just one phase.

---

## Tools

| Tool | Used in | Purpose |
|---|---|---|
| [tools/nsx/capture_nsx_state.py](../tools/nsx/capture_nsx_state.py) | EXPORT | Orchestrator: raw policy dump + segment inventory + VM-IP snapshot + impact reports |
| [tools/nsx/services.py](../tools/nsx/services.py) | EXPORT, PUSH 1, REVERT | `export` / `push` / `revert` services |
| [tools/nsx/groups.py](../tools/nsx/groups.py) | EXPORT, PUSH 1/2/3, REVERT | `export` / `push` / `revert` groups. Push accepts `--segments-mode {keep,strip,convert}` |
| [tools/nsx/policies.py](../tools/nsx/policies.py) | EXPORT, PUSH 1, REVERT | `export` / `push` / `revert` security policies |
| [tools/nsx/rules.py](../tools/nsx/rules.py) | EXPORT, PUSH 1, REVERT | `export` / `push` / `revert` rules (children of policies) |
| [tools/nsx/segments.py](../tools/nsx/segments.py) | EXPORT (optional PUSH) | `export` segments + segment↔group cross-reference. `push` is optional (only useful when target has matching transport zones). |
| [tools/nsx/membership.py](../tools/nsx/membership.py) | EXPORT | Auditing only: VM ↔ group correlation. Not consumed by any push step. |

> `--source` / `--target` are aliases resolved from `.env` (e.g. `NSX_LM1=nsx-lm1.lab.local`). Examples below use `nsx-lm1` → `nsx-lm2`.

---

## Env

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

PowerShell equivalent:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "$PWD\app"
```

---

## EXPORT — 7 commands, source-side, GET-only (run once)

```bash
python tools/nsx/capture_nsx_state.py --source nsx-lm1
python tools/nsx/services.py    export --source nsx-lm1
python tools/nsx/groups.py      export --source nsx-lm1
python tools/nsx/policies.py    export --source nsx-lm1
python tools/nsx/rules.py       export --source nsx-lm1
python tools/nsx/segments.py    export --source nsx-lm1
python tools/nsx/membership.py  export --source nsx-lm1
```

**`membership.py` is the highest-API-call-volume export.** It issues one
`/members/virtual-machines` query per customer group plus the
`build_vm_ip_index()` walk over every VM. Customer environments with
thousands of groups or a tight NSX rate limit can trip HTTP 429
("Too Many Requests"). Three knobs are exposed:

| Flag | Default | What it does |
|---|---|---|
| `--throttle-seconds N` | `0.2` | Seconds to sleep between per-group queries. Bump to `0.5` or `1.0` to pace large runs. `0` disables. |
| `--max-retries N` | `3` | How many times to retry a single call on 429 / 502 / 503 / 504 or a transient connection error. |
| `--backoff-base N` | `2.0` | Seconds base for exponential backoff. Attempt N waits `min(base * 2^(N-1), 60s)`. So defaults give ~2s, ~4s, ~8s between attempts. |

Example: pace conservatively for a customer-scale env that's previously hit rate limits:

```bash
python tools/nsx/membership.py export --source nsx-lm1 \
  --throttle-seconds 1.0 --max-retries 5 --backoff-base 3.0
```

The manifest (`nsx_membership_export/<host>/manifest.json`) records `retries_attempted` and `total_backoff_seconds` so you can see how hard NSX pushed back during the run. The default output directory is wiped on every run — re-running after a partial / rate-limited failure always produces a clean, complete bundle.

Outputs (overwritten each run when default `--output-dir` is used):

```
nsx_capture/<source-host>/
├── nsx_export/<source-host>/                  ← raw policy export
├── groups_additive/domains/default/groups/    ← Part 3 input — VM-IP-frozen groups (snapshot at capture time)
├── segment_inventory/segment_details.json     ← Parts 2 & 3 input — path → CIDR map
└── manifest.json, summary.txt, logs/, ...

nsx_services_export/<source-host>/services/<short-id>.yaml             + manifest.json + logs/
nsx_groups_export/<source-host>/groups/<short-id>.yaml                 + manifest.json + logs/
nsx_policies_export/<source-host>/security-policies/<short-id>/policy.yaml
                                                                       + manifest.json + logs/
nsx_rules_export/<source-host>/security-policies/<short-id>/rules/<seq>_<short-id>.yaml
                                                                       + manifest.json + logs/
nsx_segments_export/<source-host>/segments/<short-id>.yaml             + manifest.json + logs/
nsx_membership_export/<source-host>/{group_memberships,vm_group_membership,vm_ip_index}.json
                                                                       + manifest.json + logs/
```

Each export bundle writes its own `manifest.json` + `summary.txt` + `logs/` and a machine-readable `<type>.json` / `<type>.jsonl` for downstream consumption. Re-running is idempotent (default output dirs are wiped first).

### Review gates after EXPORT

- `nsx_capture/<host>/summary.txt` — all five sub-steps OK
- `nsx_capture/<host>/affected_rule_reports/affected_rules_impact.json` — which rules touch which groups (forensic, optional)
- Each per-tool `summary.json` shows: `written`, `errors`, `ids_with_special_chars`

---

## PUSH — target-side

> All pushes default to **dry-run**. Add `--apply` to actually write.
>
> Every `--apply` push **first** captures the target's pre-push state into
> `<reports_dir>/baselines/<RUN_TS>_target_baseline.json`. This baseline is
> what `revert` reads to undo the push.

### Part 1 — 1-for-1 clone with segments stripped

Pushes services, groups (with segment paths removed), policies, and rules
to the target.

```bash
python tools/nsx/services.py push --target nsx-lm2 \
  --services-dir nsx_services_export/nsx-lm1.lab.local/services \
  --apply

python tools/nsx/groups.py push --target nsx-lm2 \
  --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups \
  --segments-mode strip \
  --apply

python tools/nsx/policies.py push --target nsx-lm2 \
  --policies-dir nsx_policies_export/nsx-lm1.lab.local/security-policies \
  --apply

python tools/nsx/rules.py push --target nsx-lm2 \
  --rules-dir nsx_rules_export/nsx-lm1.lab.local/security-policies \
  --apply
```

After this phase, groups on the target have all non-segment expressions
intact (`Condition`, `IPAddressExpression`, references to other groups,
etc.). Segment-based PathExpressions have been removed.

### Part 2 — replace segment refs with their CIDR equivalents

Re-pushes groups, this time replacing each `/infra/segments/<id>`
PathExpression with an `IPAddressExpression` containing the segment's
native CIDR (looked up from `segment_details.json`).

```bash
python tools/nsx/groups.py push --target nsx-lm2 \
  --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups \
  --segments-mode convert \
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json \
  --apply
```

### Part 3 — add captured VM IPs to dynamic groups

Re-pushes groups using the `groups_additive/` bundle, which contains the
same groups but with VM-IP snapshots embedded. These IPs were captured on
the source at export time; **they are not re-resolved at push time**.

```bash
python tools/nsx/groups.py push --target nsx-lm2 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --segments-mode convert \
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json \
  --apply
```

This is what makes a dynamic (tag-based) group on the target match the
same VMs it matched on the source even though the target may have
different VMs / different membership-resolution behavior.

### Review gates after each push

- `summary.json` — counts of ok/failed/skipped, retry_rounds, fabric_paths_stripped
- `<tool>.jsonl` — per-row records
- `<tool>_push_<ts>.log` — interleaved INFO log of every PUT/PATCH
- `<tool>_push_<ts>.errors.log` — ERROR-only filtered file with tracebacks
- `failures.json` — present only when there were real failures (after retry exhaustion)
- `fabric_paths_stripped.json` — present only when any group had un-cloneable fabric refs stripped

---

## Safety nets baked into every push

These all fire automatically with no operator action; they're called out
here so you know what to expect when you see them in the logs/reports.

### Dependency-404 trap + retry

When a service nests another service, or a group nests another group, the
nested object may be pushed later in the iteration than its parent. NSX
returns a 404 saying "the requested object … could not be found." The
push tools **silently trap** these (no traceback dump), queue the row
with `status: failed_pending_retry`, and re-attempt after the main pass.
Up to 5 retry rounds, then any leftover pending rows promote to `failed`.

Surfaces in the log as:

```
[17/803  ok=16 fail=1 skip=0] FCB_Commvault_(Intra_Media_Agent) —
nested dep missing (404); PENDING RETRY (queued=1)
```

### Fabric-path strip (groups only)

Groups can reference host-transport-nodes, edge-TNs, edge-clusters,
transport-zones in their expressions (often vRNI-generated). These are
fabric objects bound to specific hardware on a specific manager — they
**cannot be cloned**. `groups.py push` detects any path matching the
fabric pattern, strips it from the group, lets the group land with
whatever's left (possibly empty), and writes a forensic record to
`fabric_paths_stripped.json` so an operator can rebuild membership
manually on the target if needed.

### Special-character object IDs

Every ID interpolated into a URL is URL-encoded via
`NsxPolicyClient._q()`. IDs containing parens, spaces, commas, etc.
push and revert cleanly without manual escaping.

### Windows MAX_PATH protection

All exported filenames go through `short_id_filename()` which produces
deterministic 22-ish-character filenames (`<first5>-<last5>-<8hex>.yaml`).
This keeps full paths under 260 chars even with deep `nsx_capture/...`
nesting.

---

## REVERT — reverse dependency order, LIFO baseline pop

> Each push captures a baseline before mutating. `revert --apply` pops the
> **most recent** unreverted baseline in the given `--reports-dir` and
> restores the target to that snapshot.

Run in reverse dependency order so a parent is never deleted before its
children:

```bash
# 1. rules (must precede policies — rules are children of policies)
python tools/nsx/rules.py revert --target nsx-lm2 \
  --reports-dir nsx_rules_export/nsx-lm1.lab.local/push_report \
  --apply

# 2. policies (parent of rules)
python tools/nsx/policies.py revert --target nsx-lm2 \
  --reports-dir nsx_policies_export/nsx-lm1.lab.local/push_report \
  --apply

# 3. groups Part 3 — additive baseline (in the nsx_capture path)
python tools/nsx/groups.py revert --target nsx-lm2 \
  --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report \
  --apply

# 4. groups Part 2 — pops the convert baseline (newer, LIFO)
python tools/nsx/groups.py revert --target nsx-lm2 \
  --reports-dir nsx_groups_export/nsx-lm1.lab.local/push_report \
  --apply

# 5. groups Part 1 — pops the strip baseline (older). Since the strip baseline
#    captured an empty target, this DELETES every group we pushed.
python tools/nsx/groups.py revert --target nsx-lm2 \
  --reports-dir nsx_groups_export/nsx-lm1.lab.local/push_report \
  --apply

# 6. services
python tools/nsx/services.py revert --target nsx-lm2 \
  --reports-dir nsx_services_export/nsx-lm1.lab.local/push_report \
  --apply
```

After the chain finishes, every `*_target_baseline.json` should be
renamed to `*_target_baseline.json.reverted`. You can verify with:

```bash
find nsx_*_export nsx_capture -path "*/push_report/baselines/*.json" -not -name "*.reverted" 2>/dev/null
# (empty output = clean revert stack)
```

---

## SEGMENTS — optional, only when the target has matching transport zones

```bash
python tools/nsx/segments.py push --target nsx-lm2 \
  --segments-dir nsx_segments_export/nsx-lm1.lab.local/segments \
  --apply

# Revert if needed
python tools/nsx/segments.py revert --target nsx-lm2 \
  --reports-dir nsx_segments_export/nsx-lm1.lab.local/push_report \
  --apply
```

Segments are environment-specific (different UUIDs and transport zones
per manager). In a typical lm1→lm2 migration, you do **not** push
segments; Parts 2 + 3 of the groups push handle segment-derived
membership by converting to CIDRs and adding captured VM IPs.

---

## Common questions

**Why split into per-object scripts instead of one monolithic push?**
Visibility and granularity. The legacy single-shot push (`push_from_capture.py`) handles services + groups + policies + rules in one process with one set of counters. At production scale (1000s of groups, 100s of policies), one failure cascades into thousands of dependent-object errors and the primary cause gets buried. With the broken-out flow you see exactly which class failed, with detailed per-row tracebacks, and you can re-run just that class.

**Why three parts instead of one push?**
Each part isolates a distinct transformation. Part 1 confirms the basic clone works without segment dependencies muddying the picture. Part 2 isolates segment-CIDR translation. Part 3 isolates captured-VM-IP freezing. If something breaks, you know which transformation was responsible.

**Can I run Part 3 alone (skipping Part 2)?**
Yes — Part 3's input (`groups_additive/`) is a strict superset of Part 2's. Running Part 3 directly after Part 1 gives you both the segment CIDRs AND the captured VM IPs in a single re-push. The split is for observability, not data dependency.

**What if a rule's parent policy isn't on the target yet?**
The dep-404 retry loop handles it automatically as long as the parent will be pushed during the same run. If the parent isn't in the export bundle at all, the rule lands in `failures.json` with the underlying NSX error.

**What if I want a re-IP at the same time as the clone (Workflow A + IP remap)?**
Add `--csv-remap data/<map>.csv` to the groups push. The CSV runs after segment-convert, so segment-derived CIDRs get remapped along with everything else. See [RUNBOOK_B.md](RUNBOOK_B.md) for CSV-remap mechanics — the flag works the same in Workflow A.

---

## File layout reference

```
nsx_capture/<source-host>/                     ← capture orchestrator output
├── nsx_export/<source-host>/                  ← raw policy dump
├── groups_additive/                           ← VM-IP-frozen groups (Part 3 input)
│   └── domains/default/groups/<short>.yaml
├── segment_inventory/segment_details.json     ← path → CIDR map (Parts 2&3 input)
├── affected_rule_reports/                     ← which rules touch which groups
├── vm_tag_inventory/                          ← VM tag dump
└── logs/, manifest.json, summary.txt

nsx_<class>_export/<source-host>/              ← per-tool exports
├── <class>/<short>.yaml                       ← object data
├── push_report/                               ← created on first push
│   ├── baselines/<RUN_TS>_target_baseline.json[.reverted]
│   ├── <class>_push_<ts>.log
│   ├── <class>_push_<ts>.errors.log
│   ├── summary.json, <class>.json, <class>.jsonl
│   ├── failures.json                          ← only if any real failures
│   └── fabric_paths_stripped.json             ← only if groups push stripped any fabric refs
├── manifest.json
└── logs/
```
