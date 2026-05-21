# Runbook — Clone NSX (4 tools, 3 parts)

## Summary

Four single-purpose tools, run in a fixed order, clone an NSX manager's
customer-defined configuration to a target. The clone is **byte-for-byte
except for NSX-managed metadata** (the target regenerates that on its own)
and is broken into **three parts** so each phase can be verified before the
next one starts:

| Part | What it does | Why split |
|---|---|---|
| **1** | 1-for-1 copy of services, groups, policies, rules — **with segment refs stripped from groups** | Lets you confirm the structure landed cleanly before introducing any cross-manager dependencies |
| **2** | Re-push groups with **segment refs replaced by CIDR subnets** | Resolves segment dependencies that the target doesn't have natively |
| **3** | Re-push groups with **live-evaluated VM IPs added** (for dynamic / tag-based groups) | Freezes membership that only resolved on the source |

| Tool | Object class | Notes |
|---|---|---|
| [tools/nsx/services.py](tools/nsx/services.py) | services | one subcommand each: `export`, `push` |
| [tools/nsx/groups.py](tools/nsx/groups.py) | groups | `export`, `push` with `--segments-mode {keep,strip,convert}` and optional `--csv-remap` |
| [tools/nsx/policies.py](tools/nsx/policies.py) | security-policies (no rules) | `export`, `push` |
| [tools/nsx/rules.py](tools/nsx/rules.py) | security-rules (parent policy required) | `export`, `push` |
| [tools/nsx/segments.py](tools/nsx/segments.py) | segments | `export` (with segment↔group cross-reference), `push` (⚠ transport-zone refs are manager-specific) |

Plus two **shared** tools (export-only, GET-only):

- [tools/nsx/capture_nsx_state.py](tools/nsx/capture_nsx_state.py) — produces `segment_details.json` (Parts 2 & 3) and `groups_additive/` (Part 3).
- [tools/nsx/membership.py](tools/nsx/membership.py) — produces VM ↔ group correlation files: `group_memberships.json`, `vm_group_membership.json`, `vm_ip_index.json`. Auditing and verification only — not consumed by any push step.

> `--source` / `--target` are aliases resolved from `.env` (e.g. `NSX_LM1=nsx-lm1.lab.local`). Examples below use `nsx-lm1` → `nsx-lm2`.

---

## Env

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

---

## Capture once (provides segment data + live VM IPs needed by Parts 2 & 3)

```bash
# Source: nsx-lm1 → https://nsx-lm1.lab.local
python tools/nsx/capture_nsx_state.py --source nsx-lm1
```

Produces (the files we'll consume in Parts 2 & 3):

```
nsx_capture/nsx-lm1.lab.local/
├── groups_additive/domains/default/groups/...      ← live-VM-IP-frozen groups (Part 3 input)
├── segment_inventory/segment_details.json          ← path → CIDR map (Parts 2 & 3 input)
├── nsx_export/, vm_tag_inventory/, ...
└── manifest.json
```

---

## Export everything else (per-tool, source-side, GET-only)

```bash
python tools/nsx/services.py   export --source nsx-lm1
python tools/nsx/groups.py     export --source nsx-lm1
python tools/nsx/policies.py   export --source nsx-lm1
python tools/nsx/rules.py      export --source nsx-lm1
python tools/nsx/segments.py   export --source nsx-lm1    # segments + segment↔group cross-reference
python tools/nsx/membership.py export --source nsx-lm1    # VM↔group correlation (auditing)
```

Outputs (overwritten each run when the default path is used):

```
nsx_services_export/<source-host>/services/*.yaml          + manifest.json + logs/
nsx_groups_export/<source-host>/groups/*.yaml              + manifest.json + logs/
nsx_policies_export/<source-host>/security-policies/<slug>/policy.yaml
                                                          + manifest.json + logs/
nsx_rules_export/<source-host>/security-policies/<slug>/rules/0001_<slug>.yaml
                                                          + manifest.json + logs/
nsx_segments_export/<source-host>/
    segments/*.yaml                one file per segment (full payload)
    segment_to_groups.json         per-segment: which groups reference each segment
    group_to_segments.json         per-group:   which segments each group references
    + manifest.json + logs/
nsx_membership_export/<source-host>/
    group_memberships.json     [{group_id, display_name, members:[{vm_id,name,ips}], ...}, ...]
    vm_group_membership.json   [{vm_id, display_name, ips, groups:[...]}, ...]
    vm_ip_index.json           {"<vm_id>": ["10.6.0.50", ...], ...}
    + manifest.json + logs/
```

All four export tools:
- Skip NSX system-owned objects by default (`--include-system` to keep them).
- Strip NSX-managed read-only fields (`_create_time`, `_revision`, `unique_id`, etc.) before writing.
- Cap filenames at ~50 chars + hash suffix → Windows MAX_PATH-safe.
- Log a warning + record in `manifest.json` for every id containing chars outside `[A-Za-z0-9._-]` (parens, spaces, commas, etc.) so you know what'll be URL-encoded on push.

---

## PART 1 — services + groups (strip) + policies + rules

Four push commands in this order. Each one has a **dry-run by default** and `--apply` to actually mutate the target.

### 1a. Push services

```bash
# Target: nsx-lm2 → https://nsx-lm2.lab.local
python tools/nsx/services.py push \
  --target nsx-lm2 \
  --services-dir nsx_services_export/nsx-lm1.lab.local/services
# add --apply to actually write
```

### 1b. Push groups WITH SEGMENT REFS STRIPPED

```bash
python tools/nsx/groups.py push \
  --target nsx-lm2 \
  --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups \
  --segments-mode strip
# add --apply to actually write
```

The strip step:
- Drops `/(global-)?infra/segments/<id>` paths from any `PathExpression` (including sub-paths like `.../ports/<x>`).
- Drops the whole `PathExpression` if its `paths` list becomes empty.
- Removes orphan `ConjunctionOperator` entries adjacent to a dropped `PathExpression` so NSX accepts the payload.
- Leaves `Condition`, `IPAddressExpression`, `MACAddressExpression`, `NestedExpression`, and non-segment `PathExpression` entries untouched.

### 1c. Push policies (no rules — they come next)

```bash
python tools/nsx/policies.py push \
  --target nsx-lm2 \
  --policies-dir nsx_policies_export/nsx-lm1.lab.local/security-policies
# add --apply to actually write
```

NSX defaults (`default-layer2-section`, `default-layer3-section`) are skipped automatically.

### 1d. Push rules

```bash
python tools/nsx/rules.py push \
  --target nsx-lm2 \
  --rules-dir nsx_rules_export/nsx-lm1.lab.local/security-policies
# add --apply to actually write
```

Rules must come AFTER their parent policy lands — otherwise NSX returns `[HTTP 404] dependent objects … does not exist`. Each rule YAML records its parent policy id via the `_parent_policy_id` field (set by export) and the parent-folder slug.

### Review gate — Part 1 complete

At this point nsx-lm2 has the complete 1-for-1 clone **minus segment refs**. Spot-checks:

- Object counts on lm2 match what you exported (compare `manifest.json` files)
- No `failed` rows in any of the four `push_report/summary.json` files
- `validate_nsx_groups_live.py --target nsx-lm2 --expected-root nsx_groups_export/nsx-lm1.lab.local/groups` returns 0 diffs

---

## PART 2 — add segment CIDRs back to groups

Re-push groups with `--segments-mode convert`. The conversion replaces each segment `PathExpression` ref with an `IPAddressExpression` containing the segment's CIDRs (from `subnets[].network`), read offline from the capture's `segment_details.json`.

```bash
python tools/nsx/groups.py push \
  --target nsx-lm2 \
  --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups \
  --segments-mode convert \
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json
# add --apply to actually write
```

Each group exists on lm2 from Part 1's strip pass, so PUT returns `500127 "already exists"`, the tool falls back to PATCH, and the PATCH replaces the group's `expression` with the converted payload. On NSX, a Group's `expression` is replaced wholesale by PATCH — so this single re-push restores the original structure with segment refs translated to CIDRs.

**Expected log fields** (in the per-group rows and summary):

```
segment_paths_seen    = N    ← how many segment refs were found in source YAMLs
segments_converted    = N    ← how many resolved to CIDRs (should match seen)
segments_unresolved   = 0    ← if > 0, segment_details.json was missing entries; re-capture
```

---

## PART 3 — add live VM IPs to groups

Re-push groups but read from the **additive** tree produced by `capture_nsx_state.py` — those YAMLs already have an `IPAddressExpression` of live-evaluated VM IPs appended for each dynamic/tag-based group. Keep `--segments-mode convert` so segments stay translated to CIDRs in the same payload.

```bash
python tools/nsx/groups.py push \
  --target nsx-lm2 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --segments-mode convert \
  --segments-from nsx_capture/nsx-lm1.lab.local/segment_inventory/segment_details.json
# add --apply to actually write
```

What's different from Part 2:

- `--groups-dir` points at `groups_additive/` instead of the raw export.
- The additive YAMLs are a strict superset of the raw export — same Conditions, same hard-coded IPs, plus an extra `IPAddressExpression` with the live VM IPs.
- After this PATCH, dynamic/tag-based groups on lm2 contain frozen IPs that resolved against lm1's VMs — independent of whether lm2 has any VMs at all.

---

## Workflow B equivalent (in-place CSV subnet remap)

If your goal is to PATCH groups on lm1 (or any target) with a CSV-driven IP remap, `groups.py` has it natively:

```bash
python tools/nsx/groups.py push \
  --target nsx-lm1 \
  --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups \
  --csv-remap data/nonprod_map.csv \
  --mapped-only
# add --apply to actually write
```

| Flag | Effect |
|---|---|
| `--csv-remap <csv>` | Apply longest-prefix subnet match using the CSV's `old_subnet,new_subnet` rows |
| `--mapped-only` | Replace each `IPAddressExpression` with ONLY the mapped values (drop originals). Default: append mapped, keep originals |
| `--bidirectional` | Treat each row as a bidirectional mapping (also remap new→old) |

CSV remap composes with `--segments-mode` — e.g., `--csv-remap CSV --segments-mode convert --segments-from <…>` does both transformations in one push.

---

## Using membership data for verification

`membership.py export` doesn't push anything — it produces three correlation files that let you answer auditing questions before, during, or after a clone:

```bash
# Which VMs are members of group "vm-group-1"?
python3 -c "
import json
g = next(x for x in json.load(open('nsx_membership_export/nsx-lm1.lab.local/group_memberships.json'))
          if x['group_id'] == 'vm1')
for m in g['members']:
    print(f'{m[\"display_name\"]:40s}  {m[\"ips\"]}')
"

# Which groups does VM 'web-server-3' belong to?
python3 -c "
import json
v = next(x for x in json.load(open('nsx_membership_export/nsx-lm1.lab.local/vm_group_membership.json'))
          if x['display_name'] == 'web-server-3')
print(v['groups'])
"

# Which VM owns IP 10.6.0.50?
python3 -c "
import json
ix = json.load(open('nsx_membership_export/nsx-lm1.lab.local/vm_ip_index.json'))
for vid, ips in ix.items():
    if '10.6.0.50' in ips: print(vid, ips)
"

# Which groups reference segment <id>?
python3 -c "
import json
s2g = json.load(open('nsx_segments_export/nsx-lm1.lab.local/segment_to_groups.json'))
for sid, groups in s2g.items(): print(f'{sid}: {groups}')
"

# Which segments does group X reference?
python3 -c "
import json
g2s = json.load(open('nsx_segments_export/nsx-lm1.lab.local/group_to_segments.json'))
print(g2s.get('segment-group-1'))
"
```

After Phase 4 (the live-VM-IPs push), you can verify by re-running `membership.py export` against the **target** (lm2) and diffing its `group_memberships.json` against the source's — the VM ids will differ (lm2 doesn't have the same VMs) but the per-group IP lists should match.

---

## Live progress format (all four tools)

```
[N/M  ok=X  fail=Y  skip=Z]  <object-id>  —  success_put / success_patch / FAILED: ...
```

Outcome tokens:
- `success_put` — PUT accepted (created on target)
- `success_patch` — PUT returned `500127`/`500071`, tool retried with PATCH and that worked
- `FAILED: <reason>` — captured in the row's `error` field
- `skip` — file had no `id`, was `manifest.json`/`summary.json`, or parent policy was a default

For `groups.py` with `--segments-mode strip`/`convert`, each row also reports `segments_seen=N converted=N unresolved=N`. With `--csv-remap`, rows also include `csv_changed=true/false csv_added_count=N`.

For `rules.py`, the row format is `[N/M ok=X fail=Y skip=Z] <policy-id>/<rule-id> — outcome`.

---

## Per-run reports (all four tools)

Each tool drops the same artifacts under `<input-dir>/../push_report/`:

```
push_report/
├── <tool>_<phase>_<UTC_TS>.log           ← full INFO+ log (every per-object line)
├── <tool>_<phase>_<UTC_TS>.errors.log    ← ERROR-only, full Python tracebacks
├── summary.json                          ← totals + target + log file paths
├── <objects>.json                        ← one row per object processed
├── <objects>.jsonl                       ← same data, one row per line (grep/jq)
└── failures.json                         ← only created when failures occurred
```

Each `failed` row in the JSON reports has:
- `error` — short message (e.g. `[HTTP 400] PUT … failed: 400 {…}`)
- `error_type` — exception class (`NsxApiError`, `ValueError`, etc.)
- `traceback` — full Python stack trace as a multi-line string

Failure triage:
1. Open `summary.json` for counts
2. `failures.json` is the actionable list
3. The per-run `.errors.log` has the original sequence and full tracebacks

---

## Special-character handling

NSX object ids can legally contain `(`, `)`, ` `, `,`, `&`, `+`, `'`, etc. (e.g. `App_00731__-_PCFS_Loan_Manager_(Ext_servers_1)`). The toolkit handles these in two places:

1. **URL encoding before every NSX call.** The NSX client's `_q()` helper (in [app/nsx/nsx_policy_client.py](app/nsx/nsx_policy_client.py)) percent-encodes every id before it's interpolated into the URL path. Applied to all 38 PUT/PATCH/DELETE/GET sites. Lab-verified with a parens-in-id group cloning end-to-end.

2. **Export-time warnings.** Each export tool logs a warning AND records in `manifest.json` for every id outside `[A-Za-z0-9._-]`:

   ```json
   "counts": { "ids_with_special_chars": 3 },
   "ids_with_special_chars": [
     {"id": "App_00731__-_PCFS_Loan_Manager_(Ext_servers_1)", "display_name": "..."},
     ...
   ]
   ```

Filenames on disk are filesystem-safe regardless — slugified + `__<8-char-id-prefix>` suffix preserves uniqueness without inheriting raw special chars.

---

## Rollback — per-tool `revert` subcommand

Each push tool (`services.py`, `groups.py`, `policies.py`, `rules.py`, `segments.py`) has a built-in `revert` subcommand. Here's how it works:

### Auto-baseline on every `push --apply`

Before any PUT/PATCH lands, the tool fetches the target's current customer objects of its class and writes them to a **timestamped baseline file**:

```
nsx_<obj>_export/<host>/push_report/baselines/<UTC_TS>_target_baseline.json
```

Each subsequent `push --apply` appends a NEW baseline (does not overwrite previous ones). This forms a **baseline stack**: most recent at the top, oldest at the bottom.

### `revert` pops the most recent baseline

```bash
python tools/nsx/<tool>.py revert --target nsx-lm2 [--apply]
```

What it does:
1. Finds the most recent unreverted baseline in `push_report/baselines/`
2. Fetches the CURRENT customer objects on the target
3. Computes the diff:
   - Objects in baseline → PUT/PATCH back (restores any modifications)
   - Objects on target NOT in baseline → DELETE (undoes any creations)
4. After successful revert, renames the baseline file with `.reverted` suffix so the next `revert` pops the next-most-recent
5. Skips NSX system-owned objects and default policies

Dry-run by default; pass `--apply` to actually mutate.

### Reverting a multi-phase groups workflow

Because groups gets pushed 3 times (Part 1 strip → Part 2 convert → Part 3 additive), each push appends a baseline. Reverts pop in LIFO order:

| Action | Baseline state captured at push | What revert undoes |
|---|---|---|
| `groups.py push ... --segments-mode strip --apply` | Empty target | Push 1 (would DELETE all groups on revert) |
| `groups.py push ... --segments-mode convert --apply` | Groups in "stripped" state | Push 2 (restores to stripped state on revert) |
| `groups.py push ... --groups-dir <additive> ... --apply` | Groups in "converted" state | Push 3 (restores to converted state on revert) |

**Note:** Phase 3 (`--groups-dir nsx_capture/<host>/groups_additive/...`) writes its baseline to a DIFFERENT `push_report/` than Phase 1/2 (because reports_dir defaults to `<groups-dir>/../push_report/`). Phase 1 and Phase 2 share the same stack (under `nsx_groups_export/<host>/push_report/`); Phase 3 has its own (under `nsx_capture/<host>/groups_additive/domains/default/push_report/`). To revert Phase 3 you point `--reports-dir` at the additive bundle's push_report; to revert Phase 2 then Phase 1, two consecutive reverts against the export bundle's push_report.

### Recommended revert order for a full teardown

Reverse dependency order — rules reference policies reference groups reference services:

```bash
# 1. Rules
python tools/nsx/rules.py revert --target nsx-lm2 \
  --reports-dir nsx_rules_export/nsx-lm1.lab.local/push_report --apply

# 2. Policies (after rules are gone)
python tools/nsx/policies.py revert --target nsx-lm2 \
  --reports-dir nsx_policies_export/nsx-lm1.lab.local/push_report --apply

# 3. Groups Phase 3 (pops the additive baseline; restores to "convert" state)
python tools/nsx/groups.py revert --target nsx-lm2 \
  --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report --apply

# 4. Groups Phase 2 (pops the convert baseline; restores to "strip" state)
python tools/nsx/groups.py revert --target nsx-lm2 \
  --reports-dir nsx_groups_export/nsx-lm1.lab.local/push_report --apply

# 5. Groups Phase 1 (pops the strip baseline; baseline was empty target → DELETEs all groups)
python tools/nsx/groups.py revert --target nsx-lm2 \
  --reports-dir nsx_groups_export/nsx-lm1.lab.local/push_report --apply

# 6. Services
python tools/nsx/services.py revert --target nsx-lm2 \
  --reports-dir nsx_services_export/nsx-lm1.lab.local/push_report --apply
```

(If you only ran Parts 1 + 2 + 4 + 5 of the clone — skipping Parts 2/3 — adjust accordingly.)

### Revert reports

Each `revert --apply` writes:

```
push_report/
├── revert_summary_<UTC_TS>.json        totals: restored_ok, restored_failed, deleted_ok, deleted_failed
├── revert_actions_<UTC_TS>.jsonl       one row per restored/deleted object
├── <tool>_revert_<UTC_TS>.log          full progress log
├── <tool>_revert_<UTC_TS>.errors.log   ERROR-only, with tracebacks
└── baselines/
    ├── <UTC_TS>_target_baseline.json            ← unreverted baselines (FIFO)
    └── <UTC_TS>_target_baseline.json.reverted   ← already-reverted (kept for audit)
```

### Edge cases

- **Failed revert:** if `--apply` revert fails mid-way, the baseline file is NOT renamed to `.reverted` (only renamed on success). Re-run after fixing the underlying issue.
- **Explicit baseline:** `--from-baseline <path>` lets you revert to a specific snapshot (skips the auto-stack).
- **Multiple targets:** baselines are per-target — `revert --target nsx-lm3` is a separate stack from `--target nsx-lm2`. (Implementation: the baseline file doesn't encode the target; if you push to multiple targets from the same reports_dir, use separate `--reports-dir` per target.)
- **Stale baselines:** since the baseline captures the target's state at push time, if anything else mutated the target between push and revert, those changes get clobbered. Revert is "restore to baseline," not "diff and merge."

---

## Common questions

**Why split into 4 tools instead of using `push_from_capture.py`?**
Visibility and granularity. The single-shot push handles services + groups + policies + rules in one process with one set of counters. At production scale (1000s of groups, 100s of policies), one failure cascades into thousands of dependent-object errors and the primary cause gets buried. With the four-tool flow you see exactly which class failed, with detailed per-row tracebacks, and you can re-run just that class.

**Why three parts instead of one push of the full payload?**
Same reason. Part 1 confirms the basic clone works without segment dependencies muddying the picture. Part 2 isolates segment-CIDR translation. Part 3 isolates live-VM-IP freezing. If something breaks, you know which transformation was responsible.

**Can I run Part 3 alone (skipping Part 2)?**
Yes — Part 3's input (`groups_additive/`) is a strict superset of Part 2's. Running Part 3 directly after Part 1 gives you both the segment CIDRs AND the live VM IPs in a single re-push. The split is for observability, not data dependency.

**Can I push only to a subset of policies/groups/etc.?**
Today the tools push every file under the directory you point them at. To push a subset, copy the YAMLs you want into a side directory and pass that as `--policies-dir` / `--rules-dir` / etc. Per-object selection flags could be added if needed.

**What if a rule's parent policy isn't in the target's known policies?**
NSX returns `[HTTP 404]` with error_code `500232` (`Following dependent objects … does not exist`). The row is marked `failed` in `rules.json` and re-runnable after the policy is pushed. Same applies to rules referencing groups that haven't been pushed yet — push order matters.

**What happens to `NestedServiceServiceEntry`-style dependencies between services?**
Service files are iterated in lexical order. If service A nests service B and B hasn't been pushed yet, A gets `500232` and is marked failed. Re-run `services.py push --apply` after B lands. (Topological-sort by dependency could be added — not built today.)

---

## Inner tools / NSX client methods

| Tool | Calls |
|---|---|
| `services.py`  | `list services`, `put_service`, `patch_service` |
| `groups.py`    | `list groups`, `put_group`, `patch_group` |
| `policies.py`  | `list security-policies`, `put_security_policy`, `patch_security_policy` |
| `rules.py`     | `list security-rules` (per policy), `put_security_rule`, `patch_security_rule` |
| `capture_nsx_state.py` | composes `export_nsx_objects`, `build_group_ip_additive_from_live_members`, `find_segments_referenced`, others — all GET-only |

All requests go through `app/nsx/nsx_policy_client.py` which URL-encodes every id segment before interpolating into the path.
