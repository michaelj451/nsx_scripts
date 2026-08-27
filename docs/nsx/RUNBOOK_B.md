# Runbook B — In-place CSV subnet remap on `nsx-lm1` (broken-out scripts)

## Summary

Workflow B operates **in-place against `nsx-lm1`** — no clone happens.
It's used to mutate `nsx-lm1`'s groups by re-IPing the IPs inside their
`IPAddressExpression` entries via a CSV subnet map. Groups-only; services,
policies, rules, and segments themselves are not touched.

| Pattern | What it does | Workflow B use case |
|---|---|---|
| **CSV IP remap** | Rewrite IPs inside existing `IPAddressExpression` entries via a subnet-mapping CSV. **Strict-additive contract**: originals are always preserved, mapped values are appended. `--mapped-only` is now refused when combined with `--csv-remap` (the destructive mode is unreachable via CSV remap). | Add the nonprod IP equivalents alongside prod IPs on the source manager |

The workflow is **two steps** with one human-review gate between them:

```text
1) capture_nsx_state.py                            (touches nsx-lm1, GET only)
        ↓  review the capture bundle
2) groups.py push --target nsx-lm1 --csv-remap ... (in-place PATCH on nsx-lm1)
        ↓  review the push report
3) groups.py revert --target nsx-lm1 ...           (optional, if you need to roll back)
```

Manager roles:

| Manager   | Role | NSX impact |
|-----------|------|------------|
| `nsx-lm1` | Source AND target — read for capture, PATCH at push | Read + groups-only PATCH (no services/policies/rules) |

Properties:

- **Source manager is only touched in two phases: capture, then push.** Everything between (`groups_additive` synthesis, CSV remap) is offline.
- Live VM membership is resolved by NSX at capture time and frozen to disk in `groups_additive/`.
- All transformations are deterministic and reviewable in the bundle before push.
- Dry-run is the default safe mode. `--apply` is required to actually mutate.
- Every push writes a `summary.json` + per-class JSON + log files into a `push_report/` directory and **captures a baseline** of the target's pre-push state for revert.

---

## Tools

| Tool | Used in | Purpose |
|---|---|---|
| [tools/nsx/capture_nsx_state.py](../../tools/nsx/capture_nsx_state.py) | CAPTURE | Orchestrator: produces `groups_additive/` (the Workflow B push input) |
| [tools/nsx/groups.py](../../tools/nsx/groups.py) | PUSH, REVERT | `push` with `--csv-remap`. `revert` pops the captured baseline. |

That's it. Workflow B is groups-only by design.

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

## B.1) Capture — read-only snapshot of `nsx-lm1`

```bash
python tools/nsx/capture_nsx_state.py --source nsx-lm1
```

Output bundle (everything Workflow B needs lives here):

```text
nsx_capture/nsx-lm1.lab.local/
├── manifest.json
├── summary.txt
├── nsx_export/<host>/                   ← raw NSX policy state
├── groups_additive/                     ← groups with captured (snapshot-at-export-time) VM IPs
│   └── domains/default/groups/<short>.yaml
├── segment_inventory/                   ← path → CIDR map (informational; not used by Workflow B)
│   └── segment_details.json
├── affected_rule_reports/                ← rules ↔ groups impact reference
├── vm_tag_inventory/
└── logs/
```

### Review gate after CAPTURE

- `summary.txt` — all sub-steps OK
- `manifest.json` — `"ok": true`
- `affected_rule_reports/affected_rules_impact.json` — which rules touch which groups you're about to mutate

---

## B.2) Push — in-place against `nsx-lm1`

### CSV IP remap (add mapped IPs alongside originals — strict-additive)

Rewrites every IP in `IPAddressExpression` entries using the CSV.
**Strict-additive by contract**: originals are kept, mapped values are
appended, **no IP is ever removed**. The destructive `--mapped-only`
flag is **refused** when combined with `--csv-remap` (the only way to
remove IPs is `groups.py revert`, which restores the auto-captured
baseline).

**Scope: IP-Addresses-Only groups by default.** The remap applies only to
groups with `group_type: IPAddress` (the GUI's "IP Addresses Only" type).
Generic groups, even ones containing only an IP list, are pushed with their
payload untouched, logged per group, and counted in `summary.json` as
`csv_generic_groups_skipped`. Pass `--remap-generic` to include generic
groups in the remap. The two types carry an identical `IPAddressExpression`
structure; the scope is a policy choice (a locked static list is safe to
rewrite mechanically, a generic group may be under dynamic management), not a
technical limitation.

When `--csv-remap` is in play, `--batch-size` **defaults to 1** so you
step through every change one at a time. Bump higher at any prompt as
confidence grows (`5`, `25`, `100`, `500` …). Type `n` to reset to 1.
Type `x` for a clean exit.

```bash
# Dry-run (default — safe, no writes)
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --csv-remap data/nonprod_map.csv

# Apply — defaults to --batch-size 1 (step through every group)
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --csv-remap data/nonprod_map.csv \
  --apply

# Or start at a higher batch size and bump from there at prompts
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --csv-remap data/nonprod_map.csv \
  --batch-size 10 \
  --apply
```

### Additive-only contract — what's enforced

Three independent guard rails make destruction by CSV remap operationally impossible:

1. **CLI rejection** — `--mapped-only` combined with `--csv-remap` exits non-zero before any NSX call.
2. **Per-row contract check** — if a row's diff shows `ips_removed > 0`, that group is **never** PATCHed. Marked `failed_contract_violation` with a clear error.
3. **End-of-run assertion** — the total `ips_removed` across all rows must be `0`. If anything slipped, exit code is non-zero and the log emits `ADDITIVE-ONLY contract: VIOLATED — N IP(s) removed across M violating row(s).`

The `summary.json` always carries:

```json
"totals": {
  ...
  "contract_violations": 0,
  "total_ips_removed": 0,
  "additive_only_contract": "pass"
}
```

If a violation is ever observed, the most likely cause is **drift between capture and push** — IPs were added to the target after the bundle was captured. Re-capture and re-run.

### Per-row before/after audit trail

Every row in `groups.json` / `groups.jsonl` carries the full IP state:

```json
{
  "id": "ip-address-group",
  "status": "success_patch",
  "before_ip_count": 4,
  "after_ip_count":  7,
  "ips_before": ["10.6.0.50", "10.6.0.51", "10.6.0.52-10.6.0.53", "10.6.1.0/24"],
  "ips_after":  ["10.6.0.50", "10.6.0.51", "10.6.0.52-10.6.0.53", "10.6.1.0/24",
                 "10.7.0.50", "10.7.0.51", "10.7.1.0/24"],
  "ips_added":   ["10.7.0.50", "10.7.0.51", "10.7.1.0/24"],
  "ips_removed": [],
  "csv_added_count": 3,
  "csv_skipped_values": [
    {"value": "10.6.0.52-10.6.0.53", "expression_index": 0, "reason": "range"}
  ]
}
```

Entries the remap deliberately leaves alone are listed under
`csv_skipped_values` with a reason (`range` or `ipv6`), and the run total is
in `summary.json` as `csv_total_skipped_values`. Valid IPv4 entries that no
CSV row covers are listed under `csv_unmapped_values`.

`ips_added` / `ips_removed` compare entries on canonical form, so
`10.6.0.101/32` on the target and `10.6.0.101` in the bundle are the same
entry: a format-only difference is never counted as a removal. The remap
itself never rewrites an existing entry (a `/32` stays a `/32`, and its
mapped value is emitted as a `/32` too).

That's a self-contained replayable record per group — diff `ips_before` against `ips_after` and you have exactly what the push did.

### Push flags (Workflow B)

| Flag | Default | Purpose |
|---|---|---|
| `--target nsx-lm1` | (required) | Push target — for Workflow B, same as the capture source |
| `--groups-dir <bundle>` | (required) | Path to the groups directory inside the capture bundle |
| `--csv-remap <csv>` | off | Apply CSV subnet mapping to `IPAddressExpression` IPs. Strict-additive: originals kept, mapped values appended |
| `--mapped-only` | off | **Refused** when combined with `--csv-remap` (destructive mode is blocked by contract). Only meaningful without `--csv-remap` |
| `--bidirectional` | off | With `--csv-remap`: treat each CSV row as a bidirectional mapping |
| `--remap-generic` | off | With `--csv-remap`: ALSO remap generic groups. Default scope is IP-Addresses-Only groups (`group_type: IPAddress`); generic groups are pushed untouched and counted as `csv_generic_groups_skipped` |
| `--segments-mode {keep,strip,convert}` | `keep` | For Workflow B, leave at `keep` (default) so segment refs in groups aren't disturbed |
| `--batch-size N` | `0` (off) | **Interactive batching.** Pauses every `N` applied updates, prints a compact per-group diff (status, +added/-removed IPs, segment/CSV/fabric notes), and prompts. Default `0` = fully automated. Set to `1` to step through every change; bump higher as confidence grows. Only takes effect with `--apply`. See below. |
| `--apply` | off | Required to actually mutate. Default is dry-run. |

### Interactive batch mode (`--batch-size N`)

Pass `--batch-size N` (any positive integer) to step through the push and
review what's changing before NSX is allowed to do more. Useful for a
first-run sanity pass on production-shaped data.

At each prompt the operator can answer:

| Input | Effect |
|---|---|
| `Y` / `y` / `<Enter>` | Approve the batch you just saw and continue at the current batch size |
| `n` / `no` | Continue, but **reset batch size to 1** (one-at-a-time going forward — be conservative) |
| `<positive integer>` | Continue with a **new** batch size (e.g. `25` to bump from `1`) |
| `x` / `exit` / `q` | **Stop cleanly** — finalize reports, write the baseline (revert still works on what landed), exit non-zero |

Each batch printout shows one line per applied group:

```
[1] netwo-k-6-0   success_patch   +2/-0 IPs   added=[10.7.0.101, 10.7.0.102]  csv_added=2
[2] vm1           success_patch   +3/-0 IPs   added=[10.7.0.101, 10.7.1.101, 10.7.2.101]  csv_added=3
[3] vm2           success_patch   +3/-0 IPs   added=[10.7.0.102, 10.7.1.102, 10.7.2.102]  csv_added=3
```

Notes:
- The diff is computed against the auto-captured baseline (state of each group BEFORE the push), so `added=` is exactly what NSX received that wasn't there before.
- If stdin is not a TTY (piped/non-interactive shell), prompts auto-approve at the current batch size to keep CI/test runs unblocked.
- The push summary records `interactive_mode`, `interactive_batch_size_initial`, `interactive_batch_size_final`, and `interactive_exit_requested`, plus `interactive_decisions`: the full confidence-ramp history, one record per prompt (`approve` / `resize` / `reset_to_1` / `exit` / `auto_approve_non_tty`, each with UTC timestamp, applied count, and batch size before/after). The same decisions are written to the run log, including the prompt text itself.
- Re-runs are zero-impact: a group whose diff shows nothing to add is `skipped_no_change` and **no API write is sent at all** (no PUT, no `_revision` bump, no realization cycle). Running the workflow 50 times yields one run of additions and 49 runs of pure GETs; `summary.json` counts these under `csv_no_change_skipped`.

Example:

```bash
# Start cautious — one-at-a-time review
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --csv-remap data/nonprod_map.csv \
  --batch-size 1 \
  --apply

# At the first prompt, type "25" to jump to 25-per-batch.
# Type "n" if a batch looked off — drops you back to 1.
# Type "x" to stop pushing remaining groups (already-applied changes stay, revert is available).
```

### Review gates after push

- `<push_report>/remap_report.md`: the human-readable report (header + result, what was added or would be added per group, what was left alone and why, never-remapped entries, CSV coverage misses, and the operator's batch-ramp decisions)
- `<push_report>/summary.json` — totals: ok / failed / skipped / dry_run / `csv_groups_changed` / `csv_total_added_values` / `retry_rounds`
- `<push_report>/groups.jsonl` — per-group rows
- `<push_report>/<tool>_push_<ts>.log` — interleaved INFO log
- `<push_report>/<tool>_push_<ts>.errors.log` — ERROR-only filtered file
- `<push_report>/fabric_paths_stripped.json` — present only if any group had host/edge-TN refs auto-stripped
- `<push_report>/baselines/<RUN_TS>_target_baseline.json` — pre-push snapshot used by revert

---

## CSV format

Each row: `old_subnet,new_subnet`. Longest-prefix match wins.

```csv
old_subnet,new_subnet
10.6.0.101/32,10.7.0.101/32
10.6.1.0/24,10.7.1.0/24
10.6.0.0/16,10.7.0.0/16
```

See `data/nonprod_map.csv` for the lab example.

- More-specific rows beat less-specific rows (the `/32` beats the `/24` which beats the `/16` when an IP is covered by all three).
- A token (IP or CIDR) that doesn't fall inside any row is **not mapped**; the original is kept and the token is listed in the row's `csv_unmapped_values`.
- **IP ranges (`a-b`) and IPv6 entries are never remapped.** They are left in place verbatim and listed in the row's `csv_skipped_values`. CSV rows that use a range or IPv6 are rejected at load and reported in `summary.json` under `csv_invalid_rows`.
- **Segment, path, and tag expressions are never remapped.** Only `IPAddressExpression` lists are touched; with the default `--segments-mode keep`, segment references pass through untouched.
- A CSV row whose `new_subnet` is smaller than its `old_subnet` (for example `/24` to `/25`) is rejected, because part of the old range would have nowhere to map. A duplicate `old_subnet` is rejected too (the first row wins).

---

## B.3) Revert — restore `nsx-lm1` to its pre-push state

```bash
python tools/nsx/groups.py revert --target nsx-lm1 \
  --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report \
  --apply
```

Each revert pops the most recent unreverted baseline file
(`<RUN_TS>_target_baseline.json`) and, by default, restores **only the groups
that push actually wrote**. The push records every group it PUT or PATCHed in
a companion file, `<RUN_TS>_pushed_ids.json`, updated after each successful
write (so an interrupted push still has an accurate list). Revert then:

- PUTs the baseline payload back for every pushed group that existed before the push;
- DELETEs any pushed group that did not exist in the baseline (the push created it);
- leaves every other group on the manager untouched, including any edits made since the push.

After success, both files are renamed `*.json.reverted`.

**Deletes are off by default.** Any group revert would DELETE (one the push
created, or with `--scope all` any customer group not in the baseline) is
left in place and listed in the revert summary as `deletes_blocked` unless
`--allow-delete` is given. `--scope all` refuses to run at all without it.

`--scope all` is the legacy full-baseline revert (PUT every baseline group back
and DELETE any customer group not in the baseline). It is required for
baselines captured before `pushed_ids.json` existed, and it will clobber
unrelated group changes made since the push, so dry-run it first. Note that a
restore is itself a removal of the IPs the push added; that is what revert is
for, and it stays behind `--apply`.

```bash
# Dry-run first: prints the restore / delete plan without writing
python tools/nsx/groups.py revert --target nsx-lm1 \
  --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report

# Legacy full-baseline revert (only for old baselines with no pushed_ids file)
python tools/nsx/groups.py revert --target nsx-lm1 \
  --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report \
  --scope all --apply
```

If you've stacked multiple Workflow B pushes, each `revert` undoes the
latest. Repeat until you're back where you want to be:

```bash
# How many unreverted Workflow B baselines exist?
find nsx_capture/nsx-lm1.lab.local/groups_additive -path "*/baselines/*.json" -not -name "*.reverted"
```

---

## B.4) Audit: what looks mapped, and what might be a gap

`audit_ip_remap.py` is the post-flight (and ongoing) check for an in-place
remap. It is **read-only** (one GET of the customer groups) and **never
proposes a removal**. Run it after a push, and on a schedule afterwards, with
the same CSV the push used:

```bash
# Local Manager
python tools/nsx/audit_ip_remap.py --target nsx-lm1 --csv data/nonprod_map.csv

# Global Manager
python tools/nsx/audit_ip_remap.py --target nsx-gm1 --federation-global --csv data/nonprod_map.csv

# Or from an export on disk (no NSX call at all)
python tools/nsx/audit_ip_remap.py --groups-dir nsx_groups_export/nsx-lm1.lab.local/groups --csv data/nonprod_map.csv
```

Output lands in `$NSX_LOG_DIR/reports/ip_remap_audit/<host>/<UTC ts>/`:
`ip_remap_audit.md` (the report), `ip_remap_audit.json` (per-group detail),
`gaps.json`, `summary.json`, and a log.

The report is ordered so the things that need eyes come first:

| Section | Contains | Meaning |
|---|---|---|
| **1a. Originals with no mapped equivalent** | original IP present, CSV maps it, mapped value absent (IP-only groups by default; all groups with `--include-generic`) | the remap did not reach this entry (check `failures.json` from the push) or it was added after the remap |
| **1b. Generic-group candidates** | CSV-covered originals sitting in GENERIC groups | informational, not gaps: the push skips generic groups by default. Shows exactly what a push with `--remap-generic` would add |
| **1c. Mapped-side values whose original is absent** | value inside a `new_subnet`, matching `old_subnet` value absent | original removed since the remap, or the value legitimately lived in the new range already; review, do not remove |
| **1d. IPv4 entries not covered by the CSV** | valid IPv4 entries no row covers | expected outside the remapped ranges; if one of these should map, the CSV needs a row |
| **2. Mapped** | `original -> mapped` pairs both present | what the remap achieved, with the CSV row that produced each pair |
| **3. Not remapped by design** | IP ranges and IPv6 | listed so nobody wonders why they were left alone |
| **4. Per-group status** | one line per group with IP entries | quick scan; flags groups whose IPs live in a `NestedExpression` (the remap never touches nested bodies, so covered entries there will sit in 1a) |

The audit's scope mirrors the push: by default only IP-Addresses-Only groups
are expected to be remapped, and generic-group misses land in 1b as
candidates. If the push ran with `--remap-generic`, audit with
`--include-generic` so those count as gaps in 1a instead.

Exit code is `1` when 1a or 1c is non-empty; candidates alone never trip it
(`--no-fail-on-gaps` to always return 0). It can run from cron and alert on
drift. Entries are compared on canonical form, so `10.6.0.1/32` and
`10.6.0.1` count as the same entry.

---

## Workflow diagram

```text
nsx-lm1 (source AND target)
      ▲          │
      │          │  B.1) capture_nsx_state.py
      │          ▼
      │     nsx_capture/nsx-lm1.lab.local/
      │        nsx_export/, groups_additive/, segment_inventory/, ...
      │          │
      │          │  B.2) groups.py push --target nsx-lm1
      │          │       --csv-remap <csv>  (ranges / IPv6 / segments never remapped)
      │          │       [--apply]
      └──────────┤
                 ▼
            <push_report>/
               summary.json, groups.jsonl, push.log, push.errors.log
               baselines/<ts>_target_baseline.json
               fabric_paths_stripped.json  (if any host/edge-TN refs auto-stripped)
                 │
                 │  B.3) groups.py revert --target nsx-lm1 (optional)
                 ▼
            <push_report>/baselines/<ts>_target_baseline.json.reverted
            + revert_summary_<ts>.json
```

---

## Safety characteristics

| Phase | Touches NSX? | What's touched |
|---|---|---|
| Capture | Yes — lm1, GET only | Policy + fabric GETs |
| Push (dry-run) | Yes — lm1, GET only | Reads baseline + reads files; logs every PATCH it would issue, doesn't send them |
| Push (apply) | Yes — lm1, PATCH | PATCH only the changed groups; services/policies/rules untouched |
| Revert (apply) | Yes — lm1, PUT/DELETE | Restores baseline payloads + deletes new groups; services/policies/rules untouched |

---

## Common questions

**Why is `--segments-mode keep` the default?**
Workflow B operates in-place on the source manager. Stripping or converting segment paths there would lose useful membership criteria. The default `keep` leaves segment references untouched.

**Can I combine Workflow A and Workflow B style transforms?**
Yes — `groups.py push` doesn't care about the labels. You can target lm2 with `--segments-mode convert --csv-remap …` for a re-IP at clone time.

**What if a CSV mapping conflicts (e.g., `10.6.0.0/16` and `10.6.0.0/24` both present)?**
Longest-prefix match wins. The `/24` is more specific, so a token like `10.6.0.50` matches the `/24` row, not the `/16`.

**Are nested-group dependency 404s and fabric-path strips still handled in Workflow B?**
Yes — same `groups.py push` code path. The retry trap for missing-dep 404s and the fabric-path auto-strip with forensic JSON both apply.

---

## File layout reference

```
nsx_capture/nsx-lm1.lab.local/                     ← capture bundle
├── nsx_export/nsx-lm1.lab.local/                  ← raw policy dump
├── groups_additive/                               ← Workflow B input
│   └── domains/default/groups/<short>.yaml
│       └── push_report/                           ← created on first B push
│           ├── baselines/<RUN_TS>_target_baseline.json[.reverted]
│           ├── groups_push_<ts>.log
│           ├── groups_push_<ts>.errors.log
│           ├── summary.json, groups.json, groups.jsonl
│           ├── failures.json                      ← only if real failures
│           └── fabric_paths_stripped.json         ← only if any host/edge-TN refs auto-stripped
├── segment_inventory/segment_details.json        ← informational; not used by Workflow B
├── affected_rule_reports/
├── vm_tag_inventory/
├── logs/, manifest.json, summary.txt
```
