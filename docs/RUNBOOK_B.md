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
| [tools/nsx/capture_nsx_state.py](../tools/nsx/capture_nsx_state.py) | CAPTURE | Orchestrator: produces `groups_additive/` (the Workflow B push input) |
| [tools/nsx/groups.py](../tools/nsx/groups.py) | PUSH, REVERT | `push` with `--csv-remap`. `revert` pops the captured baseline. |

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
  "before_ip_count": 3,
  "after_ip_count":  7,
  "ips_before": ["10.7.0.50", "10.7.0.51", "10.7.1.0/24"],
  "ips_after":  ["10.6.0.50", "10.6.0.51", "10.6.0.52-10.6.0.53",
                 "10.6.1.0/24", "10.7.0.50", "10.7.0.51", "10.7.1.0/24"],
  "ips_added":   ["10.6.0.50", "10.6.0.51", "10.6.0.52-10.6.0.53", "10.6.1.0/24"],
  "ips_removed": [],
  "csv_added_count": 3
}
```

That's a self-contained replayable record per group — diff `ips_before` against `ips_after` and you have exactly what the push did.

### Push flags (Workflow B)

| Flag | Default | Purpose |
|---|---|---|
| `--target nsx-lm1` | (required) | Push target — for Workflow B, same as the capture source |
| `--groups-dir <bundle>` | (required) | Path to the groups directory inside the capture bundle |
| `--csv-remap <csv>` | off | Apply CSV subnet mapping to `IPAddressExpression` IPs. Strict-additive: originals kept, mapped values appended |
| `--mapped-only` | off | **Refused** when combined with `--csv-remap` (destructive mode is blocked by contract). Only meaningful without `--csv-remap` |
| `--bidirectional` | off | With `--csv-remap`: treat each CSV row as a bidirectional mapping |
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
- The push summary records `interactive_mode`, `interactive_batch_size_initial`, `interactive_batch_size_final`, and `interactive_exit_requested` so the audit trail captures what happened.

Example:

```bash
# Start cautious — one-at-a-time review
python tools/nsx/groups.py push --target nsx-lm1 \
  --groups-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/groups \
  --csv-remap data/nonprod_map.csv \
  --mapped-only \
  --batch-size 1 \
  --apply

# At the first prompt, type "25" to jump to 25-per-batch.
# Type "n" if a batch looked off — drops you back to 1.
# Type "x" to stop pushing remaining groups (already-applied changes stay, revert is available).
```

### Review gates after push

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
- A token (IP or CIDR) that doesn't fall inside any row is **not mapped**. With `--mapped-only` it's dropped; without it, the original is kept.

---

## B.3) Revert — restore `nsx-lm1` to its pre-push state

```bash
python tools/nsx/groups.py revert --target nsx-lm1 \
  --reports-dir nsx_capture/nsx-lm1.lab.local/groups_additive/domains/default/push_report \
  --apply
```

Each revert pops the most recent unreverted baseline file
(`<RUN_TS>_target_baseline.json`) and PUTs the captured payload back, plus
deletes anything that exists on the target but wasn't in the baseline.
After success, the baseline file is renamed `<RUN_TS>_target_baseline.json.reverted`.

If you've stacked multiple Workflow B pushes, each `revert` undoes the
latest. Repeat until you're back where you want to be:

```bash
# How many unreverted Workflow B baselines exist?
find nsx_capture/nsx-lm1.lab.local/groups_additive -path "*/baselines/*.json" -not -name "*.reverted"
```

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
      │          │       --csv-remap <csv> [--mapped-only]
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
