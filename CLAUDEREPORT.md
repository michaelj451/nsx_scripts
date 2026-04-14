# NSX Global Manager — Parallel Datacenter Migration: Script Analysis Report

**Generated:** 2026-04-09
**Branch:** `push_lab`
**Prepared by:** Claude (claude-sonnet-4-6)

---

## Executive Summary

This repository is a Python toolset for a **zero-downtime, zero-destructive parallel datacenter migration** in VMware NSX. Scripts migrate IP address memberships in NSX Policy security groups from old subnets to new subnets, driven by a CSV mapping file. The workflow is designed to be:

- **Non-destructive** — original IPs are never removed until an explicit rollback or conversion
- **Idempotent** — safe to run multiple times; duplicates are not introduced
- **Fully reversible** — a dedicated rollback script restores any manager from a pre-migration export snapshot
- **CAB-ready** — dry-run modes, checkpoint prompts, and per-operation pacing enable reviewed production execution

---

## Architecture Overview

```
data/subnet_map.csv
        │
        ▼
app/nsx/nsx_object_functions/nsx_group_remap.py   ← Core IP remapping library
        │
        ├─► tools/nsx/add_mapped_ips_to_groups_files.py  (Step 2: build additive files)
        │
        ├─► tools/nsx/push_remapped_groups.py            (Steps 3–4: push to NSX)
        │
        ├─► tools/nsx/push_nsx_groups_revert.py          (Step 5a/b: rollback)
        │
        ├─► tools/nsx/validate_nsx_groups.py             (Step 5a: push validation)
        ├─► tools/nsx/validate_nsx_groups_live.py        (Final: live validation)
        │
        ├─► tools/nsx/export_nsx_objects.py              (Step 1: snapshot export)
        │
        └─► tools/nsx/find_rules_affected_by_group_changes.py  (Impact analysis)

app/nsx/nsx_policy_client.py   ← NSX REST API client
app/nsx/cli_bootstrap.py       ← Credentials/config bootstrap (.env)
```

---

## Script-by-Script Analysis

---

### Step 0 — Environment Setup
**Command:** `python3 -m venv .venv && pip install -r docker/requirements-pip.txt`

Sets up a Python virtual environment and installs dependencies. `PYTHONPATH` is set to `$PWD/app` so that internal modules (`nsx.*`) resolve correctly. No NSX connectivity at this stage.

---

### Step 1 — `export_nsx_objects.py`

**Purpose:** Captures a full point-in-time snapshot of NSX Policy objects before any changes.

**What it does:**
- Authenticates to a target NSX manager (`nsx-gm1`, `nsx-gm2`, or `nsx-lm3`) via `.env` credentials
- Lists all domains (or a specific domain with `--domain-id`)
- Exports groups, services, security policies, and rules to `nsx_export/<manager-hostname>/` as YAML or JSON files
- Purges stale output directories before writing fresh exports (prevents stale data from contaminating the snapshot)

**How it does it:**
- `NsxPolicyClient` issues GET requests to the NSX Policy REST API
- A built-in throttle wrapper limits GET requests to **5 requests/second** (`THROTTLE_INTERVAL_S = 1.0 / 5`) to avoid overwhelming the NSX manager
- Output is organized by manager hostname → domain → object type (groups, services, policies/rules)
- After export, object counts (groups, services, policies, rules) are logged and printed as JSON

**Safety measures:**
- Read-only: only GET operations, zero writes to NSX
- Throttling prevents API rate-limit errors
- Pre-export directory purge ensures the snapshot is clean and not mixed with prior runs
- Credentials come from `.env`, never from CLI arguments

---

### Step 2 — `add_mapped_ips_to_groups_files.py`

**Purpose:** Builds the additive group files — updated versions of the exported groups where **new mapped IPs are appended alongside the originals**.

**What it does:**
- Reads `data/subnet_map.csv` (columns: `old_subnet`, `new_subnet`, `vlan`, `description`)
- Scans all `*.yml`/`*.yaml`/`*.json` group files under `nsx_export/`
- For every `IPAddressExpression.ip_addresses` token that falls within a mapped old subnet, appends the corresponding new-subnet IP/CIDR/range
- Writes updated files to `nsx_groups_additive/` preserving the original directory structure
- Never removes an IP — the result contains both old and new addresses

**How it does it (core library: `nsx_group_remap.py`):**
- **Token classification:** each entry is classified as `ip_address`, `subnet` (CIDR), or `ip_range` (e.g. `10.1.0.1-10.1.0.10`)
- **Remapping logic:**
  - IP ranges: both endpoints must fall in the same subnet mapping; if they do, both are offset-remapped to the new subnet
  - CIDRs: matched exactly to a mapping or as a subnet-of; offset-preserving translation applied
  - Individual IPs: offset from the old subnet network address is preserved in the new subnet
- **Deduplication:** `_dedupe_preserve_order` ensures no duplicate tokens are written, making runs idempotent
- **JSON roundtrip copy:** `convert_groups_in_doc` deep-copies via `json.loads(json.dumps(...))` before mutation to avoid corrupting the original in-memory object

**Safety measures:**
- `--dry-run` flag: analyses and logs all changes without writing any output files
- `--no-clean` flag: by default the output directory is wiped before writing to ensure no stale files remain; `--no-clean` skips this
- Input validation: CSV is checked for required headers (`old_subnet`, `new_subnet`) and file existence before any processing begins
- IP version mismatch check: an old IPv4 subnet cannot be mapped to an IPv6 subnet
- Only `IPAddressExpression.ip_addresses` arrays are mutated — no other group fields are touched
- Full per-run snapshot written to `nsx_logs/nsx_snapshots/<ts>_add_mapped_ips_<mode>/snapshot.json` with before/after IP lists per group
- JSONL change log (`nsx_group_remap_changes.jsonl`) records every individual IP add/remove with timestamp, group ID, and expression ID
- IP range events (ranges that could not be remapped due to cross-subnet overlap) are reported in a separate `ip_range_summary_<ts>.json`
- Parse errors skip the file and log a warning rather than aborting the entire run

---

### Steps 3–4 — `push_remapped_groups.py`

**Purpose:** Pushes the additive group files built in Step 2 to a target NSX manager via the Policy REST API.

**What it does:**
- Reads updated group files from `nsx_groups_additive/` (or a custom `--input-dir`)
- Compares each group's IP membership against both the target NSX state (live fetch) and a baseline export
- PATCHes groups that differ from the expected state via `NsxPolicyClient.patch_group()`
- Supports targeting Global Manager (`--federation-global`) or Local Manager domains (`--domain-id`)

**How it does it:**
- Dry-run is the **default** — `--apply` must be explicitly passed to make changes
- Per-group diffs are computed showing `to_add`, `to_remove`, and `already_present` IP entries before any PATCH
- A `GroupImportConfig` / `NsxGroupImporter` layer handles per-group validation and patch orchestration

**Safety measures:**
- **Default dry-run**: no changes unless `--apply` is passed
- **Rate pacing**: `GROUP_PATCH_INTERVAL_SECONDS = 0.5` — a minimum half-second delay between consecutive PATCH operations
- **Operator checkpoints**: `APPLY_PROMPT_EVERY_N_UPDATES = 1` — the operator is prompted after every single update when starting; they can then increase the batch size interactively (e.g. to 5, 10, 20)
- **Dry-run review cadence**: `PROMPT_EVERY_N_UPDATES = 100` — prompts every 100 groups during a dry-run walkthrough
- **Baseline comparison**: groups are diffed against the pre-migration export to surface unexpected state before pushing
- Credentials loaded from `.env`, never passed as CLI arguments

---

### Step 5a/b — `push_nsx_groups_revert.py`

**Purpose:** Full rollback — restores NSX group membership to the pre-migration snapshot state.

**What it does:**
- Loads group payloads from the original `nsx_export/` snapshot
- Fetches the current live state from the target NSX manager
- Computes a diff per group: `to_add`, `to_remove`, `already_present`
- PATCHes groups back to their snapshot state
- Optionally deletes groups that exist in NSX but are absent from the snapshot (`--delete-extraneous`)
- Writes a validation report JSON after each run

**How it does it:**
- Strips NSX server-managed metadata (`_create_time`, `_revision`, `realization_id`, etc.) before PATCHing so the API accepts the payload cleanly
- Groups are processed in sorted ID order for deterministic, reproducible execution
- Hard no-op safeguard: if a group already matches the desired (snapshot) state exactly, it is skipped — no unnecessary PATCHes

**Safety measures:**
- **Default dry-run**: `--apply` required to make any changes
- **Rate pacing**: `GROUP_PATCH_INTERVAL_SECONDS = 0.5` between each PATCH
- **Fine-grained operator prompting**: same checkpoint model as push — `APPLY_PROMPT_EVERY_N_UPDATES = 1` means the operator approves each individual restore operation to start; can increase batch size interactively
- **Per-item skip option**: each prompt accepts `y` (apply), `s` (skip this group), or `n` (abort entirely)
- **No-change guard**: existing groups with no IP delta are silently skipped — avoids touching objects unnecessarily
- **Delete-extraneous is opt-in**: `--delete-extraneous` must be explicitly passed; by default, extra groups in NSX are left alone
- **Validation report**: every run writes a JSON summary to `nsx_logs/nsx_validation/<ts>_<target>_revert_validate/validation_report.json` detailing every group's before/after state, counts, and whether changes were needed
- Operator abort raises `KeyboardInterrupt` → caught at main() → clean `SystemExit(130)` (standard SIGINT exit code)

---

### Validation — `validate_nsx_groups.py` / `validate_nsx_groups_live.py`

**Purpose:** Post-push or post-rollback verification that the live NSX state matches expected files.

**What it does:**
- `validate_nsx_groups.py` — compares a local expected-root directory against the live NSX API state for a given manager and domain
- `validate_nsx_groups_live.py` — final live validation; compares the live state to the additive output files as the source of truth

Both scripts produce pass/fail output per group and overall summary counts.

**Safety measures:**
- Read-only: only GET operations against NSX
- Explicit `--target`, `--expected-root`, `--baseline-root`, and `--domain-id` arguments prevent accidental cross-environment validation

---

### Impact Analysis — `find_rules_affected_by_group_changes.py`

**Purpose:** Pre-change impact assessment — identifies which NSX security policy rules reference groups that will be modified.

**What it does:**
- Compares additive group files (`nsx_groups_additive/`) against the export baseline (`nsx_export/`)
- Identifies which security policies and rules reference the modified groups
- Outputs a report to `nsx_logs/affected_rule_reports/`
- `--verbose` flag produces detailed per-rule output

**Safety measures:**
- Read-only: operates entirely on local files, no NSX API calls
- Designed to be run **before** pushing changes as a pre-flight check

---

## Core Library — `nsx_group_remap.py`

This shared library is the heart of the remapping logic. Key behaviors:

| Function | Behavior |
|---|---|
| `read_csv_mappings()` | Validates CSV headers, parses subnets with `ipaddress`, checks IP version consistency, sorts by prefix length (most specific first) |
| `remap_token()` | Remaps a single IP/CIDR/range token; returns original unchanged if no mapping found |
| `add_mapped_ip_addresses_additive()` | Keeps all originals, appends mapped tokens not already present |
| `remap_ip_addresses_new_only()` | Keeps only mapped tokens, drops unmapped ones |
| `_dedupe_preserve_order()` | Removes duplicates while preserving original token order |
| `_log_ip_list_changes()` | Logs every IP add/remove to both the logger and JSONL change file |
| `load_doc()` / `write_output()` | Safe YAML (`yaml.safe_load`) and JSON I/O; rejects unsupported file extensions |

---

## Safety Model Summary

| Control | Mechanism |
|---|---|
| Default dry-run | All push/revert scripts default to read-only preview; `--apply` required for changes |
| Rate pacing | 0.5s minimum between consecutive PATCH operations across all write scripts |
| Operator checkpoints | Interactive y/n/s prompts after configurable batch sizes; operator can ramp or abort at any time |
| No-change guard | Groups with no IP delta are skipped — idempotent execution |
| Pre-export snapshot | Full NSX state captured to local files before any changes, enabling diff and rollback |
| Immutable originals | Additive mode never removes IPs from groups; rollback restores from snapshot |
| JSONL audit trail | Every individual IP add/remove is timestamped and written to `nsx_group_remap_changes.jsonl` |
| Per-run snapshots | Before/after per-group state written to `nsx_logs/nsx_snapshots/` as structured JSON |
| Validation scripts | Post-push and post-rollback live validation confirms NSX state matches expectations |
| Credential security | Credentials loaded from `.env` file only — never passed as CLI arguments |
| Read-only tools | `export_nsx_objects.py`, `validate_*.py`, and `find_rules_*.py` make no writes to NSX |
| Input validation | CSV headers, file existence, and IP version consistency checked before any processing |
| Safe YAML parsing | `yaml.safe_load` used throughout — prevents arbitrary code execution from malformed YAML |

---

## Runbook Execution Order

| Step | Script | Mode | Writes to NSX? |
|---|---|---|---|
| 0 | venv + pip | — | No |
| 1 | `export_nsx_objects.py` | Read-only | No |
| 2 | `add_mapped_ips_to_groups_files.py` | Local file transform | No |
| 3–4 | `push_remapped_groups.py` (dry-run) | Preview | No |
| 3–4 | `push_remapped_groups.py --apply` | Apply | Yes (PATCH) |
| 5a/b | `push_nsx_groups_revert.py` (dry-run) | Preview rollback | No |
| 5a/b | `push_nsx_groups_revert.py --apply` | Apply rollback | Yes (PATCH) |
| Validate | `validate_nsx_groups.py` | Read-only check | No |
| Final | `validate_nsx_groups_live.py` | Read-only check | No |
| Pre-flight | `find_rules_affected_by_group_changes.py` | Local analysis | No |
