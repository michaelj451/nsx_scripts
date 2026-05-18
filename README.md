# NSX DFW Toolset — Local Manager Operations

A collection of Python tools for snapshotting, transforming, and pushing
NSX Policy distributed-firewall objects (groups, services, security
policies, rules) between Local Managers. Built for operators with **DFW
access only** — no networking/segments permission required for the push
target.

Two distinct operations are supported, each with its own runbook:

| Operation | Source | Target | Scope | Runbook |
|---|---|---|---|---|
| **Clone** — stand up a new LM with the same DFW config | `nsx-lm1` (live) | `nsx-lm2` (new) | Services + groups + policies + rules | [RUNBOOK_A.md](RUNBOOK_A.md) |
| **Subnet remap in place** — rewrite group IPs on a single LM using a CSV mapping | `nsx-lm1` | `nsx-lm1` | Groups only (PATCH) | [RUNBOOK_B.md](RUNBOOK_B.md) |

---

## Design properties

- **Read-only source** — the live source manager is never written to in either workflow.
- **Tag/dynamic membership is resolved by NSX** — no Python tag parsing. The toolkit asks `/policy/.../groups/<id>/members/virtual-machines` for evaluated VM lists, then looks up each VM's IPs via fabric VIFs.
- **Every transform is offline and reviewable** — exports, additive trees, transformed trees, build dirs, and remapped trees are all on-disk artifacts you can diff and inspect before any push.
- **Dry-run is the default safe mode** on every write step. Real apply requires an explicit `--apply` (or `--yes` for the groups-only pusher).
- **Idempotent push** — both push tools handle "already exists" and 412 revision-conflict by falling back from PUT to PATCH automatically.
- **Per-run reports + logs** under `nsx_logs/` for every step.

---

## What's in this repo

### Tools — `tools/nsx/`

| Script | Purpose |
|---|---|
| `export_nsx_objects.py` | GET-only snapshot of an LM's groups/services/policies/rules → `nsx_export/<host>/` |
| `build_group_ip_additive_from_live_members.py` | Resolve a group's evaluated VM members on a source LM, look up their IPs via fabric VIFs, append as a static `IPAddressExpression` (with `OR`) |
| `find_rules_affected_by_group_changes.py` | Report which rules reference changed groups + which new subnets drive each match |
| `find_segments_referenced.py` | Inventory every `/infra/segments/*` path referenced by groups/rules, optionally fetch live segment details (subnets, VLANs, TZ) |
| `transform_group_segments.py` | Pre-build segment rewriter. `strip` mode drops segment refs and cleans operators; `convert` mode fetches segments and substitutes their subnet CIDRs |
| `nsx_group_ip_remap_offline.py` | Offline CSV subnet remap on a group tree (`old_subnet,new_subnet` with longest-prefix match) |
| `build_complete_nsx_payload.py` | Offline assembler — combine source services/policies/rules with a (transformed) groups tree into a ready-to-push build dir |
| `push_complete_nsx_payload.py` | Push the build dir to a target LM. Dry-run by default. Handles services + groups + policies + rules |
| `push_additive_group_ips.py` | Groups-only PATCH push. Used by Runbook B. Dry-run by default |
| `validate_nsx_groups_live.py` | Read-only diff of live NSX groups vs a prepared payload |
| `push_nsx_groups_revert.py` | Rollback — PATCH groups back to a saved export snapshot |

### App library — `app/nsx/`

| Module | Purpose |
|---|---|
| `nsx_policy_client.py` | Thin HTTP client for NSX Policy + fabric APIs (segments, groups, services, policies, rules, VMs, VIFs) |
| `cli_bootstrap.py` | `.env` loader + shared CLI setup |
| `nsx_constants.py` | Manager hostname resolution + path constants |
| `nsx_object_functions/nsx_object_exporter.py` | Generic exporter used by `export_nsx_objects.py` |
| `nsx_object_functions/nsx_object_importer.py` | Generic importer used by the push tools |
| `nsx_object_functions/nsx_group_importer.py` | Group-specific importer with additive-merge logic |
| `nsx_object_functions/nsx_group_remap.py` | Subnet-remap primitives used by `nsx_group_ip_remap_offline.py` |

### Data + logs

```
data/
  subnet_map.csv         — example IP-remap CSV
  nonprod_map.csv        — prod → non-prod subnet remap

nsx_export/              — read-only snapshots from each LM
nsx_groups_additive_a/   — additive trees built for Runbook A (lm2 target)
nsx_groups_additive_b/   — additive trees built for Runbook B (lm1 in-place)
nsx_groups_transformed/  — segment-transformed groups (post step A.4)
nsx_groups_remapped/     — CSV-remapped groups (post step B.3)
nsx_build/               — complete push payloads
nsx_logs/                — per-run logs, snapshots, validation reports
```

---

## Which runbook should I follow?

**[RUNBOOK_A.md](RUNBOOK_A.md)** — you want a *new* NSX Local Manager
(`nsx-lm2`) to look like an existing one (`nsx-lm1`). Pushes services,
groups (with live VM IPs snapshotted as static), policies, and rules. The
new manager doesn't have to share segments with the source — optional
step transforms segment refs into IP-address groups before push.

**[RUNBOOK_B.md](RUNBOOK_B.md)** — you want to modify the live manager's
own groups using a subnet remap CSV. Source and target are the same
manager (`nsx-lm1`). Groups-only PATCH; services, policies, and rules are
untouched. Use `--mapped-only` to replace IPs with their CSV-mapped
values; omit it for additive expansion.

The two workflows do not interact — pick whichever matches what you're
trying to accomplish.

---

## Quick start (Runbook A)

### 0) Env — macOS / Linux

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

### 0) Env — Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

> If PowerShell blocks the activation script, run once per session:
> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`

### 0) Env — Windows (Command Prompt)

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r docker\requirements-pip.txt
set PYTHONPATH=%CD%\app
```

> All subsequent commands are written for bash / macOS-Linux. On Windows,
> use `python` instead of `python3` and replace the `\` line-continuations
> with backticks (PowerShell) or a single line.

### Workflow commands

```bash
# 1) Export source + target
python tools/nsx/export_nsx_objects.py --manager nsx-lm1 --output-format yaml
python tools/nsx/export_nsx_objects.py --manager nsx-lm2 --output-format yaml

# 2) Resolve live members lm1 → lm2 additive tree
python tools/nsx/build_group_ip_additive_from_live_members.py \
  --source-manager nsx-lm1 --domain-id default \
  --source-groups-dir nsx_export/nsx-lm1.lab.local/domains/default/groups \
  --output-groups-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \
  --output-format yaml --copy-first --continue-on-group-error

# 3,4) optional pre-push analysis + segment transform — see RUNBOOK_A.md

# 5) Build payload
python tools/nsx/build_complete_nsx_payload.py \
  --source-manager-dir nsx_export/nsx-lm1.lab.local \
  --additive-groups-dir nsx_groups_additive_a/nsx-lm2.lab.local/domains/default/groups \
  --build-dir nsx_build/nsx-lm2.lab.local --domain-id default --overwrite

# 6) Dry-run, 7) Apply
python tools/nsx/push_complete_nsx_payload.py --target nsx-lm2 \
  --build-dir nsx_build/nsx-lm2.lab.local --domain-id default --dry-run
python tools/nsx/push_complete_nsx_payload.py --target nsx-lm2 \
  --build-dir nsx_build/nsx-lm2.lab.local --domain-id default --apply

# 8) Validate
python tools/nsx/validate_nsx_groups_live.py --target nsx-lm2 \
  --expected-root nsx_groups_additive_a/nsx-lm2.lab.local --domain-id default
```

For the full Runbook A with optional pre-push analysis, segment
transformation, sandbox testing, and rollback, see
[RUNBOOK_A.md](RUNBOOK_A.md).

For the in-place CSV remap workflow, see [RUNBOOK_B.md](RUNBOOK_B.md).
