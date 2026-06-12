# Runbook — Palo Alto Lab (Panorama API) — Windows PowerShell

> ## ⚠️ LAB ONLY — DO NOT USE AGAINST PRODUCTION PANORAMA
>
> This runbook covers tools that authenticate against the Panorama XML API
> and stage configuration changes. **It is bound to the home lab Panorama
> (`pano4.lab.local`) by configuration convention.** No production Panorama
> credentials should ever be added to `.env`.
>
> For production / customer engagements, see
> [RUNBOOK_PAN_PROD_PS.md](RUNBOOK_PAN_PROD_PS.md) — that toolkit is
> **manually run locally**, works entirely offline from exported config
> XML, and **never authenticates against a Panorama**.

Bash/macOS variant with full narrative: [RUNBOOK_PAN_LAB.md](RUNBOOK_PAN_LAB.md).

Line continuation in PowerShell is the backtick `` ` `` at end of line.

---

## What's covered here

| Tool | Purpose | Read/Write |
|---|---|---|
| `tools/pan/pull_panorama_config.py` | Pull a candidate or running config snapshot from Panorama and save to `tools\pan\configs\` | Read-only (GETs) |
| `tools/pan/add_services_to_rules.py` | Add a fixed set of service objects to every customer security rule; stages changes to candidate; no auto-commit | Write (gated by `--apply`) |

---

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

### `.env` requirements

Append (one-time):

```
panorama=pano4.lab.local
PANORAMA_TLS_VERIFY=false
```

Username/password are **reused from `vm_username` / `vm_password`** (already in `.env` for the VM-tagging toolkit). The Panorama client will look there if `PANORAMA_USERNAME` / `PANORAMA_PASSWORD` aren't set.

To mint an API key once (PAN-native, more secure than storing the password):

```powershell
Invoke-RestMethod `
  -SkipCertificateCheck `
  "https://pano4.lab.local/api/?type=keygen&user=USERNAME&password=PASSWORD"
```

Save the resulting `<key>` value as `PANORAMA_API_KEY=` in `.env`.

---

## Conventions used (lab-specific)

| Convention | Value |
|---|---|
| Target Panorama | `pano4.lab.local` (lab only — bound by `.env`) |
| TLS verify | `false` (lab self-signed cert) |
| Config snapshot output | `tools\pan\configs\<host>-<state>-<UTC_TS>.xml` — auto-gitignored |
| Tool run output | `$env:PANO_REPORTS_DIR\<tool>\<UTC_TS>\` |
| Auth | `panorama` + `vm_*` from `.env` |
| Write semantics | Changes are staged to CANDIDATE — operator commits manually in Panorama UI |

---

## 1. Pull a config snapshot — `pull_panorama_config.py`

Read-only. Saves a single XML file to `tools\pan\configs\` (gitignored).

### Pull CANDIDATE config (default — includes staged uncommitted changes)

```powershell
python tools/pan/pull_panorama_config.py
```

Capture the saved path for chaining:

```powershell
$cfg = python tools/pan/pull_panorama_config.py
Write-Host "Saved: $cfg"
```

### Pull RUNNING config (what's actually enforcing)

```powershell
python tools/pan/pull_panorama_config.py --running
```

### Notable size difference (pano4 today)

| State | Approx size | Why |
|---|---|---|
| `candidate` | ~24 MB | Includes managed-firewall device-level config + content packages |
| `running` | ~100 KB | Just Panorama-side rulebase/objects |

For policy/rule analysis, you want **candidate** (it's the pushable surface). For "what's actually deployed right now" forensics, use **running**.

---

## 2. Add services to every customer rule — `add_services_to_rules.py`

Mass-modifies every customer security rule (shared/pre + shared/post + all DG pre + all DG post) to include a fixed set of service objects (`pano4-tcp-80`, `pano4-tcp-443`, etc.). Default behavior is **dry-run**; `--apply` writes to candidate config.

### Dry-run (default)

```powershell
python tools/pan/add_services_to_rules.py
```

Output:

```
$env:PANO_REPORTS_DIR\add_services\<UTC_TS>\
├── baseline.json
├── plan.json
└── logs\
```

Inspect:

```powershell
$latest = (Get-ChildItem "$env:PANO_REPORTS_DIR\add_services" -Directory |
           Sort-Object Name -Descending | Select-Object -First 1).FullName
Get-Content "$latest\plan.json" | ConvertFrom-Json | Select-Object -ExpandProperty rules |
  Group-Object action | Select-Object Name,Count
```

### Apply (writes to CANDIDATE — never auto-commits)

```powershell
python tools/pan/add_services_to_rules.py --apply
```

Apply adds `apply_report.json` to the bundle, with per-rule success/failure.

### What it does to each rule (3-action plan)

| `services_before` | Action | API call |
|---|---|---|
| All 8 target services already present | `noop` | None |
| Specific service objects, no `any` or `application-default` | `append` | `SET` each missing member |
| Includes `any` or `application-default` | `replace` | `EDIT` the entire `<service>` element with the union (special token dropped) |

The `replace` path was added because PAN-OS rejects mixing `application-default` with explicit service objects.

### Manual commit (or revert) in Panorama UI

The tool **never commits**. After `--apply`:

- **Commit**: Panorama web UI → Commit → Commit to Panorama → then Push to Devices
- **Revert pending**: Panorama web UI → Commit → Revert Changes (drops all staged candidate changes)

---

## 3. Verify staged changes — pull-and-compare pattern

```powershell
# Snapshot the candidate after our apply
$cfg = python tools/pan/pull_panorama_config.py

# Use the production analysis tools against the pulled file
python tools/pan/check_policy_match.py `
  --config $cfg `
  --device-group dg-3 `
  --src-ip 10.1.1.20 --dst-ip 4.2.2.2 `
  --protocol tcp --dst-port 80
```

See [RUNBOOK_PAN_PROD_PS.md](RUNBOOK_PAN_PROD_PS.md) for the full production analysis toolkit (`check_policy_match.py` etc.).

---

## 4. Safety properties

| Property | Behavior |
|---|---|
| Default mode | Dry-run — no writes |
| Apply trigger | Explicit `--apply` flag required |
| Commit | **Never automatic** — staged to candidate; operator commits manually |
| Baseline preservation | Every run writes `baseline.json` |
| Read-only tools | `pull_panorama_config.py` uses only GET |
| TLS verification | Defaults true; set `PANORAMA_TLS_VERIFY=false` only for self-signed lab certs |

---

## 5. Common operational patterns

### Snapshot → analyze → modify → re-snapshot → verify

```powershell
# 1. Baseline snapshot
$before = python tools/pan/pull_panorama_config.py --running

# 2. Analyze (offline, see PROD runbook)
python tools/pan/check_policy_match.py --config $before `
  --device-group dg-3 --src-ip 10.1.1.20 --dst-ip 4.2.2.2 --protocol tcp --dst-port 80

# 3. Stage changes (writes to candidate)
python tools/pan/add_services_to_rules.py --apply

# 4. Re-snapshot the candidate to see what's staged
$after = python tools/pan/pull_panorama_config.py

# 5. Re-analyze
python tools/pan/check_policy_match.py --config $after `
  --device-group dg-3 --src-ip 10.1.1.20 --dst-ip 4.2.2.2 --protocol tcp --dst-port 80

# 6. If you like the diff: commit manually via Panorama UI
# 7. If you don't: revert pending in Panorama UI
```

---

## 6. Caveats

1. **TLS verification is disabled by default** for lab self-signed certs.
2. **API key is regenerated on every run** if `PANORAMA_API_KEY` is not set.
3. **All writes target the global Panorama candidate**. Admin-scoped commits are not implemented.
4. **No NAT, no URL filtering, no decryption handling**. The tool only edits `<security>` rule `<service>` elements.
5. **No multi-vsys handling** beyond what Panorama itself does.
6. **Concurrent operators**: Panorama doesn't lock candidate. Use `show config diff` in UI before committing.

---

## 7. Full tool flag reference

### `pull_panorama_config.py`

| Flag | Default | Purpose |
|---|---|---|
| `--running` | off | Pull running config instead of candidate |
| `--prefix <str>` | derived from host | Filename prefix |
| `--output-dir <path>` | `tools\pan\configs\` | Where to save the XML |

### `add_services_to_rules.py`

| Flag | Default | Purpose |
|---|---|---|
| `--apply` | off (dry-run) | Stage changes to candidate config |
| `--output-base <path>` | `$env:PANO_REPORTS_DIR` | Report root |

### Environment variables read

| Variable | Required | Purpose |
|---|---|---|
| `panorama` | yes | Panorama hostname or URL |
| `PANORAMA_API_KEY` | one-of | Preferred auth — bypasses keygen |
| `PANORAMA_USERNAME` (or `vm_username`) | one-of | Falls back to vm_username if not set |
| `PANORAMA_PASSWORD` (or `vm_password`) | one-of | Falls back to vm_password if not set |
| `PANORAMA_TLS_VERIFY` | no (default `true`) | Set to `false` for self-signed labs |
| `PANO_REPORTS_DIR` | yes | Where tool report bundles land |
