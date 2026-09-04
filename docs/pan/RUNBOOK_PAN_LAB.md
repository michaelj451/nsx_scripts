# Runbook — Palo Alto Lab (Panorama API) — macOS / Linux / bash

> ## ⚠️ LAB ONLY — DO NOT USE AGAINST PRODUCTION PANORAMA
>
> This runbook covers tools that authenticate against the Panorama XML API
> and stage configuration changes. **It is bound to the home lab Panorama
> (`pano4.lab.local`) by configuration convention.** No production Panorama
> credentials should ever be added to `.env`.
>
> For production / customer engagements, see
> [RUNBOOK_PAN_PROD.md](RUNBOOK_PAN_PROD.md) — that toolkit is
> **manually run locally**, works entirely offline from exported config
> XML, and **never authenticates against a Panorama**.

PowerShell variant: [RUNBOOK_PAN_LAB_PS.md](RUNBOOK_PAN_LAB_PS.md).

---

## What's covered here

| Tool | Purpose | Read/Write |
|---|---|---|
| `tools/pan/pull_panorama_config.py` | Pull a candidate or running config snapshot from Panorama and save to `tools/pan/configs/` | Read-only (GETs) |
| `tools/pan/add_services_to_rules.py` | Add a fixed set of service objects to every customer security rule (across shared + all DGs); stages changes to candidate; no auto-commit | Write (gated by `--apply`) |
| `tools/pan/export_panorama_config.py` | Export the full RUNNING config via XML `type=export`; the snapshot path that works for the read-only agent account | Read-only (keygen + export) |

Both tools land their output under `$PANO_REPORTS_DIR/<tool>` (consistent with the rest of the toolkit) and follow the same dry-run / `--apply` / per-run-baseline pattern.

---

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

### `.env` requirements

Append (one-time):

```
panorama=pano4.lab.local
PANORAMA_TLS_VERIFY=false
```

Username/password are **reused from `vm_username` / `vm_password`** (already in `.env` for the VM-tagging toolkit). The Panorama client will look there if `PANORAMA_USERNAME` / `PANORAMA_PASSWORD` aren't set.

If you'd rather use an API key (PAN-native, avoids storing the password):

```
panorama=pano4.lab.local
PANORAMA_API_KEY=<long-base64-key-from-panorama>
PANORAMA_TLS_VERIFY=false
```

To prove the credentials work and mint a key, use the auth script (read-only
against Panorama: keygen + `show system info` + name-only listings):

```bash
setopt interactive_comments 2>/dev/null || true

# Check whatever .env currently says (key stays masked)
python tools/pan/panorama_auth.py

# Generate a key from username/password and store it in .env as PANORAMA_API_KEY
python tools/pan/panorama_auth.py --keygen --write-env
```

It prints the target, which `.env` variables supplied it, the auth method
used, the Panorama hostname / serial / PAN-OS version, and how many device
groups and templates the account can see. A JSON report (key fingerprint
only, never the key) lands in `.pano_reports/`. Exit code `0` = authenticated,
`1` = auth or API failure, `2` = `.env` incomplete, `3` = `--write-env` refused.

Both Panorama clients read the same variables (see `app/palo/pan_env.py`):

| Client | Use for |
|---|---|
| `app/palo/panorama_api_client.py` | xpath-level XML API: config get/set/edit/delete, commit, config pulls |
| `app/palo/panos_client.py` | pan-os-python object model (device groups, address objects, rules); `PanosClient.from_env()` |
| `app/palo/pan_rest_client.py` | REST API GETs only (read-only by design) plus config export; works under the restricted agent account (`agent_user`/`agent_password` in `.env`); `PanRestClient.from_env(user_env=..., password_env=...)` |

The raw XML equivalent, if you ever need it by hand:

```bash
curl -ks "https://pano4.lab.local/api/?type=keygen&user=USERNAME&password=PASSWORD"
```

---

## Conventions used (lab-specific)

| Convention | Value |
|---|---|
| Target Panorama | `pano4.lab.local` (lab only — bound by `.env`) |
| TLS verify | `false` (lab self-signed cert) |
| Config snapshot output | `tools/pan/configs/<host>-<state>-<UTC_TS>.xml` — auto-gitignored |
| Tool run output | `$PANO_REPORTS_DIR/<tool>/<UTC_TS>/` |
| Auth | `ppanorama_*` or `vm_*` from `.env` (no creds in source) |
| Write semantics | Changes are staged to CANDIDATE config — operator must commit in Panorama UI |

---

## 0b. Authenticate with .env credentials (get a token)

```bash
python tools/pan/panorama_auth.py                      # check creds, masked token
python tools/pan/panorama_auth.py --keygen --write-env # mint + persist PANORAMA_API_KEY
```

With `PANORAMA_API_KEY` persisted, every pan tool skips per-run keygen.

## 0c. Live policy lookup (lab convenience)

`check_policy_match.py` stays offline-by-design, but `--live candidate|running`
first pulls the config with the .env-authenticated client (GET-only, saved to
`tools/pan/configs/`), then runs the identical offline evaluation:

```bash
python tools/pan/check_policy_match.py --live candidate \
  --src-ip 10.20.5.7 --dst-ip 192.168.10.42 --protocol tcp --dst-port 443
```

Production use keeps `--config <exported.xml>` (no network); see
[RUNBOOK_PAN_PROD.md](RUNBOOK_PAN_PROD.md).

## 1. Pull a config snapshot — `pull_panorama_config.py`

Read-only. Saves a single XML file to `tools/pan/configs/` (gitignored).

### Pull CANDIDATE config (default — includes staged uncommitted changes)

```bash
python tools/pan/pull_panorama_config.py
```

Stdout prints the saved file path so you can chain it into the analysis tools:

```bash
CFG=$(python tools/pan/pull_panorama_config.py)
echo "Saved: $CFG"
```

### Pull RUNNING config (what's actually enforcing)

```bash
python tools/pan/pull_panorama_config.py --running
```

### Notable size difference (pano4 today)

| State | Approx size | Why |
|---|---|---|
| `candidate` | ~24 MB | Includes managed-firewall device-level config + content packages |
| `running` | ~100 KB | Just Panorama-side rulebase/objects |

For policy/rule analysis, you want **candidate** (it's the pushable surface). For "what's deployed right now" forensics, use **running**.

### Where it lands

```
tools/pan/configs/
├── .gitkeep                                  (tracked — keeps dir in repo)
├── pano4-candidate-<UTC_TS>.xml              (gitignored)
├── pano4-running-<UTC_TS>.xml                (gitignored)
└── pano4-export-<UTC_TS>.xml                 (gitignored; from section 1b)
```

---

## 1b. Export the config as the read-only agent account : `export_panorama_config.py`

`pull_panorama_config.py` uses the XML config API, which the restricted
`agentuser` role denies. The export path works for it: the role permits XML
`type=export` (there is no REST equivalent; probed paths return 501), and
export returns the complete RUNNING configuration.

```bash
# As the agent account
python tools/pan/export_panorama_config.py \
  --user-env agent_user --password-env agent_password --no-tls-verify

# Chain straight into the offline policy-match engine (stdout is the file path)
CFG=$(python tools/pan/export_panorama_config.py --user-env agent_user \
      --password-env agent_password --no-tls-verify --quiet)
python tools/pan/check_policy_match.py --config "$CFG" \
  --src-ip 10.1.1.5 --dst-ip 10.2.1.5 --protocol tcp --dst-port 443 --device-group dg-4
```

Output lands in `tools/pan/configs/<host>-export-<UTC_TS>.xml` (gitignored).
`--host` targets another Panorama; omit the `--user-env` pair to use the
admin credentials.

Differences from `pull_panorama_config.py`:

| | `pull_panorama_config.py` | `export_panorama_config.py` |
|---|---|---|
| API | XML config get/show | XML `type=export` |
| Account | admin (config rights) | agent account works |
| Candidate config | yes (default) | no; RUNNING only |

SECURITY: the export contains the FULL config including `mgt-config` with
admin password hashes. Treat the file like a credential store.

---

## 2. Add services to every customer rule — `add_services_to_rules.py`

Mass-modifies every customer security rule (shared/pre + shared/post + all DG pre + all DG post) to include a fixed set of service objects (`pano4-tcp-80`, `pano4-tcp-443`, etc.). Default behavior is **dry-run**; `--apply` writes to candidate config.

### Dry-run (default — captures baseline + plan, no writes)

```bash
python tools/pan/add_services_to_rules.py
```

Output:

```
$PANO_REPORTS_DIR/add_services/<UTC_TS>/
├── baseline.json       per-rule services_before (revert input)
├── plan.json           per-rule action + services_to_add + dropped specials
└── logs/
```

### Apply (writes to CANDIDATE — never auto-commits)

```bash
python tools/pan/add_services_to_rules.py --apply
```

Apply adds `apply_report.json` to the same bundle, with per-rule success/failure.

### What it does to each rule (3-action plan)

For each rule, the tool compares the current `<service>` list against the target service set:

| `services_before` | Action | API call |
|---|---|---|
| All 8 target services already present | `noop` | None |
| Specific service objects, no `any` or `application-default` | `append` | `SET` each missing member |
| Includes `any` or `application-default` | `replace` | `EDIT` the entire `<service>` element with the union (special token dropped) |

The `replace` path was added because PAN-OS rejects mixing `application-default` with explicit service objects. The replace **drops the special token and preserves any specific services that already existed**.

### Idempotency

- Service object creation is `SET` on `/config/shared/service` — re-running on an already-existing service is a no-op (logged as `already_exists`).
- Rule modifications use `SET` (additive) or `EDIT` (replace). Re-running after a successful apply on the same rule is a `noop` (all target services already present).

### Manual commit (or revert) in Panorama UI

The tool **never commits**. After `--apply`:

- **Commit**: Panorama web UI → Commit → Commit to Panorama → then Push to Devices.
- **Revert pending**: Panorama web UI → Commit → Revert Changes (drops all staged candidate changes — including ours and anything else uncommitted).

If you need to revert just **our** changes specifically (without touching unrelated staged changes), the `baseline.json` files preserve enough state to script it. A dedicated `revert_added_services.py` tool is not yet built — flag if you want it.

---

## 3. Verify the staged changes — pull-and-compare pattern

After `--apply`, re-pulling the candidate config lets you confirm everything landed:

```bash
setopt interactive_comments 2>/dev/null || true

# Capture the candidate after our apply
CFG=$(python tools/pan/pull_panorama_config.py)

# Use the analysis runbook tools against the pulled file
python tools/pan/check_policy_match.py \
  --config "$CFG" \
  --device-group dg-3 \
  --src-ip 10.1.1.20 --dst-ip 4.2.2.2 \
  --protocol tcp --dst-port 80
```

See [RUNBOOK_PAN_PROD.md](RUNBOOK_PAN_PROD.md) for the full analysis toolkit (`check_policy_match.py` etc.).

---

## 4. Safety properties

| Property | Behavior |
|---|---|
| Default mode | Dry-run — no writes |
| Apply trigger | Explicit `--apply` flag required |
| Commit | **Never automatic** — staged to candidate; operator commits manually |
| Baseline preservation | Every run writes `baseline.json` for the rules it touched |
| Read-only tools | `pull_panorama_config.py` uses only GET; PUT/PATCH/DELETE are not used |
| TLS verification | Defaults true; set `PANORAMA_TLS_VERIFY=false` only for self-signed lab certs |
| Concurrent edit risk | If another operator is also editing candidate, your apply may collide with theirs — Panorama itself does not lock; use `show config diff` in the UI before committing |

---

## 5. Common operational patterns

### Snapshot → analyze → modify → re-snapshot → verify

```bash
setopt interactive_comments 2>/dev/null || true

# 1. Baseline snapshot
BEFORE=$(python tools/pan/pull_panorama_config.py --running)

# 2. Analyze (offline, see ANALYSIS runbook)
python tools/pan/check_policy_match.py --config "$BEFORE" \
  --device-group dg-3 --src-ip 10.1.1.20 --dst-ip 4.2.2.2 --protocol tcp --dst-port 80

# 3. Stage changes (writes to candidate)
python tools/pan/add_services_to_rules.py --apply

# 4. Re-snapshot the candidate to see what's staged
AFTER=$(python tools/pan/pull_panorama_config.py)

# 5. Re-analyze
python tools/pan/check_policy_match.py --config "$AFTER" \
  --device-group dg-3 --src-ip 10.1.1.20 --dst-ip 4.2.2.2 --protocol tcp --dst-port 80

# 6. If you like the diff: commit manually via Panorama UI
# 7. If you don't: revert pending in Panorama UI (drops all candidate changes)
```

### Roll a new tool

When adding a new write-side tool to this runbook:
- Default behavior must be dry-run.
- Apply must be gated by an explicit flag.
- Per-run baseline must be captured before any write.
- The tool must NOT commit automatically.

---

## 6. Caveats

1. **TLS verification is disabled by default** for lab self-signed certs. Don't reuse this `.env` against any Panorama with a real certificate without setting `PANORAMA_TLS_VERIFY=true`.
2. **API key is regenerated on every run** if `PANORAMA_API_KEY` is not set in `.env`. That's fine for the lab but rate-limits hard against busy Panoramas. For frequent use, mint a key once and set `PANORAMA_API_KEY`.
3. **All writes target the global Panorama candidate**. Admin-scoped candidate (PAN-OS 10.2+ scoped commits) is not implemented in the client.
4. **No NAT, no URL filtering, no decryption profile handling.** The `add_services_to_rules.py` tool only edits the `<service>` element on `<security>` rules.
5. **No multi-vsys handling** beyond what Panorama itself does — the tool treats each DG's rulebase as a flat list per the standard XPath.
6. **Concurrent operators**: Panorama doesn't lock candidate config. If two operators apply at the same time, last-write-wins on any overlapping rule.

---

## 7. Full tool flag reference

### `pull_panorama_config.py`

| Flag | Default | Purpose |
|---|---|---|
| `--running` | off | Pull running config (what's enforcing) instead of candidate |
| `--prefix <str>` | derived from host | Filename prefix |
| `--output-dir <path>` | `tools/pan/configs/` | Where to save the XML |

### `add_services_to_rules.py`

| Flag | Default | Purpose |
|---|---|---|
| `--apply` | off (dry-run) | Stage changes to candidate config |
| `--output-base <path>` | `$PANO_REPORTS_DIR` | Report root |

### Environment variables read

| Variable | Required | Purpose |
|---|---|---|
| `panorama` (or `ppanorama` / `PANORAMA_URL` / `PANORAMA_HOST`) | yes | Panorama hostname or URL |
| `PANORAMA_API_KEY` | one-of | Preferred auth — bypasses keygen |
| `PANORAMA_USERNAME` (or `vm_username`) | one-of | Falls back to vm_username if not set |
| `PANORAMA_PASSWORD` (or `vm_password`) | one-of | Falls back to vm_password if not set |
| `PANORAMA_TLS_VERIFY` | no (default `true`) | Set to `false` for self-signed labs |
| `PANO_REPORTS_DIR` | yes | Where tool report bundles land |
