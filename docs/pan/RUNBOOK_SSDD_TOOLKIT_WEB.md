# Runbook SSDD TOOLKIT WEB : Local Panorama tool hub : macOS / Linux / bash

Local, loopback-only web hub that fronts the read-only Panorama tools. Same
analyses the CLI tools run, but driven from a browser and browsable against
past runs. Bound strictly to `127.0.0.1`, no auth, never listens on the LAN.

PowerShell variant: [RUNBOOK_SSDD_TOOLKIT_WEB_PS.md](RUNBOOK_SSDD_TOOLKIT_WEB_PS.md).

```bash
setopt interactivecomments 2>/dev/null || true
```

The first line makes pasted `#` comments safe in zsh; it is a no-op in bash.

---

## What it exposes

Serves `http://127.0.0.1:8765` by default. Pages:

| Path | Purpose |
|---|---|
| `/` | Hub: link cards to every tool page below |
| `/ip-search` | IP-to-rule search: pull a config snapshot, then search IPs / subnets / ranges against it |
| `/group-remap` | CSV group remap dry run (same analysis as `tools/pan/pan_group_remap_report.py`); pick a CSV from `data/`, run, browse past reports |
| `/remap-pivot` | Same CSV remap dry-run data as `/group-remap`, pivoted: one row per group/rule with four side-columns: `Adds Source`, `Adds Destination`, `Already-mapped Source`, `Already-mapped Destination`. Empty cell = nothing on that side. Shares run history with `/group-remap` |
| `/flow-search` | Flow match: which rules a specific 5-tuple would hit |
| `/rule-placement` | Rule placement recommender |

Read-only against Panorama. Managed firewalls are never contacted. All runs
land in the same `pan_reports/` and `pan_capture/` trees the CLI tools use, so
web and CLI runs share one history.

## Setup

```bash
cd ~/dev/nsx_scripts
source .venv/bin/activate
export PYTHONPATH="$PWD/app"
```

`.env` requirements (in addition to `panorama=<host>`):

```
agent_user=agentuser
agent_password=<password>
```

## Start

Simplest form (reads `agent_user` and `agent_password` from `.env` by default):

```bash
python tools/pan/ssdd_toolkit_web.py --no-tls-verify
```

Then open **[http://127.0.0.1:8765](http://127.0.0.1:8765)** in a browser.

Alternate port (if 8765 is busy):

```bash
python tools/pan/ssdd_toolkit_web.py --no-tls-verify --port 9000
# then http://127.0.0.1:9000
```

Point at a different Panorama than the one in `.env`:

```bash
python tools/pan/ssdd_toolkit_web.py \
  --host pano-lab.example.local \
  --no-tls-verify
```

Override the .env var names (only if you're not using the standard
`agent_user` / `agent_password` keys):

```bash
python tools/pan/ssdd_toolkit_web.py \
  --user-env some_other_user \
  --password-env some_other_pw \
  --no-tls-verify
```

Note: `tools/pan/ip_rule_search_web.py` is a thin wrapper that just calls
`ssdd_toolkit_web.main()`, so either script starts the same hub.

## Flags

| Flag | Purpose |
|---|---|
| `--host <FQDN>` | Target Panorama (overrides `.env`'s `panorama=`) |
| `--user-env <VAR>` | Env var name holding the username (e.g. `agent_user`) |
| `--password-env <VAR>` | Env var name holding the password (e.g. `agent_password`) |
| `--port <N>` | Listen port on 127.0.0.1 (default 8765) |
| `--no-tls-verify` | Disable TLS cert verification toward Panorama |

## Stop

Return to the terminal running the server and press **Ctrl-C**.

## Troubleshooting

- **Port already in use** ("Address already in use"): pass `--port 9000` (or any other free port), or find what's already holding 8765:
  ```bash
  lsof -i :8765
  ```
- **Blank page / connection refused**: confirm the server is still running (its terminal window). It only serves on `127.0.0.1`, so `localhost` in the browser works but a machine name like `mac2.local` will not.
- **"Panorama auth failed"** on startup: check `.env` for `agent_user` / `agent_password` values, or override with different `--user-env` / `--password-env` names.
- **Certificate warnings** in the server log: `urllib3` warnings are suppressed on startup; if you see verify errors, add `--no-tls-verify` (safe for loopback lab work; do not use against production without a valid CA chain).

## Safety

- Loopback only (`127.0.0.1`). No LAN or external listener.
- Read-only against Panorama (REST GETs; the only XML API call is the initial keygen).
- Managed firewalls are never contacted.
- Same output trees as the CLI tools: `pan_reports/`, `pan_capture/`. Web-initiated runs are indistinguishable from CLI-initiated ones in the archive.
