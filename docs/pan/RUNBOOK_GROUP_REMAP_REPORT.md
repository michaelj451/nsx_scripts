# Runbook GROUP REMAP REPORT : Panorama CSV remap dry run : macOS / Linux / bash

Read-only report of what a CSV-driven IP remap would change on a Panorama:
which address objects would be created or reused, which address groups and
security rules would gain the mapped members, and where. Nothing is pushed;
this is the report step only (the PAN twin of the NSX
`capture_nsx_state.py` + `groups.py push --csv-remap` dry run).

PowerShell variant: [RUNBOOK_GROUP_REMAP_REPORT_PS.md](RUNBOOK_GROUP_REMAP_REPORT_PS.md).

```bash
setopt interactivecomments 2>/dev/null || true
```

The first line makes pasted `#` comments safe in zsh; it is a no-op in bash.

---

## What it covers

| Surface | Detail |
|---|---|
| Address groups | shared + every device group (static members; dynamic reported, never remapped) |
| Security rules | shared pre, per-DG pre, per-DG post, shared post; source and destination |
| Rule members | address object names, address group references, literal IP/CIDR/range tokens |
| Never touched | managed firewalls (Panorama config only), ranges and IPv6 (analysis only) |

Runs as the read-only agent account over the REST API (the only XML API call
is the initial keygen). CSV format is identical to the NSX tools: headers
`old_subnet,new_subnet`, longest prefix wins, offset-preserving.

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

## Run

```bash
CSV=data/nonprod_map.csv

# 1. Always dry-run first: shows target, account, CSV row count; sends nothing
python tools/pan/pan_group_remap_report.py --csv $CSV \
  --user-env agent_user --password-env agent_password \
  --no-tls-verify --dry-run

# 2. Full report (lab Panoramas use self-signed certs, hence --no-tls-verify)
python tools/pan/pan_group_remap_report.py --csv $CSV \
  --user-env agent_user --password-env agent_password \
  --no-tls-verify
```

Useful variations:

```bash
# Another Panorama (fresh keygen against that host)
python tools/pan/pan_group_remap_report.py --csv $CSV --host pano2.lab.local \
  --user-env agent_user --password-env agent_password --no-tls-verify

# Only specific device groups
python tools/pan/pan_group_remap_report.py --csv $CSV --device-groups dg-4,dg-5 \
  --user-env agent_user --password-env agent_password --no-tls-verify

# Admin account instead of the agent account (omit the --user-env pair;
# canonical PANORAMA_* / vm_* resolution applies)
python tools/pan/pan_group_remap_report.py --csv $CSV --no-tls-verify
```

## Outputs (UTC timestamps)

| Path | Content |
|---|---|
| `pan_capture/<host>/<TS>/` | raw pulled JSON: addresses, address groups, pre/post rules per scope |
| `pan_reports/<host>/<TS>/group_remap_dryrun/report.md` | the human report |
| `pan_reports/<host>/<TS>/group_remap_dryrun/report.json` | full structured detail, including the `updates` work list a future push tool consumes |

## Reading the report

| Section | Meaning |
|---|---|
| 1 Object actions | deduplicated: each object ONCE, at the location where it is defined; create vs reuse, with a compact reference summary |
| 2 What gets added where | the work list: one row per group / rule side, with every member it would gain and why |
| 3 Already remapped | old/new value pairs both present already (rerun safety) |
| 4 Ranges | analysis only; statuses mapped / overlaps / no_mapping |
| 5 Never remapped | fqdn, IPv6, dynamic groups |
| 6 Unresolved / nested | members that resolved to nothing, nested groups |
| 6b Group references in rules | rules that inherit changes through a group; informational, no rule edit needed |
| 7 CSV coverage | matches per CSV row; unmatched rows are the gaps |

Exit codes: `0` report written, `1` pull/analysis failure, `2` bad
arguments or `.env`.

## Guardrails

- Read-only by construction: the tool has no push path and the agent
  account's role denies writes anyway (verified with
  `tools/pan/probe_api_permissions.py`).
- Managed firewalls are never contacted; the header of every report states
  this.
- Rerunning is always safe; already-applied pairs surface in section 3
  instead of being re-proposed.
