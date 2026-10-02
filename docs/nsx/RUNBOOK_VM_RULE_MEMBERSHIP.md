# Runbook VM Rule Membership Report (macOS / Linux)

> **This runbook is for macOS / Linux shells only (bash, zsh).**
> Windows users, see [RUNBOOK_VM_RULE_MEMBERSHIP_PS.md](RUNBOOK_VM_RULE_MEMBERSHIP_PS.md).
> Do NOT paste Windows `set VAR=%CD%\...` or backslash paths into bash/zsh:
> the backslash silently corrupts filenames and `set` is a no-op, so tools
> then fail with `ModuleNotFoundError: No module named 'nsx'`.

Read-only tool. Given a list of VM display names and/or IP addresses, walks
every DFW rule and emits a markdown + JSON report organised by rule, showing
which of the requested VMs / IPs each rule touches and via which side
(Src / Dst / Scope).

Two ways to run it:

- **Live** (Steps 1 to 3): the report queries NSX every run.
- **Capture once, look up offline** ([Offline lookups](#offline-lookups-capture-once-look-up-many)):
  one read-only capture per manager (LM or GM), kept as timestamped history
  like the backups; then any number of lookups with zero NSX calls.

## Step 0: Env

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

(A `.pth` file in the venv makes `PYTHONPATH` optional. If unset, tools still find `app/nsx`.)

## Step 1: Prepare the VM target list

Edit `vm_rule_report_targets.txt` at the repo root. `#` comments and blank
lines ignored. Two entry styles:

```
# Just a name -> NSX lookup; IPs auto-fetched from VM VIFs.
ubuntu22-speedtest-10.6.0.101-ax2001
ubuntu22-speedtest-10.6.2.102-gh0202

# Just an IP -> which rules cover that address (no VM name needed).
10.6.0.101

# name,ip[,ip,...] -> NSX lookup + explicit IPs. If the name matches on NSX,
# both auto-fetched AND explicit IPs are used for group-IP matching. If the
# name does NOT match on NSX (planned VM), falls back to IP-only mode.
future-web-01,10.6.0.50
new-app,10.7.5.100,10.7.5.101
probe,10.6.0.99
```

Case-insensitive match on the name. Invalid IP tokens are logged and skipped.
Report `Kind` column shows `NSX`, `NSX+ip`, `planned`, or `IP` per entry. An
`IP` entry also names the VM that holds that address when NSX knows it.

Or skip the file and pass a comma-separated list on the command line.
Every token is its own entry, so `web01,10.6.0.101` here means the VM `web01`
AND the IP `10.6.0.101` (in the file, `name,ip` attaches the IP to the name):

```bash
python tools/reports/report_vms_in_rules.py --manager nsx-lm1 \
  --targets "ubuntu22-speedtest-10.6.0.101-ax2001,10.6.1.102,10.10.2.78"
```

Alternative locations (only if you don't want to use the repo-root file):

- CLI: `--vm-list /some/other/path.txt`
- `.env`: `VM_RULE_REPORT_LIST=/some/other/path.txt`

Precedence: `--targets` > `--vm-list` > `VM_RULE_REPORT_LIST` >
auto-discovered `vm_rule_report_targets.txt` at repo root.

## Step 2: Run the report

```bash
python tools/reports/report_vms_in_rules.py --manager nsx-lm1
```

Common variations:

```bash
setopt interactive_comments 2>/dev/null || true

# Explicit list file
python tools/reports/report_vms_in_rules.py --manager nsx-lm1 \
  --vm-list some_other_list.txt

# Custom output root (default: nsx_logs/reports/<host>/vm_rule_membership/<UTC_TS>/)
python tools/reports/report_vms_in_rules.py --manager nsx-lm1 \
  --output-dir /tmp/vm_rule_report

# Re-run into the same output dir
python tools/reports/report_vms_in_rules.py --manager nsx-lm1 --overwrite
```

### GM (federated) mode - one report across all sites

Point at a GM with `--federation-global` and the tool talks to the GM ONLY:

1. Discover federation sites from GM (`/global-manager/api/v1/global-infra/sites`).
2. Pull federated groups from GM.
3. For each group, UNION its members across every site with one GM-proxied
   call per site per group: `/members/virtual-machines` (and
   `/members/ip-addresses`) with `?enforcement_point_path=/global-infra/sites/
   <site>/enforcement-points/default`. A bare GM member call returns 400; the
   enforcement-point form is proxied by the GM to each site, so NO direct LM
   connections are needed.
4. Build the VM universe (names, ids, tags, site) from those member objects,
   so name matching works without fabric inventory.
5. Pull federated rules from GM.
6. Correlate and emit ONE report showing per-VM which site it lives on
   (`Site` column) and which federated rules touch it.

Location-scoped domains (domain id equal to a site id, e.g.
`labdc1-w01-lnsx`) are queried ONLY at their own site; cross-site NOT_FOUND
responses for a group not realized at a site are benign and logged at debug,
with one summary count at the end.

Call volume: membership is fetched ONLY for groups that rules reference
(a group no rule uses cannot produce a hit; NSX rolls nested-group members up
into the parent, so this loses nothing), with proper pagination for groups
over 1000 members. `--members-cache-minutes N` reuses the pull from disk for
repeat runs (different VM lists cost zero member calls). The target-VM list
never drives API calls at all.

A federation-global run talks to the GM and nothing else: it never opens a
session to a site LM (the client refuses the combination outright), so
fabric-sourced VM IPs are not part of the GM report. Targets with explicit
IPs in the list keep their IPs.

```bash
python tools/reports/report_vms_in_rules.py \
  --manager nsx-gm1 \
  --federation-global
```

## Offline lookups: capture once, look up many

### Capture (read-only, one or many managers)

```bash
setopt interactive_comments 2>/dev/null || true

# One LM
python tools/nsx/capture_vm_rule_data.py --source nsx-lm1

# A GM and LMs in one run; keep the 14 newest snapshots per host (cron)
python tools/nsx/capture_vm_rule_data.py --source nsx-gm1 nsx-lm1 nsx-lm2 --retain 14
```

Each manager gets `nsx_vm_rule_snapshots/<host>/<UTC_TS>/`:

| File | Purpose |
|---|---|
| `vm_rule_snapshot.json` | VMs (LM: with their VIF IPs), every domain's groups, NSX's evaluated VM members and IP members per group, every rule |
| `manifest.json` / `summary.txt` | ok flag, counts, fetch errors |
| `capture.log` | this manager's log lines |

`nsx_vm_rule_snapshots/<host>/latest` points at the newest COMPLETE snapshot.
If any group or rule fetch failed, the snapshot is still written but is NOT
marked `latest`, and the run exits 1. A GM alias (`nsx-gm*`) talks to the GM
only, exactly like a live `--federation-global` run (see GM mode above).

The capture runs the same pull code as a live report, so a lookup against a
snapshot gives the answer a live run would have given at capture time.
Verified on nsx-lm1 2026-09-29: live and snapshot reports for 9 names and IPs
were identical, entry for entry.

### Look up (no NSX contact)

```bash
python tools/reports/report_vms_in_rules.py \
  --from-snapshot nsx_vm_rule_snapshots/nsx-lm1.lab.local \
  --targets "ubuntu22-speedtest-10.6.0.101-ax2001,edge1.lab.local,10.6.1.102,10.10.2.78"
```

`--from-snapshot` takes the host dir (uses `latest`), a specific
`<host>/<UTC_TS>/` dir, or the `vm_rule_snapshot.json` file. `--manager` is
optional here (the snapshot names its manager). `--vm-list` works too. The
report header says `snapshot captured <time>`: membership is as of the
capture, so re-capture before a change window.

Things to know:

- A name matches through the VM's group memberships AND through its IPs. A
  powered-off VM has no VIF IPs, so looking it up by name finds fewer groups
  than looking up its IP (NSX keeps the last-known IP in group membership).
  For those, add the IP: `--targets "vmname,10.6.1.102"`.
- GM snapshots carry no VM IPs (the GM never talks to an LM). Name entries
  match by VM membership, IP entries by the groups' evaluated IPs.
- A GM captures membership only for groups that rules reference, the same
  as a live GM run. Every group and rule definition is still in the snapshot.

## Step 3: Read the report

```bash
setopt interactive_comments 2>/dev/null || true

LATEST=$(ls -1td nsx_logs/reports/nsx-lm1.lab.local/vm_rule_membership/*/ | head -1)
echo "Latest run: $LATEST"

# Open the markdown in your editor:
open "$LATEST/report.md"

# Or read machine-readable data:
cat "$LATEST/report.json" | jq '.counts, .rules[0]'
```

**Report structure (`report.md`)**

- Header: data source (live, or snapshot with its capture time), totals
  (requested / matched / not_found / duplicates, rules scanned, rules
  hitting targets).
- Matched-VMs table (with per-VM group count and rule-hit count).
- Names-not-found bucket (typos or VMs that aren't on this manager).
- Matched-but-in-zero-rules bucket (VMs uncovered by any DFW rule).
- One section per rule that touches at least one requested VM. Rules
  with `ANY` on both source AND destination are labelled `[GLOBAL]`.

**Files written per run**

| File | Purpose |
|---|---|
| `report.md` | Rule-centric markdown report |
| `report.json` | Full machine-readable data (rules, hits, resolution) |

Per-run log lives at `nsx_logs/vm_rule_membership_<UTC_TS>.log`.

## Safety

- Strictly read-only: GETs only, no NSX writes anywhere.
- LM mode: one live `/members/virtual-machines` and one
  `/members/ip-addresses` call per group, plus one VM list and one VIF list.
  Expect a few seconds per 25 groups. Progress logged.
- Offline (`--from-snapshot`): zero NSX calls.
- GM (federated) mode: same, but multiplied by the number of federated
  sites. Runtime scales roughly as `groups x sites`. Progress logged.

## See also

- [RUNBOOK_VM_RULE_MEMBERSHIP_PS.md](RUNBOOK_VM_RULE_MEMBERSHIP_PS.md) - Windows PowerShell variant of this runbook
- [REPORTS_DATA_SOURCES.md](../reference/REPORTS_DATA_SOURCES.md) - data-source breakdown for all report tools
