# Runbook VM Rule Membership Report (macOS / Linux)

> **This runbook is for macOS / Linux shells only (bash, zsh).**
> Windows users, see [RUNBOOK_VM_RULE_MEMBERSHIP_PS.md](RUNBOOK_VM_RULE_MEMBERSHIP_PS.md).
> Do NOT paste Windows `set VAR=%CD%\...` or backslash paths into bash/zsh:
> the backslash silently corrupts filenames and `set` is a no-op, so tools
> then fail with `ModuleNotFoundError: No module named 'nsx'`.

Read-only tool. Given a list of VM display names, walks every DFW rule and
emits a markdown + JSON report organised by rule, showing which of the
requested VMs each rule touches and via which side (Src / Dst / Scope).

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

# name,ip[,ip,...] -> NSX lookup + explicit IPs. If the name matches on NSX,
# both auto-fetched AND explicit IPs are used for group-IP matching. If the
# name does NOT match on NSX (planned VM), falls back to IP-only mode.
future-web-01,10.6.0.50
new-app,10.7.5.100,10.7.5.101
probe,10.6.0.99
```

Case-insensitive match on the name. Invalid IP tokens are logged and skipped.
Report `Kind` column shows `NSX`, `NSX+ip`, or `planned` per entry.

Alternative locations (only if you don't want to use the repo-root file):

- CLI: `--vm-list /some/other/path.txt`
- `.env`: `VM_RULE_REPORT_LIST=/some/other/path.txt`

Precedence: `--vm-list` > `VM_RULE_REPORT_LIST` > auto-discovered
`vm_rule_report_targets.txt` at repo root.

## Step 2: Run the report

```bash
python tools/reports/report_vms_in_rules.py --manager nsx-lm1
```

Common variations:

```bash
# Explicit list file
python tools/reports/report_vms_in_rules.py --manager nsx-lm1 \
  --vm-list some_other_list.txt

# Custom output root (default: nsx_logs/reports/vm_rule_membership/<host>/<UTC_TS>/)
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

Optional: `--with-vm-inventory` ALSO connects directly to each site LM for
fabric VM inventory, which enriches the report with VM IP addresses.
Unreachable LMs are warnings, never fatal (targets with explicit IPs in the
list keep their IPs either way).

```bash
python tools/reports/report_vms_in_rules.py \
  --manager nsx-gm1 \
  --federation-global
```

LM reachability is only needed with `--with-vm-inventory` (each site ID must
then resolve to a reachable LM hostname). Without it, the report is complete
minus fabric-sourced VM IPs.

## Step 3: Read the report

```bash
LATEST=$(ls -1td nsx_logs/reports/vm_rule_membership/nsx-lm1.lab.local/*/ | head -1)
echo "Latest run: $LATEST"

# Open the markdown in your editor:
open "$LATEST/report.md"

# Or read machine-readable data:
cat "$LATEST/report.json" | jq '.counts, .rules[0]'
```

**Report structure (`report.md`)**

- Header: totals (requested / matched / not_found / duplicates, rules
  scanned, rules hitting targets).
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
- LM mode: one live `/members/virtual-machines` API call per group.
  Expect a few seconds per 25 groups. Progress logged.
- GM (federated) mode: same, but multiplied by the number of federated
  sites. Runtime scales roughly as `groups x sites`. Progress logged.

## See also

- [RUNBOOK_VM_RULE_MEMBERSHIP_PS.md](RUNBOOK_VM_RULE_MEMBERSHIP_PS.md) - Windows PowerShell variant of this runbook
- [REPORTS_DATA_SOURCES.md](../reference/REPORTS_DATA_SOURCES.md) - data-source breakdown for all report tools
