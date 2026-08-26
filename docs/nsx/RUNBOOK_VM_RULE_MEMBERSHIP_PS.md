# Runbook VM Rule Membership Report (Windows PowerShell)

> **This runbook is for Windows PowerShell only.**
> macOS / Linux users, see [RUNBOOK_VM_RULE_MEMBERSHIP.md](RUNBOOK_VM_RULE_MEMBERSHIP.md).
> PowerShell line-continuation is the backtick `` ` `` at end of line. Do
> NOT paste PS lines into bash/zsh: the backtick starts a command
> substitution and hangs the shell at `bquote>`.

Read-only tool. Given a list of VM display names, walks every DFW rule and
emits a markdown + JSON report organised by rule, showing which of the
requested VMs each rule touches and via which side (Src / Dst / Scope).

## Step 0: Env (once per PowerShell session)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

Assumes `.env` at the repo root is populated with NSX credentials and
manager aliases.

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

- CLI: `--vm-list C:\path\to\other_list.txt`
- `.env`: `VM_RULE_REPORT_LIST=C:\path\to\other_list.txt`

Precedence: `--vm-list` > `VM_RULE_REPORT_LIST` > auto-discovered
`vm_rule_report_targets.txt` at repo root.

## Step 2: Run the report

```powershell
python tools/reports/report_vms_in_rules.py --manager nsx-lm1
```

Common variations:

```powershell
# Explicit list file
python tools/reports/report_vms_in_rules.py `
  --manager nsx-lm1 `
  --vm-list some_other_list.txt

# Custom output root (default: nsx_logs\reports\vm_rule_membership\<host>\<UTC_TS>\)
python tools/reports/report_vms_in_rules.py `
  --manager nsx-lm1 `
  --output-dir C:\temp\vm_rule_report

# Re-run into the same output dir
python tools/reports/report_vms_in_rules.py --manager nsx-lm1 --overwrite
```

### GM (federated) mode - one report across all sites

Point at a GM with `--federation-global` and the tool will:

1. Discover federation sites from GM (`/global-manager/api/v1/global-infra/sites`).
2. For each site, connect directly to the LM to pull fabric VM inventory
   (fabric API is LM-only, one client per site with `federation_global=False`).
3. Pull federated groups from GM.
4. For each group, UNION its members across every site (one live
   `/members/virtual-machines` per site per group, using `federation_global=True`
   clients). Works around the known GM member endpoint returning 400
   without an enforcement point.
5. Pull federated rules from GM.
6. Correlate and emit ONE report showing per-VM which site it lives on
   (new `Site` column in the matched-VMs table) and which federated rules
   touch it.

```powershell
python tools/reports/report_vms_in_rules.py `
  --manager nsx-gm1 `
  --federation-global
```

Requires that each federated site's ID resolves to a reachable LM hostname
(same convention `report_groups_usage.py` uses). Sites that fail to connect
are logged with a WARN and their VMs won't appear in the report.

## Step 3: Read the report

```powershell
$latest = (Get-ChildItem "nsx_logs\reports\vm_rule_membership\nsx-lm1.lab.local" -Directory `
           | Sort-Object Name -Descending | Select-Object -First 1).FullName
Write-Host "Latest run: $latest"

# Open the markdown in the default associated app:
Invoke-Item "$latest\report.md"

# Or inspect the JSON:
Get-Content "$latest\report.json" | ConvertFrom-Json | Select-Object -ExpandProperty counts
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

Per-run log lives at `nsx_logs\vm_rule_membership_<UTC_TS>.log`.

## Safety

- Strictly read-only: GETs only, no NSX writes anywhere.
- LM mode: one live `/members/virtual-machines` API call per group.
  Expect a few seconds per 25 groups. Progress logged.
- GM (federated) mode: same, but multiplied by the number of federated
  sites. Runtime scales roughly as `groups x sites`. Progress logged.

## See also

- [RUNBOOK_VM_RULE_MEMBERSHIP.md](RUNBOOK_VM_RULE_MEMBERSHIP.md) - macOS / Linux variant of this runbook
- [REPORTS_DATA_SOURCES.md](REPORTS_DATA_SOURCES.md) - data-source breakdown for all report tools
