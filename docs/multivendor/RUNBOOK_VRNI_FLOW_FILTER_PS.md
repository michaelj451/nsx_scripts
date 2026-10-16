# vRNI flow filter (PowerShell): leave out the Infrastructure rules

PowerShell variant of [RUNBOOK_VRNI_FLOW_FILTER.md](RUNBOOK_VRNI_FLOW_FILTER.md).
How a flow is judged, the input columns and the lab results live there; this
card carries the same steps as PowerShell commands. Run from the repository
root. The script only reads: the NSX manager is read, never written, and with
`--capture` it is not contacted at all.

**Keep real vRNI exports out of the repository.** They hold production
addresses and host names. Keep them in a folder outside the repo, for example
`$HOME\exports`; the output lands in `nsx_logs\`, which git ignores.

---

## 0) Env

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH  = "$PWD\app"
$env:NSX_LOG_DIR = "$PWD\nsx_logs"
$env:PYTHONUTF8  = "1"

function Flows { python tools/multisite/filter_vrni_flows.py @args }
function Newest($dir) {
  (Get-ChildItem $dir -Directory | Where-Object Name -match '^\d{8}_\d{6}$' |
   Sort-Object Name | Select-Object -Last 1).FullName
}
```

## 1) Export the flows from vRNI

One export per application: in vRNI, **Security > Plan Security**, scope = the
application, a long time range (rarely used rules only show up in a long
window), and make sure **Firewall Rule Id** is one of the columns; then
**Export as CSV**. Save it, for example, as `$HOME\exports\app_flows.csv`.

## 2) Run the filter

Read the rules live from the manager the flows were seen on (read-only):

```powershell
Flows --flows "$HOME\exports\app_flows.csv" --source nsx-lm1
```

Or from a capture already on disk, with no device contact, for example a
migration request's own capture:

```powershell
$R = Newest "migration_requests\nsx-lm1_to_nsx-lm3"
Flows --flows "$HOME\exports\app_flows.csv" --capture "$R\source\capture"
```

Try it first with the lab samples:

```powershell
Flows --flows data\samples\vrni_flows_infra_sample.csv --source nsx-lm1
Flows --flows data\samples\vrni_flows_sample.csv --source nsx-lm1
```

Options:

| Option | Effect |
|---|---|
| `--source nsx-lmN` | The manager the flows came from; its rules are read live (GET only) |
| `--capture DIR` | Read the rules from a `capture_nsx_state.py` folder instead (with several managers in it, add `--source`) |
| `--exclude-category NAME` | Leave out another category too; repeatable (default `Infrastructure` only) |
| `--out-dir DIR` | Where the files go (default `nsx_logs\vrni_flow_filter\<UTC_TS>\`) |
| `--domain-id` | NSX domain (default `default`) |

## 3) Read the results

```powershell
$F = Newest "nsx_logs\vrni_flow_filter"
Get-ChildItem $F
notepad "$F\summary.md"
Start-Process "$F\app_flows_rules.csv"        # opens in Excel
```

| File | Contents |
|---|---|
| `<name>_rules.csv` | Two sections: **Rules kept (application traffic)** and **Infrastructure rules hit (removed)**, each with its title, rule count and header: rule #, rule name, rule id, policy, category, action, flows, packets, result. The rule # matches the approval report and the rule approval sheet (`reports/03_rule_approval_sheet.yaml`) |
| `<name>_filtered.csv` | The kept flow rows, with the export's own columns |
| `<name>_removed.csv` | The Infrastructure flow rows, plus a `filter reason` column naming the policy and rule |
| `<name>_unmatched.csv` | Rows with no rule id, or a number not on that manager, plus the reason; review by hand |
| `summary.md` | Counts, the export window, the same two rule tables, and the unmatched reasons |
| `logs\` | The run log |

A rule marked `kept (NSX default section)`, such as a cleanup DROP, is
application traffic the default rule decided: worth a look.

## Where it fits

The filter is a separate, read-only step. Its rule list goes to the
application owner with the approval report (see
[RUNBOOK_MIGRATION_REQUEST_PS.md](RUNBOOK_MIGRATION_REQUEST_PS.md)); the
rules they approve are set to `needs_approval: false` in the request's
`reports\03_rule_approval_sheet.yaml`. Nothing in the migration request reads these files.
