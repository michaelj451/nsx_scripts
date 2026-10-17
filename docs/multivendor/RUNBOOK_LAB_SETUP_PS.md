# Lab setup (PowerShell): replicate a client migration request in the lab

PowerShell variant of [RUNBOOK_LAB_SETUP.md](RUNBOOK_LAB_SETUP.md). Why it is
Workflow A in full (Part 1, then Part 3) and not Workflow C, what lands, what
differs in the lab and the proof run live there; this card carries the same
steps as PowerShell commands. Run from the repository root.

**Client data.** The package is the client's firewall configuration. It stays
in git-ignored folders (`nsx_capture\`, `nsx_*_export\`, `migration_requests\`);
never copy it into `data\` or `docs\`, and delete it when the test is done.

---

## 0) Env

```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH  = "$PWD\app"
$env:NSX_LOG_DIR = "$PWD\nsx_logs"
$env:PYTHONUTF8  = "1"

function Mr { python tools/multisite/migration_request.py @args }
function Newest($dir) {
  (Get-ChildItem $dir -Directory | Where-Object Name -match '^\d{8}_\d{6}$' |
   Sort-Object Name | Select-Object -Last 1).FullName
}
```

## 1) At the client: capture the source, right after the request

```powershell
$SRC = "nsx-lm1"                  # the client source alias in .env
$H   = "nsx-lm1.lab.local"        # its host name
python tools/nsx/capture_nsx_state.py --source $SRC --live-query --with-segments
Get-Content "nsx_capture\$H\summary.txt"    # every step OK, Result: OK
```

## 2) At the client: the server list and the package

```powershell
$R   = Newest "migration_requests\nsx-lm1_to_nsx-lm3"     # the client request
$Out = "migration_requests\lab_replica\$H"
New-Item -ItemType Directory -Force $Out | Out-Null

$rec   = Get-Content "$R\request.json" -Raw | ConvertFrom-Json
$lines = @("# lab replica of $($rec.request_id)")
foreach ($s in $rec.servers) {
  $name = if ($s.vm) { $s.vm } else { $s.key }
  if ($s.ips) { $lines += (@($name) + $s.ips) -join "," }
  else        { $lines += "# $($s.key): no address at the client ($($s.status))" }
}
$lines | Set-Content "$Out\servers.txt" -Encoding utf8
Get-Content "$Out\servers.txt"
Copy-Item $rec.inputs.subnet_map "$Out\subnet_map.csv"
```

Package with `tar` (built into Windows 10 and later). It keeps the folder
paths, so everything unpacks where the tools expect it:

```powershell
$Req = (Resolve-Path $R -Relative).TrimStart('.', '\') -replace '\\', '/'
tar -czf "lab_replica_${H}_$((Get-Date).ToUniversalTime().ToString('yyyyMMdd')).tgz" `
  "nsx_capture/$H" "nsx_services_export/$H" "nsx_groups_export/$H" `
  "nsx_policies_export/$H" "nsx_rules_export/$H" "migration_requests/lab_replica/$H" $Req
```

## 3) Carry it to the lab and unpack

Move the `.tgz` by whatever path the client allows, then at the root of the
lab checkout:

```powershell
tar -xzf lab_replica_<host>_<date>.tgz
```

## 4) In the lab: push with Workflow A in full

Pick an **empty** lab manager. Run each without `--apply`, read its summary,
then add `--apply`.

```powershell
$LAB = "nsx-lm4"

# Part 1: 1-for-1 clone, segment members stripped
python tools/nsx/services.py push --target $LAB --services-dir "nsx_services_export\$H\services"
python tools/nsx/groups.py   push --target $LAB --groups-dir   "nsx_groups_export\$H\groups" --segments-mode strip
python tools/nsx/policies.py push --target $LAB --policies-dir "nsx_policies_export\$H\security-policies"
python tools/nsx/rules.py    push --target $LAB --rules-dir    "nsx_rules_export\$H\security-policies"

# Part 3: every group again, with its client member IPs and segment CIDRs
python tools/nsx/groups.py push --target $LAB `
  --groups-dir "nsx_capture\$H\groups_additive\domains\default\groups" `
  --segments-mode convert `
  --segments-from "nsx_capture\$H\segment_inventory\segment_details.json"
```

## 5) In the lab: run the same request

```powershell
Mr request --source $LAB --destination nsx-lm3 --no-tls-verify `
  --server-list "migration_requests\lab_replica\$H\servers.txt" `
  --subnet-map  "migration_requests\lab_replica\$H\subnet_map.csv"
```

Add `--rule-approval <client request>\reports\03_rule_approval_sheet.yaml` to
replay the client's approval decisions.

## 6) Compare, then clean up

Open the client request's `reports\` and the lab request's `reports\` side by
side; what must match and what differs is in the bash card, section 6. Clean
up with the Workflow A reverts ([RUNBOOK_A.md](../nsx/RUNBOOK_A.md)) or
[RUNBOOK_WIPE.md](../tools/test/RUNBOOK_WIPE.md), and delete the package.
