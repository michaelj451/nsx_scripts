# Migration requests (PowerShell): from a server list to approved NSX and Palo Alto changes

PowerShell variant of [RUNBOOK_MIGRATION_REQUEST.md](RUNBOOK_MIGRATION_REQUEST.md).
What a request covers, what the approver reads, the gate, verification and
the known limits live there; this card carries the same steps as PowerShell
commands. Run from the repository root.

Windows may not allow the `latest` link, so this card always finds the newest
timestamped folder instead.

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

## 1) Request

`servers_wave1.txt`, one server per line (`name`, `ip`, or `name,ip`):

```text
# wave 1, ticket REQ-1234
ubuntu22-speedtest-10.6.0.101-ax2001
10.6.2.102
ubuntu22-speedtest-10.6.1.102-0102,10.6.1.102
```

```powershell
Mr request --source nsx-lm1 --destination nsx-lm3 --device-group dg-4 `
  --no-tls-verify --name "wave 1" --server-list servers_wave1.txt

$R = Newest "migration_requests\nsx-lm1_to_nsx-lm3"
notepad "$R\request.md"
```

Offline instead (`--no-preview`), then the dry runs one part at a time:

```powershell
Mr preview --request $R --part a --no-tls-verify   # or c, d, palo, all
```

## 2) Review

Read `$R\request.md`. The full Palo plan is `$R\palo\plan.md`.

## 3) Approve

```powershell
Mr approve --request $R --change-ref CHG0012345 --approved-by "Name Surname"
```

## 4) Implement, in the change window

```powershell
Mr refresh --request $R
$RUN = Newest "$R\runs"
Get-Content "$RUN\delta.md"
```

Exit code 0: gate passed. Exit code 2: stopped, read `delta.md`.

```powershell
Mr run --run $RUN --phase a
Mr run --run $RUN --phase a --apply
Mr run --run $RUN --phase a --verify

Mr run --run $RUN --phase c
Mr run --run $RUN --phase c --apply
Mr run --run $RUN --phase c --verify

Mr run --run $RUN --phase d2a
Mr run --run $RUN --phase d2a --apply
Mr run --run $RUN --phase d3
Mr run --run $RUN --phase d3 --apply
Mr run --run $RUN --phase d3 --verify

Mr run --run $RUN --phase palo --no-tls-verify
Mr run --run $RUN --phase palo --no-tls-verify --apply
Mr run --run $RUN --phase palo --no-tls-verify --verify
```

Reports: `$RUN\report\<phase>\<mode>\`.

### Rollback

Newest first: `palo`, `d3`, `d2a`, `c`, `a`. Preview, then apply:

```powershell
Mr run --run $RUN --phase d3 --rollback
Mr run --run $RUN --phase d3 --rollback --apply
```
