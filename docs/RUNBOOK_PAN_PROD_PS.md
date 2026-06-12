# Runbook — Palo Alto Production (manual, no API) — Windows PowerShell

> ## 🔒 PRODUCTION DISCIPLINE — manual, local, no API
>
> Tools in this runbook **NEVER authenticate against a Panorama**. They run
> on the operator's local machine, read an **exported config XML** (or a
> file emailed by the customer), and produce reports locally. No network
> connection is ever opened to the customer's Panorama.
>
> | Property | Guarantee |
> |---|---|
> | Network calls to customer Panorama | None — tools have no API client loaded |
> | Credentials needed | None |
> | Where tools execute | Operator's laptop / workstation only |
> | Customer environment side-effects | Zero |
> | Reversibility | Trivially — nothing was written anywhere customer-side |
> | Input | An XML config file the customer provides |
> | Output | Reports written to the operator's local `$env:PANO_REPORTS_DIR\` dir |
>
> For lab development work against `pano4.lab.local`, see
> [RUNBOOK_PAN_LAB_PS.md](RUNBOOK_PAN_LAB_PS.md).

Bash/macOS variant with full narrative: [RUNBOOK_PAN_PROD.md](RUNBOOK_PAN_PROD.md).

Line continuation in PowerShell is the backtick `` ` `` at end of line.

---

## What's covered here

| Tool | Purpose | Input | Output |
|---|---|---|---|
| `tools/pan/check_policy_match.py` | Offline "can A reach B" policy lookup — walks the full Panorama evaluation chain in correct PAN-OS order, reports verdict + matched rule + trace | Panorama XML config file + `(src_ip, dst_ip, [zones], [service/port])` | `verdict.json` + human/JSON stdout |
| `tools/pan/recommend_dg.py` | "Which DG should a new rule go on?" — checks for existing matches, then if none, scores each DG's affinity to the flow's /24 (or other CIDR) by counting rules referencing the same address space | Same as above + `--subnet-mask` | `recommendation.json` + `recommendation.txt` + human/JSON stdout |

---

## How customers send you the config XML

| Method | Steps |
|---|---|
| Panorama Web UI | Device → Setup → Operations → "Save named configuration snapshot" → "Export named configuration snapshot" |
| Panorama CLI | `show config running` → save output |
| Operator-run API call | `Invoke-RestMethod -SkipCertificateCheck "https://<panorama>/api/?type=op&cmd=<show><config><running></running></config></show>&key=KEY"` — operator runs this, not the analysis tool |
| Backup archive | Recent `panorama_backup.tgz` from backup system — extract `running-config.xml` |

The file is **typically 10-100 MB** for a real production Panorama. If a customer sends you something dramatically smaller (~100 KB), it might be a partial export — ask before analyzing.

---

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

**No `.env` credentials needed.** The production tool does not load Panorama credentials, manager hostnames, or API tokens — even when a `.env` file is present in the repo.

The one path setting the tool optionally reads from `.env` is `PANO_REPORTS_DIR` (where to land each query's `verdict.json` audit record). The reader looks at this one variable (plus `ROOT_DIR` for `$VAR` expansion) and ignores every other line in the file. If `PANO_REPORTS_DIR` isn't set anywhere, the tool falls back to `.\.pano_reports\` in the current directory.

To opt out of disk writes entirely (one-off CAB questions where no audit trail is wanted), use `--no-disk`.

---

## Where to put the customer's XML file

| Location | Convention | Why |
|---|---|---|
| `tools\pan\configs\<customer>-<ts>.xml` | **Recommended** | Auto-gitignored. One folder for all customer configs. |
| Outside the repo (e.g., `$HOME\customer-configs\`) | Alternative | Cleanest separation. Give the tool the absolute path. |

```powershell
Copy-Item "$HOME\Downloads\customer-X-config.xml" `
          "tools\pan\configs\customer-X-2026-06.xml"
```

---

## 1. Offline policy lookup — `check_policy_match.py`

### Basic invocation

```powershell
python tools/pan/check_policy_match.py `
  --config tools/pan/configs/<customer>-<ts>.xml `
  --device-group BranchOffice-DG `
  --src-ip 10.20.5.7 --dst-ip 192.168.10.42 `
  --protocol tcp --dst-port 443
```

Add `-v` / `--verbose` for the per-rule skip trace, or `--json` for structured output.

### JSON output for piping

```powershell
$verdict = python tools/pan/check_policy_match.py `
  --config tools/pan/configs/customer-X-2026-06.xml `
  --device-group CustomerX-DG `
  --src-ip 10.50.10.5 --dst-ip 8.8.8.8 --protocol udp --dst-port 53 --json `
  | ConvertFrom-Json

Write-Host "Verdict: $($verdict.verdict)"
Write-Host "Matched rule: $($verdict.matched_rule) in $($verdict.matched_rulebase)"
$verdict.caveats | ForEach-Object { Write-Host "  caveat: $_" }
```

### Why this is production-safe

| What it does | What it does NOT do |
|---|---|
| Read the XML file on local disk | Open any network connection |
| Parse with Python `xml.etree.ElementTree` | Authenticate against anything |
| Compute matches in memory | Write to any remote service |
| Emit a report to local disk + stdout | Modify the customer's XML file |

### Exit code

`0` if ALLOWED, `1` otherwise.

---

## 2. DG recommendation — `recommend_dg.py`

When `check_policy_match.py` returns DENIED (or you already know a flow isn't allowed), the next question is **where does the new rule go?** `recommend_dg.py` answers that.

### Algorithm

1. Run an existing-match check across every DG. If any customer rule already allows the flow → tool reports the existing match and exits 0 (no new rule needed).
2. If no match, compute `src_subnet` and `dst_subnet` at `--subnet-mask` (default `/24`).
3. For each DG, scan its **DG-specific rulebases only** (DG-pre + DG-post — NOT shared, NOT default). Count rules whose source addresses overlap `src_subnet`, and rules whose destination addresses overlap `dst_subnet`.
4. Recommend the DG with the highest combined score. Ties broken alphabetically. If every DG scores zero AND shared scores zero, recommend `shared/post-rulebase` as the catch-all home.

### Basic invocation

```powershell
python tools/pan/recommend_dg.py `
  --config tools/pan/configs/<customer>-<ts>.xml `
  --src-ip 10.50.5.10 --dst-ip 8.8.8.8 `
  --protocol tcp --dst-port 443
```

### Tuning the affinity window

```powershell
# Widen to /16
python tools/pan/recommend_dg.py --config $cfg `
  --src-ip 10.50.5.10 --dst-ip 8.8.8.8 `
  --protocol tcp --dst-port 443 `
  --subnet-mask 16
```

### Pipe-friendly JSON

```powershell
$rec = python tools/pan/recommend_dg.py `
  --config tools/pan/configs/customer-X-2026-06.xml `
  --src-ip 10.50.5.10 --dst-ip 8.8.8.8 `
  --protocol tcp --dst-port 443 `
  --json --no-disk | ConvertFrom-Json

if ($rec.needs_new_rule) {
  Write-Host "Recommendation: $($rec.recommendation.type) → $($rec.recommendation.device_group ?? $rec.recommendation.rulebase)"
  $rec.recommendation.sample_rules | ForEach-Object {
    Write-Host "  supports: $($_.rulebase) / pos $($_.position) / $($_.name)"
  }
} else {
  Write-Host "Existing rule already matches — no new rule needed."
  $rec.existing_matches | ForEach-Object {
    Write-Host "  [$($_.device_group)] $($_.matched_rulebase) / $($_.matched_rule)"
  }
}
```

### What gets written

```
$env:PANO_REPORTS_DIR\recommend_dg\<UTC_TS>\
├── recommendation.json    full structured record (audit-friendly)
└── recommendation.txt     human-readable copy of the stdout view
```

### Caveats specific to this tool

- **Affinity is purely structural** — it counts rules whose address objects overlap the requested /N. It does not consider zones, services, or rule order.
- **Shared rulebases score is informational only.** The recommendation is always a DG (or, when nothing scores, a shared rulebase as fallback).
- **DAGs and FQDN addresses are skipped** (same offline limitations as `check_policy_match.py`).
- **A DG with score 0 may still be the right answer** — operator should review the recommendation.

### Exit code

`0` in all cases. The "no match → no recommendation" case isn't an error.

---

## 3. Common operational patterns

### Single-flow check (the CAB question)

```powershell
python tools/pan/check_policy_match.py `
  --config tools/pan/configs/customer-X-2026-06.xml `
  --device-group CustomerX-DG `
  --src-ip 10.50.10.5 --dst-ip 8.8.8.8 `
  --protocol udp --dst-port 53 `
  --src-zone trust --dst-zone untrust -v
```

### Batch-checking N flows from a CSV

```powershell
$cfg = "tools/pan/configs/customer-X-2026-06.xml"
$dg  = "CustomerX-DG"

Import-Csv flows.csv | ForEach-Object {
  $result = python tools/pan/check_policy_match.py `
    --config $cfg --device-group $dg `
    --src-ip $_.src --dst-ip $_.dst `
    --protocol $_.proto --dst-port $_.port `
    --json | ConvertFrom-Json
  [PSCustomObject]@{
    src     = $_.src
    dst     = $_.dst
    proto   = $_.proto
    port    = $_.port
    verdict = $result.verdict
    rule    = $result.matched_rule
  }
} | Export-Csv flow_audit.csv -NoTypeInformation
```

### When you don't know which device-group

Use `--all-device-groups` (no loop required):

```powershell
python tools/pan/check_policy_match.py --config $cfg --all-device-groups `
  --src-ip 10.50.10.5 --dst-ip 8.8.8.8 `
  --protocol tcp --dst-port 443
```

Output:

```
========================================================================
ALL-DG POLICY MATCH
========================================================================
Query:        src=10.50.10.5  dst=8.8.8.8
              proto=tcp  port=443

  [dg-3      ] ALLOWED   shared/pre-rulebase/pos 1  'allow-logging'
  [dg-5      ] ALLOWED   shared/pre-rulebase/pos 1  'allow-logging'
  [dg-6      ] DENIED    default-rules/pos 2  'interzone-default'  ← default-rule fall-through
  [dg-4      ] ALLOWED   BranchOffice-DG/post-rulebase/pos 3  'allow-web'

  Summary: 3/4 DGs have a CUSTOMER rule explicitly allowing this flow.
  Caveat:  default-rule matches above depend on actual src/dst zones (not specified in this query).
```

The `← default-rule fall-through` marker flags rows where no customer rule matched — the verdict comes from PAN's synthetic intrazone/interzone defaults and is zone-dependent on the real firewall.

JSON form for piping:

```powershell
$result = python tools/pan/check_policy_match.py --config $cfg --all-device-groups `
  --src-ip 10.50.10.5 --dst-ip 8.8.8.8 `
  --protocol tcp --dst-port 443 --json --no-disk | ConvertFrom-Json

$result.device_groups | Format-Table device_group, verdict, matched_rule, matched_rulebase
```

Exit code: `0` if at least one DG returns ALLOWED, `1` otherwise.

---

## 4. Offline limitations (surfaced as `caveats` in the verdict)

| Limitation | What the tool does |
|---|---|
| App-ID matching can't be evaluated offline | Treats `application` as wildcard when query doesn't specify app; emits caveat |
| `application-default` service depends on runtime App-ID | Treats as match-any-port with a caveat |
| Dynamic Address Groups (DAGs) have runtime tag membership | Emits caveat with the DAG filter; doesn't expand |
| FQDN address objects require DNS resolution | Caveat — IP can't be matched |
| NAT rules can change effective IPs | NAT is not evaluated yet |
| User-ID | Treated as `any` |
| Firewall-local rulebase (rules on firewall itself) | Invisible — only Panorama-side rules |
| Schedules (time-of-day rules) | Ignored |

---

## 5. Customer engagement workflow

1. **Request the config** — running-config XML export, current timestamp.
2. **Land it in `tools\pan\configs\`**
   ```powershell
   Copy-Item "$HOME\Downloads\customer-X-config.xml" "tools\pan\configs\customer-X-2026-06.xml"
   ```
3. **Run the relevant analysis tool(s)**
   ```powershell
   python tools/pan/check_policy_match.py --config tools/pan/configs/customer-X-2026-06.xml `
     --device-group <DG> --src-ip ... --dst-ip ... `
     --protocol tcp --dst-port 443 -v --json | Out-File report.json
   ```
4. **Hand back a clean report** — include verdict, matched rule, caveats; exclude unrelated config detail.
5. **Disposition the XML**
   - Leave under `tools\pan\configs\` (gitignored, never committed)
   - Or delete: `Remove-Item tools\pan\configs\customer-X-2026-06.xml`

---

## 6. Safety properties (production)

| Property | Behavior |
|---|---|
| Customer network calls | Never — no network code loaded |
| Customer credentials | Never — no auth code paths |
| Customer config writes | Never — input is read-only |
| Tool failure mode | Fails locally on operator's machine |
| Concurrent operators | Safe — each has their own local XML + reports |
| Multi-customer sessions | Safe — separate XML files = separate in-memory parses |
| Output retention | Operator-controlled — reports under `$env:PANO_REPORTS_DIR\` |

---

## 7. What customers can verify

If a customer asks "what does this tool do to my Panorama":

- "Nothing — it doesn't reach your Panorama at all"
- "I'm running it on my laptop, against the XML you sent me"
- "The repo has the source — there's no network code in the production tools"

Pointing them at this runbook is a clean way to demonstrate the scope.

---

## 8. Full tool flag reference

### `check_policy_match.py`

| Flag | Default | Purpose |
|---|---|---|
| `--config <path>` | required | Path to the Panorama running-config XML file |
| `--device-group <name>` | one-of | Target DG name. Use when you know the DG. |
| `--all-device-groups` | one-of | Evaluate against every DG and emit a per-DG verdict. **Mutually exclusive with `--device-group`.** |
| `--src-ip <ip>` | required | Source IP |
| `--dst-ip <ip>` | required | Destination IP |
| `--src-zone <name>` | (any) | Source zone — omit for zone-agnostic match |
| `--dst-zone <name>` | (any) | Destination zone — omit for zone-agnostic match |
| `--protocol {tcp,udp}` | (any) | Protocol |
| `--dst-port <int>` | (any) | Destination port |
| `--verbose` / `-v` | off | Print the full per-rule evaluation trace |
| `--json` | off | Suppress human output; emit structured JSON only |
| `--output-dir <path>` | `$env:PANO_REPORTS_DIR` (or `.\.pano_reports\`) | Override the report root. Each run lands at `<dir>\check_policy_match\<UTC_TS>\verdict.json` |
| `--no-disk` | off | Suppress the on-disk verdict.json (stdout only) |

### Exit codes (`check_policy_match.py`)

| Code | Meaning |
|---|---|
| `0` | Verdict was `allow` |
| `1` | Verdict was anything else |

### `recommend_dg.py`

| Flag | Default | Purpose |
|---|---|---|
| `--config <path>` | required | Path to the Panorama running-config XML file |
| `--src-ip <ip>` | required | Source IP |
| `--dst-ip <ip>` | required | Destination IP |
| `--src-zone <name>` | (any) | Source zone — passed through to the existing-match check |
| `--dst-zone <name>` | (any) | Destination zone — passed through to the existing-match check |
| `--protocol {tcp,udp}` | (any) | Protocol |
| `--dst-port <int>` | (any) | Destination port |
| `--subnet-mask <int>` | 24 | CIDR mask used to compute the src/dst /N subnets for affinity scoring |
| `--max-samples <int>` | 5 | Top-N supporting rules per DG to record as recommendation rationale |
| `--json` | off | Suppress human output; emit structured JSON only |
| `--output-dir <path>` | `$env:PANO_REPORTS_DIR` (or `.\.pano_reports\`) | Override report root. Each run lands at `<dir>\recommend_dg\<UTC_TS>\recommendation.{json,txt}` |
| `--no-disk` | off | Suppress the on-disk recommendation files (stdout only) |

### Exit codes (`recommend_dg.py`)

| Code | Meaning |
|---|---|
| `0` | All cases — report emitted successfully |

---

## 9. Caveats — what's NOT in this runbook

The following live in the [lab runbook](RUNBOOK_PAN_LAB_PS.md) and must not bleed into production work:

- API authentication
- Config snapshot pulling (`pull_panorama_config.py`) — uses the API
- Configuration changes (`add_services_to_rules.py`) — writes to candidate
- Commit / revert operations
- TLS verification disabling

**If you reach for any of these on a customer engagement, stop.** Ask the customer for a fresh XML export instead.
