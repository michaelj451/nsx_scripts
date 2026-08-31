# Runbook: Palo Alto flow/rule report (`report_flow_rules.py`) - Windows PowerShell

> ## 🔒 PRODUCTION DISCIPLINE: offline, local, read-only
>
> This tool **never authenticates against a Panorama** when run with
> `--config`. It reads an exported config XML on the operator's machine and
> writes reports locally. Same production guarantees as the rest of
> [RUNBOOK_PAN_PROD_PS.md](RUNBOOK_PAN_PROD_PS.md).
>
> | Property | Guarantee |
> |---|---|
> | Network calls to customer Panorama | None with `--config`. `--live` is a lab convenience and does one GET-only pull |
> | Credentials needed | None with `--config` |
> | Customer environment side-effects | Zero |
> | Output | Report bundle under `$env:PANO_REPORTS_DIR\flow_rule_report\<UTC_TS>\` |

Bash/macOS variant with the full narrative:
[RUNBOOK_PAN_FLOW_RULES.md](RUNBOOK_PAN_FLOW_RULES.md).

Line continuation in PowerShell is the backtick `` ` `` at end of line.

---

## What this is

The Palo Alto counterpart to the NSX
[VM rule membership report](../nsx/RUNBOOK_VM_RULE_MEMBERSHIP_PS.md). It takes
a list of source/destination pairs and finds every Panorama security rule
covering them.

Two input lists drive it:

| List | Flag | What it does |
|---|---|---|
| Flow CSV | `--flows` | The source/destination pairs to look up, one row per flow |
| Subnet filter | `--subnet-filter` | Suppresses matches whose **only** reason for matching is an address drawn from one of these subnets |

Versus `check_policy_match.py`: that one takes a single flow and reports the
**first** match (the verdict). This takes a CSV and reports **every** rule
covering each flow, flagging which one decides. Both share the same engine,
so they never disagree about PAN-OS ordering.

---

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r docker\requirements-pip.txt
$env:PYTHONPATH = "$PWD\app"
```

No `.env` credentials needed. The only `.env` key read is `PANO_REPORTS_DIR`
(plus `ROOT_DIR` for expansion). Use `--no-disk` to skip the report bundle.

---

## 1. List one: the flow CSV

Precedence: `--flows <path>`, then `PAN_FLOW_REPORT_LIST`, then the
auto-discovered `pan_flow_report_targets.csv` at the repo root.

Header row is optional; column names are case-insensitive:

| Column | Aliases | Required |
|---|---|---|
| `source` | `src`, `src_ip`, `source_ip`, `from` | yes |
| `destination` | `dst`, `dest`, `dst_ip`, `destination_ip`, `to` | yes |
| `protocol` | `proto` | no (`tcp`, `udp`, or blank for any) |
| `port` | `dst_port`, `destination_port` | no |
| `src_zone` | `source_zone` | no |
| `dst_zone` | `destination_zone` | no |
| `name` | `label`, `id`, `flow`, `ticket` | no |

```csv
name,source,destination,protocol,port
web-1-1,10.1.1.1,8.8.8.8,tcp,443
CHG-12345,10.6.0.101,10.1.1.1,tcp,22
```

A headerless file is read positionally as `src,dst[,protocol[,port]]`. Blank
lines and `#` comments are ignored.

Source and destination must be **single host IPs**. A `/32` or `/128` suffix
is stripped; a wider CIDR is reported as an invalid row rather than silently
evaluated on its network address:

```
[WARNING] flow list line 8 skipped: '10.1.1.0/24' is a network, not a host IP;
          list the individual hosts you want evaluated
```

Invalid rows are counted in the summary and listed in `report.md`.

Omit the zone columns for a zone-agnostic lookup. Zone-restricted rules are
then treated as matching, and every flow carries a caveat saying so.

---

## 2. List two: the subnet filter

Precedence: `--no-subnet-filter`, then `--subnet-filter <path>`, then the
auto-discovered `tools\pan\subnet_filter.txt`. Any `--exclude-subnet <cidr>`
values are always merged in.

```powershell
Copy-Item tools\pan\subnet_filter.example.txt tools\pan\subnet_filter.txt
```

`tools\pan\subnet_filter.txt` is gitignored so each operator keeps their own
list; the `.example.txt` template stays tracked. Same as `rule_filter.txt`.

### What it filters on: attribution, not rule content

The filter does **not** ask "does this rule mention that subnet". When a rule
matches, the tool records which address object, and which network inside it,
actually covered the source IP, and the same for the destination:

> A side's match is filtered when **every** network that covered the IP on
> that side is excluded by the list. If any covering network survives, the
> rule matched for a real reason and stays in the report.
>
> If either side is filtered, the whole rule/flow match is suppressed.

So if a rule's source group holds both `10.0.0.0/8` (listed) and
`10.6.0.101/32` (not listed), a flow from `10.6.0.101` is a genuine specific
match and the rule is **kept**.

`any` on a rule is treated as `0.0.0.0/0`, so listing `0.0.0.0/0` hides
any/any rules. Rules with a **negated** source or destination are never
suppressed: a negated match has no covering network to attribute.

### The two modes

| Mode | A covering network is excluded when it | Use it to |
|---|---|---|
| `broad` (default) | equals a listed subnet, or is **broader** than one | Hide matches that only happened because a rule carries a catch-all object |
| `within` | equals a listed subnet, or sits **inside** one | Mute an entire address space |

Worked example, flow `10.1.1.1 -> 8.8.8.8 tcp/443`, filter containing
`0.0.0.0/0` and `10.1.1.0/24`:

| Rule | Source object that covered `10.1.1.1` | `broad` | `within` |
|---|---|---|---|
| `allow-logging` | `any` = `0.0.0.0/0` | suppressed | suppressed |
| `test rule 1-1` | `h-10.1.1.1` = `10.1.1.1/32` | **kept** | suppressed |
| `test rule 1-2` | `n-10.1.1.0-24` = `10.1.1.0/24` | suppressed | suppressed |

> **Footgun:** a default route in a `within`-mode file suppresses everything.
> The tool warns rather than handing you a silently empty report.

### Suppressed does not mean discarded

Suppressed matches land in `suppressed_matches.jsonl` with the attribution
that dropped them. When a suppressed rule sits **earlier in the chain** than
the rule now reported as deciding, the flow is flagged:

```
  web-1-1: 10.1.1.1 -> 8.8.8.8 tcp/443
      [dg-3      ] ALLOWED  shared/pre-rulebase/pos 2 'test rule 1-1'  (+3 shadowed)
          ! suppressed rule ahead of it: shared/pre-rulebase/pos 1 'allow-logging'
            source match attributable only to filtered subnets: any=0.0.0.0/0 (filtered by 0.0.0.0/0)
```

On the real firewall `allow-logging` still decides that traffic. You asked not
to see it; here is the rule underneath it.

---

## 3. Subnet filter vs rule filter

| | Rule filter (`rule_filter.txt`) | Subnet filter (`subnet_filter.txt`) |
|---|---|---|
| Filters by | Rule **name** substring | Which **address** produced the match |
| Effect | Rule removed entirely, as if it did not exist | Rule matched, then the match suppressed |
| Audit trail | Count of removed rules | Per-match reason plus the shadowing flag |
| Reach for it when | You know the noisy rule by name | You want to hide broad matches without naming rules |

Both compose. `--rule-filter`, `--skip-rule` and `--no-filter` behave exactly
as in `check_policy_match.py`.

---

## 4. Running it

```powershell
$CFG = "tools\pan\configs\<customer>-<ts>.xml"

python tools\pan\report_flow_rules.py `
  --config $CFG `
  --flows pan_flow_report_targets.csv `
  --subnet-filter tools\pan\subnet_filter.txt
```

With no `--device-group` the tool defaults to `--all-device-groups`.

Scoped to one device group:

```powershell
python tools\pan\report_flow_rules.py `
  --config $CFG --flows flows.csv --device-group dg-3
```

One-off, nothing written to disk:

```powershell
python tools\pan\report_flow_rules.py `
  --config $CFG --flows flows.csv `
  --exclude-subnet 0.0.0.0/0 --no-disk
```

Lab only, GET-only pull then the offline engine unchanged:

```powershell
python tools\pan\report_flow_rules.py --live candidate --flows flows.csv
```

---

## 5. Reading the output

Before any subnet filter, the catch-all dominates every flow:

```
==============================================================================
PANORAMA FLOW / RULE REPORT
==============================================================================
Flows: 5   covered by a real rule: 4   default-rule only: 1   invalid rows: 1
Rule matches: 15   suppressed by subnet filter: 0   distinct rules: 12

  web-1-1: 10.1.1.1 -> 8.8.8.8 tcp/443
      [dg-3      ] ALLOWED  shared/pre-rulebase/pos 1 'allow-logging'  (+4 shadowed)
  nowhere: 192.0.2.7 -> 198.51.100.9 tcp/9999
      [dg-3      ] ALLOWED  default-rules/pos 1 'intrazone-default'  <- default-rule fall-through
```

Add `--exclude-subnet 0.0.0.0/0` and the real rules surface:

```
Rule matches: 10   suppressed by subnet filter: 6   distinct rules: 10

  web-1-1: 10.1.1.1 -> 8.8.8.8 tcp/443
      [dg-3      ] ALLOWED  shared/pre-rulebase/pos 2 'test rule 1-1'  (+3 shadowed)
          ! suppressed rule ahead of it: shared/pre-rulebase/pos 1 'allow-logging'
            source match attributable only to filtered subnets: any=0.0.0.0/0 (filtered by 0.0.0.0/0)
```

- `(+N shadowed)` means N further rules also cover this flow behind the
  deciding one. Cleanup candidates live here.
- `<- default-rule fall-through` means no real rule matched. Those verdicts
  are zone-dependent and only meaningful if you supplied zones.
- **One line per device group.** Each DG runs its own evaluation chain and so
  has its own deciding rule.

### The report bundle

`$env:PANO_REPORTS_DIR\flow_rule_report\<UTC_TS>\`:

| File | Contents |
|---|---|
| `summary.json` | Counters, plus both filters exactly as applied |
| `flow_rules.json` | Per-flow record: every match, every suppression, per-DG verdicts, invalid rows |
| `flow_rules.jsonl` | One row per kept `(flow, device group, rule)` match |
| `suppressed_matches.jsonl` | One row per subnet-filtered match, with its attribution |
| `report.md` | By-flow detail plus a by-rule rollup |
| `logs\` | Run log |

`report.md` closes with a **rule rollup**: one row per distinct rule, how many
flows it covers, how many it actually decides, which DGs it appeared in. A
rule covering many flows but deciding none is shadowed and a consolidation
candidate.

### Scripting against the JSONL

```powershell
$D = Get-ChildItem "$env:PANO_REPORTS_DIR\flow_rule_report" |
     Sort-Object Name -Descending | Select-Object -First 1

$rows = Get-Content "$($D.FullName)\flow_rules.jsonl" |
        ForEach-Object { $_ | ConvertFrom-Json }

# Which rules decide traffic, by frequency
$rows | Where-Object deciding | Group-Object name |
  Sort-Object Count -Descending | Format-Table Count, Name

# Rules that cover flows but never decide any: shadowed, cleanup candidates
$rows | Where-Object { -not $_.deciding } |
  Select-Object -ExpandProperty name -Unique

# What the subnet filter took out, and why
Get-Content "$($D.FullName)\suppressed_matches.jsonl" |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Format-Table flow, name, suppressed_reason -Wrap
```

---

## 6. Common operational patterns

### Migration or consolidation review

```powershell
python tools\pan\report_flow_rules.py --config $CFG `
  --flows customer-flows.csv `
  --exclude-subnet 0.0.0.0/0
```

Stripping any/any rules makes the rollup reflect intentional policy rather
than the catch-all.

### "Which of these flows has no real rule?"

The exit code answers this directly:

```powershell
python tools\pan\report_flow_rules.py --config $CFG --flows flows.csv --no-disk
if ($LASTEXITCODE -eq 1) { "at least one flow falls through to a default rule" }
```

Then feed the fall-through flows to `recommend_dg.py` to pick a home for the
new rules.

### Before/after a change

```powershell
python tools\pan\report_flow_rules.py --config tools\pan\configs\customer-before.xml `
  --flows flows.csv --output-dir $env:TEMP\before
python tools\pan\report_flow_rules.py --config tools\pan\configs\customer-after.xml `
  --flows flows.csv --output-dir $env:TEMP\after

$b = Get-ChildItem "$env:TEMP\before\flow_rule_report" | Select-Object -First 1
$a = Get-ChildItem "$env:TEMP\after\flow_rule_report"  | Select-Object -First 1
Compare-Object (Get-Content "$($b.FullName)\summary.json") `
               (Get-Content "$($a.FullName)\summary.json")
```

---

## 7. Full flag reference

### Config source (one required, mutually exclusive)

| Flag | Meaning |
|---|---|
| `--config <path>` | Panorama config XML. Production path |
| `--live candidate\|running` | Pull from Panorama first (GET-only). Lab only |

### Input lists

| Flag | Meaning |
|---|---|
| `--flows <path>` | Flow CSV. Falls back to `PAN_FLOW_REPORT_LIST`, then repo-root `pan_flow_report_targets.csv` |
| `--subnet-filter <path>` | Subnet list. Defaults to `tools\pan\subnet_filter.txt` if present |
| `--exclude-subnet <cidr>` | One more subnet to exclude. Repeatable |
| `--subnet-filter-mode broad\|within` | How a covering network is compared to a listed subnet. Default `broad` |
| `--no-subnet-filter` | Ignore the subnet list entirely |

### Scope

| Flag | Meaning |
|---|---|
| `--device-group <name>` | Evaluate one DG |
| `--all-device-groups` | Evaluate every DG. Default |
| `--include-defaults` | Report intrazone/interzone-default matches beyond the deciding one |

### Rule-name filter (shared with the other PAN tools)

| Flag | Meaning |
|---|---|
| `--rule-filter <path>` | Rule-name filter file |
| `--skip-rule <substring>` | Inline rule-name filter. Repeatable |
| `--no-filter` | Ignore the rule-name filter entirely |

### Output

| Flag | Meaning |
|---|---|
| `--output-dir <path>` | Report root. Defaults to `$env:PANO_REPORTS_DIR` |
| `--no-disk` | Write nothing. stdout only |
| `--json` | Emit the full report as JSON on stdout |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every flow is covered by at least one real (non-default) rule |
| `1` | At least one flow falls through to a PAN default rule only |
| `2` | Input error: missing or unusable flow list, missing filter file, failed `--live` pull |

---

## 8. Caveats

Everything in [RUNBOOK_PAN_PROD_PS.md](RUNBOOK_PAN_PROD_PS.md) section 5
applies, since this shares the evaluation engine: App-ID cannot be resolved
offline, FQDN objects and Dynamic Address Groups have no offline membership,
NAT is not evaluated, User-ID is treated as `any`, and firewall-local rules
are invisible to a Panorama export.

Specific to this tool:

| Caveat | Detail |
|---|---|
| Flow endpoints are host IPs | A subnet in the CSV is rejected, not expanded |
| Shared rules repeat per DG | In all-DG mode a shared rule appears once per DG in `flow_rules.jsonl`. The `report.md` rollup dedupes and lists the DGs |
| Suppression is a reporting choice | The subnet filter changes only what this tool shows. Real enforcement is unaffected, which is what the shadowing warning keeps visible |
| Zone-agnostic by default | Without zones, zone-restricted rules are treated as matching and default-rule verdicts are indicative only |
