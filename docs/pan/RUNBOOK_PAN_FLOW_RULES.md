# Runbook: Palo Alto flow/rule report (`report_flow_rules.py`) - macOS / Linux / bash

> ## 🔒 PRODUCTION DISCIPLINE: offline, local, read-only
>
> This tool **never authenticates against a Panorama** when run with
> `--config`. It reads an exported config XML on the operator's machine and
> writes reports locally. Same production guarantees as the rest of
> [RUNBOOK_PAN_PROD.md](RUNBOOK_PAN_PROD.md).
>
> | Property | Guarantee |
> |---|---|
> | Network calls to customer Panorama | None with `--config`. `--live` is a lab convenience and does one GET-only pull |
> | Credentials needed | None with `--config` |
> | Customer environment side-effects | Zero |
> | Input | Panorama XML + a flow CSV + an optional subnet list |
> | Output | Report bundle under `$PANO_REPORTS_DIR/flow_rule_report/<UTC_TS>/` |

PowerShell variant: [RUNBOOK_PAN_FLOW_RULES_PS.md](RUNBOOK_PAN_FLOW_RULES_PS.md).

---

## What this is

The Palo Alto counterpart to the NSX
[VM rule membership report](../nsx/RUNBOOK_VM_RULE_MEMBERSHIP.md). Where that
one takes a list of VMs and finds every DFW rule touching them, this takes a
list of source/destination pairs and finds every Panorama security rule
covering them.

Two input lists drive it:

| List | Flag | What it does |
|---|---|---|
| Flow CSV | `--flows` | The source/destination pairs to look up, one row per flow |
| Subnet filter | `--subnet-filter` | Suppresses matches whose **only** reason for matching is an address drawn from one of these subnets |

### How it differs from `check_policy_match.py`

| | `check_policy_match.py` | `report_flow_rules.py` |
|---|---|---|
| Input | One flow on the command line | A CSV of N flows |
| Rules reported | The **first** match only (the verdict) | **Every** rule in the chain that covers the flow |
| Shadowed rules | Invisible | Reported, with the deciding one flagged |
| Address-based filtering | None | The subnet filter |
| Output | `verdict.json` | Report bundle: markdown, JSON, JSONL |

Use `check_policy_match.py` for "is this one flow allowed". Use this for
"show me the rules involved in these 40 flows, and which ones are dead
weight".

Both share the same engine: this tool imports `check_policy_match` and reuses
its parser, address/service resolution and evaluation chain, so the two never
disagree about PAN-OS ordering.

---

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

No `.env` credentials needed. The only `.env` key read is `PANO_REPORTS_DIR`
(plus `ROOT_DIR` for `$VAR` expansion), same as the other PAN analysis tools.
Use `--no-disk` to skip the report bundle entirely.

---

## 1. List one: the flow CSV

### Where it comes from

| Precedence | Source |
|---|---|
| 1 | `--flows <path>` |
| 2 | `PAN_FLOW_REPORT_LIST` in `.env` or the environment |
| 3 | Auto-discovered `pan_flow_report_targets.csv` at the repo root |

The repo-root file ships as a documented template, mirroring the NSX
`vm_rule_report_targets.txt` convention.

### Format

The header row is optional and its column names are case-insensitive:

| Column | Aliases | Required |
|---|---|---|
| `source` | `src`, `src_ip`, `source_ip`, `from` | yes |
| `destination` | `dst`, `dest`, `dst_ip`, `destination_ip`, `to` | yes |
| `protocol` | `proto` | no (`tcp`, `udp`, or blank for any) |
| `port` | `dst_port`, `destination_port` | no |
| `src_zone` | `source_zone` | no |
| `dst_zone` | `destination_zone` | no |
| `name` | `label`, `id`, `flow`, `ticket` | no (free-text label for the report) |

```csv
name,source,destination,protocol,port
web-1-1,10.1.1.1,8.8.8.8,tcp,443
range-2,10.2.1.25,4.2.2.2,tcp,80
CHG-12345,10.6.0.101,10.1.1.1,tcp,22
any-port,10.2.1.25,4.2.2.2,,
```

A headerless file is read positionally as `src,dst[,protocol[,port]]`:

```csv
10.1.1.1,8.8.8.8,tcp,443
10.2.1.25,4.2.2.2
```

Blank lines and `#` comments are ignored.

### Row validation

Source and destination must be **single host IPs**. A `/32` or `/128` suffix
is tolerated and stripped. A wider CIDR is reported as an invalid row rather
than silently evaluated on its network address:

```
[WARNING] flow list line 8 skipped: '10.1.1.0/24' is a network, not a host IP;
          list the individual hosts you want evaluated
```

Invalid rows are counted in the summary and listed in `report.md`, so a typo
never disappears quietly. Bad protocols and non-integer ports are caught the
same way.

### Zones

Omit `src_zone` / `dst_zone` for a zone-agnostic lookup. Rules with specific
zone restrictions are then treated as matching, and every flow carries the
caveat saying so. Supply zones when you have them for a tighter result.

---

## 2. List two: the subnet filter

### Where it comes from

| Precedence | Source |
|---|---|
| 1 | `--no-subnet-filter` (bypass entirely) |
| 2 | `--subnet-filter <path>` |
| 3 | Auto-discovered `tools/pan/subnet_filter.txt` next to the script |

Plus any `--exclude-subnet <cidr>` values from the command line, which are
always merged in. Copy the template to get started:

```bash
cp tools/pan/subnet_filter.example.txt tools/pan/subnet_filter.txt
```

`tools/pan/subnet_filter.txt` is gitignored so each operator keeps their own
list. The `.example.txt` template stays tracked. Same arrangement as
`rule_filter.txt`.

### What it filters on: attribution, not rule content

This is the important part. The filter does **not** ask "does this rule
mention that subnet". When a rule matches a flow, the tool records which
address object, and which network inside it, actually covered the source IP,
and the same for the destination. The filter acts on that attribution:

> A side's match is filtered when **every** network that covered the IP on
> that side is excluded by the list. If any covering network survives, the
> rule matched for a real reason and stays in the report.
>
> If either the source side or the destination side is filtered, the whole
> rule/flow match is suppressed.

The "every covering network" rule is what keeps the filter honest. If a
rule's source is an address group holding both `10.0.0.0/8` (listed) and
`10.6.0.101/32` (not listed), a flow from `10.6.0.101` is a genuine specific
match, so the rule is **kept** even though the broad object also covered it.

`any` on a rule is treated as `0.0.0.0/0` (or `::/0`), so listing `0.0.0.0/0`
is how you hide any/any rules from the report.

A rule with a **negated** source or destination is never suppressed: a
negated match has no covering network to attribute. Those rules carry a
caveat saying so.

### The two modes

```bash
--subnet-filter-mode broad     # default
--subnet-filter-mode within
```

| Mode | A covering network is excluded when it | Use it to |
|---|---|---|
| `broad` (default) | equals a listed subnet, or is **broader** than one | Hide matches that only happened because a rule carries a catch-all address object |
| `within` | equals a listed subnet, or sits **inside** one | Mute an entire address space |

Worked example against the lab Panorama, flow `10.1.1.1 -> 8.8.8.8 tcp/443`,
filter file containing `0.0.0.0/0` and `10.1.1.0/24`:

| Rule | Source object that covered `10.1.1.1` | `broad` | `within` |
|---|---|---|---|
| `allow-logging` | `any` = `0.0.0.0/0` | suppressed | suppressed |
| `test rule 1-1` | `h-10.1.1.1` = `10.1.1.1/32` | **kept** (a /32 is narrower than the listed /24) | suppressed |
| `test rule 1-2` | `n-10.1.1.0-24` = `10.1.1.0/24` | suppressed (exact match) | suppressed |

In `broad` mode the specific `/32` rule survives, which is almost always what
you want. In `within` mode the whole `10.1.1.0/24` space goes quiet.

> **Footgun:** a default route in a `within`-mode file suppresses everything,
> because every covering network sits inside `0.0.0.0/0`. The tool warns
> rather than handing you a silently empty report:
>
> ```
> [WARNING] subnet filter contains 0.0.0.0/0 in 'within' mode: EVERY match sits
>           inside it, so every rule will be suppressed. Drop that entry, or use
>           --subnet-filter-mode broad to hide only any/any rules.
> ```

### Suppressed does not mean discarded

Every suppressed match is written to `suppressed_matches.jsonl` with the
attribution that dropped it. And when a suppressed rule sits **earlier in the
evaluation chain** than the rule now reported as deciding, the flow is
flagged so the report never implies the wrong rule is enforcing:

```
  web-1-1: 10.1.1.1 -> 8.8.8.8 tcp/443
      [dg-3      ] ALLOWED  shared/pre-rulebase/pos 2 'test rule 1-1'  (+3 shadowed)
          ! suppressed rule ahead of it: shared/pre-rulebase/pos 1 'allow-logging'
            source match attributable only to filtered subnets: any=0.0.0.0/0 (filtered by 0.0.0.0/0)
```

Read that as: on the real firewall `allow-logging` still decides this
traffic. You asked not to see it, and here is the rule underneath it.

---

## 3. Subnet filter vs rule filter

Both filters compose, and they do different jobs.

| | Rule filter (`rule_filter.txt`) | Subnet filter (`subnet_filter.txt`) |
|---|---|---|
| Filters by | Rule **name** substring | Which **address** produced the match |
| Effect on the chain | Rule is removed entirely, as if it did not exist | Rule is evaluated, matched, then the match is suppressed |
| Audit trail | A count of removed rules | Per-match reason in `suppressed_matches.jsonl` plus the shadowing flag |
| Reach for it when | You know the noisy rule by name | You want to hide broad matches without naming every rule |

The rule filter is shared with `check_policy_match.py` and `recommend_dg.py`,
so `--rule-filter`, `--skip-rule` and `--no-filter` behave identically here.

---

## 4. Running it

### The common case

```bash
CFG=tools/pan/configs/<customer>-<ts>.xml

python tools/pan/report_flow_rules.py \
  --config "$CFG" \
  --flows pan_flow_report_targets.csv \
  --subnet-filter tools/pan/subnet_filter.txt
```

With no `--device-group`, the tool defaults to `--all-device-groups`, the same
default as `check_policy_match.py`.

### Scoped to one device group

```bash
python tools/pan/report_flow_rules.py \
  --config "$CFG" --flows flows.csv --device-group dg-3
```

### One-off, nothing written to disk

```bash
python tools/pan/report_flow_rules.py \
  --config "$CFG" --flows flows.csv \
  --exclude-subnet 0.0.0.0/0 --no-disk
```

### Against the lab Panorama

`--live` shells out to `pull_panorama_config.py` for a GET-only pull, then
runs the offline engine unchanged:

```bash
python tools/pan/report_flow_rules.py --live candidate --flows flows.csv
```

Do not use `--live` in the production workflow. That is what `--config` is for.

---

## 5. Reading the output

### stdout

Before any subnet filter, on the lab config, the catch-all dominates every flow:

```
==============================================================================
PANORAMA FLOW / RULE REPORT
==============================================================================
Flows: 5   covered by a real rule: 4   default-rule only: 1   invalid rows: 1
Rule matches: 15   suppressed by subnet filter: 0   distinct rules: 12

  web-1-1: 10.1.1.1 -> 8.8.8.8 tcp/443
      [dg-3      ] ALLOWED  shared/pre-rulebase/pos 1 'allow-logging'  (+4 shadowed)
  range-2: 10.2.1.25 -> 4.2.2.2 tcp/80
      [dg-3      ] ALLOWED  shared/pre-rulebase/pos 1 'allow-logging'  (+1 shadowed)
  nowhere: 192.0.2.7 -> 198.51.100.9 tcp/9999
      [dg-3      ] ALLOWED  default-rules/pos 1 'intrazone-default'  <- default-rule fall-through
```

Add `--exclude-subnet 0.0.0.0/0` and the real rules surface:

```
Flows: 5   covered by a real rule: 4   default-rule only: 1   invalid rows: 1
Rule matches: 10   suppressed by subnet filter: 6   distinct rules: 10

  web-1-1: 10.1.1.1 -> 8.8.8.8 tcp/443
      [dg-3      ] ALLOWED  shared/pre-rulebase/pos 2 'test rule 1-1'  (+3 shadowed)
          ! suppressed rule ahead of it: shared/pre-rulebase/pos 1 'allow-logging'
            source match attributable only to filtered subnets: any=0.0.0.0/0 (filtered by 0.0.0.0/0)
  range-2: 10.2.1.25 -> 4.2.2.2 tcp/80
      [dg-3      ] ALLOWED  shared/pre-rulebase/pos 7 'test rule 2-2'
          ! suppressed rule ahead of it: shared/pre-rulebase/pos 1 'allow-logging'
            source match attributable only to filtered subnets: any=0.0.0.0/0 (filtered by 0.0.0.0/0)
```

Notes on reading it:

- `(+N shadowed)` means N further rules also cover this flow behind the
  deciding one. Cleanup candidates live here.
- `<- default-rule fall-through` means no real rule matched and the verdict
  comes from PAN's synthetic defaults. Those are zone-dependent, so they are
  only meaningful if you supplied zones.
- **One line per device group.** Each DG runs its own evaluation chain and so
  has its own deciding rule. In all-DG mode a flow gets one line per DG.

### The report bundle

`$PANO_REPORTS_DIR/flow_rule_report/<UTC_TS>/`:

| File | Contents |
|---|---|
| `summary.json` | Counters, plus both filters exactly as applied |
| `flow_rules.json` | Per-flow record: every match, every suppression, per-DG verdicts, invalid rows |
| `flow_rules.jsonl` | One row per kept `(flow, device group, rule)` match. Greppable |
| `suppressed_matches.jsonl` | One row per subnet-filtered match, with its attribution |
| `report.md` | By-flow detail plus a by-rule rollup |
| `logs/` | Run log |

`report.md` closes with a **rule rollup**: one row per distinct rule, how many
flows it covers, how many it actually decides, and which DGs it appeared in.
Sorted by flow count. A rule covering many flows but deciding none is
shadowed and a consolidation candidate.

### JSONL is the one to script against

```bash
D=$(ls -dt "$PANO_REPORTS_DIR"/flow_rule_report/*/ | head -1)

# Which rules decide traffic, by frequency
jq -r 'select(.deciding) | "\(.rulebase)/\(.position) \(.name)"' \
  "$D/flow_rules.jsonl" | sort | uniq -c | sort -rn

# Rules that cover flows but never decide any: shadowed, cleanup candidates
jq -r 'select(.deciding | not) | .name' "$D/flow_rules.jsonl" | sort -u

# What the subnet filter took out, and why
jq -r '"\(.flow)  \(.name)  \(.suppressed_reason)"' "$D/suppressed_matches.jsonl"
```

---

## 6. Common operational patterns

### Migration or consolidation review

Feed the flow list a customer says they need, then look at the rollup to see
how many distinct rules are really carrying it:

```bash
python tools/pan/report_flow_rules.py --config "$CFG" \
  --flows customer-flows.csv \
  --exclude-subnet 0.0.0.0/0
```

`--exclude-subnet 0.0.0.0/0` strips any/any rules so the rollup reflects
intentional policy rather than the catch-all.

### "Which of these flows has no real rule?"

The exit code answers this directly, so it works in a pipeline:

```bash
python tools/pan/report_flow_rules.py --config "$CFG" --flows flows.csv --no-disk
# exit 0 = every flow is covered by a real rule
# exit 1 = at least one flow falls through to a PAN default rule only
```

Then feed the fall-through flows to `recommend_dg.py` to pick a home for the
new rules.

### Before/after a change

```bash
BEFORE=tools/pan/configs/customer-before.xml
AFTER=tools/pan/configs/customer-after.xml

python tools/pan/report_flow_rules.py --config "$BEFORE" --flows flows.csv \
  --output-dir /tmp/before
python tools/pan/report_flow_rules.py --config "$AFTER" --flows flows.csv \
  --output-dir /tmp/after

diff <(jq -S . /tmp/before/flow_rule_report/*/summary.json) \
     <(jq -S . /tmp/after/flow_rule_report/*/summary.json)
```

### Ignoring one broad object without hiding the rules that use it properly

Put the object's network in `subnet_filter.txt` and stay in `broad` mode.
Rules matching through that object drop out; rules matching the same flow
through a specific object stay.

---

## 7. Full flag reference

### Config source

| Flag | Meaning |
|---|---|
| `--config <path>` | Panorama config XML. Production path |
| `--live candidate\|running` | Pull from Panorama first (GET-only), then report. Lab only |

One of the two is required. They are mutually exclusive.

### Input lists

| Flag | Meaning |
|---|---|
| `--flows <path>` | Flow CSV. Falls back to `PAN_FLOW_REPORT_LIST`, then repo-root `pan_flow_report_targets.csv` |
| `--subnet-filter <path>` | Subnet list. Defaults to `tools/pan/subnet_filter.txt` if present |
| `--exclude-subnet <cidr>` | One more subnet to exclude. Repeatable. Merged with the file |
| `--subnet-filter-mode broad\|within` | How a covering network is compared to a listed subnet. Default `broad` |
| `--no-subnet-filter` | Ignore the subnet list entirely |

### Scope

| Flag | Meaning |
|---|---|
| `--device-group <name>` | Evaluate one DG |
| `--all-device-groups` | Evaluate every DG. This is the default |
| `--include-defaults` | Report intrazone/interzone-default matches beyond the one deciding the flow |

### Rule-name filter (shared with the other PAN tools)

| Flag | Meaning |
|---|---|
| `--rule-filter <path>` | Rule-name filter file |
| `--skip-rule <substring>` | Inline rule-name filter. Repeatable |
| `--no-filter` | Ignore the rule-name filter entirely |

### Output

| Flag | Meaning |
|---|---|
| `--output-dir <path>` | Report root. Defaults to `$PANO_REPORTS_DIR` |
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

Everything in
[RUNBOOK_PAN_PROD.md section 5](RUNBOOK_PAN_PROD.md#5-offline-limitations-surfaced-as-caveats-in-the-verdict)
applies, since this shares the evaluation engine: App-ID cannot be resolved
offline, FQDN address objects and Dynamic Address Groups have no offline
membership, NAT is not evaluated, User-ID is treated as `any`, and rules local
to a firewall are invisible to a Panorama export. Those surface per match in
the `caveats` field and in `report.md`.

Specific to this tool:

| Caveat | Detail |
|---|---|
| Flow endpoints are host IPs | A subnet in the CSV is rejected, not expanded. Evaluating a whole subnet means listing the hosts you care about |
| Shared rules repeat per DG | In all-DG mode a shared rule appears once per DG in `flow_rules.jsonl`. The `report.md` rollup dedupes and lists the DGs |
| Suppression is a reporting choice | The subnet filter changes only what this tool shows. Real enforcement is unaffected, which is exactly what the shadowing warning exists to keep visible |
| Zone-agnostic by default | Without zones in the CSV, zone-restricted rules are treated as matching and default-rule verdicts are indicative only |
