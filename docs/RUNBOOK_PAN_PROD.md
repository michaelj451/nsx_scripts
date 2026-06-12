# Runbook — Palo Alto Production (manual, no API) — macOS / Linux / bash

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
> | Input | An XML config file the customer provides (export via UI or `scp`) |
> | Output | Reports written to the operator's local `$PANO_REPORTS_DIR/` dir |
>
> For lab development work against `pano4.lab.local`, see
> [RUNBOOK_PAN_LAB.md](RUNBOOK_PAN_LAB.md). The lab toolkit uses the API;
> the production toolkit explicitly does not.

PowerShell variant: [RUNBOOK_PAN_PROD_PS.md](RUNBOOK_PAN_PROD_PS.md).

---

## What's covered here

| Tool | Purpose | Input | Output |
|---|---|---|---|
| `tools/pan/check_policy_match.py` | Offline "can A reach B" policy lookup — walks the full Panorama evaluation chain in correct PAN-OS order, reports verdict + matched rule + trace | Panorama XML config file + `(src_ip, dst_ip, [zones], [service/port])` | `verdict.json` + human/JSON stdout |
| `tools/pan/recommend_dg.py` | "Which DG should a new rule go on?" — checks for existing matches, then if none, scores each DG's affinity to the flow's /24 (or other CIDR) by counting rules referencing the same address space | Same as above + `--subnet-mask` | `recommendation.json` + `recommendation.txt` + human/JSON stdout |

(Future tools — `find_matching_rules.py` for "every rule across the chain that matches", batch CSV mode, NAT-aware analysis — are flagged on the [PAN direction memory](#) and will be added here as they ship.)

---

## How customers send you the config XML

You'll be relying on the customer to extract and send the Panorama running-config XML. The standard ways:

| Method | Steps |
|---|---|
| Panorama Web UI | Device → Setup → Operations → "Save named configuration snapshot" → "Export named configuration snapshot" — downloads `panorama-<ts>.xml` |
| Panorama CLI | `show config running` (paste into a file) |
| Panorama API (operator-side) | `curl -k "https://<panorama>/api/?type=op&cmd=<show><config><running></running></config></show>&key=KEY"` — operator runs this, not the analysis tool |
| Backup archive | Recent `panorama_backup.tgz` from their backup system — extract `running-config.xml` |

The file is **typically 10-100 MB** for a real production Panorama. If a customer sends you something dramatically smaller (~100 KB), it might be a partial export (e.g., only one device-group). Ask before analyzing.

---

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

**No `.env` credentials needed.** The production tool does not load Panorama credentials, manager hostnames, or API tokens — even when a `.env` file is present in the repo.

The one path setting the tool optionally reads from `.env` is `PANO_REPORTS_DIR` (where to land each query's `verdict.json` audit record). The reader looks at this one variable (plus `ROOT_DIR` for `$VAR` expansion) and ignores every other line in the file. If `PANO_REPORTS_DIR` isn't set anywhere, the tool falls back to `./.pano_reports/` in the current directory.

To opt out of disk writes entirely (one-off CAB questions where no audit trail is wanted), use `--no-disk`.

---

## Where to put the customer's XML file

| Location | Convention | Why |
|---|---|---|
| `tools/pan/configs/<customer>-<ts>.xml` | **Recommended** | Auto-gitignored by repo convention (line 43 of `.gitignore` covers `tools/pan/configs/*`). One folder for all customer configs. |
| Outside the repo (e.g., `~/customer-configs/`) | Alternative | Cleanest separation. You give the tool the absolute path; the repo never sees the file. |

The gitignore rule is:

```
tools/pan/configs/*
!tools/pan/configs/.gitkeep
```

so any file (any extension, any naming) dropped under `tools/pan/configs/` is auto-excluded from git. You can rename customer files freely without losing the protection.

---

## 1. Offline policy lookup — `check_policy_match.py`

The flagship tool. Given a Panorama XML config and a `(src, dst, [zones], [service/port])` query, walks the full evaluation chain in correct PAN-OS order and reports:

- The verdict (`ALLOWED` / `DENIED` / `DROPPED` / `RESET`)
- The matched rule (rulebase + position + name)
- Any offline-evaluation caveats (App-ID, FQDN address objects, DAGs)
- Optional full per-rule trace showing why each preceding rule was skipped

### Basic invocation

```bash
python tools/pan/check_policy_match.py \
  --config tools/pan/configs/<customer>-<ts>.xml \
  --device-group BranchOffice-DG \
  --src-ip 10.20.5.7 --dst-ip 192.168.10.42 \
  --protocol tcp --dst-port 443
```

Output (concise):

```
======================================================================
VERDICT: ALLOWED
======================================================================
Query:        src=10.20.5.7  dst=192.168.10.42
              src_zone=(any)  dst_zone=(any)
              protocol=tcp  dst_port=443
              device-group=BranchOffice-DG

Matched rule: BranchOffice-DG/post-rulebase / position 1 / 'allow-web-to-internal'

Caveats:
  • query is zone-agnostic (src_zone or dst_zone not supplied) — ...

Rules evaluated: 7
```

Add `-v` / `--verbose` for the per-rule skip trace, or `--json` for tooling output.

### Why this is production-safe

| What it does | What it does NOT do |
|---|---|
| Read the XML file on local disk | Open any network connection |
| Parse with Python `xml.etree.ElementTree` | Authenticate against anything |
| Compute matches in memory using `ipaddress` | Write to any remote service |
| Emit a report to local disk + stdout | Modify the customer's XML file |

The Python process needs **read access to the XML file only**.

### Exit code

`0` if ALLOWED, `1` otherwise. Usable directly in shell pipelines and CI checks.

---

## 2. DG recommendation — `recommend_dg.py`

When `check_policy_match.py` returns DENIED (or you already know a flow isn't allowed), the next question is **where does the new rule go?** `recommend_dg.py` answers that.

The algorithm:

1. **First**, run an existing-match check across every DG (reusing `check_policy_match`'s matcher). If any customer rule already allows the flow → tool reports the existing match and exits 0 (no new rule needed).
2. **If no match**, compute `src_subnet` and `dst_subnet` at `--subnet-mask` (default `/24`).
3. For each DG, scan its **DG-specific rulebases only** (DG-pre + DG-post — NOT shared, NOT default rules). Count rules whose source addresses overlap `src_subnet`, and rules whose destination addresses overlap `dst_subnet`.
4. Also score the shared rulebases (informational — they're not DG-recommendable, but they tell you whether the flow belongs to a shared policy lineage).
5. Recommend the DG with the highest combined score. Ties broken alphabetically. If every DG scores zero AND shared scores zero, recommend `shared/post-rulebase` as the catch-all home.

### Basic invocation

```bash
python tools/pan/recommend_dg.py \
  --config tools/pan/configs/<customer>-<ts>.xml \
  --src-ip 10.50.5.10 --dst-ip 8.8.8.8 \
  --protocol tcp --dst-port 443
```

### Tuning the affinity window

```bash
# Widen to /16 — useful when /24 is too narrow and the address space is sparser
python tools/pan/recommend_dg.py --config $CFG --src-ip 10.50.5.10 --dst-ip 8.8.8.8 \
  --protocol tcp --dst-port 443 --subnet-mask 16
```

### Example output

```
========================================================================
DG RECOMMENDATION REPORT
========================================================================
Query:        src=10.3.1.10  dst=198.51.100.20
              src_subnet=10.3.1.0/24  dst_subnet=198.51.100.0/24
              proto=tcp  port=5432

Status: NO existing rule matches — new rule needed.

Per-DG affinity to the flow's /N subnets (DG-specific rulebases only):
  DG         score  src  dst  both  scanned
  dg-5           3    3    0     0        5
  dg-4           2    2    0     0        5
  dg-3           1    1    0     0        5
  dg-6           0    0    0     0        4
  shared         3    3    0     0       18  (informational)

RECOMMENDATION: add new rule to device-group 'dg-5'
  Rationale: dg-5 has the strongest affinity to the flow's address space:
             3 rule(s) with sources in 10.3.1.0/24, 0 rule(s) with
             destinations in 198.51.100.0/24, 0 rule(s) covering both.
             Total score: 3.
  Top supporting rules:
    - dg-5/pre-rulebase / pos 1 / 'test rule 3-1-dg-5'  (src overlap)
    - dg-5/pre-rulebase / pos 2 / 'test rule 3-1-1-dg-5'  (src overlap)
    - dg-5/post-rulebase / pos 1 / 'post rule dg-5'  (src overlap)
```

### What gets written

```
$PANO_REPORTS_DIR/recommend_dg/<UTC_TS>/
├── recommendation.json    full structured record (audit-friendly)
└── recommendation.txt     human-readable copy of the stdout view
```

### Caveats specific to this tool

- **Affinity is purely structural** — it counts rules whose address objects overlap the requested /N. It does not consider zones, services, or rule order. A high score means "the flow's address neighborhood already exists in this DG", not "the existing rules functionally relate".
- **Shared rulebases score is informational only.** The recommendation is always a DG (or, when nothing scores, a shared rulebase as fallback). The tool does not recommend shared/pre or shared/post when a DG has any positive affinity.
- **DAGs and FQDN addresses are skipped** (same offline limitations as `check_policy_match.py`).
- **A DG with score 0 may still be the right answer** — for example, a brand-new business unit's traffic that doesn't yet have any rules anywhere. The tool will recommend a shared rulebase fallback; the operator should still review.

### Exit code

`0` in all cases. The tool reports its finding via stdout/JSON and exits cleanly — even when the recommendation is to add to a shared rulebase. The "no match → no recommendation" case isn't an error.

---

## 3. Common operational patterns

### Single-flow check (the simplest CAB question)

```bash
python tools/pan/check_policy_match.py \
  --config tools/pan/configs/customer-X-2026-06.xml \
  --device-group CustomerX-DG \
  --src-ip 10.50.10.5 --dst-ip 8.8.8.8 \
  --protocol udp --dst-port 53 \
  --src-zone trust --dst-zone untrust -v
```

Add `--src-zone` / `--dst-zone` for zone-aware accuracy. Without them, the tool runs zone-agnostic and emits a caveat.

### Batch-checking N flows

Not yet a single tool, but easy to script:

```bash
CFG=tools/pan/configs/customer-X-2026-06.xml
DG=CustomerX-DG

while IFS=, read src dst proto port; do
  result=$(python tools/pan/check_policy_match.py --config "$CFG" \
            --device-group "$DG" --src-ip "$src" --dst-ip "$dst" \
            --protocol "$proto" --dst-port "$port" --json)
  verdict=$(echo "$result" | jq -r '.verdict')
  rule=$(echo "$result" | jq -r '.matched_rule')
  echo "$src,$dst,$proto/$port,$verdict,$rule"
done < flows.csv
```

A wrapped `batch_check_policy.py` is on the future-tools list — flag if you want it sooner.

### Finding the right device-group

If you don't know which DG a flow lands in, you can probe each one:

```bash
CFG=tools/pan/configs/customer-X-2026-06.xml
for DG in $(python3 -c "
import xml.etree.ElementTree as ET, sys
root = ET.parse('$CFG').getroot()
dg_root = root.find(\"./devices/entry/device-group\")
for e in dg_root.findall('./entry'):
    print(e.get('name'))
"); do
  echo "=== $DG ==="
  python tools/pan/check_policy_match.py --config "$CFG" --device-group "$DG" \
    --src-ip 10.50.10.5 --dst-ip 8.8.8.8 --protocol tcp --dst-port 443 --json \
    | jq -r '"  verdict=" + .verdict + "  rule=" + (.matched_rule // "(none)")'
done
```

---

## 4. Offline limitations (surfaced as `caveats` in the verdict)

| Limitation | What the tool does |
|---|---|
| **App-ID matching** can't be evaluated offline | Treats `application` field as wildcard when query doesn't specify app; emits caveat naming the apps the rule requires |
| **`application-default` service** depends on runtime App-ID | Treats as match-any-port with a caveat |
| **Dynamic Address Groups (DAGs)** have runtime tag-driven membership | Emits caveat with the DAG filter expression; doesn't expand |
| **FQDN address objects** require DNS resolution | Caveat — IP can't be matched |
| **NAT rules** can change effective IPs before security rule match | NAT is not evaluated (yet); IPs are treated as on-the-wire literals |
| **User-ID** | Treated as `any` (no user identity in queries) |
| **Firewall-local rulebase** (rules on the firewall itself, not Panorama) | Invisible — tool only sees Panorama-side rules |
| **Schedules (time-of-day rules)** | Ignored |

These are surfaced explicitly in the `Caveats:` section of every verdict so CAB tickets show the assumptions made.

---

## 5. Customer engagement workflow

1. **Request the config**
   - Ask for the running-config XML export. Mention any timestamp / freshness requirement.
   - Confirm timestamp + completeness when received. Check file size (expect 10-100 MB for a real production Panorama).

2. **Land it in `tools/pan/configs/`**
   ```bash
   cp ~/Downloads/customer-X-config.xml tools/pan/configs/customer-X-2026-06.xml
   # gitignored automatically
   ```

3. **Run the relevant analysis tool(s)**
   ```bash
   python tools/pan/check_policy_match.py --config tools/pan/configs/customer-X-2026-06.xml \
     --device-group <DG> --src-ip ... --dst-ip ... [--src-zone ...] [--dst-zone ...] \
     --protocol tcp --dst-port 443 -v --json > report.json
   ```

4. **Hand back a clean report** to the customer
   - Include: verdict, matched rule, every offline caveat that fired, the query terms verbatim.
   - Exclude: any field that wasn't part of the customer's question (don't volunteer rule contents from elsewhere in their config).

5. **Disposition the XML**
   - If you're done: leave it under `tools/pan/configs/` (gitignored, never committed)
   - If a customer requires deletion-on-completion: `rm` the file. The reports under `$PANO_REPORTS_DIR/` may still reference rule names — disposition those per the customer's data-handling policy.

---

## 6. Safety properties (production)

| Property | Behavior |
|---|---|
| Customer network calls | Never — no network code loaded |
| Customer credentials | Never — no auth code paths |
| Customer config writes | Never — input is read-only |
| Tool failure mode | Fails locally on the operator's machine, no escape into customer infra |
| Concurrent operators | Safe — each operator has their own local XML copy + reports |
| Multi-customer sessions | Safe — different XML files = different in-memory parses; no shared state |
| Output retention | Operator-controlled — reports land under `$PANO_REPORTS_DIR/`, locally only |

---

## 7. What customers can verify before authorizing analysis

If a customer asks "what does this tool do to my Panorama", the truthful answers are:

- "Nothing — it doesn't reach your Panorama at all"
- "I'm running it on my laptop, against the XML file you sent me"
- "The repo has the source; you can read what `check_policy_match.py` does — there's no network code"

Pointing them at this runbook is a clean way to demonstrate the scope.

---

## 8. Full tool flag reference

### `check_policy_match.py`

| Flag | Default | Purpose |
|---|---|---|
| `--config <path>` | required | Path to the Panorama running-config XML file |
| `--device-group <name>` | required | Target device-group name (whose firewall would receive this traffic) |
| `--src-ip <ip>` | required | Source IP |
| `--dst-ip <ip>` | required | Destination IP |
| `--src-zone <name>` | (any) | Source zone — omit for zone-agnostic match (caveat emitted) |
| `--dst-zone <name>` | (any) | Destination zone — omit for zone-agnostic match (caveat emitted) |
| `--protocol {tcp,udp}` | (any) | Protocol |
| `--dst-port <int>` | (any) | Destination port |
| `--verbose` / `-v` | off | Print the full per-rule evaluation trace |
| `--json` | off | Suppress human-readable output; emit structured JSON only |
| `--output-dir <path>` | `$PANO_REPORTS_DIR` (or `./.pano_reports/`) | Override the report root. Each run lands at `<dir>/check_policy_match/<UTC_TS>/verdict.json` |
| `--no-disk` | off | Suppress the on-disk verdict.json (stdout only) |

### Exit codes (`check_policy_match.py`)

| Code | Meaning |
|---|---|
| `0` | Verdict was `allow` |
| `1` | Verdict was anything else (deny / drop / reset / default-deny) |

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
| `--subnet-mask <int>` | 24 | CIDR mask used to compute the src/dst /N subnets for affinity scoring. Try /16 if /24 is too narrow. |
| `--max-samples <int>` | 5 | Top-N supporting rules per DG to record as recommendation rationale |
| `--json` | off | Suppress human-readable output; emit structured JSON only |
| `--output-dir <path>` | `$PANO_REPORTS_DIR` (or `./.pano_reports/`) | Override the report root. Each run lands at `<dir>/recommend_dg/<UTC_TS>/recommendation.{json,txt}` |
| `--no-disk` | off | Suppress the on-disk recommendation files (stdout only) |

### Exit codes (`recommend_dg.py`)

| Code | Meaning |
|---|---|
| `0` | All cases — report emitted successfully |

---

## 9. Caveats — what's NOT in this runbook

The following live in the [lab runbook](RUNBOOK_PAN_LAB.md) and must not bleed into production work:

- API authentication
- Config snapshot pulling (`pull_panorama_config.py`) — uses the API
- Configuration changes (`add_services_to_rules.py`) — writes to candidate
- Commit / revert operations
- TLS verification disabling

**If you find yourself reaching for any of these on a customer engagement, stop.** The right move is to ask the customer for a fresh XML export instead.
