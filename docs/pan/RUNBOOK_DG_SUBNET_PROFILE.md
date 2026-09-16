# RUNBOOK: Device Group subnet profile

Builds a DG <-> subnet ownership map from the existing rule population, bucketed
to /24, and reports the top N subnets per device group. Answers "which DG is the
natural home for a rule touching this address space".

Two front ends over one engine (`app/palo/pan_dg_subnets.py`):

| | where | data source |
|---|---|---|
| CLI | `tools/pan/dg_subnet_profile.py` | offline Panorama XML export |
| GUI | SSDD Toolkit, **Rule Placement** page | the REST config snapshot |

Use the GUI for day-to-day request handling (section 3a); use the CLI when you
want the CSV/JSON artifacts, a non-default bucket mask, or an offline run
against a customer config you were handed.

**Read-only.** The CLI makes no network calls and loads no credentials. The GUI
path reads the snapshot the toolkit already holds (agent-ro, REST reads).

---

## 1. Prerequisites

```bash
cd /path/to/nsx_scripts
export PYTHONPATH="$PWD/app"
```

(Windows CMD: `set PYTHONPATH=%CD%\app`)

You need a Panorama config export. Pull one with:

```bash
python tools/pan/export_panorama_config.py
```

Exports land in `tools/pan/configs/`.

## 2. Standing report (build the cheat sheet)

```bash
python tools/pan/dg_subnet_profile.py \
  --config tools/pan/configs/pano4-export-20260904_010750.xml
```

Writes `profile.txt`, `profile.json` and `top_subnets.csv` to
`$PANO_REPORTS_DIR/dg_subnet_profile/<UTC_TS>/`. Add `--no-disk` for stdout only.

Per DG you get: enabled rule count, how many rules carry a specific source /
destination versus `any`, the number of distinct /24s the DG references, the top
N /24s with rule counts split src/dst, what share of the DG's address-bearing
rules the top N covers, and anything that could not be resolved offline (FQDN
objects, Dynamic Address Groups, dangling references).

`shared` is profiled as a pseudo-DG, because "this flow already lives in shared
policy" is a real answer.

Useful flags:

| Flag | Effect |
|---|---|
| `--top 20` | more rows per DG (`--top 0` = every bucket) |
| `--mask 16` | bucket at /16 instead of /24 |
| `--v6-mask 48` | IPv6 bucket mask (default /64) |
| `--expand-limit N` | a rule prefix wider than the bucket mask expands into its constituent buckets when there are at most N of them (default 16, so /20 and narrower expand at /24); wider prefixes stay as one aggregate row flagged `*`, so one `0.0.0.0/0` object cannot flood the table. `0` = never expand |
| `--include-inherited` | fold ancestor-DG and shared rules into each DG's profile. Default is DG-local only, which is what tells you where a NEW rule belongs |
| `--rule-filter` / `--skip-rule` / `--no-filter` | same rule-name filtering as `check_policy_match.py` |
| `--json` | machine output only |

## 3a. In the GUI (Rule Placement page)

```bash
python tools/pan/ssdd_toolkit_web.py --no-tls-verify
# then open http://127.0.0.1:8765/rule-placement
```

No new page was needed: the subnet profile is a second evidence source on the
existing **Rule Placement** page, which already takes exactly the input a
request gives you (source IP, destination IP).

The page shows two status lines, one per signal:

* **Routing topology** - `Pull routing tables`. Authoritative, needs admin
  credentials (op commands are denied to `agent-ro`).
* **Config snapshot** - pulled on the IP Rule Search page. Feeds rule history.

`Recommend placement` now runs with **either one**. Previously the button was
dead without a routing pull; now a missing topology degrades to rule history
only (clearly labelled as a shortlist, not a verdict) instead of blocking.

Output sections:

1. **Recommended placement (routing)** - unchanged, plus the full per-DG table.
2. **Rule history** - one row per device group, showing its best covering /24
   for the source and for the destination, with rule counts and where that
   subnet ranks inside that DG.

`Show subnet map` renders the standing view: top 10 /24s per device group, with
rule counts, share, and sample objects. It needs only the config snapshot.

The profile is built once per snapshot and cached on the snapshot's `pulled_at`,
so lookups after the first are instant. Re-pulling the config rebuilds it.

## 3. Per-request lookup (CLI)

For an actual request, do not eyeball the top 10. `--lookup` consults the full
index, including each DG's long tail:

```bash
python tools/pan/dg_subnet_profile.py \
  --config tools/pan/configs/<export>.xml \
  --lookup 10.50.5.10 --lookup 172.16.9.20
```

Each hit reports the DG, the covering subnet, rule counts split src/dst, the
subnet's rank within that DG, and sample address objects. Specific buckets are
ranked above aggregates.

If nothing covers the address, no DG has any rule history for it: decide by
routing or zone, with `shared/post-rulebase` as the usual catch-all home.

## 4. Where this sits in the placement workflow

Rule population is a **proxy** for placement, not the truth. A DG only enforces
a flow its firewalls actually see. Order of authority:

1. **Routing.** `app/palo/pan_rule_placement.py` picks the DG whose firewall has
   the most specific route to each endpoint. Needs live access (routing tables
   proxied through Panorama), and it is the closest thing to ground truth.
2. **Zone / interface layout.** Which subnets terminate on which zones, and which
   template each DG's devices use. See `app/palo/pa_xml_zone.py` and
   `app/palo/dg_zone.txt`.
3. **Rule population.** This tool (standing map) and `tools/pan/recommend_dg.py`
   (single flow, plus a check for whether an existing rule already permits it).

Normal sequence for a request:

```bash
# 1. Does a rule already allow it? If yes, stop.
python tools/pan/check_policy_match.py --config <cfg> \
  --src-ip 10.50.5.10 --dst-ip 172.16.9.20 --protocol tcp --dst-port 443

# 2. Which DGs have history with this address space?
python tools/pan/dg_subnet_profile.py --config <cfg> \
  --lookup 10.50.5.10 --lookup 172.16.9.20

# 3. Confirm against routing before you write the rule.
```

## 5. Known limitations

* `check_policy_match`'s parser keys address objects by NAME across all scopes,
  so the same name defined in two device groups collapses to whichever was
  parsed last. Rare, but it can misattribute a bucket.
* CLI only: literal IP ranges written inline in a rule (`10.4.1.5-10.4.1.20`)
  are not parsed by `check_policy_match`'s resolver and show up under
  "unresolved". Range-valued *address objects* are handled on both paths, and
  the GUI path handles inline ranges too.
* The GUI path profiles each scope's own pre/post rulebases only, with no
  equivalent of the CLI's `--include-inherited`.
* Bucket mask in the GUI is fixed at /24 (`DG_SUBNET_V4_PREFIX` in
  `ssdd_toolkit_web.py`). Use the CLI when you need a different mask.
* FQDN objects and Dynamic Address Groups have no offline membership. They are
  counted in the unresolved tally, never silently dropped.
* `any` contributes no positional signal and is counted separately, not bucketed.
