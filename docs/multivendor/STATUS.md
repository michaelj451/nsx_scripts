# Multivendor rollout: status

Where the three-site NSX plus Palo Alto work stands. Updated 2026-10-04.
Runbook: [RUNBOOK_MULTIVENDOR_ROLLOUT.md](RUNBOOK_MULTIVENDOR_ROLLOUT.md)
([PowerShell](RUNBOOK_MULTIVENDOR_ROLLOUT_PS.md)).

## Scenario (theoretical, lab-tested piece by piece)

VMs leave `nsx-lm1` one at a time for **either** `nsx-lm2` (AVS) or `nsx-lm3`
(new site). Traffic must keep flowing between all three sites and through the
Palo Alto device group `dg-5` on `pano4`, which sits between them.

## Decisions so far

| Date | Decision |
|---|---|
| 2026-10-03 | lm3 is a new site that needs Workflow A and Workflow C, plus its own subnet mapping |
| 2026-10-03 | VMs can go to either lm2 or lm3; lm2 and lm3 may need to talk to each other |
| 2026-10-04 | Implement each step separately and the Palo separately |
| 2026-10-04 | **One two-column subnet map per target**, so every NSX step runs through the existing, tested driver with no new code |
| 2026-10-04 | lm3 map keeps 10.6 to 10.8, accepting that 6 of lm1's 8 VMs land on lm3's six placeholder VMs (.101/.102) |
| 2026-10-04 | New clean lm2 map; `nonprod_map.csv` left unchanged for the two-site runs |
| 2026-10-04 | Every VM must have an NSX `hostname` tag; the Palo plan never falls back to the VM name |
| 2026-10-04 | (Superseded 2026-10-05) **Palo objects mirror NSX exactly**, replacing the earlier rule (hostname + asl_id tags, a security_group tag above 10 members). Tag-based NSX groups become dynamic address groups on the same tags; IP-based groups become static groups of the same addresses; nested groups nest the same way. Each VM address object is **named by the VM's hostname** and carries **the VM's NSX tags**; any other address object is **named by its IP address** |
| 2026-10-05 | **Palo scope: only the sibling IP groups** the workflows create and add to rules (`<group>_np_ips`, `_avs_ips`, `_lm3_ips`), with the same names as on NSX. Read from the NSX step's sibling bundle. Address objects named **`<hostname>-<address>-<suffix>`** (for example `ax2001-10.6.0.101-np_ips`), or `<address>-<suffix>` when no VM owns the address. No tags, no dynamic groups |

## Built (uncommitted, branch `nsx-lm3_palo-1`)

### NSX side: ready to run, no new code in the path

| Item | Status |
|---|---|
| `data/subnet_map_lm2.csv` | `nonprod_map.csv` minus its 10.8 rows. Existing loader: 21 rows, 0 invalid |
| `data/subnet_map_lm3.csv` | 10.6 to 10.8, 10.4 to 10.24, 10.5 to 10.25, 10.10 to 10.30, 10.21 to 10.41, 10.250 to 10.252. 21 rows, 0 invalid |
| Map checks | No collision within either map or between them |
| Runbook + PowerShell card | Steps 2 to 6, each with its own run directory. Bash functions and map checks executed; PowerShell blocks parsed and run under `pwsh`. **No step has been run against the lab yet** |

### Shared library (new, existing scripts not migrated)

`app/common/`: file IO (atomic writes), paths, UTC timestamps, logging,
timestamped run folders, IP spans, subnet maps, markdown tables. It imports
neither vendor and does nothing on import; a test enforces both. An inventory of
duplicated helpers across the toolkit (about 70 logging setups, 63 timestamp
copies, 46 repo-root copies) is the backlog for moving scripts onto it one at a
time.

### Planner and Palo tag engine (built earlier, partly superseded)

- `tools/multisite/plan_multisite.py`: the runbook uses it only for
  `--check-map-only`. Its full mode (build every view at once) is superseded by
  the separate-step approach.
- `app/multisite/palo_tags.py`: Palo tag plan to the earlier rule (hostname and
  asl_id tags, security_group above 10 members). **Superseded** by the exact
  mirror (`app/multisite/pan_mirror.py`); kept until you decide to delete it.
- `data/multisite_map.csv` (three columns) now duplicates the two separate maps.
  Keep or delete: not decided.

### Fixes to existing tools (done 2026-10-04)

| Fix | Proof |
|---|---|
| `resolve_manager` knew no `nsx-lm5` although 21 tools offered it | Old code raised `KeyError`; test added |
| `tools/pan/add_services_to_rules.py` logged local time labelled "UTC" | Old code logged Central time, 5 hours off; fixed code logs UTC |
| VM-tag push **and** revert prompts auto-approved the next batch when input closed | Now stop and still write the manifest, like the shared batch helper; runbooks updated |
| `nsx-lm6` added | Every live tool's manager list runs lm1 to lm6; resolver maps `NSX_LM5`/`NSX_LM6`; `.env` not changed (no DNS records for lm5 or lm6 yet) |

Tests: 444 in the suite; the only failure is `test_longest_prefix_wins`, which
predates this work.

## Deck

`powerpoint/NSX_WORKFLOW_OVERVIEW.pptx` updated 2026-10-05 to 12 slides: the
two-site story (mapping corrected to 10.6 to 10.7, test count 444), then three
sites and the firewall, one map per target, the Palo mirror mapping, the first
live Panorama push, groundwork and fixes, and two-column open items.
Uncommitted; the previous version is in git.

## Lab changes made (all dry-run first, verified by reading back)

| Manager | Change | Undo |
|---|---|---|
| `nsx-lm1` | `hostname` tag added to 3 VMs (x515, gh0202, 551x4) | `revert_hostname_tags.py` with manifest `nsx_logs/reports/vm_tags_push/nsx-lm1.lab.local/20261004_183028_apply.json` |
| `nsx-lm3` | `hostname` tag added to all 6 VMs | same tool, manifest `.../nsx-lm3.lab.local/20261004_183041_apply.json` |
| `nsx-lm3` | `asl_id=8` added to all 6 VMs (one-off script, outside the repo) | its `--revert` with manifest `.../nsx-lm3.lab.local/20261004_183133_asl_id_apply.json` |

Left to Mike: hostname tags on lm1's `-old` and `-New` VMs (on the exclusion
list on purpose), and removing the stale group tags on six leftover test groups
on lm3.

## Palo Alto: what goes to dg-5

Only the sibling IP groups that the NSX steps create and add to rules, read
from that step's sibling bundle, so both sides come from the same data.

| From the NSX sibling bundle | On Panorama (device group dg-5) |
|---|---|
| sibling group `<group>_np_ips` / `_avs_ips` / `_lm3_ips` | static address group, same name |
| address owned by a VM (mapped addresses: the VM that owns the source address) | address object `<hostname>-<address>-<suffix>`, e.g. `ax2001-10.7.0.101-avs_ips` |
| subnet, range, or address no VM owns | address object `<address>-<suffix>`, e.g. `10.7.1.0_24-avs_ips` |

Hostnames come from the source manager's VMs (read-only). A powered-off VM
reports no address, so its addresses fall back to `<address>-<suffix>`: on lm1
today only `ax2001` is powered on. Power the VMs on before planning to get
hostname names. Plan on the existing `_avs_ips` bundle (24 siblings on lm1):
24 static groups, 26 addresses, 0 errors.

## Security finding (not fixed)

`tools/pan/probe_api_permissions.py` prints its keygen URL, including the
account password, in the traceback when Panorama is unreachable (seen
2026-10-05). The new mirror tool sends the password in the POST body and
reports connection errors without the URL.

## Not done yet

| Piece | Notes |
|---|---|
| NSX steps 2 to 6 | Ready; start with the step 2 dry run (Workflow A onto lm3) |
| Palo P1: object plan | **Built, siblings only** (2026-10-05): `nsx_pan_mirror.py plan --bundle <NSX step run dir>`. On the existing lm1 `_avs_ips` bundle: 24 static groups, 26 addresses (1 named by hostname; the other VMs are powered off), 0 errors |
| Palo P2: push to `pano4` dg-5 | **Working** (REST API only; XML API not allowed). First live test 2026-10-05 created 24 objects in candidate config, all read back exactly; **those 24 were reverted the same day** (independent read-back: all gone). Nothing is on pano4 from this work now. Lab runs need `--no-tls-verify` (PAN-OS default self-signed certificate) |
| Palo P3: rules | After P2 |

## Open questions

1. Settled 2026-10-05: the Palo gets only the sibling IP groups, named as on NSX, with `<hostname>-<address>-<suffix>` address objects.
2. Settled 2026-10-05: tags are not used on the Palo for now (pano4 does accept `scope.value` tag names if they come back).
3. Does lm2 to lm3 traffic cross `dg-5`, or only traffic to and from lm1? (Decides whether step 6 and its Palo rules are needed.)
4. Keep or delete `data/multisite_map.csv`.

## Known issues carried over

- `nonprod_map.csv`: `10.8.0.0/24 -> 10.9.1.0/24` collides with its `/16` parent row. Left unchanged.
- Workflow A keeps its undo baselines under the source host's folders, so after A onto lm3, a default A rollback on lm2 is refused (`--from-baseline` needed).
- An apply that sends nothing still writes a newer baseline (pending item #11).
- The inventory flags four more tools that may log local time as "UTC" (`recommend_dg`, `dg_subnet_profile`, `pull_panorama_config`, `report_rollback`); not yet verified.
