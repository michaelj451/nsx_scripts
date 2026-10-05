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
| 2026-10-04 | **Palo objects mirror NSX exactly**, replacing the earlier rule (hostname + asl_id tags, a security_group tag above 10 members). Tag-based NSX groups become dynamic address groups on the same tags; IP-based groups become static groups of the same addresses; nested groups nest the same way. Each VM address object is **named by the VM's hostname** and carries **the VM's NSX tags**; any other address object is **named by its IP address** |

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

## Exact mirror: how NSX maps to Panorama

| NSX | Panorama (device group dg-5) |
|---|---|
| VM with an IP | address object named by the VM's `hostname` tag, carrying all of the VM's NSX tags |
| IP address entry | address object named by the address (`10.6.0.50`, `10.6.1.0_24`, range `a-b`) |
| tag `scope|value` | tag `scope.value` (format is a flag; accepted by pano4 on 2026-10-05) |
| tag-only group (AND/OR, nesting) | dynamic address group with the same name and the same logic |
| IP-only group, sibling groups (`_avs_ips` etc.) | static address group of the address objects |
| group of groups | static address group of those groups |
| VMs by external id | static address group of those VMs' objects |
| tags and addresses in one group | static group holding a helper dynamic group `<name>-tags` (a Panorama group cannot be both kinds) |
| segment paths, non-tag conditions, empty groups | not representable; reported as findings |

## Security finding (not fixed)

`tools/pan/probe_api_permissions.py` prints its keygen URL, including the
account password, in the traceback when Panorama is unreachable (seen
2026-10-05). The new mirror tool sends the password in the POST body and
reports connection errors without the URL.

## Not done yet

| Piece | Notes |
|---|---|
| NSX steps 2 to 6 | Ready; start with the step 2 dry run (Workflow A onto lm3) |
| Palo P1: object plan | **Built**: `tools/pan/nsx_pan_mirror.py plan` (engine `app/multisite/pan_mirror.py`). Read-only against NSX. On lm1 (all 56 non-system groups): 16 tags, 57 address objects, 17 dynamic + 40 static groups; 2 errors (the -old/-New VMs lack hostname tags), 5 VMs without IP (powered off). Sample run on 5 groups: `pan_mirror_runs/nsx-lm1.lab.local/latest/plan.md` |
| Palo P2: push to `pano4` dg-5 | **Working, first live test passed 2026-10-05.** REST API only (the XML API is not allowed: Mike). `agentuser` can now create tags, addresses and address groups in dg-5 over REST (Mike added the permission); XML API config stays 403. Sample of 4 NSX groups (dynamic, static, nested, mixed): **24 objects created in candidate config, all 24 read back exactly as planned**, nothing committed. They are still in pano4's candidate config for review; undo: `python tools/pan/nsx_pan_mirror.py revert --manifest pan_mirror_runs/nsx-lm1.lab.local/20261005_114107/push_20261005_114131_apply.json --no-tls-verify --apply` (dry run confirmed it would delete exactly those 24). **If anyone commits on pano4 before the revert, these objects are committed too.** |
| Palo P3: rules | After P2 |

## Open questions

1. Settled 2026-10-04: exact mirror replaces the earlier Palo tag rule.
2. Settled 2026-10-05: NSX `scope|value` becomes Panorama tag `scope.value`; pano4 accepts it.
3. Does lm2 to lm3 traffic cross `dg-5`, or only traffic to and from lm1? (Decides whether step 6 and its Palo rules are needed.)
4. Keep or delete `data/multisite_map.csv`.

## Known issues carried over

- `nonprod_map.csv`: `10.8.0.0/24 -> 10.9.1.0/24` collides with its `/16` parent row. Left unchanged.
- Workflow A keeps its undo baselines under the source host's folders, so after A onto lm3, a default A rollback on lm2 is refused (`--from-baseline` needed).
- An apply that sends nothing still writes a newer baseline (pending item #11).
- The inventory flags four more tools that may log local time as "UTC" (`recommend_dg`, `dg_subnet_profile`, `pull_panorama_config`, `report_rollback`); not yet verified.
