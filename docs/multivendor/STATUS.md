# Multivendor rollout: status

Where the three-site NSX plus Palo Alto work stands. Updated 2026-10-06.
Runbook: [RUNBOOK_MULTIVENDOR_ROLLOUT.md](RUNBOOK_MULTIVENDOR_ROLLOUT.md)
([PowerShell](RUNBOOK_MULTIVENDOR_ROLLOUT_PS.md)).

## Scenario (theoretical, lab-tested piece by piece)

VMs leave `nsx-lm1` one at a time for **either** `nsx-lm2` (AVS) or `nsx-lm3`
(new site). Traffic must keep flowing between all three sites and through the
Palo Alto firewall between them. In the lab, device group `dg-5` on `pano4`
**stands in** for that firewall: it is treated as if it were in the path, but
pano4's firewalls are not (the managers' real BGP peers are palo7/palo8 under
pano1, see [LAB_TOPOLOGY.md](../reference/LAB_TOPOLOGY.md)). Work on dg-5
proves the API calls and payloads, not traffic flow.

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
| 2026-10-06 | **Palo rules (P3) go to `dg-5`'s pre-rulebase**, candidate only, one per NSX rule that uses a group with a sibling. Each NSX group on a rule becomes **all its sibling views** (`_np_ips` current addresses, `_avs_ips`, `_lm3_ips`): a rule copied from one manager names one view only and would allow only traffic that never crosses the firewall. **IP-only NSX groups without a source-view sibling are mirrored as themselves** (same name). Members Panorama cannot match (segments, empty tag groups) are left out: a Palo rule may be narrower than NSX, never wider, and an empty side skips the rule. Zones `any`/`any` in the lab |
| 2026-10-06 | **Palo objects are created in `shared`** (address objects, address groups, services, service groups), not in `dg-5`, so any device group can use them. Rules stay in the device group. `--object-location device-group` restores the old behaviour |
| 2026-10-06 | **Service groups stay** (briefly dropped, then reinstated the same hour): an NSX service spanning TCP and UDP is `<svc>-tcp` + `<svc>-udp` inside a service group named after the NSX service. Mike enables the `agent_role` permission for them instead |
| 2026-10-06 | **Rules can carry a security profile and a log forwarding profile**, and the device group, security profile group and log forwarding profile live in `.env` (`PANORAMA_DEVICE_GROUP`, `PANORAMA_SECURITY_PROFILE_GROUP`, `PANORAMA_LOG_FORWARDING_PROFILE`); command-line flags override them, `none` switches a profile off. Profiles must already exist on Panorama: `push` checks first and sends nothing if one is missing. Security profiles go on allow rules only |
| 2026-10-06 | **Post-rulebase supported** (`--rulebase post`). Rule names are unique across pre and post, so `--rule-suffix` and `--nsx-rule` exist for putting a rule into both |
| 2026-10-06 | **Workflow A to D code is not touched.** The multivendor and Palo workflows are additive, built on `app/common` and the Palo track's own modules; they only read the NSX workflows' bundles |

## Built (branch `nsx-lm3_palo-1`; in commits `dfd06c3` and `e8bcd5e` unless marked uncommitted)

### NSX side: ready to run, no new code in the path

| Item | Status |
|---|---|
| `data/subnet_map_lm2.csv` | `nonprod_map.csv` minus its 10.8 rows. Existing loader: 21 rows, 0 invalid |
| `data/subnet_map_lm3.csv` | 10.6 to 10.8, 10.4 to 10.24, 10.5 to 10.25, 10.10 to 10.30, 10.21 to 10.41, 10.250 to 10.252. 21 rows, 0 invalid |
| Map checks | No collision within either map or between them |
| Runbook + PowerShell card | Steps 2 to 6, each with its own run directory. Steps 2 and 3 are covered by [RUN_AC_LM3.md](../nsx/RUN_AC_LM3.md) (lm3 duplicated from lm2 on 2026-10-06). **Steps 4 and 5 `d2a` dry runs ran clean on 2026-10-06** (22 `_avs_ips` and 22 `_lm3_ips` siblings from lm1, 0 errors); nothing applied |

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

Tests: 474 in the suite (28 for the rule planner in `tests/test_pan_rules.py`);
the only failure is `test_longest_prefix_wins`, which predates this work.

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

## Palo Alto: what goes to Panorama

Only the sibling IP groups that the NSX steps create and add to rules, read
from that step's sibling bundle, so both sides come from the same data.
Objects go to `shared` (since 2026-10-06), rules to device group `dg-5`.
`push` and `revert` write a markdown report beside every manifest
(`push_<ts>_<mode>.md`, `revert_<ts>_<mode>.md`; `report --manifest` re-renders
one): per-kind counts, the failure that stopped a push, objects left unchanged
because their content differs, every object in order, the undo command.

| From the NSX sibling bundle | On Panorama (`shared`) |
|---|---|
| sibling group `<group>_np_ips` / `_avs_ips` / `_lm3_ips` | static address group, same name |
| address owned by a VM (mapped addresses: the VM that owns the source address) | address object `<hostname>-<address>-<suffix>`, e.g. `ax2001-10.7.0.101-avs_ips` |
| subnet, range, or address no VM owns | address object `<address>-<suffix>`, e.g. `10.7.1.0_24-avs_ips` |

Hostnames come from the source manager's VMs (read-only). A powered-off VM
reports no address, so its addresses fall back to `<address>-<suffix>`: on lm1
today only `ax2001` is powered on. Power the VMs on before planning to get
hostname names. Plan on the 2026-10-06 lm1 to lm3 `_np_ips` bundle: 14 static
groups, 10 addresses, 0 errors.

### Rules (P3, built 2026-10-06, uncommitted; live push stopped by a permission)

`nsx_pan_mirror.py plan-rules --bundle <np_ips run> --bundle <avs_ips run>
--bundle <lm3_ips run>` reads the source manager's policies, rules, groups and
services (read-only) and plans, besides the objects above:

| NSX | Panorama (`dg-5` pre-rulebase) |
|---|---|
| rule that uses a group with a sibling | one rule, same name (63 characters, hash suffix beyond that), NSX evaluation order, appended at the bottom of the pre-rulebase |
| group on a rule side | every sibling of the group across the bundles; an IP-only group with no source-view sibling also as itself (static group, same name); a group of groups as its members, expanded the same way |
| segment member, empty tag group, unsupported action, context profile | left out and reported; the Palo rule is narrower than NSX, never wider; a side with nothing left, or a context profile, skips the rule |
| `ANY` | `any` (never produced by leaving members out) |
| TCP/UDP service | service object of the same name in `shared` (one per protocol plus a service group when a service spans TCP and UDP); nested services flattened |
| ICMP service | a second rule `<name>-icmp` with App-IDs `icmp`, `ping`, `ipv6-icmp` and `application-default` |
| `ALLOW` / `DROP` / `REJECT`, disabled, negated sides | `allow` / `drop` / `reset-both`, `disabled`, `negate-source` / `negate-destination` |
| zones | `any` to `any` (`--zone-from` / `--zone-to`) |
| (not from NSX) security profile | `profile-setting` group (`--profile-group` / `PANORAMA_SECURITY_PROFILE_GROUP`) or individual profiles (`--profile virus=NAME ...`), allow rules only |
| (not from NSX) logging | `log-setting` (`--log-setting` / `PANORAMA_LOG_FORWARDING_PROFILE`), every rule |
| rulebase | pre (default) or post (`--rulebase post`); `--nsx-rule` limits the plan to named NSX rules, `--rule-suffix post` appends `-post` to the names |
| applied-to, direction, logging | not represented |

Plan on lm1 with the three bundles of 2026-10-06: 29 NSX rules, 27 in scope,
3 skipped (two reference `seed-tag-net-10-8-0`, empty on lm1 since its VMs
moved to lm3; one is segment-only), 1 narrowed; **28 Panorama rules**, 69
address groups (58 siblings, 11 mirrored IP-only groups), 87 addresses, 15
services, 2 service groups, 0 errors. `push` takes the same plan file; it now
also flags a same-named object whose content differs (`exists_differs`) and
still never modifies it.

**Live on pano4, 2026-10-06:** dry run 201 `would_create`. The first apply
created 171 (87 addresses, 69 groups, 15 services) and stopped at the first
service group: `agentuser` got **HTTP 403 on `Objects/ServiceGroups`**, in
`dg-5` and in `shared` alike. The `dg-5` batch was reverted (171 deleted, read
back empty) and re-pushed into `shared`. Mike then enabled the role permission
(Objects > Service Groups, Policies > Security Pre Rules) and the re-run (171
`exists_unchanged`, 0 differences) **created the 2 service groups and the 28
pre-rules** in dg-5 (manifest `20261006_150209/push_20261006_150344_apply.json`).
A post-rule test followed (`--rulebase post --nsx-rule seed-web-https
--rule-suffix post`, profiles from `.env`): the push found
`test-security-profile` and `test-logging-profile` in shared, left 119 objects
unchanged and created `seed-web-https-post` in dg-5's post-rulebase, read back
with the profile group and log forwarding profile, 0 differences.

Everything is **candidate config, not committed**. Undo in three steps, newest
manifest first because the rules reference the objects:
`revert --manifest .../20261006_155901/push_20261006_155955_apply.json` (1
post-rule), then `.../20261006_150209/push_20261006_150344_apply.json` (30),
then `.../20261006_142921/push_20261006_143143_apply.json` (171); each as a
dry run, then `--apply`.

## Security finding (not fixed)

`tools/pan/probe_api_permissions.py` prints its keygen URL, including the
account password, in the traceback when Panorama is unreachable (seen
2026-10-05). The new mirror tool sends the password in the POST body and
reports connection errors without the URL.

## Not done yet

| Piece | Notes |
|---|---|
| NSX steps 4 to 6 | Steps 2 and 3 done through RUN_AC_LM3.md. Steps 4 and 5 `d2a` dry runs clean (2026-10-06); no apply yet |
| Palo P1: object plan | **Built, siblings only** (2026-10-05): `nsx_pan_mirror.py plan --bundle <NSX step run dir>`. On the existing lm1 `_avs_ips` bundle: 24 static groups, 26 addresses (1 named by hostname; the other VMs are powered off), 0 errors |
| Palo P2: push to `pano4` dg-5 | **Working** (REST API only; XML API not allowed). First live test 2026-10-05 created 24 objects in candidate config, all read back exactly; **those 24 were reverted the same day** (independent read-back: all gone). Nothing is on pano4 from this work now. Lab runs need `--no-tls-verify` (PAN-OS default self-signed certificate) |
| Palo P3: rules | **In pano4 candidate config since 2026-10-06**: 28 pre-rules in `dg-5`, 173 objects in `shared`, read back identical to the plan. Next: Mike reviews in the Panorama UI; revert at the end of the test (two manifests, newest first, see above). Open: zones (`any`/`any` today), the real path through pano1 |

## Open questions

1. Settled 2026-10-05: the Palo gets only the sibling IP groups, named as on NSX, with `<hostname>-<address>-<suffix>` address objects.
2. Settled 2026-10-05: tags are not used on the Palo for now (pano4 does accept `scope.value` tag names if they come back).
3. Does lm2 to lm3 traffic cross `dg-5`, or only traffic to and from lm1? (Decides whether step 6 and its Palo rules are needed.)
4. Keep or delete `data/multisite_map.csv`.
5. Settled 2026-10-06: `agent_role` now has REST write on service groups and
   security pre-rules (it already had addresses, address groups, services);
   the full P3 push works as `agentuser`.
6. A nested group with a mapped sibling (for example `seed-nested-all_avs_ips`)
   appears on the Palo rule next to its expanded members' views, so some
   addresses are covered twice. Harmless; trim if the rules get too long.

## Known issues carried over

- `nonprod_map.csv`: `10.8.0.0/24 -> 10.9.1.0/24` collides with its `/16` parent row. Left unchanged.
- Workflow A keeps its undo baselines under the source host's folders, so after A onto lm3, a default A rollback on lm2 is refused (`--from-baseline` needed).
- An apply that sends nothing still writes a newer baseline (pending item #11).
- The inventory flags four more tools that may log local time as "UTC" (`recommend_dg`, `dg_subnet_profile`, `pull_panorama_config`, `report_rollback`); not yet verified.
