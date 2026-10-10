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
| 2026-10-06 | **One Palo group per NSX group, `<group>_np_ips`** (the NSX sibling naming convention, suffix from `OBJECT_APPENDIX`), holding the group's addresses at **every** site, replacing one group per sibling view. Rule sides read like the NSX rule; the address object names keep the view (`-np_ips`, `-avs_ips`, `-lm3_ips`) so the site stays visible inside the group; retiring a site later means removing address objects, not editing rules |
| 2026-10-06 | **Workflow A to D code is not touched.** The multivendor and Palo workflows are additive, built on `app/common` and the Palo track's own modules; they only read the NSX workflows' bundles |
| 2026-10-07 | **Migration requests** ([RUNBOOK_MIGRATION_REQUEST.md](RUNBOOK_MIGRATION_REQUEST.md)): a requester submits the servers to migrate (VM names or IP addresses; an IP resolves to the VM that owns it); a report lists every rule they use and every change on the destination (A, C), the source (D) and Palo Alto; the request is approved; at the change window a re-capture rebuilds it and applies it. Source changes since approval went through their own approval and are taken and listed; a change to the request's own servers stops the run |
| 2026-10-07 | **Workflow D scope in a request: only the groups the servers are members of, and the rules those groups are in.** Each D sibling holds only the requested servers' new addresses |
| 2026-10-07 | **Palo device group `dg-4`** for migration requests (pano4). palo5's direct-push objects were removed first (124 reverted, read back clean) |
| 2026-10-09 | **The Palo dry run writes the Panorama paste file** (Mike: "i need the dry run to create this"): `pan_set_commands.txt` holds one `set` command for each object the dry run found missing (addresses, address groups, services, service groups, rules, in creation order), built from the same REST entries the push sends; `pan_delete_commands.txt` removes exactly those. The dry run inside `request` (the approval report) and in `run --phase palo` both write it. Separate script `tools/pan/pan_cli_commands.py` (logic `app/multisite/pan_set_commands.py`), switchable (`--no-palo-cli` on a request, `--no-cli-commands` on the push), and runnable by hand on any run (`--all-objects` when Panorama cannot be checked). Not yet pasted on a real Panorama |
| 2026-10-08 | **Palo: dry runs only for now.** Panorama and firewall dry runs are fine; no `--apply` of push or revert until Mike says so |

## Built (branch `nsx-lm3_palo-1`; in commits `dfd06c3` and `e8bcd5e` unless marked uncommitted)

### NSX side: ready to run, no new code in the path

| Item | Status |
|---|---|
| `data/subnet_map_lm2.csv` | **Trimmed 2026-10-06** to the subnets that actually move: 10.6.0/1/2.0/24 to 10.7.0/1/2.0/24 (3 rows). The 21-row template copied from `nonprod_map.csv` remapped networks that never move (10.4, the 10.5 BGP/TEP network, 10.10, 10.21, 10.250) and /24s that do not exist; the old version is in git (`dfd06c3`) |
| `data/subnet_map_lm3.csv` | **Trimmed 2026-10-06** the same way: 10.6.0/1/2.0/24 to 10.8.0/1/2.0/24 (3 rows) |
| Map checks | Both "Map OK", no collision. Step 4/5 `d2a` dry runs rebuilt with them: 17 siblings each (was 22), mapped addresses only in 10.7.0-2.x and 10.8.0-2.x |
| Runbook + PowerShell card | Steps 2 to 6, each with its own run directory. Steps 2 and 3 are covered by [RUN_AC_LM3.md](../nsx/RUN_AC_LM3.md) (lm3 duplicated from lm2 on 2026-10-06). **Steps 4 and 5 `d2a` dry runs ran clean on 2026-10-06** (22 `_avs_ips` and 22 `_lm3_ips` siblings from lm1, 0 errors); nothing applied |

### Migration requests (built 2026-10-07, uncommitted)

`tools/multisite/migration_request.py` (commands `request`, `preview`, `approve`, `refresh`, `run`, `report`) with its logic in `app/multisite/migration_request.py` and 20 tests in `tests/test_migration_request.py`. It runs the existing push tools with the workflow driver's flags on its own bundles and never edits Workflow A to D code. The Palo plan uses the same mapping code as `plan-rules`, from the request's own capture.

Proof run 2026-10-07, read-only, lm1 to lm3 with Palo `dg-4`: 22 rules, 30 groups, 8 services, 14 C siblings, 18 D siblings (21 source rules amended, matching the live amend dry run), 106 Palo objects to create on `dg-4`; a refresh from a new capture gave the same fingerprint; every phase passed as a dry run. Nothing applied.

Found while building it (not fixed, existing tools): `filter_policy_bundle.py` and `consolidate_hot_rules.py` look for nested services in a field NSX does not use (`members` instead of `nested_service_path`), so their bundles leave out the services a service group nests (lm1/lm2: `seed-svc-web-bundle`). The migration tool follows `nested_service_path`.

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

Tests: 505 in the suite (28 for the rule planner in `tests/test_pan_rules.py`, 20 for migration requests);
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
| palo5 (firewall, vsys1 candidate config) | 2026-10-07: the 124 objects of the 04:31 UTC direct push removed with its own revert (dry run 124, apply 124 deleted, read back: no addresses, address groups, service groups or local rules left; the three local services `dns-53`, `udp-53`, `tcp-53` predate this work and were left) | re-push `pan_mirror_runs/nsx-lm1.lab.local/20261006_200022/plan.json` with `--host palo5.lab.local` |

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
| group on a rule side | one static group `<group>_np_ips` holding the members of every sibling of the group across the bundles; an IP-only group adds its own addresses; a group of groups adds its members' addresses, expanded the same way. On the Palo `<group>_np_ips` holds all sites' addresses (on lm2/lm3 the NSX group of that name holds lm1's only); IP-only groups get a `_np_ips` name there that has no NSX twin |
| segment member, empty tag group, unsupported action, context profile | left out and reported; the Palo rule is narrower than NSX, never wider; a side with nothing left, or a context profile, skips the rule |
| `ANY` | `any` (never produced by leaving members out) |
| TCP/UDP service | mirrored exactly: one port entry = a service of the same name in `shared`; several entries, or nested services = a service group of the same name whose members are one service per entry (`<svc>-tcp`, `<svc>-udp`) and the nested services' own objects. Entries are never merged |
| ALG service (FTP, TFTP, Oracle TNS, RPC) | its port as a service (ports wherever possible), listed in the App-ID review |
| App-ID anything | every case is listed in the "App-ID review" section of `plan.md`: NSX rules with context profiles (skipped), ICMP (App-IDs, no port form), ALGs (ports), services with no port form (left out) |
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

**All of it was reverted the same day (16:57 UTC)**, newest first: 1
post-rule, then 28 pre-rules and 2 service groups, then 171 shared objects,
each after a dry run showing the same count. Independent read-back: none of
the 202 left; `shared` back to its earlier 18 addresses, 2 groups and 11
services; `dg-5` rulebases and objects empty. Nothing on pano4 from this work
now.

**Layout changed the same afternoon** to one `<group>_np_ips` group per NSX
group (decision above). lm1 plan `20261006_171654`: 28 rules, **27 groups
(was 69)**, **75 names on the rules' sides (was 205)**, 87 addresses, 15
services, 2 service groups, profiles from `.env`, 0 errors. Applied 17:26 UTC
(159 created), then **reverted at 17:31 (159 deleted)** because the subnet
maps still carried template rows; the maps were then trimmed (above).

**Direct to the firewall, 2026-10-07 04:31 UTC.** `plan-rules --target
firewall` (objects in `vsys1`, rules in the firewall's local rulebase) and
`push --host palo5.lab.local --rest-version v10.2`. First the dry run found
110 names Panorama had already pushed to palo5 (a 15:05 version committed
from pano4); the 124 were reverted from pano4 and Mike committed and pushed
pano4, which cleared them. The second dry run had 0 clashes; the apply
**created 124 objects in palo5's candidate config** as `agentuser` (57
addresses, 27 `<group>_np_ips` groups, 13 services, 3 service groups, 24
local rules with the `.env` profiles). Independent read-back: nothing
missing, 0 field differences, rule order as planned. Not committed on palo5.
Undo: `revert --manifest
pan_mirror_runs/nsx-lm1.lab.local/20261006_200022/push_20261007_042611_apply.json
--host palo5.lab.local --no-tls-verify` (the REST version is taken from the
push). pano4 now holds none of these objects. **Removed 2026-10-07 20:20 UTC** with that revert (124 deleted, read back clean), before the migration-request work moved the Palo target to `dg-4`.

Earlier, **pushed again 17:48 UTC from the rebuilt bundles** (plan `20261006_174622`, reverted at 03:41 UTC on 10-07 to clear the way):
22 NSX rules in scope, 2 skipped, **24 Palo pre-rules**, 27 `<group>_np_ips`
groups, 57 addresses, 14 services, 2 service groups, profiles from `.env`.
Dry run 124 `would_create`, apply 124 created; independent read-back: nothing
missing, 0 field differences, rule order as planned. **In pano4 candidate
config now, not committed.** Undo: `revert --manifest
pan_mirror_runs/nsx-lm1.lab.local/20261006_174622/push_20261006_174718_apply.json
--no-tls-verify`, dry run then `--apply`. At the same check, pano4's
own shared objects and dg-3/4/6 objects were gone as well, removed outside
this tool (the revert deleted exactly the 159 names it had created). Keeping the Palo current as NSX changes still needs an additive
"add missing members" push (today's push only creates objects that are
missing).

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
| Palo P3: rules | **Working end to end and reverted** (2026-10-06): 28 pre-rules and a post-rule with profiles were created, read back identical, then removed. Next: decide the group layout (above), then the additive update push. Open: zones (`any`/`any` today), the real path through pano1 |

## Open questions

The full list, with today's behaviour and how to answer each, is in
[QUESTIONS.md](QUESTIONS.md) (2026-10-06). Older items:

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
