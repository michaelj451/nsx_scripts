# Lab work log

Dated record of lab troubleshooting and infrastructure changes: what was seen,
how it was measured, what changed, and what is still open. Newest entry first.
Static lab layout lives in [LAB_TOPOLOGY.md](LAB_TOPOLOGY.md).

---

## 2026-10-15 (15:03 CDT): last night's full apply backed out

Mike: back out the 2026-10-14 full apply (request 20261014_201055, run
`runs/20261015_012351`) so lm1's rules lose the `_avs_ips` siblings, then fix
the request so Workflow A never copies source siblings. Each phase's rollback
dry run, then apply, newest first: palo deleted 28; d3 restored the 3 lm1 rules
(the 6 seed-infra rules created since were left alone, "blocked"); d2a deleted
3 `_avs_ips`; c restored 3 lm3 rules, deleted 3 `_np_ips`; a deleted 3 rules,
`test-policy-2`, 3 groups, `a3-super-ssh`. Checked: lm1 has no sibling groups
and its rules name only the originals (change record gone with them); lm3 is
the critical copy plus `always-rules-poilicy`; a pano4 dry run finds all 28
missing. Code fix (uncommitted): source siblings (request C/D suffix, or the
builder's "IP-only sibling of" description) are left out of the Workflow A
groups and stripped from the copied rules, the fingerprint and the Palo plan.

## 2026-10-15: Infrastructure seed policy on lm1 (for the vRNI flow filter sample)

Mike asked for a sample flow export with infrastructure rules; the rules were
created on lm1 so the sample's rule numbers are real. Bundle `nsx_logs/seed_infra_policies/20261015_184040`
(push tools' layout), `services.py` / `groups.py` / `policies.py` /
`rules.py push`, dry run then apply, 0 failed, read back:

| Rule # | Rule | Source -> destination | Services |
|---:|---|---|---|
| 8179 | seed-infra-ad | nsx-lm1-servers -> seed-infra-ad-servers (10.3.0.20, .21) | LDAP, LDAP-over-SSL, KERBEROS, KERBEROS-UDP |
| 8180 | seed-infra-dns-lookup | nsx-lm1-servers -> seed-infra-dns-servers (10.3.0.151, .152) | DNS, DNS-UDP |
| 8181 | seed-infra-ntp | nsx-lm1-servers -> seed-infra-ntp-servers (10.3.0.30, .31) | NTP |
| 8184 | seed-infra-splunk | nsx-lm1-servers -> seed-infra-splunk-indexers (10.3.0.40, .41) | seed-svc-splunk-9997 (new) |
| 8182 | seed-infra-puppet | nsx-lm1-servers -> seed-infra-puppet-servers (10.3.0.50) | seed-svc-puppet-8140 (new) |
| 8183 | seed-infra-snmp | seed-infra-snmp-pollers (10.3.0.60) -> nsx-lm1-servers | SNMP |

Policy `seed-infra-services`, category Infrastructure, sequence 30, all ALLOW.
The 10.3.0.20 to .60 hosts do not exist; the groups only give the rules
realistic destinations. Sample: `data/samples/vrni_flows_infra_sample.csv`.
A migration request leaves these rules out (Infrastructure). Undo:
`rules.py revert`, `policies.py revert`, `groups.py revert --allow-delete`,
`services.py revert`, each `--target nsx-lm1 --reports-dir <bundle>/<class>/push_report`.

## 2026-10-14 (20:23 CDT): full apply of the 2-server request, all phases

**APPLIED; Panorama not committed.** Request
`migration_requests/nsx-lm1_to_nsx-lm3/20261014_201055` (10.6.0.101 ax2001,
10.6.0.102 0e02; rules `migration-rule-1`, `migration-rule-2`, `migration-ssh`;
Infrastructure rules left out; `_np_ips` / `_avs_ips`, `dg-5`, change record
`[Ticket LAB-20261014 | mxferguson | 2026-10-14]`, all from `.env`). Approved
LAB-20261014 (Mike Ferguson); refresh `runs/20261015_012351`: no change since
approval. Every phase dry run, apply (NSX batch prompts answered Enter), verify:

| Phase | Applied | Check |
|---|---|---|
| a (lm3) | service `a3-super-ssh`, groups `migration-101`/`-102`/`migration-combo`, policy `test-policy-2`, 3 rules; 2 groups already identical, skipped | every object present |
| c (lm3) | 3 `_np_ips` siblings; 3 rules gain them, 17 untouched | V1-V6 OK |
| d2a (lm1) | 3 `_avs_ips` siblings (10.8.0.101 / 10.8.0.102) | |
| d3 (lm1) | 3 rules gain them, 12 untouched | WF-D VALIDATION PASS |
| palo (pano4) | 28 objects in the candidate config (25 `shared`, 3 rules in `dg-5`) | every object present |

Change record read back: on created groups, policy and rules on lm3, on the C
and D siblings, and on the amended `migration-ssh` on lm1; `ip-address-group`
(skipped as identical) has none, as intended. Undo newest first:
`run --run <run> --phase palo|d3|d2a|c|a --rollback [--apply]` (`palo` needs
`--no-tls-verify`).

## 2026-10-14: Panorama-only apply of the 2-server request

**APPLIED, NOT COMMITTED.** Request
`migration_requests/nsx-lm1_to_nsx-lm3/20261014_133645` (10.6.0.101 ax2001,
10.6.0.102 0e02; rules `migration-rule-1`, `migration-rule-2`; Infrastructure
rules left out; suffixes `_np_ips` / `_avs_ips` and device group `dg-5` from
`.env`). Approved LAB-20261014 (Mike Ferguson), refresh `runs/20261014_173908`:
no change since approval. Mike asked for the Panorama part only: `run --phase
palo` dry run (23 to create), apply, verify. pano4 candidate config now holds
23 objects: 21 in `shared` (16 addresses, 4 address groups, HTTPS) and the 2
rules in `dg-5`'s pre-rulebase; verify found every object. No NSX phase was
run (lm1 and lm3 unchanged). Commit is Mike's. Undo: `migration_request.py run
--run <run> --phase palo --rollback --no-tls-verify [--apply]`.

**ROLLED BACK 16:43 CDT** (Mike), never committed. Reason: lm1 changed since
(new `migration-ssh` rule and `migration-combo` group; `migration-101` gained
10.6.2.101, `migration-102` gained 10.6.2.102), and a new request would have
found two of these address groups lacking members, which the push never adds.
Rollback dry run listed exactly the 23; apply deleted 23; a fresh dry run of
the same run finds all 23 missing again, so pano4 is back as before.

## 2026-10-13: nsx-lm3 wiped, critical rules copied from nsx-lm1

**DONE.** lm3 now holds only lm1's critical rules (VERIFY PASS). lm3's
default Layer3 rule is DROP, so on lm3 only these 15 rules allow anything.

### Wipe (Mike ran the apply)

- Backup first: `nsx_backup/nsx-lm3.lab.local/20261013_164503` (22 groups,
  4 services, 4 customer policies).
- `tools/test/wipe_target_manager.py --target nsx-lm3` (full wipe). Dry run
  plan `nsx_wipe_bundle/20261013_164521/nsx-lm3.lab.local/pre_wipe_state.json`:
  13 rules, 4 policies, 22 groups (11 groups and their 11 `_np_ips`
  siblings, lm2's earlier clone of lm1), 4 services. Default sections kept;
  `default-layer3-rule` (DROP) was their only rule. Segments, T1, VM tags
  and VMs untouched.
- Before step 3 below, lm3 read back empty: 0 services, groups, policies,
  rules.

### Critical rules copy, nsx-lm1 to nsx-lm3

Run `nsx_critical_runs/nsx-lm1_to_nsx-lm3/20261013_170618`
([RUNBOOK_CRITICAL_RULES.md](../nsx/RUNBOOK_CRITICAL_RULES.md)).

- Step 1: lm1 Policy-API statistics 500 for every policy (3.2.x), the old
  firewall API answered for 6. Hot: 11 Application rules, 1 Infrastructure.
- Step 2: Infrastructure whole, 2 policies / 4 rules (`seed-policy-infra`,
  `test-infrastructure-policy`). Application hot rules 11 of 11:
  `Start_Policy` 8 of 9 (`allow-icmp-network-8` cold), `seed-policy-app`
  3 (`seed-web-https`, `seed-multi`, `seed-logged-drop` DROP).
  `test-policy-2` not copied (no hot rules). CHECK, accepted by Mike: cold
  `seed-empty-src` (REJECT) and `seed-disabled` (DROP, disabled) not copied.
- Step 3 apply (Mike approved `--piped-answers`): services 2+4, groups 5+13
  (`seed-ip-db-block` in both bundles, second push skipped as identical),
  policies 2+2, rules 4+11, 0 failed.
- Step 4: services 6, groups 18, policies 4, rules 15; missing 0, extra 0.
  VERIFY PASS.

Undo: `tools/nsx/critical_rules/revert.py --source nsx-lm1 --target nsx-lm3`
on the same run returns lm3 to empty.

### lm1 cleanup by Mike, 12:20 to 12:44 CDT

After the copy: `web_rule` and then the rest of `test-policy-1` disabled,
`seed-policy-app` deleted, then every Application policy removed except
`test-policy-2`, which now holds only the new `migration-rule` (HTTPS from
`ip-address-group` + `ip-address-group-10.10.2.0-24` to tag group
`migration-2555` = `migrate|2555`: ax2001 10.6.0.101, 0102 10.6.1.102).
The two Infrastructure policies stay. lm3 still holds the earlier critical
copy (`Start_Policy` 8 rules enabled, `seed-policy-app` 3 rules).

### First applied migration request: 10.6.0.101 (ax2001), lm1 to lm3, dg-4

Request `migration_requests/nsx-lm1_to_nsx-lm3/20261013_174358`, approved
(LAB-20261013, Mike Ferguson), run `runs/20261013_175707` (refresh: no
change since approval). One rule, `test-policy-2/migration-rule`. Each
phase dry run, then apply (batch prompts answered Enter, with Mike's
approval), then verify:

| Phase | Applied | Verify |
|---|---|---|
| a (lm3) | `migration-2555`, `test-policy-2`, `migration-rule` created; 2 groups already identical | every object present |
| c (lm3) | `migration-2555_np_ips` (10.6.0.101, 10.6.1.102); added to the rule's destination; 15 other rules unchanged | OK |
| d2a (lm1) | `migration-2555_lm3_ips` (10.8.0.101) | |
| d3 (lm1) | added to `migration-rule` destination; 4 other rules unchanged | WF-D VALIDATION PASS |
| palo (pano4) | 18 objects created in the candidate config (17 in `shared`, rule in `dg-4` pre-rulebase); **not committed** | every planned object on Panorama |

**ROLLED BACK 13:39 CDT** (Mike, after the D suffix was moved to
`OBJECT_APPENDIX_AVS` in `.env`; this request carried `_lm3_ips`). Each
phase's rollback dry run first, then apply, newest first: palo deleted 18,
d3 restored `migration-rule`, d2a deleted `migration-2555_lm3_ips`, c
restored the rule and deleted `migration-2555_np_ips`, a deleted
`migration-rule`, `test-policy-2`, `migration-2555`. Checked after: lm3
VERIFY PASS against the critical copy run `20261013_170618` (6/18/4/15,
nothing extra); lm1 has no `_lm3_ips` group and `migration-rule` names only
`migration-2555`; a pano4 dry run finds all 18 objects missing again.

### Cold seed policies on lm1, 16:33 CDT

Mike asked for seeded policies with obscure ports, one above and one below
`test-policy-2` (Application, sequence 5), meant to stay at 0 hits.
Bundle `nsx_logs/seed_cold_policies/20261013_213329` (services, policies,
rules in the push tools' layout), pushed with `services.py` / `policies.py` /
`rules.py push`, dry run then apply, 0 failed, read back from lm1:

| Policy (seq) | Rule | Action | Source -> destination | Port |
|---|---|---|---|---|
| `seed-cold-above` (4) | `seed-cold-a-tcp-17239` | ALLOW | ip-address-group -> migration-2555 | TCP 17239 |
| | `seed-cold-a-udp-19787` | ALLOW | network-6-0 -> vm1 | UDP 19787 |
| | `seed-cold-a-drop-23417` | DROP | ANY -> segment-group-1 | TCP 23417-23419 |
| `seed-cold-below` (6) | `seed-cold-b-tcp-27853` | ALLOW | vm2 -> network-6-0 | TCP 27853 |
| | `seed-cold-b-28411` | ALLOW | hardware-subnet -> migration-2555 | TCP+UDP 28411 |
| | `seed-cold-b-reject-29873` | REJECT | ANY -> vm1 | TCP 29873 |

Six services `seed-cold-*`. Every rule names a group that holds ax2001
(10.6.0.101), so a migration request for it now selects these 6 cold rules
too. Undo: `rules.py revert`, then `policies.py revert`, then
`services.py revert`, each `--target nsx-lm1 --reports-dir <bundle>/<class>/push_report`.

### `always-rules-poilicy` copied from lm1 to lm2 and lm3, 18:40 CDT

Mike created an Infrastructure policy on lm1 (id and display name are spelled
`always-rules-poilicy`) and asked for it on lm2 and lm3. Copied as is, the
Workflow A way: lm1 captured read-only, the policy's 2 rules plus their
groups bundled (one bundle per target), pushed with `groups.py` (segments
strip) / `policies.py` / `rules.py`, dry run then apply, 0 failed on both.

- Policy: Infrastructure, sequence 5, applied to ANY. Rules:
  `servers-to-rustdesk` (5, ALLOW, nsx-lm1/2/3-servers -> allowed servers
  anytime, any service) and `install-rustdesk` (10, ALLOW,
  ip-address-group-10.10.2.0-24 -> nsx-lm1/2/3-servers, any service).
- Groups, all IP-only: `nsx-lm1-servers` 10.6.0.0/16, `nsx-lm2-servers`
  10.7.0.0/16, `nsx-lm3-servers` 10.8.0.0/16, `allowed_servers_anytime`
  (10.3.0.151, 10.3.0.152, 10.4.0.200) created on both; 
  `ip-address-group-10.10.2.0-24` was already identical on both.
- Read back: policy, rules and groups on lm2 and lm3 match lm1 field for field.
- lm3 now holds the critical copy plus this policy and its 4 new groups.
- Bundles and push reports: `nsx_logs/policy_copy/always-rules-policy/20261013_233918/bundle_nsx-lm2` and `bundle_nsx-lm3`.
  Undo per target: `rules.py revert`, `policies.py revert`, `groups.py revert --allow-delete`,
  each `--target <t> --reports-dir <bundle>/<class>/push_report`.

---

## 2026-10-12: bit flips on centos9-123/124, root cause bad RAM in vsphere1

**OPEN (vsphere1 RAM).** VMs repaired. Mike moved all four test VMs to
vsphere7 (Minisforum MS-A2, Ryzen 9 7945HX); after a reboot there, `rpm -Va`
is clean on all four (.123 also needed `dnf reinstall dnf` for the one file
damaged on disk). Kernel crash dumps from the vsphere1 period: .123 x3
(2026-10-11 23:04, 10-12 04:04, 10:15), .124 x1 (10-11 16:36), .121/.122
none. `ubuntu22-dns-10.3.0.156` is the only VM left on vsphere1. The DNS VMs
.153 to .155 sit on vsphere2, the same non-ECC Lenovo model. Still to do:
MemTest86 on vsphere1.

### Symptom

RustDesk on centos9-124 (10.4.3.124) segfaulted about once a second from 08:54
to 10:05 CDT (5,134 core dumps), then the service itself segfaulted inside
`dlopen` relocation. centos9-123 logged a kernel oops at 06:29
(`vmap_pages_pud_range`, comm rustdesk).

### Hosts involved

All four test VMs (`centos9-docker-10.4.3.121` to `.124` in vcenter8) run on
**vsphere1.lab.local**: Lenovo 10RRS4TM00, Intel Core i7-8700T, 64 GB,
ESXi 7.0.3, last boot 2026-10-10 19:24 UTC. The i7-8700T does not support
ECC, so memory errors are neither corrected nor reported; every host hardware
sensor stays Green. Also on vsphere1: `ubuntu22-dns-10.3.0.155` and `.156`.
Datastores: .121 on `iscsi-disk-5.1`, .122 to .124 on `datastore-1.1`.

### Evidence, in order

1. `rpm -Va` digest mismatches: .123 = 14 files in 14 packages, .124 = 12
   files in 11 packages, .121 and .122 = 0. All four were updated in parallel
   on 2026-10-11 from the same repos; three damaged packages per VM date from
   the January install and were not rewritten.
2. After `drop_caches`, 13 of 14 (.123) and 8 of 12 (.124) verified clean: the
   damage was in the page cache, not on disk. The rest were shared libraries
   mapped by running processes (gnome-shell greeter, dbus, polkit, pipewire),
   so their pages could not be evicted.
3. `dd iflag=direct` (bypasses the page cache) read 6 of the 7 remaining files
   correctly from disk. The only on-disk damage is `dnf.mo` on .123, written
   during the update: the flip happened in RAM before writeback.
4. Byte compare against the good copies on .121: every damaged byte is a
   single-bit flip. 9 of 10 sit at byte 3 of a 64-bit word, at recurring page
   offsets 0x063 and 0xe63. Page offsets survive guest-to-host mapping, so
   this points at one DRAM chip or data line on one vsphere1 DIMM.
5. Still happening: a cold re-verify at about 11:00 CDT found two new damaged
   files on .123 (pipewire and wireplumber modules) that were clean at 10:20.
6. Not storage: .122 shares `datastore-1.1` and is clean; direct disk reads
   are correct. Not the guest kernel: .121/.122 run the same kernel and are
   clean. Not ballooning or host swap (both 0 MB on .123/.124).
7. A 6-minute in-guest zero-hold test (1.5 GiB each on .122/.123/.124) found
   no flips. It only exercises the host pages backing that buffer, so it does
   not clear the RAM.

### Next steps (Mike decides)

1. Move the six VMs off vsphere1, or shut them down.
2. MemTest86 on vsphere1 to identify the DIMM; reseat or replace it.
3. On healthy hardware: reboot .123/.124 (clears the bad page cache),
   reinstall `dnf` on .123 (the one damaged file on disk), re-run `rpm -Va`,
   restart RustDesk.
4. Check the DNS VMs on vsphere1 (10.3.0.155/.156) for damage.

---

## 2026-10-10: lm1 ping loss and duplicate replies after a cold start

**CLOSED 23:08 CDT.** Duplicates fixed on lm1, lm2 and lm3. Close-out check
(50 pings each): 10.5.0.11 to 10.5.0.16, 10.6.0.1, 10.7.0.1, 10.8.0.1 all 0%
loss, 0 duplicates; BGP to palo7/palo8 ESTABLISHED 4/4 on each of lm1, lm2,
lm3. The items under Open items are separate, pre-existing issues carried
forward; they are not part of this incident.

### Status (last checked 09:22 CDT, reconfirmed at close 23:08)

| Item | State |
|---|---|
| Duplicate ping replies through the edges | **Fixed on all three sites.** All six nested hosts (vsphere11 to 16) on `DPortGroup-Main-Trunk-NSX`; only the pfsense VMs remain on the old port group |
| T0 uplinks 10.5.0.11 to 10.5.0.16 (edge1 to edge6) | 100 pings each: 0% loss, 0 duplicates |
| T1 gateways 10.6.0.1, 10.7.0.1, 10.8.0.1 | 100 pings each: 0% loss, 0 duplicates |
| BGP T0 uplinks -> palo7 (10.5.0.7) / palo8 (10.5.0.8) | All 12 sessions ESTABLISHED (4 per site) |
| T0 / T1 HA (Manager API) | lm1, lm2, lm3 all ACTIVE/ACTIVE T0 and ACTIVE/STANDBY T1s |
| ax2001 10.6.0.101 and the other speedtest VMs | Powered off (did not autostart after the host reboot) |
| Edge-to-edge cross TEP tunnels | **Open**, 2 of 4 down on lm1 and lm2; lm3 (one TEP per edge) is fully UP |
| Inter-SR iBGP 169.254.0.130 <-> .131 | **Open**, stuck in CONNECT on lm1, lm2 **and lm3** |

### Symptom

After a full lab shutdown, Mike brought up nsx-lm1, vcenter1, vsphere11,
vsphere12 and a few workload VMs. Pings to ax2001 (10.6.0.101) dropped
intermittently, then completely. The first measurement showed 60 pings, 5%
loss and **+51 duplicates**: nearly every reply arrived twice.

### Data path (Mac to ax2001)

| Hop | Address | Device |
|---|---|---|
| 1 | 10.10.2.1 | Core router (Mac is 10.10.2.78) |
| 2 | 10.0.1.7 | palo7 ae1.6 (transit VLAN 6) |
| 3 | 10.5.0.11 | t0-gateway-1 uplink on edge1 (VLAN 500) |
| 4 | 100.64.40.1 | T1 router link |
| 5 | 10.6.0.101 | ax2001 on segment 10.6.0.0-24, host vsphere11 |

T0 t0-gateway-1 is ACTIVE_ACTIVE (uplinks 10.5.0.11 on edge1, 10.5.0.12 on
edge2). The three T1s are ACTIVE_STANDBY, active on edge1. edge1's routes to
0.0.0.0/0 and 10.10.0.0/16 point only at palo7 (10.5.0.7).

### Investigation, in order

1. **Loss pattern.** Single dropped pings plus a duplicate for almost every
   reply. Duplicates mean something copies frames; this is not DFW policy.
2. **Per hop.** 10.10.2.1, 10.0.1.7 and palo7's 10.5.0.7 were clean. Duplicates
   started at the T0 uplinks 10.5.0.11 and 10.5.0.12 (both edges) and
   continued to 10.6.0.1 and the VM. Edge management IPs were clean.
3. **HA split brain? Ruled out.** T0 is active/active by design, and each T1 was
   cleanly ACTIVE on edge1 / STANDBY on edge2.
4. **Tunnels.** Edge-to-edge BFD: straight pairs up (.103-.105, .104-.106),
   cross pairs down (.103-.106, .104-.105). Hosts reported 0 tunnels. Host TEPs
   come from a static pool (vsphere11 10.5.1.101, vsphere12 .102), so this is
   not a DHCP-at-boot problem.
5. **Mike rebooted ax2001.** Loss stopped (30/30), duplicates stayed (+28/30).
   A stale second inventory entry for ax2001 (same instance UUID, powered
   off) disappeared. Hosts still showed 0 tunnels while traffic flowed, so
   **host tunnel count 0 is not an outage signal in this lab** (an earlier
   reading of mine that it was turned out wrong).
6. **TTL test.** Original and duplicate replies had identical TTL (62 from the
   edge uplink, 60 from the VM), the duplicate ~0.15 ms later. No routing loop
   and no extra routed hop.
7. **Edge counter test.** 300 pings to 10.5.0.11 while reading t0-int1
   statistics: rx +778, tx +608. About 600 requests in, 600 replies out:
   **the edge receives every request twice** and answers both.
8. **Firewall counter test** (Mike's hypothesis: BGP to both active/active
   Palos). 600 pings to 10.5.0.11 while reading interface counters:

   | Firewall | ae1.500 out | ae1.500 in |
   |---|---|---|
   | palo7 | 625 (600 + background) | 1356 (about 2 x 600 + background) |
   | palo8 | 26 | 158 |

   palo7 sends each request once and palo8 is not in the path, so BGP and
   active/active HA are **ruled out**. The copy happens at layer 2 between
   palo7 and the edge.
9. **Placement.** edge1 runs on vsphere11, edge2 on vsphere12. Both edges have
   fp-eth0 and fp-eth1 on vcenter1 `DPortGroup-Trunk` (dvportgroup-1017). The
   nested DSwitch uses vmnic1 + vmnic2 as Uplink 1/2 (route based on
   originating port). vsphere11 and vsphere12 are VMs on physical host
   **vsphere4 in vcenter8**, with vmnic1 to vmnic4 on vcenter8
   `DPortGroup-Main-Trunk` (dvportgroup-33): **promiscuous Accept, MAC
   learning off.**

### Root cause

Promiscuous mode on the outer (vcenter8) trunk port group delivers every frame
to every nested vmnic on it. Each nested host received each frame on both of
its DSwitch uplinks and passed both copies to the edge, which processed and
answered each one. This is the standard nested-ESXi duplicate-packet problem.
It does not depend on boot order, so it likely predates the shutdown. The
loss earlier in the morning was a separate issue local to ax2001, cleared by
rebooting the VM.

### Change made (by Mike, in vcenter8)

New distributed port group on DSwitch-Main for the lm1 nested hosts, so
nothing else on the old port group is affected:

| Setting | `DPortGroup-Main-Trunk-NSX` (dvportgroup-6050) | Old `DPortGroup-Main-Trunk` |
|---|---|---|
| VLAN | Trunk 0-4094 | Trunk 0-4094 |
| MAC learning | **Enabled**, unknown unicast flooding allowed, limit 4096 | Disabled |
| Promiscuous mode | **Reject** | Accept |
| Forged transmits | **Accept** (required: nested hosts send with the VMs' MACs) | Accept |
| MAC address changes | Reject (either value works) | Accept |
| Teaming | Source port ID, Uplink 1 + Uplink 2 | Same |

Promiscuous mode is not needed for nested ESXi on vSphere 6.7 and later. MAC
learning replaces it, and forged transmits must stay Accept. Forged transmits
was first created as Reject and was corrected before any NIC moved.

Then all four trunk NICs (adapters 2 to 5) of vsphere11, then vsphere12, were
moved to the new port group.

**Verification (50 pings each):**

| Target | After vsphere11 moved | After vsphere12 moved |
|---|---|---|
| 10.5.0.11 (edge1, vsphere11) | 0 dup | 0 dup |
| 10.5.0.12 (edge2, vsphere12) | **+49 dup** (still on old port group, control) | 0 dup |
| 10.6.0.1 / 10.6.1.1 / 10.6.2.1 | 0 dup | 0 dup |
| 10.6.0.101 | 0 dup | 0 dup |

### Reboots after the fix

- **Edge reboot (about 08:33 CDT).** Uplinks answered again at 08:38 and BGP
  re-established. But from 08:38 until the host reboot at 08:45, the T1
  gateways (10.6.0.1) **never answered**. NSX showed both edges UNKNOWN and
  every gateway's HA state DOWN.
- **Host reboot (vsphere11 08:45:48, vsphere12 08:45:54).** Edges autostarted
  at 08:47:28 / 08:47:34 and reported to NSX at 08:50:40. By 08:51 uplinks
  and all three T1 gateways answered: 0% loss, 0 duplicates. The fix held
  through the reboot. Workload VMs did not autostart.

### lm2 (vsphere13 / vsphere14), from 08:54

Mike applied the same change to the lm2 hosts and rebooted them (both booted
08:54 CDT; edge uplinks answered 08:59). Checked at 08:59:

- vcenter8: **vsphere13** trunk NICs (adapters 2 to 5) are on
  `DPortGroup-Main-Trunk-NSX`. **vsphere14** trunk NICs are **still on the old
  promiscuous** `DPortGroup-Main-Trunk`. Both run on vsphere4.
- Placement (lm2): edge3 on vsphere13 (host-1022), owns uplink 10.5.0.13 and is
  ACTIVE for all three T1s. edge4 on vsphere14 (host-21), owns 10.5.0.14.
- Duplicates (50 pings): 10.5.0.13 **0**, 10.5.0.14 **+49**, 10.7.0.1 /
  10.7.1.1 / 10.7.2.1 **0**. Exactly what the root cause predicts: only the
  edge on the unmoved host duplicates. A second independent confirmation.
- t0-gateway-2 (ACTIVE_ACTIVE): BGP 10.5.0.13 and 10.5.0.14 to palo7 and palo8
  all ESTABLISHED; inter-SR iBGP 169.254.0.130 <-> .131 **CONNECT**, same as lm1.
- Edge TEPs: edge3 .155 / .156, edge4 .153 / .154; hosts vsphere14 .151,
  vsphere13 .152. Cross pairs (.153-.156, .154-.155) **DOWN**, straight pairs
  UP: the **same pattern as lm1**.
- **Recheck 09:10** (Mike asked after updating vsphere13/14): vcenter8 still
  shows vsphere14 adapters 2 to 5 on the **old** `DPortGroup-Main-Trunk`. The
  change did not land on vsphere14 (the two port group names differ only by the
  `-NSX` suffix). 10.5.0.14 degraded from duplicates only to **42% then 54%
  loss** with duplicates. edge3 side, BGP, tunnels and T1 HA unchanged.

### lm3 (vsphere15 / vsphere16), from 09:00

Mike updated vsphere15 and vsphere16 (only adapters 2 and 3 are trunks) and
powered them on (booted 09:00 CDT). Checked at 09:11:

- vcenter8: **vsphere15** adapters 2 and 3 on `DPortGroup-Main-Trunk-NSX`;
  **vsphere16** adapters 2 and 3 **still on the old** port group.
- Placement (lm3): edge5 on vsphere15 (host-13), edge6 on vsphere16 (host-18).
  T0 t0-gateway-3 ACTIVE_ACTIVE, uplinks 10.5.0.15 (edge5) and 10.5.0.16
  (edge6); the T0 interfaces are named `t1-int-1` / `t1-int-2`. All three T1s
  ACTIVE on edge5 (transport node 0c030669), STANDBY on edge6 (d4deb606).
- Duplicates (50 pings): 10.5.0.15, 10.5.0.16, 10.8.0.1, 10.8.1.1, 10.8.2.1
  all **0 duplicates, 0% loss**, including edge6 on the unmoved vsphere16.
  This fits the root cause: lm3's nested DSwitch has **one** uplink, so even a
  promiscuous outer port group delivers each frame only once. Moving vsphere16
  still stops it receiving every frame on the trunk.
- Edge tunnels: one TEP per edge (edge5 .173, edge6 .174), tunnel **UP**.
- BGP to palo7 and palo8 all ESTABLISHED; inter-SR iBGP **CONNECT**, even
  though the edge-to-edge tunnel is healthy.

### Final move and check (vsphere14 / vsphere16), 09:13 to 09:22

Mike redid the move on vsphere14 and vsphere16 and rebooted them:

| Host | Rebooted (CDT) | Edge VM booted |
|---|---|---|
| vsphere14 | 09:14:22 | edge4 09:15:47 |
| vsphere16 | 09:14:48 | edge6 09:16:42 |

- vcenter8 at 09:18: all six nested hosts' trunk NICs on
  `DPortGroup-Main-Trunk-NSX`. Old port group holds only pfsense-10.3.2.11 to .15.
- 09:18 (edges still booting): 10.5.0.14 100% and 10.5.0.16 98% loss; lm3
  showed edge6 BGP IDLE and HA DOWN. Expected mid-boot.
- 09:21: edge4 and edge6 management and uplinks answering.
- **09:22, 100 pings each:** 10.5.0.11, .12, .13, .14, .15, .16, 10.6.0.1,
  10.7.0.1, 10.8.0.1 all **0% loss, 0 duplicates**. All 12 BGP sessions to
  palo7/palo8 ESTABLISHED. T0s ACTIVE/ACTIVE, T1s ACTIVE/STANDBY on all three
  sites (lm2 T1s active on edge3, lm3 T1s active on edge5).
- The 42 to 54% loss on 10.5.0.14 at 09:10 (vsphere14 then the only 2-uplink
  host left on the promiscuous port group) went away with the move. The exact
  mechanism of that loss was not measured.

### Open items (carried forward)

| # | Item | Evidence | Next step |
|---|---|---|---|
| 1 | Cross edge TEP pairs down: lm1 .103-.106 / .104-.105, lm2 .153-.156 / .154-.155 | BFD DOWN, NO_DIAGNOSTIC; unchanged by the port group fix and by reboots; identical on lm1 and lm2. lm3 (one TEP per edge, one nested uplink) is UP, so it is tied to the two-TEP / two-uplink edge design | Read-only edge CLI on edge1/edge2: BFD sessions, tunnel ports, TEP-to-TEP ping |
| 2 | Inter-SR iBGP 169.254.0.130 <-> .131 stuck in CONNECT | lm1, lm2 and lm3. On lm3 the edge tunnel is fully UP, so this is **independent of item 1**; likely a config shared by all three T0s | Compare the T0 BGP inter-SR settings and gateway firewall across lm1/2/3; without it an edge that loses its uplinks cannot reroute via the other edge |
| 3 | After an edge-only reboot, T1 gateways did not recover within ~7 minutes | 10.6.0.1 unreachable 08:38 to 08:45 while uplinks and BGP were up | Repeat an edge-only reboot later and watch longer, or check edge datapath state |
| 4 | Manager API reports HA DOWN for the T0 and all T1s while traffic flows | `/api/v1/logical-routers/<id>/status` at 08:51 | Compare with the Policy API state; treat this field as unreliable until explained |
| 5 | ~~Nested hosts on the promiscuous port group~~ **Done 09:14** | All six on `DPortGroup-Main-Trunk-NSX`; 0 duplicates on all six uplinks at 09:22 | None. pfsense VMs stay on the old port group |
| 6 | DSwitch-Main MTU is 1500; nested DSwitch and edge uplink profile use 9000 | vcenter8 / vcenter1 switch config | Matters if Geneve traffic leaves vsphere4 or for large overlay packets; not tested |
| 7 | ax2001 and the other speedtest VMs are powered off | vcenter1 at 08:50 | Power on when needed |
| 8 | LAB_TOPOLOGY.md says the nested hosts' parent is not in vcenter1/2/3 | vsphere11/12 parent is vsphere4 in vcenter8 | Add the parent host to LAB_TOPOLOGY.md |

### Reference facts learned

- **palo7 / palo8:** PA-440, PAN-OS 11.2.7-h4, Active-Active HA (palo7
  active-primary, palo8 active-secondary), HA1 on ethernet1/7. Data on
  aggregate ae1 with VLAN subinterfaces: ae1.6 = 10.0.1.x transit to the core
  router 10.0.1.1, ae1.500 = 10.5.0.x NSX uplink VLAN. palo7 routes 10.6.x via
  10.5.0.11; palo8 routes 10.6.x via palo7 (10.0.1.7). Management 10.2.1.27 /
  10.2.1.28, lab login `username` / `password` from the aiforge-training `.env`.
- **Nested host parent:** vsphere11 and vsphere12 are VMs on vsphere4, managed
  by vcenter8 (`VCENTER_URL` in the aiforge-training `.env`). DSwitch-Main
  (vSphere 8.0, MTU 1500) spans vsphere3 to vsphere6 on vmnic2 + vmnic4.
- **Edge NIC MACs:** edge1 fp-eth0 00:50:56:81:9a:fc (uplink 10.5.0.11 and TEP
  .105), fp-eth1 00:50:56:81:e6:dc (TEP .106). edge2 fp-eth0
  00:50:56:81:8f:03 (uplink 10.5.0.12 and TEP .103), fp-eth1 00:50:56:81:8b:2f
  (TEP .104). Uplink and TEP share fp-eth0 on each edge.
- **Edge uplink profile** `load-balance-uplink`: TEP VLAN 510, MTU 9000,
  source port ID across uplink-1/uplink-2, named teamings failover-1 /
  failover-2. The VLAN 500 uplink segment uses the default teaming.

### How to re-run the checks (all read-only)

Duplicates and loss (look for `+N duplicates`):

```bash
ping -c 300 -i 0.1 -q 10.5.0.11
```

NSX edge tunnels, BGP and HA (credentials from this repo's `.env`):

```bash
U=$(grep '^NSX_USERNAME=' .env | cut -d= -f2-); P=$(grep '^NSX_PASSWORD=' .env | cut -d= -f2-)
g() { curl -sk -u "$U:$P" "https://nsx-lm1.lab.local$1"; }
g /api/v1/transport-nodes/864515b2-b16c-4827-9f05-cbb772142bcb/tunnels | jq -r '.tunnels[] | "\(.local_ip)->\(.remote_ip) \(.bfd.state)"'   # edge1
g /policy/api/v1/infra/tier-0s/t0-gateway-1/locale-services/default/bgp/neighbors/status | jq -r '.results[] | "\(.source_address)->\(.neighbor_address) \(.connection_state)"'
```

Edge uplink packet counters (compare before and after a ping burst):

```bash
EP=/infra/sites/default/enforcement-points/default/edge-clusters/3cdeba0e-368a-41a8-98bd-ab1108afb602/edge-nodes/1
g "/policy/api/v1/infra/tier-0s/t0-gateway-1/locale-services/default/interfaces/t0-int1/statistics?edge_path=$EP" | jq '.per_node_statistics[0] | {rx: .rx.total_packets, tx: .tx.total_packets}'
```

Palo interface counters: XML API op command
`<show><counter><interface>ae1.500</interface></counter></show>`, reading
`ifnet` `ipackets` / `opackets` before and after the burst.

vCenter port group settings: pyVmomi (install into a throwaway venv), read
`config.defaultPortConfig.macManagementPolicy` (promiscuous, forged
transmits, MAC learning) on the distributed port group.
