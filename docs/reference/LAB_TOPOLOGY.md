# Lab topology: three NSX Local Managers and the Palo Alto edge

Reference record of how the home lab is built, so a manager can be rebuilt or
a fourth one added the same way. Captured read-only on 2026-10-03 to
2026-10-06. Re-capture before relying on any number here (section 7).

DFW content (groups, rules) is not described here; see the run cards
([RUN_AC_LM2.md](../nsx/RUN_AC_LM2.md), [RUN_AC_LM3.md](../nsx/RUN_AC_LM3.md)).

---

## 1. Managers at a glance

All three run NSX 3.2.2 (build 20737185), licensed NSX Data Center
Enterprise Plus, each with its own vCenter 7.0.3. Each manager owns one /16
of workload space, numbered after the manager: lm1 = 10.6, lm2 = 10.7,
lm3 = 10.8, with VLAN ids following the same digit.

| | nsx-lm1 | nsx-lm2 | nsx-lm3 |
|---|---|---|---|
| Manager | 10.4.0.51 | 10.4.0.52 | 10.4.0.53 |
| vCenter | vcenter1 (10.2.2.111) | vcenter2 (10.2.2.112) | vcenter3 (10.2.2.113) |
| Hosts | vsphere11, vsphere12 (10.2.2.11/.12) | vsphere13, vsphere14 (10.2.2.13/.14) | vsphere15, vsphere16 (10.2.2.15/.16) |
| Clusters | nsx-cluster-1, nsx-cluster-2 | nsx-cluster-3, nsx-cluster-4 | nsx-cluster-5, nsx-cluster-6 |
| Host switch | VDS `DSwitch`, 2 uplinks | VDS `DSwitch`, 2 uplinks | VDS `DSwitch`, **1 uplink** |
| Edges (mgmt IP) | edge1, edge2 (10.2.2.51/.52), SMALL | edge3, edge4 (10.2.2.53/.54), MEDIUM | edge5, edge6 (10.2.2.55/.56), SMALL |
| Edge cluster | edge-cluster-1 | edge-cluster-2 | edge-cluster-3 |
| Tier-0 | t0-gateway-1, AS **65111** | t0-gateway-2, AS **65112** | t0-gateway-3, AS **65113** |
| T0 uplinks (VLAN 500) | 10.5.0.11, 10.5.0.12 | 10.5.0.13, 10.5.0.14 | 10.5.0.15, 10.5.0.16 |
| TEP pool (10.5.1.0/24, VLAN 510) | .101 to .200 | .151 to .200 | .171 to .200 |
| Workload segments (VLAN) | 10.6.0/1/2.0/24 (600/610/620) | 10.7.0/1/2.0/24 (700/710/720) | 10.8.0/1/2.0/24 (800/810/820) |
| T1 gateways | one per segment, gateway .1 | one per segment, gateway .1 | t1-gateway-10.8.0.0/1.0/2.0, gateway .1 |

Every host in the table is a **nested ESXi 7.0.3 VM** (32 GB RAM each; the
parent is not in vcenter1/2/3). vcenter3 also sees datastore
`iscsi-disk-6.1`, which vcenter1 uses too.

## 2. Shared networks

| Purpose | Subnet | VLAN | Notes |
|---|---|---|---|
| Management (vCenter, hosts, edges) | 10.2.2.0/24, gateway 10.2.2.1 | edge mgmt on port group `DPortGroup-60` | One subnet for all three managers' hosts and edges |
| NSX managers | 10.4.0.0/24 | | |
| T0 uplinks and BGP peering | 10.5.0.0/24 | 500 | All three T0s peer with **10.5.0.7 (AS 64007)** and **10.5.0.8 (AS 64008)**, see section 5 |
| Tunnel endpoints (TEPs) | 10.5.1.0/24, gateway 10.5.1.1 | 510 | One subnet shared by all three managers; each manager has its own range |
| DNS | 10.3.0.151, 10.3.0.152 | | Technitium; edit only on the primary dns-3-0 (10.3.0.150) |
| NTP | ntp1.lab.local, ntp2.lab.local | | Set on every edge; **not** set on vsphere15/16 |

Edges attach both data NICs (where they have two) to the trunk port group
`DPortGroup-Trunk`. Port group names are the same on all three vCenters.

## 3. Design pattern (same on all three)

- Hosts are prepared in **VDS mode** with custom transport zones `overlay-tz`
  and `vlan-tz` (the system defaults exist but are unused).
- **All workload segments are VLAN-backed** on `vlan-tz`. The gateway for each
  is a **T1 service interface** (for example 10.8.0.1/24 on segment
  `10.8.0.0-24`), and each T1 links to the manager's T0.
- T0s are **active/active**, eBGP to both Palo peers, ECMP on, inter-SR iBGP
  on, graceful restart helper-only, BFD off.
- Uplink profiles are `uplink-profile-failover` (hosts) and
  `load-balance-uplink` (edges on lm1/lm2), both with transport VLAN 510.

## 4. How lm3 was built (2026-10-03 to 2026-10-04)

Order used; lm2 was the template.

1. vcenter3 with vsphere15/16 in nsx-cluster-5/6, `DSwitch` with port groups
   `DPortGroup-60`, `DPortGroup-500`, `DPortGroup-Trunk`. vcenter3 registered
   in lm3 as compute manager.
2. `vtep-pool` (10.5.1.171 to .200), uplink profiles, `overlay-tz`, `vlan-tz`.
3. Host prep of vsphere15/16.
   **Gotcha:** vsphere15 first failed with `Failed to create ramdisk
   stagebootbank ... Cannot reserve 254 MB of memory for ramdisk`. That is
   host **memory**, not disk: vsphere15 had 8 GB (vsphere16 16 GB, which
   installed). Fixed by raising both nested hosts to 32 GB, then Resolve.
4. edge5/edge6 (DNS A records first), SMALL, single uplink, then
   edge-cluster-3.
5. Segment `10.5.0.0-24` (VLAN 500), t0-gateway-3 with uplinks
   10.5.0.15/.16 and BGP to 10.5.0.7/.8; Palo side configured for AS 65113.
6. Segments `10.8.0/1/2.0-24` (VLAN 800/810/820) and their T1s.
7. The two 10.8 VMs (ubuntu22-speedtest-10.8.0.101/.102) moved from vcenter1
   to vcenter3; lm1's 10.8.0.0 segment and T1 were deleted first so only lm3
   advertises 10.8.

Verified 2026-10-04: all transport nodes up, four eBGP sessions
ESTABLISHED (about 33 to 35 prefixes received, including 0.0.0.0/0), and
10.8.0.1, 10.8.0.101, 10.8.0.102 answering ping from the Mac running the
toolkit.

## 5. Palo Alto

**BGP peers for all three T0s:** 10.5.0.7 (AS 64007) on **palo7** and
10.5.0.8 (AS 64008) on **palo8**, both managed by Panorama **pano1**
(per Mike, 2026-10-06; the firewalls themselves not yet queried).

| Device | Role | Mgmt IP (DNS) |
|---|---|---|
| palo7 | BGP peer 10.5.0.7, AS 64007 | 10.2.1.27 |
| palo8 | BGP peer 10.5.0.8, AS 64008 | 10.2.1.28 |
| pano1 | Panorama for palo7/palo8 | 10.2.1.31 |

The other lab Panorama, `pano4` (10.2.4.31), manages three firewalls with no
interface on 10.5.0.x (read 2026-10-06 through pano4's XML API):

| Firewall | Serial | Mgmt IP | Model | PAN-OS |
|---|---|---|---|---|
| palo3 | 012801074066 | 10.2.1.23 | PA-220 | 10.2.11-h1 |
| palo5 | 012801200341 | 10.2.1.25 | PA-220 | 10.2.11-h1 |
| palo6 | 012801200332 | 10.2.1.26 | PA-220 | 10.2.11-h1 |

**Access path: undecided.** Two options are being weighed:

| Path | What exists in the toolkit today |
|---|---|
| Through Panorama (`pano1` for palo7/palo8) | `tools/pan/` lab tools authenticate to one Panorama, the `panorama` host in `.env`, which is `pano4` ([RUNBOOK_PAN_LAB.md](../pan/RUNBOOK_PAN_LAB.md)). `.env` labels `pano1` as `panorama_prod`, and that runbook keeps production Panorama out of the lab tooling. Using pano1 needs that decision made explicitly. Operational commands can be proxied to a managed firewall with the XML API `target=<serial>` parameter; that is how the pano4 table above was read |
| Directly to palo7 and palo8 | No toolkit client yet. Needs per-firewall credentials in `.env` and bypasses Panorama's device-group and template layering, so changes made this way drift from what pano1 pushes |

**Known routing behavior (same on all three T0s):** each T0 sends about 36
prefixes to 10.5.0.8 but 4 to 10.5.0.7, because it re-advertises routes
learned from AS 64007 to AS 64008. Every NSX T0 is therefore a possible
transit path between the two Palo routing instances. Not filtered today;
a route map on the T0s or a filter on the Palo would stop it if unwanted.

## 6. Known quirks

Only the TEP range overlap was explicitly decided (keep it, 2026-10-04). The
rest are recorded, with no decision taken.

| Quirk | Where | Impact |
|---|---|---|
| Inter-SR iBGP stuck in CONNECT | all three T0s | Edges share TEP VLAN 510 with hosts and sit on a plain VDS port group, so edge-to-host-on-the-same-host overlay fails. Harmless while every segment is VLAN-backed; would break overlay segments |
| TEP ranges overlap: lm1 .101-.200 contains lm2 .151-.200 contains lm3 .171-.200 | 10.5.1.0/24 | No collision today (lm1 uses .101-.106, lm2 .151-.156, lm3 .171-.174). Mike chose to keep it (2026-10-04). Non-disruptive fix if it ever bites: shrink lm1 to .101-.150 and lm2 to .151-.170 |
| vsphere15 uses `load-balance-uplink`, vsphere16 `uplink-profile-failover` | lm3 hosts | Identical behavior with one uplink. Matters only if a second uplink is added |
| vcenter3 `DSwitch` has one uplink | lm3 | No uplink redundancy for lm3 hosts or edges |
| No NTP on vsphere15/16 | lm3 hosts | Clocks were in sync when checked |

## 7. Re-inventory (read-only)

```bash
export PYTHONPATH="$PWD/app"
python tools/nsx/capture_fabric_state.py --source nsx-lm1
python tools/nsx/capture_fabric_state.py --source nsx-lm2
python tools/nsx/capture_fabric_state.py --source nsx-lm3
```

Each writes `nsx_fabric_capture/<host>/<UTC_TS>/` (gitignored): compute
managers, transport nodes, edge clusters, transport zones, uplink profiles,
IP pools, T0/T1 with interfaces, BGP and neighbors, segments, gateway
policies. GET only.

Not captured by it: BGP session state, TEP allocations, host RAM, vCenter
port groups. Read those with
`GET /policy/api/v1/infra/tier-0s/<t0>/locale-services/default/bgp/neighbors/status`,
`GET /api/v1/pools/ip-pools/<pool>/allocations`, and the vCenter API.

Backups of each manager's DFW state: `tools/nsx/backup_nsx_state.py`
([RUNBOOK_BACKUP.md](../nsx/RUNBOOK_BACKUP.md)).
