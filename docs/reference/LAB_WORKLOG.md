# Lab work log

Dated record of lab troubleshooting and infrastructure changes: what was seen,
how it was measured, what changed, and what is still open. Newest entry first.
Static lab layout lives in [LAB_TOPOLOGY.md](LAB_TOPOLOGY.md).

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
