# Test migration plan: one VM from nsx-lm1 to nsx-lm3, through the Palo Alto

**Planning only (2026-10-06). Nothing here has been run.** Open choices are
marked **Choice** and collected at the end. Related questions:
[QUESTIONS.md](QUESTIONS.md). Status: [STATUS.md](STATUS.md).

## Goal

If nsx-lm1's groups and policies allow two machines to talk today, they must
still talk after one of them moves to nsx-lm3. Flows lm1 blocked must stay
blocked.

A flow between a VM left on lm1 and a VM moved to lm3 is checked in three
places. All three must agree.

| Enforcement point | What lets the flow through after the move | Built by |
|---|---|---|
| **lm1 DFW** (the VM that stayed) | The lm1 rule names the moved VM's new address: `<group>_lm3_ips` on lm1 | Rollout step 5 (`d2a` siblings, `d3` rule references) |
| **Palo Alto in the middle** | A Palo rule `<group>_np_ips` to `<group>_np_ips`, groups holding every site's addresses, and **it is the first rule that matches** in the whole rulebase | Palo track P3 (`nsx_pan_mirror.py plan-rules` / `push`), then commit and push to the firewalls |
| **lm3 DFW** (the moved VM) | The lm3 rule names the lm1 VM's address (`<group>_np_ips` on lm3), **and the moved VM is a member of its own group on lm3** | Rollout steps 2-3 (Workflows A and C onto lm3), plus copying the VM's NSX tags to lm3 (not built) |

NSX tags are stored by the NSX manager, not carried by the VM. A VM arriving
on lm3 has none of the tags lm1's tag groups matched on, and lm3's default
Layer 3 rule is DROP. Without the tag copy, lm3 drops the traffic at the moved
VM's own vNIC.

## Lab facts that shape the test (read 2026-10-06)

- On lm1 only `ax2001` (10.6.0.101) is powered on and reporting an IP.
  `0e02` (10.6.0.102) is on, but reports no IP. The other six are off.
- The lm3 map turns 10.6.x.y into 10.8.x.y. Two mapped addresses belong to
  lm3 placeholder VMs that are **running**: 10.8.0.101 and 10.8.0.102.
  The 10.8.1.x and 10.8.2.x placeholders are powered off.
- An NSX rule that covers a natural test pair: `allow-icmp-network-0`
  (network-group-0 to network-group-0, ICMP). network-group-0 holds
  10.6.0.101 and 10.6.1.102.
- pano4 `dg-5` is a stand-in and is not in the path. The managers' real BGP
  peers are palo7 and palo8 under pano1, on two separate firewalls with ECMP
  from every T0 ([LAB_TOPOLOGY.md](../reference/LAB_TOPOLOGY.md)).

## Phases

| Phase | Steps | Who | Changes |
|---|---|---|---|
| 0. Baseline | Choose the pair and flows: allowed flows both ways (for example ping), one flow lm1 blocks, and one flow from outside the sites if a rule covers it (`hardware-subnet`). Record the results. Back up lm1 and lm3 (`backup_nsx_state.py`). Export the Panorama config | read-only | none |
| 1. Prepare | Step 5 on lm1, dry run then apply (`d2a`, later `d3`). Update lm3 from lm1 (RUN_AC_LM3 part 2: A then C). Palo: `plan-rules`, review the App-ID review section, `push`, read back, **commit and push to the in-path firewall**. Plan the tag copy for the moving VM | dry runs by tooling; applies and commit by the operator | lm1, lm3, Panorama |
| 2. Move | Migrate the VM from vcenter1 to vcenter3, attach it to the matching lm3 segment, change its address per the map (10.6.x.y to 10.8.x.y, gateway 10.8.x.1) | operator, vCenter and guest OS | the VM |
| 3. Tag | Copy the VM's NSX tags from lm1 to lm3, dry run then apply, with a paired revert | tooling (new step) | lm3 VM tags |
| 4. Test | Repeat every baseline flow both ways. Read the lm1 and lm3 DFW rule hit counts (`report_rules_usage.py`). Read the Palo traffic log for the deciding rule (`PanRestClient.query_logs`, toolkit `/traffic-logs` page) | read-only | none |
| 5. Roll back | Move the VM back and restore its address. Revert in reverse order: tag copy, Palo push (`revert --manifest`) and commit, lm3 update, step 5 (`d3`, then `d2a`). Compare with the phase 0 backups | operator and tooling | all of the above |

## Pass criteria

1. Every flow allowed in phase 0 works after the move, in its NSX direction.
   Replies work too, since all three layers are stateful.
2. The phase 0 blocked flow is still blocked.
3. On the Palo, the deciding rule for each moved flow is one of the mirrored
   rules, not a broader existing rule and not the default.
4. The lm1 and lm3 hit counts move on the expected rules.
5. After phase 5, lm1, lm3 and Panorama match their phase 0 backups.

## What the test is designed to catch

- The missing tag copy (lm3 drops at the moved VM).
- Step 5 not applied (lm1 drops at the VM that stayed).
- An existing Palo rule above the mirrored ones (shadowing), or traffic
  falling to the interzone default deny.
- Asymmetric paths: forward through palo7 and return through palo8, so one
  firewall sees half a session (QUESTIONS.md question 12).
- A wrong address assumption: the VM must really get 10.8.x.y with the same
  host number, and nothing else may already hold that address.

## Choices to make before running it

| Choice | Options | Notes |
|---|---|---|
| **Which VM moves** | `0102` (10.6.1.102 to 10.8.1.102); `ax2001` (10.6.0.101 to 10.8.0.101); a new clone | `0102`'s lm3 address belongs to a powered-off placeholder, which must stay off or be deleted. `ax2001`'s belongs to a running placeholder, which must be shut down first. A clone avoids both, but needs tags to join any group |
| **Which firewall enforces it** | pano1 with palo7/palo8 (in the path); pano4 `dg-5` (stand-in) | Only the in-path firewalls prove traffic. Using pano1 with the tooling needs an explicit decision and an API account there; the lab runbooks keep production Panorama out today |
| **Address after the move** | Re-address per the map; keep the address | The design assumes re-addressing. Keeping the address would need a stretched layer 2 segment, which this design does not cover |
| **Tag copy** | Build a tag-copy step (lm1 to lm3, with revert); tag by hand in the lm3 UI for the test | The tool is the repeatable path for real migrations |
| **Second target** | lm3 only; also lm2 | Same plan with step 4 and `_avs_ips`. Whether lm2 to lm3 traffic crosses the firewall is still open |
| **Simulation first** | Build the read-only move simulation (each flow checked against lm1, the Palo rulebase with its existing rules, and lm3); skip it | Predicts phase 4 from configuration alone, so failures can be fixed before anything moves |
