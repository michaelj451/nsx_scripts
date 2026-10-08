# Multivendor rollout: open questions

Questions that decide how NSX policy is carried onto the Palo Alto firewall
between the sites. Each one says why it matters, what the tooling does today
(the default if nobody answers), and how to find the answer. Started
2026-10-06. Settled answers move to the decisions table in
[STATUS.md](STATUS.md).

Today's behaviour is that of `tools/pan/nsx_pan_mirror.py plan-rules`
(mapping rules: `app/multisite/pan_rules.py`), last run on `nsx-lm1` against
pano4 `dg-5`, which stands in for the real firewall.

---

## Requirements: what we need access to

### Test environment

| Need | Why |
|---|---|
| **A test Panorama**, same PAN-OS major version as production (the lab runs 11.2, REST API `v11.2`), with a test device group and template stack | Every push is proven on the test Panorama first. Production is only touched after the same plan passed there |
| **A test Palo Alto firewall** (VM-Series is enough), managed by that Panorama, ideally in the path between two test NSX segments | The lab stand-in (pano4 `dg-5`) proves only the API calls and payloads. A managed firewall in the path also proves the commit, the push to the device, and that traffic actually flows through the mirrored rules |
| A source NSX manager the tooling can read (test copy or production read-only) | The rule plan is built from NSX's own rules, groups and services |

### Network and accounts

| Need | Detail |
|---|---|
| HTTPS (443) from the host running the toolkit | To each NSX manager and to Panorama. No access to the firewalls themselves is needed when Panorama is used |
| NSX account | Read-only (Auditor role) is enough for the Palo track. The NSX workflows that build the sibling groups (C, D) need their own write access, see their runbooks |
| Panorama account | A dedicated API account with a custom admin role, permissions below. The lab uses `agentuser` with `agent_role` |
| Certificates | Production should present trusted certificates. The lab uses `--no-tls-verify` because pano4 has the PAN-OS self-signed one |
| Existing profiles | The security profile group and log forwarding profile the rules should use must already exist on Panorama (question 8). The tool never creates them, and `push` stops if they are missing |

### NSX APIs (all GET, read-only)

| Endpoint | Used for |
|---|---|
| `/policy/api/v1/infra/domains/default/security-policies` | Policies (category, sequence) |
| `/policy/api/v1/infra/domains/default/security-policies/<id>/rules` | Rules |
| `/policy/api/v1/infra/domains/default/groups` | Group definitions |
| `/policy/api/v1/infra/services` | Service definitions |
| `/policy/api/v1/infra/context-profiles` | App-IDs used by rules (question 2) |
| `/api/v1/fabric/virtual-machines` | VM `hostname` tags, for address object names |
| `/api/v1/fabric/vifs` | VM IP addresses |

### Panorama APIs

| API | Endpoint | Methods | Role permission |
|---|---|---|---|
| XML | `/api/?type=keygen` | GET | Key generation only, once per run. **No other XML API access** (no `config`, `op`, `commit`, `export`) |
| REST | `/restapi/v11.2/Panorama/DeviceGroups` | GET | Panorama > Device Groups: read |
| REST | `/restapi/v11.2/Objects/Addresses` | GET, POST, DELETE | Objects > Addresses: read/write |
| REST | `/restapi/v11.2/Objects/AddressGroups` | GET, POST, DELETE | Objects > Address Groups: read/write |
| REST | `/restapi/v11.2/Objects/Services` | GET, POST, DELETE | Objects > Services: read/write |
| REST | `/restapi/v11.2/Objects/ServiceGroups` | GET, POST, DELETE | Objects > Service Groups: read/write |
| REST | `/restapi/v11.2/Policies/SecurityPreRules` | GET, POST, DELETE | Policies > Security Pre Rules: read/write |
| REST | `/restapi/v11.2/Policies/SecurityPostRules` | GET, POST, DELETE | Policies > Security Post Rules: read/write (only if post-rules are used) |
| REST | `/restapi/v11.2/Objects/SecurityProfileGroups` | GET | Objects > Security Profile Groups: read |
| REST | `/restapi/v11.2/Objects/LogForwardingProfiles` | GET | Objects > Log Forwarding: read |
| REST | the individual security profile types (`AntivirusSecurityProfiles` and so on) | GET | read, only if individual profiles are used instead of a group |

**Directly to a firewall** (no Panorama; tested on palo5, PAN-OS 10.2,
2026-10-07): the same login, the same resources with REST `v10.2` (a device
accepts its own REST version and older, never newer), objects and rules at
`location=vsys&vsys=vsys1` (`shared` is refused on a single-vsys firewall),
and the firewall's one local rulebase `/restapi/v10.2/Policies/SecurityRules`
instead of pre and post rules. The account needs the same read/write
permissions on the firewall itself. On a firewall that Panorama also manages,
local objects must not reuse names Panorama pushes; `push` checks and refuses.

Writes go to `location=shared` (objects) and `location=device-group`
(rules) on Panorama. A dry run issues only GETs. **Commits are never made through the
API**: the operator reviews the candidate config and commits in Panorama
(question 12).

---

## 1. Group naming on the Palo

**Why it matters.** Support staff will read the Palo rules long after the
migration. The names decide whether a Palo rule can be traced to its NSX rule
at a glance.

**Today.**
- One Palo address group per NSX group, named `<NSX group>_np_ips`, the same
  convention as the NSX sibling groups (suffix from `OBJECT_APPENDIX` in
  `.env`).
- The group holds that NSX group's addresses at **every** site: lm1 (current),
  lm2 and lm3 (mapped).
- Address objects keep their view in the name: `ax2001-10.6.0.101-np_ips`,
  `ax2001-10.7.0.101-avs_ips`, `ax2001-10.8.0.101-lm3_ips`.

**Still to confirm.**
- On lm2/lm3, the NSX group `network-group-0_np_ips` holds lm1's addresses
  only. The Palo group of the same name holds all three sites. Is that
  acceptable, given the group's description says so?
- IP-only NSX groups (`hardware-subnet`) get a Palo name, `hardware-subnet_np_ips`,
  that has no twin on NSX, because Workflow C never builds siblings for them.
  Keep, or use the bare NSX name for those?
- Should the address suffixes say where the address lives (`-lm1`, `-lm2`,
  `-lm3`) instead of which workflow built it (`-np_ips`, `-avs_ips`,
  `-lm3_ips`)?

## 2. How often is App-ID used on NSX?

**Why it matters.** The Palo rules are port-based wherever possible. An NSX
rule that also filters by application (a context profile with `APP_ID`, a
domain name or a URL category) is narrower than its ports. Carrying only the
ports would let every application through on them.

**Today.**
- Such rules are **skipped** and listed in the "App-ID review" section at
  the top of every `plan.md`, with the profile and its App-IDs.
- That section also lists:
  - ICMP rules, which have no port form on a Palo and so need the App-IDs
    `icmp`, `ping` and `ipv6-icmp`;
  - NSX ALG services (FTP, TFTP, Oracle TNS, RPC), which are mirrored as
    their ports;
  - services with no port form (IP protocol, IGMP, EtherType), which are left
    out.

**Measured so far.**
- `nsx-lm1`: 0 of 22 in-scope rules use a context profile.
- The manager has 64 context profiles, all system-defined, none custom.
- 6 Palo rules need ICMP App-IDs.

**To answer.** Run `plan-rules` against the production source manager and read
the App-ID review count. If it is not zero, decide per rule:
- keep skipping it;
- mirror the ports only (wider than NSX);
- or map the NSX App-ID to a Palo App-ID (needs a reviewed mapping table).

## 3. Do we match case?

**Why it matters.** NSX names are copied as they are (`HTTP`, `SSH`,
`DHCP-Client`, mixed-case group names). Many Palo shops keep a naming
standard, such as all lowercase. Changing case later renames objects that
rules already reference.

**Today.** Names keep NSX's case exactly. Characters Panorama does not allow
become `_`. Names over 63 characters are cut and given a hash suffix.

**To answer.**
- Keep NSX case, or apply a Palo naming standard (lowercase, a prefix)?
- Can two NSX names differ only by case? A case-folding standard would make
  them collide. The plan would report the clash as an error.

## 4. Which rules are needed between nsx-lm1 and nsx-lm2?

**Why it matters.** The Palo only sees traffic that crosses sites. Every rule
pushed there is one more to review and later retire.

**Today.** Every lm1 rule that uses a group with a sibling becomes a Palo rule
(22 of 29 on lm1, giving 24 Palo rules). That includes rules whose traffic may
never cross the firewall.

**To answer.**
- Which lm1 rules carry traffic that will cross to lm2 (and to lm3) while
  VMs move? Candidates: application tiers split across sites, shared services
  (DNS, syslog, management).
- Does lm2 to lm3 traffic cross the firewall too? This is open question 3 in
  STATUS.md, and decides whether step 6 and its Palo rules are needed.
- Is a filter list wanted? `--nsx-rule` already limits a plan to named NSX
  rules.

## 5. ICMP App-IDs

**Today.** `ICMP-ALL` becomes `icmp`, `ping` and `ipv6-icmp`; an echo service
becomes `ping`. `traceroute` is not included. Each comes with service
`application-default`.

**To answer.** Is this App-ID set right for the firewall team? Add
`traceroute`?

## 6. Zones

**Today.** Every rule is `any` to `any`. That is acceptable for the stand-in,
not for the real firewall.

**To answer.** The zone each site's subnets sit in on palo7/palo8, as a
subnet-to-zone list per firewall.

## 7. Rulebase and position

**Today.** Rules go to the bottom of the device group's pre-rulebase, in NSX
order (`--rulebase post` is available).

**To answer.**
- Pre or post?
- Above or below which existing rules? A migration allow placed under a broad
  deny never matches.

## 8. Security and logging profiles

**Today.** They come from `.env`:
- `PANORAMA_SECURITY_PROFILE_GROUP` (lab: `test-security-profile`) goes on
  allow rules.
- `PANORAMA_LOG_FORWARDING_PROFILE` (lab: `test-logging-profile`) goes on
  every rule.

**To answer.** The production names. Should some rules (DNS, management) get a
different profile?

## 9. Real target and access

**Today.** The lab stand-in is pano4 `dg-5`. The managers' real BGP peers are
palo7/palo8 under pano1 ([LAB_TOPOLOGY.md](../reference/LAB_TOPOLOGY.md)),
which the lab runbooks keep out of the tooling.

**To answer.**
- Through Panorama (pano1, which device group?) or directly to the firewalls?
- Which account, with which REST permissions? The lab's `agent_role` needed
  write on addresses, address groups, services, service groups, and pre- and
  post-rules.

## 10. Keeping the Palo current, and retiring it

**Today.** `push` creates only what is missing and never changes an existing
object. When a VM is added on NSX later, its Palo group does not gain the
address.

**To answer.**
- Build an additive "add missing members" push (baseline and revert, like the
  NSX union push)?
- How are the migration objects retired when the move ends? Remove the
  old-site address objects from the groups, then the rules?
- Mark every tool-made object with a tag (for example `nsx-migration`)?

## 11. NSX members the Palo cannot match

**Today.** Segment-based groups (`seed-seg-10-6-1`) and tag groups that are
empty on the source manager (`seed-tag-net-10-8-0`, whose VMs moved to lm3)
are left out. A rule with nothing left on one side is skipped: 2 rules on
lm1.

**To answer.**
- Resolve a segment to its subnet (a CIDR address object)?
- Read an empty tag group's members from the site its VMs moved to?

## 12. Return traffic and asymmetric paths

**Why it matters.** The Palo, like the NSX DFW, is stateful. A rule allowing
source to destination also passes that session's replies, and a connection
opened from the other side needs its own rule, exactly as on NSX. That only
holds if a session's packets in both directions cross the **same** firewall.

**Today.**
- Rules mirror NSX's direction: source may open to destination. Replies need
  no rule.
- Every lm1 rule is `IN_OUT`.
- In the lab path, each T0 runs ECMP over eBGP to two separate firewalls,
  palo7 (AS 64007) and palo8 (AS 64008)
  ([LAB_TOPOLOGY.md](../reference/LAB_TOPOLOGY.md) section 5). A session
  whose forward path is palo7 and whose return path is palo8 is dropped by
  palo8, whatever the rules say.

**To answer.**
- Are palo7 and palo8 an HA pair with session synchronisation
  (active/active)?
- If not, will routing keep both directions of a flow on one firewall (BGP
  preference, no ECMP across them)?
- The test firewall (Requirements) should reproduce the production
  arrangement so this is tested before cutover.

## 13. Moving a VM: tags, addresses, existing firewall rules, NAT

Found while planning the test migration
([TEST_MIGRATION_PLAN.md](TEST_MIGRATION_PLAN.md)).

- **Tags.** NSX tags stay on the NSX manager. A VM moved to lm3 arrives
  untagged, so lm3's tag groups do not match it and lm3's default rule (DROP)
  applies. Who copies its tags to lm3, and when: a tool step at move time, or
  pre-tagging on lm3?
- **Addresses.** The maps assume a moved VM keeps its host number (10.6.1.102
  becomes 10.8.1.102). Is that the real re-addressing rule? Today 10.8.0.101
  and 10.8.0.102 are taken by lm3 placeholder VMs, so mapped addresses can
  already collide.
- **Existing firewall rules.** The mirrored rules are appended at the bottom of
  the pre-rulebase. Is there a rule above them, in shared or the device group,
  that would match cross-site traffic first (a site-to-site deny or a broad
  allow)?
- **NAT.** Is any traffic between the sites translated? The mirrored rules
  match the real addresses.

## 14. Commit and change control

**Today.** Nothing commits; every push stays in candidate config, and the
operator commits in Panorama.

**To answer.** Who commits, in which window? Partial commit by admin, so other
pending changes are not swept in? What evidence does the CAB need? Every push
and revert writes a markdown report beside its manifest.
