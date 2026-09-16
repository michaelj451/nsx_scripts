# NSX Migration Toolkit — Known Gaps & Manual-Intervention Items

A complement to [NSX_TOOLKIT_SUMMARY.md](NSX_TOOLKIT_SUMMARY.md). This file
catalogues the cases where a migration **will not be fully automatic** —
where the operator either has to act before the cutover, accept a known
limitation, or rebuild something by hand on the target after the toolkit
runs.

Last reviewed: 2026-05-25 against the broken-out per-tool scripts
(services, groups, policies, rules, segments, membership + capture orchestrator).

---

## How to use this document

1. **Before** a migration, walk Section 4 (Pre-flight checklist) against the
   source manager to catch any of these patterns in the export bundle.
2. **During** the push, watch the per-tool `errors_log` and forensic JSON
   reports for traces of these gaps.
3. **After** the push, work the Section 3 list against the target — anything
   that lands "structurally" but with broken references needs to be reconnected.
4. Section 5 is the "what we'd build next" roadmap if you want to close any
   of these gaps in code instead of operationally.

---

## 1. What the toolkit handles automatically today

For reference — these scenarios used to bite migrations and no longer do:

| Pattern | Handler | Where |
|---|---|---|
| Special-character object IDs (`(`, `)`, ` `, `,`, etc.) | URL-encoding (`urllib.parse.quote`) on every path interpolation | `NsxPolicyClient._q()` |
| Object filenames longer than Windows MAX_PATH 260 | Deterministic `<first5>-<last5>-<8hex>.yaml` form | `utilities/file_utilities.short_id_filename()` |
| Nested service / nested group dependency 404s | Silent trap (no traceback dump) + bounded retry loop (5 rounds) | All 5 push tools |
| Segment paths in groups | `--segments-mode strip` or `convert` (lookup to CIDRs) | `groups.py push` |
| VM IPs that would re-resolve to different VMs on the target | Frozen at capture into `groups_additive/`; never re-fetched at push | `capture_nsx_state.py` |
| Host-TN / edge-TN / TZ / edge-cluster paths in groups | Auto-stripped; logged to `fabric_paths_stripped.json` | `groups.py push` (`FABRIC_PATH_RE` + `_strip_fabric_paths_in_expression`) |
| "Already exists" on PUT | Automatic PUT → PATCH fallback | All push tools |
| Multi-phase clone reversibility | Per-tool LIFO baseline stack | All push tools |

---

## 2. HIGH-severity gaps — common in customer envs, will silently break or land wrong

### 2.0 Group IP resolution: ask NSX, do not reconstruct it (FIXED 2026-09-08)

**The most expensive mistake we have made in this toolkit.** Recorded here in
full because the failure is silent, the output looks plausible, and nothing in
any report flags it.

NSX answers "what IPs does this group resolve to?" directly:

```
GET /policy/api/v1/infra/domains/<domain>/groups/<group>/members/ip-addresses
```

That is exactly what the UI's **Effective Members > IP Addresses** tab renders.
The toolkit used to reconstruct the answer instead, from evaluated VM member
IDs looked up in a fabric VIF index. The reconstruction sees only **running
VMs' VIF IPs**, and therefore silently drops:

| Dropped by the reconstruction | Example on nsx-lm1 |
|---|---|
| Static `IPAddressExpression` entries | `hardware-subnet` to `10.2.1.0/24` |
| IP ranges | `ip-address-group` to `10.6.0.52-10.6.0.60` |
| Segment-derived subnets | `segment-group-1` to 4 subnets |
| Nested-group contributions | `super-nested-group` to 5 IPs, not 2 |
| Stopped VMs' last-known bindings | `network-2` to 2 IPs, not 0 |

**Measured 2026-09-08 on nsx-lm1: 10 of 12 groups resolved to MORE IPs via the
endpoint than the reconstruction found.** Only `network-6-1` and `vm2` agreed.

Real-world impact, same day: a Workflow C run against lm3 produced **1 sibling
group holding 2 IPs**. After the fix it produced **6 siblings holding 17 IPs**,
every one matching NSX exactly. `network-2` had been dropped entirely and was
miscounted as `skipped_empty_ips`, which reads like "this group has no IPs"
rather than "we failed to find them".

**The fix.** `NsxPolicyClient.get_group_effective_ips()` wraps the endpoint.
`build_group_ip_additive_from_live_members.py --ip-source effective` is now the
DEFAULT, and `capture_nsx_state.py --live-query` forwards it. The summary JSON
records `"ip_source"` so any bundle can be audited after the fact.

**Rules to keep:**

1. **Never reconstruct what the manager will tell you.** If the UI shows a
   number, find the endpoint behind it before deriving your own.
2. `--ip-source vm-vif` reproduces the old behaviour. It exists only to
   regenerate a pre-2026-09-08 bundle. Do not use it for a migration.
3. A stopped VM's binding is NSX's **last known** value and can be stale. On
   lm1, `network-2`'s members are the VMs named `10.6.2.101/102` while NSX
   reports `10.6.1.101/102`, consistent with a clone that was never powered on
   afterwards. Reconcile stopped-VM addresses against vCenter before cutover.
4. Bundles captured before 2026-09-08, or with `"ip_source"` absent from the
   summary, are a **lower bound**. Re-capture rather than trusting them.

Verify any bundle against the manager:

```bash
python - <<'PY'
import sys, logging; sys.path.insert(0, "app"); logging.disable(logging.INFO)
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_constants import resolve_manager
c = NsxPolicyClient(nsxmanager=resolve_manager("nsx-lm1"), federation_global=False)
idx = c.build_vm_ip_index()
for g in c.list_groups(domain_id="default"):
    if g.get("_system_owned"): continue
    old = sorted(c.get_group_member_ips(group_id=g["id"], vm_ip_index=idx))
    new = sorted(c.get_group_effective_ips(g["id"]))
    if old != new:
        print(f"{g['id']}\n   reconstructed: {old}\n   NSX says     : {new}")
PY
```

See [RUNBOOK_AVS.md](../nsx/RUNBOOK_AVS.md) for the workflow this was found in.

### 2.0b A dry run is offline, so it cannot tell you the IP delta (FIXED 2026-09-09)

`groups.py push` without `--apply` never opens a session to the target. That
makes a dry run fast and safe, and it also makes it **blind**: with no target
state to diff against, every row is reported with no `ips_added` /
`ips_removed` at all, and the summary's `total_ips_removed` is `0` no matter
what the apply would do.

That is worst exactly where it matters most. The decomposition workflow's
destructive step (`--intentional-ip-removal`, pushing the stripped originals)
is gated on an operator approving a removal count, and the preview showed zero.

Measured on the same bundle and target, 2026-09-09:

| Dry run mode | `total_ips_removed` | Apply actually removed |
|---|---|---|
| offline (default) | 0 | 2 |
| `--diff-target` | **2** | 2 |

**The fix.** `groups.py push --diff-target` makes one read-only pass over the
target, populates `ips_before` / `ips_after` / `ips_added` / `ips_removed` on
every dry-run row, makes the summary total truthful, and logs
`WOULD REMOVE n IP(s) on apply` for any group that would lose IPs without
`--intentional-ip-removal`. It is opt-in, so a plain dry run stays fully
offline and no existing behaviour changes. Ignored with `--apply`, which
always captures a baseline and diffs against it.

**Rules to keep:**

1. Pass `--diff-target` on every group dry run you intend to approve from.
   Without it the preview is structural only: which objects get touched, not
   what changes inside them.
2. When the baseline is absent the IP fields are **omitted, not zeroed**. An
   empty baseline would make every IP look newly added, which is worse than
   silence. Absent fields mean "not measured", not "no change".
3. A dry run reports, it does not decide: `--diff-target` warns about a
   would-be contract violation but does not fail the row.

**Related trap: the dry run and the apply overwrite each other's report.**
Both write `<bundle>/push_report/<class>.json`. Run `report_avs_run.py` after
each pass into separate `--out-dir`s; the aggregated report is the only durable
record. Baselines under `push_report/baselines/` are unaffected, so revert is
never at risk.

See [RUNBOOK_AVS.md](../nsx/RUNBOOK_AVS.md) Phase 4.

### 2.0c Group-to-group references produce NO sibling and vanish on the target

A group whose membership comes only from a `PathExpression` pointing at another
**group** (not a segment) is dropped by `build_sibling_groups.py`. It has no
`Condition`, so it is counted in `skipped_no_condition`; it has no
`IPAddressExpression`, so it does not reach the `pure_ip_remap` bundle either.
It appears in no output bundle at all.

On the source that group resolves correctly, and transitively:

| Test group (lm1, 2026-09-09) | Expression | NSX resolves to | Sibling built |
|---|---|---|---|
| `nestvar-grp-ref-tag` | PathExpression -> group `vm1` | 3 IPs | **none** |
| `nestvar-grp-ref-ip` | PathExpression -> group `ip-address-group` | 6 IPs (incl. a range and 2 CIDRs) | **none** |
| `nestvar-grp-ref-chain` | PathExpression -> `grp-ref-tag` -> `vm1` | 3 IPs | **none** |

Group nesting is transitive: the 3-level chain returned exactly `vm1`'s IPs.

**Why it matters for AVS.** The parent inherits its IPs from the child's *tag*
evaluation. On a target with no matching VM inventory or tags, the child
resolves to nothing, so the parent resolves to nothing, and every rule using
the parent silently stops matching. Nothing errors, and no report flags it,
because from the tool's point of view there was never anything to decompose.

**A group-ref alongside a Condition is fine.** `nestvar-nest-mixed-all`
(NestedExpression + PathExpression to a group + static IPs) got a sibling with
all 9 IPs, because the Condition made it eligible and the sibling is built from
NSX's effective IP list, which already includes the referenced group's
contribution.

**How to apply:** before Phase 3, list any group whose expression is
PathExpression-only and whose paths point at `/groups/`. Either give it a
sibling by hand from `get_group_effective_ips()`, or flatten it into the
referencing rules. Detect them with:

```bash
python - <<'PY'
import sys, os, logging; sys.path.insert(0, "app"); logging.disable(logging.INFO)
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_constants import resolve_manager
c = NsxPolicyClient(nsxmanager=resolve_manager(os.environ.get("SRC","nsx-lm1")),
                    federation_global=False)
for g in c.list_groups(domain_id="default"):
    if g.get("_system_owned"): continue
    ex = g.get("expression") or []
    kinds = {e.get("resource_type") for e in ex}
    paths = [p for e in ex for p in (e.get("paths") or []) if "/groups/" in p]
    if paths and "Condition" not in kinds and "NestedExpression" not in kinds:
        print(f"{g['id']}: group-ref only -> {paths}")
        print(f"   resolves to {len(c.get_group_effective_ips(g['id']))} IPs, sibling will NOT be built")
PY
```

### 2.0d Stale realized port bindings contaminate every effective IP list

NSX group membership counts a segment port's **realized** address bindings, not
only its **discovered** ones. A manual or leftover `address_bindings` entry
therefore attaches an address to every group that port's VM belongs to, and
`get_group_effective_ips()` faithfully reports it.

Measured on nsx-lm1 2026-09-09: **5 of 6 VM ports carried realized-only
bindings**, and one stray address, `10.6.1.102`, appeared in **14 groups**.

```
port ubuntu22-speedtest-10.6.0.101-ax2001
  discovered: 10.6.0.101   <- real, matches the VIF
  realized:   10.6.1.102   <- stale, wrong address on the same MAC
  realized:   10.6.0.101
```

That single stale binding made a group whose only member VM is `10.6.0.101`
resolve to `['10.6.0.101', '10.6.1.102']`. It also explains why `network-2`,
whose members are the stopped `10.6.2.x` VMs, reports `10.6.1.101/102`: those
ports have realized-only bindings and no discovered ones at all.

**This is environment data, not a tool defect**, and the effective-IP endpoint
is still the right source (it is what the firewall enforces). But every stale
binding is copied verbatim into a sibling and shipped to the target, where it
becomes a permanent literal IP rather than something that self-corrects when
the VM is fixed.

**How to apply:** audit ports before Phase 3 and clear stale bindings, or
accept them knowingly. Any port whose realized set exceeds its discovered set
is suspect:

```bash
python - <<'PY'
import sys, os, logging; sys.path.insert(0, "app"); logging.disable(logging.INFO)
from nsx.nsx_policy_client import NsxPolicyClient
from nsx.nsx_constants import resolve_manager
c = NsxPolicyClient(nsxmanager=resolve_manager(os.environ.get("SRC","nsx-lm1")),
                    federation_global=False)
for seg in c._get_all_results("/policy/api/v1/infra/segments"):
    for p in c._get_all_results(f"/policy/api/v1/infra/segments/{seg['id']}/ports"):
        st = c._get(f"/policy/api/v1/infra/segments/{seg['id']}/ports/{p['id']}/state")
        d = {b.get("binding",{}).get("ip_address") for b in (st.get("discovered_bindings") or [])}
        r = {b.get("binding",{}).get("ip_address") for b in (st.get("realized_bindings") or [])}
        stale = {x for x in r - d if x}
        if stale:
            print(f"STALE {p.get('display_name')}: discovered={sorted(x for x in d if x)} "
                  f"realized-only={sorted(stale)}")
PY
```

### 2.1 `applied_to` (a.k.a. `scope`) in rules — ONLY the gateway-targeted case

**Important:** This is **not** a gap when `applied_to` references **groups**.
That's the safe, common case — and it's directly validated in the lab. The
toolkit pushes groups before rules, the group IDs are byte-identical
between source and target, and every `applied_to: ['/infra/domains/default/groups/<g>']`
entry resolves on the target without any operator intervention.

The **only** problematic sub-case is when `applied_to` references something
the migration does not create on the target:

| `applied_to` content | Status |
|---|---|
| `ANY` sentinel | ✅ Safe |
| `/infra/domains/default/groups/<g>` (a group) | ✅ Safe — directly tested |
| `/infra/services/<s>` (a service) | ✅ Safe — also tested |
| `/infra/tier-0s/<t0>` | ❌ **Gateway UUID differs on target** |
| `/infra/tier-1s/<t1>` | ❌ Same |
| `/infra/tier-0s/<t0>/vrfs/<vrf>` | ❌ Same (VRF gateway) |
| `/infra/sites/.../host-transport-nodes/<id>` | ❌ Fabric-bound |

**Symptom (gateway case only):** Rule push 404s with
`/infra/tier-0s/t0-prod-edge could not be found`.

**Why:** Gateway UUIDs are environment-specific. The toolkit does not
migrate Tier-0 / Tier-1 gateways — they're fabric/edge resources, not
firewall policy.

**Risk surface:** Envs that use gateway-scoped DFW enforcement (rare in
modern designs — the recommended pattern is group-scoped `applied_to`,
which the toolkit handles natively).

**Current behavior (gateway case):** Push fails. Retry loop won't help
(the dep isn't something the migration creates).

**Manual fix (gateway case):** Operator must edit the affected rules either
before push (in the export YAML) or after (in NSX UI) to either drop the
applied_to or substitute the target's gateway path.

**Detection today:** `failures.json` in the push_report will show every
affected rule, but only after the push runs.

**How to know before the migration whether you're affected:**

```bash
setopt interactive_comments 2>/dev/null || true

# Returns every distinct PATH PREFIX used in any rule's applied_to / scope field
grep -h "^- /infra" nsx_rules_export/<host>/security-policies/*/rules/*.yaml \
  | grep -oE "/infra/(domains/default/groups|tier-[01]s|sites|services|context-profiles|time-ranges)" \
  | sort | uniq -c

# If you only see "/infra/domains/default/groups" and "/infra/services" → zero gap.
# If you see "/infra/tier-0s" or "/infra/tier-1s" → you have rules that will need attention.
```

### 2.2 `profiles` in rules referencing context / L7 / FQDN profiles

**Symptom:** Rule push 404s with `/infra/context-profiles/<name> could not be found`.

**Why:** Context profiles (also called L7 access profiles, FQDN attributes,
app identifiers) are first-class NSX objects we don't export. Rules can
reference them in the `profiles` field.

**Risk surface:** Any env using application-aware DFW (Layer 7), FQDN
whitelisting, or domain-name-based rules. Increasingly common.

**Current behavior:** Push fails.

**Manual fix:** Export context profiles separately from lm1 (NSX UI or
`/policy/api/v1/infra/context-profiles/...`), push to lm2, then re-push rules.

**Detection today:** Same as above — surfaces in `failures.json`.

### 2.3 TimeWindow / time-range references in rules

**Symptom:** Rule push 404s with `/infra/time-ranges/maintenance-window
could not be found`.

**Why:** Time ranges (e.g. "business hours", "maintenance window") are
referenced by rules via `time_ranges`. We don't export them.

**Risk surface:** Envs using scheduled-enforcement rules.

**Current behavior:** Push fails.

**Manual fix:** Recreate time ranges on lm2 before push.

### 2.4 Distributed Firewall exclusion list

**Symptom:** **None at push time — no error.** But after migration, lm2 starts
enforcing DFW on VMs that lm1 was exempting (vCenter VMs, NSX managers,
edges, jump hosts, backup proxies).

**Why:** The exclusion list lives at a different endpoint
(`/policy/api/v1/infra/settings/firewall/security/exclude-list`). It's a
single flat document, not per-object. We don't export it.

**Risk surface:** **High blast radius.** Most prod envs have at least
infrastructure VMs in the exclusion list. Forgetting this is a recipe for
"DFW broke my vCenter" on cutover.

**Current behavior:** Silently missing on target.

**Manual fix:** Before cutover, manually copy the exclusion list contents
from lm1 → lm2.

**Detection today:** None — invisible to the toolkit. Operator has to know
to check.

---

## 3. MEDIUM-severity gaps — common in some envs

### 3.1 Identity-based groups (AD / LDAP)

**Symptom:** Group push succeeds. Group lands empty (no matching members)
because lm2 doesn't have AD bound.

**Why:** Groups with `IdentityGroupExpression` evaluate against the NSX
manager's Directory Service config (AD bind). The group definition clones
fine; the membership evaluation requires the same AD setup on lm2.

**Risk surface:** Envs using user-identity DFW (VDI, jump hosts, app-tier-by-role).

**Current behavior:** Group lands but is functionally inert.

**Manual fix:** Configure Directory Service on lm2 (same domain, same OU
mapping). Group membership re-evaluates automatically.

### 3.2 Distributed IDS rules

**Symptom:** IDS rules don't appear on lm2.

**Why:** They live at `/policy/api/v1/infra/domains/<d>/intrusion-service-rules/`
— a separate API surface from regular DFW rules. We don't export them.

**Risk surface:** Envs with IDS/IPS enabled and customer-tuned signature
selection.

**Current behavior:** Silently not migrated.

### 3.3 Compute-manager / vCenter-cluster references in groups

**Symptom:** Group push 400s with `is invalid` on a path like
`/infra/sites/default/enforcement-points/default/compute-collections/<vcenter-uuid>`.

**Why:** Compute collections (vCenter clusters, resource pools) appear in
NSX as fabric-attached objects with their own UUIDs. Different on each
manager even when both point at the same vCenter.

**Risk surface:** Envs that scope groups to "all VMs in cluster X" via
membership criteria.

**Current behavior:** Push fails. **Our fabric-path strip regex doesn't
currently catch `compute-collections`.**

**Manual fix:** Same as host-TN — either widen the regex or strip the path
manually in the export YAML.

### 3.4 VRF Tier-0 / Tier-1 references

**Symptom:** Same 400s/404s as Tier-0/Tier-1, but for VRF paths.

**Why:** VRF gateways are themselves Tier-0/Tier-1 children. If a rule's
`applied_to` or a group's `paths` references a VRF, the VRF UUID is
manager-specific.

**Risk surface:** Multi-tenant envs with NSX VRF separation.

---

## 4. LOW-severity gaps — usually out of scope for a firewall migration

These don't break the firewall migration itself, but operators sometimes
expect them to be migrated:

| Class | Why we don't migrate | Where it lives in NSX |
|---|---|---|
| NAT rules | Gateway-attached, environment-specific | `/policy/api/v1/infra/tier-{0,1}s/<gw>/nat/...` |
| Load Balancer config | Tier-1 attached, IP-pool-bound | `/policy/api/v1/infra/lb-...` |
| DHCP relay / static config | Segment-attached | `/policy/api/v1/infra/dhcp-...` |
| L2/L3 VPN | Per-edge config | `/policy/api/v1/infra/tier-0s/<t0>/ipsec-vpn/...` |
| EVPN config | VLAN/VNI mappings | `/policy/api/v1/infra/global-config/...` |
| Service Insertion (partner SVMs) | Separate API | `/policy/api/v1/infra/service-references/...` |
| Threat detection / Malware prevention | Separate feature set | `/policy/api/v1/infra/settings/firewall/idfw/...` |
| User accounts, RBAC, SSO bindings | Auth domain, not policy | `/api/v1/aaa/...` |
| Backup/restore, NTP, syslog, certs | Infrastructure config | `/api/v1/cluster/...` |
| Licensing | Per-manager | `/api/v1/licenses/...` |
| Custom annotations / labels | Stripped by `sanitize_payload` as volatile fields | n/a |

---

## 5. What's truly out of scope (intentional, by architecture)

| Class | Why it cannot be cloned |
|---|---|
| Host transport nodes | Bound to specific ESXi host registrations |
| Edge transport nodes | Bound to specific edge VM/appliance hardware |
| Transport zones | Fabric-layer, defined per manager |
| Compute managers (vCenter attachments) | Each NSX has its own |
| Manager-mode (deprecated) NSGroups/NSServices | Different API surface |

The toolkit doesn't try to migrate these. References to them in
policy-layer objects are stripped (groups) or surface as failed pushes
(rules — see 2.1).

---

## 6. Pre-flight checklist for operators

Run these checks against the source manager **before** kicking off the
migration. They're all read-only (`GET`) calls; do them from the operator
workstation against `nsx-lm1`.

### Things that will need same-or-equivalent setup on the target

```
□ Are there any AD-bound (Identity) groups?
  GET /policy/api/v1/infra/domains/default/groups
  | grep -c IdentityGroupExpression
  → if >0: configure AD/Directory Service on lm2 before cutover

□ What's in the DFW exclusion list?
  GET /policy/api/v1/infra/settings/firewall/security/exclude-list
  → copy to lm2 manually before cutover

□ Any context profiles referenced by rules?
  GET /policy/api/v1/infra/context-profiles
  → if non-default: export from lm1, push to lm2 first

□ Any time-range / TimeWindow profiles referenced by rules?
  GET /policy/api/v1/infra/time-ranges
  → recreate on lm2 first

□ Any rules with applied_to pointing at specific T0/T1 gateways?
  Scan exported rule YAMLs for "applied_to" containing "/infra/tier-"
  → manually translate the gateway paths source→target, or set applied_to: ['ANY']

□ Any groups with compute-collection (cluster) references?
  Scan exported group YAMLs for "compute-collections" in expression paths
  → strip those paths manually (fabric-strip regex doesn't catch these today)

□ Any IDS rules customer-tuned beyond defaults?
  GET /policy/api/v1/infra/domains/default/intrusion-service-rules
  → export separately, push to lm2 separately
```

### Things to verify on the target before push

```
□ Same NSX version (or compatible) on lm2 vs lm1
□ Same set of Tier-0 / Tier-1 gateway names if you're using applied_to
□ Directory Service configured (if IdentityGroupExpression is used)
□ Required context profiles created (if non-default profiles are in rules)
□ Required time ranges created (if scheduled rules are in use)
□ Transport zones present on lm2 (segments push needs matching TZs)
```

### Things to capture from the migration itself

After each push, inspect:

```
□ <reports_dir>/failures.json              → anything that didn't push
□ <reports_dir>/fabric_paths_stripped.json → groups that lost fabric refs
□ <reports_dir>/<tool>_push_<ts>.errors.log → real errors with tracebacks
□ Summary totals — confirm retry_rounds completed cleanly
```

---

## 7. Roadmap — what we'd build to close these gaps

Prioritized by impact / effort:

### 7.1 Rule-level fabric-path strip (mirror what groups.py does)

**Impact:** HIGH — covers 2.1 (T0/T1 applied_to) and 3.4 (VRF refs).
**Effort:** Low — copy `_strip_fabric_paths_in_expression()` pattern from
groups.py and apply to rules' `applied_to`, `scope`, `source_groups`,
`destination_groups`, `services` fields. Same forensic JSON report.

### 7.2 DFW exclusion list migration

**Impact:** HIGH — covers 2.4 (silent prod-breaker).
**Effort:** Low — single endpoint, single document, idempotent PUT.
Maybe `dfw_exclusion.py` with export/push/revert symmetry.

### 7.3 Context profile + time-range exporter / pusher

**Impact:** MEDIUM-HIGH — covers 2.2 and 2.3.
**Effort:** Medium — two new per-tool scripts following the existing
pattern (export/push/revert with baseline). Push order would be: context
profiles + time ranges → services → groups → policies → rules.

### 7.4 Capture-time audit report

**Impact:** HIGH (changes operator experience) — surfaces problems BEFORE
push instead of as failures during.
**Effort:** Medium — `capture_nsx_state.py` already has a step structure;
add a step that scans the exported objects for any of the patterns in
Section 2 and writes a `manual_dependencies.json` with one entry per
operator-action item.

### 7.5 Widen fabric-path regex to include compute-collections

**Impact:** MEDIUM — covers 3.3.
**Effort:** Trivial — single regex addition to `FABRIC_PATH_RE` in
`groups.py`.

### 7.6 Detect & report IdentityGroupExpression in groups

**Impact:** MEDIUM — covers 3.1.
**Effort:** Trivial — scan group expressions during push; if any
`IdentityGroupExpression` present, log to a new
`identity_groups_needing_ad.json` for operator follow-up.

### 7.7 Distributed IDS rules workflow

**Impact:** LOW — only relevant if IDS is in use.
**Effort:** Medium — new tool that mirrors rules.py against the IDS rule
endpoint.

---

## 8. Quick reference — operator action by symptom

| Push error you see | Likely cause | Section |
|---|---|---|
| `400 / "is invalid" / host-transport-nodes` | Fabric path in group | Auto-stripped → check `fabric_paths_stripped.json` |
| `400 / "is invalid" / compute-collections` | Cluster/resource-pool ref in group | §3.3 — strip manually for now |
| `404 / "could not be found" / tier-0s/tier-1s` | Rule's `applied_to` references a gateway | §2.1 — edit rule, drop or remap |
| `404 / "could not be found" / context-profiles` | Rule references an L7/FQDN profile | §2.2 — clone profile first |
| `404 / "could not be found" / time-ranges` | Rule uses scheduled enforcement | §2.3 — clone time range first |
| `404 / "could not be found" / groups/<other-group>` | Real dependency 404 between customer groups | Auto-retry loop handles it (no manual action) |
| `400 / unrelated error` | Schema/version mismatch | Check NSX version parity lm1 vs lm2 |
| Group lands but has no members | `IdentityGroupExpression` without AD on target | §3.1 — bind AD to lm2 |
| Cutover breaks vCenter / NSX manager connectivity | Missing DFW exclusion list | §2.4 — copy exclusion list manually |
| Customer-tuned IDS rules missing | IDS rules not migrated | §3.2 — separate tool needed |
