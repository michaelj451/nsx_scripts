# Lab setup: replicate a client migration request in the lab

PowerShell variant: [RUNBOOK_LAB_SETUP_PS.md](RUNBOOK_LAB_SETUP_PS.md).

Mike, 2026-10-16. Every migration request at a client is also copied to the
lab, so the same test can be run again there: the same rules found, the same
approval sheet, the same Workflow A, C and D dry runs and the same Palo plan.

The configuration is copied with **Workflow A in full** (Part 1 and Part 3).
The lab does not have the client's VMs, and does not need them: Part 3 pushes
every group with the member IPs it had at the client written in as literal
addresses, so in the lab each group still holds the client's servers, and a
request that lists the servers as `name,ip` finds them by address.

Workflow C is **not** used for this. C puts the client IPs into `_np_ips`
sibling groups, which the migration request treats as migration siblings and
ignores; the original groups would stay empty in the lab, Workflow D would
find no groups for the servers, and the lab request's own C step would create
siblings with the same names.

| Step | Where | Touches |
|---|---|---|
| 1. Capture | client | client source manager, GET only |
| 2. Server list and package | client | local files only |
| 3. Carry the package out | | client configuration: handle it as client data |
| 4. Push (Workflow A Part 1, then Part 3) | lab | the lab manager standing in for the client source |
| 5. Run the same request | lab | lab managers and lab Panorama, dry runs |
| 6. Compare, then clean up | lab | lab only |

**Client data.** The package holds the client's firewall configuration,
addresses and server names. Everything below lives in git-ignored folders
(`nsx_capture/`, `nsx_services_export/`, `nsx_groups_export/`,
`nsx_policies_export/`, `nsx_rules_export/`, `migration_requests/`). Never copy
any of it into `data/`, `docs/` or anything else that is tracked, and delete it
from the lab when the test is done.

---

## 0) Env

```bash
setopt interactive_comments 2>/dev/null || true
source .venv/bin/activate
export PYTHONPATH="$PWD/app"
export NSX_LOG_DIR="$PWD/nsx_logs"
alias mr='python tools/multisite/migration_request.py'
```

At the client, `.env` holds the client's managers; in the lab, the lab's.

## 1) At the client: capture the source, right after the request

Run it on the same day as the request, so the copy matches what the request
saw. `--live-query` freezes each group's member IPs (Part 3 needs it);
`--with-segments` records the segment CIDRs (Part 3 converts segment members
to them). One command writes the capture and the push-ready exports.

```bash
SRC=nsx-lm1                       # the client source alias in .env
H=nsx-lm1.lab.local               # its host name (the folder name the capture uses)
python tools/nsx/capture_nsx_state.py --source $SRC --live-query --with-segments
cat nsx_capture/$H/summary.txt    # every step OK, Result: OK
```

It writes:

| Folder | Holds |
|---|---|
| `nsx_capture/$H/` | the capture: `groups_additive/` (groups with their member IPs, the Part 3 input), `segment_inventory/segment_details.json`, manifest, summary |
| `nsx_services_export/$H/services/` | every custom service |
| `nsx_groups_export/$H/groups/` | every group as defined |
| `nsx_policies_export/$H/security-policies/` | every policy, Infrastructure included |
| `nsx_rules_export/$H/security-policies/` | every rule, carrying its policy id |

The request's own `source/capture/` cannot be used for this: it is taken
without the push-ready exports, and its rules do not carry their policy id.

## 2) At the client: the server list and the package

The lab has no VM to resolve a name to, so the lab request needs every server
as `name,ip`. Write that list from the request itself:

```bash
R=migration_requests/nsx-lm1_to_nsx-lm3/latest        # the client request
mkdir -p migration_requests/lab_replica/$H
python - "$R" "migration_requests/lab_replica/$H/servers.txt" <<'PY'
import json, sys
from pathlib import Path
rec = json.loads((Path(sys.argv[1]) / "request.json").read_text())
lines = [f"# lab replica of {rec['request_id']}"]
for s in rec["servers"]:
    if s["ips"]:
        lines.append(",".join([s["vm"] or s["key"], *s["ips"]]))
    else:
        lines.append(f"# {s['key']}: no address at the client ({s['status']})")
Path(sys.argv[2]).write_text("\n".join(lines) + "\n")
print("\n".join(lines))
PY
cp "$(python -c "import json;print(json.load(open('$R/request.json'))['inputs']['subnet_map'])")" \
   migration_requests/lab_replica/$H/subnet_map.csv
```

Then package everything, the request folder included (its `reports/` is what
the lab run is compared against):

```bash
REQ=$(readlink -f "$R")
tar czf lab_replica_${H}_$(date -u +%Y%m%d).tgz \
  nsx_capture/$H nsx_services_export/$H nsx_groups_export/$H \
  nsx_policies_export/$H nsx_rules_export/$H \
  migration_requests/lab_replica/$H "${REQ#$PWD/}"
```

## 3) Carry it to the lab

Move the `.tgz` by whatever path the client allows, and unpack it at the root
of the lab checkout: `tar xzf lab_replica_<host>_<date>.tgz`. Every folder
lands where the tools expect it. Nothing connects the client to the lab.

## 4) In the lab: push with Workflow A in full

Pick an **empty** lab manager to stand in for the client source (pushes are
additive, so anything already there would mix in). `nsx-lm2` is empty today;
to empty one, see [RUNBOOK_WIPE.md](../tools/test/RUNBOOK_WIPE.md). The pushes
are the unchanged Workflow A commands ([RUNBOOK_A.md](../nsx/RUNBOOK_A.md)).
Run each without `--apply` first, read its summary, then add `--apply`.

```bash
H=nsx-lm1.lab.local               # the client host name, from the package
LAB=nsx-lm2                       # the lab stand-in for the client source

# Part 1: 1-for-1 clone, segment members stripped
python tools/nsx/services.py push --target $LAB \
  --services-dir nsx_services_export/$H/services
python tools/nsx/groups.py push --target $LAB \
  --groups-dir nsx_groups_export/$H/groups --segments-mode strip
python tools/nsx/policies.py push --target $LAB \
  --policies-dir nsx_policies_export/$H/security-policies
python tools/nsx/rules.py push --target $LAB \
  --rules-dir nsx_rules_export/$H/security-policies

# Part 3: every group again, with its client member IPs and segment CIDRs
python tools/nsx/groups.py push --target $LAB \
  --groups-dir nsx_capture/$H/groups_additive/domains/default/groups \
  --segments-mode convert \
  --segments-from nsx_capture/$H/segment_inventory/segment_details.json
```

Part 3 alone covers Part 2 (its input is a superset), so Part 2 is skipped.
Applies are interactive: one object, then a pause before each batch.

What lands, and what does not:

- Every custom service, group, policy and rule, Infrastructure policies
  included, so the request leaves out the same rules in the lab.
- Groups keep their tag conditions; their members in the lab are the client
  IPs from Part 3. A lab VM carrying the same tag would join them too.
- Segment members become their CIDRs. Fabric references (transport nodes,
  edges) cannot be cloned and are stripped; `fabric_paths_stripped.json` in the
  push report lists any.
- NSX default sections are not copied; the lab manager has its own.
- `_np_ips` / `_avs_ips` groups that already exist at the client come across
  and are ignored by the request, as at the client.

## 5) In the lab: run the same request

Use the lab source stand-in, a lab destination, the carried server list and
subnet map, and the lab Panorama device group from the lab `.env`. Dry runs
only (the request is read-only; its dry runs write nothing):

```bash
mr request --source $LAB --destination nsx-lm3 --no-tls-verify \
  --server-list migration_requests/lab_replica/$H/servers.txt \
  --subnet-map migration_requests/lab_replica/$H/subnet_map.csv
```

To replay the client's approval decisions, add the client request's sheet:
`--rule-approval <client request>/reports/03_rule_approval_sheet.yaml`.

From there the lab follows the normal process
([RUNBOOK_MIGRATION_REQUEST.md](RUNBOOK_MIGRATION_REQUEST.md)): approve,
refresh, and each phase's dry run, apply, verify and rollback.

## 6) Compare with the client, then clean up

Open both `reports/` folders side by side. Expect these to match:

- the rules found (by policy and rule name), the rules left out, and why;
- the groups each server is in, and every server's new address;
- Workflow A, C and D counts, and the Palo objects and rules.

Expect these to differ, and nothing more:

- **rule #**: NSX numbers rules per manager, so the lab numbers are its own.
  A replayed approval sheet matches rules by policy and rule id, and lists each
  renumbered rule under Warnings.
- **Servers** say "not a VM on the source: matched by the given addresses
  only": the lab has no VM by that name. Their status is still ok, but the
  summary counts them under "need attention".
- **Palo address object names lose the hostname.** At the client an address
  is named `<hostname>-<address>-<suffix>` (`ax2001-10.6.0.101-np_ips`), the
  hostname being the NSX `hostname` tag of the VM that owns the address. The
  lab has no VM to read it from, so the same object is `10.6.0.101-np_ips`.
  The number of objects, the groups and the rules are the same.
- **Group fingerprints** of tag groups: in the lab they hold the client
  addresses as literal IPs (Part 3), so their content differs while their
  membership is the same.
- The change record (ticket, user, date) is the lab's `.env`.

## Proof run, 2026-10-16 (lm1 as the "client", lm4 as the lab stand-in)

- Capture of nsx-lm1 (`--live-query --with-segments`): 19 services, 44 groups,
  9 policies, 23 rules, 2 segment members.
- Workflow A onto the empty nsx-lm4, every push 0 failed: services 19,
  groups 44 (Part 1), policies 7 and rules 21 (lm1's two NSX default sections
  skipped), groups Part 3 19 updated with their member IPs and the 2 segment
  members converted (25 had nothing to add).
- Request `nsx-lm4_to_nsx-lm3/20261016_230641` from the `name,ip` list against
  lm1's `nsx-lm1_to_nsx-lm3/20261016_221506`: the same 2 servers in the same 4
  groups each with 12 rules, the same 3 candidate rules, the same 10 rules not
  copied (8 Infrastructure, 2 default) with the same reasons, identical
  policies, rules, services, C siblings, D siblings, C and D amendments, and
  28 Palo objects. Differences: exactly the ones listed above (rule numbers
  8168/8175/8178 became 4089/4090/4091; 6 address objects without the hostname
  prefix; servers matched by address).

The revert baselines of these pushes are written inside the unpacked folders
(`nsx_*_export/<host>/push_report/`, `nsx_capture/<host>/groups_additive/.../push_report/`).
A later capture of the same host on the same machine wipes those folders, so
revert or wipe the stand-in first.

Clean up when done: roll back any phase that was applied (newest first), then
empty the stand-in manager with [RUNBOOK_WIPE.md](../tools/test/RUNBOOK_WIPE.md)
or the Workflow A reverts in [RUNBOOK_A.md](../nsx/RUNBOOK_A.md) (group reverts
that delete need `--allow-delete`), and delete the unpacked package and the
`.tgz`.
