# Migration requests: from a server list to approved NSX and Palo Alto changes

Someone asks for a set of servers to move from one NSX manager to another.
This runbook turns that list into a report of every firewall change the move
needs, gets it approved, and later applies exactly that, picking up any
changes the source has had since. One tool does it:
`tools/multisite/migration_request.py`.

PowerShell variant: [RUNBOOK_MIGRATION_REQUEST_PS.md](RUNBOOK_MIGRATION_REQUEST_PS.md).
Background on the sites, suffixes and maps:
[RUNBOOK_MULTIVENDOR_ROLLOUT.md](RUNBOOK_MULTIVENDOR_ROLLOUT.md). Decisions:
[STATUS.md](STATUS.md).

Status: built 2026-10-07 and proven read-only in the lab (lm1 to lm3, Palo
`dg-4` on pano4, every phase as a dry run). Nothing has been applied with it
yet.

## The four steps

| Step | Who | Command | Touches |
|---|---|---|---|
| 1. Request | requester or operator | `request` | Reads the source. Dry runs against the destination, the source and Panorama. Writes nothing to any of them |
| 2. Review | approver | read `request.md` | Nothing |
| 3. Approve | approver or operator | `approve` | A local file only |
| 4. Implement | operator, in the change window | `refresh`, then `run` per phase | Destination (A, C), source (D), Panorama candidate config (Palo) |

At step 4 the source is captured again and everything is rebuilt from the
request's own inputs. Rule changes on the source since approval went through
their own approval, so they are taken as they are now and listed in
`delta.md`. A change to the **request's own servers** (a server no longer
found, a different VM behind a name, a changed address, a changed subnet map)
stops the run: raise a new request. `refresh --strict` stops on any change.

## What a request covers

| Part | Scope |
|---|---|
| Servers | One per entry: a VM name, an IP address, or `name,ip[,ip]`. An IP that exactly one VM owns resolves to that VM, so its group memberships count. An IP no VM owns (powered off, or not a VM) matches by address only. A misspelt name gets "did you mean" suggestions |
| Rules | Every NSX rule whose source, destination or applied-to contains a server, through a group the VM is in or a group whose addresses cover the server. NSX default sections are never copied. A copied rule covers every member of its groups, not only the requested servers |
| Workflow A (destination) | Those rules, their policies, and every group and service they need: nested groups, nested services, a policy's own applied-to. Segment references inside groups are stripped (segment ids differ per manager). Built-in NSX services are not copied (every manager has them). Context profiles are listed, not copied |
| Workflow C (destination) | An IP-only `_np_ips` sibling for every tag-based group in that bundle, holding the source's current addresses, added to the copied rules. Copied rules keep matching servers that have not moved |
| Workflow D (source) | Mike, 2026-10-07: **only the groups the servers are members of, and the rules those groups are in.** Each sibling holds only the requested servers' new addresses. Segment-based groups get no sibling, as in Workflow D |
| Palo Alto | Planned from the same capture with the same mapping as `nsx_pan_mirror.py plan-rules`, for exactly the copied rules: one `<group>_np_ips` address group per NSX group holding the C and D addresses, objects in `shared`, rules in the named device group's pre-rulebase. Security profile group and log forwarding profile from `.env` |

The destination picks the Workflow D suffix and subnet map:

| Destination | D suffix | Subnet map |
|---|---|---|
| `nsx-lm2` (AVS) | `_avs_ips` | `data/subnet_map_lm2.csv` |
| `nsx-lm3` | `_lm3_ips` | `data/subnet_map_lm3.csv` |

Any other destination needs `--d-appendix` and `--subnet-map`.

---

## 0) Env

```bash
setopt interactive_comments 2>/dev/null || true
source .venv/bin/activate
export PYTHONPATH="$PWD/app"
export NSX_LOG_DIR="$PWD/nsx_logs"
mr() { python tools/multisite/migration_request.py "$@"; }
```

Lab Panorama (pano4) presents the PAN-OS default certificate, so lab
commands that reach Panorama take `--no-tls-verify`.

## 1) Request

The servers go in **`migration_request_servers.txt`** at the repository root,
one per line. The file is tracked in git, so its history shows what was
requested and when. `request` reads it whenever no servers are given on the
command line.

```text
# wave 1, REQ-1234
ubuntu22-speedtest-10.6.0.101-ax2001
10.6.2.102
ubuntu22-speedtest-10.6.1.102-0102,10.6.1.102
```

A powered-off VM reports no address to NSX. Give it as `name,ip`, or its
Workflow D sibling and its Palo address object have nothing to work with.

```bash
mr request --source nsx-lm1 --destination nsx-lm3 --device-group dg-4 \
  --no-tls-verify --name "wave 1"

R=migration_requests/nsx-lm1_to_nsx-lm3/latest
open $R/request.md
```

Each request keeps its own copy of the list (`servers.txt`), and
`request.json` records the tracked file's sha256, so a later edit to the
file never changes an existing request. The report names the list it came
from near the top.

Other ways to give servers: `--server-list FILE` reads another file in the
same format, and `--servers "name1,10.6.0.101"` takes them on the command
line, where every comma-separated token is its own server. With either, the
tracked file is not read unless it is the file named. The run takes a
minute or two: two read-only captures of the source, the builds, then dry
runs against the destination, the source and Panorama. Exit code 1 means
the request lists errors (top of the report).

Useful options:

| Option | Effect |
|---|---|
| `--no-preview` | Skip the dry runs (offline report). Run `mr preview --request $R --part a` (or `c`, `d`, `palo`, `all`) later |
| `--no-palo` | NSX only |
| `--include-default-sections` | Also copy rules from NSX's default sections (normally never) |
| `--rulebase post`, `--object-location device-group`, `--zone-from`, `--zone-to` | Palo placement, as in `plan-rules` |
| `--profile-group none`, `--log-setting none` | No security profile or log forwarding profile on the Palo rules |

## 2) Review: what the approver reads

`request.md`, top to bottom:

1. **Summary**, then **Servers**: what each entry resolved to, its addresses
   now and at the destination, how many groups and rules, and anything that
   needs attention (not found, shared address, no address, unmapped address).
2. **Firewall rules these servers use**: every rule, in NSX order, with each
   side's groups, the services, and which server matches on which side. This
   is the access the servers get at the destination.
3. **Workflow A**: what is copied, and from the dry run, what is new, an
   update, or already identical on the destination.
4. **Workflow C**: the destination siblings and the rules that gain them.
5. **Workflow D**: the source siblings (only the requested servers' new
   addresses) and the source rules that gain them, with the dry run's counts.
6. **Palo Alto**: what the dry run against Panorama found to create, by
   kind, the address groups, and every Panorama rule. NSX rules the Palo
   cannot mirror (segment members, empty tag groups) are listed with why.
   Address groups already on Panorama that lack members are listed
   separately: the push never edits an existing object, so those members are
   added by hand.

The full Palo plan is `palo/plan.md`, the Panorama dry run
`palo/push_<ts>_dryrun.md`.

## 3) Approve

```bash
mr approve --request $R --change-ref CHG0012345 --approved-by "Name Surname"
```

The approval records the request's fingerprint. If `request.json` changes
afterwards, `refresh` refuses until it is approved again. A request that lists
errors is refused unless `--accept-errors` is given (recorded in the approval).

## 4) Implement, in the change window

```bash
mr refresh --request $R                 # re-capture the source, rebuild, compare
cat $R/runs/latest/delta.md
RUN=$R/runs/latest
```

`refresh` exits 0 when the gate passes and 2 when it stops. `delta.md` says
which, and lists every change since approval. `implementation.md` is the
request report as of now: this is what the phases push.

Then each phase, in this order, dry run first. A phase's apply is refused
when the gate did not pass.

```bash
mr run --run $RUN --phase a             # Workflow A onto the destination
mr run --run $RUN --phase a --apply
mr run --run $RUN --phase a --verify

mr run --run $RUN --phase c             # Workflow C siblings + rule references
mr run --run $RUN --phase c --apply
mr run --run $RUN --phase c --verify

mr run --run $RUN --phase d2a           # Workflow D siblings on the source
mr run --run $RUN --phase d2a --apply
mr run --run $RUN --phase d3            # Workflow D rule references on the source
mr run --run $RUN --phase d3 --apply
mr run --run $RUN --phase d3 --verify   # only after d3

mr run --run $RUN --phase palo --no-tls-verify          # Panorama dry run
mr run --run $RUN --phase palo --no-tls-verify --apply  # candidate config, never commits
mr run --run $RUN --phase palo --no-tls-verify --verify
```

Every phase runs the same commands as `tools/nsx/run_workflow.py` (the push
tools with the same flags), on the run's own bundles, and writes its report to
`$RUN/report/<phase>/<mode>/`. Applies are interactive (one object, then a
pause before each batch), so the operator runs them, not an agent. D3 is the
only step that changes what the source enforces. Review and commit the Palo
change in Panorama yourself.

Verification:

| Phase | Check |
|---|---|
| a | Every bundle object exists on the destination, and every destination group resolves |
| c | Every sibling exists with every source address, every rule that names an original also names its sibling |
| d3 | `validate_wf_d.py`: nothing deleted, no address lost, siblings typed IP-only, every rule naming an original names its sibling. Run it after d3: between d2a and d3 the rule check fails by design |
| palo | A fresh Panorama dry run finds nothing left to create and no group lacking members |

### Rollback

Newest first: `palo`, `d3`, `d2a`, `c`, `a`. Preview, then apply:

```bash
mr run --run $RUN --phase d3 --rollback
mr run --run $RUN --phase d3 --rollback --apply
```

The Palo rollback deletes exactly what that run's apply created. The NSX
rollbacks are the push tools' own reverts, scoped as in the workflow driver.
Known gap: the policies and services reverts remove any object that is not in
their baseline, so an object someone else created on the destination after
the apply would be removed too (pending item in STATUS.md).

## Folder layout

```text
migration_requests/<source>_to_<destination>/<UTC_TS>/
  request.md  request.json  servers.txt (copy of the list used)  approval.json
  source/capture/          source capture (capture_nsx_state.py, effective IPs)
  source/vm_rules/         VM-rule snapshot (capture_vm_rule_data.py)
  bundle/                  Workflow A bundle, plus c_input/ and d_input/
  c/ d/                    Workflow C and D sibling bundles (build_sibling_groups.py)
  palo/                    plan.json, plan.md, Panorama dry runs
  preview/previews.json    dry-run counts shown in request.md
  runs/<UTC_TS>/           one per refresh: the same layout, plus run.json,
                           delta.md, implementation.md, phases.json, report/
```

`migration_requests/` is not tracked by git.

## Credentials

The lab uses one `.env` for every manager and Panorama. Where the source and
the destination need different credentials, build with `--no-preview`, then
run `preview --part d` with the source's credentials and `preview --part a`
and `--part c` with the destination's. `refresh` reads only the source.
`run` phases a and c contact only the destination, d2a and d3 only the
source, palo only Panorama.

## Known limits

- **Palo groups from earlier requests.** The push creates only missing
  objects and never edits one. A later request whose servers join an address
  group an earlier request created shows that group under "lack members";
  those members are added by hand until an "add missing members" push exists.
- **Palo rule order across requests.** The push appends rules to the bottom of
  the pre-rulebase. Rules from a later request land below earlier ones even
  where NSX evaluates them first.
- **One domain.** Only the `default` domain is captured; rules in other
  domains are listed as not copied.
- **Addresses at the destination stay reserved.** Siblings are additive, so a
  server's new address stays in every rule until the migration ends.

## Proof run, 2026-10-07 (read-only)

lm1 to lm3, Palo `dg-4`, three entries: `10.6.0.101` (resolved to
`ubuntu22-speedtest-10.6.0.101-ax2001`), the powered-off
`ubuntu22-speedtest-10.6.1.102-0102,10.6.1.102`, and the misspelt
`speedtest-x515` (suggested: `ubuntu22-speedtest-10.6.0.103-x515`).

| Result | Value |
|---|---|
| Rules to copy | 22 (2 default-section rules excluded) |
| Bundle | 5 policies, 30 groups, 8 services |
| Workflow A dry run on lm3 | all 65 objects already identical (lm3 holds lm2's clone of lm1) |
| Workflow C | 14 siblings, 17 destination rules gain one |
| Workflow D | 18 siblings, 21 source rules gain one: the offline count matched the live amend dry run (21 would change, 8 unchanged) |
| Palo `dg-4` dry run | 106 objects to create (24 rules, 27 address groups, 39 addresses, 13 services, 3 service groups), none present |
| Refresh a minute later, from a new capture | fingerprint unchanged, gate passed |
| Every phase as a dry run, A verify | all OK |
