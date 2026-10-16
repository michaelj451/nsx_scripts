# vRNI flow filter: leave out the Infrastructure rules

Takes a flow export from vRNI (VMware Aria Operations for Networks) and makes
a new list without the flows that hit an **Infrastructure** rule, so what is
left is the application traffic a migration has to carry. One script:
`tools/multisite/filter_vrni_flows.py` (logic `app/multisite/vrni_flows.py`).
It only reads: the NSX manager is read, never written, and with `--capture`
it is not contacted at all.

Mike, 2026-10-15. PowerShell variant: [RUNBOOK_VRNI_FLOW_FILTER_PS.md](RUNBOOK_VRNI_FLOW_FILTER_PS.md).

---

## How a flow is judged

1. Each row's **firewall ruleid** is NSX's numeric rule id on the manager the
   flow was seen on (for example `8168` for `migration-rule-1` on nsx-lm1).
2. The script reads that manager's rules and finds the rule with that number.
3. If the rule's **policy** is in the Infrastructure category, the row is
   removed. This is the same test the migration request uses to leave
   Infrastructure rules out.

Every row ends up in exactly one list, with all its original columns:

| List | What is in it |
|---|---|
| filtered | rows whose rule is known and is not in an Infrastructure policy |
| removed | rows whose rule is in an Infrastructure policy, with the reason |
| unmatched | rows with no rule id, or a number that is not on that manager; review these by hand |

**Read the rules from the manager the flows came from.** Each NSX manager
numbers its own rules, so a rule copied from nsx-lm1 to nsx-lm3 has a
different number there (lab: 8168 on lm1, 7162 on lm3). Matching against the
wrong manager puts most rows in "unmatched".

Only the NSX category decides. A rule for, say, Active Directory or DNS that
sits in an **Application** policy is kept; check the "Flows per rule" table in
the summary for those.

## Input

A CSV exported from vRNI. The columns are found by their header text, in any
order, case not important:

| Column | Used for |
|---|---|
| `firewall ruleid` | **Required.** The rule number |
| `firewall rule`, `Source IP Address`, `Destination IP Address`, `firewall action` | Kept as they are |
| `Flow Packet Count (<from> to <to>)` | The export window, shown in the summary |

All other columns are carried through unchanged. A file saved from Excel (with
its byte-order mark) is fine, and rule numbers written as `8,168` or `8168.0`
are read as 8168.

Two made-up samples in this format, built from nsx-lm1's real rules and
numbers:

| Sample | Rows | What is in it |
|---|---:|---|
| [`vrni_flows_sample.csv`](../../data/samples/vrni_flows_sample.csv) | 12 | Mostly application flows, four Infrastructure ones, an NSX default rule, a row with no rule id and a number not on lm1 |
| [`vrni_flows_infra_sample.csv`](../../data/samples/vrni_flows_infra_sample.csv) | 19 | Mostly infrastructure traffic, like a real estate's export: Active Directory (389, 88, 636), DNS, NTP, Splunk (9997), Puppet (8140), SNMP (161), RustDesk, plus a few application flows, a default-rule DROP and two rows that cannot be matched |

The second sample's rules are the lab seed policy `seed-infra-services` on
nsx-lm1 (Infrastructure category, rules 8179 to 8184), created for it on
2026-10-15.

**Keep real exports out of the repository.** They hold production addresses
and host names. Put them in a folder outside the repo; the output lands in
`nsx_logs/`, which git ignores.

## Run (bash)

```bash
cd ~/dev/nsx_scripts
source .venv/bin/activate
export PYTHONPATH="$PWD/app" NSX_LOG_DIR="$PWD/nsx_logs"

# Rules read live from the manager the flows came from (read-only)
python tools/multisite/filter_vrni_flows.py --flows ~/exports/vrni_workflows.csv --source nsx-lm1

# Or from a capture already on disk (no device contact), e.g. a migration request's
python tools/multisite/filter_vrni_flows.py --flows ~/exports/vrni_workflows.csv \
  --capture migration_requests/nsx-lm1_to_nsx-lm3/latest/source/capture
```

Options:

| Option | Effect |
|---|---|
| `--source nsx-lmN` | The manager the flows came from; its rules are read live (GET only) |
| `--capture DIR` | Read the rules from a `capture_nsx_state.py` folder instead (with several managers in it, add `--source`) |
| `--exclude-category NAME` | Leave out another category too; repeatable (default `Infrastructure` only) |
| `--out-dir DIR` | Where the files go (default `$NSX_LOG_DIR/vrni_flow_filter/<UTC_TS>/`) |
| `--domain-id` | NSX domain (default `default`) |

## Output

In the output folder, named after the input file:

| File | Contents |
|---|---|
| `<name>_filtered.csv` | The new list: the input's columns, Infrastructure rows taken out |
| `<name>_removed.csv` | The Infrastructure rows, plus a `filter reason` column naming the policy and rule |
| `<name>_unmatched.csv` | Rows that could not be judged, plus the reason |
| `<name>_rules.csv` | Two sections: **Rules kept (application traffic)** and **Infrastructure rules hit (removed)**, each with its title, rule count and header: rule # (the number vRNI shows), rule name, NSX rule id, policy, category, action, flows, packets, result. The rule # matches the approval report and `rule_approval.yaml` |
| `summary.md` | Counts, the export window, the same two rule tables, and the unmatched reasons |
| `logs/` | The run log |

The summary marks rows that hit an NSX default rule (`kept (NSX default
section)`), such as a cleanup DROP: they are application traffic the
default rule decided, worth a look.

## Lab run, 2026-10-15

The sample against nsx-lm1, rules read live:

| Result | Rows | Rules |
|---|---:|---|
| kept | 6 | migration-rule-1 (8168), migration-rule-2 (8175), migration-ssh (8178, 2 flows), seed-cold-a-tcp-17239 (8170), Default Layer3 Rule (2) |
| removed | 4 | servers-to-rustdesk (8177), install-rustdesk (8176), seed-infra-dns (7212), test-infrastructure-rule-1 (7198) |
| unmatched | 2 | a row with no rule id, rule 99999 (not on lm1) |

The infrastructure sample against nsx-lm1, rules read live: 19 rows, **13
removed** (seed-infra-ad x3, dns-lookup x2, ntp x2, splunk x2, snmp x2, puppet,
servers-to-rustdesk), **4 kept** (migration-rule-1, migration-rule-2,
migration-ssh, Default Layer3 Rule DROP), 2 unmatched.

Tests: `tests/test_vrni_flows.py`.
