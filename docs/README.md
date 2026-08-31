# Runbook Index

One page that says what every document in `docs/` is for. Start here.

Naming convention: the change workflows each have a narrative runbook
(`RUNBOOK_X.md`), a bare bash command sheet (`RUNBOOK_X_COMMANDS.md`), and a
PowerShell command sheet (`RUNBOOK_X_COMMANDS_PS.md`). Single-file runbooks
pair `RUNBOOK_X.md` (bash) with `RUNBOOK_X_PS.md` (PowerShell).

## Reference (read first)

| Doc | What it is |
|---|---|
| [NSX_TOOLKIT_SUMMARY.md](reference/NSX_TOOLKIT_SUMMARY.md) | How the whole toolkit works: workflows, safety mechanics, revert model. Slide-ready |
| [NSX_TOOLKIT_GAPS.md](reference/NSX_TOOLKIT_GAPS.md) | Known gaps and manual-intervention items, with symptoms and fixes |
| [QUICKREF_PS.md](reference/QUICKREF_PS.md) | Compact PowerShell quick reference for the most-used workflows |
| [REPORTS_DATA_SOURCES.md](reference/REPORTS_DATA_SOURCES.md) | Which NSX endpoints feed each report tool |

## NSX change workflows

Every one of these is dry-run by default, baselines before `--apply`, and has
a matching revert.

| Workflow | Narrative | Commands | PowerShell | Purpose |
|---|---|---|---|---|
| **A** Clone | [RUNBOOK_A.md](nsx/RUNBOOK_A.md) | [cmds](nsx/RUNBOOK_A_COMMANDS.md) | [ps](nsx/RUNBOOK_A_COMMANDS_PS.md) | Clone customer DFW config lm1 to lm2 (3 push phases) |
| **B** In-place remap | [RUNBOOK_B.md](nsx/RUNBOOK_B.md) | [cmds](nsx/RUNBOOK_B_COMMANDS.md) | [ps](nsx/RUNBOOK_B_COMMANDS_PS.md) | CSV subnet remap in place (strict-additive; IP-only groups by default, `--remap-generic` widens). Includes the B.4 remap audit |
| **C** Sibling decomposition | [RUNBOOK_C.md](nsx/RUNBOOK_C.md) | [cmds](nsx/RUNBOOK_C_COMMANDS.md) | [ps](nsx/RUNBOOK_C_COMMANDS_PS.md) | After a clone: decompose tagged groups into IP-only siblings on the target |
| **D** Prod remap-to-siblings | [RUNBOOK_D.md](nsx/RUNBOOK_D.md) | [cmds](nsx/RUNBOOK_D_COMMANDS.md) | [ps](nsx/RUNBOOK_D_COMMANDS_PS.md) | Production-grade WF-C: land IP-only siblings in place on a live manager |
| Single-capture clone + WF-D | [RUNBOOK_FROM_CAPTURE.md](nsx/RUNBOOK_FROM_CAPTURE.md) | included | [ps](nsx/RUNBOOK_FROM_CAPTURE_PS.md) | One capture, then run everything else off it |
| Selective category copy | [RUNBOOK_FILTER_COPY.md](nsx/RUNBOOK_FILTER_COPY.md) | included | [ps](nsx/RUNBOOK_FILTER_COPY_PS.md) | Copy chosen DFW policies plus only their transitive dependencies |
| Services only | [RUNBOOK_SERVICES.md](nsx/RUNBOOK_SERVICES.md) | included | included | Export / push / revert customer services alone |
| GM to LM copy | `tools/nsx/transform_gm_export_to_lm.py` | tool docstring | n/a | Rewrite a Global Manager export's `/global-infra/` refs (and optionally the domain) so the standard Workflow A pushes land it on a Local Manager |

## Backup (separate from capture on purpose)

| Doc | Purpose |
|---|---|
| [RUNBOOK_BACKUP.md](nsx/RUNBOOK_BACKUP.md) / [ps](nsx/RUNBOOK_BACKUP_PS.md) | `backup_nsx_state.py`: read-only, definitions-only, timestamped kept history, multi-manager, GM-aware. Restore = push the bundle back. The backup-vs-capture table at the top explains why this is not `capture_nsx_state.py` |

## Tagging and group hygiene

| Doc | Purpose |
|---|---|
| [RUNBOOK_VM_TAGS.md](nsx/RUNBOOK_VM_TAGS.md) ([cmds](nsx/RUNBOOK_VM_TAGS_COMMANDS.md) / [ps](nsx/RUNBOOK_VM_TAGS_COMMANDS_PS.md)) | VM hostname tagging: plan / validate / push / revert |
| [RUNBOOK_GROUP_LABEL_TAGS.md](nsx/RUNBOOK_GROUP_LABEL_TAGS.md) / [ps](nsx/RUNBOOK_GROUP_LABEL_TAGS_PS.md) | Mirror a group's tag-based membership criteria into its own label tags |

## Reports and audits (all read-only)

| Doc | Purpose |
|---|---|
| [RUNBOOK_INFO_GATHER.md](nsx/RUNBOOK_INFO_GATHER.md) / [ps](nsx/RUNBOOK_INFO_GATHER_PS.md) | One-session, read-only evidence pack: VM rule membership, group membership, 30-day rule hit counts, hostname tag dry run, IP remap dry run; LM and GM blocks for every step, variable-driven paths |
| [RUNBOOK_REPORTS.md](nsx/RUNBOOK_REPORTS.md) / [ps](nsx/RUNBOOK_REPORTS_PS.md) | The report tools under `tools/reports/`, plus the IP remap audit pointer |
| [RUNBOOK_RULES_USAGE.md](nsx/RUNBOOK_RULES_USAGE.md) / [ps](nsx/RUNBOOK_RULES_USAGE_PS.md) | Rule hit-count / usage report, diff mode, federation notes |
| [RUNBOOK_VM_RULE_MEMBERSHIP.md](nsx/RUNBOOK_VM_RULE_MEMBERSHIP.md) / [ps](nsx/RUNBOOK_VM_RULE_MEMBERSHIP_PS.md) | Given VM names: every DFW rule they participate in and why |
| IP remap audit | Lives in [RUNBOOK_B.md](nsx/RUNBOOK_B.md) section B.4: `audit_ip_remap.py`, gaps first, exit 1 on gaps, cron-safe |

## Palo Alto

| Doc | Purpose |
|---|---|
| [RUNBOOK_PAN_LAB.md](pan/RUNBOOK_PAN_LAB.md) / [ps](pan/RUNBOOK_PAN_LAB_PS.md) | Lab Panorama over the API: auth (`panorama_auth.py`), config pulls, rule-service tooling |
| [RUNBOOK_PAN_PROD.md](pan/RUNBOOK_PAN_PROD.md) / [ps](pan/RUNBOOK_PAN_PROD_PS.md) | Production Panorama, manual / file-driven (no API): offline policy lookup flow |
| [RUNBOOK_PAN_FLOW_RULES.md](pan/RUNBOOK_PAN_FLOW_RULES.md) / [ps](pan/RUNBOOK_PAN_FLOW_RULES_PS.md) | Offline flow/rule report: a CSV of source/destination pairs in, every covering rule out, plus a subnet list that suppresses matches by attribution |

## Testing

| Doc | Purpose |
|---|---|
| [README-TEST.md](reference/README-TEST.md) | Load-test scaffolding under `tools/test/` for exercising the NSX tools at scale |

Unit tests for the remap / audit / backup / Panorama code live in
[`tests/`](../tests/): `python -m unittest discover tests`.
