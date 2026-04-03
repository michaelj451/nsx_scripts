# NSX Scripts — Project Context

## What this repo does
Python tooling for managing VMware NSX Policy security group objects during a network subnet migration. Scripts read a CSV subnet mapping and either additively append new IPs to existing groups, or create new group objects with only the remapped IPs.

## Key files

| Path | Purpose |
|------|---------|
| `app/nsx/nsx_object_functions/nsx_group_remap.py` | Core library: IP remapping logic, CSV parsing, two processing modes |
| `data/subnet_map.csv` | Subnet mapping input (columns: old_subnet, new_subnet, vlan, description) |
| `tools/nsx/add_mapped_ips_to_groups_files.py` | Additive mode: keeps original IPs + appends mapped IPs |
| `tools/nsx/push_remapped_groups.py` | Pushes remapped group files to NSX via API |
| `tools/nsx/push_nsx_groups_revert.py` | Rollback: restores groups from an export snapshot via NSX Policy API |
| `tools/nsx/promote_local_groups.py` | Promotes local manager groups to global manager |
| `tools/nsx/export_nsx_objects.py` | Exports NSX objects to YAML/JSON files |
| `app/nsx/nsx_policy_client.py` | NSX API client |
| `app/nsx/cli_bootstrap.py` | CLI auth/config bootstrap |

## Processing modes
- **Additive** (`add_mapped_ips_in_doc`): keeps all original IPs, appends newly mapped IPs. Used during dual-stack transition so both old and new subnet IPs are present in groups.
- **New-only** (`convert_groups_in_doc`): drops original IPs, keeps only remapped ones, creates new group objects with a name suffix appended.

## Directory layout
- `nsx_export/` — raw NSX export (input)
- `nsx_groups_additive/` — additive-mode output
- `nsx_logs/` — timestamped log files + `nsx_group_remap_changes.jsonl`

## Active branch
`push_lab`
