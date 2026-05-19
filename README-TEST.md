# README-TEST — NSX Test Tooling

Tools under [`tools/test/`](tools/test/) for **load testing** an NSX
manager (Local or Global) with synthetic objects, then **wiping** them
cleanly when done. These are not part of the production runbooks
([RUNBOOK_A.md](RUNBOOK_A.md) / [RUNBOOK_B.md](RUNBOOK_B.md) /
[RUNBOOK_VM_TAGS.md](RUNBOOK_VM_TAGS.md)) — they exist to populate a
sandbox with realistic shape and quantity so the production tools can be
exercised against substantial data.

## At a glance

| Phase | Script | What it does |
|---|---|---|
| **Load** | `tools/test/create_load_objects.py` | PUT bulk Groups + Services + Application Security Policies + Rules. Idempotent (re-running with same `--prefix` updates the same objects). |
| **Wipe** | `tools/test/wipe_app_policies_then_groups.py` | DELETE policies (all categories by default), then non-system groups, then optionally non-system services. System-owned objects always preserved. |

Both scripts support **Local Manager** and **Global Manager**, but they
use different conventions (a quirk worth knowing):

| Manager | Loader flag | Wiper flag |
|---|---|---|
| Local Manager (LM) | `--mode lm` | (omit `--federation-global`) |
| Global Manager (GM) | `--mode gm` | `--federation-global` |

---

## 1. `create_load_objects.py` — bulk loader

PUTs N groups, M services, P policies, and Q rules. Idempotent — same
`--prefix` updates the same objects.

### Required flags

| Flag | Purpose |
|---|---|
| `--mode {gm,lm}` | API surface to use. `gm` = `/global-manager/api/v1/global-infra`, `lm` = `/policy/api/v1/infra` |
| `--host` | Manager hostname (e.g. `nsx-lm3.lab.local`, `nsx-gm2.lab.local`) |
| `--user` / `--password` | Credentials (or env `NSX_USER` / `NSX_PASS`) |
| `--groups N` | Total groups |
| `--policies M` | Total Application-category policies |
| `--rules-per-policy R` | Rules each policy carries |
| `--groups-per-side S` | Groups assigned as source AND destination on each rule (random sample) |

### Common optional flags

| Flag | Default | Purpose |
|---|---|---|
| `--domain-id` | `default` | NSX domain to write into. On a GM this can be a domain that fronts an LM (e.g. `nsx-lm3.lab.local`). |
| `--prefix` | `loadtest` | Object id/name prefix. Two runs with different prefixes produce two independent loadouts. |
| `--seed` | `1337` | Random seed for rule-to-group / rule-to-service sampling — deterministic reproducibility. |
| `--throttle-rps` | `5.0` | Request rate cap; set `0` to disable throttling. |
| `--base-cidr` | `10.250.0.0/16` | Pool for generated IP material. |

### Per-group IP material

| Flag | Default | Purpose |
|---|---|---|
| `--subnets-per-group` | 5 | CIDRs per group |
| `--subnet-prefix` | 30 | Prefix length for those CIDRs |
| `--ranges-per-group` | 5 | IP-range tokens per group |
| `--range-width` | 2 | IPs per range |
| `--single-ips-per-group` | 0 | Bare IPs per group |

### Custom services (opt in with `--services > 0`)

| Flag | Default | Purpose |
|---|---|---|
| `--services X` | 0 | Custom L4 services to create. `0` = rules use built-in `ANY`. |
| `--ports-per-service P` | 1 | Destination ports per service (each service gets a unique contiguous port block starting at `--service-port-base`). |
| `--service-protocol {TCP,UDP}` | `TCP` | L4 protocol on the generated `L4PortSetServiceEntry`. |
| `--service-port-base` | 40000 | Starting port number, walks upward without colliding with NSX built-ins. |
| `--services-per-rule` | 1 | Custom services attached to each rule (random sample). Cannot exceed `--services`. |

### Phase ordering inside the loader

The script creates objects in dependency order so each subsequent layer
can reference the previous one:

1. Groups
2. Services (if `--services > 0`)
3. Policies
4. Rules (each rule references `--groups-per-side` groups on each side and `--services-per-rule` custom services, or `["ANY"]` if no custom services)

### Example — Local Manager load against `nsx-lm3`

```bash
NSX_USER=$(.venv/bin/python -c "from dotenv import dotenv_values; print(dotenv_values('.env')['NSX_USERNAME'])")
NSX_PASS=$(.venv/bin/python -c "from dotenv import dotenv_values; print(dotenv_values('.env')['NSX_PASSWORD'])")

NSX_USER="$NSX_USER" NSX_PASS="$NSX_PASS" \
  .venv/bin/python tools/test/create_load_objects.py \
  --mode lm --host nsx-lm3.lab.local \
  --groups 25 \
  --policies 20 \
  --rules-per-policy 5 \
  --groups-per-side 5 \
  --services 25 \
  --services-per-rule 5 \
  --service-protocol TCP \
  --ports-per-service 3 \
  --throttle-rps 10
```

Produces, in dependency order:

```
25 loadtest-grp-*       (each: 5 subnets + 5 ranges + 0 single IPs)
25 loadtest-svc-*       (TCP, ports 40000–40074, 3 ports per service)
20 loadtest-pol-*       (Application category)
100 rules               (loadtest-r-NNNN-MMMM, 5 src groups, 5 dst groups, 5 services each)
```

### Example — Global Manager load against `nsx-gm2`

Same shape but `--mode gm`. The script auto-rewrites group/service paths
under `/global-infra/...`:

```bash
NSX_USER="$NSX_USER" NSX_PASS="$NSX_PASS" \
  .venv/bin/python tools/test/create_load_objects.py \
  --mode gm --host nsx-gm2.lab.local \
  --groups 25 \
  --policies 20 \
  --rules-per-policy 5 \
  --groups-per-side 5 \
  --services 25 \
  --services-per-rule 5 \
  --service-protocol TCP \
  --ports-per-service 3 \
  --throttle-rps 10
```

### Loading multiple LM domains via the GM

A GM exposes each federated LM as a domain. The loader can fill each one
independently with a different prefix and base-CIDR:

```bash
# domain that fronts nsx-lm3 — uses 10.5.x.x for IP material
.venv/bin/python tools/test/create_load_objects.py \
  --mode gm --host nsx-gm2.lab.local \
  --domain-id nsx-lm3.lab.local \
  --prefix loadtest-lm3 \
  --base-cidr 10.5.0.0/16 \
  --groups 100 --policies 10 --rules-per-policy 20 --groups-per-side 3

# domain that fronts nsx-lm4 — uses 10.6.x.x
.venv/bin/python tools/test/create_load_objects.py \
  --mode gm --host nsx-gm2.lab.local \
  --domain-id nsx-lm4.lab.local \
  --prefix loadtest-lm4 \
  --base-cidr 10.6.0.0/16 \
  --groups 100 --policies 10 --rules-per-policy 20 --groups-per-side 3
```

---

## 2. `wipe_app_policies_then_groups.py` — wipe tool

Counterpart to the loader. Deletes objects in the reverse dependency
order so referential integrity holds at every step.

### Required flag

| Flag | Purpose |
|---|---|
| `--target` | Manager hostname. Defaults to `nsx_gm1` from `.env` if omitted. |

### Common flags

| Flag | Default | Purpose |
|---|---|---|
| `--domain-id` | `default` | Domain to operate on. |
| `--federation-global` | off | Use the GM API surface (`/global-infra/...`). **Required** when `--target` is a GM. |
| `--policy-categories` | (none → ALL) | Comma-separated list of policy categories to delete. Default is **every** category. Example: `Application,Infrastructure,Ethernet`. Case-insensitive. |
| `--include-services` | off | Also wipe non-system services after groups. NSX built-ins (WINS, DNS, etc.) preserved. |
| `--apply` | off (dry-run default) | Actually delete. Without this, the run is a preview. |
| `--verify-delay` | 2 | Seconds to wait before the post-wipe verification re-query. |
| `--verbose` | off | DEBUG-level logging. |

### Phase ordering inside the wiper

1. Security policies in scope (cascades to rules and removes references that pin groups in place)
2. Non-system groups (now safe to delete because rules referencing them are gone)
3. Non-system services (optional, only if `--include-services`)

This matters because NSX enforces referential integrity. Out of order
and the delete fails with `400 BAD_REQUEST: cannot be deleted as it is
being referenced by other objects`.

### Safety guards (always on)

- **System-owned objects skipped.** `_system_owned: true` is never deleted. NSX built-in groups (`Edge_NSGroup`, `SystemVM_NSGroup`, `ServiceInsertion_NSGroup`) and the 400+ built-in services (`WINS`, `DNS`, etc.) are always preserved.
- **NSX default sections cannot be deleted by any script.** Policies named `default-layer2-section` and `default-layer3-section` will appear in `failed_policies` with `Default policy ... cannot be deleted` from NSX. This is unavoidable — NSX rejects the request server-side.
- **Apply requires typed confirmation.** With `--apply`, the script prompts you to type the target hostname exactly before doing anything.
- **Dry-run is the default.** Without `--apply`, every action is logged with a `[DRY-RUN]` prefix and nothing changes.

### Example — wipe `nsx-lm3` (LM, everything)

```bash
# dry-run preview (default if --apply is absent)
PYTHONPATH="$PWD/app" python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-lm3.lab.local --domain-id default --include-services

# apply
PYTHONPATH="$PWD/app" python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-lm3.lab.local --domain-id default --include-services --apply
```

### Example — wipe `nsx-gm2` (GM, everything)

```bash
# dry-run preview
PYTHONPATH="$PWD/app" python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-gm2.lab.local --federation-global --include-services

# apply
PYTHONPATH="$PWD/app" python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-gm2.lab.local --federation-global --include-services --apply
```

### Example — restrict to a specific category

```bash
PYTHONPATH="$PWD/app" python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-lm3.lab.local \
  --policy-categories Application \
  --include-services \
  --apply
```

### Example — wipe a federated LM domain via the GM

```bash
PYTHONPATH="$PWD/app" python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-gm2.lab.local --federation-global \
  --domain-id nsx-lm3.lab.local \
  --include-services --apply
```

---

## End-to-end load / wipe cycle

```bash
# 1. Load
NSX_USER="$NSX_USERNAME" NSX_PASS="$NSX_PASSWORD" \
  .venv/bin/python tools/test/create_load_objects.py \
  --mode lm --host nsx-lm3.lab.local \
  --groups 25 --policies 20 --rules-per-policy 5 --groups-per-side 5 \
  --services 25 --services-per-rule 5 \
  --throttle-rps 10

# 2. Verify (optional)
PYTHONPATH="$PWD/app" python -c "
from nsx.cli_bootstrap import init_cli
from nsx.nsx_constants import resolve_manager
from nsx.nsx_policy_client import NsxPolicyClient
init_cli()
c = NsxPolicyClient(nsxmanager=resolve_manager('nsx-lm3'), federation_global=False)
print(f'groups: {len(c.list_groups())}, services: {len(c.list_services())}, policies: {len(c.list_security_policies())}')
"

# 3. Wipe (dry-run)
PYTHONPATH="$PWD/app" python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-lm3.lab.local --domain-id default --include-services

# 4. Wipe (apply)
PYTHONPATH="$PWD/app" python tools/test/wipe_app_policies_then_groups.py \
  --target nsx-lm3.lab.local --domain-id default --include-services --apply
```

Repeatable. Idempotent. Both managers (LM and GM) supported.

---

## Other test scripts in `tools/test/`

Older auxiliary tooling that predates the load/wipe pair. Mostly used
for ad-hoc import/export tree experiments.

| Script | Purpose |
|---|---|
| `add_groups_to_rules.py` | Append a range of existing groups (by prefix + numeric range) to existing rules' source / destination lists. Used after a load to bulk-reshape rule membership. |
| `build_nsx_import_tree.py` | Build a clean `nsx_import/` tree from a read-only `nsx_export/` tree, ready for compilation. |
| `compile_nsx_policies.py` | Compile each policy directory into a single payload file with rules embedded inline. |
| `prepare_export_for_push.py` | Strip server-managed metadata from exported objects to make them push-safe. |
| `push_nsx_object_tree.py` | Push a compiled `nsx_import/` tree to an NSX manager. Supports `--push-type {all,services,groups,rules}` for partial pushes. |
| `testing.md` | Older command-snippets file kept as a quick-reference card. |

Many of these have been superseded by the production runbook tools in
[`tools/nsx/`](tools/nsx/) but they're kept around for one-off scenarios
the production tools don't address.

---

## Recommended sandbox: `nsx-lm3`

Per the project's manager-role convention (recorded in agent memory):

- `nsx-lm1` — live source (read-only)
- `nsx-lm2` — apply target for the clone workflow
- `nsx-lm3` — **throwaway** sandbox, safe to load up and wipe at will
- `nsx-gm1` / `nsx-gm2` — Global Managers

Load testing usually targets `nsx-lm3` or `nsx-gm2`. If you load `nsx-lm1`
or `nsx-lm2` by accident, the wipe tool will clean it up — but doing
load/wipe cycles on those managers will interfere with the production
runbooks' rollback snapshots.
