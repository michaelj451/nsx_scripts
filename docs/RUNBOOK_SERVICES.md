# Runbook — Services-Only Export + Push

## Summary

One tool, two subcommands. Export NSX customer-defined services from a
source manager into per-service YAMLs, then push those YAMLs to a target.
Used for debugging services in isolation, or pushing just services without
dragging the rest of the policy payload along.

| Subcommand | Purpose |
|---|---|
| `services.py export` | Read `/policy/api/v1/infra/services`, save each as a YAML on disk. GET-only. |
| `services.py push` | Read those YAMLs, PUT/PATCH each to a target. Live per-service progress. |

> `--source` / `--target` are aliases resolved from `.env` (e.g. `NSX_LM1=nsx-lm1.lab.local`). Each command below annotates the resolved FQDN inline.

---

## Env

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

---

## 1. Export services from source

```bash
# Source: nsx-lm1 → https://nsx-lm1.lab.local
python tools/nsx/services.py export --source nsx-lm1
```

Output (overwritten each run when default path is used):

```
nsx_services_export/<source-host>/
├── manifest.json                              counts + per-service status
├── logs/services_export_<UTC_TS>.log
└── services/
    ├── <slug>__<id-prefix>.yaml               one file per customer service
    └── ...
```

Behavior:
- Skips NSX system-owned services (default). Pass `--include-system` to keep them.
- Strips read-only NSX metadata (`_create_time`, `_revision`, `unique_id`, etc.) so pushes don't conflict with the target's view.
- Filenames capped at ~50 chars with a hash suffix on truncation (Windows MAX_PATH safe).

---

## 2. Push services to target

### 2a. Dry-run (default — no writes)

```bash
# Target: nsx-lm2 → https://nsx-lm2.lab.local
python tools/nsx/services.py push \
  --target nsx-lm2 \
  --services-dir nsx_services_export/nsx-lm1.lab.local/services
```

Iterates every YAML, parses, confirms the `id` field, prints what would be pushed. No NSX writes.

### 2b. Apply

```bash
# Target: nsx-lm2 → https://nsx-lm2.lab.local
python tools/nsx/services.py push \
  --target nsx-lm2 \
  --services-dir nsx_services_export/nsx-lm1.lab.local/services \
  --apply
```

Live per-service progress on stderr as each one lands:

```
[1/12  ok=1  fail=0  skip=0] my-service-id — success_put
[2/12  ok=2  fail=0  skip=0] another-service — success_patch
[3/12  ok=2  fail=1  skip=0] broken-svc — FAILED: [HTTP 400] ...
[4/12  ok=3  fail=1  skip=0] next-svc — success_patch
...
```

Outcome tokens:
- `success_put` — created cleanly on the target (didn't exist)
- `success_patch` — existed already (`500127`) or revision mismatch (`500071`); the tool retried with PATCH and that worked
- `FAILED: …` — actual error; full HTTP code and NSX message captured in the row
- `skip` — file had no `id`, or was an excluded filename (`manifest.json`, etc.)

Reports land at `<services-dir>/../push_report/`:

```
push_report/
├── services_push_<UTC_TS>.log
├── summary.json                  totals + target + log_file
├── services.json                 one row per service file processed
├── services.jsonl                same data, one row per line for grep/jq
└── failures.json                 (only if any failed) — just the failed rows
```

---

## Rollback

`services.py push` doesn't capture a target baseline by itself — it's intentionally narrow. If you need to roll back the services you just pushed, the simplest paths are:

**Option A — you had a pre-push baseline:** run a `capture_nsx_state.py` of the target BEFORE the push, then use `push_complete_nsx_revert.py --include-services --apply` against that baseline.

**Option B — you only want to remove services you just pushed:** the `push_services` reports list every service id that landed. Delete them individually via NSX UI / API, or via a small script that reads `services.jsonl` and calls `client.delete_service(id)`.

For the standard "push and rollback if it fails" pattern, use Workflow A's `push_from_capture.py` instead — that wraps the baseline capture, push, and validation in one tool.

---

## Common questions

**Can I push the same services back to the same manager?**
Yes — idempotent. PUT will return "already exists" (`500127`), the tool falls back to PATCH, and PATCHing the same payload is a no-op on NSX.

**Will this push the EtherType / ICMP / ALG / Nested service entries?**
Yes. The tool is type-agnostic. It preserves `service_type` (`NON_ETHER` / `ETHER` / `OTHER`) and every `service_entries[].resource_type` (`L4PortSetServiceEntry`, `ICMPTypeServiceEntry`, `IGMPTypeServiceEntry`, `IPProtocolServiceEntry`, `ALGTypeServiceEntry`, `EtherTypeServiceEntry`, `NestedServiceServiceEntry`) byte-for-byte.

**What if a service depends on another service (`NestedServiceServiceEntry`)?**
The pusher iterates files in lexical order. If a nested service references one that hasn't been pushed yet, NSX returns `500232 "dependent objects … does not exist"` and the push fails for that file. Re-run after the dependency lands, or share which two services collide and we can add a topological-sort pass.

**Pushing back to the same source — what does that prove?**
Round-trip integrity: the exported YAML is a valid representation NSX can re-accept. We've used this to confirm the export step doesn't drop fields the push step needs.

---

## Inner tools

| Tool | Used by |
|---|---|
| `app/nsx/nsx_policy_client.py` — `NsxPolicyClient.put_service` / `patch_service` / `list_services` | `services.py` |
| `_policy_path("/services")` | Underlying URL builder |
