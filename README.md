# Multi-Vendor Network Automation Toolkit

A workshop of Python tools for snapshotting, transforming, reporting on, and
selectively pushing distributed-firewall configuration — built around the
principle that **every push is reviewable, dry-runnable, and revertible**.

Started as an NSX-only DFW toolkit; expanding into a cross-vendor template
(NSX → Palo Alto → others) where the same operating model — capture, build,
push, revert, report — is replayed against each vendor's API or config format.

---

## What's where

```
.
├── tools/
│   ├── nsx/                  Mature NSX Policy API toolkit — capture, build, push, revert
│   ├── pan/                  Palo Alto Panorama tools — offline XML-driven (no API)
│   │   ├── configs/          (gitignored) drop Panorama running-config XMLs here
│   │   └── tests/fixtures/   synthetic + script-test XMLs (script-test-* gitignored)
│   ├── reports/              Cross-vendor report generators (rules-usage, etc.)
│   ├── vm_tags/              VM hostname → NSX tag automation
│   ├── test/                 Load-test scaffolding for the NSX tools
│   ├── bootstrap_server/     Local-host bootstrap helpers
│   └── archive/              Deprecated tools kept for one-off scenarios
│
├── app/
│   ├── nsx/                  Shared NSX policy client + CLI bootstrap + constants
│   ├── palo/                 Earlier PAN exploration (XML diff, test cases)
│   └── utilities/            Cross-tool helpers
│
├── docs/                     All runbooks + toolkit summaries (you're at the index here)
├── certificates/             PEM trust bundles for lab managers
├── nsx_logs/                 (gitignored) per-run logs + reports
└── nsx_<bundle>/             (gitignored) capture / transform / push artifacts
```

---

## Which runbook do I want?

### NSX workflows (mature, validated round-trip in lab)

| Workflow | Source → Target | Scope | Runbook |
|---|---|---|---|
| **A — Clone** — stand up a new LM with the same DFW config | `nsx-lm1` (live) → `nsx-lm2` (new) | services + groups + policies + rules | [docs/RUNBOOK_A.md](docs/RUNBOOK_A.md) |
| **B — Subnet remap in place** — rewrite group IPs on one LM using a CSV map | `nsx-lm1` → `nsx-lm1` | groups only (PATCH) | [docs/RUNBOOK_B.md](docs/RUNBOOK_B.md) |
| **C — Lab decomposition** — split tag+IP groups into siblings on a non-prod target | `nsx-lm1` → `nsx-lm3` | groups (sibling-decompose) + amend rules | [docs/RUNBOOK_C.md](docs/RUNBOOK_C.md) |
| **D — Production in-place remap to siblings** — additive prod amendment with Phase-2 forced strip option | `nsx-lm1` → `nsx-lm1` | groups + rules + optional Phase-2 strip | [docs/RUNBOOK_D.md](docs/RUNBOOK_D.md) |
| **VM hostname tagging** — give every regular VM an NSX tag matching its trailing digits | `nsx-lm1` → `nsx-lm1` | VM tags only (append, never replace) | [docs/RUNBOOK_VM_TAGS.md](docs/RUNBOOK_VM_TAGS.md) |
| **Capture-first variant of A+D** — single-capture clone + WF-D in one flow (lab validation pattern) | `nsx-lm1` → any non-prod | full | [docs/RUNBOOK_FROM_CAPTURE.md](docs/RUNBOOK_FROM_CAPTURE.md) |

Each runbook has a `_PS.md` PowerShell variant where applicable.

### Cross-vendor reports

| Report | What it does | Runbook |
|---|---|---|
| **Rules usage report** — every rule classified HOT / USED / STALE / UNUSED / DORMANT, with optional "no hits in N days" filter; works on LM or GM (full federation walk) | Read-only, GETs only, double-locked | [docs/RUNBOOK_RULES_USAGE.md](docs/RUNBOOK_RULES_USAGE.md) |

### Palo Alto (in progress)

| Tool | What it does | Status |
|---|---|---|
| **`tools/pan/check_policy_match.py`** — offline "can A reach B" policy lookup | Parses exported Panorama running-config XML; walks the full DG hierarchy in correct PAN-OS evaluation order; emits verdict + matched-rule + trace | v1 shipped, smoke-tested on real config |

---

## Quick-start

### Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r docker/requirements-pip.txt
export PYTHONPATH="$PWD/app"
```

Create a `.env` at the repo root (see existing fields by running any tool — they error clearly on missing config):

```
NSX_USERNAME=...
NSX_PASSWORD=...
NSX_LOG_DIR=$PWD/nsx_logs
```

### Most-common commands

```bash
# Read-only inventory snapshot of an NSX LM (creates capture bundle + IP coverage report)
python tools/nsx/capture_nsx_state.py --source nsx-lm1 --ip-report-csv data/nonprod_map.csv

# Rules-usage snapshot (real-time, read-only) — works against LM or GM (--all-domains on GM)
python tools/reports/report_rules_usage.py --target nsx-lm1
python tools/reports/report_rules_usage.py --target nsx-gm1 --federation-global --all-domains \
  --min-days-since-hit 365

# Offline Panorama policy lookup
python tools/pan/check_policy_match.py \
  --config tools/pan/configs/your-panorama.xml \
  --device-group YourDG \
  --src-ip 10.20.5.7 --dst-ip 192.168.10.42 \
  --protocol tcp --dst-port 443
```

---

## Design properties (repo-wide)

| Property | Meaning |
|---|---|
| **Read-only by default** | Every read tool only does HTTP GETs. The rules-usage report has an additional runtime lockdown on the client instance to refuse PUT/PATCH/POST/DELETE. The Panorama tool never opens a network socket at all. |
| **Dry-run is the default safe mode** | Every push tool requires an explicit `--apply` to write. Dry-runs emit the same diff artifacts as real applies, minus the API calls. |
| **Idempotent push** | Push tools handle "already exists" and 412 revision-conflict by falling back from PUT to PATCH automatically. |
| **Strict-additive amendments** | Group amendments never remove IPs unless `--intentional-ip-removal` is explicitly passed; rule amendments only ever append refs, never remove. |
| **LIFO baseline revert** | Every push tool captures a per-run baseline; revert pops the most-recent unreverted baseline. Reverts run in reverse phase order to avoid dangling refs. |
| **Per-run reports + logs** | Every step writes to `nsx_logs/<tool>/<host>/<UTC_TS>/` and a timestamped JSON report. |
| **Source state is never mutated** | The live source manager is never written to in any workflow. |
| **Offline review-able** | Capture bundles, transformed bundles, build dirs, and remapped trees are all on-disk artifacts diff-able before any push. |

---

## File and data conventions

| Pattern | Convention |
|---|---|
| `NSX_LOG_DIR=$PWD/nsx_logs` | All per-run reports and logs land here, gitignored |
| `nsx_capture/<host>/`, `nsx_groups_export/<host>/`, etc. | Per-tool bundles, gitignored (regenerable from source) |
| `tools/pan/configs/<x>.xml` | Drop real Panorama configs here — auto-gitignored |
| `tools/pan/tests/fixtures/panorama_running_config.xml` | Synthetic test fixture, tracked in git |
| `tools/pan/tests/fixtures/script-test-*.xml` | Real configs used as test inputs, gitignored by name pattern |
| Timestamps in filenames | Always UTC, `%Y%m%d_%H%M%S` |
| Manager aliases | `nsx-lm1` / `nsx-lm2` / `nsx-lm3` / `nsx-gm1` / `nsx-gm2` — resolved in `app/nsx/nsx_constants.py` |

---

## Status

| Area | State |
|---|---|
| NSX Workflows A / B / C / D | Validated round-trip in lab |
| NSX VM tagging | Validated, used in prod |
| NSX rules-usage report (LM + GM federation walk) | Shipped, double-locked read-only |
| PAN Panorama policy-lookup tool | v1 shipped, smoke-tested on real config |
| Cross-vendor abstraction layer | Not started — each vendor's toolkit is independent for now |

---

## Contributing conventions

- **No surprise writes.** Adding any new code path that mutates a vendor's state requires an explicit operator-supplied flag.
- **Reports go to `tools/reports/`.** Operational tools go to `tools/<vendor>/`.
- **Don't commit vendor configs.** Drop them in the gitignored directories.
- **Don't touch existing tools when adding new functionality** — prefer additive new tools over modifications to the well-tested ones.
- **All scripts pass `--target` aliases**, not hostnames or IPs. Hostnames live in `app/nsx/nsx_constants.py`.
