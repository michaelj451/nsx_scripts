# RUNBOOK: Panorama API Performance Test

Tool: `tools/pan/perf_test_panorama.py`

Read-only benchmark of a Panorama's XML API. Sends only keygen, operational
`show` commands, and config gets. Nothing is written to Panorama: no set/edit,
no commits, no candidate changes.

## What it measures

| Phase | What | Default samples |
|-------|------|-----------------|
| 1 | Transport: DNS resolve, TCP connect, TLS handshake | 10 each |
| 2 | Authentication: keygen latency (or stored key check) | 1 |
| 3 | Op commands: system info, clock, devices connected, devicegroups, templates | 10 each |
| 4 | Config reads: device-groups, shared address, shared pre-rules xpaths | 10 each |
| 5 | Full running-config pull (size + transfer throughput) | 3 |
| 6 | Concurrency: cheapest op at 1/4/8 parallel workers, throughput + latency spread | 24 requests per level |

`show system resources` is snapshotted before and after so the report records
what the Panorama itself was doing (load average, task counts).

## Target and credentials

Defaults come from `.env` (same variables as every other pan tool; see
`app/palo/pan_env.py`). `--host` overrides the hostname; when it differs from
the `.env` host, any stored `PANORAMA_API_KEY` is ignored (keys are
per-device) and a fresh keygen runs against the override host using the
`.env` username/password.

## Usage

```bash
export PYTHONPATH="$PWD/app"

# Always dry-run first: prints the resolved target and plan, sends nothing
python tools/pan/perf_test_panorama.py --host pano2.lab.local --dry-run

# Full run (lab Panoramas use self-signed certs)
python tools/pan/perf_test_panorama.py --host pano2.lab.local --no-tls-verify

# Heavier sampling
python tools/pan/perf_test_panorama.py --host pano2.lab.local --no-tls-verify \
    --iterations 25 --concurrency 1,4,8,16 --requests-per-level 40

# Skip the full-config pull on a large production Panorama
python tools/pan/perf_test_panorama.py --skip-full-config
```

Exit codes: 0 all phases completed, 1 a phase failed (partial results still
reported), 2 unusable target/arguments.

Reports (no secrets; API key fingerprint only) land in
`.pano_reports/perf_test_<host>_<UTC ts>.json`.

## Baseline: pano2.lab.local (2026-09-03, PAN-OS test box, near-empty config)

- Transport: sub-5 ms everything (local LAN)
- keygen: 0.6 to 1.8 s (first-call variance)
- Op floor: ~210 ms per call (`show devices connected`, `show templates`)
- `show system info`: ~700 ms avg
- `show clock` via op: ~320 ms
- Config gets: ~215 ms avg regardless of xpath (config nearly empty, 56 B results)
- Full running config: 3.8 KB in ~220 ms
- Concurrency: 2.8 req/s at 1 worker, 11.4 at 4, ~20 at 8; p95 grew from
  ~360 ms to ~500 ms at 8 workers, zero errors; load average unchanged
  (~0.4 before and after)

Interpretation: this Panorama has a per-request floor around 200 ms that
dominates small reads, so batching (bigger xpath gets) and modest parallelism
(4 to 8 workers) are both worthwhile for future pan tools. Rules of that
shape are already how the NSX toolkit paginates; same idea applies here.
