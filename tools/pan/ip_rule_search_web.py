#!/usr/bin/env python3
"""tools/pan/ip_rule_search_web.py

Local web UI for the Panorama IP-to-rule search. Serves a single page on
127.0.0.1 that accepts IP addresses, subnets, AND ranges (one per line,
same syntax as pan_ip_rule_targets.txt), pulls a FRESH configuration from
Panorama on every search (fresh keygen, fresh REST pulls; nothing cached),
runs the same matching engine as tools/pan/report_ips_in_rules.py, and
renders the results. Every search is also saved locally, and past runs are
listed in the page for one-click reload.

Read-only against Panorama, stdlib HTTP server only (no new deps), binds
loopback only; there is no auth because it never listens beyond 127.0.0.1.

USAGE:
    python tools/pan/ip_rule_search_web.py \
        --user-env agent_user --password-env agent_password --no-tls-verify
    # then open http://127.0.0.1:8765

    # other Panorama / port
    python tools/pan/ip_rule_search_web.py --host pano2.lab.local --port 9000 ...

Run history: pan_reports/<host>/web_ip_search/<UTC_TS>.json (one file per
search, inputs + full results).

Endpoints: GET / (page), POST /api/search, GET /api/runs, GET /api/run?id=
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "app"))

from palo.pan_ip_rules import apply_exclusions, match_rules, parse_ip_lines  # noqa: E402
from palo.pan_rest_client import PanRestClient, PanRestError  # noqa: E402

log = logging.getLogger("ip_rule_search_web")

DEFAULT_PORT = 8765
REPO_EXCLUDE_FILE = REPO_ROOT / "pan_ip_rule_exclude.txt"
RUN_ID_RE = re.compile(r"^\d{8}_\d{6}$")

CONFIG: Dict[str, Any] = {}   # filled from CLI args at startup


# =============================================================================
# Search execution (fresh client, fresh pulls, per request)
# =============================================================================

def pull_rules(client: PanRestClient, scope: str, rulebase: str) -> List[Dict[str, Any]]:
    resource = f"Policies/Security{rulebase.capitalize()}Rules"
    try:
        if scope == "shared":
            return client.entries(resource, location="shared")
        return client.entries(resource, device_group=scope)
    except PanRestError as exc:
        text = str(exc).lower()
        if exc.status_code == 404 or "not present" in text or "non exist" in text:
            return []
        raise


def run_search(payload: Dict[str, Any]) -> Dict[str, Any]:
    targets_text = payload.get("targets", "")
    exclusions_text = payload.get("exclusions", "")
    use_repo_exclusions = bool(payload.get("use_repo_exclusions", True))

    raw_targets, invalid = parse_ip_lines(targets_text)
    exclusions, invalid_excl = parse_ip_lines(exclusions_text)
    if use_repo_exclusions and REPO_EXCLUDE_FILE.exists():
        repo_excl, repo_invalid = parse_ip_lines(REPO_EXCLUDE_FILE.read_text(encoding="utf-8"))
        exclusions += repo_excl
        invalid_excl += repo_invalid
    invalid += [f"(exclusions) {x}" for x in invalid_excl]
    if not raw_targets:
        raise ValueError("No valid targets given (IPs, subnets, or ranges, one per line).")
    targets, excluded = apply_exclusions(raw_targets, exclusions)

    client = PanRestClient.from_env(user_env=CONFIG["user_env"],
                                    password_env=CONFIG["password_env"],
                                    host=CONFIG["host"])
    all_dgs = client.list_device_groups()
    wanted = [d.strip() for d in (payload.get("device_groups") or "").split(",") if d.strip()]
    unknown = sorted(set(wanted) - set(all_dgs))
    if unknown:
        raise ValueError(f"Unknown device groups: {unknown} (available: {all_dgs})")
    dgs = wanted or all_dgs

    shared_addresses = client.list_addresses(location="shared")
    shared_groups = client.list_address_groups(location="shared")

    scope_results: List[Dict[str, Any]] = []

    def run_scope(scope: str, addresses, groups) -> None:
        for rulebase in ("pre", "post"):
            rules = pull_rules(client, scope, rulebase)
            scope_results.append(match_rules(rules, addresses, groups, targets,
                                             scope=scope, rulebase=rulebase))

    if payload.get("include_shared", True):
        run_scope("shared", shared_addresses, shared_groups)
    for dg in dgs:
        dg_addresses = client.list_addresses(device_group=dg)
        dg_groups = client.list_address_groups(device_group=dg)
        run_scope(dg, dg_addresses + shared_addresses, dg_groups + shared_groups)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    result = {
        "run_id": run_id,
        "meta": {
            "ran_at": datetime.now(timezone.utc).isoformat(),
            "target": client.env.url,
            "username": client.username,
            "device_groups": dgs,
            "read_only": True,
            "firewalls_contacted": False,
        },
        "inputs": {"targets": targets_text, "exclusions": exclusions_text,
                   "use_repo_exclusions": use_repo_exclusions,
                   "repo_exclude_file": str(REPO_EXCLUDE_FILE) if use_repo_exclusions else None,
                   "device_groups": payload.get("device_groups") or ""},
        "totals": {
            "targets_searched": len(targets),
            "targets_excluded": len(excluded),
            "rules_matched": sum(len(sr["matched_rules"]) for sr in scope_results),
            "any_any_rules": sum(len(sr["any_any_rules"]) for sr in scope_results),
        },
        "targets": [t["raw"] for t in targets],
        "excluded": [{"raw": t["raw"], "excluded_by": t["excluded_by"]} for t in excluded],
        "invalid_lines": invalid,
        "scopes": scope_results,
    }
    run_dir = runs_dir(client.env.hostname)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / f"{run_id}.json").write_text(json.dumps(result, indent=2) + "\n",
                                            encoding="utf-8")
    log.info("Search %s: %d targets, %d matches (saved %s)", run_id,
             len(targets), result["totals"]["rules_matched"], run_dir / f"{run_id}.json")
    return result


def runs_dir(hostname: str) -> Path:
    return REPO_ROOT / "pan_reports" / hostname.split(".")[0] / "web_ip_search"


def list_runs() -> List[Dict[str, Any]]:
    d = runs_dir(CONFIG["display_host"])
    if not d.exists():
        return []
    out = []
    for f in sorted(d.glob("*.json"), reverse=True)[:50]:
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
            out.append({"run_id": r["run_id"], "ran_at": r["meta"]["ran_at"],
                        "totals": r["totals"], "targets": r["targets"][:8]})
        except (ValueError, KeyError):
            continue
    return out


def load_run(run_id: str) -> Dict[str, Any] | None:
    if not RUN_ID_RE.match(run_id):
        return None
    f = runs_dir(CONFIG["display_host"]) / f"{run_id}.json"
    if not f.exists():
        return None
    return json.loads(f.read_text(encoding="utf-8"))


# =============================================================================
# Page
# =============================================================================

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Panorama IP Rule Search</title>
<style>
:root { color-scheme: light dark;
  --bg:#f6f7f9; --panel:#ffffff; --ink:#1a2330; --muted:#5b6878;
  --line:#dde3ea; --accent:#0e7490; --accent-ink:#ffffff; --bad:#b4232a; }
@media (prefers-color-scheme: dark) { :root {
  --bg:#12161c; --panel:#1a2029; --ink:#e6ebf2; --muted:#8fa0b3;
  --line:#2a3442; --accent:#22a3bf; --accent-ink:#0b1015; --bad:#ef6a70; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
  font:14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; }
header { padding:14px 22px; border-bottom:1px solid var(--line);
  display:flex; align-items:baseline; gap:14px; flex-wrap:wrap; }
header h1 { font-size:17px; margin:0; }
header .sub { color:var(--muted); font-size:12.5px; }
.layout { display:grid; grid-template-columns:300px 1fr; gap:18px;
  padding:18px 22px; max-width:1500px; }
@media (max-width: 900px){ .layout { grid-template-columns:1fr; } }
.panel { background:var(--panel); border:1px solid var(--line);
  border-radius:8px; padding:14px; }
label { display:block; font-weight:600; margin:10px 0 4px; font-size:13px; }
label:first-child { margin-top:0; }
textarea, input[type=text] { width:100%; background:var(--bg); color:var(--ink);
  border:1px solid var(--line); border-radius:6px; padding:8px;
  font:12.5px/1.5 ui-monospace, Menlo, monospace; }
textarea { resize:vertical; }
.hint { color:var(--muted); font-size:12px; margin:2px 0 0; }
.row { display:flex; align-items:center; gap:8px; margin-top:10px; font-size:13px; }
button { margin-top:14px; width:100%; padding:9px; border:0; border-radius:6px;
  background:var(--accent); color:var(--accent-ink); font-weight:700;
  font-size:14px; cursor:pointer; }
button:disabled { opacity:.5; cursor:wait; }
.err { color:var(--bad); font-size:13px; margin-top:10px; white-space:pre-wrap; }
.chips { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:14px; }
.chip { background:var(--panel); border:1px solid var(--line); border-radius:8px;
  padding:8px 14px; }
.chip b { font-size:19px; display:block; }
.chip span { color:var(--muted); font-size:12px; }
h2 { font-size:14px; margin:20px 0 8px; }
table { border-collapse:collapse; width:100%; background:var(--panel);
  border:1px solid var(--line); border-radius:8px; overflow:hidden; font-size:12.5px; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); }
th { background:color-mix(in srgb, var(--panel) 60%, var(--bg)); font-size:12px; }
tr:last-child td { border-bottom:0; }
td code { font:12px ui-monospace, Menlo, monospace; }
.flag { color:var(--bad); font-weight:600; }
.none { color:var(--muted); font-style:italic; }
.tblwrap { overflow-x:auto; }
#runs { list-style:none; margin:6px 0 0; padding:0; }
#runs li { padding:7px 8px; border:1px solid var(--line); border-radius:6px;
  margin-bottom:6px; cursor:pointer; font-size:12.5px; }
#runs li:hover { border-color:var(--accent); }
#runs .when { color:var(--muted); font-size:11.5px; }
.readonly { font-size:11.5px; color:var(--muted); margin-top:12px; }
</style>
</head>
<body>
<header>
  <h1>Panorama IP Rule Search</h1>
  <span class="sub" id="server-info"></span>
</header>
<div class="layout">
  <div>
    <div class="panel">
      <label for="targets">Search targets</label>
      <textarea id="targets" rows="7" placeholder="10.1.1.5&#10;10.2.1.0/24&#10;10.1.1.5-10.1.1.20"></textarea>
      <p class="hint">IPs, subnets (CIDR), or ranges. One per line, # comments OK.</p>
      <label for="exclusions">Extra exclusions (optional)</label>
      <textarea id="exclusions" rows="3" placeholder="10.3.0.0/16"></textarea>
      <div class="row">
        <input type="checkbox" id="repo-excl" checked>
        <label for="repo-excl" style="margin:0;font-weight:400">also apply pan_ip_rule_exclude.txt</label>
      </div>
      <label for="dgs">Device groups (optional)</label>
      <input type="text" id="dgs" placeholder="all (or: dg-4,dg-5)">
      <button id="go">Search (pulls fresh config)</button>
      <div class="err" id="error"></div>
      <div class="readonly">Read-only. Fresh keygen + REST pull every search.
        Firewalls are never contacted. Runs saved under pan_reports/.</div>
    </div>
    <div class="panel" style="margin-top:14px">
      <label style="margin-top:0">Previous runs</label>
      <ul id="runs"></ul>
    </div>
  </div>
  <div id="results"><p class="none">No search yet.</p></div>
</div>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"]/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

function table(headers, rows) {
  if (!rows.length) return '<p class="none">(none)</p>';
  return '<div class="tblwrap"><table><tr>' +
    headers.map(h => `<th>${esc(h)}</th>`).join("") + "</tr>" +
    rows.map(r => "<tr>" + r.map(c => `<td>${c}</td>`).join("") + "</tr>").join("") +
    "</table></div>";
}

function render(r) {
  const t = r.totals;
  const matchRows = [], anyRows = [];
  for (const sr of r.scopes) {
    for (const rule of sr.matched_rules) {
      const flags = [rule.disabled ? "DISABLED" : "",
                     rule.any_sides.length ? "any on " + rule.any_sides.join("/") : ""]
                    .filter(Boolean).join(", ");
      for (const m of rule.matches) {
        const via = m.via ? ` <span class="none">via group ${esc(m.via)}</span>` : "";
        matchRows.push([esc(sr.scope), esc(sr.rulebase), esc(rule.rule),
          esc(rule.action || ""), `<span class="flag">${esc(flags)}</span>`,
          `<code>${esc(m.target)}</code>`, esc(m.side),
          `${esc(m.member)} = <code>${esc(m.value)}</code>${via}`]);
      }
    }
    for (const name of sr.any_any_rules)
      anyRows.push([esc(sr.scope), esc(sr.rulebase), esc(name)]);
  }
  const matched = new Set();
  for (const sr of r.scopes) for (const rule of sr.matched_rules)
    for (const m of rule.matches) matched.add(m.target);
  const noMatch = r.targets.filter(x => !matched.has(x)).map(x => [`<code>${esc(x)}</code>`]);
  const exclRows = r.excluded.map(e => [`<code>${esc(e.raw)}</code>`, `<code>${esc(e.excluded_by)}</code>`]);
  const invRows = r.invalid_lines.map(x => [`<code>${esc(x)}</code>`]);

  $("results").innerHTML = `
    <div class="chips">
      <div class="chip"><b>${t.targets_searched}</b><span>targets searched</span></div>
      <div class="chip"><b>${t.rules_matched}</b><span>rule matches</span></div>
      <div class="chip"><b>${t.any_any_rules}</b><span>any/any rules</span></div>
      <div class="chip"><b>${t.targets_excluded}</b><span>excluded</span></div>
    </div>
    <p class="hint">Run ${esc(r.run_id)} at ${esc(r.meta.ran_at)} against
      ${esc(r.meta.target)} as ${esc(r.meta.username)}</p>
    <h2>Rules matching the targets</h2>
    ${table(["Scope","Rulebase","Rule","Action","Flags","Target","Side","Matched through"], matchRows)}
    <h2>Global any/any rules (match every IP)</h2>
    ${table(["Scope","Rulebase","Rule"], anyRows)}
    <h2>Targets with no matches</h2>${table(["Target"], noMatch)}
    <h2>Excluded targets</h2>${table(["Target","Excluded by"], exclRows)}
    ${invRows.length ? "<h2>Invalid input lines</h2>" + table(["Line"], invRows) : ""}`;
}

async function refreshRuns() {
  const runs = await (await fetch("/api/runs")).json();
  $("runs").innerHTML = runs.length ? runs.map(r =>
    `<li data-id="${esc(r.run_id)}">
       <div><b>${r.totals.rules_matched}</b> matches, ${r.totals.targets_searched} targets
         ${r.totals.targets_excluded ? `(${r.totals.targets_excluded} excluded)` : ""}</div>
       <div><code>${esc(r.targets.join(", "))}</code></div>
       <div class="when">${esc(r.ran_at)}</div></li>`).join("")
    : '<li class="none" style="cursor:default">none yet</li>';
  for (const li of $("runs").querySelectorAll("li[data-id]"))
    li.onclick = async () => {
      const run = await (await fetch("/api/run?id=" + li.dataset.id)).json();
      if (!run.error) { render(run); fillInputs(run.inputs); }
    };
}

function fillInputs(i) {
  if (!i) return;
  $("targets").value = i.targets || "";
  $("exclusions").value = i.exclusions || "";
  $("repo-excl").checked = !!i.use_repo_exclusions;
  $("dgs").value = i.device_groups || "";
}

$("go").onclick = async () => {
  $("error").textContent = "";
  $("go").disabled = true;
  $("go").textContent = "Pulling fresh config and searching...";
  try {
    const resp = await fetch("/api/search", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        targets: $("targets").value,
        exclusions: $("exclusions").value,
        use_repo_exclusions: $("repo-excl").checked,
        device_groups: $("dgs").value,
      })});
    const data = await resp.json();
    if (data.error) $("error").textContent = data.error;
    else { render(data); refreshRuns(); }
  } catch (e) { $("error").textContent = String(e); }
  $("go").disabled = false;
  $("go").textContent = "Search (pulls fresh config)";
};

fetch("/api/info").then(r => r.json()).then(i => {
  $("server-info").textContent =
    `${i.target} as ${i.username_source} (read-only)`; });
refreshRuns();
</script>
</body>
</html>
"""


# =============================================================================
# HTTP server
# =============================================================================

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # route access logs through logging
        log.debug("%s " + fmt, self.address_string(), *args)

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/api/runs":
            self._json(list_runs())
        elif self.path == "/api/info":
            self._json({"target": CONFIG["display_target"],
                        "username_source": CONFIG["user_env"] or "PANORAMA_* resolution"})
        elif self.path.startswith("/api/run?"):
            run_id = (self.path.split("id=", 1) + [""])[1].split("&")[0]
            run = load_run(run_id)
            self._json(run if run else {"error": f"run {run_id!r} not found"},
                       200 if run else 404)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if self.path != "/api/search":
            self._json({"error": "not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            self._json(run_search(payload))
        except ValueError as exc:
            self._json({"error": str(exc)}, 400)
        except PanRestError as exc:
            self._json({"error": f"Panorama pull failed: {exc}"}, 502)
        except Exception as exc:  # keep the server alive on surprises
            log.exception("search failed")
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("USAGE:", 1)[1] if "USAGE:" in __doc__ else None)
    parser.add_argument("--host", default=None, help="Target Panorama hostname (overrides .env).")
    parser.add_argument("--user-env", default=None,
                        help="Env var holding the username (e.g. agent_user).")
    parser.add_argument("--password-env", default=None,
                        help="Env var holding the password (e.g. agent_password).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Listen port on 127.0.0.1 (default {DEFAULT_PORT}).")
    parser.add_argument("--no-tls-verify", action="store_true",
                        help="Disable TLS certificate verification toward Panorama.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s UTC [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S", stream=sys.stderr)
    logging.Formatter.converter = time.gmtime

    if args.no_tls_verify:
        os.environ["PANORAMA_TLS_VERIFY"] = "false"

    # Resolve once at startup so a broken .env fails fast, then per-search
    # clients are built fresh from the same settings.
    try:
        probe = PanRestClient.from_env(user_env=args.user_env,
                                       password_env=args.password_env, host=args.host)
    except PanRestError as exc:
        log.error("%s", exc)
        return 2
    CONFIG.update({
        "user_env": args.user_env, "password_env": args.password_env,
        "host": args.host, "display_host": probe.env.hostname,
        "display_target": probe.env.url,
    })

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    log.info("Panorama IP Rule Search UI: http://127.0.0.1:%d (target %s, loopback only)",
             args.port, probe.env.url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
