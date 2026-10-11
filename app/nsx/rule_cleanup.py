"""app/nsx/rule_cleanup.py

Shared pieces of the unused-rule cleanup scripts in tools/nsx/rule_cleanup/,
for one NSX Local Manager:

    step 1  disable every customer DFW rule that has never been hit
    step 2  after a soak period, delete those rules, then every customer
            policy left with no rules and every customer group that nothing
            references any more

Services are never touched. NSX's own objects (the Default Layer2/Layer3
sections and their rules, built-in groups, anything is_default,
_system_owned or created by NSX itself) are never changed. Each step plans
first (dry run, read only) and its --apply carries out only the reviewed
plan, re-checking every object live right before writing it.

"Never used" means NSX returned a counter row for the rule and its hit,
packet, byte and session counts are all 0. NSX counts from the rule's
creation (or the last statistics reset). A rule with no counter row is
NO_STATS and is never touched. NSX 3.2.x answers the Policy-API statistics
call with HTTP 500, even for local policies, so the counters fall back to the
older firewall API on the same manager, exactly as report_rules_usage does.

One folder per run:

    <runs dir>/<target>/<UTC_TS>/
        run.json                  what each script did
        step1/plan.json, plan.md  every customer rule: counters, class, full JSON
        step1/disabled.json       rules step 1 disabled, full JSON after the
                                  write (step1_undo.py and step 2 read it)
        step2/plan.json, plan.md  what step 2 deletes
        step2/before_<ts>.json    policies, rules and groups before each apply
        step2/deleted.json        every deleted object, full JSON, in delete
                                  order (step2_undo.py puts them back)
        logs/

<runs dir> is --runs-dir, else $NSX_CLEANUP_RUNS_DIR, else
<repo>/nsx_cleanup_runs.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from common.bundles import new_run_dir, timestamped_dirs
from nsx.critical_rules import is_system_default

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_BASE = REPO_ROOT / "nsx_cleanup_runs"
RUNS_ENV = "NSX_CLEANUP_RUNS_DIR"
DOMAIN = "default"

DEFAULT_SECTION_IDS = {"default-layer3-section", "default-layer2-section"}
COUNTERS = ("hit_count", "packet_count", "byte_count", "session_count")
DENY_ACTIONS = {"DROP", "REJECT"}

# Step 1 classes. Only DISABLE is written by step 1; ALREADY_DISABLED rules
# are step 2 candidates with --include-pre-disabled.
DISABLE = "DISABLE"
ALREADY_DISABLED = "ALREADY_DISABLED"
USED = "USED"
NO_STATS = "NO_STATS"
TOO_NEW = "TOO_NEW"
KEEP_DENY = "KEEP_DENY"
CLASS_ORDER = (DISABLE, ALREADY_DISABLED, KEEP_DENY, TOO_NEW, NO_STATS, USED)

# Fields NSX manages itself (same set as the push tools strip). Never
# compared, never sent when re-creating an object.
STRIP_KEYS = {
    "_create_time", "_create_user", "_last_modified_time", "_last_modified_user",
    "_revision", "revision", "_protection", "_system_owned",
    "marked_for_delete", "overridden", "remote_path",
    "realization_id", "unique_id", "origin_site_id", "owner_id",
    "_links", "_schema", "_self", "status", "children",
}
# Also left out of content comparisons: a re-created rule gets a new internal id.
VOLATILE_KEYS = STRIP_KEYS | {"rule_id"}

# Where else NSX can reference a group. Each is read and every group path
# found anywhere in it counts as a reference. NSX refuses to delete a group
# that is still referenced, which backs this list up.
CONSUMER_FAMILIES = ("gateway-policies", "intrusion-service-policies",
                     "intrusion-service-gateway-policies", "redirection-policies",
                     "forwarding-policies", "endpoint-policies")
CONSUMER_OBJECTS = ("/settings/firewall/security/exclude-list",)
CONSUMER_LISTS = ("/lb-pools", "/lb-virtual-servers")
NOT_AVAILABLE = (400, 404)   # the feature or endpoint does not exist on this manager

GROUP_PATH_RE = re.compile(r"^/infra/domains/[^/]+/groups/[^/]+$")
SELF_KEYS = {"path", "parent_path", "relative_path", "remote_path", "id",
             "unique_id", "realization_id", "_links", "_self"}


# =============================================================================
# Run folders and the run record
# =============================================================================

def runs_base(runs_dir: Optional[str] = None) -> Path:
    """Where runs are stored: --runs-dir, else $NSX_CLEANUP_RUNS_DIR, else <repo>/nsx_cleanup_runs."""
    chosen = runs_dir or os.environ.get(RUNS_ENV)
    return Path(chosen).expanduser().resolve() if chosen else RUNS_BASE


def add_runs_dir_arg(parser: Any) -> None:
    parser.add_argument("--runs-dir", default=None,
                        help=f"folder that holds the runs (default: ${RUNS_ENV}, else <repo>/nsx_cleanup_runs)")


def next_command(script: str, args: Any, extra: str = "") -> str:
    """A ready-to-paste command for the next script, carrying --runs-dir if it was given."""
    cmd = f"python tools/nsx/rule_cleanup/{script} --target {args.target}"
    if getattr(args, "runs_dir", None):
        cmd += f' --runs-dir "{args.runs_dir}"'
    return f"{cmd} {extra}".rstrip()


def new_run(target: str, target_host: str, base: Path = RUNS_BASE) -> Path:
    run = new_run_dir(base / target)
    save_record(run, {"target": target, "target_host": target_host,
                      "created_at": datetime.now(timezone.utc).isoformat(),
                      "steps": {}, "history": []})
    return run


def resolve_run(target: str, run: Optional[str] = None, base: Path = RUNS_BASE) -> Path:
    """The --run folder if given, else the newest run for this target."""
    if run:
        p = Path(run).expanduser().resolve()
        if not (p / "run.json").is_file():
            raise SystemExit(f"not a rule-cleanup run folder (no run.json): {p}")
        return p
    runs = timestamped_dirs(base / target)
    if not runs:
        raise SystemExit(f"no run for {target} under {base / target}; start one with step1_disable.py")
    return runs[-1]


def load_record(run: Path) -> Dict[str, Any]:
    return json.loads((run / "run.json").read_text(encoding="utf-8"))


def save_record(run: Path, rec: Dict[str, Any]) -> None:
    write_json(run / "run.json", rec)


def record_step(run: Path, step: str, data: Dict[str, Any]) -> None:
    """Keep the latest result per step plus every result in history."""
    rec = load_record(run)
    data = {"step": step, "at": datetime.now(timezone.utc).isoformat(), **data}
    rec.setdefault("steps", {})[step] = data
    rec.setdefault("history", []).append(data)
    save_record(run, rec)


def check_run(rec: Dict[str, Any], target: str, host_now: str) -> None:
    """Refuse a run made for another manager, or an alias that now resolves
    to a different host than the one the run was planned against."""
    if rec.get("target") != target:
        raise SystemExit(f"run is for {rec.get('target')}, not {target}")
    if host_now != rec.get("target_host"):
        raise SystemExit(f"{target} now resolves to {host_now!r} but this run was planned against "
                         f"{rec.get('target_host')!r}; fix .env (NSX_LM*) or start a new run")


def read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    """Write through a temp file, so an interrupted run never leaves half a record."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


# =============================================================================
# Hit counters
# =============================================================================

def _rru():
    """tools/reports/report_rules_usage.py: its stats parsers, fallback and read-only lock."""
    tools_reports = str(REPO_ROOT / "tools" / "reports")
    if tools_reports not in sys.path:
        sys.path.insert(0, tools_reports)
    import report_rules_usage as rru   # noqa: E402
    return rru


def lock_read_only(client: Any) -> None:
    """Make every write on this client instance raise before any HTTP request."""
    _rru()._lock_client_read_only(client)


def policy_counters(client: Any, policy: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], str, Optional[str]]:
    """Counter rows for one policy's rules, keyed by internal rule id.

    Policy API first; if it fails or returns nothing, the old firewall API on
    the same manager. Returns (rows, source, policy_api_error) with source
    policy_api, old_firewall_api or none.
    """
    rru = _rru()
    err = None
    try:
        rows = rru._flatten_policy_stats(client.get_security_policy_statistics(
            security_policy_id=policy["id"], domain_id=DOMAIN))
        if rows:
            return rows, "policy_api", None
    except Exception as exc:
        err = str(exc)[:200]
    rows = rru._fetch_stats_via_old_firewall_api(client, policy.get("display_name") or policy["id"])
    return (rows, "old_firewall_api", err) if rows else ({}, "none", err)


def rule_usage(rule: Dict[str, Any], rows: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, int]]:
    """The rule's counters, or None when NSX returned no row for it."""
    row = rows.get(str(rule.get("rule_id") or ""))
    if row is None:
        return None
    return {k: int(row.get(k) or 0) for k in COUNTERS}


def age_days(obj: Dict[str, Any], now_ms: int) -> Optional[int]:
    created = obj.get("_create_time")
    if not created:
        return None
    return max(0, int((now_ms - int(created)) // 86_400_000))


def is_cleanup_policy(policy: Dict[str, Any]) -> bool:
    """A customer DFW policy these scripts may change (never NSX's default sections)."""
    return not is_system_default(policy) and policy.get("id") not in DEFAULT_SECTION_IDS


def classify(rule: Dict[str, Any], usage: Optional[Dict[str, int]], *, now_ms: int,
             min_age_days: int = 0, keep_deny: bool = False) -> str:
    if usage is None:
        return NO_STATS
    if any(usage.values()):
        return USED
    if min_age_days:
        age = age_days(rule, now_ms)
        if age is None or age < min_age_days:
            return TOO_NEW
    if rule.get("disabled"):
        return ALREADY_DISABLED
    if keep_deny and str(rule.get("action") or "").upper() in DENY_ACTIONS:
        return KEEP_DENY
    return DISABLE


# =============================================================================
# Comparing and writing objects
# =============================================================================

def _strip(obj: Any, drop: Set[str]) -> Any:
    if isinstance(obj, dict):
        return {k: _strip(v, drop) for k, v in obj.items() if k not in drop}
    if isinstance(obj, list):
        return [_strip(i, drop) for i in obj]
    return obj


def content(obj: Dict[str, Any], ignore: Tuple[str, ...] = ()) -> Dict[str, Any]:
    """An object's configuration without NSX's own bookkeeping, for comparisons."""
    return _strip(obj, VOLATILE_KEYS | set(ignore))


def update_payload(live: Dict[str, Any], **changes: Any) -> Dict[str, Any]:
    """The live object with `changes`, keeping _revision so NSX rejects the
    write (HTTP 412) if anyone changed the object since it was read."""
    body = _strip(live, STRIP_KEYS - {"_revision"})
    body.update(changes)
    return body


def create_payload(obj: Dict[str, Any], drop: Tuple[str, ...] = ()) -> Dict[str, Any]:
    """A saved object as a create body: NSX bookkeeping and `drop` keys removed."""
    return _strip({k: v for k, v in obj.items() if k not in drop}, STRIP_KEYS)


def is_412(exc: Exception) -> bool:
    return getattr(exc, "status_code", None) == 412


def is_not_found(exc: Exception) -> bool:
    return getattr(exc, "status_code", None) == 404


def is_still_referenced(exc: Exception) -> bool:
    """NSX refusing a delete because something still references the object."""
    text = str(exc).lower()
    return getattr(exc, "status_code", None) in (400, 409, 500) and (
        "referenc" in text or "in use" in text or "being used" in text or "500030" in text)


# =============================================================================
# Group references
# =============================================================================

def group_refs(obj: Any) -> Set[str]:
    """Every group path anywhere in an object, except the object's own path fields."""
    found: Set[str] = set()

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                if k not in SELF_KEYS:
                    walk(v)
        elif isinstance(x, list):
            for i in x:
                walk(i)
        elif isinstance(x, str) and GROUP_PATH_RE.match(x):
            found.add(x)

    walk(obj)
    return found


def group_path(group: Dict[str, Any]) -> str:
    return group.get("path") or f"/infra/domains/{DOMAIN}/groups/{group.get('id')}"


def closure(roots: Set[str], nested: Dict[str, Set[str]]) -> Set[str]:
    """Every group reachable from `roots` through nested group references."""
    seen: Set[str] = set()
    pending = list(roots)
    while pending:
        g = pending.pop()
        if g in seen:
            continue
        seen.add(g)
        pending.extend(nested.get(g, set()) - seen)
    return seen


def parents_first(groups: List[str], nested: Dict[str, Set[str]]) -> List[str]:
    """Order groups so a group is deleted before any group it nests (NSX
    refuses to delete a group another group still references)."""
    todo = set(groups)
    indeg = {g: 0 for g in todo}
    for p in todo:
        for c in (nested.get(p, set()) & todo) - {p}:
            indeg[c] += 1
    ready = sorted(g for g in todo if indeg[g] == 0)
    order: List[str] = []
    while ready:
        g = ready.pop(0)
        order.append(g)
        for c in sorted((nested.get(g, set()) & todo) - {g}):
            indeg[c] -= 1
            if indeg[c] == 0:
                ready.append(c)
        ready.sort()
    return order + sorted(todo - set(order))   # a nesting loop, should NSX ever allow one


def _list(client: Any, suffix: str) -> List[Dict[str, Any]]:
    return client._get_all_results(client._policy_path(suffix))


def other_consumers(client: Any) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Gateway, IDS, redirection, forwarding and endpoint policies with their
    rules, the DFW exclusion list and load-balancer pools and virtual servers:
    everything besides DFW that can reference a group. A family this manager
    does not have (HTTP 400/404) is noted and skipped; any other read error
    stops the run, because group references would then be unknown."""
    out: List[Dict[str, Any]] = []
    checked: Dict[str, str] = {}

    def read(label: str, fn):
        try:
            return fn()
        except Exception as exc:
            if getattr(exc, "status_code", None) in NOT_AVAILABLE:
                checked[label] = f"not available (HTTP {exc.status_code})"
                return None
            raise SystemExit(f"could not read {label} ({exc}); group references would be unknown, stopping")

    for fam in CONSUMER_FAMILIES:
        pols = read(fam, lambda: _list(client, f"/domains/{DOMAIN}/{fam}"))
        if pols is None:
            continue
        n = 0
        for p in pols:
            out.append({"kind": fam, "id": p.get("id"), "obj": p})
            rules = read(f"{fam}/{p.get('id')}/rules",
                         lambda: _list(client, f"/domains/{DOMAIN}/{fam}/{client._q(p['id'])}/rules")) or []
            for r in rules:
                out.append({"kind": f"{fam} rule", "id": f"{p.get('id')}/{r.get('id')}", "obj": r})
            n += len(rules)
        checked[fam] = f"{len(pols)} policies, {n} rules"
    for suffix in CONSUMER_OBJECTS:
        obj = read(suffix, lambda: client._get(client._policy_path(suffix)))
        if obj is not None:
            out.append({"kind": suffix, "id": obj.get("id"), "obj": obj})
            checked[suffix] = f"{len(group_refs(obj))} group references"
    for suffix in CONSUMER_LISTS:
        objs = read(suffix, lambda: _list(client, suffix))
        if objs is not None:
            out += [{"kind": suffix, "id": o.get("id"), "obj": o} for o in objs]
            checked[suffix] = f"{len(objs)} objects"
    return out, checked


def read_state(client: Any) -> Dict[str, Any]:
    """Live DFW policies with their rules, groups, and every other group consumer."""
    policies = client.list_security_policies(domain_id=DOMAIN)
    rules = {p["id"]: client.list_security_rules(security_policy_id=p["id"], domain_id=DOMAIN)
             for p in policies}
    consumers, checked = other_consumers(client)
    return {"policies": policies, "rules": rules, "groups": client.list_groups(domain_id=DOMAIN),
            "consumers": consumers, "consumers_checked": checked}


# =============================================================================
# Step 2 plan
# =============================================================================

def step2_candidates(run: Path, include_pre_disabled: bool) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Rules step 2 may delete: those step 1 disabled (minus any re-enabled by
    step1_undo.py), plus with include_pre_disabled the never-used rules that
    were already disabled when step 1 planned. Each carries the reference
    copy it must still match."""
    disabled = (read_json(run / "step1" / "disabled.json", {}) or {}).get("rules", [])
    plan = read_json(run / "step1" / "plan.json", {}) or {}
    out = [{"policy_id": d["policy_id"], "rule_id": d["rule_id"], "origin": "disabled by step 1",
            "reference": d["after"]} for d in disabled if not d.get("reenabled_at")]
    pre = [e for e in plan.get("rules", []) if e["class"] == ALREADY_DISABLED]
    if include_pre_disabled:
        out += [{"policy_id": e["policy_id"], "rule_id": e["rule_id"],
                 "origin": "already disabled before step 1", "reference": e["rule"]} for e in pre]
    return out, {"disabled_by_step1": sum(1 for d in disabled if not d.get("reenabled_at")),
                 "reenabled": sum(1 for d in disabled if d.get("reenabled_at")),
                 "pre_disabled": len(pre), "pre_disabled_included": len(pre) if include_pre_disabled else 0}


def plan_step2(state: Dict[str, Any], candidates: List[Dict[str, Any]],
               usage: Dict[str, Optional[Dict[str, int]]]) -> Dict[str, Any]:
    """What step 2 deletes, from live state. Pure: no NSX calls.

    Rules: a candidate is deleted only if it is still on the manager, still
    disabled, unchanged since its reference copy, and has no hits now.
    Policies: every customer policy left with no rules once those are gone
    (including policies that were already empty). Groups: every customer
    group not reachable from what stays (remaining DFW rules and policies,
    the other consumers, nested references from NSX's own groups), ordered
    so a group goes before the groups it nests.
    """
    live_rules = {(pid, r.get("id")): r for pid, rs in state["rules"].items() for r in rs}
    rules_del, rules_kept = [], []
    for c in candidates:
        key = (c["policy_id"], c["rule_id"])
        live = live_rules.get(key)
        ref = live or c["reference"]
        row = {"policy_id": key[0], "rule_id": key[1], "display_name": ref.get("display_name"),
               "action": ref.get("action"), "sequence_number": ref.get("sequence_number"),
               "origin": c["origin"]}
        u = usage.get(f"{key[0]}/{key[1]}")
        if live is None:
            reason = "no longer on the manager"
        elif not live.get("disabled"):
            reason = "enabled again since step 1"
        elif content(live) != content(c["reference"]):
            reason = "changed since step 1"
        elif u and any(u.values()):
            reason = f"has hits now (hit_count {u['hit_count']})"
        else:
            reason = None
        row["counters"] = u
        (rules_kept if reason else rules_del).append({**row, "reason": reason} if reason else row)
    del_keys = {(r["policy_id"], r["rule_id"]) for r in rules_del}

    policies_del = []
    for p in state["policies"]:
        if not is_cleanup_policy(p):
            continue
        rs = state["rules"].get(p["id"], [])
        if all((p["id"], r.get("id")) in del_keys for r in rs):
            policies_del.append({"id": p["id"], "display_name": p.get("display_name"),
                                 "category": p.get("category"), "rules_deleted_first": len(rs),
                                 "origin": "emptied by this run" if rs else "already empty"})
    pol_del = {p["id"] for p in policies_del}

    customer = {group_path(g): g for g in state["groups"] if not is_system_default(g)}
    nested = {group_path(g): group_refs(g) for g in state["groups"]}

    def roots(after: bool) -> Set[str]:
        out: Set[str] = set()
        for p in state["policies"]:
            if after and p["id"] in pol_del:
                continue
            out |= group_refs({k: v for k, v in p.items() if k not in ("rules", "children")})
            for r in state["rules"].get(p["id"], []):
                if not (after and (p["id"], r.get("id")) in del_keys):
                    out |= group_refs(r)
        for c in state["consumers"]:
            out |= group_refs(c["obj"])
        for path, refs in nested.items():
            if path not in customer:          # NSX's own groups stay, and so does what they nest
                out |= refs
        return out

    used_before = closure(roots(False), nested)
    used_after = closure(roots(True), nested)
    order = parents_first([p for p in customer if p not in used_after], nested)
    groups_del = [{"id": customer[p].get("id"), "path": p, "display_name": customer[p].get("display_name"),
                   "nests": sorted(r.rsplit("/", 1)[-1] for r in nested[p] if r in customer),
                   "origin": "already unreferenced" if p not in used_before else "freed by this run"}
                  for p in order]
    return {"rules": rules_del, "rules_kept": rules_kept, "policies": policies_del, "groups": groups_del,
            "consumers_checked": state.get("consumers_checked", {}),
            "counts": {"rules": len(rules_del), "rules_kept": len(rules_kept),
                       "policies": len(policies_del), "groups": len(groups_del),
                       "groups_total": len(customer)}}


# A single-policy GET embeds the policy's rules; a re-created policy must not
# carry them (a PUT with `rules` would set the policy's whole rule list).
POLICY_CREATE_DROP = ("rules", "rule_count")


def restore_order(deleted: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Put deleted objects back so every reference resolves: groups in the
    reverse of their delete order (nested groups first), then policies, then
    rules by policy and sequence number."""
    groups = [d for d in deleted if d["kind"] == "group"][::-1]
    policies = [d for d in deleted if d["kind"] == "policy"]
    rules = sorted((d for d in deleted if d["kind"] == "rule"),
                   key=lambda d: (d["policy_id"], d["obj"].get("sequence_number") or 0, d["rule_id"]))
    return groups + policies + rules


# =============================================================================
# Markdown
# =============================================================================

def _cell(v: Any) -> str:
    return str("" if v is None else v).replace("|", "\\|")


def step1_markdown(plan: Dict[str, Any]) -> str:
    c = plan["counts"]
    lines = [f"# Unused rule cleanup, step 1 plan: {plan['target_host']}", "",
             f"- Planned at: {plan['planned_at']}",
             f"- Min age (days): {plan['min_age_days']}; keep never-hit DROP/REJECT: {plan['keep_deny']}",
             f"- Counter source per policy: {plan['stats_sources']}",
             f"- Customer rules: {c['rules']}; by class: {c['by_class']}", "",
             "`DISABLE` = step 1 disables it. `ALREADY_DISABLED` = never hit and already off "
             "(step 2 deletes it only with `--include-pre-disabled`). Every other class is left alone.", ""]
    if plan.get("skipped_policies"):
        lines += ["## Policies not looked at", "", "| Policy | Reason |", "|---|---|"]
        lines += [f"| `{_cell(s['id'])}` | {_cell(s['reason'])} |" for s in plan["skipped_policies"]]
        lines.append("")
    lines += ["## Rules", "",
              "| Class | Category | Policy | Rule | Seq | Action | Disabled | Hits | Packets | Sessions | Age (d) |",
              "|---|---|---|---|---:|---|---|---:|---:|---:|---:|"]
    for e in plan["rules"]:
        u = e.get("counters") or {}
        lines.append(f"| {e['class']} | {_cell(e.get('category'))} | `{_cell(e['policy_id'])}` "
                     f"| `{_cell(e.get('display_name') or e['rule_id'])}` | {_cell(e.get('sequence_number'))} "
                     f"| {_cell(e.get('action'))} | {'yes' if e.get('disabled') else 'no'} "
                     f"| {_cell(u.get('hit_count', '-'))} | {_cell(u.get('packet_count', '-'))} "
                     f"| {_cell(u.get('session_count', '-'))} | {_cell(e.get('age_days', '-'))} |")
    return "\n".join(lines) + "\n"


def step2_markdown(plan: Dict[str, Any]) -> str:
    c = plan["counts"]
    lines = [f"# Unused rule cleanup, step 2 plan: {plan['target_host']}", "",
             f"- Planned at: {plan['planned_at']}",
             f"- Delete: {c['rules']} rules, then {c['policies']} policies, then {c['groups']} groups "
             f"(of {c['groups_total']} customer groups). Services are never touched.",
             f"- Candidates: {plan['candidates']}",
             f"- Other group consumers checked: {plan['consumers_checked']}", ""]
    lines += ["## Rules to delete", "", "| Policy | Rule | Seq | Action | Origin |", "|---|---|---:|---|---|"]
    lines += [f"| `{_cell(r['policy_id'])}` | `{_cell(r.get('display_name') or r['rule_id'])}` "
              f"| {_cell(r.get('sequence_number'))} | {_cell(r.get('action'))} | {r['origin']} |"
              for r in plan["rules"]]
    if plan["rules_kept"]:
        lines += ["", "## Candidates kept", "", "| Policy | Rule | Reason |", "|---|---|---|"]
        lines += [f"| `{_cell(r['policy_id'])}` | `{_cell(r.get('display_name') or r['rule_id'])}` "
                  f"| {_cell(r['reason'])} |" for r in plan["rules_kept"]]
    lines += ["", "## Policies to delete (no rules left)", "", "| Policy | Category | Rules deleted first | Origin |",
              "|---|---|---:|---|"]
    lines += [f"| `{_cell(p['display_name'] or p['id'])}` | {_cell(p.get('category'))} "
              f"| {p['rules_deleted_first']} | {p['origin']} |" for p in plan["policies"]]
    lines += ["", "## Groups to delete (nothing references them), in delete order", "",
              "| # | Group | Nests | Origin |", "|---:|---|---|---|"]
    lines += [f"| {i} | `{_cell(g['display_name'] or g['id'])}` | {_cell(', '.join(g['nests']))} | {g['origin']} |"
              for i, g in enumerate(plan["groups"], start=1)]
    return "\n".join(lines) + "\n"
