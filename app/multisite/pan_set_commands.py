"""app/multisite/pan_set_commands.py

A Palo plan as PAN-OS CLI commands (Mike, 2026-10-09): one file of `set`
commands to paste into configure mode on Panorama (or on a firewall, for a
firewall-target plan), and one file of `delete` commands that removes them
again, newest first. The push dry run writes them for exactly the objects it
found missing (write_from_dryrun); render_files covers every object of a plan
for when the device cannot be checked.

Every command is rendered mechanically from the same REST entry that
`nsx_pan_mirror.py push` sends (plan["writes"]), in the same order, so the
two routes build the same configuration:

    tags, addresses, address groups (members before holders), services,
    service groups, then the security rules in NSX evaluation order

Locations follow the plan:

    objects in "shared"        set shared address ...
    objects in a device group  set device-group dg-4 address ...
    rules, Panorama            set device-group dg-4 pre-rulebase security rules ...
                               (post-rulebase for a post plan)
    firewall target (vsys)     set address ... / set rulebase security rules ...
                               (single-vsys firewall syntax)

The files hold commands only: no comments and no `configure` or `commit`
line, because the CLI rejects anything that is not a command and the
operator reviews and commits in Panorama. A `set` on an object that already
exists updates it in place; check the push dry-run report for objects that
are already there before pasting.

No network access here; pure functions over a plan dict.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

# Plan write kind -> CLI keyword (rules are handled separately).
CLI_KIND = {"tag": "tag", "address": "address", "address-group": "address-group",
            "service": "service", "service-group": "service-group"}
# REST rulebase resource -> CLI path under the device group (Panorama) or the firewall.
RULEBASE_CLI = {"Policies/SecurityPreRules": "pre-rulebase security rules",
                "Policies/SecurityPostRules": "post-rulebase security rules",
                "Policies/SecurityRules": "rulebase security rules"}
_BARE = re.compile(r"[A-Za-z0-9._/:\-]+")
# Attribute order on each line, as PAN-OS shows the object: what it is first,
# description last. Keys not listed follow in alphabetical order.
KEY_ORDER = {
    "address": ["ip-netmask", "ip-range", "ip-wildcard", "fqdn", "tag", "description"],
    "address-group": ["static", "dynamic", "tag", "description"],
    "service": ["protocol", "tag", "description"],
    "service-group": ["members", "tag"],
    "tag": ["color", "comments"],
    "security-rule": ["from", "to", "source", "destination", "negate-source", "negate-destination",
                      "source-user", "category", "application", "service", "action", "profile-setting",
                      "log-setting", "disabled", "tag", "description"],
}


def quote(value: Any) -> str:
    """One CLI token. Plain when it holds only name-safe characters, else in
    double quotes (a double quote inside becomes a single quote: the CLI has
    no escape for it)."""
    s = str(value)
    if s and _BARE.fullmatch(s):
        return s
    return '"' + s.replace('"', "'") + '"'


def _members(m: Any) -> List[str]:
    items = m if isinstance(m, list) else [m]
    if len(items) == 1:
        return [quote(items[0])]
    return ["["] + [quote(x) for x in items] + ["]"]


def value_tokens(value: Any) -> List[str]:
    """A REST value as CLI tokens: {"member": [...]} -> a value or [ a b ];
    a nested dict -> its keys in order (protocol tcp port 443, profile-setting
    group x); a scalar -> one token."""
    if isinstance(value, dict):
        if set(value) == {"member"}:
            return _members(value["member"])
        out: List[str] = []
        for k, v in value.items():
            out += [k] + value_tokens(v)
        return out
    if isinstance(value, list):
        return _members(value)
    return [quote(value)]


def entry_tokens(entry: Dict[str, Any], kind: str = "") -> List[str]:
    order = KEY_ORDER.get(kind, [])
    keys = [k for k in order if k in entry] + sorted(k for k in entry if k not in order and k != "@name")
    out: List[str] = []
    for k in keys:
        out += [k] + value_tokens(entry[k])
    return out


def object_path(write: Dict[str, Any]) -> str:
    """Everything between `set` and the attributes: location, kind, name."""
    name = quote(write["name"])
    dg = quote(write.get("device_group") or "")
    if write["kind"] == "security-rule":
        rb = RULEBASE_CLI.get(write.get("resource", ""))
        if rb is None:
            raise ValueError(f"unknown rulebase resource {write.get('resource')!r} for rule {write['name']}")
        if write.get("location") == "vsys":
            return f"{rb} {name}"
        return f"device-group {dg} {rb} {name}"
    kind = CLI_KIND.get(write["kind"])
    if kind is None:
        raise ValueError(f"no CLI form for plan object kind {write['kind']!r}")
    loc = write.get("location") or "device-group"
    if loc == "shared":
        return f"shared {kind} {name}"
    if loc == "vsys":
        return f"{kind} {name}"
    return f"device-group {dg} {kind} {name}"


def set_command(write: Dict[str, Any]) -> str:
    return " ".join(["set", object_path(write)] + entry_tokens(write["entry"], write["kind"]))


def delete_command(write: Dict[str, Any]) -> str:
    return f"delete {object_path(write)}"


def set_commands(plan: Dict[str, Any]) -> List[str]:
    """One `set` per object, in the push's creation order."""
    return [set_command(w) for w in plan.get("writes") or []]


def delete_commands(plan: Dict[str, Any]) -> List[str]:
    """One `delete` per object, newest first (rules before the objects they use)."""
    return [delete_command(w) for w in reversed(plan.get("writes") or [])]


def render_files(plan: Dict[str, Any]) -> Dict[str, str]:
    """{file name: text} for every object of the plan."""
    return {"pan_set_commands.txt": "\n".join(set_commands(plan)) + "\n",
            "pan_delete_commands.txt": "\n".join(delete_commands(plan)) + "\n"}


def missing_writes(push_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The objects a push dry run found missing on the device (status
    would_create), in the plan's creation order. Rows carry the same kind,
    name, location, resource, device group and entry as the plan's writes."""
    return [r for r in push_doc.get("results") or [] if r.get("status") == "would_create" and r.get("entry")]


def write_files(directory: Path, prefix: str, writes: List[Dict[str, Any]]) -> List[Path]:
    """<prefix>set_commands.txt and <prefix>delete_commands.txt in `directory`.
    An empty list still writes both files, empty: nothing to paste."""
    from common.fileio import write_text
    body = {"set_commands.txt": [set_command(w) for w in writes],
            "delete_commands.txt": [delete_command(w) for w in reversed(writes)]}
    out = []
    for suffix, lines in body.items():
        path = directory / f"{prefix}{suffix}"
        write_text(path, "\n".join(lines) + ("\n" if lines else ""))
        out.append(path)
    return out


def write_from_dryrun(manifest_path: Path, push_doc: Dict[str, Any]) -> List[Path]:
    """Paste files for exactly what a push dry run found missing (Mike,
    2026-10-09: the dry run creates them). Written beside the dry-run manifest
    as push_<ts>_dryrun_{set,delete}_commands.txt, and copied to
    pan_{set,delete}_commands.txt so the newest dry run is always at one name."""
    writes = missing_writes(push_doc)
    stem = manifest_path.name[:-len(".json")] if manifest_path.name.endswith(".json") else manifest_path.name
    dated = write_files(manifest_path.parent, f"{stem}_", writes)
    latest = write_files(manifest_path.parent, "pan_", writes)
    return dated + latest
