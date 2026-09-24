"""Display names for reports, never bare ids.

Reports are read by people, and an NSX id is often an opaque token: a UUID, or
a short handle like `vm1` whose display name is "vm-group-1". Every report
names objects by display name.

Display names are NOT unique in NSX: two groups may share one, and only the id
tells them apart. So a label carries the id as well exactly when the display
name alone would be ambiguous within the same report, and never otherwise.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

import yaml

# "/infra/domains/default/groups/vm1", "/global-infra/services/ICMP-ALL", ...
_REF = re.compile(r"/(groups|services|security-policies|rules|context-profiles)/([^/]+)$")


def ref_key(path_or_id: str) -> Tuple[str, str]:
    """(kind, id) for a policy path; ("", id) for a bare id."""
    m = _REF.search(path_or_id or "")
    return (m.group(1), m.group(2)) if m else ("", path_or_id or "")


class NameMap:
    """path / (kind, id) -> display name, gathered from wherever names are known."""

    def __init__(self) -> None:
        self._by_path: Dict[str, str] = {}
        self._by_key: Dict[Tuple[str, str], str] = {}
        self._ids_per_name: Dict[str, set] = {}

    def add(self, path: Optional[str], ident: Optional[str], name: Optional[str],
            kind: str = "") -> None:
        if not name:
            return
        if path:
            self._by_path[path] = name
            kind, ident = ref_key(path) if not ident else (ref_key(path)[0] or kind, ident)
        if ident:
            self._by_key[(kind, ident)] = name
            self._by_key.setdefault(("", ident), name)
            self._ids_per_name.setdefault(name, set()).add((kind, ident))

    def add_object(self, obj: Dict[str, Any], kind: str = "") -> None:
        if isinstance(obj, dict):
            self.add(obj.get("path"), obj.get("id"), obj.get("display_name"), kind)

    def add_mapping(self, names: Optional[Dict[str, str]]) -> None:
        """Merge a {path: display_name} dict recorded by a push tool."""
        for path, name in (names or {}).items():
            self.add(path, None, name)

    def add_bundle(self, root: Path) -> None:
        """Every YAML under a bundle directory that carries id + display_name."""
        root = Path(root)
        if not root.exists():
            return
        for f in root.rglob("*.y*ml"):
            if "push_report" in f.parts:
                continue
            try:
                obj = yaml.safe_load(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(obj, dict) and obj.get("id") and obj.get("display_name"):
                kind = {"Group": "groups", "Service": "services",
                        "SecurityPolicy": "security-policies",
                        "Rule": "rules"}.get(obj.get("resource_type"), "")
                self.add(obj.get("path"), obj["id"], obj["display_name"], kind)
        # WF-C / WF-D sibling maps name both halves of every pair.
        import json
        for f in root.rglob("sibling_map.json"):
            try:
                m = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            for e in m.get("map") or []:
                self.add(None, e.get("original_id"), e.get("original_display_name"), "groups")
                self.add(None, e.get("sibling_id"), e.get("sibling_display_name"), "groups")

    def name(self, path_or_id: str) -> str:
        """Display name, falling back to the id only when no name is known."""
        if path_or_id in self._by_path:
            return self._by_path[path_or_id]
        kind, ident = ref_key(path_or_id)
        return self._by_key.get((kind, ident)) or self._by_key.get(("", ident)) or ident

    def label(self, path_or_id: str) -> str:
        """Display name, plus the id only if the name is shared by another object."""
        kind, ident = ref_key(path_or_id)
        name = self.name(path_or_id)
        if name != ident and len(self._ids_per_name.get(name, ())) > 1:
            return f"{name} ({ident})"
        return name


def ambiguous(pairs: Iterable[Tuple[str, str]]) -> set:
    """Display names used by more than one id, from (id, display_name) pairs."""
    seen: Dict[str, set] = {}
    for ident, name in pairs:
        if name:
            seen.setdefault(name, set()).add(ident)
    return {n for n, ids in seen.items() if len(ids) > 1}


def display(name: Optional[str], ident: str, ambiguous_names: set = frozenset()) -> str:
    """One object's report label: display name, id appended only if ambiguous."""
    if not name:
        return ident
    return f"{name} ({ident})" if name in ambiguous_names and name != ident else name


def target_ref_names(client: Any, domain_id: str = "default") -> Dict[str, str]:
    """{path: display_name} for every group and service a rule on the target
    can reference, plus the domain's policies (so a rule row can name the
    policy it sits in): the domain's groups, services and policies, and on a
    federated LM the GM-owned objects under /global-infra. Read-only; a failed lookup just
    leaves those names out, and the report falls back to the id for them."""
    out: Dict[str, str] = {}

    def take(objs: Iterable[Dict[str, Any]]) -> None:
        for o in objs or []:
            if isinstance(o, dict) and o.get("path") and o.get("display_name"):
                out[o["path"]] = o["display_name"]

    for fetch in (lambda: client.list_groups(domain_id), lambda: client.list_services(),
                  lambda: client.list_security_policies(domain_id)):
        try:
            take(fetch())
        except Exception:
            pass
    for path in (f"/policy/api/v1/global-infra/domains/{domain_id}/groups",
                 "/policy/api/v1/global-infra/services"):
        try:
            for page in client._get_pages(path):
                take(page.get("results"))
        except Exception:
            pass
    return out


def names_for(paths: Iterable[str], mapping: Dict[str, str]) -> Dict[str, str]:
    """The subset of `mapping` a single report row needs."""
    return {p: mapping[p] for p in paths if isinstance(p, str) and p in mapping}


def policy_name_by_id(ref_names: Dict[str, str]) -> Dict[str, str]:
    """{policy_id: display_name} from a target_ref_names() result."""
    return {path.rsplit("/", 1)[-1]: name for path, name in ref_names.items()
            if "/security-policies/" in path}
