"""Offline source data for the capture-then-push A/C workflow."""
from __future__ import annotations

import json
from pathlib import Path

import yaml


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read capture file {path}: {exc}") from exc


def validate_capture(capture: Path, source_host: str, domain_id: str) -> dict:
    """Validate this bundle, never an unrelated latest global log."""
    manifest = read_json(capture / "manifest.json")
    if not isinstance(manifest, dict) or manifest.get("ok") is not True:
        raise ValueError(f"Capture is incomplete or failed: {capture}")
    origin = manifest.get("captured_from", {})
    if (not isinstance(origin, dict) or origin.get("manager_host") != source_host
            or origin.get("domain_id") != domain_id
            or origin.get("federation_global")):
        raise ValueError(f"Capture does not match LM source {source_host}, domain {domain_id}")
    summary = read_json(capture / "groups_additive" / "domains" / domain_id / "groups" / "manifest.json")
    if (not isinstance(summary, dict) or summary.get("source_manager_host") != source_host
            or summary.get("domain_id") != domain_id):
        raise ValueError("Additive summary does not match the capture source/domain")
    if summary.get("ip_source") != "effective":
        raise ValueError("Capture needs --live-query --ip-source effective; effective IPs were not saved")
    if summary.get("groups_errors") != 0:
        raise ValueError(f"Capture has unresolved group errors: {summary.get('groups_errors')}")
    groups_seen = summary.get("groups_seen", 0)
    if not isinstance(groups_seen, int) or groups_seen <= 0:
        raise ValueError("Capture has no processed groups; review the source capture before continuing")
    # Older effective captures lack this counter. Their ip_source/groups_errors
    # checks still apply; new captures must record one successful query per group.
    if "effective_ip_queries" in summary and summary["effective_ip_queries"] != groups_seen:
        raise ValueError("Capture did not complete an effective-IP query for every processed group")
    return manifest


class CapturedSource:
    """The source reads used by the verifier, implemented entirely from disk."""

    def __init__(self, capture: Path, source_host: str, domain_id: str):
        self.capture = capture.resolve()
        self.domain_id = domain_id
        self.manifest = validate_capture(self.capture, source_host, domain_id)
        root = self.capture / "nsx_export" / source_host / "domains" / domain_id
        self.groups = self._objects(root / "groups", "Group")
        self.services = self._objects(root / "services", "Service")
        self.policies = self._objects(root / "security-policies", "SecurityPolicy")
        self.rules = self._objects(root / "security-policies", "Rule")
        if any(not rule.get("parent_path") for rule in self.rules):
            raise ValueError("Captured rules are missing parent_path; cannot verify policy/rule parity")
        # candidate_ips is the captured NSX endpoint answer. The additive group
        # payload can also contain old manual IPs, so it is not equivalent truth.
        reports = self.capture / "groups_additive" / "domains" / domain_id / "reports" / "captured-member-ip-additive"
        if not reports.is_dir():
            # Older captures kept the reports outside the bundle. Use only the
            # exact path recorded by THIS capture, never a latest-log search.
            summary = read_json(self.capture / "groups_additive" / "domains" / domain_id / "groups" / "manifest.json")
            if not summary.get("reports_dir"):
                raise ValueError("Capture has no effective-IP reports; recapture with --live-query")
            reports = Path(summary["reports_dir"])
        self.effective_ips = {}
        for name in ("groups_changed", "groups_no_new_ips", "groups_no_members", "groups_no_ips"):
            for row in read_json(reports / f"{name}.json"):
                ips = row["candidate_ips"] if name in ("groups_changed", "groups_no_new_ips") else []
                self.effective_ips[row["group_id"]] = ips

    @staticmethod
    def _objects(directory: Path, resource_type: str) -> list:
        if not directory.is_dir():
            raise ValueError(f"Missing capture object directory: {directory}")
        objects = []
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix not in (".yaml", ".yml", ".json"):
                continue
            try:
                obj = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError) as exc:
                raise ValueError(f"Cannot read captured object {path}: {exc}") from exc
            if isinstance(obj, dict) and obj.get("resource_type") == resource_type:
                if not obj.get("id"):
                    raise ValueError(f"Captured {resource_type} has no id: {path}")
                objects.append(obj)
        return objects

    def list_groups(self, *, domain_id):
        return self.groups

    def list_services(self):
        return self.services

    def list_security_policies(self, *, domain_id):
        return self.policies

    def list_security_rules(self, *, security_policy_id, domain_id):
        parent = f"/infra/domains/{domain_id}/security-policies/{security_policy_id}"
        return [rule for rule in self.rules if rule.get("parent_path") == parent]

    def get_group_effective_ips(self, group_id, *, domain_id):
        if group_id not in self.effective_ips:
            raise ValueError(f"No captured effective-IP result for group {group_id}")
        return self.effective_ips[group_id]
