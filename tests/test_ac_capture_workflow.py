"""Offline tests for the LM1 capture / manual credential switch / LM2 workflow."""
import importlib.util
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "app"))
from nsx.captured_source import CapturedSource, validate_capture


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "tools/nsx" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


workflow = load_tool("run_workflow")
verify = load_tool("verify_avs_run")
capture_tool = load_tool("capture_nsx_state")
additive_tool = load_tool("build_group_ip_additive_from_live_members")
transform_tool = load_tool("transform_capture")


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def resolver(alias):
    return {"nsx-lm1": "lm1.test", "nsx-lm2": "lm2.test"}[alias]


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.capture = self.root / "nsx_capture/lm1.test"
        self.manifest = {
            "ok": True, "captured_at": "2026-09-19T12:00:00Z",
            "captured_from": {"manager_host": "lm1.test", "domain_id": "default",
                              "federation_global": False},
            "options": {"emit_flat_exports": True},
        }
        write_json(self.capture / "manifest.json", self.manifest)
        self.summary_path = self.capture / "groups_additive/domains/default/groups/manifest.json"
        self.summary = {"source_manager_host": "lm1.test", "domain_id": "default",
                        "ip_source": "effective", "groups_errors": 0, "vm_ip_index_count": 0,
                        "groups_seen": 3, "effective_ip_queries": 3}
        write_json(self.summary_path, self.summary)
        self.reports = self.capture / "groups_additive/domains/default/reports/captured-member-ip-additive"
        write_json(self.reports / "groups_changed.json", [
            {"group_id": "g1", "candidate_ips": ["10.0.0.1"], "ips_added": ["10.0.0.1"]}])
        write_json(self.reports / "groups_no_new_ips.json", [
            {"group_id": "g2", "candidate_ips": ["10.0.0.2"]}])
        write_json(self.reports / "groups_no_members.json", [{"group_id": "empty"}])
        write_json(self.reports / "groups_no_ips.json", [])
        self.raw = self.capture / "nsx_export/lm1.test/domains/default"
        self.group = {"id": "g1", "resource_type": "Group", "expression": []}
        self.service = {"id": "svc1", "resource_type": "Service"}
        self.policy = {"id": "p1", "resource_type": "SecurityPolicy"}
        self.rule = {"id": "r1", "resource_type": "Rule",
                     "parent_path": "/infra/domains/default/security-policies/p1",
                     "source_groups": ["/infra/domains/default/groups/g1",
                                       "/infra/domains/default/groups/g1_np_ips"]}
        write_json(self.raw / "groups/g1.json", self.group)
        write_json(self.raw / "services/svc1.json", self.service)
        write_json(self.raw / "security-policies/policy-slug/policy.json", self.policy)
        write_json(self.raw / "security-policies/policy-slug/rules/r1.json", self.rule)
        for kind, subdir in (("services", "services"), ("groups", "groups"),
                             ("policies", "security-policies"), ("rules", "security-policies")):
            (self.root / f"nsx_{kind}_export/lm1.test" / subdir).mkdir(parents=True)
        self.run = self.root / "run"
        self.smap = self.run / "nsx_sibling_groups/lm1.test/sibling_map.json"
        write_json(self.smap, {"map": [{"original_id": "g1", "sibling_id": "g1_np_ips"}]})

    def test_source_reader_uses_endpoint_results_and_rule_parent_id(self):
        src = CapturedSource(self.capture, "lm1.test", "default")
        self.assertEqual(src.list_groups(domain_id="default"), [self.group])
        self.assertEqual(src.list_security_rules(security_policy_id="p1", domain_id="default"), [self.rule])
        self.assertEqual(src.get_group_effective_ips("g1", domain_id="default"), ["10.0.0.1"])
        self.assertEqual(src.get_group_effective_ips("g2", domain_id="default"), ["10.0.0.2"])
        self.assertEqual(src.get_group_effective_ips("empty", domain_id="default"), [])
        with self.assertRaises(ValueError):
            src.get_group_effective_ips("missing", domain_id="default")

    def test_gate_rejects_wrong_source_domain_failed_capture_and_offline_ips(self):
        for host, domain in (("lm2.test", "default"), ("lm1.test", "wrong")):
            with self.subTest(host=host, domain=domain), self.assertRaises(ValueError):
                validate_capture(self.capture, host, domain)
        for field, value in (("ip_source", "n/a (offline copy)"), ("groups_errors", 1),
                             ("groups_seen", 0), ("effective_ip_queries", 2), ("domain_id", "wrong")):
            write_json(self.summary_path, {**self.summary, field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_capture(self.capture, "lm1.test", "default")
        write_json(self.summary_path, self.summary)
        write_json(self.capture / "manifest.json", {**self.manifest, "ok": False})
        with self.assertRaises(ValueError):
            validate_capture(self.capture, "lm1.test", "default")

    def test_old_capture_uses_its_recorded_report_directory(self):
        old_reports = self.root / "old_logs/capture_123"
        old_reports.parent.mkdir(parents=True)
        self.reports.rename(old_reports)
        legacy_summary = {k: v for k, v in self.summary.items() if k != "effective_ip_queries"}
        write_json(self.summary_path, {**legacy_summary, "reports_dir": str(old_reports)})
        write_json(old_reports / "groups_changed.json", [{"group_id": "g1",
                   "candidate_ips": ["10.0.0.1", "10.0.0.3"], "ips_added": ["10.0.0.3"]}])
        src = CapturedSource(self.capture, "lm1.test", "default")
        self.assertEqual(src.get_group_effective_ips("g1", domain_id="default"),
                         ["10.0.0.1", "10.0.0.3"])

    def run_workflow(self, phase, *flags):
        commands = []

        def run_step(label, cmd, log_dir):
            log_dir.mkdir(parents=True, exist_ok=True)
            commands.append((label, cmd))
            return {"label": label, "cmd": cmd, "rc": 0, "ok": True, "log": "test"}

        argv = ["run_workflow.py", "--source", "nsx-lm1", "--target", "nsx-lm2",
                "--phase", phase, "--run-dir", str(self.run), *flags]
        with patch.object(workflow, "REPO_ROOT", self.root), \
                patch.object(workflow, "resolve_manager", resolver), \
                patch.object(workflow, "init_cli"), patch.object(workflow, "run_step", run_step), \
                patch.dict(os.environ, {"OBJECT_APPENDIX": "_np_ips", "OBJECT_APPENDIX_AVS": "_avs_ips"}), \
                patch.object(sys, "argv", argv):
            rc = workflow.main()
        return rc, commands

    def test_ac_all_modes_never_launch_capture(self):
        for phase in ("a", "c"):
            for flags in ((), ("--apply",), ("--verify",), ("--rollback",), ("--no-capture",)):
                with self.subTest(phase=phase, flags=flags):
                    rc, commands = self.run_workflow(phase, *flags)
                    self.assertEqual(rc, 0)
                    self.assertFalse(any("capture_nsx_state.py" in " ".join(cmd) for _, cmd in commands))
                    if flags == ("--verify",):
                        self.assertIn("--source-capture", commands[0][1])
                        self.assertIn(str(self.capture), commands[0][1])
                        self.assertEqual("--sibling-map" in commands[0][1], phase == "c")
                    for _, cmd in commands:
                        if "--target" in cmd:
                            self.assertEqual(cmd[cmd.index("--target") + 1], "nsx-lm2")

    def test_ac_explicit_capture_rejected_before_any_step(self):
        for phase in ("a", "c"):
            self.assertEqual(self.run_workflow(phase, "--capture"), (2, []))

    def test_missing_capture_does_not_run_target_or_recapture(self):
        (self.capture / "manifest.json").unlink()
        for phase in ("a", "c"):
            for flags in ((), ("--apply",), ("--verify",)):
                self.assertEqual(self.run_workflow(phase, *flags), (2, []))

    def test_a_missing_flat_export_refuses_before_target_calls(self):
        (self.root / "nsx_services_export/lm1.test/services").rmdir()
        self.assertEqual(self.run_workflow("a"), (2, []))

    def test_c_verification_requires_sibling_map(self):
        self.smap.unlink()
        self.assertEqual(self.run_workflow("c", "--verify"), (2, []))

    def test_d_keeps_default_capture_and_no_capture_override(self):
        rc, commands = self.run_workflow("d2a", "--csv-remap", "map.csv")
        self.assertEqual(rc, 0)
        self.assertEqual(commands[0][0], "a0_capture")
        self.assertNotIn("--quiet", commands[0][1])
        rc, commands = self.run_workflow("d2a", "--csv-remap", "map.csv", "--no-capture")
        self.assertEqual(rc, 0)
        self.assertEqual(commands[0][0], "d1_build_siblings")

    def run_verify(self, ips=None, missing_rule=False):
        outer = self
        connected = []

        class Target:
            def __init__(self, *, nsxmanager, **kwargs):
                connected.append(nsxmanager)
                if nsxmanager != "lm2.test":
                    raise AssertionError("Verification attempted to log into LM1 with LM2 credentials")

            def list_groups(self, **kwargs):
                return [outer.group]

            def list_services(self):
                return [outer.service]

            def list_security_policies(self, **kwargs):
                return [outer.policy]

            def list_security_rules(self, **kwargs):
                return [] if missing_rule else [outer.rule]

            def get_group(self, *, group_id, **kwargs):
                if group_id == "g1":
                    return outer.group
                return {"id": group_id, "expression": [{"resource_type": "IPAddressExpression",
                                                         "ip_addresses": ips if ips is not None else ["10.0.0.1"]}]}

            def get_group_effective_ips(self, *args, **kwargs):
                return []

        argv = ["verify_avs_run.py", "--source", "nsx-lm1", "--target", "nsx-lm2",
                "--source-capture", str(self.capture), "--sibling-map", str(self.smap),
                "--report-dir", str(self.run / "verify")]
        with patch.object(verify, "NsxPolicyClient", Target), patch.object(verify, "init_cli"), \
                patch.object(verify, "resolve_manager", resolver), patch.object(sys, "argv", argv):
            rc = verify.main()
        report_path = self.run / "verify/verify_avs_run.json"
        return rc, connected, json.loads(report_path.read_text()) if report_path.exists() else None

    def test_verification_uses_only_target_credentials_and_records_capture(self):
        rc, connected, report = self.run_verify()
        self.assertEqual(rc, 0)
        self.assertEqual(connected, ["lm2.test"])
        self.assertEqual(report["source_mode"], "capture")
        self.assertEqual(report["source_captured_at"], self.manifest["captured_at"])
        self.assertEqual({r["check"] for r in report["checks"]}, {"V1", "V2", "V3", "V4", "V5", "V6"})

    def test_verification_fails_wrong_ips_and_missing_rules(self):
        rc, _, report = self.run_verify(ips=["10.0.0.99"])
        self.assertEqual(rc, 1)
        self.assertTrue(any(r["check"] == "V3" and not r["ok"] for r in report["checks"]))
        rc, _, report = self.run_verify(missing_rule=True)
        self.assertEqual(rc, 1)
        self.assertTrue(any(r["subject"] == "rules" and not r["ok"] for r in report["checks"]))

    def test_missing_truth_is_failure_not_empty_success_or_live_fallback(self):
        write_json(self.reports / "groups_changed.json", [])
        rc, connected, report = self.run_verify()
        self.assertEqual(rc, 1)
        self.assertEqual(connected, ["lm2.test"])
        self.assertTrue(any(r["check"] == "V3" and not r["ok"] for r in report["checks"]))

    def test_missing_report_refuses_before_authentication(self):
        (self.reports / "groups_changed.json").unlink()
        rc, connected, _ = self.run_verify()
        self.assertEqual(rc, 2)
        self.assertEqual(connected, [])

    def run_capture(self, *flags):
        commands = []

        def run_step(label, cmd, *args, **kwargs):
            commands.append(cmd)
            if label == "1_export_nsx_objects":
                dest = self.root / "new_capture/nsx_export/lm1.test/domains/default"
                shutil.copytree(self.raw, dest, dirs_exist_ok=True)
            return {"label": label, "ok": True, "returncode": 0, "cmd": cmd}

        argv = ["capture_nsx_state.py", "--source", "nsx-lm1", "--live-query",
                "--output-dir", str(self.root / "new_capture"), *flags]
        with patch.object(capture_tool, "run_step", run_step), \
                patch.object(capture_tool, "REPO_ROOT", self.root), \
                patch.object(capture_tool, "setup_logging", return_value=self.root / "test.log"), \
                patch.object(capture_tool, "resolve_manager", resolver), \
                patch.object(capture_tool, "init_cli"), \
                patch.object(capture_tool, "write_summary"), patch.object(sys, "argv", argv):
            rc = capture_tool.main()
        self.assertEqual(rc, 0)
        manifest = json.loads((self.root / "new_capture/manifest.json").read_text())
        return commands, manifest

    def test_capture_defaults_keep_only_core_steps_and_flat_exports(self):
        commands, manifest = self.run_capture()
        self.assertEqual([s["label"] for s in manifest["steps"]], [
            "1_export_nsx_objects", "2_build_group_ip_additive_from_live_members", "7_emit_flat_exports"])
        self.assertTrue(manifest["ok"])
        self.assertTrue((self.root / "nsx_groups_export/lm1.test/groups/g1.json").is_file())
        for option in ("with_segments", "with_vm_tags", "with_vm_attribution", "with_ip_report", "with_impact_report"):
            self.assertFalse(manifest["options"][option], option)
        for key in ("segment_inventory_dir", "segment_details_file", "segments_inventory_file", "vm_tags_export_root", "impact_report_dir"):
            self.assertIsNone(manifest["paths"][key], key)
        self.assertNotIn("--with-vm-attribution", commands[1])

    def test_optional_capture_steps_are_explicitly_available(self):
        commands, manifest = self.run_capture("--with-segments", "--with-vm-tags",
            "--with-vm-attribution", "--with-ip-report", "--impact-report")
        self.assertEqual(len(manifest["steps"]), 7)
        self.assertIn("--with-vm-attribution", commands[1])
        self.assertTrue(manifest["paths"]["segment_details_file"])
        self.assertTrue(manifest["paths"]["vm_tags_export_root"])

    def test_csv_report_is_explicit_opt_in_and_no_flags_still_work(self):
        commands, manifest = self.run_capture("--ip-report-csv", "map.csv")
        self.assertTrue(manifest["options"]["with_ip_report"])
        self.assertIn("--csv", commands[-1])
        commands, manifest = self.run_capture("--ip-report-csv", "map.csv", "--no-ip-report",
                                               "--no-vm-tags", "--no-flat-exports")
        self.assertFalse(manifest["options"]["with_ip_report"])
        self.assertEqual(len(manifest["steps"]), 2)

    def test_capture_keeps_effective_reports_inside_bundle(self):
        commands, _ = self.run_capture()
        cmd = next(c for c in commands if "tools/nsx/build_group_ip_additive_from_live_members.py" in c)
        reports = Path(cmd[cmd.index("--reports-dir") + 1])
        self.assertTrue(reports.is_relative_to(self.root / "new_capture"))
        self.assertIn("--live-query", cmd)
        self.assertFalse(any("find_rules_affected_by_group_changes.py" in " ".join(c) for c in commands))

    def test_segment_conversion_requires_opt_in_capture(self):
        argv = ["transform_capture.py", "--capture", str(self.capture), "--segment-mode", "convert",
                "--output-dir", str(self.root / "transformed")]
        with patch.object(transform_tool, "init_cli"), \
                patch.object(transform_tool, "setup_logging", return_value=self.root / "test.log"), \
                patch.object(transform_tool, "run_step") as run_step, patch.object(sys, "argv", argv):
            with self.assertRaisesRegex(SystemExit, "--with-segments"):
                transform_tool.main()
            run_step.assert_not_called()


class AdditiveCaptureTests(unittest.TestCase):
    """Exercise the real builder with a fake API that records every query."""

    def run_build(self, *flags, fail_group=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        source, output, reports = root / "source", root / "groups", root / "reports"
        for gid, ips in (("g1", []), ("g2", ["10.0.0.2"]), ("empty", [])):
            write_json(source / f"{gid}.json", {"id": gid, "display_name": gid, "resource_type": "Group",
                "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ips}] if ips else []})
        calls = []

        class Client:
            def __init__(self, **kwargs):
                calls.append("connect")

            def build_vm_ip_index(self):
                calls.append("vm_index")
                return {"vm1": ["10.0.0.99"]}

            def get_group_member_vm_ips(self, *, group_id, **kwargs):
                calls.append(("vm_members", group_id))
                return {"vm1": ["10.0.0.99"]} if group_id != "empty" else {}

            def get_group_effective_ips(self, *, group_id, **kwargs):
                calls.append(("effective", group_id))
                if group_id == fail_group:
                    raise RuntimeError("group not realized")
                return {"g1": ["10.0.0.1"], "g2": ["10.0.0.2"], "empty": []}[group_id]

        argv = ["build_group_ip_additive_from_live_members.py", "--source-manager", "nsx-lm1",
                "--source-groups-dir", str(source), "--output-groups-dir", str(output),
                "--reports-dir", str(reports), "--copy-first", "--output-format", "json", *flags]
        with patch.object(additive_tool, "NsxPolicyClient", Client), \
                patch.object(additive_tool, "resolve_manager", resolver), \
                patch.object(additive_tool, "init_cli"), \
                patch.object(additive_tool, "_setup_logging", return_value=root / "test.log"), \
                patch.object(sys, "argv", argv):
            additive_tool.main()
        return calls, json.loads((output / "manifest.json").read_text()), output, reports

    def test_effective_capture_skips_vm_queries_and_preserves_truth(self):
        calls, summary, output, reports = self.run_build("--live-query")
        self.assertEqual(calls, ["connect", ("effective", "empty"), ("effective", "g1"), ("effective", "g2")])
        self.assertEqual(summary["effective_ip_queries"], 3)
        self.assertEqual(summary["vm_ip_index_count"], 0)
        self.assertFalse(summary["vm_attribution_collected"])
        self.assertEqual(json.loads((output / "g1.json").read_text())["expression"][0]["ip_addresses"], ["10.0.0.1"])
        self.assertEqual(json.loads((reports / "groups_no_new_ips.json").read_text())[0]["candidate_ips"], ["10.0.0.2"])
        self.assertEqual(json.loads((reports / "groups_no_ips.json").read_text())[0]["group_id"], "empty")
        self.assertEqual(summary["groups_errors"], 0)

    def test_vm_attribution_opt_in_does_not_change_effective_truth(self):
        calls, summary, output, _ = self.run_build("--live-query", "--with-vm-attribution")
        self.assertIn("vm_index", calls)
        self.assertIn(("vm_members", "g1"), calls)
        self.assertEqual(summary["effective_ip_queries"], 3)
        self.assertTrue(summary["vm_attribution_collected"])
        self.assertEqual(json.loads((output / "g1.json").read_text())["expression"][0]["ip_addresses"], ["10.0.0.1"])

    def test_legacy_vm_vif_still_uses_vm_queries(self):
        calls, summary, output, _ = self.run_build("--live-query", "--ip-source", "vm-vif")
        self.assertIn("vm_index", calls)
        self.assertIn(("vm_members", "g1"), calls)
        self.assertEqual(summary["effective_ip_queries"], 0)
        self.assertTrue(summary["vm_attribution_collected"])
        self.assertEqual(json.loads((output / "g1.json").read_text())["expression"][0]["ip_addresses"], ["10.0.0.99"])

    def test_offline_copy_does_not_connect_even_with_attribution_flag(self):
        calls, summary, _, _ = self.run_build("--with-vm-attribution")
        self.assertEqual(calls, [])
        self.assertEqual(summary["ip_source"], "n/a (offline copy)")
        self.assertFalse(summary["vm_attribution_collected"])

    def test_failed_effective_query_is_recorded_for_capture_gate(self):
        _, summary, _, _ = self.run_build("--live-query", "--continue-on-group-error", fail_group="g1")
        self.assertEqual(summary["groups_errors"], 1)
        self.assertEqual(summary["effective_ip_queries"], 2)


if __name__ == "__main__":
    unittest.main()
