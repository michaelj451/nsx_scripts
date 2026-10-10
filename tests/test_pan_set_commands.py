"""PAN-OS CLI commands from a Palo plan (app/multisite/pan_set_commands.py),
Mike 2026-10-09: a paste-ready file that creates every object of the plan, and
the matching deletes. Each line comes from the same REST entry the push sends.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from multisite.pan_set_commands import (  # noqa: E402
    delete_commands, quote, render_files, set_command, set_commands)


def w(kind, name, entry, location="shared", resource="", dg="dg-4"):
    return {"kind": kind, "name": name, "location": location, "device_group": dg, "vsys": "vsys1",
            "resource": resource, "entry": {"@name": name, **entry}}


class QuoteTests(unittest.TestCase):
    def test_plain_and_quoted(self):
        self.assertEqual(quote("ax2001-10.6.0.101-np_ips"), "ax2001-10.6.0.101-np_ips")
        self.assertEqual(quote("10.6.0.52-10.6.0.53"), "10.6.0.52-10.6.0.53")
        self.assertEqual(quote("10.8.1.102/32"), "10.8.1.102/32")
        self.assertEqual(quote("NSX service HTTPS"), '"NSX service HTTPS"')
        self.assertEqual(quote('say "hi"'), "\"say 'hi'\"")
        self.assertEqual(quote(""), '""')


class ObjectTests(unittest.TestCase):
    def test_address_type_first_description_last(self):
        line = set_command(w("address", "0102-10.8.1.102-lm3_ips",
                             {"description": "NSX VM vm1 (mapped from 10.6.1.102)",
                              "ip-netmask": "10.8.1.102/32"}))
        self.assertEqual(line, 'set shared address 0102-10.8.1.102-lm3_ips ip-netmask 10.8.1.102/32 '
                               'description "NSX VM vm1 (mapped from 10.6.1.102)"')

    def test_range_and_device_group_location(self):
        line = set_command(w("address", "10.6.0.52-10.6.0.53", {"ip-range": "10.6.0.52-10.6.0.53"},
                             location="device-group"))
        self.assertEqual(line, "set device-group dg-4 address 10.6.0.52-10.6.0.53 ip-range 10.6.0.52-10.6.0.53")

    def test_static_group_members(self):
        line = set_command(w("address-group", "web_np_ips",
                             {"static": {"member": ["a-np_ips", "b-lm3_ips"]}, "description": "NSX group web"}))
        self.assertEqual(line, 'set shared address-group web_np_ips static [ a-np_ips b-lm3_ips ] '
                               'description "NSX group web"')
        one = set_command(w("address-group", "g", {"static": {"member": ["only"]}}))
        self.assertEqual(one, "set shared address-group g static only")

    def test_dynamic_group_filter(self):
        line = set_command(w("address-group", "d", {"dynamic": {"filter": "'web' and 'prod'"}}))
        self.assertEqual(line, "set shared address-group d dynamic filter \"'web' and 'prod'\"")

    def test_service_and_source_port(self):
        line = set_command(w("service", "svc", {"protocol": {"tcp": {"port": "8443", "source-port": "1024-65535"}},
                                                "description": "NSX service svc"}))
        self.assertEqual(line, 'set shared service svc protocol tcp port 8443 source-port 1024-65535 '
                               'description "NSX service svc"')

    def test_service_group(self):
        line = set_command(w("service-group", "bundle", {"members": {"member": ["bundle-tcp", "bundle-udp"]}}))
        self.assertEqual(line, "set shared service-group bundle members [ bundle-tcp bundle-udp ]")


class RuleTests(unittest.TestCase):
    ENTRY = {"action": "allow", "application": {"member": ["any"]}, "category": {"member": ["any"]},
             "description": "NSX app / web", "destination": {"member": ["db_np_ips"]}, "disabled": "no",
             "from": {"member": ["any"]}, "log-setting": "test-logging-profile",
             "profile-setting": {"group": {"member": ["test-security-profile"]}},
             "service": {"member": ["HTTPS", "svc"]}, "source": {"member": ["web_np_ips"]},
             "source-user": {"member": ["any"]}, "to": {"member": ["any"]}}

    def test_pre_rule_in_device_group(self):
        line = set_command(w("security-rule", "web to db", self.ENTRY, location="device-group",
                             resource="Policies/SecurityPreRules"))
        self.assertEqual(line,
                         'set device-group dg-4 pre-rulebase security rules "web to db" from any to any '
                         'source web_np_ips destination db_np_ips source-user any category any application any '
                         'service [ HTTPS svc ] action allow profile-setting group test-security-profile '
                         'log-setting test-logging-profile disabled no description "NSX app / web"')

    def test_post_rule_and_negate(self):
        e = {**self.ENTRY, "negate-source": "yes"}
        line = set_command(w("security-rule", "r", e, location="device-group",
                             resource="Policies/SecurityPostRules"))
        self.assertTrue(line.startswith("set device-group dg-4 post-rulebase security rules r from any to any "
                                        "source web_np_ips destination db_np_ips negate-source yes "))

    def test_individual_profiles(self):
        e = {**self.ENTRY, "profile-setting": {"profiles": {"virus": {"member": ["av1"]},
                                                            "spyware": {"member": ["as1"]}}}}
        line = set_command(w("security-rule", "r", e, location="device-group",
                             resource="Policies/SecurityPreRules"))
        self.assertIn(" profile-setting profiles virus av1 spyware as1 ", line)

    def test_firewall_target(self):
        line = set_command(w("security-rule", "r", {"action": "deny"}, location="vsys",
                             resource="Policies/SecurityRules"))
        self.assertEqual(line, "set rulebase security rules r action deny")
        self.assertEqual(set_command(w("address", "a", {"ip-netmask": "10.0.0.1/32"}, location="vsys")),
                         "set address a ip-netmask 10.0.0.1/32")

    def test_unknown_rulebase_refused(self):
        with self.assertRaises(ValueError):
            set_command(w("security-rule", "r", {}, location="device-group", resource="Policies/Nope"))


class PlanTests(unittest.TestCase):
    def test_order_and_deletes_reversed(self):
        plan = {"writes": [
            w("address", "a1", {"ip-netmask": "10.6.0.1/32"}),
            w("address-group", "g1", {"static": {"member": ["a1"]}}),
            w("service", "s1", {"protocol": {"udp": {"port": "53"}}}),
            w("security-rule", "r1", {"action": "allow"}, location="device-group",
              resource="Policies/SecurityPreRules")]}
        self.assertEqual([c.split()[2] for c in set_commands(plan)],
                         ["address", "address-group", "service", "dg-4"])
        self.assertEqual(delete_commands(plan), [
            "delete device-group dg-4 pre-rulebase security rules r1",
            "delete shared service s1", "delete shared address-group g1", "delete shared address a1"])
        files = render_files(plan)
        self.assertEqual(sorted(files), ["pan_delete_commands.txt", "pan_set_commands.txt"])
        text = files["pan_set_commands.txt"]
        self.assertEqual(len(text.splitlines()), 4)
        self.assertFalse(any(line.startswith("#") or not line.startswith("set ") for line in text.splitlines()))

    def test_real_rule_plan_one_line_per_write(self):
        """A plan from the real rule planner: one set line per write, objects
        in shared before the device-group rule that uses them."""
        sys.path.insert(0, str(ROOT / "tests"))
        import test_pan_rules as tpr
        plan = tpr.plan_for(tpr.rule("r1", ["web"], ["db"], ["HTTPS"]))
        lines = set_commands(plan)
        self.assertEqual(len(lines), len(plan["writes"]))
        self.assertTrue(lines[-1].startswith("set device-group dg-5 pre-rulebase security rules r1 from any to any "))
        kinds = [l.split()[2] for l in lines[:-1]]
        self.assertTrue(set(kinds) <= {"address", "address-group", "service", "service-group"}, kinds)
        self.assertTrue(all(l.startswith("set shared ") for l in lines[:-1]))
        self.assertEqual(delete_commands(plan)[0], "delete device-group dg-5 pre-rulebase security rules r1")

class DryRunTests(unittest.TestCase):
    """Mike, 2026-10-09: the push dry run writes the paste text, for exactly
    the objects it found missing; the delete text removes only those."""

    def _doc(self):
        a1 = w("address", "a1", {"ip-netmask": "10.6.0.1/32"})
        a2 = w("address", "a2", {"ip-netmask": "10.6.0.2/32"})
        g1 = w("address-group", "g1", {"static": {"member": ["a1", "a2"]}})
        rows = []
        for x, status in ((a1, "exists_unchanged"), (a2, "would_create"), (g1, "would_create")):
            r = {k: x[k] for k in ("kind", "name", "resource", "location", "device_group")}
            r["status"] = status
            if status == "would_create":
                r["entry"] = x["entry"]
            rows.append(r)
        return {"results": rows, "summary": {"would_create": 2, "exists_unchanged": 1}}

    def test_only_missing_objects_in_order(self):
        from multisite.pan_set_commands import missing_writes, write_from_dryrun
        import tempfile
        doc = self._doc()
        self.assertEqual([r["name"] for r in missing_writes(doc)], ["a2", "g1"])
        d = Path(tempfile.mkdtemp())
        paths = write_from_dryrun(d / "push_20261009_120000_dryrun.json", doc)
        self.assertEqual([x.name for x in paths], [
            "push_20261009_120000_dryrun_set_commands.txt", "push_20261009_120000_dryrun_delete_commands.txt",
            "pan_set_commands.txt", "pan_delete_commands.txt"])
        self.assertEqual((d / "pan_set_commands.txt").read_text().splitlines(),
                         ["set shared address a2 ip-netmask 10.6.0.2/32", "set shared address-group g1 static [ a1 a2 ]"])
        self.assertEqual((d / "pan_delete_commands.txt").read_text().splitlines(),
                         ["delete shared address-group g1", "delete shared address a2"])
        self.assertEqual(paths[0].read_text(), paths[2].read_text())

    def test_nothing_missing_gives_empty_files(self):
        from multisite.pan_set_commands import write_from_dryrun
        import tempfile
        d = Path(tempfile.mkdtemp())
        paths = write_from_dryrun(d / "push_x_dryrun.json", {"results": [{"status": "exists_unchanged"}]})
        self.assertEqual([x.read_text() for x in paths], ["", "", "", ""])


class StandaloneScriptTests(unittest.TestCase):
    """tools/pan/pan_cli_commands.py: the same text by hand, from any run."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("pan_cli_commands_t", ROOT / "tools/pan/pan_cli_commands.py")
        cls.cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.cli)

    def _plan(self, root, writes):
        import json
        pdir = root / "palo"
        pdir.mkdir(parents=True)
        (pdir / "plan.json").write_text(json.dumps({"writes": writes}), encoding="utf-8")
        return pdir / "plan.json"

    def test_finds_plan_from_file_folder_or_run_folder(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        plan = self._plan(root, [w("address", "a1", {"ip-netmask": "10.6.0.1/32"})])
        for given in (plan, plan.parent, root):
            self.assertEqual(self.cli.resolve_plan(str(given)), plan.resolve())
        with self.assertRaises(SystemExit):
            self.cli.resolve_plan(str(root / "nowhere"))

    def test_default_uses_newest_dry_run(self):
        import json, tempfile
        root = Path(tempfile.mkdtemp())
        plan = self._plan(root, [w("address", "a1", {"ip-netmask": "10.6.0.1/32"})])
        with self.assertRaises(SystemExit):          # no dry run yet
            self.cli.main(["--plan", str(root)])
        old = DryRunTests()._doc()
        (plan.parent / "push_20261009_100000_dryrun.json").write_text(json.dumps({"results": []}))
        (plan.parent / "push_20261009_110000_dryrun.json").write_text(json.dumps(old))
        self.assertEqual(self.cli.main(["--plan", str(root)]), 0)
        self.assertEqual(len((plan.parent / "pan_set_commands.txt").read_text().splitlines()), 2)

    def test_all_objects_without_a_dry_run(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        plan = self._plan(root, [w("address", "a1", {"ip-netmask": "10.6.0.1/32"}),
                                 w("address-group", "g1", {"static": {"member": ["a1"]}})])
        self.assertEqual(self.cli.main(["--plan", str(root), "--all-objects"]), 0)
        self.assertEqual((plan.parent / "pan_all_set_commands.txt").read_text().splitlines(),
                         ["set shared address a1 ip-netmask 10.6.0.1/32", "set shared address-group g1 static a1"])
        self.assertEqual((plan.parent / "pan_all_delete_commands.txt").read_text().splitlines(),
                         ["delete shared address-group g1", "delete shared address a1"])
        self.assertFalse((plan.parent / "pan_set_commands.txt").exists())
        empty = Path(tempfile.mkdtemp())
        self._plan(empty, [])
        with self.assertRaises(SystemExit):
            self.cli.main(["--plan", str(empty), "--all-objects"])

if __name__ == "__main__":
    unittest.main()
