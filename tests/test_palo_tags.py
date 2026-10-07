"""Palo Alto tag plan (app/multisite/palo_tags.py).

Mike's rule (2026-10-04): every VM is tagged with hostname and asl_id;
groups of at most 10 member VMs match their members' hostname tags; larger
groups get a unique security_group tag. Every VM has an asl_id.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from common.subnet_map import load_site_map  # noqa: E402
from multisite.palo_tags import PAN_NAME_MAX, TagOptions, build_tag_plan, pan_name  # noqa: E402

G = "/infra/domains/default/groups/"


def vm(i, ip=None, host=True, asl="7", name=None):
    tags = [{"scope": "asl_id", "tag": asl}] if asl else []
    if host:
        tags.append({"scope": "hostname", "tag": f"h{i:03d}"})
    return {"external_id": f"vm{i}", "display_name": name or f"vm-{i}", "type": "REGULAR",
            "ips": [ip] if ip else [], "tags": tags}


def snapshot(vms, groups, group_ips=None, rules=None):
    return {
        "vms": vms,
        "groups_by_path": {G + g: {"display_name": g, "id": g} for g in groups},
        "group_to_members": {G + g: m for g, m in groups.items()},
        "group_ips": {G + g: ips for g, ips in (group_ips or {}).items()},
        "rules": rules if rules is not None else [
            {"display_name": "r1", "source_groups": [G + g for g in groups], "destination_groups": ["ANY"]}],
    }


class StrategyTests(unittest.TestCase):
    def test_threshold_picks_hostname_or_security_group(self):
        vms = [vm(i, f"10.6.0.{i}") for i in range(1, 13)]
        snap = snapshot(vms, {"small": [f"vm{i}" for i in range(1, 11)],     # exactly 10
                              "big": [f"vm{i}" for i in range(1, 12)]})      # 11
        p = build_tag_plan(snap, TagOptions())
        g = {x["nsx_group"]: x for x in p["dynamic_groups"]}
        self.assertEqual(g["small"]["strategy"], "hostname")
        self.assertEqual(g["small"]["filter"].count("'hostname_h"), 10)
        self.assertEqual(g["big"]["strategy"], "security_group")
        self.assertEqual(g["big"]["filter"], "'security_group_big'")
        obj = {o["name"]: o for o in p["address_objects"]}
        self.assertEqual(obj["h001-10.6.0.1"]["tags"], ["asl_id_7", "hostname_h001", "security_group_big"])
        self.assertEqual(obj["h012-10.6.0.12"]["tags"] if "h012-10.6.0.12" in obj else None, None)  # not in a rule group
        self.assertEqual(p["findings"], [])

    def test_loose_addresses_become_tagged_static_objects(self):
        snap = snapshot([vm(1, "10.6.0.1"), vm(2, "10.6.0.2")],
                        {"g": ["vm1"], "other": ["vm2"]},
                        {"g": ["10.6.0.1", "10.21.0.0/24", "10.6.0.2", "10.21.1.5-10.21.1.9"]})
        p = build_tag_plan(snap, TagOptions())
        g = next(x for x in p["dynamic_groups"] if x["nsx_group"] == "g")
        self.assertEqual(g["filter"], "'hostname_h001' or 'security_group_g'")
        obj = {o["name"]: o for o in p["address_objects"]}
        self.assertEqual(obj["addr-10.21.0.0_24"]["tags"], ["security_group_g"])
        self.assertEqual(obj["addr-10.21.1.5-10.21.1.9"]["type"], "ip-range")
        # 10.6.0.2 is vm2's address: the group tag goes on vm2's own object
        self.assertIn("security_group_g", obj["h002-10.6.0.2"]["tags"])
        self.assertNotIn("addr-10.6.0.2", obj)

    def test_findings_for_missing_data(self):
        snap = snapshot([vm(1, "10.6.0.1", asl=None), vm(2, "10.6.0.2", host=False),
                         vm(3, None), vm(4, "10.6.0.4", name="dup")],
                        {"g": ["vm1", "vm2", "vm3", "vm4"]})
        snap["vms"][3]["tags"][1]["tag"] = "h001"          # same hostname as vm1
        codes = sorted({f["code"] for f in build_tag_plan(snap, TagOptions())["findings"]})
        self.assertEqual(codes, ["duplicate_hostname", "group_member_without_hostname",
                                 "vm_missing_asl_id", "vm_missing_hostname", "vm_without_ip"])

    def test_only_rule_referenced_groups_unless_all(self):
        snap = snapshot([vm(1, "10.6.0.1")], {"used": ["vm1"], "unused": ["vm1"]},
                        rules=[{"display_name": "r", "source_groups": [G + "used"],
                                "destination_groups": ["ANY"]},
                               {"display_name": "off", "disabled": True,
                                "source_groups": [G + "unused"], "destination_groups": []}])
        self.assertEqual([g["nsx_group"] for g in build_tag_plan(snap, TagOptions())["dynamic_groups"]],
                         ["used"])
        self.assertEqual(len(build_tag_plan(snap, TagOptions(all_groups=True))["dynamic_groups"]), 2)


class PrestageTests(unittest.TestCase):
    def test_vm_and_loose_addresses_prestaged_per_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = Path(tmp) / "m.csv"
            m.write_text("old_subnet,nsx-lm2,nsx-lm3\n10.6.0.0/16,10.7.0.0/16,10.8.0.0/16\n"
                         "10.21.0.0/16,10.31.0.0/16,\n", encoding="utf-8")
            sm = load_site_map(m)
        snap = snapshot([vm(1, "10.6.0.1")], {"g": ["vm1"]},
                        {"g": ["10.6.0.1", "10.21.0.0/24", "10.21.1.5-10.21.1.9"]})
        p = build_tag_plan(snap, TagOptions(), sm, sm.sites)
        obj = {o["name"]: o for o in p["address_objects"]}
        self.assertEqual(obj["h001-10.7.0.1"]["sites"], ["nsx-lm2"])
        self.assertEqual(obj["h001-10.8.0.1"]["tags"], obj["h001-10.6.0.1"]["tags"])
        self.assertIn("addr-10.31.0.0_24", obj)
        codes = [f["code"] for f in p["findings"]]
        self.assertIn("range_not_prestaged", codes)       # ranges are never remapped
        self.assertNotIn("addr-10.31.1.5-10.31.1.9", obj)

    def test_same_value_objects_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = Path(tmp) / "m.csv"
            m.write_text("old_subnet,nsx-lm2\n10.6.0.0/16,10.7.0.0/16\n", encoding="utf-8")
            sm = load_site_map(m)
        # the group already lists the lm2 address literally
        snap = snapshot([], {"g": []}, {"g": ["10.6.1.0/24", "10.7.1.0/24"]})
        p = build_tag_plan(snap, TagOptions(), sm, sm.sites)
        o = next(x for x in p["address_objects"] if x["name"] == "addr-10.7.1.0_24")
        self.assertEqual(o["sites"], ["nsx-lm2", "source"])
        self.assertFalse(any(f["code"] == "duplicate_object_name" for f in p["findings"]))


class NameTests(unittest.TestCase):
    def test_pan_names(self):
        long = pan_name("x" * 100)
        self.assertEqual(len(long), PAN_NAME_MAX)
        self.assertNotEqual(pan_name("x" * 100), pan_name("x" * 99 + "y"))
        self.assertEqual(pan_name("web/tier*1"), "web_tier_1")


if __name__ == "__main__":
    unittest.main()
