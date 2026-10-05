"""NSX to Panorama exact mirror (app/multisite/pan_mirror.py, tools/pan/nsx_pan_mirror.py).

Mike, 2026-10-04: match everything created on NSX exactly: group type,
membership, tags. VM objects are named by hostname, address objects by the
address; objects carry the VMs' NSX tags.

The push and revert tests use a fake Panorama: push creates only what is
missing and never changes an existing object; revert deletes only what the
push created, newest first.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from multisite.pan_mirror import MirrorOptions, build_mirror, ip_object, split_expression, tag_name  # noqa: E402

G = "/infra/domains/default/groups/"
OR = {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"}
AND = {"resource_type": "ConjunctionOperator", "conjunction_operator": "AND"}


def cond(value, key="Tag", member="VirtualMachine", op="EQUALS"):
    return {"resource_type": "Condition", "member_type": member, "key": key, "operator": op, "value": value}


def ips(*a):
    return {"resource_type": "IPAddressExpression", "ip_addresses": list(a)}


def paths(*a):
    return {"resource_type": "PathExpression", "paths": list(a)}


def group(gid, *expr, system=False):
    g = {"id": gid, "display_name": gid, "path": G + gid, "expression": list(expr)}
    if system:
        g["_system_owned"] = True
    return g


def vm(ext, host, ip, *tags):
    t = [{"scope": "hostname", "tag": host}] if host else []
    t += [{"scope": s, "tag": v} for s, v in tags]
    return {"external_id": ext, "display_name": f"vm-{ext}", "type": "REGULAR",
            "ips": [ip] if ip else [], "tags": t}


class NamingTests(unittest.TestCase):
    def test_address_objects_named_by_address(self):
        self.assertEqual(ip_object("10.6.0.50"), {"name": "10.6.0.50", "type": "ip-netmask", "value": "10.6.0.50/32"})
        self.assertEqual(ip_object("10.6.1.0/24")["name"], "10.6.1.0_24")
        self.assertEqual(ip_object("10.6.0.52-10.6.0.53")["type"], "ip-range")
        self.assertIsNone(ip_object("not-an-ip"))

    def test_tag_names(self):
        self.assertEqual(tag_name("network", "10.6.0.0", "{scope}.{value}"), "network.10.6.0.0")
        self.assertEqual(tag_name("", "Edge_NSGroup", "{scope}.{value}"), "Edge_NSGroup")


class ExpressionTests(unittest.TestCase):
    def test_and_or_and_nesting_preserved(self):
        p = split_expression([{"resource_type": "NestedExpression",
                               "expressions": [cond("network|10.6.0.0"), AND, cond("vm|1")]},
                              OR, cond("asl_id|1"), OR, ips("10.2.3.0/24")], MirrorOptions())
        self.assertEqual(" ".join(p.filter_terms), "('network.10.6.0.0' and 'vm.1') or 'asl_id.1'")
        self.assertEqual(p.ips, ["10.2.3.0/24"])

    def test_unsupported_reported(self):
        p = split_expression([cond("web", key="Name", op="CONTAINS"), OR,
                              paths("/infra/segments/seg-1"), OR, cond("network|")], MirrorOptions())
        self.assertEqual(p.filter_terms, [])
        self.assertEqual(len(p.unsupported), 3)


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.groups = [
            group("tag-web", cond("network|10.6.0.0")),
            group("ip-only", ips("10.6.0.50", "10.6.1.0/24")),
            group("nested", paths(G + "tag-web", G + "ip-only")),
            group("mixed", cond("vm|2"), OR, ips("10.21.10.20")),
            group("by-id", {"resource_type": "ExternalIDExpression", "member_type": "VirtualMachine",
                            "external_ids": ["e2"]}),
            group("seg-only", paths("/infra/segments/seg-1")),
            group("sys", cond("x|y"), system=True),
        ]
        self.vms = [vm("e1", "ax2001", "10.6.0.101", ("network", "10.6.0.0"), ("asl_id", "0")),
                    vm("e2", "0e02", "10.6.0.102", ("vm", "2")),
                    vm("e3", None, "10.6.0.103", ("network", "10.6.0.0")),
                    vm("e4", "x515", None, ("network", "10.6.0.0"))]
        self.plan = build_mirror(self.groups, self.vms, MirrorOptions())
        self.by_name = {g["name"]: g for g in self.plan["address_groups"]}
        self.addr = {a["name"]: a for a in self.plan["addresses"]}

    def test_group_types_match_nsx(self):
        self.assertEqual(self.by_name["tag-web"], {**self.by_name["tag-web"], "kind": "dynamic",
                                                   "filter": "'network.10.6.0.0'"})
        self.assertEqual(self.by_name["ip-only"]["kind"], "static")
        self.assertEqual(self.by_name["ip-only"]["members"], ["10.6.0.50", "10.6.1.0_24"])
        self.assertEqual(self.by_name["nested"]["members"], ["tag-web", "ip-only"])
        self.assertEqual(self.by_name["by-id"]["members"], ["0e02"])
        self.assertNotIn("sys", self.by_name)
        self.assertNotIn("seg-only", self.by_name)

    def test_mixed_group_gets_helper(self):
        self.assertEqual(self.by_name["mixed-tags"]["kind"], "dynamic")
        self.assertEqual(self.by_name["mixed"]["members"], ["mixed-tags", "10.21.10.20"])

    def test_vm_objects_named_by_hostname_with_all_nsx_tags(self):
        a = self.addr["ax2001"]
        self.assertEqual(a["value"], "10.6.0.101/32")
        self.assertEqual(a["tags"], ["asl_id.0", "hostname.ax2001", "network.10.6.0.0"])
        self.assertIn("0e02", self.addr)
        self.assertIn("vm.2", [t["name"] for t in self.plan["tags"]])

    def test_findings(self):
        codes = {(f["code"], f.get("vm") or f.get("group")) for f in self.plan["findings"]}
        self.assertIn(("vm_missing_hostname", "vm-e3"), codes)
        self.assertIn(("vm_without_ip", "vm-e4"), codes)
        self.assertIn(("empty_group", "seg-only"), codes)
        self.assertIn(("mixed_group", "mixed"), codes)

    def test_members_created_before_holders(self):
        order = [w["name"] for w in self.plan["writes"]]
        kinds = [w["kind"] for w in self.plan["writes"]]
        self.assertEqual(kinds, sorted(kinds, key=["tag", "address", "address-group"].index))
        self.assertLess(order.index("tag-web"), order.index("nested"))
        self.assertLess(order.index("mixed-tags"), order.index("mixed"))

    def test_only_pulls_in_nested_dependencies(self):
        p = build_mirror(self.groups, self.vms, MirrorOptions(), only=["nested"])
        self.assertEqual(sorted(g["name"] for g in p["address_groups"]), ["ip-only", "nested", "tag-web"])

    def test_rest_payloads(self):
        """Exact REST bodies: POST <resource>?location=device-group&device-group=dg-5&name=<name>."""
        w = {x["name"]: x for x in self.plan["writes"]}
        self.assertEqual(w["tag-web"]["resource"], "Objects/AddressGroups")
        self.assertEqual(w["tag-web"]["device_group"], "dg-5")
        self.assertEqual(w["tag-web"]["entry"]["dynamic"], {"filter": "'network.10.6.0.0'"})
        self.assertEqual(w["ip-only"]["entry"]["static"], {"member": ["10.6.0.50", "10.6.1.0_24"]})
        self.assertEqual(w["ax2001"]["resource"], "Objects/Addresses")
        self.assertEqual(w["ax2001"]["entry"]["ip-netmask"], "10.6.0.101/32")
        self.assertEqual(w["ax2001"]["entry"]["tag"], {"member": ["asl_id.0", "hostname.ax2001", "network.10.6.0.0"]})
        self.assertEqual(w["network.10.6.0.0"]["resource"], "Objects/Tags")
        self.assertNotIn("xpath", w["ax2001"])

    def test_vm_selection_does_not_depend_on_order(self):
        """A VM sharing only a non-filter tag (asl_id.0) with an included VM is not
        pulled in, whatever order the VMs come in."""
        extra = vm("e9", "zz99", "10.6.9.9", ("asl_id", "0"))
        for vms in (self.vms + [extra], [extra] + self.vms):
            p = build_mirror(self.groups, vms, MirrorOptions())
            self.assertNotIn("zz99", [a["name"] for a in p["addresses"]])

    def test_shared_namespace_clash(self):
        g = [group("10.6.0.50", ips("10.6.0.50"))]       # a group named like an address
        p = build_mirror(g, [], MirrorOptions())
        self.assertIn("name_clash", [f["code"] for f in p["findings"]])


def load_tool():
    spec = importlib.util.spec_from_file_location("nsx_pan_mirror_t", ROOT / "tools/pan/nsx_pan_mirror.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class FakePanorama:
    """REST-shaped stand-in: objects keyed by (resource, name)."""

    def __init__(self, existing=(), fail_on=None, device_groups=("dg-5",)):
        self.objs = {k: {"@name": k[1]} for k in existing}
        self.calls = []
        self.fail_on = fail_on
        self.dgs = set(device_groups)

    def device_group_exists(self, dg):
        return dg in self.dgs

    def exists(self, w):
        self.calls.append(("get", w["resource"], w["name"]))
        return self.objs.get((w["resource"], w["name"]))

    def create(self, w):
        self.calls.append(("post", w["resource"], w["name"]))
        if self.fail_on == w["name"]:
            raise RuntimeError("refused")
        self.objs[(w["resource"], w["name"])] = w["entry"]

    def delete(self, w):
        self.calls.append(("delete", w["resource"], w["name"]))
        del self.objs[(w["resource"], w["name"])]


class PushRevertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()
        def w(kind, res, name, entry):
            return {"kind": kind, "name": name, "resource": res, "device_group": "dg-5", "entry": entry}
        cls.writes = [w("tag", "Objects/Tags", "t1", {"@name": "t1"}),
                      w("address", "Objects/Addresses", "a1", {"@name": "a1", "ip-netmask": "1.1.1.1/32"}),
                      w("address-group", "Objects/AddressGroups", "g1", {"@name": "g1", "static": {"member": ["a1"]}})]

    def test_missing_device_group_is_detected(self):
        self.assertTrue(self.tool.device_group_exists(FakePanorama(), "dg-5"))
        self.assertFalse(self.tool.device_group_exists(FakePanorama(device_groups=()), "dg-5"))

    def test_dry_run_writes_nothing(self):
        pan = FakePanorama()
        rows = self.tool.push_writes(pan, self.writes, apply=False)
        self.assertEqual([r["status"] for r in rows], ["would_create"] * 3)
        self.assertFalse([c for c in pan.calls if c[0] != "get"])
        self.assertEqual(rows[0]["entry"], {"@name": "t1"})

    def test_apply_creates_only_missing_and_never_touches_existing(self):
        pan = FakePanorama(existing=[("Objects/Addresses", "a1")])
        rows = self.tool.push_writes(pan, self.writes, apply=True)
        self.assertEqual([r["status"] for r in rows], ["created", "exists_unchanged", "created"])
        self.assertNotIn(("post", "Objects/Addresses", "a1"), pan.calls)

    def test_apply_stops_at_first_failure(self):
        pan = FakePanorama(fail_on="a1")
        rows = self.tool.push_writes(pan, self.writes, apply=True)
        self.assertEqual([r["status"] for r in rows], ["created", "failed"])
        self.assertNotIn(("Objects/AddressGroups", "g1"), pan.objs)

    def test_revert_deletes_only_created_newest_first(self):
        pan = FakePanorama(existing=[("Objects/Addresses", "a1")])
        rows = self.tool.push_writes(pan, self.writes, apply=True)
        preview = self.tool.revert_created(pan, rows, apply=False)
        self.assertEqual([r["status"] for r in preview], ["would_delete", "would_delete"])
        done = self.tool.revert_created(pan, rows, apply=True)
        self.assertEqual([(r["name"], r["status"]) for r in done], [("g1", "deleted"), ("t1", "deleted")])
        self.assertEqual(list(pan.objs), [("Objects/Addresses", "a1")])   # the pre-existing object stays
        again = self.tool.revert_created(pan, rows, apply=True)
        self.assertEqual([r["status"] for r in again], ["already_gone", "already_gone"])


if __name__ == "__main__":
    unittest.main()


class SiblingMirrorTests(unittest.TestCase):
    """Mike, 2026-10-05: only the sibling IP groups go to the Palo, same names
    as on NSX; addresses named <hostname>-<address>-<suffix>."""

    def setUp(self):
        from multisite.pan_mirror import build_sibling_mirror
        self.build = build_sibling_mirror
        self.vms = [vm("e1", "ax2001", "10.6.0.101"), vm("e2", "0e02", None),
                    vm("e3", "dupA", "10.6.0.150"), vm("e4", "dupB", "10.6.0.150")]

    @staticmethod
    def mapped(appendix, *rows):
        return {"path": f"b{appendix}", "sibling_map": {"appendix": appendix, "source_host": "lm1", "map": [
            {"sibling_display_name": n, "original_display_name": n.rsplit(appendix, 1)[0],
             "ip_pairs": pairs, "ips_sibling_mapped": [d for _, ds in pairs for d in ds]} for n, pairs in rows]}}

    def test_mapped_view_names(self):
        b = self.mapped("_avs_ips", ("web_avs_ips", [["10.6.0.101", ["10.7.0.101"]], ["10.6.1.0/24", ["10.7.1.0/24"]],
                                                     ["10.6.0.99", ["10.7.0.99"]], ["10.6.0.5-10.6.0.9", []]]))
        p = self.build([b], self.vms)
        g = p["address_groups"][0]
        self.assertEqual(g["name"], "web_avs_ips")
        self.assertEqual(g["members"], ["ax2001-10.7.0.101-avs_ips", "10.7.1.0_24-avs_ips", "10.7.0.99-avs_ips"])
        self.assertEqual(p["counts"]["named_by_hostname"], 1)
        self.assertEqual(p["counts"]["dynamic_groups"], 0)
        self.assertEqual(p["tags"], [])

    def test_source_view_names_and_range(self):
        b = {"path": "bnp", "sibling_map": {"appendix": "_np_ips", "map": [
            {"sibling_display_name": "web_np_ips", "original_display_name": "web", "ips_sibling_mapped": None,
             "ip_pairs": [], "ips_source": ["10.6.0.101", "10.21.1.10-10.21.1.12"]}]}}
        p = self.build([b], self.vms)
        self.assertEqual(p["address_groups"][0]["members"], ["ax2001-10.6.0.101-np_ips", "10.21.1.10-10.21.1.12-np_ips"])
        a = {x["name"]: x for x in p["addresses"]}
        self.assertEqual(a["10.21.1.10-10.21.1.12-np_ips"]["type"], "ip-range")
        self.assertEqual(a["ax2001-10.6.0.101-np_ips"]["value"], "10.6.0.101/32")

    def test_address_shared_by_two_vms_named_by_ip(self):
        b = self.mapped("_avs_ips", ("g_avs_ips", [["10.6.0.150", ["10.7.0.150"]]]))
        p = self.build([b], self.vms)
        self.assertEqual(p["address_groups"][0]["members"], ["10.7.0.150-avs_ips"])
        self.assertIn("address_shared_by_vms", [f["code"] for f in p["findings"]])

    def test_same_sibling_in_two_bundles(self):
        same = self.mapped("_lm3_ips", ("g_lm3_ips", [["10.6.0.101", ["10.8.0.101"]]]))
        other = self.mapped("_lm3_ips", ("g_lm3_ips", [["10.6.0.101", ["10.8.0.201"]]]))
        self.assertEqual(len(self.build([same, same], self.vms)["address_groups"]), 1)
        codes = [f["code"] for f in self.build([same, other], self.vms)["findings"]]
        self.assertIn("sibling_differs_between_bundles", codes)

    def test_bundle_inconsistency_and_empty_sibling(self):
        b = self.mapped("_avs_ips", ("g_avs_ips", [["10.6.0.101", ["10.7.0.101"]]]), ("empty_avs_ips", []))
        b["sibling_map"]["map"][0]["ips_sibling_mapped"] = ["10.7.9.9"]
        p = self.build([b], self.vms)
        codes = [f["code"] for f in p["findings"]]
        self.assertIn("bundle_inconsistent", codes)
        self.assertIn("empty_group", codes)
        self.assertEqual([g["name"] for g in p["address_groups"]], ["g_avs_ips"])

    def test_rest_writes_are_addresses_then_static_groups(self):
        b = self.mapped("_avs_ips", ("g_avs_ips", [["10.6.0.101", ["10.7.0.101"]]]))
        w = self.build([b], self.vms)["writes"]
        self.assertEqual([x["resource"] for x in w], ["Objects/Addresses", "Objects/AddressGroups"])
        self.assertEqual(w[1]["entry"]["static"], {"member": ["ax2001-10.7.0.101-avs_ips"]})
        self.assertNotIn("tag", w[0]["entry"])

    def test_no_vm_lookup_names_everything_by_address(self):
        b = self.mapped("_avs_ips", ("g_avs_ips", [["10.6.0.101", ["10.7.0.101"]]]))
        self.assertEqual(self.build([b], [])["address_groups"][0]["members"], ["10.7.0.101-avs_ips"])
