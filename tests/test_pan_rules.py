"""NSX rules to Panorama pre-rulebase rules (app/multisite/pan_rules.py), Palo track P3.

Decisions (Mike, 2026-10-06): every NSX group on a rule becomes ALL its
siblings across the bundles; an IP-only group with no source-view sibling is
mirrored as itself; members Panorama cannot match are left out (the rule gets
narrower, never wider; an empty side skips the rule); zones any/any.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from multisite.pan_rules import build_rule_mirror, group_kind  # noqa: E402

G = "/infra/domains/default/groups/"
S = "/infra/services/"


def ips(*a):
    return {"resource_type": "IPAddressExpression", "ip_addresses": list(a)}


def tag(v):
    return {"resource_type": "Condition", "member_type": "VirtualMachine", "key": "Tag", "operator": "EQUALS",
            "value": v}


def group(gid, *expr, name=None):
    return {"id": gid, "display_name": name or gid, "path": G + gid, "expression": list(expr)}


def l4(proto, *ports, src=()):
    return {"resource_type": "L4PortSetServiceEntry", "l4_protocol": proto, "destination_ports": list(ports),
            "source_ports": list(src)}


def svc(sid, *entries):
    return {"id": sid, "display_name": sid, "service_entries": list(entries)}


def rule(rid, src, dst, services=("ANY",), action="ALLOW", seq=1, **kw):
    r = {"id": rid, "display_name": rid, "sequence_number": seq, "action": action,
         "source_groups": [x if x == "ANY" or not x[0].isalpha() or "." in x else G + x for x in src],
         "destination_groups": [x if x == "ANY" or not x[0].isalpha() or "." in x else G + x for x in dst],
         "services": [x if x == "ANY" else S + x for x in services]}
    r.update(kw)
    return r


def policy(pid, *rules, category="Application", seq=10):
    return {"id": pid, "display_name": pid, "category": category, "sequence_number": seq, "rules": list(rules)}


def source_bundle(appendix, *rows):
    """WF-C view: siblings hold the group's current addresses."""
    return {"path": f"b{appendix}", "sibling_map": {"appendix": appendix, "source_host": "lm1", "map": [
        {"original_id": o, "original_display_name": o, "sibling_id": o + appendix,
         "sibling_display_name": o + appendix, "ips_sibling_mapped": None, "ip_pairs": [], "ips_source": a}
        for o, a in rows]}}


def mapped_bundle(appendix, *rows):
    """WF-D view: siblings hold the mapped addresses."""
    return {"path": f"b{appendix}", "sibling_map": {"appendix": appendix, "source_host": "lm1", "map": [
        {"original_id": o, "original_display_name": o, "sibling_id": o + appendix,
         "sibling_display_name": o + appendix, "ip_pairs": pairs,
         "ips_sibling_mapped": [d for _, ds in pairs for d in ds]} for o, pairs in rows]}}


GROUPS = [group("web", tag("network|10.6.0.0")), group("db", tag("network|10.6.1.0")),
          group("mgmt", ips("10.2.1.0/24")), group("seg", {"resource_type": "PathExpression",
                                                           "paths": ["/infra/segments/abc"]}),
          group("nest", {"resource_type": "PathExpression", "paths": [G + "mgmt", G + "web"]}),
          group("gone", tag("vm|9")), group("empty")]
SERVICES = [svc("HTTPS", l4("TCP", "443")), svc("DNS", l4("TCP", "53"), l4("UDP", "53")),
            svc("ICMP-ALL", {"resource_type": "ICMPTypeServiceEntry", "protocol": "ICMPv4"},
                {"resource_type": "ICMPTypeServiceEntry", "protocol": "ICMPv6"}),
            svc("echo", {"resource_type": "ICMPTypeServiceEntry", "protocol": "ICMPv4", "icmp_type": 8}),
            svc("bundle", {"resource_type": "NestedServiceServiceEntry", "nested_service_path": S + "HTTPS"},
                l4("TCP", "8443")),
            svc("gre", {"resource_type": "IPProtocolServiceEntry", "protocol_number": 47}),
            svc("FTP", {"resource_type": "ALGTypeServiceEntry", "alg": "FTP", "destination_ports": ["21"]}),
            svc("two-tcp", l4("TCP", "80"), l4("TCP", "8080"))]
BUNDLES = [source_bundle("_np_ips", ("web", ["10.6.0.101"]), ("db", ["10.6.1.101"])),
           mapped_bundle("_avs_ips", ("web", [["10.6.0.101", ["10.7.0.101"]]]),
                         ("db", [["10.6.1.101", ["10.7.1.101"]]]),
                         ("mgmt", [["10.2.1.0/24", ["10.20.1.0/24"]]])),
           mapped_bundle("_lm3_ips", ("web", [["10.6.0.101", ["10.8.0.101"]]]),
                         ("db", [["10.6.1.101", ["10.8.1.101"]]]))]


def plan_for(*rules, bundles=BUNDLES, category="Application"):
    return build_rule_mirror([policy("p1", *rules, category=category)], GROUPS, SERVICES, bundles, [])


def by_name(plan):
    return {r["name"]: r["entry"] for r in plan["rules"]}


class SideTests(unittest.TestCase):
    """Mike, 2026-10-06: one Panorama group per NSX group, "<group>_np_ips",
    holding the group's addresses from every view."""

    @staticmethod
    def members(p, name):
        return {g["name"]: g["members"] for g in p["address_groups"]}[name]

    def test_one_group_per_nsx_group_with_every_view(self):
        p = plan_for(rule("r1", ["web"], ["db"], ["HTTPS"]))
        e = by_name(p)["r1"]
        self.assertEqual(e["source"]["member"], ["web_np_ips"])
        self.assertEqual(e["destination"]["member"], ["db_np_ips"])
        self.assertEqual(self.members(p, "web_np_ips"), ["10.6.0.101-np_ips", "10.7.0.101-avs_ips", "10.8.0.101-lm3_ips"])
        self.assertEqual((e["from"], e["to"]), ({"member": ["any"]}, {"member": ["any"]}))
        # The per-view sibling groups are not created on Panorama.
        names = [g["name"] for g in p["address_groups"]]
        self.assertEqual(sorted(names), ["db_np_ips", "web_np_ips"])
        self.assertIn("all", p["address_groups"][0]["view"])
        self.assertIn("every site", p["writes"][[w["kind"] for w in p["writes"]].index("address-group")]["entry"]["description"])

    def test_sibling_refs_on_the_rule_fold_back_to_the_original(self):
        # A rule read from lm2/lm3 names original + _np_ips; the Palo still gets one group.
        p = plan_for(rule("r1", ["web", "web_np_ips"], ["db_np_ips"], ["HTTPS"]))
        e = by_name(p)["r1"]
        self.assertEqual((e["source"]["member"], e["destination"]["member"]), (["web_np_ips"], ["db_np_ips"]))

    def test_ip_only_group_adds_its_own_addresses(self):
        p = plan_for(rule("r1", ["mgmt"], ["web"], ["HTTPS"]))
        self.assertEqual(by_name(p)["r1"]["source"]["member"], ["mgmt_np_ips"])
        self.assertEqual(self.members(p, "mgmt_np_ips"), ["10.20.1.0_24-avs_ips", "10.2.1.0_24"])
        self.assertEqual(p["counts"]["address_groups"], 2)

    def test_nested_group_is_one_group_of_its_members_addresses(self):
        p = plan_for(rule("r1", ["nest"], ["db"], ["HTTPS"]))
        self.assertEqual(by_name(p)["r1"]["source"]["member"], ["nest_np_ips"])
        self.assertEqual(self.members(p, "nest_np_ips"),
                         ["10.20.1.0_24-avs_ips", "10.2.1.0_24", "10.6.0.101-np_ips", "10.7.0.101-avs_ips",
                          "10.8.0.101-lm3_ips"])

    def test_only_used_addresses_are_pushed(self):
        p = plan_for(rule("r1", ["web"], ["web"], ["HTTPS"]))
        self.assertEqual(sorted(a["name"] for a in p["addresses"]),
                         ["10.6.0.101-np_ips", "10.7.0.101-avs_ips", "10.8.0.101-lm3_ips"])

    def test_group_suffix_option(self):
        from multisite.pan_rules import RuleOptions
        p = build_rule_mirror([policy("p1", rule("r1", ["web"], ["db"]))], GROUPS, SERVICES, BUNDLES, [],
                              ropts=RuleOptions(group_suffix="_x"))
        self.assertEqual(by_name(p)["r1"]["source"]["member"], ["web_x"])

    def test_unmatchable_member_narrows_the_rule(self):
        p = plan_for(rule("r1", ["web", "seg"], ["db"], ["HTTPS"]))
        self.assertEqual(by_name(p)["r1"]["source"]["member"], ["web_np_ips"])
        self.assertIn("rule_narrower", [f["code"] for f in p["findings"]])

    def test_empty_side_skips_the_rule_never_any(self):
        p = plan_for(rule("r1", ["seg", "gone"], ["db"], ["HTTPS"]))
        self.assertEqual(p["rules"], [])
        self.assertEqual(p["counts"]["nsx_rules_skipped"], 1)

    def test_any_stays_any_and_literal_addresses_become_objects(self):
        p = plan_for(rule("r1", ["ANY"], ["db", "10.9.9.9"], ["HTTPS"]))
        e = by_name(p)["r1"]
        self.assertEqual(e["source"]["member"], ["any"])
        self.assertEqual(e["destination"]["member"], ["10.9.9.9", "db_np_ips"])
        self.assertIn("10.9.9.9", [a["name"] for a in p["addresses"]])

    def test_rules_without_any_sibling_are_out_of_scope(self):
        p = plan_for(rule("r1", ["seg"], ["empty"]), rule("r2", ["web"], ["db"], ["HTTPS"], seq=2))
        self.assertEqual([r["name"] for r in p["rules"]], ["r2"])
        self.assertEqual((p["counts"]["nsx_rules"], p["counts"]["nsx_rules_in_scope"]), (2, 1))

    def test_no_source_view_bundle_is_an_error(self):
        p = plan_for(rule("r1", ["web"], ["db"], ["HTTPS"]), bundles=BUNDLES[1:])
        self.assertIn("no_source_view", [f["code"] for f in p["findings"] if f["severity"] == "error"])
        self.assertEqual(self.members(p, "web_np_ips"), ["10.7.0.101-avs_ips", "10.8.0.101-lm3_ips"])


class ServiceTests(unittest.TestCase):
    """Mike, 2026-10-06: services mirror NSX exactly; ports wherever possible."""

    @staticmethod
    def svcs(p):
        return {x["name"]: x["protocol"] for x in p["services"]}, {g["name"]: g["members"] for g in p["service_groups"]}

    def test_services_mirror_nsx_structure(self):
        p = plan_for(rule("r1", ["web"], ["db"], ["HTTPS", "DNS", "bundle", "two-tcp"]))
        s, g = self.svcs(p)
        self.assertEqual(s["HTTPS"], {"tcp": {"port": "443"}})               # one entry: the service itself
        self.assertEqual((s["DNS-tcp"], s["DNS-udp"]), ({"tcp": {"port": "53"}}, {"udp": {"port": "53"}}))
        self.assertEqual(g["DNS"], ["DNS-tcp", "DNS-udp"])                  # several entries: a group
        self.assertEqual(g["bundle"], ["HTTPS", "bundle-tcp"])              # nested service kept as a member
        self.assertEqual(s["bundle-tcp"], {"tcp": {"port": "8443"}})
        self.assertEqual(g["two-tcp"], ["two-tcp-tcp-1", "two-tcp-tcp-2"])  # entries never merged
        self.assertEqual(by_name(p)["r1"]["service"]["member"], ["HTTPS", "DNS", "bundle", "two-tcp"])

    def test_alg_becomes_a_port_service_and_is_reviewed(self):
        p = plan_for(rule("r1", ["web"], ["db"], ["FTP"]))
        self.assertEqual(self.svcs(p)[0]["FTP"], {"tcp": {"port": "21"}})
        self.assertEqual([x["kind"] for x in p["app_id_review"]], ["alg_ports"])

    def test_icmp_gets_its_own_rule_and_is_reviewed(self):
        p = plan_for(rule("r1", ["web"], ["db"], ["HTTPS", "ICMP-ALL"]))
        e = by_name(p)
        self.assertEqual(e["r1"]["application"]["member"], ["any"])
        self.assertEqual(e["r1-icmp"]["application"]["member"], ["icmp", "ping", "ipv6-icmp"])
        self.assertEqual(e["r1-icmp"]["service"]["member"], ["application-default"])
        self.assertEqual([(x["kind"], x["nsx_rule"]) for x in p["app_id_review"]], [("icmp_app_id", "r1")])

    def test_icmp_only_rule_keeps_its_name(self):
        e = by_name(plan_for(rule("r1", ["web"], ["db"], ["echo"])))
        self.assertEqual(list(e), ["r1"])
        self.assertEqual(e["r1"]["application"]["member"], ["ping"])

    def test_no_port_form_left_out_reviewed_and_rule_skipped_if_nothing_remains(self):
        p = plan_for(rule("r1", ["web"], ["db"], ["gre"]), rule("r2", ["web"], ["db"], ["gre", "HTTPS"], seq=2))
        self.assertEqual([r["name"] for r in p["rules"]], ["r2"])
        self.assertIn("service_not_mirrored", [f["code"] for f in p["findings"]])
        self.assertEqual({x["kind"] for x in p["app_id_review"]}, {"no_port_form"})

    def test_nsx_context_profile_app_id_is_reviewed_and_skipped(self):
        ctx = [{"id": "SSL", "display_name": "SSL",
                "attributes": [{"key": "APP_ID", "value": ["SSL", "TLS1.2"]}]}]
        p = build_rule_mirror([policy("p1", rule("r1", ["web"], ["db"], ["HTTPS"],
                                                 profiles=["/infra/context-profiles/SSL"]))],
                              GROUPS, SERVICES, BUNDLES, [], context_profiles=ctx)
        self.assertEqual(p["rules"], [])
        rv = p["app_id_review"]
        self.assertEqual((rv[0]["kind"], rv[0]["nsx_rule"]), ("nsx_app_id", "r1"))
        self.assertIn("APP_ID SSL, TLS1.2", rv[0]["nsx"])
        self.assertEqual(p["counts"]["nsx_rules_with_app_id"], 1)

    def test_any_service(self):
        e = by_name(plan_for(rule("r1", ["web"], ["db"])))["r1"]
        self.assertEqual((e["application"]["member"], e["service"]["member"]), (["any"], ["any"]))


class RuleFieldTests(unittest.TestCase):
    def test_actions_disabled_and_negation(self):
        p = plan_for(rule("a", ["web"], ["db"], action="DROP", disabled=True, sources_excluded=True),
                     rule("b", ["web"], ["db"], action="REJECT", seq=2),
                     rule("c", ["web"], ["db"], action="JUMP_TO_APPLICATION", seq=3))
        e = by_name(p)
        self.assertEqual((e["a"]["action"], e["a"]["disabled"], e["a"]["negate-source"]), ("drop", "yes", "yes"))
        self.assertEqual(e["b"]["action"], "reset-both")
        self.assertNotIn("c", e)

    def test_context_profile_skips_the_rule(self):
        p = plan_for(rule("r1", ["web"], ["db"], profiles=["/infra/context-profiles/SSL"]))
        self.assertEqual(p["rules"], [])

    def test_long_names_fit_and_stay_unique(self):
        long = "x" * 72
        p = build_rule_mirror([policy("p1", rule(long, ["web"], ["db"])), policy("p2", rule(long, ["web"], ["db"]), seq=20)],
                              GROUPS, SERVICES, BUNDLES, [])
        names = [r["name"] for r in p["rules"]]
        self.assertEqual(len(set(names)), 2)
        self.assertTrue(all(len(n) <= 63 for n in names))

    def test_nsx_evaluation_order_and_ethernet_ignored(self):
        pols = [policy("app", rule("app-r", ["web"], ["db"]), seq=1),
                policy("infra", rule("infra-r", ["web"], ["db"]), category="Infrastructure", seq=50),
                policy("l2", rule("l2-r", ["web"], ["db"]), category="Ethernet", seq=1),
                {**policy("default-layer3-section", rule("default-layer3-rule", ["web"], ["db"]), seq=2147483647),
                 "is_default": True}]
        p = build_rule_mirror(pols, GROUPS, SERVICES, BUNDLES, [])
        self.assertEqual([r["name"] for r in p["rules"]], ["infra-r", "app-r"])
        self.assertEqual(p["counts"]["nsx_rules"], 2)

    def test_writes_objects_then_services_then_rules(self):
        p = plan_for(rule("r1", ["mgmt"], ["db"], ["DNS"]))
        kinds = [w["kind"] for w in p["writes"]]
        self.assertEqual(kinds, sorted(kinds, key=["address", "address-group", "service", "service-group",
                                                   "security-rule"].index))
        self.assertEqual(p["writes"][-1]["resource"], "Policies/SecurityPreRules")
        self.assertEqual({w["kind"]: w["location"] for w in p["writes"]},
                         {"address": "shared", "address-group": "shared", "service": "shared",
                          "service-group": "shared", "security-rule": "device-group"})

    def test_post_rulebase_only_rules_and_suffix(self):
        from multisite.pan_rules import RuleOptions
        pols = [policy("p1", rule("r1", ["web"], ["db"], ["HTTPS"]), rule("r2", ["web"], ["db"], seq=2))]
        p = build_rule_mirror(pols, GROUPS, SERVICES, BUNDLES, [], ropts=RuleOptions(
            rulebase="post", only_rules=["r2", "nope"], name_suffix="-post"))
        self.assertEqual([r["name"] for r in p["rules"]], ["r2-post"])
        rw = [w for w in p["writes"] if w["kind"] == "security-rule"]
        self.assertEqual([w["resource"] for w in rw], ["Policies/SecurityPostRules"])
        self.assertIn("rule_not_found", [f["code"] for f in p["findings"] if f["severity"] == "error"])

    def test_profiles_on_allow_rules_log_on_all(self):
        from multisite.pan_rules import RuleOptions, profile_refs
        pols = [policy("p1", rule("ok", ["web"], ["db"], ["HTTPS"]), rule("no", ["web"], ["db"], action="DROP", seq=2))]
        ro = RuleOptions(profile_group="pg1", log_setting="lf1")
        e = by_name(build_rule_mirror(pols, GROUPS, SERVICES, BUNDLES, [], ropts=ro))
        self.assertEqual(e["ok"]["profile-setting"], {"group": {"member": ["pg1"]}})
        self.assertNotIn("profile-setting", e["no"])
        self.assertEqual((e["ok"]["log-setting"], e["no"]["log-setting"]), ("lf1", "lf1"))
        ro2 = RuleOptions(profiles={"virus": "default", "vulnerability": "vp1"})
        p2 = build_rule_mirror(pols, GROUPS, SERVICES, BUNDLES, [], ropts=ro2)
        self.assertEqual(by_name(p2)["ok"]["profile-setting"],
                         {"profiles": {"virus": {"member": ["default"]}, "vulnerability": {"member": ["vp1"]}}})
        self.assertNotIn("log-setting", by_name(p2)["ok"])
        # Built-in "default" cannot be looked up, so only vp1 is checked before a push.
        self.assertEqual([n for _, _, n in profile_refs(p2["options"])], ["vp1"])
        self.assertEqual([n for _, _, n in profile_refs(build_rule_mirror(
            pols, GROUPS, SERVICES, BUNDLES, [], ropts=ro)["options"])], ["pg1", "lf1"])
        with self.assertRaises(ValueError):
            build_rule_mirror(pols, GROUPS, SERVICES, BUNDLES, [], ropts=RuleOptions(profile_group="x",
                                                                                     profiles={"virus": "y"}))
        with self.assertRaises(ValueError):
            build_rule_mirror(pols, GROUPS, SERVICES, BUNDLES, [], ropts=RuleOptions(profiles={"bogus": "y"}))

    def test_firewall_target_writes_vsys_and_local_rulebase(self):
        from multisite.pan_mirror import MirrorOptions
        from multisite.pan_rules import RuleOptions
        pols = [policy("p1", rule("r1", ["web"], ["db"], ["DNS"]))]
        p = build_rule_mirror(pols, GROUPS, SERVICES, BUNDLES, [],
                              MirrorOptions(object_location="vsys", vsys="vsys2"), RuleOptions(rulebase="local"))
        self.assertEqual({(w["kind"], w["location"], w["vsys"]) for w in p["writes"]},
                         {(k, "vsys", "vsys2") for k in ("address", "address-group", "service", "service-group",
                                                          "security-rule")})
        self.assertEqual([w["resource"] for w in p["writes"] if w["kind"] == "security-rule"],
                         ["Policies/SecurityRules"])
        with self.assertRaises(ValueError):    # a firewall rulebase needs firewall (vsys) objects
            build_rule_mirror(pols, GROUPS, SERVICES, BUNDLES, [], ropts=RuleOptions(rulebase="local"))

    def test_group_kinds(self):
        g = {x["id"]: group_kind(x) for x in GROUPS}
        self.assertEqual(g, {"web": "tag", "db": "tag", "mgmt": "ip_only", "seg": "segment", "nest": "nested",
                             "gone": "tag", "empty": "empty"})


class DiffersTests(unittest.TestCase):
    """push flags a same-named object whose content differs (never modifies it)."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("nsx_pan_mirror_r", ROOT / "tools/pan/nsx_pan_mirror.py")
        cls.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.tool)

    def test_differs(self):
        planned = {"@name": "g", "static": {"member": ["a", "b"]}, "description": "x"}
        self.assertEqual(self.tool.differs(planned, {"@name": "g", "@location": "device-group",
                                                     "static": {"member": ["b", "a"]}, "description": "y"}), [])
        self.assertEqual(self.tool.differs(planned, {"static": {"member": ["a"]}}), ["static"])

    def test_env_settings_precedence(self):
        import os
        s = self.tool._setting
        old = os.environ.get("X_TEST_SETTING")
        try:
            os.environ["X_TEST_SETTING"] = "from-env"
            self.assertEqual(s("from-cli", "X_TEST_SETTING", "d"), "from-cli")   # command line wins
            self.assertEqual(s(None, "X_TEST_SETTING", "d"), "from-env")         # then .env
            self.assertIsNone(s("none", "X_TEST_SETTING", "d"))                  # "none" switches off
            del os.environ["X_TEST_SETTING"]
            self.assertEqual(s(None, "X_TEST_SETTING", "d"), "d")                # then the default
        finally:
            if old is not None:
                os.environ["X_TEST_SETTING"] = old

    def test_missing_profiles_checked_before_push(self):
        class Pan:
            def named_exists(self, resource, name, scopes):
                return "shared" if name == "pg1" else None
        plan = {"device_group": "dg-5", "options": {"profile_group": "pg1", "log_setting": "gone"}}
        self.assertEqual(self.tool.missing_profiles(Pan(), plan), [("log forwarding profile", "gone")])

    def test_firewall_scopes_params_and_pushed_conflicts(self):
        fw = {"device_group": None, "options": {"object_location": "vsys", "vsys": "vsys1"},
              "writes": [{"kind": "address", "name": "a1", "resource": "Objects/Addresses"},
                         {"kind": "address", "name": "a2", "resource": "Objects/Addresses"}]}
        self.assertEqual([s["location"] for s in self.tool.lookup_scopes(fw)], ["vsys", "panorama-pushed"])
        self.assertEqual(self.tool.target_label(fw), "vsys vsys1")
        self.assertEqual(self.tool.RestSession._params({"location": "vsys", "vsys": "vsys1", "name": "a1"}),
                         {"location": "vsys", "vsys": "vsys1", "name": "a1"})

        class Pan:
            def named_exists(self, resource, name, scopes):
                return "panorama-pushed" if name == "a2" else None
        self.assertEqual(self.tool.pushed_conflicts(Pan(), fw), [{"kind": "address", "name": "a2"}])
        self.assertEqual(self.tool.pushed_conflicts(Pan(), {**fw, "options": {}}), [])   # Panorama target

    def test_push_and_revert_reports(self):
        rows = [{"kind": "address", "name": "a1", "status": "created", "entry": {"ip-netmask": "1.1.1.1/32"}},
                {"kind": "address-group", "name": "g1", "status": "exists_unchanged", "differs": ["static"],
                 "existing": {"static": {"member": ["x"]}}},
                {"kind": "security-rule", "name": "r1", "status": "failed", "error": "HTTP 403 Unauthorized",
                 "entry": {"action": "allow", "source": {"member": ["g1"]}, "destination": {"member": ["any"]},
                           "service": {"member": ["HTTPS"]}, "application": {"member": ["any"]}}}]
        doc = {"created_at": "t", "mode": "apply", "plan": "/x/plan.json", "device_group": "dg-5",
               "panorama": "https://pano", "planned": 5, "results": rows, "manifest": "/x/push_1_apply.json"}
        md = self.tool.render_push_md(doc)
        for s in ("APPLY", "3 of 5 planned", "stopped here, 2 later", "HTTP 403", "differs in", "allow: g1 to any",
                  "revert --manifest"):
            self.assertIn(s, md)
        self.assertIn("| total", md)
        rv = self.tool.render_revert_md({"created_at": "t", "mode": "dryrun", "source_manifest": "/x/p.json",
                                         "results": [{"kind": "address", "name": "a1", "status": "would_delete"}]})
        self.assertIn("DRY RUN", rv)
        self.assertIn("would_delete", rv)

    def test_push_marks_differs(self):
        class Pan:
            def exists(self, w):
                return {"@name": "g", "static": {"member": ["other"]}}
        w = {"kind": "address-group", "name": "g", "resource": "Objects/AddressGroups", "device_group": "dg-5",
             "entry": {"@name": "g", "static": {"member": ["a"]}}}
        row = self.tool.push_writes(Pan(), [w], apply=True)[0]
        self.assertEqual((row["status"], row["differs"]), ("exists_unchanged", ["static"]))


if __name__ == "__main__":
    unittest.main()
