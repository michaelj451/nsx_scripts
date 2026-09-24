"""Reports name objects by display name, never by bare id. The id appears only
when a display name is shared, because NSX display names are not unique."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "app"))

from nsx.names import NameMap, ambiguous, display, names_for, ref_key  # noqa: E402

G = "/infra/domains/default/groups/"


class NameMapTests(unittest.TestCase):

    def test_path_resolves_to_display_name(self):
        m = NameMap()
        m.add(G + "vm1", "vm1", "vm-group-1")
        self.assertEqual(m.label(G + "vm1"), "vm-group-1")

    def test_uuid_id_resolves_to_display_name(self):
        m = NameMap()
        m.add(G + "a8b5ed22", "a8b5ed22", "ip-address-group-10.10.2.0-24")
        self.assertEqual(m.label(G + "a8b5ed22"), "ip-address-group-10.10.2.0-24")

    def test_shared_display_name_carries_the_id(self):
        m = NameMap()
        m.add(G + "a", "a", "web")
        m.add(G + "b", "b", "web")
        self.assertEqual(m.label(G + "a"), "web (a)")
        self.assertEqual(m.label(G + "b"), "web (b)")

    def test_unknown_reference_falls_back_to_id(self):
        self.assertEqual(NameMap().label(G + "never-seen"), "never-seen")

    def test_global_infra_path_resolves(self):
        m = NameMap()
        m.add_mapping({"/global-infra/domains/default/groups/hw": "hardware-subnet"})
        self.assertEqual(m.label("/global-infra/domains/default/groups/hw"), "hardware-subnet")

    def test_bundle_yaml_and_sibling_map_are_read(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "groups").mkdir()
            (root / "groups" / "g.yaml").write_text(
                "id: network-6-0\ndisplay_name: network-group-0\nresource_type: Group\n"
                f"path: {G}network-6-0\n")
            (root / "sibling_map.json").write_text(json.dumps({"map": [{
                "original_id": "vm1", "original_display_name": "vm-group-1",
                "sibling_id": "vm1_np_ips", "sibling_display_name": "vm-group-1_np_ips"}]}))
            m = NameMap()
            m.add_bundle(root)
            self.assertEqual(m.label(G + "network-6-0"), "network-group-0")
            self.assertEqual(m.label(G + "vm1_np_ips"), "vm-group-1_np_ips")
            self.assertEqual(m.label(G + "vm1"), "vm-group-1")


class HelperTests(unittest.TestCase):

    def test_display_adds_id_only_for_ambiguous_names(self):
        amb = ambiguous([("a", "web"), ("b", "web"), ("vm1", "vm-group-1")])
        self.assertEqual(display("web", "a", amb), "web (a)")
        self.assertEqual(display("vm-group-1", "vm1", amb), "vm-group-1")
        self.assertEqual(display(None, "vm1", amb), "vm1")

    def test_ref_key(self):
        self.assertEqual(ref_key(G + "vm1"), ("groups", "vm1"))
        self.assertEqual(ref_key("/infra/services/HTTP"), ("services", "HTTP"))
        self.assertEqual(ref_key("vm1"), ("", "vm1"))

    def test_names_for_keeps_only_known_paths(self):
        self.assertEqual(names_for([G + "a", G + "b"], {G + "a": "alpha"}), {G + "a": "alpha"})


class RunReportRenderingTests(unittest.TestCase):
    """The run report's reference rendering goes through the shared name map."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "report_avs_run", REPO_ROOT / "tools" / "nsx" / "report_avs_run.py")
        cls.rar = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.rar)

    def setUp(self):
        self.rar.NAMES = NameMap()
        self.rar.NAMES.add(G + "a8b5ed22", "a8b5ed22", "ip-address-group-10.10.2.0-24")

    def test_gained_refs_render_display_names(self):
        lines = self.rar.audit_lines({"verdict": "changed", "per_field_diff": {"source_groups": {
            "before": [], "after": [G + "a8b5ed22"], "added": [G + "a8b5ed22"], "removed": []}}})
        joined = "\n".join(lines)
        self.assertIn("ip-address-group-10.10.2.0-24", joined)
        self.assertNotIn("a8b5ed22", joined)

    def test_kept_refs_keep_their_field_and_use_the_name(self):
        lines = self.rar.audit_lines({"verdict": "changed", "refs_preserved": [f"destination_groups:{G}a8b5ed22"]})
        joined = "\n".join(lines)
        self.assertIn("destination_groups: ip-address-group-10.10.2.0-24", joined)
        self.assertNotIn("a8b5ed22", joined)


if __name__ == "__main__":
    unittest.main()
