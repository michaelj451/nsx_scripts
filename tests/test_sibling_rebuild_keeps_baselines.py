"""A C / D2a dry run rebuilds the sibling bundle. The rebuild must clear the
previous build's output but keep push_report/, where the apply that pushed the
bundle keeps its revert baseline. Losing it costs that apply its rollback (this
happened to WF-C on nsx-lm1_to_nsx-lm2 on 2026-09-25). An old pure-IP remap
bundle from the retired D2b phase is never touched: it may hold a baseline."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "app"))

_spec = importlib.util.spec_from_file_location(
    "build_sibling_groups", REPO_ROOT / "tools" / "nsx" / "build_sibling_groups.py")
bsg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bsg)

LABEL = "nsx-test.lab.local"

# Tag condition + captured IPs: produces a sibling. Pure IP: no sibling
# without a CSV map (WF-C decomposes tag groups only).
TAG_GROUP = {
    "id": "web", "display_name": "web", "resource_type": "Group",
    "expression": [
        {"resource_type": "Condition", "member_type": "VirtualMachine",
         "key": "Tag", "operator": "EQUALS", "value": "0|web"},
        {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
        {"resource_type": "IPAddressExpression", "ip_addresses": ["10.6.0.101"]},
    ],
}
PURE_IP_GROUP = {
    "id": "subnet", "display_name": "subnet", "resource_type": "Group",
    "expression": [{"resource_type": "IPAddressExpression",
                    "ip_addresses": ["10.2.1.0/24"]}],
}


class RebuildKeepsBaselinesTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.capture = self.tmp / "capture" / LABEL
        groups = self.capture / "groups_additive" / "domains" / "default" / "groups"
        groups.mkdir(parents=True)
        (groups / "web.yaml").write_text(yaml.safe_dump(TAG_GROUP), encoding="utf-8")
        (groups / "subnet.yaml").write_text(yaml.safe_dump(PURE_IP_GROUP), encoding="utf-8")
        self.out = self.tmp / "run"
        self.sib = self.out / "nsx_sibling_groups" / LABEL
        self.pure = self.out / "nsx_pure_ip_remap" / LABEL
        # Keep the build's global log out of the real nsx_logs/.
        patcher = mock.patch.object(bsg, "nsx_log_dir", str(self.tmp / "logs"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def _build(self):
        argv = ["build_sibling_groups.py", "--capture", str(self.capture),
                "--output-base", str(self.out), "--appendix", "_t"]
        with mock.patch.object(sys, "argv", argv):
            rc = bsg.main()
        self.assertEqual(rc, 0)

    def _plant(self, bundle: Path) -> Path:
        """What an apply leaves behind, plus stale output from an older build."""
        baseline = bundle / "push_report" / "baselines" / "20260924_180811_target_baseline.json"
        baseline.parent.mkdir(parents=True, exist_ok=True)
        baseline.write_text(json.dumps({"pre-existing": {"id": "pre-existing"}}), encoding="utf-8")
        (bundle / "push_report" / "baselines" / "20260924_180811_pushed_ids.json").write_text(
            json.dumps(["web_t"]), encoding="utf-8")
        (bundle / "groups").mkdir(parents=True, exist_ok=True)
        (bundle / "groups" / "stale_from_old_build.yaml").write_text("id: stale\n", encoding="utf-8")
        (bundle / "stale_top_level_file.json").write_text("{}", encoding="utf-8")
        return baseline

    def test_first_build_creates_the_sibling_bundle_only(self):
        self._build()
        self.assertTrue((self.sib / "sibling_map.json").exists())
        self.assertTrue(list((self.sib / "groups").glob("*.yaml")))
        self.assertFalse(self.pure.exists(), "the retired pure-IP bundle was emitted")

    def test_rebuild_keeps_sibling_push_report(self):
        baseline = self._plant(self.sib)
        self._build()
        self.assertTrue(baseline.exists(), "rebuild deleted the C3/D2a revert baseline")
        self.assertEqual(json.loads(baseline.read_text()), {"pre-existing": {"id": "pre-existing"}})
        self.assertTrue((baseline.parent / "20260924_180811_pushed_ids.json").exists())

    def test_rebuild_leaves_an_old_pure_ip_bundle_untouched(self):
        baseline = self._plant(self.pure)
        stale = self.pure / "groups" / "stale_from_old_build.yaml"
        self._build()
        self.assertTrue(baseline.exists(), "rebuild deleted an old D2b revert baseline")
        self.assertTrue(stale.exists(), "rebuild touched the retired pure-IP bundle")

    def test_rebuild_still_clears_stale_build_output(self):
        self._plant(self.sib)
        self._build()
        self.assertFalse((self.sib / "groups" / "stale_from_old_build.yaml").exists())
        self.assertFalse((self.sib / "stale_top_level_file.json").exists())
        # And the fresh build is really there.
        self.assertTrue((self.sib / "sibling_map.json").exists())

    def test_clear_helper_keeps_only_preserved_entries(self):
        b = self.tmp / "bundle"
        (b / "push_report" / "baselines").mkdir(parents=True)
        (b / "groups").mkdir()
        (b / "reports").mkdir()
        (b / "manifest.json").write_text("{}", encoding="utf-8")
        bsg._clear_build_output(b)
        self.assertEqual(sorted(p.name for p in b.iterdir()), ["push_report"])
        self.assertTrue((b / "push_report" / "baselines").is_dir())

    def test_clear_helper_on_missing_dir_is_a_no_op(self):
        bsg._clear_build_output(self.tmp / "does-not-exist")


if __name__ == "__main__":
    unittest.main()
