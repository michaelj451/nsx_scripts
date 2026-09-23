"""Skip-unchanged is the default for every push, so its comparison has to be
exactly right in both directions: never skip a write that would change
something, never push one that would not."""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "app"))

from nsx.push_skip import is_unchanged, content_key, VOLATILE_KEYS  # noqa: E402


class SkipUnchangedTests(unittest.TestCase):

    def test_missing_target_is_a_create_never_a_skip(self):
        self.assertFalse(is_unchanged({"id": "g"}, None))
        self.assertFalse(is_unchanged({"id": "g"}, {}))

    def test_nsx_managed_metadata_is_ignored(self):
        payload = {"id": "g", "display_name": "G"}
        live = dict(payload, _revision=7, _create_time=1, _last_modified_time=2,
                    realization_id="abc", _protection="NOT_PROTECTED")
        self.assertTrue(is_unchanged(payload, live))

    def test_per_manager_rule_id_is_ignored(self):
        # NSX assigns rule_id per manager: the same cloned rule gets a
        # different number on each, and it says nothing about behaviour.
        self.assertTrue(is_unchanged({"id": "r", "rule_id": 11253},
                                     {"id": "r", "rule_id": 6132}))

    def test_toolkit_parent_policy_id_is_ignored(self):
        # Injected into rule files by the capture; never part of the NSX object.
        self.assertTrue(is_unchanged({"id": "r", "_parent_policy_id": "p1"},
                                     {"id": "r"}))

    def test_reference_lists_are_sets_not_sequences(self):
        # NSX returns scope / source_groups in arbitrary order.
        self.assertTrue(is_unchanged({"id": "r", "scope": ["a", "b"]},
                                     {"id": "r", "scope": ["b", "a"]}))

    def test_expression_order_is_meaning_and_is_preserved(self):
        # A group's expression interleaves Conditions with ConjunctionOperators;
        # reordering it changes membership, so it must NOT compare equal.
        a = {"id": "g", "expression": [{"value": "x"}, {"op": "OR"}, {"value": "y"}]}
        b = {"id": "g", "expression": [{"value": "y"}, {"op": "OR"}, {"value": "x"}]}
        self.assertFalse(is_unchanged(a, b))

    def test_real_changes_are_never_skipped(self):
        base = {"id": "r", "action": "ALLOW", "scope": ["a"]}
        for changed in (
            {"id": "r", "action": "DROP", "scope": ["a"]},          # action
            {"id": "r", "action": "ALLOW", "scope": ["a", "b"]},    # added ref
            {"id": "r", "action": "ALLOW", "scope": []},            # removed ref
            {"id": "r", "action": "ALLOW"},                          # dropped field
        ):
            self.assertFalse(is_unchanged(base, changed), changed)

    def test_added_ip_is_a_change(self):
        a = {"id": "g", "expression": [{"resource_type": "IPAddressExpression",
                                        "ip_addresses": ["10.0.0.1"]}]}
        b = {"id": "g", "expression": [{"resource_type": "IPAddressExpression",
                                        "ip_addresses": ["10.0.0.1", "10.0.0.2"]}]}
        self.assertFalse(is_unchanged(a, b))

    def test_content_key_is_stable_across_key_order(self):
        self.assertEqual(content_key({"a": 1, "b": 2}), content_key({"b": 2, "a": 1}))

    def test_volatile_set_covers_the_server_assigned_fields(self):
        for k in ("_revision", "_create_time", "realization_id", "rule_id",
                  "_parent_policy_id", "_self", "children"):
            self.assertIn(k, VOLATILE_KEYS)


if __name__ == "__main__":
    unittest.main()
