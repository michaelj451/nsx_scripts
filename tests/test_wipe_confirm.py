"""The wipe's confirmation gate: hostname, then WIPE, both exact. Anything
else, including closed stdin, must refuse before the first DELETE."""
import builtins
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "app"))

_spec = importlib.util.spec_from_file_location(
    "wipe_target_manager", REPO_ROOT / "tools" / "test" / "wipe_target_manager.py")
wipe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wipe)

HOST = "nsx-gm1.lab.local"
SNAP = {"rules_to_delete": [1, 2], "customer_policies": [1],
        "customer_groups": [1, 2, 3], "customer_services": [1]}


def answers(*replies):
    it = iter(replies)
    def fake_input(_prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError
    return mock.patch.object(builtins, "input", fake_input)


class ConfirmWipeTests(unittest.TestCase):

    def test_correct_hostname_and_wipe_proceeds(self):
        with answers(HOST, "WIPE"):
            self.assertTrue(wipe._confirm_wipe("nsx-gm1", HOST, SNAP))

    def test_alias_instead_of_hostname_refuses(self):
        # The alias is what you already passed as --target; typing it back is
        # an echo, not a deliberate check. The full hostname is required.
        with answers("nsx-gm1", "WIPE"):
            self.assertFalse(wipe._confirm_wipe("nsx-gm1", HOST, SNAP))

    def test_wrong_hostname_refuses_without_asking_for_wipe(self):
        with answers("nsx-lm1.lab.local"):
            self.assertFalse(wipe._confirm_wipe("nsx-gm1", HOST, SNAP))

    def test_lowercase_wipe_refuses(self):
        with answers(HOST, "wipe"):
            self.assertFalse(wipe._confirm_wipe("nsx-gm1", HOST, SNAP))

    def test_yes_is_not_wipe(self):
        with answers(HOST, "yes"):
            self.assertFalse(wipe._confirm_wipe("nsx-gm1", HOST, SNAP))

    def test_closed_stdin_refuses(self):
        with answers():
            self.assertFalse(wipe._confirm_wipe("nsx-gm1", HOST, SNAP))

    def test_stdin_closing_after_hostname_refuses(self):
        with answers(HOST):
            self.assertFalse(wipe._confirm_wipe("nsx-gm1", HOST, SNAP))

    def test_surrounding_whitespace_is_tolerated(self):
        with answers(f"  {HOST}  ", " WIPE "):
            self.assertTrue(wipe._confirm_wipe("nsx-gm1", HOST, SNAP))


if __name__ == "__main__":
    unittest.main()
