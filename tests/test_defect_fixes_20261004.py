"""Three defects fixed 2026-10-04 (found by the duplicated-helper inventory):

1. nsx_constants.resolve_manager had no nsx-lm5 although 21 tools offer it
   as a --source/--target choice: picking it raised KeyError.
2. tools/pan/add_services_to_rules.py wrote LOCAL time into log lines whose
   format says "UTC" (it never imports nsx.cli_bootstrap, which is what sets
   the UTC clock everywhere else).
3. The VM-tag push and revert prompts AUTO-APPROVED the next batch of writes
   when input closed (EOF), the opposite of app/nsx/apply_batch.ApplyBatch,
   which stops. Ctrl-C at the prompt crashed out without the manifest.
"""
import importlib
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "tools/vm_tags"))


class ManagerChoiceTests(unittest.TestCase):
    def test_lm5_resolves_from_env(self):
        import nsx.nsx_constants as nc
        with patch.dict(os.environ, {"NSX_LM5": "nsx-lm5.example.test"}):
            nc = importlib.reload(nc)
            self.assertEqual(nc.resolve_manager("nsx-lm5"), "nsx-lm5.example.test")
        nc = importlib.reload(nc)
        # Unset stays None (or whatever .env gives), as for every other alias:
        # tools that check `if not manager_host` keep their clean exit.
        self.assertEqual(nc.resolve_manager("nsx-lm5"), os.getenv("NSX_LM5"))

    def test_every_alias_a_tool_offers_resolves(self):
        """Static guard: any nsx-lmN / nsx-gmN literal in a live tool must be
        a key resolve_manager knows, so no choice can raise KeyError."""
        from nsx.nsx_constants import resolve_manager
        aliases = set()
        for base in ("tools", "app"):
            for f in (ROOT / base).rglob("*.py"):
                if "archive" in f.parts or "__pycache__" in f.parts:
                    continue
                aliases |= set(re.findall(r'"(nsx-(?:lm|gm)\d+)"', f.read_text(encoding="utf-8")))
        self.assertIn("nsx-lm5", aliases)
        for a in sorted(aliases):
            try:
                resolve_manager(a)
            except KeyError:
                self.fail(f"{a} is offered by a tool but resolve_manager does not know it")


class PanLogClockTests(unittest.TestCase):
    def test_log_lines_labelled_utc_are_utc(self):
        """Run in a child with a non-UTC zone: the logged time must be UTC."""
        with tempfile.TemporaryDirectory() as tmp:
            code = (
                "import sys, logging, importlib.util; from pathlib import Path\n"
                f"sys.path.insert(0, {str(ROOT / 'app')!r})\n"
                "spec = importlib.util.spec_from_file_location('asr', "
                f"{str(ROOT / 'tools/pan/add_services_to_rules.py')!r})\n"
                "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
                f"m._setup_logging(Path({tmp!r}))\n"
                "logging.getLogger('probe').info('clock check')\n"
            )
            env = dict(os.environ, TZ="America/Chicago")
            r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            logs = list((Path(tmp) / "logs").glob("add_services_*.log"))
            self.assertEqual(len(logs), 1)
            line = next(l for l in logs[0].read_text().splitlines() if "clock check" in l)
            stamp = datetime.strptime(line.split(" UTC ")[0], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            self.assertLess(abs((datetime.now(timezone.utc) - stamp).total_seconds()), 300, line)


def _load(name):
    spec = importlib.util.spec_from_file_location(f"defect_{name}", ROOT / f"tools/vm_tags/{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class VmTagPromptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mods = {n: _load(n) for n in ("push_hostname_tags", "revert_hostname_tags")}

    def test_closed_input_stops_never_approves(self):
        for name, mod in self.mods.items():
            for exc in (EOFError, KeyboardInterrupt):
                with self.subTest(tool=name, input=exc.__name__):
                    with patch("builtins.input", side_effect=exc):
                        with self.assertRaises(mod._InteractiveExit):
                            mod._prompt_batch_continue(3, 5)

    def test_operator_answers_unchanged(self):
        for name, mod in self.mods.items():
            with self.subTest(tool=name):
                with patch("builtins.input", return_value=""):
                    self.assertEqual(mod._prompt_batch_continue(1, 4), 4)
                with patch("builtins.input", return_value="n"):
                    self.assertEqual(mod._prompt_batch_continue(1, 4), 1)
                with patch("builtins.input", return_value="7"):
                    self.assertEqual(mod._prompt_batch_continue(1, 4), 7)
                with patch("builtins.input", return_value="x"):
                    with self.assertRaises(mod._InteractiveExit):
                        mod._prompt_batch_continue(1, 4)


if __name__ == "__main__":
    unittest.main()
