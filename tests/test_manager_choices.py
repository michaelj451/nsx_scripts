"""Manager aliases stay consistent across every live tool (nsx-lm6 added
2026-10-04; nsx-lm5 had been offered by 21 tools without being resolvable).

There is no single list of managers that tools import: each tool spells its
own --source/--target choices. These checks keep those copies in line:

  * every list/set/tuple literal of nsx-lmN names covers nsx-lm1..nsx-lm6;
  * every alias -> host map has an entry for each of those aliases;
  * every alias any live tool mentions is one resolve_manager knows;
  * every nsx_lmN host variable a file uses is imported in that file.

Adding nsx-lm7 later: extend LMS below, nsx_constants, .env.example, and
let this test list every place still missing it.
"""
import ast
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

LMS = {f"nsx-lm{i}" for i in range(1, 7)}


def live_files():
    for base in ("tools", "app"):
        for f in sorted((ROOT / base).rglob("*.py")):
            if "archive" not in f.parts and "__pycache__" not in f.parts:
                yield f


def string_elts(node):
    return {e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}


class ManagerChoiceConsistencyTests(unittest.TestCase):
    def test_choice_lists_cover_lm1_to_lm6(self):
        gaps = []
        for f in live_files():
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
                    names = {s for s in string_elts(node) if s.startswith("nsx-lm")}
                elif isinstance(node, ast.Dict):
                    names = {k.value for k in node.keys
                             if isinstance(k, ast.Constant) and str(k.value).startswith("nsx-lm")}
                else:
                    continue
                if names and not LMS <= names:
                    gaps.append(f"{f.relative_to(ROOT)}:{node.lineno} missing {sorted(LMS - names)}")
        self.assertEqual(gaps, [], "\n".join(gaps))

    def test_host_variables_used_are_imported(self):
        """Caught on 2026-10-04: a map gained nsx_lm5/nsx_lm6 entries in a
        file whose one-line import stopped at nsx_lm4 (NameError at runtime)."""
        problems = []
        for f in live_files():
            tree = ast.parse(f.read_text(encoding="utf-8"))
            bound = set()
            for n in ast.walk(tree):
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    bound |= {(a.asname or a.name).split(".")[0] for a in n.names}
                elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    bound.add(n.id)
                elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    bound.add(n.name)
                elif isinstance(n, ast.arg):
                    bound.add(n.arg)
            used = {n.id for n in ast.walk(tree)
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                    and n.id.startswith(("nsx_lm", "nsx_gm"))}
            if used - bound:
                problems.append(f"{f.relative_to(ROOT)}: {sorted(used - bound)}")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_resolver_knows_lm6(self):
        import importlib
        import nsx.nsx_constants as nc
        with patch.dict(os.environ, {"NSX_LM6": "nsx-lm6.example.test"}):
            nc = importlib.reload(nc)
            self.assertEqual(nc.resolve_manager("nsx-lm6"), "nsx-lm6.example.test")
        nc = importlib.reload(nc)
        for alias in sorted(LMS | {"nsx-gm1", "nsx-gm2"}):
            nc.resolve_manager(alias)          # KeyError would fail the test

    def test_env_example_lists_every_lm(self):
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        for i in range(1, 7):
            self.assertIn(f"NSX_LM{i}=", text)


if __name__ == "__main__":
    unittest.main()
