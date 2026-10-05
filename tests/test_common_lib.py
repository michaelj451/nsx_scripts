"""app/common: the vendor-neutral library.

Covers the contract in app/common/__init__.py (no vendor imports, no import
side effects) and the behavior each helper promises.
"""
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from common import bundles, fileio, ipspan, logs, md, paths, timeutil  # noqa: E402


class ContractTests(unittest.TestCase):
    def test_no_vendor_imports_in_common(self):
        pat = re.compile(r"^\s*(from|import)\s+(nsx|palo|utilities)\b", re.M)
        for f in (ROOT / "app" / "common").glob("*.py"):
            self.assertIsNone(pat.search(f.read_text(encoding="utf-8")), f"{f.name} imports a vendor package")

    def test_import_has_no_side_effects(self):
        """Importing every module loads no vendor package, reads no .env into
        the environment and creates nothing in the working directory."""
        with tempfile.TemporaryDirectory() as tmp:
            code = ("import sys, os; sys.path.insert(0, %r)\n"
                    "before = dict(os.environ)\n"
                    "import common.timeutil, common.paths, common.fileio, common.logs, "
                    "common.bundles, common.ipspan, common.subnet_map, common.md\n"
                    "bad = [m for m in sys.modules if m.split('.')[0] in ('nsx', 'palo', 'utilities', 'dotenv')]\n"
                    "assert not bad, bad\n"
                    "assert dict(os.environ) == before\n"
                    "import logging; assert logging.Formatter.converter is __import__('time').localtime\n"
                    % str(ROOT / "app"))
            r = subprocess.run([sys.executable, "-c", code], cwd=tmp, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(os.listdir(tmp), [])


class TimeTests(unittest.TestCase):
    def test_formats(self):
        ts = timeutil.run_ts()
        self.assertRegex(ts, r"^\d{8}_\d{6}$")
        self.assertEqual(timeutil.run_ts(timeutil.parse_run_ts(ts)), ts)
        self.assertTrue(timeutil.utc_now_iso().endswith("+00:00"))


class PathTests(unittest.TestCase):
    def test_env_dir_relative_default_is_repo_root(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("X_TEST_DIR", None)
            self.assertEqual(paths.env_dir("X_TEST_DIR", "nsx_logs"), (ROOT / "nsx_logs").resolve())
            os.environ["X_TEST_DIR"] = "$HOME/zz"
            self.assertEqual(paths.env_dir("X_TEST_DIR", "nsx_logs"),
                             Path(os.path.expandvars("$HOME/zz")).resolve())

    def test_names_match_existing_helpers(self):
        """Same algorithm as app/utilities/file_utilities, so files land at
        the same names whichever helper wrote them."""
        from utilities import file_utilities as fu
        for s in ("web-tier", "App 0 / s - 2", "x" * 80, "", "a/b\\c:d"):
            self.assertEqual(paths.slugify(s), fu.slugify(s))
            self.assertEqual(paths.short_id_filename(s), fu.short_id_filename(s))

    def test_safe_name(self):
        self.assertEqual(paths.safe_name("https://nsx-lm1.lab.local/"), "nsx-lm1.lab.local")


class FileIoTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def test_json_yaml_jsonl_round_trip(self):
        data = {"b": 1, "a": [1, 2]}
        p = fileio.write_json(self.d / "x" / "a.json", data)
        self.assertEqual(fileio.read_json(p), data)
        self.assertTrue(p.read_text().endswith("\n"))
        self.assertEqual(fileio.read_doc(fileio.write_yaml(self.d / "a.yaml", data)), data)
        fileio.write_jsonl(self.d / "r.jsonl", [{"i": 1}, {"i": 2}])
        fileio.append_jsonl(self.d / "r.jsonl", {"i": 3})
        self.assertEqual([r["i"] for r in fileio.read_jsonl(self.d / "r.jsonl")], [1, 2, 3])
        with self.assertRaises(ValueError):
            fileio.read_doc(self.d / "a.txt")

    def test_atomic_write_keeps_old_file_on_failure(self):
        p = fileio.write_text(self.d / "f.txt", "old")
        with patch("common.fileio.os.replace", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                fileio.write_text(p, "new")
        self.assertEqual(p.read_text(), "old")
        self.assertEqual(sorted(x.name for x in self.d.iterdir()), ["f.txt"])

    def test_csv_bom_and_duplicate_headers(self):
        p = self.d / "m.csv"
        p.write_text("﻿old_subnet, new_subnet\n10.0.0.0/24 , 10.1.0.0/24\n\n", encoding="utf-8")
        header, rows = fileio.read_csv_rows(p)
        self.assertEqual(header, ["old_subnet", "new_subnet"])
        self.assertEqual(rows, [["10.0.0.0/24", "10.1.0.0/24"]])
        p.write_text("a,a\n1,2\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            fileio.read_csv_dicts(p)

    def test_sha256_tree_excludes_dirs(self):
        fileio.write_text(self.d / "g" / "a.yaml", "x")
        fileio.write_text(self.d / "push_report" / "b.json", "y")
        t = fileio.sha256_tree(self.d, exclude_dirs=("push_report",))
        self.assertEqual(list(t["files"]), ["g/a.yaml"])
        self.assertEqual(len(t["manifest_sha256"]), 64)


class BundleTests(unittest.TestCase):
    def test_run_dirs_latest_and_prune(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Path(tmp) / "h"
            made = [bundles.new_run_dir(host, f"2026100{i}_000000") for i in range(1, 5)]
            with self.assertRaises(FileExistsError):
                bundles.new_run_dir(host, "20261001_000000")
            self.assertTrue(bundles.update_latest(host, made[1]))
            self.assertEqual(bundles.find_bundle(host), made[1].resolve())
            self.assertEqual(bundles.find_bundle(made[2]), made[2])
            self.assertEqual(bundles.prune_old(host, 2), ["20261001_000000", "20261002_000000"])
            (host / "latest").unlink()
            self.assertEqual(bundles.find_bundle(host), made[3])

    def test_same_second_runs_get_separate_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = bundles.new_run_dir(Path(tmp))
            b = bundles.new_run_dir(Path(tmp))
            self.assertNotEqual(a, b)


class SpanTests(unittest.TestCase):
    def test_parse_and_format(self):
        self.assertEqual(ipspan.fmt(ipspan.span_of("10.6.0.0/24")), "10.6.0.0/24")
        self.assertEqual(ipspan.fmt(ipspan.span_of("10.6.0.5")), "10.6.0.5")
        self.assertEqual(ipspan.fmt(ipspan.span_of("10.6.0.5-10.6.0.9")), "10.6.0.5-10.6.0.9")
        self.assertEqual(ipspan.to_cidrs(ipspan.span_of("10.6.0.4-10.6.0.7")), ["10.6.0.4/30"])
        with self.assertRaises(ValueError):
            ipspan.span_of("10.6.0.9-10.6.0.5")
        with self.assertRaises(ValueError):
            ipspan.span_of("10.10.3.0/23", strict=True)
        self.assertIsNone(ipspan.try_span("nope"))

    def test_subtract_merge(self):
        whole = ipspan.span_of("10.0.0.0/24")
        left = ipspan.subtract(whole, [ipspan.span_of("10.0.0.10"), ipspan.span_of("10.0.0.0/28")])
        self.assertEqual([ipspan.fmt(s) for s in left], ["10.0.0.16-10.0.0.255"])
        merged = ipspan.merge([ipspan.span_of("10.0.0.0/25"), ipspan.span_of("10.0.0.128/25")])
        self.assertEqual([ipspan.fmt(s) for s in merged], ["10.0.0.0/24"])
        self.assertFalse(ipspan.overlaps(ipspan.span_of("10.0.0.1"), ipspan.span_of("::1")))


class LogTests(unittest.TestCase):
    def test_setup_twice_does_not_stack_handlers(self):
        root = logging.getLogger()
        before = list(root.handlers)
        # Other test modules call logging.disable(CRITICAL) at import.
        was_disabled = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, was_disabled)
        with tempfile.TemporaryDirectory() as tmp:
            try:
                p1 = logs.setup_logging("t", tmp, run_ts="20261004_000000", console=False)
                logs.setup_logging("t", tmp, run_ts="20261004_000001", console=False)
                ours = [h for h in root.handlers if h not in before]
                self.assertEqual(len(ours), 1)
                logging.getLogger("x").info("hello")
                self.assertTrue(p1.exists())
                self.assertIn("UTC [INFO] x: hello",
                              (Path(tmp) / "t_20261004_000001.log").read_text())
            finally:
                for h in [h for h in root.handlers if h not in before]:
                    root.removeHandler(h)
                    h.close()


class MdTests(unittest.TestCase):
    def test_table_escapes_cells(self):
        out = md.align_markdown_tables("\n".join(md.md_table(["a", "n"], [["x|y\nz", 1]], ["l", "r"])))
        self.assertIn("x\\|y z", out)
        self.assertEqual(len(out.splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
