#!/usr/bin/env python3
"""
tests/test_backup_nsx_state.py

Offline tests for tools/nsx/backup_nsx_state.py planning and housekeeping.
No NSX calls, no subprocesses.

    python -m unittest tests/test_backup_nsx_state.py -v
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "app") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "app"))

logging.disable(logging.CRITICAL)


def _load():
    spec = importlib.util.spec_from_file_location(
        "backup_nsx_state", REPO_ROOT / "tools" / "nsx" / "backup_nsx_state.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


backup = _load()


class PlanStepsTests(unittest.TestCase):
    def test_lm_plan_has_three_steps_no_federation(self):
        steps = backup.plan_steps("nsx-lm1", Path("/b"), python="py")
        self.assertEqual([s[0] for s in steps],
                         ["1_export_objects", "2_export_segments", "3_export_vm_tags"])
        for _, cmd in steps:
            self.assertNotIn("--federation-global", cmd)
        export_cmd = steps[0][1]
        self.assertIn("tools/nsx/export_nsx_objects.py", export_cmd)
        self.assertIn("/b/nsx_export", export_cmd)
        self.assertIn("tools/vm_tags/export_vm_tags.py", steps[2][1])

    def test_gm_plan_skips_vm_tags_and_sets_federation(self):
        steps = backup.plan_steps("nsx-gm1", Path("/b"), python="py")
        self.assertEqual([s[0] for s in steps], ["1_export_objects", "2_export_segments"])
        for _, cmd in steps:
            self.assertIn("--federation-global", cmd)

    def test_no_vm_tags_flag(self):
        steps = backup.plan_steps("nsx-lm1", Path("/b"), with_vm_tags=False, python="py")
        self.assertEqual([s[0] for s in steps], ["1_export_objects", "2_export_segments"])

    def test_all_domains_passthrough(self):
        steps = backup.plan_steps("nsx-lm1", Path("/b"), all_domains=True, python="py")
        self.assertIn("--all-domains", steps[0][1])
        self.assertNotIn("--all-domains", steps[1][1])

    def test_gm_detection(self):
        self.assertTrue(backup.is_global_manager("nsx-gm2"))
        self.assertFalse(backup.is_global_manager("nsx-lm5"))


class PruneTests(unittest.TestCase):
    def _host_dir(self, names):
        d = Path(tempfile.mkdtemp())
        for n in names:
            (d / n).mkdir()
        return d

    def test_retain_zero_keeps_everything(self):
        d = self._host_dir(["20260101_000000", "20260102_000000"])
        self.assertEqual(backup.prune_old_backups(d, 0), [])
        self.assertEqual(len(list(d.iterdir())), 2)

    def test_prunes_oldest_beyond_retain(self):
        names = [f"2026010{i}_000000" for i in range(1, 6)]
        d = self._host_dir(names)
        removed = backup.prune_old_backups(d, 2)
        self.assertEqual(removed, names[:3])
        self.assertEqual(sorted(x.name for x in d.iterdir()), names[3:])

    def test_non_timestamp_entries_untouched(self):
        d = self._host_dir(["20260101_000000", "20260102_000000", "20260103_000000"])
        (d / "notes.txt").write_text("keep me")
        (d / "latest").symlink_to("20260103_000000")
        removed = backup.prune_old_backups(d, 1)
        self.assertEqual(removed, ["20260101_000000", "20260102_000000"])
        self.assertTrue((d / "notes.txt").exists())
        self.assertTrue((d / "latest").is_symlink())

    def test_missing_dir_is_noop(self):
        self.assertEqual(backup.prune_old_backups(Path(tempfile.mkdtemp()) / "nope", 3), [])


class ManifestAndSymlinkTests(unittest.TestCase):
    def test_write_manifest_round_trip(self):
        b = Path(tempfile.mkdtemp())
        p = backup.write_manifest(b, {"ok": True, "workflow": "backup"})
        self.assertEqual(json.loads(p.read_text())["workflow"], "backup")

    def test_update_latest_symlink_replaces(self):
        host = Path(tempfile.mkdtemp())
        for n in ("20260101_000000", "20260102_000000"):
            (host / n).mkdir()
        backup.update_latest_symlink(host, host / "20260101_000000")
        backup.update_latest_symlink(host, host / "20260102_000000")
        self.assertEqual((host / "latest").readlink().name, "20260102_000000")


if __name__ == "__main__":
    unittest.main()
