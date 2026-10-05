"""app/common/subnet_map.py: one CSV, one column per target site.

The defining rule: each site column behaves exactly like the two-column file
you get by cutting it out. The parity tests below prove that against the
existing loader (tools/nsx/nsx_group_ip_remap_offline.py), which is what
build_sibling_groups and groups.py push actually use.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "tools/nsx"))

from common.subnet_map import check_site_map, load_site_map, reserved_spans  # noqa: E402
from common import ipspan  # noqa: E402


def write(tmp, text):
    p = Path(tmp) / "m.csv"
    p.write_text(text, encoding="utf-8")
    return p


GOOD = ("old_subnet,nsx-lm2,nsx-lm3\n"
        "10.6.0.0/16,10.7.0.0/16,10.8.0.0/16\n"
        "10.6.1.0/24,10.7.1.0/24,\n"
        "10.6.0.101,10.7.0.101,10.9.0.201\n"
        "10.10.1.0/24,10.20.1.0/24,10.30.1.0/24\n")


class LoadTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._t.cleanup()

    def load(self, text):
        return load_site_map(write(self._t.name, text))

    def test_sites_and_blank_cells(self):
        sm = self.load(GOOD)
        self.assertTrue(sm.ok, sm.errors)
        self.assertEqual(sm.sites, ["nsx-lm2", "nsx-lm3"])
        self.assertEqual(len(sm.pairs("nsx-lm2")), 4)
        self.assertEqual(len(sm.pairs("nsx-lm3")), 3)     # blank cell = no row for lm3

    def test_blank_cell_falls_through_to_broader_row(self):
        sm = self.load(GOOD)
        self.assertEqual(sm.map_value("nsx-lm2", "10.6.1.5"), "10.7.1.5")
        self.assertEqual(sm.map_value("nsx-lm3", "10.6.1.5"), "10.8.1.5")   # via the /16
        self.assertEqual(sm.map_value("nsx-lm3", "10.6.0.101"), "10.9.0.201")  # /32 wins
        self.assertEqual(sm.map_value("nsx-lm3", "10.6.1.0/24"), "10.8.1.0/24")
        self.assertIsNone(sm.map_value("nsx-lm2", "10.99.0.1"))
        self.assertIsNone(sm.map_value("nsx-lm2", "10.6.0.0/15"))   # wider than any row

    def test_legacy_two_column_file(self):
        sm = self.load("old_subnet,new_subnet\n10.6.0.0/24,10.7.0.0/24,\n10.250.0.0/16, 10.251.0.0/16\n")
        self.assertTrue(sm.ok, sm.errors)
        self.assertEqual(sm.sites, ["new_subnet"])
        self.assertEqual(sm.pairs("new_subnet")[1], ("10.250.0.0/16", "10.251.0.0/16"))

    def test_cell_errors_are_collected_not_skipped(self):
        sm = self.load("old_subnet,a,b\n"
                       "10.1.0.0/24,10.2.0.1-10.2.0.9,\n"     # range
                       "10.3.0.0/24,2001:db8::/64,\n"         # ipv6
                       "10.4.0.0/24,10.5.1.0/23,\n"           # off boundary
                       "10.6.0.0/24,10.6.0.0/24,\n"           # same
                       "10.7.0.0/24,10.8.0.0/25,\n"           # smaller
                       "10.9.0.0/24,10.10.0.0/24,\n"
                       "10.9.0.0/24,10.11.0.0/24,\n"          # duplicate old
                       ",10.12.0.0/24,\n"                     # no old
                       "10.13.0.0/24,,,10.14.0.0/24\n")       # value with no header
        self.assertFalse(sm.ok)
        reasons = " | ".join(e["reason"] for e in sm.errors)
        for needle in ("range", "IPv6", "boundary", "itself", "smaller", "duplicate old_subnet",
                       "no old_subnet", "no header"):
            self.assertIn(needle, reasons)

    def test_header_errors(self):
        self.assertFalse(self.load("subnet,a\n10.0.0.0/24,10.1.0.0/24\n").ok)
        self.assertFalse(self.load("old_subnet,a,a\n10.0.0.0/24,10.1.0.0/24,10.2.0.0/24\n").ok)
        self.assertFalse(self.load("old_subnet\n10.0.0.0/24\n").ok)
        self.assertFalse(self.load("").ok)


class CheckTests(unittest.TestCase):
    def check(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            sm = load_site_map(write(tmp, text))
            self.assertTrue(sm.ok, sm.errors)
            return sm, check_site_map(sm)

    def test_clean_map(self):
        _, f = self.check(GOOD)
        self.assertEqual(f, [])

    def test_child_row_disagreeing_with_parent_collides(self):
        """The shape found in data/nonprod_map.csv on 2026-10-04: a /24 row
        that maps somewhere its /16 parent also sends addresses."""
        _, f = self.check("old_subnet,s\n10.8.0.0/16,10.9.0.0/16\n10.8.0.0/24,10.9.1.0/24\n")
        self.assertEqual([x["code"] for x in f], ["collision_within_site"])
        self.assertEqual(f[0]["destination"], "10.9.1.0/24")

    def test_host_override_into_parent_image_collides(self):
        """10.6.0.101 -> 10.8.0.201 while the /16 already sends 10.6.0.201
        there: two source hosts, one destination."""
        _, f = self.check("old_subnet,s\n10.6.0.0/16,10.8.0.0/16\n10.6.0.101,10.8.0.201\n")
        self.assertEqual([(x["code"], x["destination"]) for x in f],
                         [("collision_within_site", "10.8.0.201")])

    def test_consistent_child_row_is_fine(self):
        _, f = self.check("old_subnet,s\n10.8.0.0/16,10.9.0.0/16\n10.8.5.0/24,10.9.5.0/24\n")
        self.assertEqual(f, [])

    def test_two_sites_sharing_destinations(self):
        _, f = self.check("old_subnet,a,b\n10.1.0.0/24,10.50.0.0/24,\n10.2.0.0/25,,10.50.0.0/25\n")
        self.assertEqual([x["code"] for x in f], ["collision_between_sites"])

    def test_mapping_into_source_space_warns(self):
        _, f = self.check("old_subnet,a\n10.1.0.0/24,10.2.0.0/24\n10.2.0.0/24,10.3.0.0/24\n")
        self.assertEqual([(x["code"], x["severity"]) for x in f], [("lands_in_source_space", "warning")])

    def test_reserved_spans(self):
        sm, _ = self.check(GOOD)
        self.assertEqual([ipspan.fmt(s) for s in reserved_spans(sm, "nsx-lm3")],
                         ["10.8.0.0-10.8.0.100", "10.8.0.102-10.8.255.255", "10.9.0.201",
                          "10.30.1.0/24"])

    def test_repo_maps(self):
        """The new multi-site map is clean; nonprod_map.csv carries the known
        10.8 collision (reported to Mike 2026-10-04, file left unchanged)."""
        sm = load_site_map(ROOT / "data" / "multisite_map.csv")
        self.assertTrue(sm.ok, sm.errors)
        self.assertEqual(sm.sites, ["nsx-lm2", "nsx-lm3"])
        self.assertEqual(check_site_map(sm), [])


class ParityWithExistingLoaderTests(unittest.TestCase):
    TOKENS = ["10.6.0.1", "10.6.0.101", "10.6.1.77", "10.6.1.0/24", "10.6.0.0/16", "10.6.200.0/24",
              "10.10.1.9", "10.10.1.0/24", "10.10.2.1", "10.99.0.1", "10.6.1.0/25"]

    def test_each_column_equals_its_cut_out(self):
        from nsx_group_ip_remap_offline import _load_mapping_csv
        for text, tokens in ((GOOD, self.TOKENS),
                             ((ROOT / "data" / "multisite_map.csv").read_text(encoding="utf-8"),
                              self.TOKENS + ["10.4.2.5", "10.5.0.0/16", "10.21.3.0/24", "10.250.7.7"])):
            with tempfile.TemporaryDirectory() as tmp:
                sm = load_site_map(write(tmp, text))
                for site in sm.sites:
                    cut = Path(tmp) / f"{site}.csv"
                    sm.write_two_column(site, cut)
                    table, invalid = _load_mapping_csv(cut, bidirectional=False)
                    self.assertEqual(invalid, [], f"{site}: existing loader rejected the cut-out")
                    for tok in tokens:
                        theirs, _ = table.map_token(tok)
                        ours = sm.map_value(site, tok)
                        self.assertEqual([ours] if ours else [], theirs, f"{site} {tok}")


if __name__ == "__main__":
    unittest.main()
