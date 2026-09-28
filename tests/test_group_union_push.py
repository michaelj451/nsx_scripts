"""groups.py push sends the UNION of the source payload and the IPs the target
already holds. An IP the source stops reporting (a powered-off VM, a
re-captured group) used to block the whole group, so its new IPs never landed.
Now it is kept, recorded as ips_kept_from_target, and nothing is removed."""
import contextlib
import copy
import importlib.util
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "tools/nsx"))

_spec = importlib.util.spec_from_file_location("union_test_groups", ROOT / "tools/nsx/groups.py")
groups = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(groups)


def ip_expr(ips, eid=None):
    e = {"resource_type": "IPAddressExpression", "ip_addresses": list(ips)}
    if eid:
        e["id"] = eid
    return e


def group(gid, *expr):
    return {"id": gid, "display_name": gid, "resource_type": "Group", "expression": list(expr)}


TAG = {"resource_type": "Condition", "member_type": "VirtualMachine", "key": "Tag",
       "operator": "EQUALS", "value": "0|web"}


class KeepTargetIpsTests(unittest.TestCase):

    def test_target_only_ips_join_the_payload_ip_expression(self):
        payload = group("g", ip_expr(["10.6.0.101", "10.6.0.105"]))
        target = group("g", ip_expr(["10.6.0.101", "10.8.0.101", "10.8.0.102"]))
        kept = groups._keep_target_ips(payload, target)
        self.assertEqual(kept, ["10.8.0.101", "10.8.0.102"])
        self.assertEqual(payload["expression"][0]["ip_addresses"],
                         ["10.6.0.101", "10.6.0.105", "10.8.0.101", "10.8.0.102"])

    def test_canonical_forms_are_the_same_address(self):
        payload = group("g", ip_expr(["10.6.0.1"]))
        target = group("g", ip_expr(["10.6.0.1/32"]))
        self.assertEqual(groups._keep_target_ips(payload, target), [])
        self.assertEqual(payload["expression"][0]["ip_addresses"], ["10.6.0.1"])

    def test_nothing_on_target_leaves_payload_untouched(self):
        payload = group("g", ip_expr(["10.6.0.1"]))
        before = copy.deepcopy(payload)
        self.assertEqual(groups._keep_target_ips(payload, group("g", TAG)), [])
        self.assertEqual(payload, before)

    def test_payload_without_ip_expression_gets_one_with_target_ids(self):
        payload = group("g", dict(TAG))
        target = group("g", dict(TAG),
                       {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR",
                        "id": "conj-1"},
                       ip_expr(["10.9.0.1"], eid="ipx-1"))
        kept = groups._keep_target_ips(payload, target)
        self.assertEqual(kept, ["10.9.0.1"])
        self.assertEqual(payload["expression"][1],
                         {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR",
                          "id": "conj-1"})
        self.assertEqual(payload["expression"][2], ip_expr(["10.9.0.1"], eid="ipx-1"))

    def test_empty_payload_expression_gets_ip_expression_without_conjunction(self):
        payload = group("g")
        kept = groups._keep_target_ips(payload, group("g", ip_expr(["10.9.0.1"])))
        self.assertEqual(kept, ["10.9.0.1"])
        self.assertEqual(payload["expression"], [ip_expr(["10.9.0.1"])])


class UnionPushTests(unittest.TestCase):
    """Drives groups.py push end to end against a fake target."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()

    def push(self, payloads, target, *, apply, extra=()):
        data, reports = self.root / "data", self.root / "reports"
        data.mkdir(parents=True, exist_ok=True)
        reports.mkdir(parents=True, exist_ok=True)
        for p in payloads:
            (data / f"{p['id']}.json").write_text(json.dumps(p))
        writes = []

        class Client:
            def __init__(self, **kwargs):
                pass

            def put_group(self, gid, obj, domain_id="default"):
                writes.append((gid, copy.deepcopy(obj)))

            def __getattr__(self, method):
                raise AssertionError(f"Unexpected API call: {method}")

        def setup_logging(directory, label):
            directory.mkdir(parents=True, exist_ok=True)
            return directory / "test.log", directory / "errors.log"

        argv = ["groups", "push", "--target", "nsx-lm2", "--reports-dir", str(reports),
                "--groups-dir", str(data)] + (["--apply"] if apply else []) + list(extra)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(groups, "NsxPolicyClient", Client))
            stack.enter_context(patch.object(groups, "_capture_target_groups",
                                             return_value=copy.deepcopy(target)))
            stack.enter_context(patch.object(groups, "_setup_logging", setup_logging))
            stack.enter_context(patch.object(groups, "resolve_manager", return_value="lm2.test"))
            stack.enter_context(patch.object(groups, "init_cli"))
            stack.enter_context(patch.object(groups.time, "sleep"))
            # Enter at every checkpoint: continue at the current batch size.
            stack.enter_context(patch("builtins.input", side_effect=itertools.repeat("")))
            stack.enter_context(patch.object(sys, "argv", argv))
            rc = groups.main()
        rows = {r["id"]: r for r in json.loads((reports / "groups.json").read_text())}
        summary = json.loads((reports / "summary.json").read_text())
        return rc, rows, summary, writes

    # The lab case: the sibling on the target holds 10.8.0.101 from an earlier
    # run; the VM is off, so the new capture does not have it, but the capture
    # does have a NEW address, 10.6.0.105.
    SOURCE = group("sib", ip_expr(["10.6.0.101", "10.6.0.105"]))
    TARGET = {"sib": group("sib", ip_expr(["10.6.0.101", "10.8.0.101"]))}

    def test_dry_run_adds_new_ips_and_keeps_stale_ones(self):
        rc, rows, summary, writes = self.push([self.SOURCE], self.TARGET, apply=False)
        self.assertEqual(rc, 0)
        self.assertEqual(writes, [])
        r = rows["sib"]
        self.assertEqual(r["status"], "dry_run")
        self.assertEqual(r["ips_added"], ["10.6.0.105"])
        self.assertEqual(r["ips_removed"], [])
        self.assertEqual(r["ips_kept_from_target"], ["10.8.0.101"])
        self.assertEqual(summary["totals"]["total_ips_kept_from_target"], 1)
        self.assertEqual(summary["totals"]["additive_only_contract"], "pass")

    def test_apply_pushes_the_union(self):
        rc, rows, summary, writes = self.push([self.SOURCE], self.TARGET, apply=True)
        self.assertEqual(rc, 0)
        self.assertEqual(len(writes), 1)
        gid, sent = writes[0]
        self.assertEqual(gid, "sib")
        self.assertEqual(sorted(groups._extract_ip_entries(sent)),
                         ["10.6.0.101", "10.6.0.105", "10.8.0.101"])
        self.assertNotEqual(rows["sib"]["status"], "failed_contract_violation")

    def test_union_equal_to_target_is_skipped_not_refused(self):
        # Nothing new in the source, one stale address on the target: the
        # union IS the target, so nothing is sent, and the kept IP is reported.
        source = group("sib", ip_expr(["10.6.0.101"]))
        rc, rows, summary, writes = self.push([source], self.TARGET, apply=True)
        self.assertEqual(rc, 0)
        self.assertEqual(writes, [])
        self.assertEqual(rows["sib"]["status"], groups.SKIPPED_STATUS)
        self.assertEqual(rows["sib"]["ips_kept_from_target"], ["10.8.0.101"])

    def test_new_group_has_nothing_to_keep(self):
        rc, rows, summary, writes = self.push([self.SOURCE], {}, apply=False)
        self.assertEqual(rc, 0)
        self.assertNotIn("ips_kept_from_target", rows["sib"])
        self.assertFalse(rows["sib"]["exists_on_target"])


class SkipNoIpChangeTests(UnionPushTests):
    """--skip-no-ip-change (the driver passes it for C3 / D2a): a sibling whose
    IPs are already all on the target is not sent, whatever else differs. The
    build regenerates the description with its build time on every run, so
    without this every sibling was rewritten, prompted for and re-described."""

    ON_TARGET = {"sib": dict(group("sib", ip_expr(["10.16.0.1", "10.16.0.2"], eid="nsx-id")),
                             description="generated 2026-09-27T22:01:50Z")}
    SAME_IPS = dict(group("sib", ip_expr(["10.16.0.2", "10.16.0.1"])),
                    description="generated 2026-09-28T17:41:28Z")

    def test_same_ips_new_description_is_not_sent(self):
        for apply in (False, True):
            with self.subTest(apply=apply):
                rc, rows, summary, writes = self.push([self.SAME_IPS], self.ON_TARGET,
                                                      apply=apply, extra=["--skip-no-ip-change"])
                self.assertEqual(rc, 0)
                self.assertEqual(writes, [])
                self.assertEqual(rows["sib"]["status"], groups.SKIPPED_STATUS)
                self.assertEqual(rows["sib"]["skipped_reason"], "no IP change on target")

    def test_a_new_ip_is_still_sent(self):
        grows = dict(group("sib", ip_expr(["10.16.0.1", "10.16.0.2", "10.16.0.3"])),
                     description="generated 2026-09-28T17:41:28Z")
        rc, rows, summary, writes = self.push([grows], self.ON_TARGET, apply=True,
                                              extra=["--skip-no-ip-change"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(writes), 1)
        self.assertEqual(rows["sib"]["ips_added"], ["10.16.0.3"])

    def test_a_new_group_is_created(self):
        rc, rows, summary, writes = self.push([self.SAME_IPS], {}, apply=True,
                                              extra=["--skip-no-ip-change"])
        self.assertEqual(len(writes), 1)

    def test_without_the_flag_the_description_alone_forces_a_write(self):
        # Why the flag exists: the plain content comparison sees the new
        # description and the ids / paths NSX adds, and rewrites the group.
        rc, rows, summary, writes = self.push([self.SAME_IPS], self.ON_TARGET, apply=True)
        self.assertEqual(len(writes), 1)

    def test_force_push_overrides_it(self):
        rc, rows, summary, writes = self.push([self.SAME_IPS], self.ON_TARGET, apply=True,
                                              extra=["--skip-no-ip-change", "--force-push"])
        self.assertEqual(len(writes), 1)


if __name__ == "__main__":
    unittest.main()
