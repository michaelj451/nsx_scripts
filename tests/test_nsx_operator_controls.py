"""Offline tests for live output and incremental NSX apply checkpoints."""
import argparse
import contextlib
import importlib.util
import io
import json
import logging
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "tools/nsx"))
from nsx.apply_batch import ApplyBatch
from nsx.streaming import stream_command


def load(name):
    spec = importlib.util.spec_from_file_location(f"operator_test_{name}", ROOT / f"tools/nsx/{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


TOOLS = {name: load(name) for name in ("groups", "services", "policies", "rules")}
workflow = load("run_workflow")
capture = load("capture_nsx_state")
backup = load("backup_nsx_state")


def dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


class BatchTests(unittest.TestCase):
    def test_starts_one_ramps_resets_and_stops(self):
        batch = ApplyBatch(True, logging.getLogger("test"))
        with patch("builtins.input", side_effect=["3", "n", "x"]) as prompt:
            self.assertTrue(batch.before_write())
            prompt.assert_not_called()
            batch.record({"display_name": "First", "status": "success_put"})
            self.assertTrue(batch.before_write())
            self.assertEqual(batch.size, 3)
            for _ in range(3):
                self.assertTrue(batch.before_write())
                batch.record({"id": "test"})
            self.assertTrue(batch.before_write())
            self.assertEqual(batch.size, 1)
            batch.record({"id": "last"})
            self.assertFalse(batch.before_write())
            self.assertFalse(batch.before_write())
            self.assertEqual(prompt.call_count, 3)

    def test_no_input_never_auto_approves(self):
        for exc in (EOFError, KeyboardInterrupt):
            batch = ApplyBatch(True, logging.getLogger("test"))
            batch.record({"id": "one"})
            with patch("builtins.input", side_effect=exc):
                self.assertFalse(batch.before_write())
            self.assertEqual(batch.decisions[-1]["decision"], "input_closed")

    def test_invalid_sizes_reprompt_and_cannot_disable_checkpoints(self):
        batch = ApplyBatch(True, logging.getLogger("test"))
        batch.record({"id": "one"})
        with patch("builtins.input", side_effect=["0", "-2", "bad", "2"]) as prompt:
            self.assertTrue(batch.before_write())
        self.assertEqual(prompt.call_count, 4)
        self.assertEqual(batch.size, 2)
        for size in (0, 10):
            with self.assertRaises(ValueError):
                ApplyBatch(True, logging.getLogger("test"), size)


class PushTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()

    def run_tool(self, name, *, answers=("x",), count=4, apply=True, fail_first=False,
                 action="push", eof=False, conflict_on_put=False, restore=False):
        mod = TOOLS[name]
        root = self.root / f"{name}_{action}"
        data, reports = root / "data", root / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        payloads = []
        for n in range(count):
            payload = {"id": f"id{n}", "display_name": f"Object {n}", "expression": [],
                       "resource_type": {"groups": "Group", "services": "Service",
                                         "policies": "SecurityPolicy", "rules": "Rule"}[name]}
            payloads.append(payload)
            file = (data / f"p{n}/policy.json" if name == "policies" else
                    data / f"p0/rules/r{n}.json" if name == "rules" else data / f"obj{n}.json")
            if name == "rules":
                payload["_parent_policy_id"] = "p0"
                payload["source_groups"] = ["/infra/domains/default/groups/original"]
            dump(file, payload)
        writes, prompts = [], []
        current = {p["id"]: p for p in payloads}
        if name == "rules":
            current = {f"p0::{p['id']}": {"policy_id": "p0", "rule_id": p["id"], "payload": p}
                       for p in payloads}
        failed_once = False

        class Client:
            def __init__(self, **kwargs):
                pass

            def __getattr__(self, method):
                if not method.startswith(("put_", "patch_", "delete_")):
                    raise AssertionError(f"Unexpected API call: {method}")

                def write(*args, **kwargs):
                    nonlocal failed_once
                    gid = kwargs.get("rule_id") or (args[0] if args else "unknown")
                    writes.append((method, gid))
                    if conflict_on_put and method.startswith("put_"):
                        raise mod.NsxApiError(409, "already exists")
                    if fail_first and not failed_once:
                        failed_once = True
                        raise RuntimeError("404 requested object could not be found. Object identifiers are case sensitive.")
                return write

        answer_iter = iter(answers)

        def answer(prompt):
            prompts.append(len(writes))
            if eof:
                raise EOFError
            return next(answer_iter)

        def setup_logging(directory, label):
            directory.mkdir(parents=True, exist_ok=True)
            return directory / "test.log", directory / "errors.log"

        argv = [name, action, "--target", "nsx-lm2", "--reports-dir", str(reports)]
        if action == "push":
            argv += [f"--{name}-dir", str(data)]
        elif action == "amend-refs":
            smap = root / "sibling_map.json"
            dump(smap, {"domain_id": "default", "map": [{"original_id": "original", "sibling_id": "sibling"}]})
            argv += ["--sibling-map", str(smap)]
        else:
            baseline = reports / "baselines/test_target_baseline.json"
            dump(baseline, current if restore else {})
            if name == "groups":
                argv += ["--scope", "all", "--allow-delete"]
        if apply:
            argv += ["--apply"]
        helper = f"_capture_target_{name}"
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(mod, "NsxPolicyClient", Client))
            stack.enter_context(patch.object(mod, helper, return_value=current if action != "push" else {}))
            stack.enter_context(patch.object(mod, "_setup_logging", setup_logging))
            stack.enter_context(patch.object(mod, "resolve_manager", return_value="lm2.test"))
            stack.enter_context(patch.object(mod, "init_cli"))
            stack.enter_context(patch.object(mod.time, "sleep"))
            stack.enter_context(patch("builtins.input", side_effect=answer))
            stack.enter_context(patch.object(sys, "argv", argv))
            rc = mod.main()
        report = (reports / "summary.json" if action == "push" else
                  reports / "amend_refs_summary.json" if action == "amend-refs" else
                  next(reports.glob("revert_summary_*.json")))
        return rc, writes, prompts, json.loads(report.read_text()), reports

    def test_all_push_types_start_one_and_ramp_at_prompt(self):
        for name in TOOLS:
            with self.subTest(name=name):
                rc, writes, prompts, report, _ = self.run_tool(name, answers=("2", "x"))
                self.assertEqual(rc, 130)
                self.assertEqual(len(writes), 3)
                self.assertEqual(prompts, [1, 3])
                self.assertEqual(report["totals"]["interactive_batch_size_initial"], 1)
                self.assertEqual(report["totals"]["interactive_batch_size_final"], 2)
                self.assertTrue(report["totals"]["interactive_exit_requested"])

    def test_all_push_types_stop_on_eof(self):
        for name in TOOLS:
            with self.subTest(name=name):
                rc, writes, _, report, _ = self.run_tool(name, eof=True)
                self.assertEqual(rc, 130)
                self.assertEqual(len(writes), 1)
                self.assertEqual(report["interactive_decisions"][0]["decision"], "input_closed")

    def test_retry_pass_requires_checkpoint_and_stops_without_more_writes(self):
        for name in TOOLS:
            with self.subTest(name=name):
                rc, writes, prompts, _, _ = self.run_tool(name, count=2, fail_first=True)
                self.assertEqual(rc, 130)
                self.assertEqual(len(writes), 2)
                self.assertEqual(prompts, [2])

    def test_dry_runs_never_prompt_or_write(self):
        for name in TOOLS:
            with self.subTest(name=name):
                rc, writes, prompts, _, _ = self.run_tool(name, apply=False)
                self.assertEqual(rc, 0)
                self.assertEqual(writes, [])
                self.assertEqual(prompts, [])

    def test_rule_amendments_start_one_and_ramp(self):
        rc, writes, prompts, report, _ = self.run_tool("rules", action="amend-refs", answers=("2", "x"))
        self.assertEqual(rc, 130)
        self.assertEqual(len(writes), 3)
        self.assertEqual(prompts, [1, 3])
        self.assertTrue(report["totals"]["interactive_exit_requested"])

    def test_completed_pushes_exit_successfully(self):
        for name in TOOLS:
            with self.subTest(name=name):
                rc, writes, prompts, report, _ = self.run_tool(name, answers=("10",))
                self.assertEqual(rc, 0)
                self.assertEqual(len(writes), 4)
                self.assertEqual(prompts, [1])
                self.assertFalse(report["totals"]["interactive_exit_requested"])

    def test_put_patch_fallback_counts_as_one_object(self):
        for name in TOOLS:
            with self.subTest(name=name):
                rc, writes, prompts, report, _ = self.run_tool(name, conflict_on_put=True)
                self.assertEqual(rc, 130)
                self.assertEqual(len(writes), 2)
                self.assertTrue(writes[0][0].startswith("put_"))
                self.assertTrue(writes[1][0].startswith("patch_"))
                self.assertEqual(prompts, [2])
                self.assertEqual(report["interactive_decisions"][0]["applied_count"], 1)

    def test_completed_reverts_mark_baseline_after_all_objects(self):
        for name in TOOLS:
            for restore in (False, True):
                with self.subTest(name=name, restore=restore):
                    rc, writes, prompts, report, _ = self.run_tool(
                        name, action="revert", answers=("10",), restore=restore)
                    self.assertEqual(rc, 0)
                    self.assertEqual(len(writes), 4)
                    self.assertEqual(prompts, [1])
                    self.assertTrue(report["baseline_file"].endswith(".reverted"))
                    self.assertTrue(Path(report["baseline_file"]).is_file())

    def test_revert_stop_retains_baseline(self):
        for name in TOOLS:
            with self.subTest(name=name):
                rc, writes, prompts, report, reports = self.run_tool(name, action="revert")
                self.assertEqual(rc, 130)
                self.assertEqual(len(writes), 1)
                self.assertEqual(prompts, [1])
                self.assertTrue(Path(report["baseline_file"]).is_file())
                self.assertEqual(list((reports / "baselines").glob("*.reverted")), [])

    def test_stop_prevents_remaining_domains(self):
        args = argparse.Namespace(func=lambda sub: 130, apply=True)
        with patch.object(TOOLS["groups"], "_discover_domains", return_value=["first", "second"]), \
                patch.object(args, "func", return_value=130) as run_domain:
            self.assertNotEqual(TOOLS["groups"]._run_all_domains(args), 0)
        self.assertEqual(run_domain.call_count, 1)

    def test_workflow_stop_overrides_continue_on_error(self):
        run = self.root / "workflow"
        dump(run / "nsx_sibling_groups/source.test/sibling_map.json", {"map": []})
        labels = []

        def run_step(label, cmd, logs):
            logs.mkdir(parents=True, exist_ok=True)
            labels.append(label)
            rc = 130 if label == "c3_siblings" else 0
            return {"label": label, "cmd": cmd, "ok": rc == 0, "rc": rc}

        argv = ["run_workflow", "--source", "nsx-lm1", "--target", "nsx-lm2", "--phase", "c",
                "--apply", "--continue-on-error", "--run-dir", str(run)]
        with patch.object(workflow, "init_cli"), patch.object(workflow, "resolve_manager", return_value="source.test"), \
                patch.object(workflow, "check_capture_gate", return_value=None), \
                patch.object(workflow, "run_step", run_step), patch.object(sys, "argv", argv):
            self.assertNotEqual(workflow.main(), 0)
        self.assertEqual(labels, ["c3_siblings", "report"])


class StreamingTests(unittest.TestCase):
    def test_child_inherits_operator_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            logfile = Path(tmp) / "child.log"
            child = "answer=input('Next batch: '); print('Selected', answer)"
            wrapper = (
                f"import sys; sys.path.insert(0, {str(ROOT / 'app')!r}); "
                "from pathlib import Path; from nsx.streaming import stream_command; "
                f"rc, _ = stream_command([sys.executable, '-c', {child!r}], "
                f"Path({str(ROOT)!r}), Path({str(logfile)!r})); sys.exit(rc)"
            )
            result = subprocess.run([sys.executable, "-c", wrapper], input="2\n",
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "Next batch: Selected 2\n")
            self.assertEqual(logfile.read_text(), result.stdout)

    def test_output_and_prompt_are_live_and_log_is_written_before_child_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ack = root / "ack"
            logfile = root / "child.log"
            class Terminal(io.StringIO):
                def write(self, text):
                    result = super().write(text)
                    if "Continue? " in self.getvalue():
                        # The child cannot finish until the terminal has seen
                        # this partial line and the log already contains it.
                        if "Continue? " in logfile.read_text():
                            ack.touch()
                    return result
            child = ("import sys,time; from pathlib import Path; "
                     "sys.stdout.write('collected café\\n'); sys.stderr.write('Continue? '); "
                     f"p=Path({str(ack)!r}); end=time.monotonic()+3\n"
                     "while not p.exists() and time.monotonic()<end: time.sleep(.01)\n"
                     "sys.exit(7 if p.exists() else 9)")
            terminal = Terminal()
            with contextlib.redirect_stdout(terminal):
                rc, tail = stream_command([sys.executable, "-c", child], ROOT, logfile)
            self.assertEqual(rc, 7)
            self.assertEqual(logfile.read_text(), terminal.getvalue())
            self.assertIn("café", tail)
            self.assertIn("Continue? ", tail)

    def test_removed_quiet_option_is_rejected_without_running_capture(self):
        for mod in (capture, backup):
            with patch.object(sys, "argv", ["tool", "--source", "nsx-lm1", "--quiet"]), \
                    patch.object(mod, "run_step") as run_step:
                with self.assertRaises(SystemExit) as exc:
                    mod.main()
                self.assertEqual(exc.exception.code, 2)
                run_step.assert_not_called()


if __name__ == "__main__":
    unittest.main()
