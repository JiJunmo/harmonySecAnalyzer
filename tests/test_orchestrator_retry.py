import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / ".opencode" / "skills" / "audit-orchestration" / "scripts" / "audit_orchestrator.py"
SPEC = importlib.util.spec_from_file_location("audit_orchestrator_retry", ORCHESTRATOR)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OrchestratorRetryTests(unittest.TestCase):
    def make_run(self, td):
        run = Path(td) / "run"
        MODULE.cmd_init(SimpleNamespace(
            run_dir=str(run), target_repo="/tmp/target", scope="full",
        ))
        MODULE.enqueue_tasks(str(run), [{"kind": "path_finding", "entry_id": "E-001"}])
        return run

    def test_missing_result_is_requeued_and_second_attempt_can_complete(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td)

            first_task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            first = MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task=first_task["task_id"]))

            self.assertTrue(Path(first_task["result_path"]).is_absolute())
            self.assertTrue(first["ok"])
            self.assertTrue(first["retry_scheduled"])
            self.assertEqual(first["next_attempt"], 2)

            second_task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            MODULE.write_json(second_task["result_path"], {
                "task_id": second_task["task_id"],
                "entry_id": second_task["entry_id"],
                "conclusions": [{"classification": "no_path"}],
            })
            second = MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task=second_task["task_id"]))
            stored = MODULE.read_jsonl(MODULE.P(str(run))["queue"])[0]

            self.assertTrue(second["ok"])
            self.assertEqual(stored["status"], "done")
            self.assertEqual(stored["attempts"], 2)
            self.assertIsNone(stored["error"])
            self.assertIn("missing_or_invalid_result", stored["last_error"])
            self.assertEqual(len(stored["retry_history"]), 1)

    def test_missing_result_reaches_terminal_failure_on_third_attempt(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td)
            results = []

            for _ in range(MODULE.MAX_ATTEMPTS):
                task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
                results.append(MODULE.cmd_complete(SimpleNamespace(
                    run_dir=str(run), task=task["task_id"],
                )))

            stored = MODULE.read_jsonl(MODULE.P(str(run))["queue"])[0]
            events = MODULE.read_jsonl(MODULE.P(str(run))["events"])

            self.assertTrue(results[0]["retry_scheduled"])
            self.assertTrue(results[1]["retry_scheduled"])
            self.assertFalse(results[2]["ok"])
            self.assertFalse(results[2]["retry_scheduled"])
            self.assertEqual(stored["status"], "failed")
            self.assertEqual(stored["attempts"], MODULE.MAX_ATTEMPTS)
            self.assertEqual(len(stored["retry_history"]), MODULE.MAX_ATTEMPTS)
            self.assertEqual(
                [event["event"] for event in events].count("retry_scheduled"), 2,
            )
            self.assertEqual([event["event"] for event in events].count("fail"), 1)

    def test_complete_requires_running_task(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td)

            result = MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task="path-E-001"))

            self.assertFalse(result["ok"])
            self.assertEqual(result["error"], "task_not_running")

    def test_terminal_failure_requires_force_for_manual_retry(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td)
            for _ in range(MODULE.MAX_ATTEMPTS):
                task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
                MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task=task["task_id"]))

            denied = MODULE.cmd_retry(SimpleNamespace(
                run_dir=str(run), task="path-E-001", force=False,
            ))
            forced = MODULE.cmd_retry(SimpleNamespace(
                run_dir=str(run), task="path-E-001", force=True,
            ))
            next_task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]

            self.assertFalse(denied["ok"])
            self.assertEqual(denied["error"], "max_attempts_reached")
            self.assertTrue(forced["ok"])
            self.assertTrue(forced["forced"])
            self.assertEqual(next_task["attempts"], MODULE.MAX_ATTEMPTS + 1)


if __name__ == "__main__":
    unittest.main()
