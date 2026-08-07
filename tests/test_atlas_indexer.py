import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
INDEXER = ROOT / "resources" / "skills" / "project-modeling" / "scripts" / "atlas_indexer.py"
SPEC = importlib.util.spec_from_file_location("atlas_indexer", INDEXER)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AtlasIndexerTests(unittest.TestCase):
    @staticmethod
    def fake_atlas(root):
        executable = root / "atlas"
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o755)
        return executable

    def run_prepare(self, root, database_exists=False):
        atlas = self.fake_atlas(root)
        if database_exists:
            database = root / "repo" / ".atlas" / "atlas.db"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"db")
        output = root / "run" / "atlas" / "index_status.json"

        def finish_index(command):
            database = root / "repo" / ".atlas" / "atlas.db"
            database.parent.mkdir(parents=True, exist_ok=True)
            database.write_bytes(b"db")
            return 0, ["index complete"]

        with patch.object(MODULE, "run_streaming", side_effect=finish_index) as run:
            with patch.object(MODULE.subprocess, "run", return_value=subprocess.CompletedProcess(
                args=[], returncode=0, stdout="Files indexed:   7\n", stderr="",
            )):
                result = MODULE.prepare_index(
                    root / "repo", output, atlas=str(atlas),
                )
        return result, MODULE.json.loads(output.read_text(encoding="utf-8")), run.call_args.args[0]

    def test_first_run_builds_full_index(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "repo").mkdir()

            result, stored, command = self.run_prepare(root)

            self.assertTrue(result["ok"])
            self.assertEqual(result["action"], "index")
            self.assertEqual(result["files_indexed"], 7)
            self.assertEqual(command[1], "index")
            self.assertEqual(command[-1], "full")
            self.assertEqual(stored["status"], "ready")

    def test_existing_database_uses_incremental_sync(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "repo").mkdir()

            result, _, command = self.run_prepare(root, database_exists=True)

            self.assertTrue(result["ok"])
            self.assertEqual(result["action"], "sync")
            self.assertEqual(command[1], "sync")

    def test_zero_indexed_files_is_not_ready(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo"
            repo.mkdir()
            atlas = self.fake_atlas(root)
            output = root / "index_status.json"

            def finish_index(command):
                database = repo / ".atlas" / "atlas.db"
                database.parent.mkdir(parents=True)
                database.write_bytes(b"db")
                return 0, []

            with patch.object(MODULE, "run_streaming", side_effect=finish_index):
                with patch.object(MODULE.subprocess, "run", return_value=subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="Files indexed:   0\n", stderr="",
                )):
                    result = MODULE.prepare_index(repo, output, atlas=str(atlas))

            self.assertFalse(result["ok"])
            self.assertEqual(result["error"], "atlas_index_not_ready")


if __name__ == "__main__":
    unittest.main()
