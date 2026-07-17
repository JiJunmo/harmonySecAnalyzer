import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / ".opencode" / "skills" / "audit-orchestration" / "scripts" / "audit_orchestrator.py"
SPEC = importlib.util.spec_from_file_location("audit_orchestrator_matrix", ORCHESTRATOR)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AttackMatrixTests(unittest.TestCase):
    def make_run(self, td, entry_type="deeplink", seeds=None):
        run = Path(td) / "run"
        MODULE.cmd_init(SimpleNamespace(run_dir=str(run), target_repo="/tmp/target", scope="full"))
        paths = MODULE.P(str(run))
        MODULE.write_json(paths["entryList"], {
            "entry_list": [{
                "entry_id": "E-001",
                "analysis_unit_id": "AU-001",
                "component_id": "CMP-001",
                "ability": "EntryAbility",
                "entry_function": "EntryAbility.onNewWant",
                "entry_function_file": "EntryAbility.ets",
                "type": entry_type,
                "project_candidate_ids": ["PE-001"],
            }],
            "excluded_candidates": [], "unresolved_candidates": [], "coverage_gaps": [],
        })
        MODULE.write_json(paths["dangerSeedList"], {"danger_seed_list": seeds or []})
        MODULE.write_json(paths["discoveryPlan"], {
            "schema_version": 1,
            "units": [{"unit_id": "AU-001", "status": "completed", "entry_ids": ["E-001"]}],
        })
        return run

    @staticmethod
    def sql_seed(seed_id, location="Db.ets:20"):
        return {
            "seed_id": seed_id,
            "category": "sql",
            "operation": "execute query",
            "symbol": "Database.query",
            "symbol_file": "Db.ets",
            "location": location,
            "sink_parameter": "sql",
        }

    def test_compiler_normalizes_duplicate_sinks_and_builds_sparse_work_item(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td, seeds=[self.sql_seed("D-001"), self.sql_seed("D-002")])

            result = MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            paths = MODULE.P(str(run))
            seeds = MODULE.read_json(paths["normalizedSeeds"])
            matrix = MODULE.read_json(paths["attackMatrix"])
            queue = MODULE.read_jsonl(paths["queue"])

            self.assertTrue(result["ok"])
            self.assertEqual(result["seed_normalization"]["before"], 2)
            self.assertEqual(result["seed_normalization"]["after"], 1)
            self.assertEqual(seeds["danger_seeds"][0]["seed_aliases"], ["D-001", "D-002"])
            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["pattern"], "deeplink-injection")
            self.assertEqual(matrix["work_items"][0]["capability_id"], "CAP-INJ-001")
            self.assertEqual(queue[0]["work_item_id"], matrix["work_items"][0]["work_item_id"])
            self.assertEqual(queue[0]["capability_id"], "CAP-INJ-001")

    def test_incompatible_pair_is_not_added_as_cartesian_work(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td, entry_type="exported_ability", seeds=[self.sql_seed("D-001")])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(matrix["work_items"], [])
            self.assertEqual(matrix["routing_gaps"][0]["reason"], "no_compatible_pattern_route")

    def test_web_navigation_routes_only_to_navigation_capability(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-WEB-001", "category": "web_navigation", "operation": "load URL",
                "symbol": "WebPage.load", "symbol_file": "WebPage.ets", "location": "WebPage.ets:20",
                "sink_role": "terminal", "sink_parameter": "url", "tags": ["web", "navigation"],
            }
            run = self.make_run(td, seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["capability_id"], "CAP-WEB-001")
            self.assertEqual(matrix["work_items"][0]["pattern"], "web-untrusted-navigation")

    def test_jsbridge_terminal_sink_routes_only_to_bridge_capability(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-WEB-002", "category": "fs", "operation": "bridge file read",
                "symbol": "WebBridge.openFile", "symbol_file": "WebBridge.ets", "location": "WebBridge.ets:42",
                "sink_role": "terminal", "sink_parameter": "path", "tags": ["web", "jsbridge"],
            }
            run = self.make_run(td, seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["capability_id"], "CAP-WEB-002")
            self.assertEqual(matrix["work_items"][0]["pattern"], "web-jsbridge-origin-exposure")

    def test_generic_sensitive_sink_does_not_enter_jsbridge_route(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-WEB-003", "category": "network", "operation": "send request",
                "symbol": "ApiClient.send", "symbol_file": "ApiClient.ets", "location": "ApiClient.ets:18",
                "sink_role": "terminal", "sink_parameter": "body",
            }
            run = self.make_run(td, seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(matrix["work_items"], [])
            self.assertEqual(matrix["routing_gaps"][0]["reason"], "no_compatible_pattern_route")

    def test_jsbridge_registration_is_intermediate_and_not_routed(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-WEB-004", "category": "jsbridge", "operation": "register proxy",
                "symbol": "WebPage.registerBridge", "symbol_file": "WebPage.ets", "location": "WebPage.ets:30",
                "sink_role": "intermediate", "tags": ["web", "jsbridge"],
            }
            run = self.make_run(td, seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(matrix["work_items"], [])
            self.assertEqual(matrix["routing_gaps"], [])
            self.assertEqual(matrix["seeds"][0]["disposition"], "excluded_intermediate")

    def test_want_redirect_seed_routes_to_icc_capability(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-ICC-001", "category": "ability_data", "operation": "forward Want",
                "symbol": "ProxyAbility.forward", "symbol_file": "ProxyAbility.ets", "location": "ProxyAbility.ets:35",
                "sink_role": "terminal", "sink_parameter": "want",
                "tags": ["icc", "want", "want_redirect"],
                "controlled_properties": ["abilityName", "parameters.operation"],
            }
            run = self.make_run(td, entry_type="exported_ability", seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["capability_id"], "CAP-ICC-001")
            self.assertEqual(matrix["work_items"][0]["pattern"], "want-redirect")

    def test_generic_ability_data_seed_does_not_enter_want_redirect(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-ICC-002", "category": "ability_data", "operation": "update state",
                "symbol": "StateStore.update", "symbol_file": "StateStore.ets", "location": "StateStore.ets:22",
                "sink_role": "terminal", "sink_parameter": "value",
            }
            run = self.make_run(td, entry_type="exported_ability", seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(matrix["work_items"], [])
            self.assertEqual(matrix["routing_gaps"][0]["reason"], "no_compatible_pattern_route")

    def test_jsbridge_ability_dispatch_does_not_enter_want_redirect(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-ICC-003", "category": "ability_data", "operation": "bridge starts Ability",
                "symbol": "WebBridge.openPage", "symbol_file": "WebBridge.ets", "location": "WebBridge.ets:50",
                "sink_role": "terminal", "sink_parameter": "want", "tags": ["web", "jsbridge"],
            }
            run = self.make_run(td, entry_type="exported_ability", seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["capability_id"], "CAP-WEB-002")

    def test_datashare_query_routes_only_to_query_capability(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-PROVIDER-001", "category": "sql", "operation": "provider query",
                "symbol": "CatalogStore.query", "symbol_file": "CatalogStore.ets", "location": "CatalogStore.ets:31",
                "sink_role": "terminal", "sink_parameter": "query",
                "tags": ["provider", "datashare", "datashare_query"],
                "controlled_properties": ["order", "selection"],
            }
            run = self.make_run(td, entry_type="extension_uri", seeds=[seed])
            paths = MODULE.P(str(run))
            entries = MODULE.read_json(paths["entryList"])
            entries["entry_list"][0]["entry_types"] = ["deeplink", "implicit_want", "extension_uri"]
            MODULE.write_json(paths["entryList"], entries)

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(paths["attackMatrix"])

            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["capability_id"], "CAP-PROVIDER-001")
            self.assertEqual(matrix["work_items"][0]["pattern"], "datashare-query-injection")

    def test_datashare_file_routes_only_to_file_capability(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-PROVIDER-002", "category": "fs", "operation": "provider file open",
                "symbol": "ShareProvider.open", "symbol_file": "ShareProvider.ets", "location": "ShareProvider.ets:44",
                "sink_role": "terminal", "sink_parameter": "file",
                "tags": ["provider", "datashare", "datashare_file"],
                "controlled_properties": ["uri.path", "mode"],
            }
            run = self.make_run(td, entry_type="extension_uri", seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["capability_id"], "CAP-PROVIDER-002")
            self.assertEqual(matrix["work_items"][0]["pattern"], "datashare-file-access")

    def test_jsbridge_file_sink_is_excluded_from_generic_file_route(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-PROVIDER-003", "category": "fs", "operation": "bridge file read",
                "symbol": "WebBridge.read", "symbol_file": "WebBridge.ets", "location": "WebBridge.ets:60",
                "sink_role": "terminal", "sink_parameter": "path", "tags": ["web", "jsbridge"],
            }
            run = self.make_run(td, entry_type="extension_uri", seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["capability_id"], "CAP-WEB-002")

    def test_untagged_extension_file_sink_remains_generic_file_capability(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-PROVIDER-004", "category": "fs", "operation": "extension file read",
                "symbol": "FileExtension.read", "symbol_file": "FileExtension.ets", "location": "FileExtension.ets:25",
                "sink_role": "terminal", "sink_parameter": "path",
            }
            run = self.make_run(td, entry_type="extension_uri", seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["capability_id"], "CAP-FS-001")

    def test_ipc_transaction_routes_to_authorization_capability(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-IPC-001", "category": "privacy", "operation": "read private account",
                "symbol": "AccountStore.read", "symbol_file": "AccountStore.ets", "location": "AccountStore.ets:40",
                "sink_role": "terminal", "sink_parameter": "accountId", "tags": ["ipc", "ipc_transaction"],
            }
            run = self.make_run(td, entry_type="ipc_stub_transaction", seeds=[seed])
            paths = MODULE.P(str(run))
            entries = MODULE.read_json(paths["entryList"])
            entries["entry_list"][0].update({
                "ability": "AccountStub", "entry_function": "AccountStub.onRemoteMessageRequest",
                "entry_function_file": "AccountStub.ets", "ipc_stub_class": "AccountStub",
                "ipc_descriptor": "ohos.demo.IAccount", "transaction_code": 7,
                "publication_point": "AccountService.onConnect",
            })
            MODULE.write_json(paths["entryList"], entries)

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(paths["attackMatrix"])

            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["capability_id"], "CAP-IPC-001")
            self.assertEqual(matrix["work_items"][0]["pattern"], "ipc-unauthorized-transaction")

    def test_ipc_message_sink_creates_separate_authorization_and_input_work(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-IPC-002", "category": "command", "operation": "run maintenance command",
                "symbol": "Maintenance.run", "symbol_file": "Maintenance.ets", "location": "Maintenance.ets:55",
                "sink_role": "terminal", "sink_parameter": "command",
                "tags": ["ipc", "ipc_transaction", "ipc_message"],
                "controlled_properties": ["message_string"],
            }
            run = self.make_run(td, entry_type="ipc_stub_transaction", seeds=[seed])
            paths = MODULE.P(str(run))
            entries = MODULE.read_json(paths["entryList"])
            entries["entry_list"][0].update({
                "ability": "MaintenanceStub", "entry_function": "MaintenanceStub.onRemoteMessageRequest",
                "entry_function_file": "MaintenanceStub.ets", "ipc_stub_class": "MaintenanceStub",
                "ipc_descriptor": "ohos.demo.IMaintenance", "transaction_code": 4,
                "publication_point": "SystemAbility.addSystemAbility",
            })
            MODULE.write_json(paths["entryList"], entries)

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(paths["attackMatrix"])

            self.assertEqual(
                {row["capability_id"] for row in matrix["work_items"]},
                {"CAP-IPC-001", "CAP-IPC-002"},
            )
            self.assertEqual(len(matrix["work_items"]), 2)

    def test_intermediate_seed_is_excluded_without_routing_gap(self):
        with tempfile.TemporaryDirectory() as td:
            seed = {
                "seed_id": "D-001", "category": "network", "symbol": "State.write",
                "symbol_file": "State.ets", "location": "State.ets:10", "sink_role": "intermediate",
                "tags": ["web"], "discovered_from_unit": "AU-001",
            }
            run = self.make_run(td, entry_type="exported_ability", seeds=[seed])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(MODULE.P(str(run))["attackMatrix"])

            self.assertEqual(matrix["work_items"], [])
            self.assertEqual(matrix["routing_gaps"], [])
            self.assertEqual(matrix["seeds"][0]["disposition"], "excluded_intermediate")
            self.assertEqual(matrix["summary"]["excluded_intermediate"], 1)

    def test_discovery_unit_prefilter_avoids_unrelated_entry_sink_pair(self):
        with tempfile.TemporaryDirectory() as td:
            seed = self.sql_seed("D-001")
            seed["discovered_from_unit"] = "AU-001"
            run = self.make_run(td, seeds=[seed])
            paths = MODULE.P(str(run))
            entry_doc = MODULE.read_json(paths["entryList"])
            entry_doc["entry_list"].append({
                "entry_id": "E-002", "analysis_unit_id": "AU-002", "component_id": "CMP-002",
                "ability": "OtherAbility", "entry_function": "OtherAbility.onCreate",
                "entry_function_file": "OtherAbility.ets", "type": "deeplink",
                "project_candidate_ids": ["PE-002"],
            })
            MODULE.write_json(paths["entryList"], entry_doc)

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            matrix = MODULE.read_json(paths["attackMatrix"])

            self.assertEqual(len(matrix["work_items"]), 1)
            self.assertEqual(matrix["work_items"][0]["entry_id"], "E-001")
            self.assertEqual(matrix["summary"]["prefiltered_pairs"], 1)

    def test_seed_normalization_merges_unit_arrays_and_preserves_terminal_role(self):
        with tempfile.TemporaryDirectory() as td:
            first = self.sql_seed("D-001")
            first.update({"sink_role": "intermediate", "discovered_from_units": ["AU-001"]})
            second = self.sql_seed("D-002")
            second.update({"sink_role": "terminal", "reachable_from_unit": "AU-002"})
            run = self.make_run(td, seeds=[first, second])

            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            seed = MODULE.read_json(MODULE.P(str(run))["normalizedSeeds"])["danger_seeds"][0]

            self.assertEqual(seed["sink_role"], "terminal")
            self.assertEqual(seed["discovered_from_units"], ["AU-001"])
            self.assertEqual(seed["reachable_from_units"], ["AU-002"])

    def test_work_item_result_must_match_matrix_identity(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td, seeds=[self.sql_seed("D-001")])
            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            MODULE.write_json(run / task["result_file"], {
                "task_id": task["task_id"],
                "work_item_id": task["work_item_id"],
                "entry_id": task["entry_id"],
                "conclusions": [{
                    "seed_id": "D-WRONG",
                    "pattern": task["pattern"],
                    "classification": "no_path",
                }],
            })

            result = MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task=task["task_id"]))
            coverage = MODULE.attack_matrix_coverage(str(run))

            self.assertTrue(result["ok"])
            self.assertTrue(result["retry_scheduled"])
            self.assertIn("seed_id_mismatch", result["error"])
            self.assertEqual(coverage["by_status"], {"queued": 1})
            self.assertFalse(coverage["ready"])
            self.assertTrue(Path(result["archived_result"]).is_file())

    def test_terminal_no_path_closes_matrix_work_item(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td, seeds=[self.sql_seed("D-001")])
            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            MODULE.write_json(run / task["result_file"], {
                "task_id": task["task_id"],
                "work_item_id": task["work_item_id"],
                "entry_id": task["entry_id"],
                "conclusions": [{
                    "seed_id": task["seed_id"],
                    "pattern": task["pattern"],
                    "classification": "no_path",
                    "atlas_evidence": {"query_id": "q-1"},
                }],
            })

            result = MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task=task["task_id"]))
            coverage = MODULE.attack_matrix_coverage(str(run))

            self.assertTrue(result["ok"])
            self.assertEqual(result["classification"], "no_path")
            self.assertTrue(coverage["ready"])
            self.assertEqual(coverage["by_status"], {"no_path": 1})

    def test_analysis_gap_is_terminal_but_remains_visible(self):
        with tempfile.TemporaryDirectory() as td:
            run = self.make_run(td, seeds=[self.sql_seed("D-001")])
            MODULE.cmd_compile_matrix(SimpleNamespace(run_dir=str(run)))
            task = MODULE.cmd_next(SimpleNamespace(run_dir=str(run)))["task"]
            MODULE.write_json(run / task["result_file"], {
                "task_id": task["task_id"],
                "work_item_id": task["work_item_id"],
                "entry_id": task["entry_id"],
                "conclusions": [{
                    "seed_id": task["seed_id"],
                    "pattern": task["pattern"],
                    "classification": "analysis_gap",
                    "evidence_gap": "Atlas returned terminal partial",
                }],
            })

            result = MODULE.cmd_complete(SimpleNamespace(run_dir=str(run), task=task["task_id"]))
            coverage = MODULE.attack_matrix_coverage(str(run))
            gaps = MODULE.read_jsonl(MODULE.P(str(run))["analysisGaps"])

            self.assertTrue(result["ok"])
            self.assertTrue(coverage["ready"])
            self.assertEqual(coverage["by_status"], {"analysis_gap": 1})
            self.assertEqual(gaps[0]["work_item_id"], task["work_item_id"])


if __name__ == "__main__":
    unittest.main()
