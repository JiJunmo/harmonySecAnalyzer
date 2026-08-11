import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "resources/skills/audit-orchestration/scripts"
sys.path.insert(0, str(SCRIPTS))

from audit_runtime.common import SIX_EXPLOITABILITY_CHECKS, canonical_json, run_paths, write_json
from audit_runtime.commands import finalize_run, submit_result
from audit_runtime.incremental import (
    BASELINE_SCHEMA_VERSION, _entry_groups, audit_contract_hash, baseline_paths, file_manifest, git_state,
    plan_incremental,
)
from audit_runtime.lifecycle import initialize_run, new_run
from audit_runtime.reporting import build_report
from audit_runtime.scheduler import claim_batch
from audit_runtime.store import database


class IncrementalRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.target.mkdir()
        for module in ("entry", "feature"):
            source = self.target / module / "src/main/ets"
            source.mkdir(parents=True)
            (source / f"{module.title()}Ability.ets").write_text(
                f"export default class {module.title()}Ability {{}}\n", encoding="utf-8"
            )

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _component(module, index):
        module_id = f"MOD-{module}"
        component_id = f"CMP-{module}"
        name = f"{module.title()}Ability"
        return {
            "component_id": component_id, "module_id": module_id, "module_name": module,
            "module_root": module, "module_file": f"{module}/src/main/module.json5",
            "kind": "ability", "name": name, "src_entry": f"./ets/{name}.ets",
            "source_scope": f"{module}/src/main", "source_file_hint": f"{module}/src/main/ets/{name}.ets",
            "extension_type": None, "exported": True, "enabled": True, "permissions": [],
            "uri": None, "skills": [], "lifecycle_candidates": ["onCreate", "onNewWant"],
            "included_in_build": True,
        }

    def model(self, modules=("entry", "feature")):
        components = [self._component(module, index) for index, module in enumerate(modules)]
        module_rows = [{
            "module_id": f"MOD-{module}", "file": f"{module}/src/main/module.json5",
            "root": module, "name": module, "included_in_build": True,
            "component_ids": [f"CMP-{module}"], "dependency_ids": [],
        } for module in modules]
        candidates = []
        for component in components:
            for kind in ("component_scope", "exported_component"):
                candidates.append({
                    "candidate_id": f"PE-{component['module_name']}-{kind}", "type": kind,
                    "source": "manifest", "component_id": component["component_id"],
                    "component_name": component["name"], "module_id": component["module_id"],
                    "module_name": component["module_name"], "module_root": component["module_root"],
                    "location": component["module_file"], "exported": True, "permissions": [],
                    "src_entry": component["src_entry"], "lifecycle_candidates": ["onCreate"],
                    "trigger_facts": {"component_scope": True} if kind == "component_scope" else {"exported": True},
                })
        return {
            "schema_version": 2, "status": "complete", "target_repo": str(self.target),
            "application": {"bundle_name": "com.example.incremental"},
            "summary": {"modules": len(module_rows), "components": len(components), "entry_candidates": len(candidates)},
            "modules": module_rows, "components": components, "entry_candidates": candidates,
            "module_dependencies": [], "diagnostics": [],
        }

    @staticmethod
    def source_evidence(summary="entry reaches protected query", location="EntryAbility.ets:42"):
        return {"kind": "atlas_trace", "source": "atlas", "summary": summary, "location": location}

    @staticmethod
    def verification_evidence(summary="verified query construction", location="EntryAbility.ets:44"):
        return {"kind": "source_read", "source": "validator", "summary": summary, "location": location}

    @staticmethod
    def evidence_support(group, verification=None):
        return {
            "semantic_refs": [row["evidence_id"] for row in group["evidence_scope"]["admissible"]],
            "verification": list(verification or []),
        }

    @staticmethod
    def semantic_result(entry_id, task_id, symbol, external_candidate_id):
        return {
            "task_id": task_id, "entry_id": entry_id, "summary": "组件未发现安全相关操作",
            "coverage": {
                "entry_status": "confirmed", "external_entry_status": "confirmed",
                "confirmed_external_candidate_ids": [external_candidate_id],
                "entry_notes": ["入口已确认"],
                "entry_symbols_checked": [symbol], "operation_sites_checked": [], "unresolved_targets": [],
            },
            "operation_groups": [], "component_calls": [],
        }

    def write_baseline(self, model, source_type="snapshot", git=None, semantic_overrides=None):
        entries = _entry_groups(model)
        semantics = {}
        for index, (entry_key, entry) in enumerate(sorted(entries.items())):
            entry_id = f"OLD-ENTRY-{index}"
            external_candidate_id = next(
                row["candidate_id"] for row in entry["candidates"]
                if row.get("type") != "component_scope"
            )
            result = self.semantic_result(
                entry_id, f"OLD-TASK-{index}", f"{entry['component_id']}.onCreate",
                external_candidate_id,
            )
            semantics[entry_key] = {"entry_id": entry_id, "result": result}
        semantics.update(semantic_overrides or {})
        paths = baseline_paths(self.target)
        paths["root"].mkdir(parents=True, exist_ok=True)
        write_json(paths["project_model"], model)
        write_json(paths["semantic_results"], semantics)
        write_json(paths["validation_results"], {"schema_version": 1, "entries": {}})
        write_json(paths["findings"], {"schema_version": 1, "items": []})
        write_json(paths["metadata"], {
            "schema_version": BASELINE_SCHEMA_VERSION, "run_id": "RUN-BASELINE",
            "completed_at": "2026-01-01T00:00:00Z", "source_type": source_type,
            "git": git, "file_manifest": file_manifest(self.target), "semantic_results": len(semantics),
            "audit_contract_hash": audit_contract_hash(),
        })
        return semantics

    def test_snapshot_change_reaudits_one_module_and_reuses_the_other(self):
        model = self.model()
        semantics = self.write_baseline(model)
        changed = self.target / "entry/src/main/ets/EntryAbility.ets"
        changed.write_text("export default class EntryAbility { changed = true }\n", encoding="utf-8")

        plan = plan_incremental(self.target, model)
        entries = _entry_groups(model)
        entry_key = next(key for key, row in entries.items() if row["module_id"] == "MOD-entry")
        feature_key = next(key for key, row in entries.items() if row["module_id"] == "MOD-feature")
        self.assertIn(entry_key, plan["impact_plan"]["affected_entries"])
        self.assertIn(feature_key, plan["impact_plan"]["reusable_entries"])

        allocated = new_run(self.target / "reports", self.target, "incremental")
        run = Path(allocated["run_dir"])
        paths = run_paths(run)
        write_json(paths["project_model"], model)
        write_json(paths["change_set"], plan["change_set"])
        write_json(paths["impact_plan"], plan["impact_plan"])
        write_json(paths["baseline_semantics"], semantics)
        write_json(paths["baseline_findings"], {
            "schema_version": 1, "items": [{"finding_id": "FIND-REMOVED", "title": "已消失风险"}],
        })
        initialized = initialize_run(run, paths["project_model"])
        self.assertEqual(len(initialized["task_ids"]), 1)
        self.assertEqual(initialized["reused_semantic_analyses"], 1)
        with database(paths["db"]) as conn:
            counts = {row["status"]: row["n"] for row in conn.execute(
                "SELECT status,COUNT(*) n FROM tasks GROUP BY status"
            )}
            self.assertEqual(counts, {"completed": 1, "queued": 1})
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM semantic_analyses").fetchone()["n"], 1)
            conn.execute("UPDATE tasks SET status='completed'")
            conn.execute("UPDATE runs SET correlation_status='complete'")
        build_report(run, live=True)
        report = json.loads(paths["report_model"].read_text(encoding="utf-8"))
        changes = report["run"]["incremental"]["risk_path_changes"]
        self.assertEqual(changes["status"], "complete")
        self.assertEqual([row["finding_id"] for row in changes["removed"]], ["FIND-REMOVED"])

    def test_added_component_and_manifest_change_do_not_reaudit_existing_components(self):
        previous = self.model(("entry",))
        self.write_baseline(previous)

        existing = previous["components"][0]
        added = self._component("entry", 1)
        added["component_id"] = "CMP-entry-cache-cleanup"
        added["name"] = "CacheCleanupAbility"
        added["src_entry"] = "./ets/CacheCleanupAbility.ets"
        added["source_file_hint"] = "entry/src/main/ets/CacheCleanupAbility.ets"
        current = json.loads(json.dumps(previous))
        current["components"].append(added)
        current["modules"][0]["component_ids"].append(added["component_id"])
        current["summary"]["components"] += 1
        for kind in ("component_scope", "exported_component"):
            current["entry_candidates"].append({
                "candidate_id": f"PE-cache-{kind}", "type": kind, "source": "manifest",
                "component_id": added["component_id"], "component_name": added["name"],
                "module_id": added["module_id"], "module_name": added["module_name"],
                "module_root": added["module_root"], "location": added["module_file"],
                "exported": True, "permissions": [], "src_entry": added["src_entry"],
                "lifecycle_candidates": ["onCreate"],
                "trigger_facts": {"component_scope": True} if kind == "component_scope" else {"exported": True},
            })
        current["summary"]["entry_candidates"] += 2

        manifest = self.target / "entry/src/main/module.json5"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text("{ module: { abilities: ['CacheCleanupAbility'] } }\n", encoding="utf-8")
        source = self.target / added["source_file_hint"]
        source.write_text("export default class CacheCleanupAbility {}\n", encoding="utf-8")

        plan = plan_incremental(self.target, current)
        entries = _entry_groups(current)
        existing_key = next(key for key, row in entries.items() if row["component_id"] == existing["component_id"])
        added_key = next(key for key, row in entries.items() if row["component_id"] == added["component_id"])
        self.assertEqual(plan["impact_plan"]["affected_entries"], [added_key])
        self.assertIn(existing_key, plan["impact_plan"]["reusable_entries"])
        self.assertEqual(plan["impact_plan"]["affected_modules"], [])
        self.assertEqual(plan["impact_plan"]["affected_components"], [added["component_id"]])

    def test_shared_source_change_still_reaudits_the_module(self):
        model = self.model()
        self.write_baseline(model)
        shared = self.target / "entry/src/main/ets/SharedSecurityPolicy.ets"
        shared.write_text("export const allow = false\n", encoding="utf-8")

        plan = plan_incremental(self.target, model)
        entry_key = next(
            key for key, row in _entry_groups(model).items()
            if row["module_id"] == "MOD-entry"
        )
        self.assertIn(entry_key, plan["impact_plan"]["affected_entries"])
        self.assertEqual(plan["impact_plan"]["affected_modules"], ["MOD-entry"])

    def test_module_level_manifest_change_reaudits_the_module(self):
        previous = self.model()
        self.write_baseline(previous)
        current = json.loads(json.dumps(previous))
        current["modules"][0]["request_permissions"] = [{"name": "ohos.permission.INTERNET"}]
        manifest = self.target / "entry/src/main/module.json5"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text("{ module: { requestPermissions: ['ohos.permission.INTERNET'] } }\n", encoding="utf-8")

        plan = plan_incremental(self.target, current)
        entry_key = next(
            key for key, row in _entry_groups(current).items()
            if row["module_id"] == "MOD-entry"
        )
        self.assertIn(entry_key, plan["impact_plan"]["affected_entries"])
        self.assertEqual(plan["impact_plan"]["affected_modules"], ["MOD-entry"])

    def test_successful_full_run_creates_a_readable_incremental_baseline(self):
        model = self.model()
        model_path = self.root / "full-model.json"
        write_json(model_path, model)
        allocated = new_run(self.target / "reports", self.target, "full")
        run = Path(allocated["run_dir"])
        initialize_run(run, model_path)
        batch = claim_batch(run, 5)
        self.assertEqual(batch["count"], 2)
        for handle in batch["tasks"]:
            task = json.loads(Path(handle["task_file"]).read_text(encoding="utf-8"))
            external_candidate_id = next(
                row["candidate_id"] for row in task["input"]["entry"]["project_candidates"]
                if row.get("type") != "component_scope"
            )
            result = self.semantic_result(
                task["subject_id"], task["task_id"], task["input"]["entry"]["symbol"],
                external_candidate_id,
            )
            submission = Path(handle["submission_file"])
            submission.write_text(json.dumps(result), encoding="utf-8")
            accepted = submit_result(run, task["task_id"], submission, task["attempt"])
            self.assertTrue(accepted["accepted"], accepted)
        self.assertEqual(claim_batch(run, 5)["reason"], "no_queued")
        finalized = finalize_run(run)
        self.assertTrue(finalized["baseline"]["updated"], finalized)
        self.assertTrue(baseline_paths(self.target)["metadata"].is_file())
        plan = plan_incremental(self.target, model)
        self.assertEqual(plan["impact_plan"]["affected_entries"], [])
        self.assertEqual(len(plan["impact_plan"]["reusable_entries"]), 2)

    def test_unchanged_validation_is_reused_without_dispatching_an_agent(self):
        model = self.model(("entry",))
        model_path = self.root / "validation-model.json"
        write_json(model_path, model)
        full = Path(new_run(self.target / "reports", self.target, "full")["run_dir"])
        initialize_run(full, model_path)

        semantic_handle = claim_batch(full, 5)["tasks"][0]
        semantic_task = json.loads(Path(semantic_handle["task_file"]).read_text(encoding="utf-8"))
        source_evidence = [self.source_evidence()]
        group = {
            "group_key": "protected-query", "category": "data_access",
            "capability_id": "CAP-PROVIDER-001", "title": "受保护的数据查询",
            "operation": {"body": "query private records", "location": "EntryAbility.ets:42",
                          "evidence": source_evidence},
            "controlled_properties": ["want.parameters.recordId"],
            "context": {
                "external_actor": "third-party application", "intended_behavior": "query one record",
                "protected_assets": ["private records"], "direct_observed_effect": "record is returned",
                "effect_hypotheses": [],
                "evidence": source_evidence,
            },
            "branches": [{
                "condition": "action == query", "locations": ["EntryAbility.ets:20"],
                "evidence": source_evidence,
            }],
            "facts": [
                {"fact_key": "entry", "type": "entrypoint", "body": "external Want",
                 "location": "EntryAbility.ets:10", "evidence": source_evidence},
                {"fact_key": "operation", "type": "operation", "body": "query private records",
                 "location": "EntryAbility.ets:42", "evidence": source_evidence},
            ],
            "security_checks": [{
                "type": "owner check", "location": "EntryAbility.ets:35",
                "protects": "private records", "subject_kind": "origin_principal",
                "validated_property": "record owner", "behavior": "rejects another owner",
                "evidence": source_evidence,
            }],
        }
        semantic = self.semantic_result(
            semantic_task["subject_id"], semantic_task["task_id"], "EntryAbility.onCreate",
            "PE-entry-exported_component",
        )
        semantic["operation_groups"] = [group]
        semantic["coverage"]["operation_sites_checked"] = ["EntryAbility.ets:42"]
        semantic_submission = Path(semantic_handle["submission_file"])
        semantic_submission.write_text(json.dumps(semantic), encoding="utf-8")
        semantic_accepted = submit_result(
            full, semantic_task["task_id"], semantic_submission, semantic_task["attempt"]
        )
        self.assertTrue(semantic_accepted["accepted"], semantic_accepted)

        validation_handle = claim_batch(full, 5)["tasks"][0]
        validation_task = json.loads(Path(validation_handle["task_file"]).read_text(encoding="utf-8"))
        persisted_group = validation_task["input"]["semantic_analysis"]["operation_groups"][0]
        evidence = self.evidence_support(persisted_group)
        checks = {name: {
            "status": "false" if name in {"security_check_bypassed_or_absent", "boundary_violated", "concrete_impact"} else "true",
            "reason": "所有者校验阻止越权" if name in {"security_check_bypassed_or_absent", "boundary_violated", "concrete_impact"} else "源码事实已确认",
            "evidence_level": "direct", "evidence": evidence,
        } for name in SIX_EXPLOITABILITY_CHECKS}
        validation = {
            "group_id": persisted_group["group_id"], "capability_id": "CAP-PROVIDER-001",
            "classification": "protected_exposure", "title": "所有者校验有效",
            "security_check_outcome": "effective",
            "business_intent": {
                "is_public_api": True, "declared_or_inferred_purpose": "query one owned record",
                "allowed_controls": ["recordId"], "evidence": evidence,
            },
            "security_boundary": {
                "type": "data_owner", "expected_boundary": "only the owner may query the record",
                "reason": "owner check rejects another caller",
                "evidence": evidence,
            },
            "exploitability": checks,
            "counter_evidence": [{
                "kind": "effective_security_check", "reason": "owner check dominates the query",
                "evidence": evidence,
            }],
            "demotion_reason": "owner check prevents unauthorized access",
            "evidence": evidence,
        }
        validation_result = {
            "task_id": validation_task["task_id"], "entry_id": validation_task["subject_id"],
            "summary": "六维验证完成", "validations": [validation],
        }
        validation_submission = Path(validation_handle["submission_file"])
        validation_submission.write_text(json.dumps(validation_result), encoding="utf-8")
        accepted = submit_result(
            full, validation_task["task_id"], validation_submission, validation_task["attempt"]
        )
        self.assertTrue(accepted["accepted"], accepted)
        self.assertTrue(finalize_run(full)["baseline"]["updated"])

        plan = plan_incremental(self.target, model)
        incremental = Path(new_run(self.target / "reports", self.target, "incremental")["run_dir"])
        paths = run_paths(incremental)
        write_json(paths["project_model"], model)
        write_json(paths["change_set"], plan["change_set"])
        write_json(paths["impact_plan"], plan["impact_plan"])
        write_json(paths["baseline_semantics"], plan["baseline"]["semantic_results"])
        write_json(paths["baseline_validations"], plan["baseline"]["validation_results"])
        write_json(paths["baseline_findings"], {"schema_version": 1, "items": []})
        initialized = initialize_run(incremental, paths["project_model"])
        self.assertEqual(initialized["task_ids"], [])
        self.assertEqual(claim_batch(incremental, 5)["count"], 0)
        with database(paths["db"]) as conn:
            validation_task_row = conn.execute(
                "SELECT status,attempts FROM tasks WHERE kind='exploitability_validation'"
            ).fetchone()
            self.assertEqual(dict(validation_task_row), {"status": "completed", "attempts": 0})
            self.assertEqual(conn.execute("SELECT COUNT(*) n FROM validation_results").fetchone()["n"], 1)

    def test_deleted_component_invalidates_its_historical_caller(self):
        previous = self.model()
        entries = _entry_groups(previous)
        entry_key = next(key for key, row in entries.items() if row["module_id"] == "MOD-entry")
        semantics = self.write_baseline(previous)
        semantics[entry_key]["result"]["component_calls"] = [{"target_component_id": "CMP-feature"}]
        write_json(baseline_paths(self.target)["semantic_results"], semantics)

        current = self.model(("entry",))
        plan = plan_incremental(self.target, current)
        self.assertEqual(len(plan["impact_plan"]["deleted_entries"]), 1)
        self.assertIn(entry_key, plan["impact_plan"]["affected_entries"])
        self.assertIn("called_component_deleted", plan["impact_plan"]["reasons"][entry_key])

    def test_git_change_range_spans_multiple_commits_and_worktree(self):
        subprocess.run(["git", "init"], cwd=self.target, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "incremental@example.com"], cwd=self.target, check=True)
        subprocess.run(["git", "config", "user.name", "Incremental Test"], cwd=self.target, check=True)
        subprocess.run(["git", "add", "."], cwd=self.target, check=True)
        subprocess.run(["git", "commit", "-m", "baseline"], cwd=self.target, check=True, capture_output=True)
        base_git = git_state(self.target)
        self.write_baseline(self.model(), "git", base_git)

        source = self.target / "entry/src/main/ets/EntryAbility.ets"
        source.write_text("export default class EntryAbility { first = true }\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.target, check=True)
        subprocess.run(["git", "commit", "-m", "first"], cwd=self.target, check=True, capture_output=True)
        source.write_text("export default class EntryAbility { second = true }\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.target, check=True)
        subprocess.run(["git", "commit", "-m", "second"], cwd=self.target, check=True, capture_output=True)
        worktree = self.target / "feature/src/main/ets/FeatureAbility.ets"
        worktree.write_text("export default class FeatureAbility { dirty = true }\n", encoding="utf-8")

        plan = plan_incremental(self.target, self.model())
        git_range = plan["change_set"]["git"]
        self.assertEqual(git_range["base_commit"], base_git["commit"])
        self.assertEqual(git_range["target_commit"], git_state(self.target)["commit"])
        self.assertGreaterEqual(len(git_range["commit_changes"]), 1)
        self.assertTrue(plan["change_set"]["working_tree_dirty"])
        self.assertIn("feature/src/main/ets/FeatureAbility.ets", plan["change_set"]["files"]["modified"])


if __name__ == "__main__":
    unittest.main()
