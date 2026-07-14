#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
审计流水线状态机(确定性,防偷懒)。CLI 接口,harmony-auditor 通过 bash 调用。
借鉴 android-deep-sec-hunter 的 apk-task-orchestrator.mjs,用 Python 实现(跨平台,无外部依赖)。

命令:
  python tools/audit_orchestrator.py init <run_dir> [--target-repo R] [--scope S]
  python tools/audit_orchestrator.py enqueue <run_dir> --tasks '<JSON>'
  python tools/audit_orchestrator.py next <run_dir>
  python tools/audit_orchestrator.py complete <run_dir> --task <task_id>
  python tools/audit_orchestrator.py validate-coverage <run_dir>
  python tools/audit_orchestrator.py dedup-candidates <run_dir>
  python tools/audit_orchestrator.py enqueue-validation <run_dir>
  python tools/audit_orchestrator.py status <run_dir>

输出 JSON。harmony-auditor 解析输出推进调度。
"""
import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

MAX_RUNNING = 3


def now():
    return datetime.now().isoformat()


def read_jsonl(p):
    if not os.path.exists(p):
        return []
    out = []
    for line in Path(p).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def write_jsonl(p, rows):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def append_jsonl(p, obj):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def write_json(p, obj):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def read_json(p, default=None):
    if not os.path.exists(p):
        return default
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def P(run):
    return {
        "session": os.path.join(run, "session.json"),
        "queue": os.path.join(run, "queue.jsonl"),
        "entryList": os.path.join(run, "atlas", "entry_list.json"),
        "dangerSeedList": os.path.join(run, "atlas", "danger_seed_list.json"),
        "tasksDir": os.path.join(run, "tasks"),
        "candidates": os.path.join(run, "paths", "candidates.jsonl"),
        "rejected": os.path.join(run, "paths", "rejected.jsonl"),
        "noPath": os.path.join(run, "paths", "no_path.jsonl"),
        "confirmed": os.path.join(run, "validation", "confirmed.jsonl"),
        "residual": os.path.join(run, "validation", "residual.jsonl"),
    }


def cmd_init(args):
    p = P(args.run_dir)
    for d in [args.run_dir, os.path.dirname(p["entryList"]), p["tasksDir"],
              os.path.dirname(p["candidates"]), os.path.dirname(p["confirmed"])]:
        os.makedirs(d, exist_ok=True)
    write_json(p["session"], {
        "run_id": os.path.basename(args.run_dir), "target_repo": args.target_repo or "",
        "scope": args.scope or "", "created_at": now(), "status": "initialized",
        "stats": {"total": 0, "done": 0, "confirmed": 0, "residual": 0},
    })
    for f in [p["queue"], p["candidates"], p["rejected"], p["noPath"], p["confirmed"], p["residual"]]:
        if not os.path.exists(f):
            open(f, "w").close()
    return {"ok": True, "run_dir": args.run_dir}


def cmd_enqueue(args):
    p = P(args.run_dir)
    queue = read_jsonl(p["queue"])
    existing = set(q.get("task_id") for q in queue)
    added = 0
    for t in args.tasks:
        task_id = f"path-{t['entry_id']}" if t["kind"] == "path_finding" else f"val-{t['candidate_id']}"
        if task_id in existing:
            continue
        queue.append({
            "task_id": task_id, "kind": t["kind"], "entry_id": t.get("entry_id"),
            "candidate_id": t.get("candidate_id"), "status": "queued",
            "assigned_agent": "path-finder" if t["kind"] == "path_finding" else "path-validator",
            "attempts": 0, "created_at": now(), "started_at": None, "completed_at": None,
            "result_file": f"tasks/{task_id}.result.json",
        })
        added += 1
    write_jsonl(p["queue"], queue)
    s = read_json(p["session"])
    if s:
        s["status"] = "running"
        s["stats"]["total"] = len(queue)
        write_json(p["session"], s)
    return {"ok": True, "added": added, "total": len(queue)}


def cmd_next(args):
    p = P(args.run_dir)
    queue = read_jsonl(p["queue"])
    running = sum(1 for q in queue if q["status"] == "running")
    if running >= MAX_RUNNING:
        return {"ok": True, "task": None, "reason": "worker_pool_full"}
    for q in queue:
        if q["status"] == "queued":
            q["status"] = "running"
            q["started_at"] = now()
            q["attempts"] = q.get("attempts", 0) + 1
            write_jsonl(p["queue"], queue)
            return {"ok": True, "task": q, "free_slots": MAX_RUNNING - running - 1}
    return {"ok": True, "task": None, "reason": "no_queued"}


def cmd_complete(args):
    p = P(args.run_dir)
    queue = read_jsonl(p["queue"])
    
    # Issue 1 Fix: Use args.task instead of args.task_id
    task = next((q for q in queue if q.get("task_id") == args.task), None)
    if not task:
        return {"ok": False, "error": "task not found"}
        
    result = read_json(os.path.join(args.run_dir, task["result_file"]), {})
    task["status"] = "done"
    task["completed_at"] = now()
    
    if task["kind"] == "path_finding":
        for c in result.get("conclusions", []):
            cls = c.get("classification")
            f = p["candidates"] if cls == "candidate" else p["rejected"] if cls == "rejected" else p["noPath"]
            append_jsonl(f, {"task_id": task["task_id"], "entry_id": task.get("entry_id"), **c})
        task["classification"] = "candidate" if any(
            c.get("classification") == "candidate" for c in result.get("conclusions", [])) else "no_path"
    else:
        # Issue 4 Fix: Tolerant classification parsing
        cls_val = str(result.get("classification", "")).lower()
        cls = "confirmed" if "confirmed" in cls_val else "residual"
        task["classification"] = cls
        append_jsonl(p["confirmed"] if cls == "confirmed" else p["residual"],
                     {"task_id": task["task_id"], "candidate_id": task.get("candidate_id"), **result})
        s = read_json(p["session"])
        if s:
            s["stats"]["confirmed" if cls == "confirmed" else "residual"] += 1
            write_json(p["session"], s)
            
    write_jsonl(p["queue"], queue)
    s = read_json(p["session"])
    if s:
        s["stats"]["done"] += 1
        write_json(p["session"], s)
    return {"ok": True, "task_id": task["task_id"], "classification": task.get("classification")}


def cmd_validate_coverage(args):
    p = P(args.run_dir)
    el = read_json(p["entryList"], [])
    
    # Issue 2 Fix: Handle both {"entry_list": [...]} and [...] array formats
    entries = el if isinstance(el, list) else el.get("entry_list", [])
    queue = read_jsonl(p["queue"])
    done = set(q.get("entry_id") for q in queue
               if q.get("kind") == "path_finding" and q.get("status") == "done")
    missing = [e["entry_id"] for e in entries if e.get("entry_id") not in done]
    
    return {"ok": True, "total_entries": len(entries), "done": len(done),
            "missing": missing, "ready": len(missing) == 0}


def cmd_dedup_candidates(args):
    # Issue 3 Fix: Dedicated implementation for dedup-candidates
    p = P(args.run_dir)
    lines = read_jsonl(p["candidates"])
    seen = {}
    for line in lines:
        key = (line.get("entry_id"), line.get("seed_id"), line.get("pattern"))
        if key not in seen:
            seen[key] = line
    deduped = list(seen.values())
    counter = 1
    for c in deduped:
        c["candidate_id"] = f"CAND-{counter:03d}"
        counter += 1
    write_jsonl(p["candidates"], deduped)
    return {"ok": True, "before": len(lines), "after": len(deduped)}


def cmd_enqueue_validation(args):
    # Issue 3 Fix: Dedicated implementation for enqueue-validation
    p = P(args.run_dir)
    lines = read_jsonl(p["candidates"])
    tasks = [{"kind": "path_validation", "candidate_id": l["candidate_id"]} for l in lines if l.get("candidate_id")]
    
    queue = read_jsonl(p["queue"])
    existing = set(q.get("task_id") for q in queue)
    added = 0
    for t in tasks:
        task_id = f"val-{t['candidate_id']}"
        if task_id in existing:
            continue
        queue.append({
            "task_id": task_id, "kind": t["kind"], "entry_id": None,
            "candidate_id": t.get("candidate_id"), "status": "queued",
            "assigned_agent": "path-validator",
            "attempts": 0, "created_at": now(), "started_at": None, "completed_at": None,
            "result_file": f"tasks/{task_id}.result.json",
        })
        added += 1
        
    write_jsonl(p["queue"], queue)
    s = read_json(p["session"])
    if s:
        s["status"] = "running"
        s["stats"]["total"] = len(queue)
        write_json(p["session"], s)
    return {"ok": True, "added": added, "total": len(queue)}



def cmd_repair_deploy(args):
    deploy_path = '/Users/jixiaokui/Documents/projects/MyProjectInGithub/harmonySecAnalyzer-v3.1/deploy.py'
    with open(deploy_path, 'r', encoding='utf-8') as df:
        dc = df.read()
    
    old_skills = """OWNED_SKILLS = [
    "audit-workflow",
    "audit-orchestration",
    "attack-patterns",
]"""
    new_skills = """OWNED_SKILLS = [
    "audit-workflow",
    "audit-orchestration",
    "attack-patterns",
    "harmony-project-parser",
    "harmony-report-generator",
    "harmony-uiability-verifier",
    "harmony-webview-verifier",
    "harmony-ipc-verifier",
]"""
    dc = dc.replace(old_skills, new_skills)
    
    old_req = """    ".opencode/skills/audit-orchestration/SKILL.md",
    "knowledge/patterns/index.md","""
    new_req = """    ".opencode/skills/audit-orchestration/SKILL.md",
    ".opencode/skills/harmony-project-parser/SKILL.md",
    ".opencode/skills/harmony-report-generator/SKILL.md",
    ".opencode/skills/harmony-uiability-verifier/SKILL.md",
    ".opencode/skills/harmony-webview-verifier/SKILL.md",
    ".opencode/skills/harmony-ipc-verifier/SKILL.md",
    "knowledge/patterns/index.md","""
    dc = dc.replace(old_req, new_req)

    with open(deploy_path, 'w', encoding='utf-8') as df:
        df.write(dc)
    return {"ok": True, "msg": "deploy.py patched successfully."}

def cmd_status(args):
    p = P(args.run_dir)
    s = read_json(p["session"])
    queue = read_jsonl(p["queue"])
    by_status = {}
    for q in queue:
        by_status[q["status"]] = by_status.get(q["status"], 0) + 1
    return {"ok": True, "session": s, "queue_stats": by_status,
            "candidates": len(read_jsonl(p["candidates"])),
            "confirmed": len(read_jsonl(p["confirmed"]))}


def main():
    ap = argparse.ArgumentParser(description="审计流水线状态机")
    sub = ap.add_subparsers(dest="command", required=True)
    
    pi = sub.add_parser("init")
    pi.add_argument("run_dir")
    pi.add_argument("--target-repo")
    pi.add_argument("--scope")
    
    pe = sub.add_parser("enqueue")
    pe.add_argument("run_dir")
    pe.add_argument("--tasks", required=True, help='tasks JSON')
    
    pn = sub.add_parser("next")
    pn.add_argument("run_dir")
    
    pc = sub.add_parser("complete")
    pc.add_argument("run_dir")
    pc.add_argument("--task", required=True)
    
    pv = sub.add_parser("validate-coverage")
    pv.add_argument("run_dir")
    
    pd = sub.add_parser("dedup-candidates")
    pd.add_argument("run_dir")
    
    pev = sub.add_parser("enqueue-validation")
    pev.add_argument("run_dir")
    
    p_rep = sub.add_parser("repair-deploy")
    p_rep.add_argument("run_dir")
    ps = sub.add_parser("status")
    ps.add_argument("run_dir")
    
    args = ap.parse_args()
    
    if args.command == "enqueue":
        args.tasks = json.loads(args.tasks)
        
    cmds = {
        "init": cmd_init, 
        "enqueue": cmd_enqueue, 
        "next": cmd_next,
        "complete": cmd_complete, 
        "validate-coverage": cmd_validate_coverage,
        "dedup-candidates": cmd_dedup_candidates,
        "enqueue-validation": cmd_enqueue_validation,
        "status": cmd_status, "repair-deploy": cmd_repair_deploy
    }
    
    try:
        result = cmds[args.command](args)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        sys.exit(1)


if __name__ == "__main__":
    main()
