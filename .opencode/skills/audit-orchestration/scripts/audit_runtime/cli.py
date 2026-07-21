"""Command-line interface for the flow-driven runtime."""
from __future__ import annotations

import argparse
import json
import sys

from .commands import *
from .reporting import build_report


def parser():
    root = argparse.ArgumentParser(description="Entry-driven HarmonyOS audit runtime")
    sub = root.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("new-run")
    cmd.add_argument("reports_root")
    cmd.add_argument("--target-repo", required=True)
    cmd.add_argument("--mode", choices=("full", "capability"), default="full")
    cmd.add_argument("--capability", action="append", default=[])
    cmd.add_argument("--component", action="append", default=[])
    cmd = sub.add_parser("init")
    cmd.add_argument("run_dir")
    cmd.add_argument("--project-model", required=True)
    cmd = sub.add_parser("claim")
    cmd.add_argument("run_dir")
    cmd.add_argument("--limit", type=int, default=5)
    cmd.add_argument("--worker", default="harmony-auditor")
    cmd = sub.add_parser("submit")
    cmd.add_argument("run_dir")
    cmd.add_argument("--task", required=True)
    cmd.add_argument("--input", required=True)
    cmd = sub.add_parser("fail")
    cmd.add_argument("run_dir")
    cmd.add_argument("--task", required=True)
    cmd.add_argument("--error", required=True)
    cmd.add_argument("--retryable", action="store_true")
    cmd.add_argument("--max-attempts", type=int, default=2)
    for name in ("validate-ready", "export", "build-report", "finalize", "status"):
        sub.add_parser(name).add_argument("run_dir")
    return root


def dispatch(args):
    if args.command == "new-run":
        return new_run(args.reports_root, args.target_repo, args.mode, args.capability, args.component)
    if args.command == "init": return initialize_run(args.run_dir, args.project_model)
    if args.command == "claim": return claim_tasks(args.run_dir, args.limit, args.worker)
    if args.command == "submit": return submit_result(args.run_dir, args.task, args.input)
    if args.command == "fail": return fail_task(args.run_dir, args.task, args.error, args.retryable, args.max_attempts)
    if args.command == "validate-ready": return readiness(args.run_dir)
    if args.command == "export": return export_state(args.run_dir)
    if args.command == "build-report": return {"ok": True, **build_report(args.run_dir)}
    if args.command == "finalize": return finalize_run(args.run_dir)
    if args.command == "status": return status(args.run_dir)
    raise ValueError(f"unknown_command:{args.command}")


def main(argv=None):
    try:
        result = dispatch(parser().parse_args(argv))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok", True) else 2
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
