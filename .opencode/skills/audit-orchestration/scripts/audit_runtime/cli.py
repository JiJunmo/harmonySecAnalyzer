"""Command-line interface for the flow-driven runtime."""
from __future__ import annotations

import argparse
import json
import sys

from .commands import *
from .initialization import prepare_run
from .scheduler import next_task, recover_tasks


def parser():
    root = argparse.ArgumentParser(description="Entry-driven HarmonyOS audit runtime")
    sub = root.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("prepare")
    cmd.add_argument("--target-repo", required=True)
    cmd.add_argument("--mode", choices=("full", "capability"), default="full")
    cmd.add_argument("--capability", action="append", default=[])
    cmd.add_argument("--component", action="append", default=[])
    cmd.add_argument("--atlas")
    cmd = sub.add_parser("next")
    cmd.add_argument("run_dir")
    cmd.add_argument("--worker", default="harmony-auditor")
    cmd = sub.add_parser("submit")
    cmd.add_argument("run_dir")
    cmd.add_argument("--task", required=True)
    cmd.add_argument("--input", required=True)
    cmd.add_argument("--attempt", required=True, type=int)
    cmd = sub.add_parser("fail")
    cmd.add_argument("run_dir")
    cmd.add_argument("--task", required=True)
    cmd.add_argument("--error", required=True)
    cmd.add_argument("--attempt", required=True, type=int)
    cmd.add_argument("--retryable", action="store_true")
    for name in ("recover", "validate-ready", "export", "build-report", "finalize", "status"):
        sub.add_parser(name).add_argument("run_dir")
    return root


def dispatch(args):
    if args.command == "prepare":
        return prepare_run(args.target_repo, args.mode, args.capability, args.component, args.atlas)
    if args.command == "next": return next_task(args.run_dir, args.worker)
    if args.command == "submit": return submit_result(args.run_dir, args.task, args.input, args.attempt)
    if args.command == "fail": return fail_task(args.run_dir, args.task, args.error, args.retryable, args.attempt)
    if args.command == "recover": return recover_tasks(args.run_dir)
    if args.command == "validate-ready": return readiness(args.run_dir)
    if args.command == "export": return export_state(args.run_dir)
    if args.command == "build-report": return build_report_ready(args.run_dir)
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
