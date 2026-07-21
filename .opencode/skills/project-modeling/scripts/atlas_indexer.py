#!/usr/bin/env python3
"""Prepare a complete Atlas full-analysis index before MCP-based auditing."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def write_json_atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def run_streaming(command):
    lines = []
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if process.stdout:
        for line in process.stdout:
            sys.stderr.write(line)
            sys.stderr.flush()
            lines.append(line.rstrip())
            if len(lines) > 200:
                lines.pop(0)
    return process.wait(), lines


def indexed_file_count(status_output):
    match = re.search(r"Files indexed:\s+(\d+)", status_output)
    return int(match.group(1)) if match else None


def prepare_index(target_repo, output, atlas=None, force_index=False):
    root = Path(target_repo).expanduser().resolve()
    executable = Path(atlas or shutil.which("atlas") or "").expanduser()
    database = root / ".atlas" / "atlas.db"
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()

    if not root.is_dir():
        result = {"ok": False, "error": "target_repo_not_found", "target_repo": str(root)}
        write_json_atomic(output, result)
        return result
    if not executable.is_file() or not os.access(executable, os.X_OK):
        result = {"ok": False, "error": "atlas_executable_not_found", "atlas": str(executable)}
        write_json_atomic(output, result)
        return result

    action = "index" if force_index or not database.is_file() else "sync"
    command = [
        str(executable),
        action,
        "--project",
        str(root),
        "--analysis",
        "full",
    ]
    returncode, output_tail = run_streaming(command)

    status = subprocess.run(
        [str(executable), "status", "--project", str(root)],
        capture_output=True,
        text=True,
    )
    status_text = "\n".join(part for part in (status.stdout, status.stderr) if part)
    status_summary = status_text.split("Indexed files:", 1)[0].strip()
    files_indexed = indexed_file_count(status_text)
    ready = (
        returncode == 0
        and status.returncode == 0
        and database.is_file()
        and isinstance(files_indexed, int)
        and files_indexed > 0
    )
    result = {
        "ok": ready,
        "status": "ready" if ready else "failed",
        "action": action,
        "analysis": "full",
        "target_repo": str(root),
        "atlas": str(executable.resolve()),
        "database": str(database),
        "files_indexed": files_indexed,
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.monotonic() - started, 3),
        "command_returncode": returncode,
        "status_returncode": status.returncode,
        "output_tail": output_tail,
        "status_summary": status_summary,
    }
    if not ready:
        result["error"] = "atlas_index_not_ready"
    write_json_atomic(output, result)
    return result


def main():
    parser = argparse.ArgumentParser(description="Build or sync an Atlas full-analysis index")
    parser.add_argument("target_repo")
    parser.add_argument("--output", required=True)
    parser.add_argument("--atlas")
    parser.add_argument("--force-index", action="store_true")
    args = parser.parse_args()

    result = prepare_index(
        args.target_repo,
        args.output,
        atlas=args.atlas,
        force_index=args.force_index,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result.get("ok"):
        sys.exit(1)


if __name__ == "__main__":
    main()
