#!/usr/bin/env python3
"""Entry point for the flow-driven audit runtime."""
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from audit_runtime.cli import main


if __name__ == "__main__":
    sys.exit(main())
