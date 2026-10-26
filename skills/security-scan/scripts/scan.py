#!/usr/bin/env python3
"""Standalone entry point when the skill folder is copied to another machine."""
import sys

if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11 or newer is required. No scan was performed.")
from securityscan.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
