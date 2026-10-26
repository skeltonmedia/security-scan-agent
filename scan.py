#!/usr/bin/env python3
"""Run the bundled scanner without installing a package."""
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11 or newer is required. No scan was performed.")
sys.path.insert(0, str(Path(__file__).resolve().parent / "skills/security-scan/scripts"))
from securityscan.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
