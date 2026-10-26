"""Portable skill packaging check; the full behavioral tests live at repo root."""
import ast
import subprocess
import sys
import unittest
from pathlib import Path

skill = Path(__file__).resolve().parents[1]
required = ["SKILL.md", "scripts/scan.py", "references/audit-prompt.md",
            "references/remediation-prompt.md", "references/sources.md", "references/sources.json"]
for name in required:
    assert (skill / name).is_file(), name
for source in (skill / "scripts").rglob("*.py"):
    ast.parse(source.read_text(), filename=str(source))
result = subprocess.run([sys.executable, str(skill / "scripts/scan.py"), "--help"],
                        capture_output=True, text=True, timeout=10)
assert result.returncode == 0, result.stderr
assert "--query-packages" in result.stdout
tests = skill.parents[1] / "tests"
if tests.is_dir():
    assert unittest.defaultTestLoader.discover(str(tests)).countTestCases() > 0, "No behavioral tests discovered"
print("PASS: self-contained skill, valid Python, working command entry point")
