"""Inspect explicit project roots without executing project code or installers."""
import json
import os
import re
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

from .common import ASSIGNMENT, TOKEN_PATTERNS, finding, gap
from .fileio import bounded_read

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next",
             "dist", "build", ".cache", ".tox", ".mypy_cache", ".pytest_cache"}
PACKAGE_NAME = re.compile(r"(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_.-]+\Z")
VERSION = re.compile(r"\d{1,9}(?:\.\d{1,9}){1,3}(?:[-+._]?[A-Za-z][0-9A-Za-z.+_-]{0,60})?\Z")
PIN = re.compile(r"([A-Za-z0-9_.-]+)(?:\[[^]]+\])?==([^\s;]+)(?:\s*;.*)?\Z")


def add_package(report, ecosystem, name, version, location, direct=None):
    if not isinstance(name, str) or not isinstance(version, str):
        gap(report, f"A dependency lacks an exact supported name/version at {location}.", incomplete=True)
        return
    if (not PACKAGE_NAME.fullmatch(name) or not VERSION.fullmatch(version)
            or any(p.search(name) or p.search(version) for p in TOKEN_PATTERNS)):
        gap(report, f"Unresolved, URL-based or unsupported dependency at {location} was not queried.")
        return
    if ecosystem == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()
    report["packages"].append({"ecosystem": ecosystem, "name": name, "version": version,
                               "location": location, "direct": direct,
                               "evidence_type": "file_pin_not_proof_of_running_code"})


def npm_lock(report, data, location):
    if not isinstance(data, dict):
        raise ValueError("invalid npm lock")
    if isinstance(data.get("packages"), dict):
        root = data["packages"].get("", {})
        if not isinstance(root, dict):
            raise ValueError("npm root package metadata is malformed")
        direct = set(root.get("dependencies", {})) | set(root.get("devDependencies", {}))
        for path, item in data["packages"].items():
            if not path or not isinstance(item, dict) or item.get("link"):
                continue
            resolved = item.get("resolved")
            if resolved and (not isinstance(resolved, str) or urlsplit(resolved).scheme != "https" or urlsplit(resolved).hostname != "registry.npmjs.org"):
                gap(report, f"Non-public or unsupported npm source at {location} was not mapped to the public registry.")
                continue
            name = item.get("name") or path.rsplit("node_modules/", 1)[-1]
            add_package(report, "npm", name, item.get("version"), location, name in direct)
    elif isinstance(data.get("dependencies"), dict):
        pending = [(data["dependencies"], True)]
        while pending:
            items, direct = pending.pop()
            for name, item in items.items():
                if not isinstance(item, dict):
                    continue
                if isinstance(item.get("dependencies"), dict):
                    pending.append((item["dependencies"], False))
                resolved = item.get("resolved")
                if resolved and (not isinstance(resolved, str) or urlsplit(resolved).scheme != "https" or urlsplit(resolved).hostname != "registry.npmjs.org"):
                    gap(report, f"Non-public or unsupported npm source at {location} was not mapped to the public registry.")
                    continue
                add_package(report, "npm", name, item.get("version"), location, direct)
    else:
        gap(report, f"No supported resolved package inventory found in {location}.")


def inventory_file(report, path, text, location):
    name = path.name
    if name == "package-lock.json":
        npm_lock(report, json.loads(text), location)
    elif name in {"poetry.lock", "uv.lock"}:
        data = tomllib.loads(text)
        packages = data.get("package", [])
        if not isinstance(packages, list):
            raise ValueError("invalid Python lock package list")
        for item in packages:
            if isinstance(item, dict):
                source = item.get("source")
                if name == "uv.lock":
                    public = isinstance(source, dict) and set(source) == {"registry"} and source["registry"] in {"https://pypi.org/simple", "https://pypi.org/simple/"}
                else:
                    public = source is None or (isinstance(source, dict) and source.get("type") in {"legacy", "index"} and source.get("url") in {"https://pypi.org/simple", "https://pypi.org/simple/"})
                if not public:
                    gap(report, f"Git, path, editable, private-registry or unknown Python source in {location} was not mapped to PyPI.")
                    continue
                add_package(report, "PyPI", item.get("name"), item.get("version"), location)
    elif name.startswith("requirements") and name.endswith(".txt"):
        if re.search(r"(?m)^\s*(?:--(?:extra-)?index-url\b|--find-links\b|--no-index\b|-i|-f)", text):
            gap(report, f"Custom package source directives in {location} prevent public-registry mapping; file pins were not queried.")
            return
        for line in text.splitlines():
            line = line.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            match = PIN.fullmatch(line)
            if match:
                add_package(report, "PyPI", *match.groups(), location, True)
            else:
                gap(report, f"Non-exact requirement, include or option in {location} was not resolved.")
    elif name in {"yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "composer.lock", "Cargo.lock", "go.sum"}:
        gap(report, f"Lock format {name} is not supported by this release: {location}.")
    elif name in {"package.json", "pyproject.toml"}:
        report["coverage"]["manifests"].append(location)


def looks_like_credential(value):
    value = value.strip().strip("\"'")
    if len(value) < 8 or value.startswith(("#", "$", "<", "${")):
        return False
    lower = value.lower()
    return not any(x in lower for x in ("placeholder", "your_", "your-", "example", "insert_", "changeme"))


def scan_text(report, path, text, location):
    env_file = path.name.endswith(".env") or path.name.startswith(".env")
    for number, line in enumerate(text.splitlines(), 1):
        kinds = []
        if any(pattern.search(line) for pattern in TOKEN_PATTERNS):
            kinds.append("recognized credential pattern")
        if env_file:
            match = ASSIGNMENT.match(line)
            if match and re.search("KEY|TOKEN|PASSWORD|SECRET", match[1], re.I) and looks_like_credential(match[2]):
                kinds.append("non-placeholder env credential assignment")
        if kinds:
            # Neither the matched value nor the source line enters the report.
            finding(report, "potential-secret", f"{location}:{number}",
                    {"location": location, "line": number, "pattern_types": kinds},
                    confidence="pattern_match_requires_local_review")


def collect_projects(report, roots, budget, max_files=5000, max_bytes=1_000_000):
    coverage = report["coverage"]
    coverage.update({"files_read": 0, "symlinks_skipped": 0, "large_files_skipped": 0,
                     "binary_files_skipped": 0, "manifests": [], "roots_completed": 0})
    stop = False
    for index, root in enumerate(roots, 1):
        label = f"project-{index}"
        def failed_walk(_error):
            gap(report, f"Unreadable directory in {label}; traversal incomplete.", incomplete=True)
        for base, dirs, names in os.walk(root, followlinks=False, onerror=failed_walk):
            kept = []
            for name in sorted(dirs):
                candidate = Path(base) / name
                if candidate.is_symlink():
                    coverage["symlinks_skipped"] += 1
                elif name not in SKIP_DIRS:
                    kept.append(name)
            dirs[:] = kept
            for name in sorted(names):
                if coverage["files_read"] >= max_files or budget.remaining() <= 0:
                    gap(report, "Project traversal reached its file or time budget; files remain unchecked.", incomplete=True)
                    stop = True
                    break
                path = Path(base) / name
                if path.is_symlink():
                    coverage["symlinks_skipped"] += 1
                    continue
                location = label + "/" + str(path.relative_to(root)).replace(os.sep, "/")
                try:
                    raw, read_status = bounded_read(root, path.relative_to(root), max_bytes)
                    if read_status == "special":
                        gap(report, f"Special non-regular file was not inspected: {location}.")
                        continue
                    if read_status == "large":
                        coverage["large_files_skipped"] += 1
                        gap(report, f"File over the byte limit was not inspected: {location}.", incomplete=True)
                        continue
                    if read_status == "growing":
                        gap(report, f"Growing file exceeded the byte limit: {location}.", incomplete=True)
                        continue
                    coverage["files_read"] += 1
                    if b"\x00" in raw:
                        coverage["binary_files_skipped"] += 1
                        continue
                    text = raw.decode("utf-8")
                    scan_text(report, path, text, location)
                    inventory_file(report, path, text, location)
                except UnicodeError:
                    coverage["binary_files_skipped"] += 1
                except (OSError, ValueError, TypeError, AttributeError, RecursionError):
                    gap(report, f"Unreadable or malformed input was not fully inspected: {location}.", incomplete=True)
            if stop:
                break
        if stop:
            break
        coverage["roots_completed"] += 1
    if coverage["symlinks_skipped"]:
        gap(report, "Symlink files/directories were not followed; their targets are outside coverage.")
    for manifest in coverage["manifests"]:
        directory = manifest.rsplit("/", 1)[0]
        if not any(row["location"].rsplit("/", 1)[0] == directory for row in report["packages"]):
            gap(report, f"No supported exact package pins were collected for manifest {manifest}.")
    gap(report, "Git history, ignored dependency trees, binary contents and unselected directories were not scanned.")
