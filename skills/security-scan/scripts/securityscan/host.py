"""Bounded host checks. Never run a project script or an executable from its PATH."""
import platform
import plistlib
import re
import subprocess
from pathlib import Path

from .common import finding, gap


def command(args, budget):
    if budget.remaining() <= 0:
        return None
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=min(8, budget.remaining()),
                                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def listeners(text):
    rows = []
    for line in (text or "").splitlines()[1:]:
        fields = line.split()
        if len(fields) < 9:
            continue
        address = fields[-2] if fields[-1] == "(LISTEN)" else fields[-1]
        match = re.search(r":(\d+)$", address)
        if not match:
            continue
        scope = ("all_interfaces" if address.startswith("*:") else
                 "loopback" if address.startswith(("127.", "[::1]:")) else "other_interface")
        row = {"process": fields[0], "port": int(match[1]), "scope": scope}
        if row not in rows:
            rows.append(row)
    return rows


def collect_host(report, budget):
    system = platform.system()
    report["host"] = {"system": system, "architecture": platform.machine(),
                      "controls": {}, "software": [], "listeners": []}
    host = report["host"]
    for binary in ["/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node"]:
        if Path(binary).is_file():
            output = command([binary, "--version"], budget)
            if output and re.fullmatch(r"v\d+\.\d+\.\d+", output):
                host["software"].append({"product": "node", "version": output[1:], "location": binary})
            else:
                gap(report, "An installed runtime version could not be read.")
    if system != "Darwin":
        gap(report, "Detailed firewall, disk-encryption and app checks are currently macOS-only; this host is partially covered.")
        return
    host["os_version"] = command(["/usr/bin/sw_vers", "-productVersion"], budget) or "unknown"
    checks = {
        "firewall": (["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], "enabled", "disabled"),
        "filevault": (["/usr/bin/fdesetup", "status"], "FileVault is On", "FileVault is Off"),
        "gatekeeper": (["/usr/sbin/spctl", "--status"], "assessments enabled", "assessments disabled"),
        "sip": (["/usr/bin/csrutil", "status"], "enabled", "disabled"),
    }
    for name, (args, enabled, disabled) in checks.items():
        output = command(args, budget)
        status = "unknown" if output is None else (
            "disabled" if disabled in output else "enabled" if enabled in output else "unknown")
        host["controls"][name] = status
        if status == "unknown":
            gap(report, f"Host control {name} could not be verified; unavailable is not disabled.")
    if host["controls"]["firewall"] == "disabled":
        finding(report, "firewall-disabled", "host/application-firewall", {"status": "disabled"})
    for app, product in [("Google Chrome.app", "chrome-mac"), ("Plex Media Server.app", "plex-mac")]:
        path = Path("/Applications") / app / "Contents/Info.plist"
        if path.is_file():
            try:
                data = plistlib.loads(path.read_bytes())
                version = data.get("CFBundleVersion") if product == "plex-mac" else data.get("CFBundleShortVersionString")
                if isinstance(version, str):
                    host["software"].append({"product": product, "version": version, "location": str(path.parents[1])})
            except (OSError, ValueError):
                gap(report, f"Installed application metadata could not be read: {product}.")
    output = command(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], budget)
    host["listeners"] = listeners(output)
    if output is None:
        gap(report, "TCP listeners could not be enumerated; no absence claim is possible.")
    gap(report, "Listener scopes do not establish external reachability. UDP, router forwarding and other devices were not checked.")
