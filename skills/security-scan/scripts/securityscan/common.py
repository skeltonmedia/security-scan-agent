"""Data boundaries shared by collection, enrichment and reporting."""
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

REFERENCES = Path(__file__).resolve().parents[2] / "references"
SOURCES = json.loads((REFERENCES / "sources.json").read_text())
RULES = json.loads((REFERENCES / "rules.json").read_text())
TOKEN_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
]
ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def fingerprint(*values):
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()[:20]


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r"v?\d+(?:\.\d+){1,3}", value):
        return None
    return tuple(int(x) for x in value.lstrip("v").split("."))


def safe_url(value):
    if not isinstance(value, str):
        return None
    try:
        p = urlsplit(value)
        if p.scheme != "https" or not p.hostname or p.username or p.password:
            return None
        if p.port not in (None, 443):
            return None
        return urlunsplit((p.scheme, p.netloc, p.path, "", ""))
    except ValueError:
        return None


def scrub(value):
    """Defense in depth; never intentionally put raw secret values in evidence."""
    if isinstance(value, dict):
        return {scrub(str(k)): scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(x) for x in value]
    if not isinstance(value, str):
        return value
    value = value.replace(str(Path.home()), "~")
    value = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", value)
    value = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[email]", value)
    for pattern in TOKEN_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value


def gap(report, message, *, incomplete=False):
    if message not in report["coverage"]["gaps"]:
        report["coverage"]["gaps"].append(message)
    if incomplete:
        report["coverage"]["collection_errors"] = True


def finding(report, rule, subject, evidence, *, confidence="observed", priority=None,
            references=None, extra=None):
    policy = RULES[rule]
    row = {"id": fingerprint(rule, subject, (extra or {}).get("advisory_id", "")),
           "rule": rule, "subject": subject, "priority": priority or policy["priority"],
           "title": policy["title"], "confidence": confidence, "evidence": evidence,
           "action": policy["action"], "references": references or []}
    if extra:
        row.update(extra)
    report["findings"].append(row)


class Budget:
    def __init__(self, seconds=120, requests=100):
        self.deadline = time.monotonic() + seconds
        self.requests_left = requests

    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())

    def request(self):
        if self.remaining() <= 0 or self.requests_left <= 0:
            raise RuntimeError("scan budget exhausted")
        self.requests_left -= 1
