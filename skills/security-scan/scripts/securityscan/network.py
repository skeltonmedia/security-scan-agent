"""HTTPS JSON only, allowlisted destinations, no auth or project configuration."""
import json
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .common import SOURCES, utcnow

MAX_RESPONSE_BYTES = 16 * 1024 * 1024
ALLOWED_HOSTS = frozenset(urlsplit(url).hostname for value in SOURCES.values()
                         for url in (value if isinstance(value, list) else [value]))


def validate_destination(url):
    try:
        p = urlsplit(url)
        valid = (p.scheme == "https" and p.hostname in ALLOWED_HOSTS
                 and p.username is None and p.password is None and p.port in (None, 443))
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("network destination is not an approved feed")


class FeedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_destination(newurl)
        # A POST body must not be redirected to another feed provider.
        if req.data is not None:
            raise ValueError("feed POST redirect refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Client:
    def __init__(self, report, budget):
        self.report = report
        self.budget = budget
        # Do not inherit proxy credentials or install a cookie/auth handler.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), FeedRedirect())

    def json(self, source, url, payload=None):
        validate_destination(url)
        row = {"source": source, "url": url, "retrieved_at": utcnow(), "status": "failed"}
        self.report["sources"].append(row)
        try:
            self.budget.request()
            data = None if payload is None else json.dumps(payload).encode()
            req = urllib.request.Request(url, data=data, headers={
                "User-Agent": "security-scan-agent/0.1 (read-only audit)",
                "Accept": "application/json", "Content-Type": "application/json"})
            with self.opener.open(req, timeout=min(10, self.budget.remaining())) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("feed response exceeded the size limit")
            result = json.loads(body)
            if not isinstance(result, (dict, list)):
                raise ValueError("feed is not an object or array")
            row["status"] = "fresh"
            row["bytes"] = len(body)
            return result
        except (OSError, ValueError, RuntimeError) as error:
            # Errors can echo URLs or response bodies. Store only the class.
            row["error_type"] = type(error).__name__
            return None
