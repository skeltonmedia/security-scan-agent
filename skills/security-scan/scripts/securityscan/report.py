"""Private JSON evidence and a readable plan. No reports are uploaded."""
import html
import json
import os
from pathlib import Path
from string import Template
from urllib.parse import quote

from .common import REFERENCES, safe_url, scrub


def cell(value):
    return html.escape(str(value)).replace("|", "\\|").replace("`", "\\`").replace("\n", " ")


def link(url):
    url = safe_url(url)
    return "[source](" + quote(url, safe="/:._-~%") + ")" if url else ""


def markdown(report):
    counts = {p: sum(x["priority"] == p for x in report["findings"]) for p in ["P1", "P2", "P3"]}
    summary = (f"Findings: {counts['P1']} P1, {counts['P2']} P2, {counts['P3']} P3. "
               "P1 means review promptly; it does not mean compromise is proven.\n\n"
               f"Collection status: **{cell(report['coverage']['collection_status'])}**. "
               f"Package network queries: **{cell(report['scope']['package_queries'])}**.")
    rows = []
    for f in report["findings"]:
        refs = " ".join(link(x) for x in f["references"][:4])
        rows += [f"### {cell(f['priority'])}: {cell(f['title'])}", "",
                 f"Subject: `{cell(f['subject'])}`. Confidence: {cell(f['confidence'])}.", "",
                 "Evidence: " + cell(json.dumps(f["evidence"], sort_keys=True)), "",
                 "Action: " + cell(f["action"]), ""]
        if f.get("known_exploited_cves"):
            rows += ["CISA KEV match: " + cell(", ".join(f["known_exploited_cves"])) + ".", ""]
        if f.get("epss"):
            rows += ["EPSS (global estimate): " + cell(json.dumps(f["epss"], sort_keys=True)), ""]
        if refs:
            rows += [refs, ""]
    watch = "\n".join("- " + cell(json.dumps(row, sort_keys=True)) for row in report["watchlist"])
    cov = report["coverage"]
    coverage = (f"- Selected roots completed: {cov.get('roots_completed', 0)}/{report['scope']['project_count']}\n"
                f"- Files read: {cov.get('files_read', 0)}\n"
                f"- Symlinks skipped: {cov.get('symlinks_skipped', 0)}\n"
                f"- Large files skipped: {cov.get('large_files_skipped', 0)}\n"
                f"- Exact package pins collected: {len(report['packages'])}\n"
                f"- Query coverage: {cell(json.dumps(cov.get('package_queries', {}), sort_keys=True))}\n"
                f"- Host controls: {cell(json.dumps(report.get('host', {}).get('controls', {}), sort_keys=True))}")
    sources = "\n".join(f"- {cell(x['source'])}: {cell(x['status'])}; retrieved {cell(x['retrieved_at'])}; {link(x['url'])}"
                         for x in report["sources"])
    if cov.get("kev"):
        sources += "\n- KEV catalog: " + cell(json.dumps(cov["kev"], sort_keys=True))
    return Template((REFERENCES / "report-template.md").read_text()).substitute(
        timestamp=cell(report["timestamp"]), summary=summary,
        findings="\n".join(rows) or "No findings in the checked inputs. Unchecked inputs remain unknown.",
        watchlist=watch or "No product-name leads were returned by the checked feeds.",
        coverage=coverage, sources=sources or "No live feeds requested. Advisory coverage is unavailable.",
        changes=cell(json.dumps(report.get("changes", {"baseline": "not supplied"}), sort_keys=True)),
        gaps="\n".join("- " + cell(x) for x in cov["gaps"]))


def write_reports(directory, report):
    directory = Path(directory).expanduser()
    if directory.exists() or directory.is_symlink():
        raise ValueError("Choose a new output directory; existing reports are never overwritten.")
    directory.mkdir(mode=0o700, parents=True)
    directory.chmod(0o700)
    for name, text in [("report.json", json.dumps(scrub(report), indent=2) + "\n"),
                       ("report.md", markdown(scrub(report)))]:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(directory / name, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    return directory
