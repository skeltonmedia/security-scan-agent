"""Explicit scope and network consent; bounded execution with disclosed gaps."""
import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .common import Budget, fingerprint, gap, scrub, utcnow
from .feeds import enrich_epss, fetch_kev, product_leads, query_packages, refresh_products
from .host import collect_host
from .inventory import collect_projects
from .network import Client
from .report import markdown, write_reports


def integer_between(low, high):
    def parse(value):
        result = int(value)
        if not low <= result <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return result
    return parse


def parser():
    p = argparse.ArgumentParser(description="Read-only local security evidence with optional current advisories.")
    p.add_argument("--project", action="append", required=True, help="owned local project root; repeat up to ten times")
    p.add_argument("--online", action="store_true", help="fetch public KEV and applicable vendor release feeds")
    p.add_argument("--query-packages", action="store_true", help="send exact package names/versions to OSV; requires --online")
    p.add_argument("--epss", action="store_true", help="send matched public CVE IDs to FIRST for optional probability estimates")
    p.add_argument("--no-host", action="store_true", help="scan selected projects without machine inventory")
    p.add_argument("--output", help="new private directory for report.md/report.json; omit to print Markdown")
    p.add_argument("--baseline", help="previous report.json for change comparison, never automatic resolution")
    p.add_argument("--max-files", type=integer_between(1, 100000), default=5000)
    p.add_argument("--max-file-bytes", type=integer_between(1024, 16000000), default=1000000)
    p.add_argument("--max-packages", type=integer_between(1, 10000), default=250)
    p.add_argument("--max-requests", type=integer_between(1, 1000), default=100)
    p.add_argument("--time-budget", type=integer_between(1, 600), default=120)
    p.add_argument("--fail-on", choices=["none", "P1", "P2"], default="none", help="optional findings exit gate")
    p.add_argument("--version", action="version", version=__version__)
    return p


def compare(report, previous):
    if not isinstance(previous, dict) or previous.get("schema_version") != report["schema_version"]:
        gap(report, "Baseline schema is incompatible; no change comparison was made.")
        return
    if previous.get("scope") != report["scope"]:
        gap(report, "Baseline scope or network mode differs; no change comparison was made.")
        return
    before = {x["id"] for x in previous.get("findings", []) if isinstance(x, dict) and "id" in x}
    after = {x["id"] for x in report["findings"]}
    report["changes"] = {"new_finding_ids": sorted(after - before),
        "not_seen_in_this_scan": sorted(before - after),
        "interpretation": "Not seen is not resolved. Check source failures, limits, input drift and fix evidence."}


def collect(args, *, client_factory=Client):
    roots = [Path(x).expanduser().resolve() for x in args.project]
    if len(roots) > 10 or any(not p.is_dir() for p in roots):
        raise ValueError("Select one to ten existing project directories.")
    report = {"schema_version": 1, "scanner_version": __version__, "timestamp": utcnow(),
        "scope": {"project_count": len(roots), "scope_token": fingerprint([str(p) for p in roots]),
                  "host": not args.no_host, "online": args.online, "package_queries": args.query_packages,
                  "epss": args.epss, "limits": {"files": args.max_files, "bytes": args.max_file_bytes,
                        "packages": args.max_packages, "requests": args.max_requests, "seconds": args.time_budget}},
        "coverage": {"gaps": []}, "sources": [], "packages": [], "findings": [], "watchlist": []}
    budget = Budget(args.time_budget, args.max_requests)
    collect_projects(report, roots, budget, args.max_files, args.max_file_bytes)
    if not args.no_host:
        collect_host(report, budget)
    if args.online:
        client = client_factory(report, budget)
        kev = fetch_kev(client)
        refresh_products(client)
        product_leads(report, kev)
        if args.query_packages:
            query_packages(client, kev, args.max_packages)
        else:
            gap(report, "OSV version matching was not requested; public feed refresh does not check package versions.")
        if args.epss:
            enrich_epss(client)
    else:
        gap(report, "Offline scan: no current advisory, known-exploitation or vendor-version check was performed.")
    if budget.remaining() <= 0:
        gap(report, "Time budget expired; remaining inputs or requests were not checked.")
    # Collapse alias-equivalent package records without inflating the finding count.
    deduped = {}
    for row in report["findings"]:
        previous = deduped.get(row["id"])
        if previous:
            previous["references"] = sorted(set(previous["references"] + row["references"]))
            previous["known_exploited_cves"] = sorted(set(previous.get("known_exploited_cves", []) + row.get("known_exploited_cves", [])))
            if row["priority"] < previous["priority"]:
                previous["priority"] = row["priority"]
        else:
            deduped[row["id"]] = row
    report["findings"] = sorted(deduped.values(), key=lambda row: (row["priority"], row["subject"], row["id"]))
    source_states = {}
    for row in report["sources"]:
        source_states.setdefault(row["source"], []).append(row["status"])
    failed = [name for name, states in source_states.items() if "fresh" not in states]
    queries = report["coverage"].get("package_queries", {})
    incomplete = (budget.remaining() <= 0 or bool(failed) or report["coverage"].get("collection_errors", False)
                  or report["coverage"]["roots_completed"] < len(roots)
                  or queries.get("completed", 0) < queries.get("unique_versions", 0)
                  or queries.get("advisory_details_missing", 0) > 0)
    report["coverage"]["collection_status"] = "incomplete" if incomplete else "completed_with_documented_limits"
    if args.baseline:
        path = Path(args.baseline).expanduser()
        if path.stat().st_size > 16000000:
            raise ValueError("Baseline exceeds the byte limit.")
        compare(report, json.loads(path.read_text()))
    return scrub(report)


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if (args.query_packages or args.epss) and not args.online:
        p.error("--query-packages and --epss require --online; no network request was made")
    try:
        report = collect(args)
        if args.output:
            directory = write_reports(args.output, report)
            print(f"Reports saved in {scrub(str(directory))}; collection: {report['coverage']['collection_status']}")
        else:
            print(markdown(report))
        if report["coverage"]["collection_status"] == "incomplete":
            return 2
        if args.fail_on != "none" and any(x["priority"] <= args.fail_on for x in report["findings"]):
            return 1
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print("Scan/report failed. Check input format, permissions and output location. No clean result is available.", file=sys.stderr)
        return 2
