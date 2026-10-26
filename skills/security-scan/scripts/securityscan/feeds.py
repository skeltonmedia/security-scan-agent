"""Current global feeds, package-version matches, and clearly separate product leads."""
import re
from datetime import datetime, timezone
from urllib.parse import urlencode, quote

from .common import SOURCES, finding, gap, safe_url, version_tuple


def invalid(client, message):
    if client.report["sources"]:
        client.report["sources"][-1]["status"] = "invalid"
    gap(client.report, message, incomplete=True)


def fetch_kev(client):
    report = client.report
    for url in SOURCES["kev"]:
        data = client.json("cisa-kev", url)
        if data is None:
            continue
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            invalid(client, "A KEV feed response had an unsupported schema.")
            continue
        rows = data["vulnerabilities"]
        if data.get("count") != len(rows) or not rows:
            invalid(client, "KEV record count was empty or inconsistent.")
            continue
        if any(not isinstance(x, dict) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", x.get("cveID", "")) for x in rows):
            invalid(client, "KEV contained invalid record identifiers.")
            continue
        report["coverage"]["kev"] = {"status": "available", "records": len(rows),
                                         "catalog_date": data.get("dateReleased"), "url": url}
        try:
            released = datetime.fromisoformat(data["dateReleased"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - released).total_seconds() / 86400
            if age > 7 or age < -1:
                report["coverage"]["kev"]["status"] = "stale_or_future_dated"
                gap(report, "The retrieved KEV catalog is over seven days old or future dated; check publisher freshness.", incomplete=True)
        except (KeyError, TypeError, ValueError):
            report["coverage"]["kev"]["status"] = "unknown_date"
            gap(report, "KEV publisher freshness could not be established.", incomplete=True)
        return {row["cveID"]: row for row in rows}
    report["coverage"]["kev"] = {"status": "unavailable"}
    gap(report, "All KEV feed requests failed. Known-exploitation enrichment is incomplete.")
    return {}


def refresh_products(client):
    report = client.report
    software = report.get("host", {}).get("software", [])
    nodes = [x for x in software if x["product"] == "node"]
    if nodes:
        releases = client.json("node-releases", SOURCES["node-releases"])
        schedule = client.json("node-schedule", SOURCES["node-schedule"])
        if not isinstance(releases, list) or not isinstance(schedule, dict):
            gap(report, "Runtime release/support feeds are unavailable or invalid; no up-to-date claim is possible.", incomplete=True)
        else:
            for item in nodes:
                current = version_tuple(item["version"])
                if not current:
                    continue
                branch = "v" + str(current[0])
                try:
                    end = datetime.strptime(schedule[branch]["end"], "%Y-%m-%d").date()
                    if end <= datetime.now(timezone.utc).date():
                        finding(report, "eol-runtime", item["location"],
                                {"installed": item["version"], "support_end": str(end)},
                                references=[SOURCES["node-schedule"]])
                except (KeyError, TypeError, ValueError):
                    gap(report, f"Runtime support status is unknown for branch {branch}.", incomplete=True)
                candidates = [r.get("version") for r in releases if isinstance(r, dict)
                              and version_tuple(r.get("version"))
                              and version_tuple(r["version"])[0] == current[0]]
                if candidates:
                    latest = max(candidates, key=version_tuple)
                    newer_release(report, item, latest, SOURCES["node-releases"])
                else:
                    gap(report, f"No release record was available for runtime branch {branch}.", incomplete=True)
    for product in ["chrome-mac", "plex-mac"]:
        installed = [x for x in software if x["product"] == product]
        if not installed:
            continue
        data = client.json(product, SOURCES[product])
        try:
            latest = data[0]["version"] if product == "chrome-mac" else data["version"].split(",", 1)[0].split("-", 1)[0]
            if not version_tuple(latest):
                raise ValueError("unrecognized version")
            for item in installed:
                newer_release(report, item, latest, SOURCES[product])
        except (KeyError, TypeError, ValueError, IndexError):
            gap(report, f"Release feed is unavailable or invalid for {product}.", incomplete=True)


def newer_release(report, item, latest, url):
    current, available = version_tuple(item["version"]), version_tuple(latest)
    if current and available and current < available:
        finding(report, "newer-release", item["location"],
                {"product": item["product"], "installed": item["version"], "available": latest},
                references=[url])


def product_leads(report, kev):
    aliases = {"node": {"nodejs", "node"}, "chrome-mac": {"chrome", "googlechrome"},
               "plex-mac": {"mediaserver", "plexmediaserver"}}
    for item in report.get("host", {}).get("software", []):
        for cve, row in kev.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(row.get("product", "")).lower())
            vendor = str(row.get("vendorProject", "")).lower()
            if normalized not in aliases.get(item["product"], set()):
                continue
            if item["product"] == "plex-mac" and "plex" not in vendor:
                continue
            report["watchlist"].append({"product": item["product"], "installed": item["version"],
                "cve": cve, "confidence": "product_name_lead_only",
                "action": "Verify affected version and configuration against the vendor advisory; this is not a confirmed vulnerable version.",
                "source": report["coverage"]["kev"].get("url"), "date_added": row.get("dateAdded")})


def query_packages(client, kev, max_packages=250):
    report = client.report
    unique = {}
    for row in report["packages"]:
        key = (row["ecosystem"], row["name"], row["version"])
        unique.setdefault(key, []).append(row["location"])
    selected = list(unique)[:max_packages]
    report["coverage"]["package_queries"] = {"unique_versions": len(unique), "selected": len(selected),
                                                "completed": 0, "advisory_details_missing": 0}
    if len(selected) < len(unique):
        gap(report, "Package query budget truncated the inventory; some exact versions were not checked.")
    records = {}
    pairs = []
    for offset in range(0, len(selected), 50):
        pending = [(key, None, 0) for key in selected[offset:offset + 50]]
        while pending:
            queries = []
            for key, token, _depth in pending:
                ecosystem, name, version = key
                query = {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
                if token:
                    query["page_token"] = token
                queries.append(query)
            data = client.json("osv-querybatch", SOURCES["osv"], {"queries": queries})
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list) or len(results) != len(pending):
                gap(report, "OSV query failed or returned a mismatched result count; package coverage is incomplete.")
                break
            next_page = []
            for (key, _token, depth), row in zip(pending, results):
                if not isinstance(row, dict) or row.get("error") or not isinstance(row.get("vulns", []), list):
                    gap(report, "OSV returned an invalid package result; that version remains unverified.", incomplete=True)
                    continue
                for vuln in row.get("vulns", []):
                    identifier = vuln.get("id") if isinstance(vuln, dict) else None
                    if isinstance(identifier, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,150}", identifier):
                        pairs.append((key, identifier))
                    else:
                        gap(report, "An OSV advisory identifier was invalid and could not be resolved.", incomplete=True)
                token = row.get("next_page_token")
                if token and depth < 4 and isinstance(token, str) and len(token) < 4096:
                    next_page.append((key, token, depth + 1))
                elif token:
                    gap(report, "OSV pagination limit reached; that package's advisory list is incomplete.")
                else:
                    report["coverage"]["package_queries"]["completed"] += 1
            pending = next_page
    for key, identifier in sorted(set(pairs)):
        if identifier not in records:
            records[identifier] = client.json("osv-advisory", SOURCES["osv-detail"] + quote(identifier, safe=""))
        data = records[identifier]
        if not isinstance(data, dict) or data.get("id") != identifier:
            report["coverage"]["package_queries"]["advisory_details_missing"] += 1
            gap(report, "One or more OSV advisory details were unavailable; IDs are retained without invented severity or fixes.")
            data = {"id": identifier}
        if data.get("withdrawn"):
            continue
        raw_aliases = data.get("aliases", [])
        raw_refs = data.get("references", [])
        raw_db = data.get("database_specific", {})
        if not isinstance(raw_aliases, list) or not isinstance(raw_refs, list) or not isinstance(raw_db, dict):
            gap(report, "Malformed optional advisory metadata was ignored; enrichment is incomplete.", incomplete=True)
        aliases = [x for x in (raw_aliases if isinstance(raw_aliases, list) else []) if isinstance(x, str)]
        cves = sorted(x for x in aliases + [identifier] if re.fullmatch(r"CVE-\d{4}-\d{4,}", x))
        exploited = [x for x in cves if x in kev]
        canonical = cves[0] if cves else identifier
        severity = str((raw_db if isinstance(raw_db, dict) else {}).get("severity", "unknown")).upper()
        priority = "P1" if exploited or severity in {"CRITICAL", "HIGH"} else "P2"
        references = [safe_url(x.get("url")) for x in (raw_refs if isinstance(raw_refs, list) else []) if isinstance(x, dict)]
        references = [x for x in references if x][:10]
        references.insert(0, "https://osv.dev/vulnerability/" + quote(identifier, safe=""))
        ecosystem, name, version = key
        finding(report, "package-advisory", f"{ecosystem}/{name}@{version}",
                {"locations": sorted(set(unique[key])), "matched_version": version,
                 "severity": severity, "summary": str(data.get("summary", "Details unavailable"))[:600],
                 "published": data.get("published"), "modified": data.get("modified")},
                confidence="version_matched_runtime_reachability_unverified", priority=priority,
                references=references, extra={"advisory_id": canonical, "source_id": identifier,
                    "aliases": aliases, "known_exploited_cves": exploited})


def enrich_epss(client):
    report = client.report
    cves = sorted({x for f in report["findings"] for x in f.get("aliases", []) + [f.get("advisory_id", "")]
                   if re.fullmatch(r"CVE-\d{4}-\d{4,}", x)})
    if len(cves) > 50:
        gap(report, "EPSS lookup capped at 50 CVEs; remaining matched CVEs were not scored.")
    if not cves:
        return
    data = client.json("first-epss", SOURCES["epss"] + "?" + urlencode({"cve": ",".join(cves[:50]), "limit": 50}))
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        gap(report, "Optional EPSS lookup failed; no score was inferred.")
        return
    scores = {}
    for row in data["data"]:
        try:
            probability = float(row["epss"])
            if 0 <= probability <= 1:
                scores[row["cve"]] = {"probability": probability, "date": row.get("date")}
        except (KeyError, TypeError, ValueError):
            gap(report, "An EPSS score was malformed and ignored.")
    for f in report["findings"]:
        matches = {cve: scores[cve] for cve in f.get("aliases", []) + [f.get("advisory_id", "")] if cve in scores}
        if matches:
            f["epss"] = matches
            if max(x["probability"] for x in matches.values()) >= 0.5:
                f["priority"] = "P1"
    gap(report, "EPSS is a global exploitation probability estimate, not proof of compromise or local reachability.")
