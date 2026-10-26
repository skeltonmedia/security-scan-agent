# Security Scan Agent

Give your AI assistant evidence about your machine and projects before it
recommends a security fix.

Security Scan Agent combines a read-only local scanner with reusable AI audit
and remediation prompts. It checks selected project files, inventories a few
host controls, and can match exact package versions against current public
advisories. It produces a private report with findings, source timestamps,
coverage gaps and next actions. It never installs patches or changes settings.

**No API key, AI subscription or Python dependency is required to run the
scanner. Python 3.11+ is required.** An AI assistant is optional for interpreting
the report, checking vendor guidance and preparing approved fixes.

## Start with a local scan

```bash
git clone https://github.com/skeltonmedia/security-scan-agent.git
cd security-scan-agent
python3 scan.py --project /path/to/your/project --output ~/security-reports/first-scan
```

Choose a new output directory for every run. Reports are created with private
permissions where supported, and existing reports are never overwritten.
Keep reports outside public repositories and review them before sharing.
The default scan makes **no network requests**. Use `--no-host` for a
project-only scan. Repeat `--project` to select additional owned roots.

## Add current threat information

```bash
python3 scan.py --project /path/to/your/project \
  --online --query-packages --epss \
  --output ~/security-reports/current-advisories
```

These switches make the data boundaries explicit:

| Switch | What leaves your machine | What comes back |
|---|---|---|
| `--online` | Ordinary HTTPS request metadata to the listed public feed providers | CISA KEV and applicable vendor/distribution release feeds |
| `--query-packages` | Exact package names, ecosystems and versions to OSV | Package-version advisory matches |
| `--epss` | Matched public CVE identifiers to FIRST | Dated global exploitation probability estimates |

Source files, environment variables, credential values and raw logs are not
uploaded by the scanner. Private package names may still be sensitive, so use
package queries only when that disclosure is acceptable. A failed feed is a
visible coverage gap, never an empty success result.

- [CISA KEV](https://github.com/cisagov/kev-data): vulnerabilities known to be
  exploited. An exact CVE overlap with an OSV version match raises priority.
  A product-name overlap is only a lead for vendor verification.
- [OSV](https://google.github.io/osv.dev/api/): advisory matches for exact
  dependency versions. Lockfile presence does not prove a package is installed,
  deployed or reachable.
- [FIRST EPSS](https://www.first.org/epss/data.html): optional probability
  context, not evidence that your machine was attacked.
- Vendor/distribution release feeds identify newer Node, macOS Chrome and
  macOS Plex versions; Node's upstream schedule identifies unsupported branches.
  Being behind a release is not itself a confirmed CVE match.

Full source registry and semantics: [sources](skills/security-scan/references/sources.md).

## Use the AI agent

Open this repository in an assistant that reads `AGENTS.md`, or provide
[the audit prompt](skills/security-scan/references/audit-prompt.md) and the
selected scope. To install it as a reusable skill, copy the entire
`skills/security-scan` folder to your assistant's supported skill directory.
The folder includes its own runner: `python3 scripts/scan.py --help`.

Ask:

> Audit my selected project and this machine. Use the Security Scan skill.
> Fetch current advisories, explain exactly what data will leave the machine,
> and return a prioritized fix plan. Treat missing permissions and unsupported
> checks as unknown. Do not change anything without my approval.

For a broader audit, the prompt also covers owned public domains, repository
exposure, account integrations, backups and incident history. Those are
assistant-led, separately authorized checks, not capabilities secretly
performed by the Python scanner. No report is sent to an LLM automatically.

The [remediation prompt](skills/security-scan/references/remediation-prompt.md)
turns approved findings into tested changes: explain impact first, preserve
data, verify the running/deployed version, and record unresolved work.

## Know what version 0.1 covers

| Area | Coverage |
|---|---|
| macOS | Firewall, FileVault, Gatekeeper and SIP status where readable; TCP listener scopes; fixed-location Node binaries; installed Chrome/Plex metadata |
| Linux / Windows | Selected project files and package inventories; limited runtime/platform inventory; detailed host controls remain unsupported |
| npm | `package-lock.json` v1, v2 and v3, including transitive resolved versions |
| Python | Exact `requirements*.txt` pins, `poetry.lock` and `uv.lock`; environment markers are not evaluated |
| Possible secrets | Common credential formats and non-placeholder env assignments; reports contain locations/pattern types, never matched values |
| Change tracking | `--baseline previous/report.json` shows new and not-seen finding IDs within matching scope; not-seen does not mean fixed |

Git, path, editable and explicitly private-registry dependencies are skipped
where their origin is recorded. Requirements files with custom index or
find-links directives are skipped. Pins without origin metadata still require
owner review before public package queries; matching a name does not establish
that a private fork is the public package.

There is no malware detection engine, exploit execution, network port sweep,
automatic patcher, cloud-account audit or zero-day prediction. Git history,
symlink targets, dependency directories, binary contents, unsupported lock
formats and unselected paths are outside the scanner's coverage. No result
certifies a machine safe. Pattern-based credential detection can miss secrets
or flag examples. Version matches still need feature and exposure review.

Collection is bounded by time, files, file bytes, package queries, pagination
and HTTP requests. Defaults: 120 seconds, 5,000 files, 1 MB per file, 250 unique
package versions, 100 HTTP requests. Limits and skipped inputs appear in the
report. The output is `report.md` plus inspectable `report.json`.

Exit codes: `0` collection completed within its documented scope, **not** a
security pass; `1` findings crossed an explicitly requested `--fail-on P1` or
`--fail-on P2` gate; `2` collection/report failed or required enrichment was
incomplete. Findings do not change the default exit code.

## Repeat without silently enabling a service

Run again after software changes or new advisories, using a fresh output
directory and the prior JSON as `--baseline`. The CLI runs once and exits.
You may add it to your own scheduler after reviewing the data boundaries and
runtime limits. This repository installs no scheduled job, background service
or GitHub workflow that scans your personal machine.

## Develop and verify

```bash
python3 -m unittest discover -s tests -v
python3 skills/security-scan/testing/check.py
```

Tests use temporary synthetic projects and fake feed responses. They exercise
network consent, redaction, alias matching, pagination, failure paths, budgets,
symlink boundaries, scope comparisons and output permissions.

[GitHub Actions](.github/workflows/test.yml) runs both commands on every push
and pull request across Linux, macOS and Windows with Python 3.11 and 3.13.
The workflow pins action commits, grants read-only repository permissions and
does not persist checkout credentials. CI tests the code on those platforms;
detailed host checks still run only on macOS. [Dependabot](.github/dependabot.yml)
proposes weekly action updates for review.

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Do not post
private scan reports or credentials in an issue. MIT licensed; contributions
welcome. Build from source and review changes before running a new release.
