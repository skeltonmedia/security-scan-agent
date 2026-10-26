# Public sources and what their results mean

The machine-readable URLs are in `sources.json`. Requests are HTTPS-only,
host-allowlisted, size-limited and bounded by a total scan/request budget.
No credentials, cookies or inherited authenticated proxy handler are attached.
The scanner does not execute commands or follow instructions from any feed.

| Source | Use | Boundary |
|---|---|---|
| [CISA KEV](https://github.com/cisagov/kev-data) | Refresh known exploitation, using CISA's official GitHub mirror if its primary JSON endpoint fails | Exact CVE alias overlap enriches a package match; product names alone remain leads. Catalog date and retrieval time are distinct. |
| [OSV API](https://google.github.io/osv.dev/api/) | Query exact package versions and retrieve individual advisories | Batch query results contain IDs, not full severity/fix details. The helper follows pagination within a cap and discloses incomplete details. |
| [FIRST EPSS](https://api.first.org/epss/) | Optional lookup for up to 50 matched CVEs | This is a global probability estimate. Scores are dated; absence is not zero. It is not a compromise detector. |
| [Node release index](https://nodejs.org/dist/index.json) and [support schedule](https://github.com/nodejs/Release/blob/main/schedule.json) | Compare installed releases in the same major branch and identify support end dates | A second executable may have different consumers. No automatic deletion or major-version migration. |
| [Chromium release dashboard](https://chromiumdash.appspot.com/releases) | Compare installed macOS Chrome with stable release metadata | Component revocation updates may ship separately. A browser version alone does not establish trust-store incident exposure. |
| [Homebrew Plex cask](https://formulae.brew.sh/cask/plex-media-server) | Compare installed macOS Plex with the trusted distribution's current vendor release | This is a release comparison, not a vendor-specific affected-version rule or proof of prior exposure. |

Advisories from vendors, national CERTs and upstream maintainers should be
consulted by the AI assistant for host/application incidents that package
databases cannot map. NVD and GitHub advisories are useful references; this
release does not implement a generic CPE version matcher or automatic cloud
incident-account matching. Those checks are explicitly outside its coverage.

No successful request guarantees an advisory is complete. Failed sources,
stale/future-dated KEV catalogs, query truncation, pagination caps and missing
advisory details remain visible. Package presence does not prove deployment;
deployment does not prove an affected feature is reachable.
