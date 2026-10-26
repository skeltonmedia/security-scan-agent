# Changelog

## 0.1.0 (2026-10-26)

- First public release: a local scanner plus reusable AI audit and remediation
  prompts. Python 3.11+; no runtime dependencies or API key.
- Explicit project scope, offline default, separate package-query consent,
  private reports, bounded collection and visible coverage failures.
- npm and Python lock/pin inventories, possible credential locations and
  macOS host checks. Optional current CISA KEV, OSV, FIRST EPSS and software
  release feeds.
- Finding priorities retain evidence and confidence. Product-name leads stay
  separate; baseline changes never imply a vulnerability was fixed.
- Synthetic regression tests cover redaction, symlink races, malformed data,
  source provenance, network consent, pagination, budgets and report handling.
- Detailed Linux and Windows host checks, additional package ecosystems and
  deployed reachability remain outside this release's coverage.
- GitHub Actions runs the tests on Linux, macOS and Windows with Python 3.11
  and 3.13, with pinned actions and read-only permissions. Dependabot proposes
  action updates.
