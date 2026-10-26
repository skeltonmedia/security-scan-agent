# Fix the approved findings and verify the result

Use the selected audit report and the user's current authorization. Recheck
installed/deployed versions and current vendor instructions before changing
anything; previous reports can be stale. Do not assume a missing finding was
fixed or a package-only match proves exploitation.

Explain the proposed change in plain language: what software or setting it
affects, why it matters, possible workflow disruption, and recovery options.
Continue within existing authorization; ask only for missing decisions or
permissions. Preserve user data and unrelated changes. Prefer a bounded
vendor/package-manager update to a blind forced dependency upgrade.

For secrets, move private configuration outside shared folders, restrict
permissions and update every reader before removing the old copy. Confirm
identical content locally without printing it. Previously exposed keys need
revocation/rotation; moving or deleting a copy does not revoke a credential.
Never log a key, password, recovery code, full environment or authenticated URL.

For software, distinguish installed files from running processes and deployed
artifacts. Verify the intended version and vendor signature/checksum where
available. Restart consumers only within scope. Test meaningful workflows and
preserve libraries/settings. Check consumers before deleting a second runtime.

For dependencies, prioritize active internet-facing deployments and reachable
features, then local development tools. Record compatibility tradeoffs and
remaining advisories. Do not automatically deploy changes. For confirmed
compromise, use the vendor's containment and clean-recovery guidance; updating
a version alone is not evidence the host is trustworthy again.

Finish with what changed, what was tested, any pre-existing failures, what
still needs account/administrator access, and exact closure criteria. Save
private evidence and update the project/run log. Do not publish the report.
