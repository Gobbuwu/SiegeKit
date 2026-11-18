# 0008. Supply chain of SiegeKit and its tools

- Status: Proposed
- Date: 2026-11-18

## Context

A security tool is a high-value target. On 19 March 2026 attackers used a leaked token to force-push the version tags of Aqua Security's `trivy-action` and `setup-trivy` GitHub Actions to malicious commits and published a malicious Trivy v0.69.4 release; pipelines that referenced mutable tags ran the attacker's code ([Aqua Security write-up](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/), advisory GHSA-cxm3-wv7p-598c). SiegeKit downloads and runs many third-party tools, so the same class of attack applies to us twice: to our own build, and to the tools we fetch for users.

## Decision

### Tools SiegeKit runs for users

- Every tool artifact is pinned in its manifest by exact version **and** SHA-256 (image digest for containers). A mismatch aborts the run.
- SiegeKit never resolves "latest" or a floating tag at runtime.
- Upstream signatures or provenance are verified in addition to the checksum where the upstream project publishes them.
- Updating a tool is a reviewed pull request that changes the manifest, re-runs the parser golden tests, and records where the new checksum was obtained.
- New upstream versions are adopted after a waiting period (default 7 days) unless they fix a vulnerability, so compromised releases are more likely to be caught and pulled first.

### SiegeKit's own repository and releases

- `main` is protected: pull request and passing checks required, no force-push, no deletion.
- GitHub Actions are pinned to full commit SHAs, never tags. Workflow `GITHUB_TOKEN` permissions default to read-only and are raised per job only where needed.
- No long-lived publishing credentials: releases use short-lived OIDC identities.
- Release builds run only in CI from a signed tag, are reproducible, and are signed with Sigstore cosign. Each release carries an SBOM and SLSA build provenance, and checksums are published.
- Go dependencies are kept minimal, pinned by `go.sum`, and checked in CI with `govulncheck` and OSV-Scanner. SiegeKit scans itself in CI.
- OpenSSF Scorecard runs on the repository.

## Consequences

- Updating a wrapped tool is deliberate work, not automatic. This is the intended trade-off.
- Users can verify any SiegeKit binary against its signature and provenance before running it.

## Alternatives considered

- **Auto-update tools to latest:** fastest access to new detections, but exactly the path the Trivy incident exploited. Rejected.
