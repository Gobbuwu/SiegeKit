# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue.

Include the SiegeKit version, your OS, steps to reproduce, and the impact you observed.

## What to expect

- Acknowledgement within 7 days.
- An assessment and planned fix version within 30 days for confirmed issues.
- Critical issues are fixed in a dedicated patch release; others are batched into the next planned release.
- Credit in the release notes if you want it.

## Scope

In scope: SiegeKit's own code, its target-authorization checks, sandbox and egress controls, report generation, and its release artifacts.

Vulnerabilities in the third-party tools SiegeKit runs should be reported to those projects (see [THIRD_PARTY.md](THIRD_PARTY.md)). If SiegeKit's pinned version is affected, please also tell us so we can update the pin.

## Supported versions

SiegeKit has not been released yet. After 1.0, the latest minor release receives security fixes.
