# Architecture decision records

Each significant design decision is recorded as a short ADR before code is written. An ADR is never edited after it is accepted; a later ADR supersedes it.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-implementation-language.md) | Implementation language and platforms | Accepted |
| [0003](0003-wrap-external-tools.md) | Wrap external tools as sandboxed processes | Accepted |
| [0004](0004-plugin-manifest.md) | Plugin manifest | Accepted |
| [0005](0005-target-authorization.md) | Target modes and authorization | Accepted |
| [0006](0006-sandbox.md) | Sandbox and network egress control | Accepted |
| [0007](0007-findings-format.md) | Findings format and storage | Accepted |
| [0008](0008-supply-chain.md) | Supply chain of SiegeKit and its tools | Accepted |
| [0009](0009-honest-results.md) | Honest results: coverage, not a "secure" verdict | Accepted |
| [0010](0010-login-checks.md) | Login protection and secret-exposure checks | Accepted |
| [0011](0011-app-logic-and-ai-checks.md) | Access-control, backend-rules and AI-feature checks | Accepted |
| [0012](0012-manifest-file-format.md) | Plugin manifest file format and validator (amends 0004) | Accepted |
| [0013](0013-run-storage.md) | Run storage as JSON files (amends 0007) | Accepted |
| [0014](0014-offline-tool-data.md) | Offline tool data and update containers (amends 0006) | Accepted |
| [0015](0015-built-in-checks.md) | Built-in static checks run in-process (amends 0006, 0011) | Accepted |
| [0016](0016-dependency-consent.md) | Ask before installing dependencies (amends 0006, 0014) | Accepted |
| [0017](0017-target-rule-details.md) | Target rule details (amends 0005) | Accepted |
| [0018](0018-egress-proxy.md) | Egress proxy design (amends 0006) | Accepted |
| [0019](0019-egress-relay.md) | Egress through a relay with no network (amends 0018) | Accepted |
| [0020](0020-repository-suppressions.md) | Suppressions in the scanned repository (amends 0009) | Accepted |
| [0021](0021-built-in-relay.md) | The relay runs SiegeKit's own binary (amends 0019) | Accepted |
| [0022](0022-plan-confirmation.md) | Ask before running only for URL targets (amends 0004) | Accepted |
| [0023](0023-active-web-scans.md) | Running active web scans: ZAP as the first active plugin (amends 0004) | Accepted |
| [0024](0024-pinned-file-downloads.md) | Pinned file downloads (amends 0004, 0008, 0016) | Accepted |
| [0025](0025-m2-5-web-tools.md) | Nuclei, ffuf and Schemathesis (M2.5) (amends 0023) | Accepted |
| [0026](0026-nuclei.md) | Running Nuclei (amends 0004, 0018, 0021, 0023, 0025) | Accepted |
| [0027](0027-ffuf.md) | Running ffuf (amends 0004, 0024) | Accepted |

ADRs 0002 to 0011 were accepted at the M0 design sign-off on 2026-11-18.

## Template

```markdown
# NNNN. Title

- Status: Proposed | Accepted | Superseded by NNNN
- Date: YYYY-MM-DD

## Context
What problem or force requires a decision.

## Decision
What we will do.

## Consequences
What becomes easier, harder, or riskier.

## Alternatives considered
Options rejected and why.
```
