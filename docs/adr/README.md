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
