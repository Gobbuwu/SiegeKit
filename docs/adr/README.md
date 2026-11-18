# Architecture decision records

Each significant design decision is recorded as a short ADR before code is written. An ADR is never edited after it is accepted; a later ADR supersedes it.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-implementation-language.md) | Implementation language and platforms | Proposed |
| [0003](0003-wrap-external-tools.md) | Wrap external tools as sandboxed processes | Proposed |
| [0004](0004-plugin-manifest.md) | Plugin manifest | Proposed |
| [0005](0005-target-authorization.md) | Target modes and authorization | Proposed |
| [0006](0006-sandbox.md) | Sandbox and network egress control | Proposed |
| [0007](0007-findings-format.md) | Findings format and storage | Proposed |
| [0008](0008-supply-chain.md) | Supply chain of SiegeKit and its tools | Proposed |
| [0009](0009-honest-results.md) | Honest results: coverage, not a "secure" verdict | Proposed |
| [0010](0010-login-checks.md) | Login protection and secret-exposure checks | Proposed |

"Proposed" ADRs become "Accepted" when the M0 design review is signed off.

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
