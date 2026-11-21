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
| [0028](0028-schemathesis.md) | Running Schemathesis (amends 0004, 0025) | Accepted |
| [0029](0029-check-selection.md) | Choosing checks by family and profile (amends 0004) | Accepted |
| [0030](0030-login-throttling.md) | The login throttling check (amends 0010, 0029) | Accepted |
| [0031](0031-default-logins.md) | Default credentials with Nuclei (amends 0010, 0026, 0029) | Accepted |
| [0032](0032-served-secrets.md) | Secrets in served files (amends 0010) | Accepted |
| [0033](0033-mobile-app-targets.md) | Mobile app targets (amends 0004, when built in M3) | Accepted |
| [0034](0034-weak-passwords.md) | Weak passwords written into files | Accepted |
| [0035](0035-access-control-replay.md) | The access-control check: replaying a recording as another account (amends 0011) | Accepted |
| [0036](0036-rate-limit-check.md) | The rate-limit check (amends 0011, 0029) | Accepted |
| [0037](0037-backend-live-check.md) | The live hosted-backend check (amends 0011) | Accepted |
| [0038](0038-run-environment.md) | Every run and result names its environment (amends 0006) | Accepted |
| [0039](0039-known-answers-and-engine-parity.md) | Known-answer tests, and one sandbox on every engine (amends 0006, 0038) | Accepted |
| [0040](0040-tools-that-skip-work.md) | A tool that skips part of its work makes the run incomplete (amends 0009, 0039) | Accepted |
| [0041](0041-typed-skip-causes.md) | Every skipped check has a typed cause (amends 0016, 0039) | Accepted |
| [0042](0042-one-origin-check.md) | One origin check for every URL flag (amends 0005) | Accepted |
| [0043](0043-zap-reports-every-alert.md) | ZAP reports every alert instance (amends 0023, 0040) | Accepted |
| [0044](0044-typed-confirmations-limit.md) | What a typed confirmation can and cannot stop (amends 0035, 0037) | Accepted |
| [0045](0045-gosec-one-package-at-a-time.md) | gosec checks one package at a time (amends 0040) | Accepted |
| [0046](0046-public-api-maps.md) | Public API specs and source maps (amends 0028, 0032) | Accepted |
| [0047](0047-recorded-requests-to-zap.md) | Recorded requests in ZAP's attack scan (amends 0004, 0023, 0035) | Accepted |
| [0048](0048-get-replay-skips-actions.md) | Access-control replay skips GETs that name an action (amends 0035) | Accepted |

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
