# 0011. Access-control, backend-rules and AI-feature checks

- Status: Accepted
- Date: 2026-11-18
- Amended by: [0015](0015-built-in-checks.md) (static backend-rules check written in Go), [0035](0035-access-control-replay.md) (item 1: requests from a browser recording, what counts as a finding), [0036](0036-rate-limit-check.md) (item 2: the rate-limit check)

## Context

A gap review against the OWASP Top 10 (2025), OWASP API Security Top 10 (2023), CWE Top 25 (2025) and OWASP Top 10 for LLM Applications (2025) ([mapping](../standards-mapping.md)) found that the most common serious flaw in quickly built apps, **broken access control** (OWASP A01, API1/API3/API5, CWE-862/863/639/284/306), was marked manual only. Apps built with AI assistants also often share three further failures: hosted backends with open data rules (for example Supabase tables without row-level security, or permissive Firebase rules), AI API keys in client code, and features that pass untrusted text to a language model.

## Decision

### 1. Authorization differential test (M2, built in SiegeKit; ZAP's Access Control add-on evaluated as an alternative)

- The user supplies two test accounts they own (A and B), optionally with different roles.
- SiegeKit crawls as A, records the requests, then replays each one as B and again with no session.
- A replay that succeeds with the same data is reported as a likely broken object-level or function-level authorization finding, with both requests and responses as evidence.
- Every API route discovered (crawl, OpenAPI spec, or routes found in source) is also requested without credentials to flag **missing authentication**.
- Replays of state-changing requests (POST, PUT, PATCH, DELETE) are `destructive` and follow ADR 0005 (off in deployed mode unless allowed for the run).

This is a heuristic: it finds many real access-control bugs but cannot prove their absence, and the report says so (ADR 0009).

### 2. Generic rate-limit check (M2)

Same approach as the login check in ADR 0010, for any endpoint the user names (for example an expensive search or an AI endpoint): a capped burst (default 20, hard maximum 50) to see whether the app throttles. This checks CWE-770 / API4 / LLM10 without load testing. Amended by [0036](0036-rate-limit-check.md): `--rate-limit-url`, local targets only until M2.10, a limit seen at a 429 or 503 or a rate-limit header, no limit is low.

### 3. Hosted-backend rules (M1 static, M2 live)

- Static (M1): SiegeKit-maintained Semgrep rules flag Firebase/Firestore rules files that allow public reads or writes, and SQL migrations that create Supabase tables without enabling row-level security.
- Live (M2, verified target only): using the public client key found in the app's own bundle, SiegeKit attempts **read-only** list queries against the backend and reports any table or collection readable without a signed-in user.

### 4. AI feature checks (M3)

- AI provider keys in code and served bundles: covered by Gitleaks, which has rules for OpenAI and Anthropic keys among others (M1, M2).
- Static rules for model output passed to `eval`, shell commands, SQL or HTML without escaping (LLM05 Improper Output Handling).
- Optional prompt-injection and data-leak probing of the app's own AI endpoint with [garak](https://github.com/NVIDIA/garak) (Apache-2.0, 0.17.1 on PyPI) or [promptfoo](https://github.com/promptfoo/promptfoo) (MIT, 0.126.0 on npm), both checked 2026-11-18. Rate-capped and verified-target only; it consumes the user's AI provider credits, which the plan screen states.

## Consequences

- SiegeKit gains its own detection code for the first time (items 1 to 3). It gets the same golden-file, fixture and fuzz testing as parsers.
- Users must create two test accounts to get access-control coverage; without them the report lists access control as "not tested".

## Alternatives considered

- **Leave access control manual:** honest, but leaves the most common serious flaw unchecked for the audience most likely to have it.
