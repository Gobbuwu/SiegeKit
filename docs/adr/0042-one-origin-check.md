# 0042. One origin check for every URL flag

- Status: Accepted
- Date: 2026-11-21
- Amends: [0005](0005-target-authorization.md) (how URLs other than the target are checked)

## Context

The full project check of 2026-11-21 (findings F6, F7, root cause RC3) found that each flag naming a URL on the target checked it in its own code, so the checks differed:

- `--login-url http://host//x` was accepted (logged while building M2.7b): `internal/login` checked the origin but not the path.
- `--openapi http://host//x/openapi.json` was accepted too (measured with a throwaway test of `openAPISource`: `path="//x/openapi.json" err=<nil>`); `--openapi` with a query silently dropped it and fetched another URL.
- Only `--rate-limit-url` refused a `//` path. It accepted a query with a NUL byte (measured 2026-11-21 against `main` at 5e1997f with a throwaway test: accepted, no error).
- HAR entries with a `//` path were kept and then refused by the egress proxy, so they were counted as account A's failed requests. Served-secrets links with such a path were counted as "not answered with 200".

No request left the origin in any of these: `egress.SendHeader` refuses a path that does not start with a single `/`. The user got a confusing failure instead of a clear refusal.

## Decision

1. **`target.OnOrigin(t, raw, flag, allowQuery)`** is the one check for a URL a flag names: valid per `target.Parse`, no spaces or control characters, no fragment, a valid query only when `allowQuery`, on the target's origin, and a path that starts with a single `/` (`target.SendablePath`). It is fuzzed (`FuzzOnOrigin`: whatever passes builds a request URL whose host is the target's).
2. **Used by `--login-url`, `--rate-limit-url` (query allowed) and `--openapi` (no query).** `--backend-url` names another host, so it keeps its own check, which already requires the path `/`.
3. **URLs from files and pages** (HAR entries, served-secrets links) use `target.SendablePath` and are counted as "with a path that does not start with a single /", not sent.
4. **The egress check stays as a backstop** and uses the same `SendablePath`.

## Consequences

- A new URL flag calls `OnOrigin` and gets the same rules; messages name the flag.
- `--openapi URL?query` is now refused instead of fetching the URL without its query.
- `--rate-limit-url` messages for spaces and control characters changed wording.

## Alternatives considered

- **Add the `//` check to `--login-url` and `--openapi` only:** fixes F6 and F7 but leaves the next flag to repeat the bug (instance, not root cause). Rejected.
- **Rely on the egress backstop:** safe, but the user gets a failed check instead of a clear refusal, and HAR and page counts are wrong. Rejected.
