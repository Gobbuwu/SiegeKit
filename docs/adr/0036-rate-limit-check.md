# 0036. The rate-limit check

- Status: Accepted
- Date: 2026-11-20
- Amends: [0011](0011-app-logic-and-ai-checks.md) item 2 (how the URL is given, what counts as a limit, where it runs), [0029](0029-check-selection.md) (what `--profile quick` leaves out)

## Context

ADR 0011 item 2 adds a capped burst against an endpoint the user names, to see whether the app limits requests (CWE-770, OWASP API4, LLM10) without load testing. The owner answered the M2.7 design questions on 2026-11-20 ([design](https://claude.ai/artifact/UjmsK3MmQ4btjaPg5427ar), answer 7a: "429/503 or RateLimit headers, no limit = low CWE-770, local only until M2.10"; 9a: three pull requests, this is the second).

Measured before the design answer, on OWASP Juice Shop v20.4.0 (the CI gate's image): its password-reset route carries `X-RateLimit-Limit: 100` from the first request, a limit a burst of 20 never reaches; its product search had no limit and no such header in 25 requests. Measured again with this check on 2026-11-20 (record: `rate-limit-measurement-2026-11-20.md` in the project files, summarised under Evidence).

## Decision

1. **The URL** is given with `--rate-limit-url URL`, on the target's origin (ADR 0005), with a path that starts with a single `/`, no fragment, and an optional query (a search term), which must parse and have no spaces. The request is a GET. With `--rate-limit-body BODY` (at most 8 KiB) it is a POST: sent as JSON (`application/json`) when the body starts with `{` or `[` (it must then be valid JSON), otherwise as a form (it must then parse as one). `--rate-limit-requests N` sets the number of requests, from 2 to 50, 20 by default. Mistakes are refused before any lookup or request; directory scans refuse the flags.
2. **Where it runs.** On local targets only, until M2.10 (owner answer 7a), even for a GET; on deployed targets it is reported as skipped, and `ratelimit.Check` and `egress.Send` refuse a POST on a read-only configuration. A POST can create data each time, so on a loopback target a POST needs a typed `yes` or `--authorized-host`, as the attack tests do (ADR 0023); a GET does not. `--profile quick` leaves it out, as it leaves out `login-throttle` (amends ADR 0029). Without `--rate-limit-url` it is reported as skipped with the reason. Like the other URL checks it runs only on Linux for now (ADR 0018).
3. **How it runs.** SiegeKit sends the requests itself with `egress.Send` (pinned addresses, no redirects, at most 2 MiB read from each answer), right after `login-throttle` and before the other URL checks, so their traffic does not count against a limit. Requests start at least one second apart. No login or session is sent.
4. **What counts as a limit** (owner answer 7a). An answer with status 429 or 503, a `Retry-After` header, or a header named `RateLimit`, `RateLimit-*` or `X-RateLimit-*` (the IETF draft's names and the common older ones, such as express-rate-limit's; matched after canonicalising the name). A header in the first answer counts, and the result says "already at the first request". The check stops at the first sign of a limit.
5. **When it cannot tell.** The check fails, with the reason, when the first answer is 401 or 403 (the URL needs a login, which this check does not send), 404, 405 or 501 (wrong URL or method), or another server error (5xx); when the target does not answer; or when a later answer is a server error or does not come, because a crash and a block of SiegeKit's address look the same from the host. Other client errors (such as a 400 for a missing parameter) are a valid baseline: the same request, answered the same way.
6. **Results.** When every planned request was answered with no sign of a limit, there is one finding, "Requests are not rate limited" (`rate-not-limited`, CWE-770), **low** severity (owner answer 7a), located at the URL without its query. The message names the number of requests, the method and the status, and says what the check cannot see. When a limit was seen there is no finding. The report's plugin entry gives `input` (`GET URL` or `POST URL`) and `result`, such as `limit seen after 4 of 20 requests: answered 429` or `no limit seen in 20 requests, all answered 200 with no rate-limit header`.

## Evidence

| Claim | Backed by |
|---|---|
| Juice Shop's product search has no limit; the check reports it | Measured 2026-11-20: 20 GETs to `/rest/products/search?q=apple`, all 200, finding reported; 60 back-to-back curl GETs, all 200 with no rate-limit header. CI gate step asserts it. |
| A header on the first answer is enough to see Juice Shop's password-reset limit | Measured 2026-11-20: the check stopped after 1 POST to `/rest/user/reset-password` with `X-Ratelimit-Limit`; curl shows `X-RateLimit-Limit: 100`, `X-RateLimit-Remaining: 98`. |
| A 429 after a few requests is seen and gives no finding | `TestRateLimitFindsPlantedIssue` (fixture `POST /api/report`, 429 after 3: limited at request 4). |
| Requests arrive at least one second apart | `TestCheckRate` (real server and clock). |
| URLs off the target's origin or starting with `//` are refused | `TestParse`, `FuzzParse` (in CI's fuzz list). |
| A URL that needs a login fails the check instead of reporting "not limited" | Unit test `TestCheckFails`; measured on Juice Shop `/rest/basket/1` (401, check failed). |

## Consequences

- Limits on deployed targets are not tested until M2.10; the report lists the check as skipped there.
- Not seen, and reported as no limit: a limit set above the number of requests (20 by default, 50 at most), one per IP address that SiegeKit's single address does not reach, one that only slows answers, and one that answers 200 with no header (some apps return an error message in the body). The finding says so.
- URLs behind a login cannot be tested; the check fails with that reason. This is a coverage gap until a session can be passed (how many expensive endpoints need a login is not measured).
- On an app that answers every unknown page with 200 (a single-page app such as Juice Shop), a mistyped URL is reported as not limited (measured). The finding asks the user to check the URL.
- Only one URL per run; the user picks which endpoint is expensive.
- The check takes about one second per request (about 19 seconds by default).
- The CI gate runs it on Juice Shop's product search, which has no limit, so the gate expects the finding.

## Alternatives considered

- Medium severity for "no limit": not chosen (owner answer 7a); unlike logins, the harm depends on how expensive the URL is, which SiegeKit cannot see.
- Counting a slower answer as a limit, as `login-throttle` does: not in answer 7a; a search's time varies with load and results, which would give false "limited" results.
- Deployed targets with GET only now: not chosen until request limits are measured in M2.10 (answer 7a).
- Sending account A's session (`--har`'s headers or `SIEGEKIT_SESSION_B`) to test URLs behind a login: not in answer 7a; left for a later decision.
