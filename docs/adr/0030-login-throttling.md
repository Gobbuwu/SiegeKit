# 0030. The login throttling check

- Status: Accepted
- Date: 2026-11-20
- Amended by: [0055](0055-rate-limit-pages.md) (spraying), [0062](0062-form-logins.md) (logins that are page forms, the right-password guard, limits seen in the redirect, what "no limit" claims and the 20-attempt floor)
- Amends: [0010](0010-login-checks.md) (deployed mode, how the login is given, what counts as a limit), [0029](0029-check-selection.md) (what `--profile quick` leaves out)

## Context

ADR 0010 adds a check of whether an app limits failed logins: SiegeKit sends logins for a test account the user owns with a random wrong password (20 by default, 50 at most, at most one per second). It left open how the user gives the login and what counts as a limit, and allowed deployed targets with `--allow-destructive login-throttle`. ADR 0025, decided later, keeps deployed targets GET and HEAD only, with no `--allow-destructive` before M2.10. The owner answered the M2.6 design questions on 2026-11-20 ([design](https://claude.ai/artifact/62fVx5n5HBpLwfWXEwQ2mB), answers "1a 2a 3a"; question 6, the split into three pull requests, "split ok").

Measured on 2026-11-20 with OWASP Juice Shop v20.4.0 (the CI gate's image): 20 logins for `jim@juice-sh.op` at `POST /rest/user/login`, one per second, each answered 401 "Invalid email or password.", with no change in status, words or time.

## Decision

1. **The login** is given with three flags, all or none: `--login-url URL` (on the target's origin, without a query or fragment, ADR 0005), `--login-user NAME` (at most 256 bytes, no control characters) and `--login-body TEMPLATE` (at most 8 KiB, containing `{user}` and `{password}`). The request is a POST. A body that starts with `{` is sent as JSON (`application/json`), with the values escaped as JSON strings; anything else is sent as a form, with the values URL-encoded. The body must be valid JSON, or a valid form, once filled in. `--login-attempts N` sets the number of logins, from 2 to 50, 20 by default. Mistakes are refused before any lookup or request. Directory scans refuse the flags.
2. **Where it runs.** On local targets only, until M2.10 (owner answer 2a). On deployed targets the check is reported as skipped; besides that, `egress.Send` and `login.Check` refuse a POST on a read-only (deployed) configuration. It is destructive, because it can lock the test account: on a loopback target it needs a typed `yes` or `--authorized-host`, as the attack tests do (ADR 0023), and the confirmation names the account. `--profile quick` leaves it out (amends ADR 0029). Without the login flags it is reported as skipped with the reason. Like the other URL checks it runs only on Linux for now (ADR 0018).
3. **How it runs.** SiegeKit sends the logins itself, from the host to the pinned addresses with the same transport as the proxy (`egress.Send`), with no redirects followed, reading at most 2 MiB of each answer. It runs before the other URL checks, so their traffic cannot trip a limit it would then report. Each login has a new random password, `siegekit-wrong-` and 20 random characters, so the app's logs show where it came from. Logins start at least one second apart. The password is never written anywhere.
4. **What counts as a limit** (owner answer 3a). The first answer is the baseline. A later answer shows a limit when it has status 429, 423 or 503, a `Retry-After` header, a status other than the baseline's, one of the words "captcha", "too many", "locked", "lockout", "try again later", "rate limit", "rate-limit" or "throttl" (any case) that the baseline did not have, or it took at least 3 times as long as the baseline and at least 1 second. A 429, 423, 503 or `Retry-After` already in the first answer counts too, and the result says so. The check stops at the first sign of a limit.
5. **When it cannot tell.** The check fails, with the reason, when the first answer is 404, 405 or 501 (wrong URL or method) or another server error (5xx), when the target does not answer, or when a later answer is a server error or does not come: a crash and a block of SiegeKit's address look the same from the host.
6. **Results.** When every login got the baseline answer, there is one finding, "Failed logins are not limited" (`login-not-limited`, CWE-307), **medium** severity (owner answer 3a), located at the login URL. The message names the number of attempts and says that a limit above that number, one per IP address, or one across many accounts is not seen. When a limit was seen there is no finding. Either way the report's plugin entry gives `input` (`POST URL as "NAME"`) and a new field, `result`, such as `limited after 6 of 20 attempts: answered 429` or `no limit seen in 20 attempts, all answered 401`.

## Consequences

- Login limits on deployed targets are not tested until M2.10; the report lists the check as skipped there.
- A limit set above the number of attempts (20 by default, 50 at most), a limit per IP address, or one across many accounts is reported as missing or not seen; the finding says so.
- Logins that are not one POST with a JSON or form body (a CSRF token fetched first, several steps, a request built in JavaScript) cannot be tested; the first answer usually makes the check fail with a reason.
- The test account may be locked. SiegeKit cannot unlock it; the plan and the confirmation say so.
- The check takes about one second per attempt (about 19 seconds by default).
- The CI gate runs it on Juice Shop, which has no limit (measured above), so the gate expects the finding.

## Alternatives considered

- A login file (`--login FILE`, JSON with URL, method, headers and body): offered, not chosen; flags are enough for AI assistants too.
- Deployed targets now, with `--allow-destructive login-throttle` and a single-URL POST allowance in the proxy: offered, not chosen until M2.10.
- Low severity for "no limit": offered, not chosen.
- Running the check as a container plugin: it needs no third-party tool, and its parsing is limited to a status, one header and a word search over at most 2 MiB, so it runs in the SiegeKit process like the spec lookup of ADR 0028.
