# 0057. Known answers for the reset, sign-up and code pages on Juice Shop, and no answer that depends on map order

- Status: Accepted (gate answers: design build plan, owner 2026-11-21; item 4's scope: owner card 2026-11-23, see below)
- Date: 2026-11-23
- Amends: [0055](0055-rate-limit-pages.md) (item 10: this is its PR 3), [0036](0036-rate-limit-check.md) (which header a limit is named by)

## Context

ADR 0055's design ends with the CI gate's known answers on OWASP Juice Shop: reset and code pages limited, sign-up not limited, on both engines (item 10, PR 3). Until now the Juice Shop gate lists `reset-limit`, `signup-limit` and `code-limit` as skipped: its hand-written `a.har` holds none of those pages. The `mail` job (ADR 0056) already runs `reset-limit` and `signup-limit` from flags on Gitea, so the flags path is gated; finding the pages in a real browser recording (ADR 0055 item 2) and turning their bodies into safe templates (item 3) is not.

While measuring this job's answer, 4 of 6 runs failed: the result named a different rate-limit header on each run.

## Decision

1. **A gate job `pages`.** Juice Shop v20.4.0 (the web job's image) runs under rootless Podman and under Docker. Playwright's Chromium (pinned, as in the `writes` job) records what a person would do before a scan (`.github/gate/record-juice-shop-pages.js`): sign up a new account, reset its password with the right security answer, and log in with a second factor as `wurstbrot`, the TOTP user Juice Shop seeds itself (`/juice-shop/data/static/users.yml` in the image). Each step must get its expected answer (201, 200, 200) or the job fails at the recording. SiegeKit then runs `--only reset-limit,signup-limit,code-limit --har a.har`, so the pages and bodies come from the recording, as an attacker maps them from the app's own traffic.
2. **The answer** (`testdata/known-answers/juice-shop-pages.json`): the reset and code pages are limited at the first request (every answer carries `X-RateLimit-Limit: 100`), the reset with no finding and the code page with `code-limit-high` (low; its `X-RateLimit-Reset` window is at most 300 s, so more than 100 wrong codes a day, ADR 0055 item 5); the sign-up answers 201 to all 20 and reports `signup-not-limited` (low). The job also requires each check's input to name the recorded page and its result text, as the other gate jobs do.
3. **The gate reads the app itself.** After the recording the gate changes the new account's password a second time, so the recorded new password no longer works. After the scan it requires 20 `siegekit-new-...@example.com` accounts in Juice Shop's user list, the recorded new password to be refused (401) and the gate's own to work (200): the scan neither sent the recorded answer and new password again (ADR 0055 item 3) nor changed the account. Checked: sending the recorded reset by hand after a run turns both around (200 and 401), so the gate fails.
4. **No output from Go's map order.** `ratelimit.Signal` named the first rate-limit header it met while ranging over the answer's header map, whose order Go changes on each run, so Juice Shop's answers were named by `X-RateLimit-Limit`, `-Remaining` or `-Reset` at random. It now takes the names in sorted order. A scan of every `range` over a map that returns or breaks inside the loop (a throwaway `go/types` walk, 18 places) found 5 more whose answer depends on the order: `authz.ActionReason`'s and `lockoutReason`'s reason when a query has two matching parameters, `csrfValue`'s token when a recorded write holds two CSRF-named headers or JSON fields with different values (the only one that changes what is sent), and the first error `sandbox.CheckEnv` and `knownanswers` report when several entries are wrong. All now read keys in sorted order; the other 12 return a yes or no that every order gives alike, or break only an inner loop. Scope: the owner's card of 2026-11-23 (fix all 6 here, recommended, or only the measured one).
5. **Not in this job.** `login-spray` (Juice Shop locks no account, so it is skipped; measured on Mattermost, ADR 0055) and the web job's checks; the web job keeps its answers, with the three page checks skipped for want of pages in its `a.har`.

## Evidence

Environment for every local measurement: Claude's sandbox, 4 CPUs, cgroup v1, Go 1.26.0; Docker 29.10.0 rootful and Podman 4.9.3 rootless (netavark); Juice Shop v20.4.0 (`bkimminich/juice-shop@sha256:9bbaecc4…`); Playwright 1.63.0 and its Chromium. The job's steps were run from `gate.yml` itself by a local runner (from "Start Juice Shop" on, with the built binary), each run on a fresh app and a fresh recording.

| Claim | Backed by |
|---|---|
| The answer holds on both engines | 6 runs after the fix of item 4: app on Docker 3 times and on rootless Podman 3 times; every run met `juice-shop-pages.json` and every assertion of the job; requests 1, 20 and 1 each time; scan 19 s each time. |
| The recorded pages are found and kept safe | Each run: inputs `POST .../rest/user/reset-password`, `POST .../api/Users/` and `POST .../rest/2fa/verify` `(recorded in a.har)`; afterwards the recorded new password answered 401 and the gate's 200, and 20 accounts named `siegekit-new-...` were in the user list. |
| The password check catches a replayed reset | After a run, the recorded reset body sent by hand answered 200; then the recorded password answered 200 and the gate's 401 (the job's test would fail). |
| The header was named at random | Before the fix, 4 of 6 runs failed the job's result check: `-Reset` and `-Remaining` named instead of `-Limit` (runs on Docker and rootless Podman). `TestSignal` (200 calls on Juice Shop's three headers) fails on the old code and passes now. |
| The 5 other places | `TestSameAnswerEachRun` (`ActionReason`, `lockoutReason`, `csrfValue` of headers and of JSON), `TestEngineArgsEnv` and `TestLoadSameErrorEachRun`: each fails on the old code (each case checked separately) and passes now. |
| The code page's window | 4 min 40 s to 4 min 41 s on every run (the recording's login started it, ADR 0055 item 5), 30,747 or 30,857 wrong codes a day; the finding is the same for any window under 24 hours. |
| The gate on cgroup v2 | CI (filled in from this PR's gate run). |

## Consequences

- The three page checks, the recording rules and the reset template are now tested on a real app on every change to SiegeKit's code. The web job is unchanged; the new job runs beside it and adds 19 s of scanning (1.0 item 3 allows about 77 s).
- Each run makes 21 accounts in the job's own Juice Shop and nothing outside the runner.
- A result names the same header, reason or error for the same answer on every run, so known answers can compare them exactly.
- Juice Shop's seeded 2FA user and secret are part of the fixture: a Juice Shop update that changes them fails the recording step, not the answer.

## Alternatives considered

- Adding the pages to the web job's `a.har`: `zap-active` attacks every recorded request, so it would also attack the reset, sign-up and 2FA requests, change its own known answers and run longer in a job that already takes up to 40 minutes; the 20 new accounts would also be in `access-control`'s user-list reads.
- The pages from flags (`--reset-url` and the others): the `mail` job already gates that path; the recording path was the one not gated.
- Matching the gate's text on any of the three header names: hides the cause, which is the unordered loop.
