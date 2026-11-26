# 0073. Rate-limit stops at a first redirect to a login page

- Status: Accepted (owner 2026-11-26 00:58Z, Porchlet R2 fix plan PR B: "go for it then"; one root fix, no options card)
- Date: 2026-11-26
- Amends: [0036](0036-rate-limit-check.md) (what a first answer may be), [0055](0055-rate-limit-pages.md) item 4 (the code page's first answer), [0049](0049-write-replay.md) (the write check's login-page test moves to `internal/webform`, unchanged)
- Related: issue [#94](https://github.com/Gobbuwu/SiegeKit/issues/94) (`from-porchlet`), ADR [0069](0069-reset-and-signup-page-forms.md) (guard G1)

## Context

Porchlet's R2 run (2026-11-26) pointed `rate-limit` at its invite page, a Next.js Server Action page that needs a session. Every one of the 20 requests was answered `307` to `/login?next=/w/<id>` by Porchlet's proxy, no request reached the form (0 invitations), and the check reported low `rate-not-limited`: a finding about a URL it never tested.

Root cause (read from the code at 05373ff, then reproduced): `ratelimit.Check` refused a first answer only for 401/403 ("needs a login"), 404/405/501 and 5xx. A 3xx to a login page became the baseline. Many web apps answer a request with no session with a redirect to the login page, not a 401, so the 401/403 rule missed the whole class. Guard G1 (ADR 0069) covers reset and sign-up pages only.

Reproduced through SiegeKit before the fix: on the gate's Next.js 16 app behind a login wall like Porchlet's (`.github/gate/logins/proxy.js`), main reported `rate-not-limited` after 20 × 307 for a POST and a GET; on Porchlet's own code (main df7df7c, local `next start`, the issue's exact command) main exited 3 with the same finding.

## Decision

1. At the first answer, `--rate-limit-url` and the code page stop with "the URL redirected to a login page (Location): it needs a login, which this check does not send; name a URL that answers without one" when the answer is a 3xx whose `Location` is a login page and the URL is not a login page itself. The check fails (exit 4 unless findings decide the exit), like the 401/403 rule; later answers are not sent.
2. A login page is `webform.LoginPage`: a segment of the path (not the query) is, or splits into, a login word (`login`, `logon`, `signin`, `auth`, `sso`, `oauth`, `oauth2`, `authorize`), in any case and with `-` or `_` inside. It is the test access-control-write already used for redirects (ADR 0049), moved to `internal/webform` so both checks share one rule. Here it is strict: an empty or unparsable `Location` is not a login page. The write check keeps its own "or nowhere" rule on top (`toLogin`), unchanged.
3. A URL that is itself a login page and redirects to a login page (a login form answered with `/login?error=1`) reached the app's login code, so that answer stays the baseline.
4. Reset and sign-up pages are not checked this way: their success may redirect to the login page (a sign-up's "now log in"), and guard G1 already holds back their "no limit" when no answer differed from the page's own GET.

Not taken: failing on every first 3xx (a form answered with 303 to its result is a valid baseline, as Gitea's web writes are, ADR 0049); following the redirect and reading the page (more requests for the same answer in the measured cases).

## Measured

All through SiegeKit; local: Claude cloud session, linux/amd64, Docker 29.9.3 rootful, cgroup v1, Node 22.23.5, go1.26.0, 2026-11-26.

| Target | main (05373ff) | This change |
|---|---|---|
| Gate Next.js 16.4.6 app, `/w/gate` behind `proxy.js` (307 to `/login?next=`), POST | ran, 20 requests, `rate-not-limited` | failed, 1 request, 0 findings, 0 invite runs |
| Same, GET | ran, 20 requests, `rate-not-limited` | failed, 1 request, 0 findings |
| Porchlet main df7df7c, `/w/<id>`, the issue's command | ran, 20 requests, `rate-not-limited`, exit 3 | failed, 1 request, 0 findings, exit 4 |
| Every other `logins` gate scan (12) | known answers | unchanged |

CI and the gate on rootless Podman and Docker, amd64 and arm64: see `docs/milestones/M2.md`.

## Consequences

- A URL behind a login wall that redirects is reported as needing a login, not as "no limit". `rate-limit` still sends no session, so a limit on an action that needs a login (Porchlet's invite cap) is not tested (`docs/coverage.md`).
- Not caught (gaps): a login page answered with 200 at the same URL (no redirect); a wall that redirects to a page whose path has no login word (`/`, `/welcome`); any URL whose own path has a login word (a code page at `/login/2fa`, an API under `/api/auth/`) that redirects to the login page, which item 3 keeps as the baseline.
