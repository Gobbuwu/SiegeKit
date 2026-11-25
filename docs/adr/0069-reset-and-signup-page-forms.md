# 0069. Reset and sign-up pages given as their forms, limits seen in the redirect, and a guard that the requests reached the app

- Status: Accepted (owner 2026-11-25 00:54 UTC, Porchlet R1 fix plan PR B: "All recommended picks" on the plan's card, after every option was measured through SiegeKit)
- Date: 2026-11-25
- Amends: [0055](0055-rate-limit-pages.md) (item 1: how a reset or sign-up page is given; items 5 and 6: what the "not limited" findings need and say), [0056](0056-mail-catcher-count.md) (an email that arrived also shows the requests reached the app), [0062](0062-form-logins.md) (its form reader moves to `internal/webform`, shared with these pages)
- Related: issue [#81](https://github.com/Gobbuwu/SiegeKit/issues/81) (from Porchlet's R1 run), [0057](0057-page-checks-known-answers.md) (the pages' known answers)

## Context

Porchlet's R1 run (2026-11-24) reported `signup-not-limited` ("up to 20 accounts were made") and `reset-not-limited` on Next.js Server Action pages while the app's actions never ran. Reproduced on a local fixture (Next.js 16.4.6): the urlencoded body with the page's `$ACTION_ID_…` field gets the page back (200) and the action runs 0 times. The causes, at 6d110a7:

- `ParsePage` took only a JSON or urlencoded body, and `Check` sent it as is: no page read, no multipart, no Origin, no cookie. A Server Action runs only on the browser's multipart post; a CSRF-token form (Gitea, Django) needs the page's token and cookie.
- `Check` read status, headers and limit words, never `Location`. The fixture's own limit shows only in the redirect: 10 × `303 /signup?notice=check-email`, then `303 /signup?error=too-many-attempts`, all 303.
- `pageFindings` reported "not limited" from answers below 400 alone, with nothing showing the requests reached the app's code.

The fix plan measured three guards (G1 shape or email, G2 email required, G3 none) and two ways to read the redirect through SiegeKit on the fixture, Gitea 1.24.6 and Juice Shop (record: `porchlet-r1-fixes-2026-11-24.md`, round 2, Q2, in the project files). The owner chose G1, the page form, and `Location` on 3xx only.

## Decision

1. **`--signup-page URL` and `--reset-page URL`** give the page whose form SiegeKit sends, instead of `--signup-url` / `--reset-url` (not both, refused before any request). The page is on the target's origin and may have a query. `--signup-body` / `--reset-body` then name the form's fields as a form body (`email={new}%40example.com&password=...`), `{new}` and `{wrong}` in values only, each field once; a JSON body is refused with an example. There is no `--code-page`.
2. **How the form is sent.** Before each request SiegeKit GETs the page with no cookie (`Accept: text/html`), reads its form with ADR 0062's reader (now `internal/webform`, shared with `login-throttle`), fills the named fields, and posts it as the browser does: the form's action, method and encoding (multipart with `$ACTION_*` fields for a Server Action), the page's cookies, the target's `Origin`. The first page read must answer 200 and have a form SiegeKit can send, or the check fails with the reason. Later, a 429 or a limit header on the page read is a limit; another status, or a limit word the first read did not have, is a limit; a 5xx fails the check.
3. **Limits seen in the redirect (3xx only).** A reset's or sign-up's 301, 302 or 303 to the target's origin is followed once with a GET, as a browser does (ADR 0062 item 4). With the same status as the first answer, a different `Location` (the request's own `{new}` and `{wrong}` values put back, random values left out) is a limit, and so is a limit word on the followed page that the first one's did not have. `Location` on any other status is not read: Juice Shop's `201 Location: /api/Users/27`, then `/26`, read as a false limit after 3 (measured), which hid a true finding.
4. **Guard G1: the requests must be seen to reach the app.** For a reset or sign-up, SiegeKit compares each answer with the page's own answer to a GET (one GET of the URL when the body is sent as is; the first page read in page mode): status, redirect, and the names of the cookies it sets. An answer below 400 that differs in status or redirect, or sets a cookie the page did not, shows the requests reached the app; so does any email at the mail catcher (`--mail-catcher`). Without either, no "not limited" finding is reported, and the result says why and names `--mail-catcher` and the page flag.
   - A cookie the page set that the answer does not set again is no difference: the form was sent with it (Gitea's answer to its own form sets neither of the page's `_csrf` and `i_like_gitea`, measured). Counting it made a post the app ignores read as reached in the unit fixture.
   - An answer of 400 or more is no proof: a CSRF check refuses before the app's code runs. Measured on Django 5.2.8's `PasswordResetView` (CSRF on): `--reset-url` got 20 × 403 against the page's 200 and 0 emails, and the first build reported `reset-not-limited` with "SiegeKit knows they reached the app"; now no finding, and the result points to `--reset-page`, which sends the token and gets the true finding (20 × 302, 20 emails).
5. **Results.** The finding says how SiegeKit knows the requests reached the app (the differing answer, or the emails). A sign-up says "up to N accounts may have been made" (was "were made"). The report's `requests` counts every request (page reads, the guard's GET, redirects followed), and `input` names the form's action, encoding and button.

## Consequences

Measured through SiegeKit on 2026-11-25 (Go 1.27.4, Docker 29.9.3 rootful, cgroup v1, amd64), against the record's G1 column; every case agrees:

| Case | Truth | Result |
|---|---|---|
| Fixture `formAction` sign-up, raw urlencoded (R1's case), with and without Mailpit | 0 action runs | no finding, "cannot tell" |
| Fixture reset, raw (R1's case), with Mailpit | 0 runs | no finding |
| Fixture sign-up, `--signup-page` with Mailpit | limit at 11 | limited after 11 (redirect), 10 emails |
| Fixture reset, `--reset-page` with Mailpit | limit at 6 | limited after 6, 5 emails |
| Fixture `useActionState` sign-up (200, no limit), page, no Mailpit | 20 runs | no finding (missed) |
| same with Mailpit | 20 emails | finding |
| Gitea 1.24.6 sign-up raw / page, no Mailpit | 20 accounts | no finding (missed) |
| Gitea sign-up raw / page with Mailpit | 20 emails | finding |
| Gitea reset page with Mailpit, fresh user | 1 email for 20 | "the app limits these emails", no finding |
| Juice Shop v20.4.0 `POST /api/Users` JSON | 20 accounts | finding (201 against the GET's 401), no false limit from `Location` |
| Django 5.2.8 reset, raw (403) / page | 0 / 20 emails | no finding / finding |

- R1's false findings on Server Action pages are gone, and those pages can now be tested with the page flag.
- A sign-up or reset that answers like its page (the `useActionState` form, Gitea's 200s) gives no finding without a mail catcher: a missed finding, never a false one. The result names the way to test it.
- A reset that answers every request with 401 (a wrong security answer) is no longer proof without a mail catcher.
- The guard's GET goes to the URL the check posts to, which may be an API route with no page: Juice Shop answers `GET /rest/user/reset-password` with a 500 and logs it (CI, 2026-11-25). The page checks run on local targets only (ADR 0055).
- Each request costs one or two more: the guard's GET (21 for a body sent as is), and in page mode a page read per request and the redirect followed (Gitea: 40; the fixture's sign-up: 33).
- Not tested: forms built only by JavaScript, a form that is not the first with the named fields, pages behind a login, and code pages (no `--code-page`, no guard: a code page whose posts the app ignores can still give a false `code-not-limited`).
- A raw post that an app ignores but answers with a different redirect or a new cookie (an app that redirects every unknown post to its login page with a new session) would read as reached. None was seen in the five apps measured.
- The CI gate holds known answers for the fixture's six scans (`logins` job, emails counted at Mailpit for each action run) and Gitea's page forms with the mail catcher (`mail` job). Django is measured locally only.

## Alternatives considered

- G2, an email required: misses Juice Shop's JSON sign-up (no email) and every app without a mail catcher.
- G3, no guard: keeps R1's false findings (fixture raw sign-up and reset).
- `Location` on every status: the false limit on Juice Shop (item 3).
- A status difference at any status counting as reached: the Django false finding (item 4).
- Any cookie-name difference counting as reached: an ignored post sent with the page's cookies reads as reached (item 4).
