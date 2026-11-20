# 0035. The access-control check: replaying a recording as another account

- Status: Accepted
- Date: 2026-11-20
- Amends: [0011](0011-app-logic-and-ai-checks.md) item 1 (how requests are found, what is replayed, what counts as a finding)

## Context

ADR 0011 item 1 plans a two-account test: crawl as account A, replay each request as account B and with no login, and report answers that come back with the same data. It left open where the requests come from, how B's session is given, and what "the same data" means. The owner answered the M2.7 design questions on 2026-11-20 ([design](https://claude.ai/artifact/UjmsK3MmQ4btjaPg5427ar)): first "i want the claims to be measured before making a decision", then, after the measurements below, "since they're all backed by tests and proven working, let's go with them" (answers 1a to 9a). This ADR records answers 1a to 6a; 7a (rate limits) and 8a (live backend rules) get their own ADRs with M2.7b and M2.7c (answer 9a).

Measured before the decision (2026-11-20, local OWASP Juice Shop v20.4.0, the CI gate's image):

- **Crawling as A does not work on a single-page app.** ZAP's AJAX spider given A's `Authorization` header and cookie found 361, 3,227 and 2,859 URLs in three runs, and none of the 4 requests that leak data between accounts: the app stayed logged out. ZAP's Access Control add-on is not in the pinned `zap-stable` 2.17.0 image.
- **A naive rule is noisy.** 17 GET requests replayed as A and B: "B gets the same answer as A" matched 11, of which 4 were real leaks (`/rest/basket/{id}`, `/api/Users/{id}`, `/api/Users`, `/api/Complaints`). Adding "a request with no login is refused" and "the answer holds data" matched exactly those 4. "No login gets 200" matched 6, all public by design.
- **Similarity scores cannot separate them**: all 11 equal answers were byte for byte identical, so the rule compares bytes.

## Decision

1. **`access-control`** is SiegeKit's own check (ADR 0015), family `dast`, for URL scans, in `internal/authz`.
2. **Requests come from a recording** (answer 1a): `--har FILE`, a HAR file the person records in their browser while using the app as account A (at most 64 MiB, a regular file). SiegeKit keeps the GET and HEAD requests to the target's origin, in order, without duplicates and without static files (scripts, styles, images, fonts, media), at most 100. It keeps their headers except those the transport or browser owns (`Host`, `User-Agent`, `Content-Length`, connection and transfer headers, `Accept-Encoding`, cache validators, `Sec-*`, `Proxy-*`, HTTP/2 pseudo-headers). Requests on other origins, other methods, duplicates and those over the limit are counted in the result. When an OpenAPI spec is available (`--openapi`, or found at a default path on local targets, ADR 0025), its JSON GET routes without path parameters are added under its base path, with A's session headers from the last recorded request that has any. YAML specs add none.
3. **Account B's session** (answer 2a) comes from the environment variable `SIEGEKIT_SESSION_B`: one `Name: value` header per line, at most 8 KiB, such as `Authorization: Bearer ...` and `Cookie: token=...`. It cannot set `Host`, `User-Agent` or the other headers above. Without it, only requests with no login are tested, and the plan and result say so. Mistakes in the HAR file or the variable are refused before any lookup or request.
4. **What is sent** (answer 3a). Only GET and HEAD, on every target including deployed ones and in `--profile quick`, so no confirmation is asked beyond the target's own. Each request goes first as A (as recorded). If A does not get a 2xx answer, nothing more is sent for it. Otherwise it goes as B (A's headers without the session headers, `Authorization`, `Cookie`, `X-Api-Key`, `X-Auth-Token`, `X-Access-Token`, `X-Session-Token` and any header B sets, plus B's headers) and with no login (A's headers without the session headers). SiegeKit sends them itself from the host to the pinned address (`egress.SendHeader`, read-only, no redirects followed, at most 2 MiB per answer), one at a time at the run's request rate (100 per second local, 10 deployed). At most 300 requests.
5. **When B can read A's data** (answer 4a): B's answer has the same 2xx status and the same bytes as A's, the request with no login was refused (401, 403 or a redirect), and the answer holds data. A JSON answer holds data when, outside the keys `status`, `message`, `msg`, `result`, `error`, `code`, `ok` and `success`, it has a non-empty array, a non-zero number, `true` or a non-empty string; any other non-blank answer holds data. Finding `cross-account-read`, **high** (answer 5a), CWE-639 when the URL holds an ID (a number, a UUID or 16 or more hex digits) and CWE-862 otherwise.
6. **When anyone can read A's data** (answer 6a): the request with no login gets A's exact answer, it holds data, and it contains A's login name, given with `--har-user NAME` (any case). Without `--har-user` this is not reported, and the result says so. Finding `no-login-read`, **high**, CWE-306.
7. **Reports.** Findings are at the request's URL without its query. Messages give the method, path, status and size, never the answers' content or any header. The plugin entry gives `input` (the HAR file's name, the number of recorded requests, the spec's routes, whether B was given) and `result` (requests replayed, how many each rule reported, and the counts of what was not replayed). A result where B was refused on every request suggests B's session has expired.
8. Like the other URL checks it runs only on Linux for now (ADR 0018).

## Evidence for the check as built

- Unit tests (`internal/authz`): HAR and session parsing, the data rule, IDs, the check against a test server shaped like Juice Shop (a basket any account reads, a user list, answers that differ per account, an empty list, a public list, a profile readable with no login), B refused, cancellation, spec routes; `FuzzParseHAR` in CI. The test app (`internal/runner`) gets an order any logged-in account can read, an order that checks its owner, orders that differ per account and a profile readable with no login; `TestAuthzFindsPlantedIssues` reports exactly the two planted issues.
- Measured on local Juice Shop v20.4.0 with the built check (2026-11-20, two new accounts; record in the project's shared files, `access-control-measurement-2026-11-20.md`):
  - **A HAR recorded in Chromium with Playwright 1.63.0** while A logged in, filled the basket, saved an address and a card, and opened 16 pages: 28 requests replayed, 80 sent. Reported 1, true (`/rest/basket/7`, A's basket).
  - **A hand-made HAR of 20 API requests:** 60 requests sent, 1.2 seconds. Reported 5, all true (`/rest/basket/7`, `/api/Users/26`, `/api/Users`, `/api/Complaints`, `/api/BasketItems`).
  - **The CI gate's setup** (a fresh container, two new accounts, a hand-made HAR of 10 requests): 30 requests sent, 4 reported, all true (A's basket, A's user record, the user list, the complaints). A's new basket is empty but still reported: B reads its record, with A's user ID. The gate expects exactly these 4.
  - Every replay of the first two runs was labelled by hand: 6 reported, 6 true, 0 false. Not reported, and correct: answers scoped per account (addresses, cards, profile, whoami), empty answers for both accounts (order history, wallet), a 400 for no login on a public price, and public lists. One miss: `/rest/memories/` gives anyone every memory's full user record, password hashes included, but it does not hold A's login name (rule 6). The labels are Claude's; nobody else checked them.

## Consequences

- Access control gets an automated check for the first time; without `--har`, it is not tested, and the report's "Not tested" list says so.
- **Not covered:**
  - requests the recording did not make: in the browser run, the user list, complaints and basket items were never requested, so 4 of the 5 leaks found from the hand-made list were not tested;
  - IDs other than the recorded ones (no guessing of other users' IDs), and OpenAPI routes with path parameters;
  - state-changing requests (POST, PUT, PATCH, DELETE);
  - answers that change on every request (timestamps, tokens), which never match byte for byte;
  - data readable with no login that does not hold A's login name, such as other users' records (the `/rest/memories/` miss above);
  - leaks between roles when B's answer differs from A's even though B should get nothing.
- The person must record a HAR and give B's session, which needs two test accounts they own (as ADR 0011 said). A HAR holds A's session; SiegeKit only reads it, but the file should be deleted after use. `docs/agents.md` tells AI assistants this.
- A short public answer that both accounts get and that a request with no login is refused (for example a price shown only to logged-in users) would be reported. The sample had none.
- The labels come from one reviewer on one app. False-positive rates on other apps are unmeasured; the M2 milestone check triages again.

## Alternatives considered

- **Crawling as A with ZAP's AJAX spider:** found none of the 4 leaks on Juice Shop in three runs (measured above).
- **"B gets the same answer" alone:** 11 reported, 4 real, in the design measurement.
- **Similarity scores instead of equal bytes:** the equal answers were identical, so a score adds nothing and allows false matches.
- **ZAP's Access Control add-on:** not in the pinned image, and it needs ZAP contexts and users set up by hand.
