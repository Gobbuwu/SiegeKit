# 0048. Access-control replay skips GETs that name an action

- Status: Accepted (owner picked "Skip action-named URLs, both modes" on 2026-11-21, 22:06 UTC, after all four options were measured)
- Date: 2026-11-21
- Amends: [0035](0035-access-control-replay.md) (what is replayed)

## Context

ADR 0035 replays the GET and HEAD requests of account A's browser recording as A, as account B and with no login, on every target including deployed ones, on the assumption that a GET changes nothing. The item 2 design work (2026-11-21) noticed that Juice Shop changes a password with a GET. Measured on 2026-11-21 (project file `get-replay-safety-2026-11-21.md`; Docker rootful in the sandbox; the check is plain Go HTTP and does not use the engine):

- Real browser recordings made with Playwright: Juice Shop v20.4.0 (login, basket, search, 18 pages, change password through the form, log out) and Gitea 1.24.6 (login, new repository, new issue, 40 pages). Each GET that `ParseHAR` kept was replayed by the shipped `Check`, one at a time, and the app's whole SQLite database was diffed around it.
- Juice Shop, 35 replays: `GET /rest/user/change-password?current=…&new=…&repeat=…` answered A and B with 200 and **changed account B's password** (B's old password then answered 401, the recorded new one 200). `GET /rest/saveLoginIp` changed B's last-login IP. `GET /rest/captcha/` added captcha rows, and `GET /rest/basket/6` made Juice Shop mark its own "view another basket" challenge solved.
- Gitea, 56 replays: no database or file change (every write in the session was a POST with a CSRF token).

The owner chose between four options, each measured on both recordings, the CI gate's 12 GETs and, for false skips, the 229 GET operations of Gitea's API spec (held out: checked after the word list was fixed):

| Option | Stopped user-data changes | Findings lost | Wrong skips | Cost |
|---|---|---|---|---|
| Skip GETs whose URL names an action (chosen) | 2 of 2 | 0 | 1 of 91 recorded (a Gitea form page), 0 of 12 gate, 0 of 229 held out | none per run; a write with no action word in its URL still gets through |
| Skip GETs with a query string | 1 of 2 (misses `saveLoginIp`) | 0 | 21 of 91 recorded, 1 of 12 gate (the product search) | fails the main case |
| No replay on deployed targets | 2 of 2 on deployed, 0 local | every deployed finding | all | local scans still change data |
| The person reviews the URL list each run | depends on the reader | depends | depends | 35 to 56 URLs to read per run; a typed answer can be given by a program (ADR 0044) |

## Decision

1. **The rule.** A GET or HEAD is not replayed when, after splitting its path segments (percent-decoded) into words of ASCII letters at every other character and at camelCase boundaries, a word is on SiegeKit's list of 97 action words (such as add, change, create, delete, logout, remove, reset, save, update; `internal/authz/action.go`); or a query parameter named `action`, `do`, `cmd`, `op` or `operation` has such a word in its value; or a query parameter name holds `pass`, `password`, `passwd`, `pwd` or `secret`. Nouns that name read pages more often than actions (order, archive, sort, login, new, read, set, star, watch, close, send) are not on the list: in the first measurement they skipped only read pages.
2. **Where.** In both local and deployed modes, in `ParseHAR` (recorded requests) and `AddSpecRoutes` (routes from an OpenAPI spec). `Check` refuses a request that names an action, as a backstop.
3. **Report.** The check's summary counts them as not replayed and names the first 5 paths, without their query (a query can hold a password). A recording whose GETs all name actions skips the check with cause `no-input`, saying how many were left out.
4. **Not changed.** `zap-active` (local only, destructive, confirmed by the person) still gets every recorded request (ADR 0047).

## Consequences

- With the rule, the same Juice Shop replay (33 requests, re-recorded) left B's password unchanged (B's original password still answered 200). Juice Shop still wrote captcha rows and its challenge table.
- **Not covered:**
  - a GET that changes data with no action word in its URL (such as `/rest/captcha/`), or with the word only in a form other than the listed ones;
  - access-control findings on a URL that names an action (none in the measurement);
  - the other GET senders on deployed targets (the `zap` spider, `ffuf`, `nuclei`) send requests without a login to links or fixed paths, not to recorded action URLs; whether they reach GETs that change data is not measured here and is logged for the M2 milestone check.
- The word list was measured on two apps; how often it misses or skips wrongly on other apps is unverified.

## Alternatives considered

The other three options in the table above.
