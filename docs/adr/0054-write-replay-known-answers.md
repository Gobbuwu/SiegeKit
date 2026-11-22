# 0054. Known answers for the write replay in CI, and IDs replaced by their place

- Status: Accepted (CI known answers: M2 queue item, coordinator 2026-11-22; the CI options card: see Decision 4)
- Date: 2026-11-22
- Amends: [0049](0049-write-replay.md) (item 2a: where a copy's ID replaces the recorded one; item 2d: which earlier writes name the object), [0039](0039-known-answers-and-engine-parity.md) (a run that starts no container has no engine)

## Context

`access-control-write` (ADR 0049) was measured by hand on real apps, but CI checked it only on SiegeKit's test app: nothing would fail if a change made it miss Juice Shop's write flaws or raise false alarms on Gitea. ADR 0039 asks for known answers from complete runs, on both engines.

Measuring the first known answer found a bug. Environment: Claude's sandbox, Docker 29.10.0 rootful, cgroup v1, a fresh Juice Shop v20.4.0 (the gate's image) with three accounts, a Chromium recording of account A (Playwright 1.63.0), the CLI with `--only access-control-write`. When B and C logged in before A, A's basket was 8, and the address A made during the recording was 8 too. The checkout is `POST /rest/basket/8/checkout` with `"addressId": "8"` in its body. SiegeKit linked it to the address create (item 2a), made a copy (ID 15) and replaced every 8 in the request, so C and B were sent to `/rest/basket/15/checkout` ("Basket with id=15 does not exist", 500), and the earlier steps (item 2d) were dropped because the basket's 8 was taken as the copied ID. B's and C's checkout of A's basket, a real high (checked by hand: C's checkout of basket 8 was accepted), was missed. Per-table numbers collide all the time, so the cause is the rule, not this app: an ID was matched and replaced by its value alone.

The same rule changed Kanboard's `moveTaskPosition`: `project_id`, `column_id` and `swimlane_id` (all 1) were replaced along with `task_id` (1) by the task copy's ID (scripted JSON-RPC HAR, Kanboard v1.2.48; B was refused either way, so the result did not change).

## Decision

1. **Each place an ID sits has a noun** (`internal/authz/write_ids.go`): a path segment takes the nearest segment before it that is not an ID (`/rest/basket/8` is a basket), a query value or body key takes its key's last word that is not an ID word (`addressId` is an address; `id`, `_id` and `number` have none). A create's noun is its path's last segment that is not an ID (`POST /api/Addresss/`), or a method call's last word (`createTask`). Nouns match in the singular or plural (`address`, `addresses`, Juice Shop's `addresss`; `category`, `categories`).
2. **A copy's ID replaces only the places that name the create's kind** when some place in the write does; places with no noun (`"id"`) are replaced too. When no place names that kind, every place holding the value is replaced, as before (Rocket.Chat's `chat.update` names a message as `msgId`).
3. **Linking and earlier steps use the same nouns.** A create that a place names by kind wins over one that only shares the number (+500 over the shared path segments). The path IDs the copy does not replace are the ones earlier steps are looked for (item 2d); when an earlier write names such an ID under the path segment's noun (`BasketId`), writes that hold the number under another noun (`ProductId`) are not steps. Among several hits in one body, the noun match and then the smallest ID is taken, so map order cannot pick it.
4. **CI known answers** (`gate.yml`, job `writes`): on every change to SiegeKit's code, account A is recorded in Chromium (Playwright 1.63.0 and its own Chromium build, pinned with integrity hashes in `.github/gate/package-lock.json`, install scripts not run) on two real apps, and the scan runs `--only access-control-write` with accounts B and C, typing both confirmations through a pseudo-terminal (ADR 0044):
   - Juice Shop v20.4.0 (the web job's image), the recording of ADR 0049's measurements (`.github/gate/record-juice-shop.js`): basket, address, card, review, feedback, checkout. Known answer `testdata/known-answers/juice-shop-writes.json`: 6 high and 4 medium, all real flaws (ADR 0049), exact.
   - Gitea 1.24.6's web UI (`.github/gate/record-gitea.js`), the setup of ADR 0051: alice's private repository, bob a collaborator, carol outside. It covers CSRF tokens swapped for the sender's own (item 7) and a sender refused on every write (C). Known answer `gitea-writes.json`: bob's 3 writes, allowed by design, low; nothing else.
   - The recorder fails the job when any step of the recording fails, so a changed app fails at the recording, not in the answer.
   - The check runs in SiegeKit's own process and starts no container; the matrix runs the app under rootless Podman and rootful Docker.
5. **A run with no container has no engine** (`knownanswers.EngineOf`): when every check in the report is SiegeKit's own (`tool` `siegekit`), the answers are compared with no engine (a `byEngine` answer never applies); any other report without an engine is still refused (ADR 0038).

## Evidence

| Claim | Backed by |
|---|---|
| The checkout is found again when IDs collide | Same recording as Context, after the fix: C's and B's checkout sent to `/rest/basket/8/checkout` with the address copy's ID in the body, both accepted, high; 3 earlier basket items sent before each replay; 6 high, 4 medium, 295 requests. `TestWriteCheckIDCollision` (basket 5 and address 5, plus a later card 5 and a wish naming product 5) fails on the old rule. |
| Mutations caught | Each fails a test: copy replaced everywhere (no noun), noun bonus in linking removed, steps without the noun filter, path IDs skipped by value. |
| Other apps' links do not change, except the collisions | Offline, the same recordings parsed by `main` (811fc1a) and by this branch, every write's create, sent path, body and steps compared: Gitea web (12 writes), DVGA (2), Rocket.Chat 6.13.1 (3, `updateMessage` on `sendMessage`), Mattermost 12.0.2 (5) identical; Juice Shop: only the colliding checkout; Kanboard: only `moveTaskPosition` (above). The Wiki.js 2 recording lost the create's answer body (the known Playwright HAR issue of ADR 0050's record), so it has no link to compare; GraphQL creates take the noun `graphql`, which no place has, so they keep the old rule (`TestWriteCheckGraphQL`, `TestParseWritesGraphQLBatch`). |
| The Chromium recording gives the same answer every time | 10 fresh Juice Shop containers in the gate's account order (Docker 29.10.0 rootful, cgroup v1): every run 14 recorded writes, 17 tried, 295 requests, the same 9 findings (10 before merging), 75 to 76 s per recording. Gitea: 36 requests and the same 3 low findings on every run. |
| A scripted HAR would give the same Juice Shop answer | A HAR written with curl from the same API requests and their answers (no browser): the same findings and 295 requests, in 3 s. It has no Socket.IO polling entry, the browser's headers or its extra reads. |
| Rootless Podman | Podman 4.9.3 rootless (cgroup v1, netavark) running the app: see the record. |
| CI | The gate of this PR: see the record. |

Labels ("real", "allowed by design") are Claude's, from ADR 0049's and ADR 0051's checks against each app's database; nobody else checked them.

## Consequences

- A change that makes the write replay miss Juice Shop's flaws, raise one on Gitea, or do less work (requests below 90% of the fewest measured) fails CI.
- CI gets four more jobs (two apps, two engines) and a pinned npm package and browser build; their time is in the record.
- An abbreviated key that names the copy's object while another place names it in full (`msgId` beside `/messages/5`) keeps the old ID: the copy and the body then disagree. Not measured on a real app.
- GraphQL and method-call apps (Wiki.js, DVGA, Rocket.Chat, Kanboard, Mattermost) are not in CI; their write replay is covered by unit tests and the local measurements of ADR 0049 to 0051.

## Alternatives considered

- **A scripted HAR instead of a browser recording**: same Juice Shop answer, 3 s instead of about 75 s and no npm package; it does not test what only real recordings hold (Socket.IO polling, browser headers, the reads the browser makes, which drive the tries of item 2c). See Decision 4 for the owner's choice.
- **Writes added to the web job's hand-made HAR**: zap-active also attacks the recording's requests (ADR 0047), so its known answer would change and its attacks on A's writes would run after the write replay in the same job; a separate job keeps each answer about one check.
- **Value replacement with a closer path match only** (the fix for the address and card both being 7, ADR 0049): it cannot tell the basket in the path from the address in the body.
