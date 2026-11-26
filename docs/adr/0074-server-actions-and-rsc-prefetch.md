# 0074. Server Actions, RSC prefetches and page noise in the access checks

- Status: Proposed (decision cards 1 and 2 posted 2026-11-26 in the thread "Build PR C"; this ADR follows the recommended options A5 and R3 until the owner answers)
- Date: 2026-11-26
- Amends: [0049](0049-write-replay.md) (item 1: when a write is accepted; item 3 and [0051](0051-outsider-account-c.md) item 2: the order of senders; item 6: the caps), [0035](0035-access-control-replay.md) (what is compared), [0007](0007-findings-format.md) (a finding's key can hold a variant; a merged finding keeps one finding's own text)
- Related: issues [#95](https://github.com/Gobbuwu/SiegeKit/issues/95) and [#96](https://github.com/Gobbuwu/SiegeKit/issues/96) (`from-porchlet`), threat model T26

## Context

Porchlet's R2 run (Next.js 16.4.6 and Supabase) gave a false high and 10 false mediums in `access-control-write` (#95) and a false medium in `access-control` (#96). Causes, each reproduced through SiegeKit:

1. **A refused Server Action answers 200.** Next.js answers a Server Action with 200 and the form's state whether it ran or not, so the 2xx rule (ADR 0049 item 1) accepted every refusal. Every Server Action of a page posts to the page's URL, so the writes of one page were also merged into one finding, and the merged finding paired one write's severity with another's message (the wrong "C may have expired" note).
2. **A page differs on every answer.** A Content-Security-Policy nonce and React's per-request IDs are new in every answer, so no answer was ever "the same as A's", and A's read of a page always "changed".
3. **A page streams in one of two layouts at random** (Porchlet's workspace page: 9,717 or 9,856 bytes on 8 reads by hand, for GET and DELETE alike).
4. **A page route answers any method with the page.** A DELETE on the workspace URL "was accepted" with the page.
5. **An RSC prefetch holds the route's layout, not its data.** The router's prefetch of `/w` is the same skeleton for every account, so C "read A's data".
6. **No login was sent after C**, and C's false acceptance stopped it (ADR 0051 item 2).

Records: `siegekit/pr-c-95-96/measurements.md` in the project files (gate runs [45738560116](https://github.com/Gobbuwu/SiegeKit/actions/runs/45738560116) and [45746228551](https://github.com/Gobbuwu/SiegeKit/actions/runs/45746228551), and the local Porchlet runs).

### Card 1: when is a replayed write accepted?

All options were measured through SiegeKit (a prototype build with the rule as a switch) on the gate's Juice Shop v20.4.0, Gitea 1.24.6 and a Porchlet-like Next.js 16.4.6 app (`.github/gate/logins`), on rootless Podman and Docker, amd64 and arm64: each set was identical on all 4. Porchlet itself ran on Docker 29.9.3 rootful, cgroup v1, amd64 only.

| Rule | Next.js app (4 true, 4 traps) | Juice Shop (18 true) | Gitea (B's 3) | Porchlet |
|---|---|---|---|---|
| A0 any 2xx (before) | 4 false, 4 true, 38 requests | 18 | 3 | 6 false mediums, 43 requests |
| A1 a Server Action needs A's Next.js success headers | 1 false, 41 requests | 18 | 3 | not run |
| A2 a write needs A's redirect-type header | 2 false, 40 requests | 18 | 3 | not run |
| A3 A's read changed | 0 false, loses the webhook, 103 requests | 12 | 1 | not run |
| A4 hybrid for every write: A's success header if A's answer had one, else A's read changed | 0 false, 4 true, 51 requests | 16 (loses PUT `/api/Products/1` as C and with no login: it replays A's own value) | 3 | 0, 47 requests |
| **A5 A4 for Server Actions, A0 for every other write** | 0 false, 4 true, 51 requests | 18 | 3 | 0, 52 requests |

A1 to A3 were dropped from the card after gate run 1: each is beaten by A4 or A5 on every app.

### Card 2: what proves C read A's data?

| Rule | Next.js app (2 true leaks) | Juice Shop (4 true) | Porchlet |
|---|---|---|---|
| R0 any non-blank body (before) | 7 false | 4 | the #96 medium |
| R1 an RSC answer needs non-structural content | 3 false | 4 | 1 false |
| R2 an answer without an ID needs a value of A's recording | 4 false | 3 (drops Complaints) | 0 |
| R2b every answer needs a value of A's recording | 0 false | 2 (drops basket and Complaints) | 0 |
| **R3 a router prefetch is not compared** | 0 false | 4 | 0 |

Every rule kept both Next.js leaks (the notes page and `/latest`'s RSC answer). R3 costs no request.

## Decision

1. **Accepted, for a Server Action** (a `Next-Action` header; A5): the 2xx rule, and one of the success headers A's recorded answer had (`x-action-redirect` not to a login page, `x-action-revalidated` not `0`, `Location`, `HX-Redirect`, `HX-Location`, `Refresh`). When A's answer had none, A reads the page the action posts to (a recorded GET of its path, not an RSC request) before and after, and the replay is accepted only when that read changed; with no such page, or a page that cannot be compared, the 2xx rule. Every other write keeps ADR 0049 item 1.
2. **A router prefetch is not compared** (R3): a GET with `RSC: 1` and `Next-Router-Prefetch: 1` is replayed but never a finding, and the result counts them. In Next.js 16.4.6 the value 1 is the loading-boundary and segment-tree prefetch (`segment-cache/cache.js`); a full prefetch (`prefetch={true}`) sends no such header, and the runtime prefetches (2 and 3) are compared.
3. **Page noise.** An answer that lines up with A's word by word (`[A-Za-z0-9_+/=-]+` runs, the bytes between them the same) but differs is compared outside the words that differ between two of A's own answers. Reads: A's request is sent once more when C's, B's or no login's answer lines up with A's. Writes: A reads twice before the replay (until two reads line up, at most 3), and after a change once more (settle read): words that differ between the two reads after are noise too (Gitea's footer render time: 12 of 56 false "changed" before, 3 after, measured locally).
4. **Layouts.** When A's read before is an HTML page and the read after has the same status but does not line up, A reads again, at most 7 more times, for one that does. A JSON answer is read once: its changed answer never lines up (Juice Shop: 46 requests for nothing in gate run 45746228551).
5. **A method the page ignored.** A PUT, PATCH or DELETE answered 2xx with a body, whose read did not change, is followed by the sender's GET of the same URL (at most 4 for an HTML page, until one lines up; once otherwise). When the GET's answer is the same page with only fresh random values (16 bytes or more, two of lower case, upper case and digits, at most 8, each swapped the same way everywhere), the write is not accepted.
6. **Order: no login first**, then C, then B (amends ADR 0051 item 2). A no-login acceptance no longer stops C or B, and C's acceptance no longer keeps no login from being sent. Gate run 45738560116 found 2 real Juice Shop no-login writes this way (a review posted and a product changed, checked by hand). The "C's session may have expired" note is given only when a write was sent both as C and with no login.
7. **One finding per operation.** A finding's key holds a variant: the Server Action ID for writes, the query's names and the RSC kind for reads. A merged finding keeps the most severe finding's own text and lists every source.
8. **Caps.** At most 23 requests per replay (A's copy, 3 earlier steps, 3 reads before, a form page, the write, 8 reads after, a settle read, 4 method reads and a DELETE), sent as no login, C and B: at most 6,900 for 100 writes and tries (ADR 0049 item 6 said 2,000 for 10 per replay and two senders). Measured: Juice Shop 418 with every new read, Gitea 42 to 51, the Next.js app 51.

## Consequences

- Porchlet's R2 false findings are gone (0 write and 0 read findings on Porchlet, which has no true write or read leak to keep), and the Next.js app keeps all 4 true writes and both true reads.
- A Server Action refused in a way that still sends A's success header, or that changes A's page for another reason, is still accepted (medium unless A's read changed).
- Fingerprints of access-control and access-control-write findings change (the variant is part of the key).
- More requests: the second read, the settle read and the layout and method reads (Juice Shop 372 to about 375 expected with item 4; to be measured on the gate).
- Gaps: a router prefetch that holds data is not compared (none seen; Next.js 16.4.6's value 1 prefetches the skeleton); on the read side a page in another layout than A's does not line up, so C's read of it is missed (a false negative, not measured on a real app); a Server Action whose page has no recorded GET is judged by the 2xx rule; a page whose random values are under 16 bytes or more than 8 still differs.

## Alternatives considered

- A0 (keep the 2xx rule): 6 false mediums on Porchlet.
- A4 (hybrid for every write): loses a real Juice Shop write whose replay changes nothing A can read.
- A1, A2, A3: more false findings or lost true ones than A4 and A5 on every app (gate run 1).
- R1 (parse the RSC answer), R2 and R2b (A's markers): false findings left (R1, R2) or real leaks lost (R2, R2b).
- Not sending prefetches at all: fewer requests, but not measured, and their answers also show whether C's session works.
- Reading every answer again for a layout (gate run 2): 46 more Juice Shop requests and no finding changed.
