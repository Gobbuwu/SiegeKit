# 0065. Recorded request bodies reach ZAP framed and unchanged

- Status: Accepted (owner, 2026-11-24: trace the intermittent 40045 miss on the Juice Shop gate to its root cause before merging PR #74 and #76)
- Date: 2026-11-24
- Amends: [0047](0047-recorded-requests-to-zap.md) (how the recorded requests are written for ZAP)

## Context

The Juice Shop URL gate's known answer held ZAP rule 40045 (Spring4Shell, high) on `/rest/user/login`, noted as "probably a false positive". The gate missed it at random: Podman runs 44959093507, 45002585112 and 45035779456, Docker runs 45125037847, 45192466982 and 45200611817, then 45289954829 (Docker, arm64), 45292461117 (Podman and Docker, amd64) and 45295928245 (Docker, arm64), with no change to ZAP or Juice Shop between hits and misses.

Rule 40045 reports when a request with `class.module.classLoader.DefaultAssertionStatus=nonsense` is answered 400 and the same request with `aaa=bbb` is not (`Spring4ShellScanRule.java`, zap-extensions `ascanrules`). Juice Shop never answers 400 to either: `GET /rest/user/login?...` gives 500 ("Unexpected path") and the form POST gives 401 (checked with curl, 2026-11-24).

Measured on 2026-11-24 (local, Docker 29.9.3 rootful, cgroup v1, linux/amd64, pinned ZAP 2.17.0 and Juice Shop v20.4.0, the gate's steps copied into a script; packets captured on the target's port and, with `nsenter`, on ZAP's side of the relay inside the ZAP container):

1. **The 400 never came from Juice Shop.** Run 1 reported 40045 with evidence `HTTP/1.1 400 Bad Request` on `GET /rest/user/login?class...`. In the capture at the target, that request never arrived; its `aaa=bbb` twin arrived and was answered 500. No request to `/rest/user/login` was answered 400 at all (24 × 200, 403 × 401, 66 × 500).
2. **ZAP sent the recorded login without a Content-Length.** In run 2 (40045 reported again), ZAP sent 7,530 requests; 43 were the recorded JSON login sent unchanged: `POST`, `Content-Type: application/json`, no `Content-Length`, no `Transfer-Encoding`, then the 67-byte body. A request with neither header has no body (RFC 9112 section 6.3), so the egress proxy forwarded an empty login (Juice Shop answered 401) and read the 67 bytes as the start of the next request on that connection. That request (`{"email":...}GET http://...`) was malformed, so Go's server answered it 400 and closed the connection. 44 requests were lost this way: 26 × `GET /api/Addresss`, 11 × the login, and one each of 7 others, including the 40045 attack in run 2. Which request follows the login on a pooled connection depends on ZAP's thread timing, so 40045 came and went.
3. **Why the length was missing.** `authz.replayHeaders` drops `Content-Length` (SiegeKit's own replay computes it), and `writeRecorded` wrote the HAR without one. ZAP's HAR import builds the request header from the HAR headers as given (`HarUtils.createHttpMessage`, zap-extensions `exim`) and adds none; rules that change the body set their own, which is why only unchanged sends broke.
4. **The same happens without SiegeKit's proxy.** ZAP run alone against a logging server, with a HAR like SiegeKit's (rules 40018 and 40045 only): 2 of 18 requests arrived glued to a body, one of them the 40045 attack.
5. **Non-Latin-1 bodies.** ZAP makes the request body from the HAR text in ISO-8859-1 (`HttpBody.DEFAULT_CHARSET`; `HttpRequestBody` does not guess another), so `€` or an emoji becomes one `?` byte. With a `Content-Length` of the UTF-8 length, the body sent was shorter than its length and the run stalled after 2 requests. With each body byte written as one character U+0000 to U+00FF and `Content-Length` as the byte count, 6 of 11 requests carried the exact original bytes and none broke framing; with ASCII and the length, 0 of 18 broke.

So 40045 on Juice Shop was made by SiegeKit's HAR, not found in Juice Shop, and the same fault silently dropped other attacks.

## Decision

1. **Every recorded request with a body gets `Content-Length`** in the HAR written for ZAP, set to the body's length in bytes (`internal/runner/url.go`, `writeRecorded`). Requests without a body get none.
2. **The body text is written byte for byte**: each byte of the recorded body is one character U+0000 to U+00FF (`zapBodyText`), so ZAP's ISO-8859-1 import turns it back into exactly the recorded bytes and the length matches.
3. **40045 leaves the Juice Shop known answer**, and the gate's Scan step fails if `zap-active` reports 40045 there again (the answer format compares by "includes", so it cannot say that a finding must be absent).
4. **Tests.** `TestRecordedRequests` checks the HAR: one `Content-Length` per request with a body, equal to its byte count, none without a body, and text whose ISO-8859-1 bytes are the body (a `€ 😀` body included). `TestZAPFindsPlantedIssues` (real ZAP, behind the relay and egress proxy) now counts how the recorded `POST /api/import` arrives at the test app, whose recorded XML now holds `€ 😀`: whole and unchanged at least once, empty never.

## Evidence

| Claim | Backed by |
|---|---|
| The 400 behind 40045 came from the proxy, not the app | Local run 1: the alert's evidence is `HTTP/1.1 400 Bad Request` on the GET attack; the target capture holds no such request and no 400 on the login. Run 2: ZAP-side capture shows the attack arriving glued to the login body and answered 400 with `Connection: close` |
| The recorded login had no length | Run 2: 43 unchanged recorded logins with no `Content-Length` or `Transfer-Encoding`, each followed by a 400 on the next request of its connection (44 lost requests) |
| ZAP adds no length to imported requests | `HarUtils.createHttpMessage` copies the HAR headers only; ZAP run alone (no SiegeKit) broke 2 of 18 requests with the old HAR, 0 of 18 with the length |
| The fix stops it on the gate's app | Local run 3 with the fix (same setup): 7,534 requests from ZAP, 0 recorded bodies without a length, 0 requests glued to a body; the only 400s are Juice Shop's own on `POST /rest/memories` (multer); `zap-active` 7,526 requests, 40018 on the search and the login as before, no 40045 |
| The tests catch the old behaviour | On the old `writeRecorded`, `TestRecordedRequests` fails ("Content-Length [] for a 8-byte body", "'€' is not one byte in ISO-8859-1") and `TestZAPFindsPlantedIssues` fails ("arrived whole 0 times and empty 43 times"), where it also reported 40045 and 10104 on `/api/import`; with the fix it passes with 69 whole arrivals, 0 empty, 90023 still found and neither 40045 nor 10104 reported |

Engines and architectures beyond local Docker on amd64: see the CI and gate runs listed in `docs/milestones/M2.md` for this change.

## Consequences

- Every recorded request with a body now reaches the app as recorded when ZAP replays it, and attacks that followed one on a connection are no longer lost: on Juice Shop that was 44 of about 7,500 requests per run, including attacks on `/api/Addresss` and the login.
- Juice Shop's gate answer loses a false high (40045). Other findings that came only from these 400s can go too: on the test app 40045 and 10104 on `/api/import` went.
- A body ZAP's rules change is re-encoded by ZAP in ISO-8859-1, as before; only the unchanged replay is now exact.
- The egress proxy still answers a malformed request 400 without counting it (Go's server does this before SiegeKit's handler runs). This fix removes the cause seen here; a tool that sends malformed requests some other way would again lose them silently. Counting those is left for the M2 milestone check.

## Alternatives considered

- **Retry or mark 40045 unstable in the answer.** Rejected: it hides lost requests instead of stopping them (owner's rule: no flake workarounds).
- **Make the proxy read bodies without a length.** Rejected: a request with neither header has no body by RFC 9112, and guessing would break correct clients.
- **The UTF-8 length with the text unchanged.** Rejected by measurement (point 5): bodies with characters outside ISO-8859-1 stalled the scan.
