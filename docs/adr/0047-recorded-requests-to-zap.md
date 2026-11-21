# 0047. Recorded requests in ZAP's attack scan

- Status: Accepted (owner picked "Every request in --har" on 2026-11-21, 20:23 UTC, after all three options were measured)
- Date: 2026-11-21
- Amends: [0023](0023-active-web-scans.md) (what `zap-active` attacks), [0035](0035-access-control-replay.md) (what is taken from `--har`, and who the "test accounts" confirmation covers), [0004](0004-plugin-manifest.md) (field `run.recordedRequests`)

## Context

Item 4 of the ARTEX comparison (2026-11-21) asked whether SiegeKit tests XML external entities (XXE). Measured on 2026-11-21 (project file `xxe-through-siegekit-2026-11-21.md`; Docker 29.10.0 rootful, cgroup v1):

- The pinned ZAP 2.17.0 image has the rule: `XxeScanRule`, 90023 "XML External Entity Attack", in `ascanrules-release-84.zap`.
- ZAP's spider does not find XML request bodies, so `zap-active` never sends XML. On a toy app with an XXE in `POST /api/order` (lxml with entities on, checked by hand), SiegeKit's `zap-active` found nothing in 2 of 2 runs (147 and 148 requests, 21 s each).
- Given that one recorded request (a HAR file) through a ZAP `import` job, it reported 90023 on `/api/order` in 3 of 3 runs (419 to 420 requests, 24 to 25 s).
- Given a whole browser recording of Juice Shop (74 requests to the target: 65 GET, 8 POST, 1 PUT, made as a new user), it reported 40018 SQL injection (high) on `/rest/products/search` and on the JSON login `/rest/user/login` in 2 of 2 runs: 23,389 and 23,391 requests, 507 and 494 s, against 3,443 requests and 180 s without it. Both were confirmed by hand on 2026-11-20 and were in the Juice Shop known answers' "missed" list. The login one is in a JSON POST, which seeding GET URLs (part 5) cannot reach.
- XML bodies taken from an OpenAPI spec do not work through ZAP: with an `application/xml` request body, ZAP's `openapi` job fails ("the content type application/xml is not supported", exit 1, 3 of 3 runs); with `text/xml` it sends a JSON body, so 90023 never fires (2 runs).
- Juice Shop's Docker image switches its XML-upload XXE off (`routes/fileUpload.js` parses the XML only when the challenge is enabled; an XXE upload answers 410). So the gate's Juice Shop cannot show XXE.
- ZAP's SAML support is an add-on that is not in the pinned image, so SAML is out of scope here.

`--har` already takes a browser recording made as test account A, for `access-control` (ADR 0035), which replays only its GET and HEAD requests. `access-control` runs before the plugins, so ZAP's attacks cannot change what it replays.

The owner chose between: only the recording's XML requests (cheapest, XXE only), every request of the recording (chosen), and XML bodies generated from an OpenAPI spec (ZAP cannot; SiegeKit would need its own XML writer, not built or measured).

## Decision

1. **What is taken.** From the `--har` recording SiegeKit keeps, for ZAP, each GET, HEAD, POST, PUT, PATCH or DELETE request to the target's origin, with its body and body type, leaving out static files (the same list as `access-control`). A path must be one SiegeKit may send (ADR 0042). Duplicates (same method, URL and body) are dropped. At most 100 are kept (the same as `access-control`'s replay limit), and the rest are counted. Headers are kept as `access-control` keeps them, the session included; the transport's own headers are dropped, and a request without a body carries no `Content-Type`. A recording with no GET or HEAD request is accepted: `access-control` is then skipped with cause `no-input`.
2. **How ZAP gets them.** The manifest field `run.recordedRequests` is allowed only for ZAP plugins that are destructive and local-only and have a `spider` job. On such a plugin SiegeKit writes the kept requests as a HAR 1.2 file into the run's private directory and mounts it read-only at `/siegekit/files/recorded`. It then adds `{"type": "import", "parameters": {"type": "har", "fileName": ...}}` before the first `spider` job, so the spider and the attack scan that follow include them. Only `zap-active` sets the field. The file is removed with the run.
3. **Confirmation.** ZAP attacks these requests with account A's session, which changes that account's data and can create accounts (it re-sends the recorded writes with attack payloads). So the "test accounts" question of ADR 0035 is asked when `access-control` runs or when `zap-active` will get recorded requests, and it names both. If the answer is not typed, `zap-active` runs without the recorded requests and says so, and `access-control` is skipped as before. `zap-active` keeps its own confirmation (ADR 0005).
4. **Report.** `zap-active`'s `input` names how many recorded requests it got and from which file. Findings come from ZAP's own rules (XXE is 90023, high), with no change to the parser.
5. **Test app and gate.** The test app gets `POST /api/import`, which resolves the `file://` entities its DOCTYPE declares and echoes the document (done by hand, because Go's XML parser never resolves entities). No page links to it. The container test gives `zap-active` a recording with a GET of `/` and one XML POST to it, and requires 90023. The Juice Shop gate's recording gets the product search and account A's JSON login, and the gate requires 40018 on both.

## Consequences

- Every request the person records is attacked, on local targets: XXE on recorded XML endpoints, and SQL injection or other server-side flaws on recorded JSON and form requests the spider never sends.
- Cost grows with the recording: about +5 minutes and about 7 times the requests for a 74-request Juice Shop recording; about +3 s for one XML request on the toy app. A 100-request recording is not measured.
- **Not covered:**
  - endpoints the recording did not reach;
  - XML inside a multipart file upload (whether rule 90023 attacks it is unverified), and SOAP endpoints known only from a WSDL;
  - XML bodies that an OpenAPI spec declares but nobody recorded (ZAP cannot send them, measured above);
  - SAML (no add-on in the pinned image);
  - XXE that shows only through an out-of-band callback, because the target cannot reach ZAP's callback listener inside the sandbox (by design, ADR 0018 and 0019; not measured); the measured finding was XXE that reflects a file in the answer;
  - recorded requests whose body the HAR holds only as form `params` without `text` (not kept as a body; unverified how often browsers write that).
- The recording's session is written to a temporary file that the ZAP container reads. It is the same session that `access-control` already sends.
- Overlap with part 5 (the shared URL list): part 5 seeds GET URLs when no recording is given; this ADR covers what a recording holds, writes included.

## Alternatives considered

- Only the recording's XML requests (POST, PUT, PATCH with an XML body, at most 20): built first; finds the XXE for about +3 s per request, but leaves both Juice Shop SQL injections missed.
- Generating XML requests from an OpenAPI spec's XML request bodies: ZAP's OpenAPI import cannot (measured); SiegeKit would need its own XML writer from schemas, not built or measured.
- A separate XXE check written in Go: it would repeat ZAP's rule, which works once it is given the request.
