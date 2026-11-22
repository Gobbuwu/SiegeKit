# 0050. Method calls sent as POST in the write replay

- Status: Accepted (build: owner 2026-11-22, "Merge #59, fix in next PR"; item 4b pending the owner's choice, see below)
- Date: 2026-11-22
- Amends: [0049](0049-write-replay.md) (items 2, 3b and 4)

## Context

`access-control-write` (ADR 0049) takes every recorded POST as a write. Some apps send every action, reads included, as a POST that names a method in its body. Measured on Rocket.Chat 6.13.1 (`rocketchat/rocket.chat:6.13.1`, image ID `f245efa7c787`, with `mongo:8.0` `479e85ced54f`; Claude's sandbox, Docker 29.10.0 rootful, cgroup v1; Chromium recording made with Playwright of alice logging in, sending a message in `#general` and editing it):

- Every method goes over HTTP as `POST /api/v1/method.call/<method>` (or `method.callAnon` with no login), with a DDP method message inside a JSON string: `{"message":"{\"msg\":\"method\",\"id\":\"16\",\"method\":\"sendMessage\",\"params\":[…]}"}`. The WebSocket carried only `connect`, a resume login, subscriptions and typing notices.
- With the check as merged in #59 (`main` 0e52b83), 46 POSTs of the recording were taken as writes, and 16 no-login replays were reported as medium findings, all false: 14 `POST /__meteor__/dynamic-import/fetch` (Meteor's code-bundle fetch) and the anonymous `public-settings/get` and `license:isEnterprise`, which are reads.
- Account B sent nothing: the message ID is inside the DDP string, so the edit (`updateMessage`) looked like a plain create (ADR 0049 item 3b) and was not sent as B.
- The answer to a refused method is HTTP 200 with the error inside the DDP string: B's `updateMessage` on alice's message answers `{"message":"{\"msg\":\"result\",…,\"error\":{\"error\":\"error-action-not-allowed\",…}}","success":true}`. On 2xx alone it reads as accepted.
- The browser chooses a new message's `_id` and sends it in `sendMessage`; the answer gives it back. Sent again with that `_id`, Rocket.Chat answers 200 with no result and makes nothing. So A's copy (ADR 0049 item 2a) failed, B's edit went to A's recorded message, whose text already matched the recorded edit, and Rocket.Chat answered that unchanged edit with success before its permission check: 1 false medium for the edit and 1 for B's send, which made nothing.

## Decision

1. **Method calls** (`rpcOp`, `internal/authz/write_rpc.go`). A POST body is a method call when it is a DDP method message inside a JSON string field `message` (`"msg":"method"` and a `method` name), or a JSON-RPC request: an object or a batch of objects with a `method` string and either a `jsonrpc` member or both `params` and `id` (JSON-RPC 1.0). A body with only a `method` field (a payment method, say) is a plain JSON body. GraphQL (ADR 0049 item 7b) is read first and is not affected.
2. **Reads are not replayed.** A call reads when every method in it reads by name (`readName`): the name is cut into parts at every character other than a letter or digit, and a part's first word (split at camelCase) is `get`, `list`, `fetch`, `find`, `search`, `load`, `query`, `count`, `lookup`, `describe`, `is`, `has` or `can`, and no word of the name is a write verb (ADR 0048's action words plus `send`, `set`, `mark`, `write`, `post`, `put`): `public-settings/get`, `loadHistory`, `license:isEnterprise` and `eth_getBalance` read; `sendMessage`, `updateMessage`, `readMessages` (marks a room read) and `getOrCreateRoom` do not. A POST that is not a method call or GraphQL is a read when its last path segment that is not an ID names a read in the same way (`/__meteor__/dynamic-import/fetch`, Gitea's `/-/fetch-redirect`). Both are counted, and the result names the first 5. The lockout words (ADR 0049 item 5) also apply to method names (`login` sent to `/rpc`).
3. **IDs in params.** For a method call, object IDs are looked for, and replaced in a copy, only in the call's params (the DDP message inside the string, encoded again), never in the envelope's own `id`, which numbers the call. A create's new ID is read in the call's result (the DDP message's `result`, or JSON-RPC's `result`); the plain-create rule (ADR 0049 item 3b) reads the params.
4. **IDs the client chose.** A recorded POST whose answer gives back an ID that its own body held at a key of the same name (`_id` sent, `_id` answered), and that appears nowhere earlier in the recording, made an object under an ID the client chose.
   - a. A's copy of such an object (ADR 0049 item 2a) is made with a fresh random ID of the same shape (a new version 4 UUID for a UUID; otherwise each digit and letter replaced by one of the same kind). An ID seen earlier names an object that exists, so a POST that sends it changes that object and is replayed as recorded.
   - b. When such a create is itself replayed (B's or the no-login send), it carries a fresh ID too, and that ID does not count as naming another object for the plain-create rule. **Pending the owner's choice** (decision card in the project thread, 2026-11-22), built as recommended; the alternative is below.
5. **Refusals inside a 2xx answer.** A write answered 2xx is not accepted when the answer is JSON with a top-level `success` that is false (Rocket.Chat's REST style; any write), when a DDP call's answer has an `error` in the DDP message, or when a JSON-RPC call's answer has a non-null `error` (JSON-RPC 2.0 specification; a batch when every answer in it has one).
6. Findings and the listing name the method when the path does not already end with it: `POST /rpc (method note.update)`.

## Evidence

Measured in Claude's sandbox (Docker 29.10.0 rootful, cgroup v1, 4 CPUs) with the built Go code driven by a test harness (not committed) through `egress.SendHeader`, a fresh container and a fresh recording for each run. Record: `write-replay-rpc-2026-11-22.md` in the project's shared files.

| App | Before (`main` 0e52b83) | After |
|---|---|---|
| Rocket.Chat 6.13.1 | 46 writes, 46 requests; 16 medium, all false (reads with no login); B sent nothing | 3 writes, 7 requests; B's edit sent on A's copy and refused inside the 200 answer; 1 medium: B's own message in `#general`, which Rocket.Chat allows by design (B is a member); 30 calls and 15 POSTs counted as reads; the login not replayed; A's 2 copies stay (no DELETE route ends with their ID) |
| Juice Shop v20.4.0 (fuller recording) | 6 high, 4 medium, 199 requests | identical replays and findings, 199 requests |
| Gitea 1.24.6 web UI | 4 medium (allowed by design), 52 requests | same 4 medium; the 4 `/-/fetch-redirect` POSTs counted as reads instead of replayed and refused, 48 requests |
| DVGA | 2 queries not replayed, 2 no-login `CreatePaste` medium | identical |
| Wiki.js 2 | 3 mutations, login not replayed, 9 requests, 1 medium | identical replays and findings |

Item 4b, both options measured on fresh Rocket.Chat containers: with a fresh ID, B's send makes B's own message (1 medium, data really changed, allowed by design); keeping A's ID, Rocket.Chat ignores it and answers 200 with no result (1 medium, false, nothing written). Both 7 requests. The Wiki.js runs used a group allowed to edit every page, unlike the 2026-11-21 run, so B's page edit is accepted by design there, and Wiki.js refused B's comment with "Too many requests" (its comment rate limit) in every run.

Unit tests (`internal/authz/write_rpc_test.go`): `TestReadName`, `TestReadPath`, `TestRPCOp` (DDP, JSON-RPC 2.0 and 1.0, batches, a payment `method` field, a DDP answer), `TestEnvelopeRefused`, `TestWithIDRPC` (the DDP string re-encoded, the envelope's `id` untouched), `TestFreshID`, `TestParseWritesRPC` (a Rocket.Chat-shaped recording plus a JSON-RPC create and update), `TestWriteCheckRPC` (a server shaped like `method.call`: the recorded `_id` never sent again, 2 copies, B's edit refused inside 200, 1 medium).

## Consequences

- On apps that send actions as method calls, reads are no longer reported as writes, edits reach account B, and refusals inside a 200 answer are seen.
- POST-only apps still never reach high: A's reads on such apps are method calls too (`loadHistory`), and A does not send them before and after a replay.
- **Not covered:** methods named without a read verb that only read (they are replayed: a false medium at most); methods named with a read verb that change data and no write verb (not replayed); calls nested inside another call's params (Odoo's `call_kw` with the model method inside); refusal shapes other than those in item 5; JSON-RPC over GET; copies the app cannot delete with a DELETE on their URL stay in A's account (every Rocket.Chat copy); access control of reads sent as POST is not tested by either check.
- The word lists are measured on one app that uses method calls (Rocket.Chat) and the JSON-RPC shapes are tested only in unit tests; false-alarm rates on other method-call apps are not measured.

## Alternatives considered

- **Path only** (`/method.call/<name>`, `/rpc`): misses JSON-RPC at other paths and DDP behind other routes; the body shape names the protocol.
- **Any read verb anywhere in the name**: `targetList` or `blacklistUser` would read; the first word of each part is closer to how methods are named.
- **Item 4b, keeping A's ID for B's send**: keeps a test of B overwriting A's object by reusing its ID, but Rocket.Chat ignores the reused ID and answers success, so the finding is false and nothing is written.
- **Treating a DDP answer with no `result` as a refusal**: Rocket.Chat's successful `updateMessage` and `deleteMessage` answer with no result too (measured by hand).
