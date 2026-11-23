# 0037. The live hosted-backend check

- Status: Accepted
- Date: 2026-11-20
- Amends: [0011](0011-app-logic-and-ai-checks.md) item 3 (live part: which targets, how the backend is confirmed, what is read)
- Amended by: [0044](0044-typed-confirmations-limit.md) (what the typed confirmation can stop), [0053](0053-routes-from-server-code.md) (on local targets `--source` also gives the route sweep the routes of the server code), [0058](0058-storage-write-test.md) (Firebase and Supabase Storage are tested live, with writes, by `storage-write`)

## Context

ADR 0011 item 3 plans a read-only check, on verified targets only, that uses the public client key in the app's own scripts to see whether a hosted backend's tables or paths can be read without signing in. Apps built quickly on Supabase or the Firebase Realtime Database often ship with row-level security off or with open read rules. The owner answered the M2.7 design questions on 2026-11-20 ([design](https://claude.ai/artifact/UjmsK3MmQ4btjaPg5427ar), answer 8a: `--backend-url`, one read-only GET per table with `limit=1`, Supabase readable only when rows come back, Firebase paths from the rules and scripts; 9a: three pull requests, this is the third). The open questions were answered on 2026-11-20 at 18:27 UTC ([questions](https://claude.ai/artifact/EcDMGbfvRV8ixhB2V5r4Ev), "1a 2a 3a" and 6a).

The backend is a different host from the target. Its owner may not be the person running SiegeKit, and the target's ownership proof (ADR 0005) does not cover it.

## Decision

1. **The backend** is given with `--backend-url URL`. It has no path, no fragment, and no query except `ns=NAME` (the Realtime Database emulator's namespace). `*.supabase.co` is Supabase. `*.firebaseio.com` and `*.firebasedatabase.app` are Firebase. Other hosts (a local stack or emulator) get their kind from the app's scripts. Hosted backends must use https. Mistakes are refused before any lookup or request. Directory scans refuse the flag.
2. **Which names are read** (owner answer 1a). The names are:
   - tables named in `.from('NAME')` calls in the scripts that the start page links (the same files `served-secrets` collects, ADR 0032);
   - Realtime Database paths from `ref('PATH')` and `.child('PATH')` (at most two literal segments; a template literal counts up to its first `${`);
   - with `--source DIR`, tables created in the `public` schema by `.sql` files under a `supabase/` directory, and paths up to two levels deep from `database.rules.json`.

   At most 200 names are read. The result counts any names left out. `--source` is read locally, and nothing in it is sent.
3. **The backend must be the app's, and a person confirms it** (owner answer 2a).
   - A backend that is not on this machine must appear in the scripts the app serves; otherwise the check fails before any request to it.
   - A person must also type its host name in a terminal. No flag skips this, not `--yes` and not `--authorized-host`, so an AI assistant that follows the guide cannot confirm it for the person (as for deployed targets, [agents.md](../agents.md)). A program that gives SiegeKit a pseudo-terminal and types the answer can (ADR 0044).
   - A backend on this machine (loopback) follows the local target rules and needs no prompt.
   - A blocked address (cloud metadata, for example) is refused. A backend whose addresses mix public and private is refused. A private backend on a deployed run is refused.
   - The backend gets its own audit entry, with "typed backend host" or "loopback".
4. **How it reads.** SiegeKit sends the requests itself, GET only, on a read-only configuration (`egress.SendHeader`): pinned addresses, no redirects, TLS verified for public hosts, at most 5 requests per second, and at most 1 MiB read from each answer.
   - Supabase: `GET /rest/v1/TABLE?select=*&limit=1`, with the public key from the scripts. The key is a JWT whose role is `anon` (and whose `ref` matches the project when that is known), or an `sb_publishable_` key. The key goes in `apikey`, and a JWT also goes in `Authorization: Bearer`. A `service_role` or `sb_secret_` key is never used.
   - Firebase: `GET /PATH.json?shallow=true` with no key, the root first. When the root is readable, no paths are sent.
   - Because the check only reads, it runs on every target, `--deployed` and `--profile quick` included.
5. **Results** (owner answer 3a).
   - A table that returns a row is "Supabase table is readable with the app's public key" (`supabase-table-readable`). A path that returns data is "Realtime Database data is readable without signing in" (`firebase-rtdb-readable`).
   - Both are **high**, with CWE-284 and CWE-862. The location is the backend URL without its query.
   - The message gives the column names (Supabase) or the number of keys (Firebase), never values.
   - `[]` (empty, or hidden by row-level security), `null`, 401, 403 and 404 give no finding. The plugin's `result` counts each kind.
   - The check fails when the backend does not answer, or when none of its answers can be read.
6. **`--source` also gives Schemathesis a spec** (owner answer 6a). When neither `--openapi` nor a served spec is used, the first valid `openapi*` or `swagger*` file in the repository (shortest path first) is used before probing the target's default spec paths.

## Evidence

| Claim | Backed by |
|---|---|
| PostgREST answers a row for a table with RLS off, `[]` for RLS on without a policy, a row for `using (true)`, and 404 `PGRST205` for an unknown table | Measured 2026-11-20 (supabase/postgres 17.12.0.002, PostgREST v16.6, local). |
| The check reads those answers correctly end to end | Real CLI run 2026-11-20 against that stack behind a `/rest/v1` proxy, with a local app whose script holds an anon JWT and `.from()` calls and with a `--source` migration: 5 tables tested, 2 readable (RLS off, `using (true)`), 2 empty (RLS on, empty table), 1 not found; 7 requests; no row values in `report.json`, `report.sarif` or `report.html`. `TestCheckOverHTTP` repeats this over real HTTP. |
| Realtime Database: a closed root with an open child refuses the root and serves the child; `shallow=true` gives keys only | Measured 2026-11-20 (emulator 4.11.2). Real CLI run against the emulator: root and `users` refused, `public` and `chats` (from a template literal) reported, no values kept. |
| Many tables are never named in client code, so scripts alone miss them | Measured 2026-11-20: 18 apps with Supabase migrations, 46 tables, 27 named with `.from()` in any code. |
| A backend not named in the scripts, a wrong typed host, no terminal, or `--authorized-host` sends nothing to it | `TestScanURLBackend` (CLI, fake backend: no call in each case). |
| Only anon or publishable keys are used | `TestReadScripts` (service-role JWT and `sb_secret_` keys ignored; ref mismatch ignored). `FuzzReadScripts` and `FuzzParse` run in CI. |

## Consequences

- Unverified: the hosted Supabase gateway and publishable (`sb_publishable_`) keys were not tested against a real project. Only the local stack and unit tests back them.
- Tables neither named in the served scripts nor created in a migration under `supabase/` are not tested. Scripts loaded later by other scripts are not read (ADR 0032).
- Firestore and Cloud Storage are not read live. They are covered only by the static rules check (ADR 0015). Realtime Database paths deeper than two literal segments, or built from variables, are not tested.
- A table meant to be public, such as a product list, is reported. The message asks the person to check the columns and ignore it if it is public.
- Only reads are tested. A table that anyone can write to but not read is not seen.
- A hosted backend needs a person at a terminal, so CI and AI agents can test only a local backend.

## Alternatives considered

- Accept `--authorized-host` or `--yes` for the backend: not chosen (answer 2a); the backend is often someone else's account, and a flag can be set by an agent.
- Report values or a row sample as evidence: not chosen (answer 3a); column names show the risk without copying user data into reports.
- Supabase's OpenAPI table list with the anon key: no longer served to anon keys since 2026-04-08 (Supabase changelog entry 42949, read during the M2.7 design; not checked against a hosted project), so names come from scripts and migrations.
- Medium severity: not chosen (answer 3a); a readable table is readable by anyone who loads the app.
