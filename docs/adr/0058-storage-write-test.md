# 0058. The storage write test

- Status: Accepted (design approved by the owner 2026-11-21: live write at the root and app paths, Firebase and Supabase, leftovers reported; local targets only: recommended on 2026-11-23, see item 1)
- Date: 2026-11-23
- Amends: [0037](0037-backend-live-check.md) (Cloud Storage is now tested live, and writes are tested), [0044](0044-typed-confirmations-limit.md) (one more typed phrase)

## Context

ADR 0037 reads Supabase tables and Realtime Database paths with the app's public key. It never writes, and it does not touch file storage. Apps built quickly on Firebase or Supabase often let anyone upload to their storage buckets. The static `backend-rules` check finds some of these in the repository's rules: measured on the design's test bed, 4 of 5 open Firebase rule sets (it misses a write rule whose only condition is a file size) and 0 of 5 open Supabase policy sets, because it does not read storage policies at all.

The owner approved the design on 2026-11-21 ([design](https://claude.ai/artifact/5aSWb8Cvg7dq5D1MxzyZdS): Q1 C, Q2 A, Q3 A). This ADR records the answers and the details the design left to the build. The measurements are in `storage-write-build-2026-11-23.md` in the project files.

## Decision

1. **Opt in, local targets only.** The check `storage-write` runs only when `--storage-url URL` is given. `--backend-url` alone stays read-only. `--storage-url` with `--deployed` is refused, like `--replay-writes` (ADR 0049 item 1): the person runs the app locally against the same backend, and M2.10 decides deployed mode for every data-changing check. It is left out of `--profile quick`, and directory scans refuse the flag.
2. **`--storage-url`** has no path, query, fragment or user name. `*.supabase.co` is Supabase Storage (`/storage/v1`). `firebasestorage.googleapis.com` is hosted Firebase Storage, shared by every Firebase project. Both must use https. Another host (a local stack or the emulator) gets its kind from the app's scripts, as in ADR 0037. The address rules of ADR 0037 item 3 apply (blocked ranges and mixed public and private addresses are refused).
3. **Which buckets and folders** (design Q1 C).
   - Buckets: Firebase `storageBucket: "..."` in the app's config and `gs://...` literals; Supabase `.storage.from("...")` and, with `--source`, `insert into storage.buckets (id, ...) values ('...')` in `supabase/` migrations. Hosted Firebase uses only the buckets the app's own config names.
   - Folders: the part before the last `/` of the first argument of `.upload("...")` (Supabase) or `ref(x, "...")` and `.child("...")` (Firebase), up to its first `${`, at most three plain segments; with `--source`, the literal folders of Firebase `storage.rules` `match` blocks (nested blocks followed) and Supabase policies' `(storage.foldername(name))[1] = '...'`.
   - Order: each bucket's root, then folders the scripts upload to in a named bucket (`.storage.from("files").upload("uploads/...")`), then every other folder in every bucket. **At most 5 files per run**, roots included; the rest are counted as not tested. Bucket names outside `[A-Za-z0-9_][A-Za-z0-9._-]*` and folders that are not plain are never sent.
4. **A person confirms, in a terminal only.** After reading the scripts, SiegeKit prints every file it will upload and its full path. For a storage host not on this machine it first asks for the host name (Supabase, private hosts), or for each bucket name (hosted Firebase, because the host names no project). A Supabase host already typed for `backend-live` in the same run is not asked again. Then the person types `write test files`. No flag skips either, not `--yes` and not `--authorized-host`; a program that drives a pseudo-terminal can type them (ADR 0044). Without a terminal, or with a wrong answer, it is skipped (`not-confirmed`) and nothing is sent to the storage. A storage host that is not on this machine must appear in the app's scripts (Supabase); for hosted Firebase the bucket from the app's config ties it to the app. The storage gets its own audit entry (`typed storage host`, `typed bucket name` or `loopback`, each `+ typed phrase`).
5. **What it sends** (the REST calls of firebase 12 `uploadBytes` and supabase-js 2.49 `upload` and `remove`), from SiegeKit's process to the storage's pinned addresses, one request per 200 ms, labeled `SiegeKit/<version>`:
   - Upload a 36-byte text file `SiegeKit write test. Safe to delete.` named `siegekit-write-test-<16 random hex>.txt`: Firebase multipart `POST /v0/b/BUCKET/o?name=PATH` with no login; Supabase `POST /storage/v1/object/BUCKET/PATH` with `x-upsert: false` and the app's public key (anon JWT or publishable key, as ADR 0037; never a service or secret key).
   - Read it back, delete it (Firebase `DELETE`; Supabase bulk `DELETE /storage/v1/object/BUCKET` with `{"prefixes": [PATH]}`), and read it again.
   - The delete and the second read are sent for every accepted upload even when the run is interrupted.
6. **What counts** (measured, section 1 of the record). Firebase: an upload answering 200 with the object's `name` is written; 401 or 403 is refused; a delete answering 204 is deleted; a second read answering 404 shows it gone. Supabase storage-api answers **400** and puts the real code in the body: `"statusCode":"403"` is refused, `"404"` is a missing bucket or object. Its bulk delete answers 200 with the objects deleted, and `[]` when none was, so only a list naming the file counts as deleted, because a later read cannot tell a deleted file from one the public key cannot see.
7. **Leftovers** (design Q2 A). A file whose delete was refused or not confirmed is named with its full path (`gs://BUCKET/PATH` or `BUCKET/PATH`) in the console, in the plugin's `result`, and in the finding. It is accepted, not avoided: measured, 2 of 7 Firebase rule sets (v3, v6) and 3 of 7 Supabase policy sets (s3, s6, s7) refuse the delete.
8. **Findings.** Each accepted upload is `storage-public-write`, **critical** (the severity `backend-rules` gives an open write), CWE-284 and CWE-862. The location is the bucket and folder (`gs://BUCKET/FOLDER/` or the Supabase object URL of the folder), so the same open folder is the same finding on every run. The message says whether the file could also be read back and how to fix the rule or policy.
9. **Not done here** (design build plan). The CI fixtures with the Firebase emulator and local Supabase and rule sets v1 to v7 and s1 to s7 as known answers are the next PR. `backend-rules` learning storage policies and the size-only Firebase write rule are separate fixes.

## Evidence

Environment: Claude's sandbox, Linux amd64, 4 CPUs, cgroup v1, Go 1.26.0, 2026-11-23. Firebase Storage emulator from firebase-tools 15.37.0 (Node 22.23.5, OpenJDK 21.0.13, rules runtime v1.1.3), run natively. Supabase `supabase/postgres:15.19.0.019` and `supabase/storage-api:v1.94.2` (digests as in the design) on Docker 29.10.0 rootful and on Podman 4.9.3 rootless. Apps bundled with esbuild 0.25.0 `--minify` from firebase 12 and supabase-js 2.49.4.

| Claim | Backed by |
|---|---|
| The answers in item 6 | Raw REST calls before the build: Firebase rule sets v1 to v7 at the root and `uploads/`; Supabase policy sets s1 to s7 with single and bulk deletes, checked against a service-key listing (record, section 1). |
| Every open setup is found and the object count is unchanged when the rules allow the delete | Real CLI runs: Firebase v1 to v7 (6 of 6 open found, v4 quiet; v1, v2, v5, v7 count before = after; v3, v6 +1 each, named); Supabase s1 to s7 on Docker and on rootless Podman with the same results (6 of 6 open found, s4 quiet; s1, s2, s5 unchanged; s3, s6, s7 +2 each, named). |
| Pairs from chained calls are needed | The first build missed s5 on Docker: the 5-file cap dropped `files/uploads/`, the folder the app's own code uploads to. After item 3's order, found on both engines. `TestPlanFiles`. |
| Folders: minified Firebase bundles give none from scripts; rules give them | esbuild 0.25.0 renamed `ref()` (`Ue(Be, ...)`); v5 found through `storage.rules` with `--source`. `TestReadStorageScripts` (cut from the real bundles), `TestStorageRuleFolders`, `TestReadSourceStorage`. |
| The fake storage answers as measured | `TestWriteStorageFirebase` and `TestWriteStorageSupabase` (real HTTP, a server answering as in item 6) check findings, reads, leftovers, object counts and request counts per rule set. |
| An interrupt still deletes | `TestWriteStorageInterrupted`. |
| No answer is sent without the confirmations, wrong answers, `--yes`, `--authorized-host` or a terminal stop it, and `--deployed` is refused | `TestScanURLStorage`. |
| The Firebase emulator answers the same inside a container | Rules v1 to v7 with the emulator in `eclipse-temurin:21-jre` (host Node 22 mounted) on Docker 29.10.0 rootful and Podman 4.9.3 rootless, cgroup v1: the same findings, leftovers and request counts as the native runs on both engines, rules reloaded 7 of 7 times. The emulator must listen on `0.0.0.0` in a container: with its default `127.0.0.1` the published port answers nothing (connection reset). |
| Storage triggers run on the test upload and delete, and what they create stays | Firebase Functions emulator (firebase-functions 6.6.0, firebase-admin 13.6.0) with `onObjectFinalized` and `onObjectDeleted` functions: both fired for SiegeKit's file. A function that reads the file failed with "No such object", because SiegeKit had already deleted it; a function that records the upload left `processed/<file>.json` under v1, where SiegeKit reported every test file deleted, and two derived files beside the named leftover under v3. Supabase (rootless Podman) with an `after insert or delete` trigger on `storage.objects` writing to a table: 4 rows for s1 (2 uploads, 2 deletes), 2 for s6; the rows stay. None of these is in the report, so the prompt says so. |
| Requests stay inside a named bucket | `FuzzReadStorageScripts` (no dot segments, no `#`, at most 5 files, for any script); `FuzzParseStorage`; `FuzzStorageRuleFolders`; all run in CI. |

## Consequences

- Unverified: real Firebase Storage and hosted Supabase over the internet (needs an empty test project the owner creates); the hosted Supabase gateway is assumed to answer as storage-api does behind it.
- Storage triggers run for the test file's upload and delete (measured). What they create (a derived file, a table row, a message) is not seen, deleted or reported by SiegeKit, and a trigger that reads the file can fail because the file is already gone; the prompt says both before the person types the phrase.
- Folders named nowhere are not tested; minified Firebase apps need `--source` for folders. A rule that allows only some file types (`request.resource.contentType.matches('image/.*')`) refuses the text file and is not reported. Rules that depend on the user's ID in the path (`uploads/{uid}/`) are tested only at the literal folder, where they refuse.
- A rule set that allows the upload but refuses the delete keeps the test file: 36 bytes that say what they are, named in the report for the person to delete.
- A bucket meant to take anonymous uploads (a public drop box) is reported. The message says what the open write allows, so the person can decide.
- Like `backend-live`, a storage host not on this machine needs a person at a terminal, so CI and AI agents can test only a local stack or emulator.

## Alternatives considered

- Rules file only (design Q1 A): misses the size-only Firebase rule and every Supabase policy.
- Bucket root only (Q1 B): misses folders opened on their own (v5, s5).
- Start an upload but send no data (Q1 D): the emulator answered 200 even when the rules needed a login, so it cannot tell open from closed.
- Write only when the repository shows the delete is allowed (Q2 B): needs `--source` and loses the size-only case.
- Deployed targets too: not chosen while every data-changing check is local only (item 1).
- Single-object delete for Supabase: it answers 400 both when refused and when the object is missing; the bulk delete's list says what was deleted.
- One finding per random file: would change on every run; the folder is stable.
