# 0028. Running Schemathesis

- Status: Accepted
- Date: 2026-11-20
- Amends: [0004](0004-plugin-manifest.md) (placeholders `{openapi}` and `{target-origin}`, field `run.findingsExitCodes`, parser `schemathesis-json`), [0025](0025-m2-5-web-tools.md) item 4 (how the spec is fetched and checked)

## Context

ADR 0025 item 4 makes Schemathesis destructive and local only, and gives it the spec named by `--openapi FILE_OR_URL`, or else the first valid spec at a fixed list of default paths on local targets. Facts checked on 2026-11-20 with the official image `schemathesis/schemathesis` 4.33.4 (index digest `708d934c…0eec`, built 2026-11-12, MIT, about 160 MB):

- **Reports.** `--report json` writes one small file. Each failed check is listed once with its code (`ST101` server error, `ST103` undocumented status code, `ST201` schema-violating request accepted, `ST204` wrong answer to an undeclared method, and others), its title and the operations it failed on, such as `GET /items/{id}`. The file has no request URLs. `--report ndjson` has every request and response body, so it grows with the run (92 KB for 42 test cases), and is not used.
- **Exit codes.** 0 when every check passed, 1 when a check failed or the API could not be reached, 2 for usage errors. An unreachable API gives exit 1 and an `errors` list in the report (`Network Error`).
- **Base path.** Given `--origin` (scheme, host and port), Schemathesis keeps the spec's own base path: a relative OpenAPI 3 server URL (`/api`), an absolute one (a spec naming `https://prod.example.com/api` was tested at the target with `/api`), and a Swagger 2.0 `basePath`.
- **`--max-time` repeats failing requests.** With `--max-time`, Schemathesis sent one request that failed with a 500 again and again until the time ran out: 6,173 times in 40 seconds against a test API, where the same run without the option sent 6 requests. Through SiegeKit this tripped the proxy's stop after 100 server errors in a row. Without `--max-time` the run ends on its own.
- **Random inputs can miss bugs.** Against an endpoint that crashes on negative ids, with no minimum in the spec, 1 run in 5 found nothing. When the spec says `minimum: 1`, the coverage phase always tried 0, and 10 runs in 10 found the crash.
- **Coverage report.** The image's hook loads a coverage plugin unless `SCHEMATHESIS_COVERAGE=false`, and tries to write `schema-coverage.html` in the working folder.
- **Juice Shop** answers every default path with its HTML page (or a 301 or 500), so no spec is found there.

## Decision

1. **Finding the spec.** `--openapi FILE` is read and checked before any request; a missing or invalid file stops the scan. `--openapi URL` must be on the target's origin, because SiegeKit sends requests only to the target (ADR 0005); it is fetched once after the run is in the audit log. Without the flag, local targets get one GET for each of 10 default paths (`/openapi.json`, `/openapi.yaml`, `/swagger.json`, `/swagger.yaml`, `/v3/api-docs`, `/v2/api-docs`, `/api-docs`, `/api/openapi.json`, `/api/swagger.json`, `/swagger/v1/swagger.json`), stopping at the first valid spec. These GETs go from SiegeKit itself to the pinned addresses, follow no redirects, and read at most 10 MiB. They are sent only when a plugin that needs a spec is about to run.
2. **Checking the spec.** A spec must be JSON with `"openapi": "3.x"` or `"swagger": "2.0"` and a `paths` object, or YAML with those keys on top-level lines; HTML is refused. Schemathesis parses it. The report names the spec used ("tested from"), or the paths tried. A spec named with `--openapi` that cannot be used makes the plugin fail; finding none at the default paths skips it.
3. **Manifest.** `{openapi}` is the spec's path, mounted read-only at `/siegekit/files/openapi/spec.json` or `spec.yaml`; no artifact may use that mount, and only plugins whose only target is `url` may use it. `{target-origin}` is the target's scheme, host and port. `run.findingsExitCodes` lists exit codes other than 0 that mean "ran and found issues" (at most 4, from 1 to 125); the report is still read and checked.
4. **`schemathesis`** runs from the pinned image, on local targets only, after the confirmation ADR 0005 asks for destructive plugins: `run {openapi} --origin {target-origin} --proxy http://127.0.0.1:8080 --rate-limit {ratelimit}/s --no-shrink --report json`, with `SCHEMATHESIS_COVERAGE=false` and exit code 1 read as a result. No `--max-time`. No shrinking: SiegeKit reports no examples, and shrinking also repeats failing requests. Resources: 1 CPU, 1 GiB, 15 minutes.
5. **Results.** The parser `schemathesis-json` gives one finding per failed check and path, naming the methods. The location is the target's origin, the spec's base path and the operation's path template, such as `http://localhost:3000/api/items/{id}`, so the same issue has the same fingerprint in every run. When the base path cannot be read (an OpenAPI 3 server URL with a variable that has no default, a relative server URL that is not an absolute path, or YAML that is not plain block style), the location has no base path and the message says so. A report with errors, one that says the run did not complete, or one that tested no operation, is a failed plugin: it did not check what it should have.
6. **Severity** (SiegeKit's own scale, the owner's choice of 2026-11-20 over Schemathesis's own ratings): a server error (`ST101`) is medium, every other check is low. Schemathesis rates server errors critical; a crash on generated input shows a bug, not a proven vulnerability, so it ranks below confirmed flaws such as ZAP's SQL injection (high).

## Consequences

- An API without a spec, or with one at another path, is not tested by Schemathesis unless `--openapi` names it. Juice Shop is not tested by it.
- Deployed targets never get the default-path GETs, and Schemathesis does not run on them before M2.10 (ADR 0025).
- Without `--max-time`, a large API can take longer than the 15-minute timeout; the plugin is then reported as timed out with no findings. M2.10 measures run times.
- Random generation can miss bugs that the spec's constraints do not point to (1 run in 5 in the test above).
- A plugin needing a spec may have its image downloaded (with consent) and then be skipped because no spec was found: the spec is looked for only after the run is allowed, so the consent question comes first.

## Alternatives considered

- Reading the NDJSON event stream for request URLs: it holds every response body and grows with the run, past the size limit for tool reports.
- `--url` with the target's path instead of `--origin`: the spec's base path would be lost, and operations under `/api` would be sent to the wrong paths.
- `--max-time` below the container timeout, so a long run still writes its report: rejected after measuring the repeated requests above.
- Looking for a spec before the consent question and the plan: those GETs would be traffic sent before the run is in the audit log (ADR 0005).
