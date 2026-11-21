# 0046. Public API specs and source maps

- Status: Accepted
- Date: 2026-11-21
- Amends: [0028](0028-schemathesis.md) (where the spec is looked for), [0032](0032-served-secrets.md) (source maps that a file does not name)

## Context

Unit 42's report on the ARTEX attack tool (2026-11-11, https://unit42.paloaltonetworks.com/artex-and-ai-powered-red-teaming-tools/) says it tests "routes from downloaded OpenAPI specs and source maps" and advises "Remove public attack maps". SiegeKit already fetched both, but only as inputs: Schemathesis uses a spec found at 10 paths on local targets (ADR 0028), and `served-secrets` scans the source maps a script names for keys (ADR 0032). A spec or source map served to anyone was never a finding, and deployed targets were never looked at for a spec. The owner asked for this check on 2026-11-21 (item 1 of the ARTEX comparison, "what's certain first").

Measured on 2026-11-21 on Juice Shop v20.4.0 (the gate's image, `bkimminich/juice-shop@sha256:9bbaecc4…197b`), Docker 29.10.0 rootful, cgroup v1, in the development sandbox:

- **No spec file at the guessed path.** The comparison said Juice Shop serves a spec at `/api-docs/swagger.json`, because Nuclei's `swagger-api` template reports that URL. It does not: `/api-docs/swagger.json` and `/api-docs/swagger.yaml` answer 200 with the Swagger UI HTML page, and the 10 default paths answer with the app's HTML page, a redirect (`/api-docs`, 301) or a 500. The spec is in the page's setup script, `/api-docs/swagger-ui-init.js` (5,457 bytes): OpenAPI 3.0.0, server `/b2b/v2`, one operation `POST /orders`.
- **How that script is written.** Juice Shop mounts swagger-ui-express 5.0.1 at `/api-docs` (`app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))` in its `build/server.js`). That package writes `var options = ` and then its options with `JSON.stringify(..., 2)`, the spec first, under `"swaggerDoc"`; options that are JavaScript functions are written as code, so the whole object is not always JSON (read from `node_modules/swagger-ui-express/index.js` in the image). The package README mounts it at `/api-docs` in both of its examples.
- **Schemathesis on that spec**, run directly with the pinned image 4.33.4 and the arguments of ADR 0028 item 4, 3 runs: every run 3 test cases and the same one failure, `ST103` (undocumented status code: the operation answers 401, which the spec does not list), with Schemathesis warning that authentication failed; about 5 seconds each. Through SiegeKit (3 runs, `--only public-maps,served-secrets,schemathesis`): 4 requests and the same `ST103` finding at `http://127.0.0.1:3000/b2b/v2/orders` each time, about 10 seconds per scan.
- **Source maps.** None of Juice Shop's 7 scripts and 1 style names a source map, and `<file>.map` answers 200 with the app's HTML page for all 8. So a source map must be recognized by its content, not by a 200.
- **Source map format.** ECMA-426 (the Source Map specification, `tc39/ecma426` `spec.emu`): the `version` field "shall always be the number 3"; an index map has `sections` instead of `mappings`; servers may put a line starting with `)]}'` before the JSON.

## Decision

1. **`public-maps`** is SiegeKit's own check, family `dast`, for URL targets. It runs on every target, `--deployed` and `--profile quick` included, because it sends only GET requests (on deployed targets through a read-only configuration, as `served-secrets`). Like the other URL checks it runs only on Linux for now (ADR 0018). It needs no container image.
2. **Specs.** SiegeKit sends one GET to each of 11 paths: the 10 default paths of ADR 0028, then `/api-docs/swagger-ui-init.js`. It follows no redirects, reads at most 10 MiB, and sends no faster than the mode's rate (100 per second on local targets, 10 on deployed ones). A path is a spec when it answers 200 and passes ADR 0028's check (`openapi.Check`); for the setup script, the `"swaggerDoc"` value that follows `var options = {` is decoded as JSON and then checked. Every spec found is a finding, not only the first.
3. **Source maps.** The files `served-secrets` fetches are fetched once and shared (as for `backend-live`, ADR 0037). A source map counts when its content is one: a JSON object whose `version` is the number 3, with a `mappings` string or a `sections` array, after an optional `)]}'` line. In addition to the map a script or style names (ADR 0032), SiegeKit now also tries `<file>.map` for each fetched same-origin script and style that names none and has no query, because build tools can write a map without naming it (webpack's `hidden-source-map`). Such a guessed file is kept only if it is a source map; otherwise it is counted (`tried <file>.map for N file(s) naming no source map, M not one`) and not scanned. These GETs count toward ADR 0032's limit of 200 requests, so `served-secrets` also scans the maps found this way.
4. **Findings.** Severity low (SiegeKit's scale): a served spec or source map helps an attacker choose what to test, but is not itself a flaw, and a public API may publish its spec on purpose (the message says so).
   - `public-api-spec`, CWE-200, at the spec's URL (the setup script's URL for Swagger UI, and the message names the page).
   - `public-source-map`, CWE-540, at the map's URL. Keys inside it stay `served-secrets` findings.
   The report's plugin entry gives `input`, `result` (`found N API spec(s) at 11 path(s) tried, and M source map(s) for K script(s) and style(s)`) and `requests`: the 11 GETs, plus the shared fetches when neither `served-secrets` nor `backend-live` ran and counted them.
5. **Schemathesis and access-control.** The 11 paths are tried once per run and shared: on local targets the first spec found is the one Schemathesis tests and access-control adds routes from, as before; the setup script comes last, so a spec at a default path still wins. A spec found at the setup script is mounted as `spec.json`. On deployed targets the spec found is only reported: Schemathesis does not run there, and access-control does not add its routes (unchanged from ADR 0028 and 0035; using them is a later decision).
6. **Order.** When a check that uses a spec runs, the 11 GETs are sent where the default-path GETs were sent before (after the audit entry and the reachability GET); otherwise they are sent after `served-secrets` and `backend-live`.
7. **Test app and gate.** The test app also serves its spec in a Swagger UI setup script and a second script with a map it does not name; the in-process test must find both specs and both maps and nothing else. On Juice Shop the gate expects one `public-api-spec` at `/api-docs/swagger-ui-init.js`, no source map, and Schemathesis to run on that spec with the `ST103` finding.

## Consequences

- A spec or source map that anyone can download is reported on every URL target, deployed ones included. With the setup-script path, Schemathesis now runs on Juice Shop, and on other apps that use swagger-ui-express at `/api-docs`.
- Each URL scan sends 11 more GETs (about 0.1 s at 100 per second, 1 s at 10 per second) and one more GET per script or style that names no source map (8 on Juice Shop). On local targets with a check that uses a spec, the paths after the first spec are now also tried (up to 10 more GETs than before).
- **Not covered:**
  - specs at other paths (for example `/docs/openapi.json`, `/api/v1/swagger.json`), Swagger UI mounted elsewhere than `/api-docs`, other Swagger UI setups (a page that loads its spec from a URL, Redoc, FastAPI's `/docs` page; its spec at `/openapi.json` is covered), and GraphQL schemas;
  - source maps of scripts loaded later by other scripts, inline `data:` maps, maps at another name, and files behind a login (as ADR 0032);
  - whether a spec lists more than the app's public routes: SiegeKit reports that it is served, not what it reveals.
- The finding is low and may be intended: a public API often publishes its spec. The person decides.

## Alternatives considered

- Adding `/api-docs/swagger.json` to the path list, as first proposed: it would not have helped, because Juice Shop answers that path with HTML (measured).
- Parsing any Swagger UI page and following its spec URL: more cases, but the forms differ between Swagger UI builds and none was measured. Not chosen now.
- Reporting at info level, like ffuf's `path-found` and Nuclei's `swagger-api`: an exposed attack map is what Unit 42 advises removing, so it is ranked above an informational path; it stays below flaws.
- Making the findings part of `served-secrets`: it needs the Gitleaks image and is about secrets, so a spec would not be reported when the image is declined.
