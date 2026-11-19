# 0023. Running active web scans: ZAP as the first active plugin

- Status: Accepted
- Date: 2026-11-19
- Amends: [0004](0004-plugin-manifest.md) (two manifest fields)

## Context

M2.4 is the first time SiegeKit sends test traffic to a target. ADRs 0005, 0017, 0018, 0019, 0021 and 0022 decide who may be tested, how the traffic is confined, and that the plan is shown first. They do not decide how a URL scan runs its plugins, how a tool that needs a configuration file gets one, or which tests may run on a deployed target before the request limits are measured (M2.10).

The owner decided on 2026-11-19 ("1c 2a 3a"):

1. SiegeKit's own small vulnerable app is the test fixture, so every planted issue is known; OWASP Juice Shop is scanned in the CI gate as well (M2.4b).
2. The fixture is for tests and CI only. There is no `siegekit demo` command.
3. ZAP crawls and runs its passive checks on every target. Its attack scan runs only on local targets. Deployed targets get the passive checks until M2.10 measures the load.

Facts checked before this ADR, with the pinned image `zaproxy/zap-stable:2.17.0` (published 2026-11-03 by the ZAP organization, "ZAProxy Ltd", on Docker Hub; index digest `sha256:9624669d…`, linux/amd64 and linux/arm64):

- ZAP's packaged scan scripts (`zap-baseline.py`) write to `/home/zap`, which fails on the sandbox's read-only root file system. Running `zap.sh -cmd -autorun PLAN` with `-dir /tmp/zap` works read-only, as a non-root user.
- ZAP opens its own proxy on port 8080 by default, which is the relay's port in the shared network namespace. It must listen elsewhere (`-port 8090`).
- Java ignores `HTTP_PROXY`. ZAP's outbound proxy is set with `-config network.connection.httpProxy.*`.
- `zap.sh` sets the Java heap to a quarter of the memory it finds. It reads the container limit only on cgroup v1, so on cgroup v2 hosts (GitHub's Ubuntu runners) it sized the heap from the host and the container was killed (exit 137). ZAP also needs more than 512 MiB to start, even with a 256 MiB heap. The plugins pass `-Xmx1024m` with a 2048 MiB limit; a full scan of Juice Shop peaked at 1.23 GiB.
- `-silent` stops ZAP's own update and news requests. Without it, the egress proxy refused 9 requests that were not for the target.
- The Automation Framework accepts a JSON plan, and the `sarif-json` report lists each alert's CWE in `relationships` and its references in `properties.references`.

## Decision

1. **URL scans run active plugins.** After the target rules allow the target, SiegeKit selects the built-in plugins whose `targets` include `url`. It reports the ones that do not run in this mode, and asks before downloading the images of the others and of the relay (ADR 0016). It prints the plan: target, mode, addresses, plugins, limits and the User-Agent label (ADR 0022). It appends the run to the audit log, and if that fails no test is sent (ADR 0005). Each plugin runs in turn, each behind its own egress proxy, relay and CA (ADR 0018, 0019).
2. **`localOnly` manifest field.** An active plugin with `localOnly: true` never runs on a deployed target. The report says why. A destructive plugin is also skipped on deployed targets until `--allow-destructive` arrives with M2.5 (ADR 0005 item 3).
3. **`run.config` manifest field.** A JSON object that SiegeKit writes to a file and mounts read-only at `/siegekit/config.json`. `{config}` in `run.args` is that path. Its string values may use only `{target}` and `{target-regex}` (the target URL with regular-expression characters escaped). They are substituted inside JSON strings before the file is written, so a target can never change the file's structure. The file is never written into the tool's output directory, which must start empty and is writable by the tool.
4. **Two ZAP plugins**, both pinned to the image above:
   - `zap`: spider plus passive rules. It is not destructive, so it runs in both modes. Its spider does not submit forms (`processForm` and `postForm` are false): ZAP's spider fills in and submits forms, POST forms included, by default. The security review of this change found that, and a test server received a POST from the spider before the fix and none after it.
   - `zap-active`: spider plus ZAP's active scan rules, with passive rules turned off so their results are not counted twice. It is `destructive` and `localOnly`.
   Both scope ZAP to the target URL, use `-silent`, keep ZAP's files in `/tmp`, and write SARIF to `/out`. The `sarif-zap` parser takes the help link from ZAP's references. The SARIF reader now also takes CWE IDs from rule `relationships`, which gosec's reports carry too.
5. **Provisional limits until M2.10.** Local targets: 100 requests per second (burst 20), 16 connections, and a stop after 100 server errors in a row. Deployed targets: 10 requests per second (burst 5), 8 connections, and a stop after 10. A plugin that sent no request to the target is reported as failed, because it tested nothing (ADR 0009). Reports show how many requests each plugin sent and how many the proxy refused.
6. **Linux only** for now (ADR 0018). Elsewhere, active plugins are reported as failed, so the run is incomplete, never clean.

## Consequences

- `siegekit scan URL` now sends traffic. Everything before the first request (target rules, proof, typed confirmation, plan, audit entry) is unchanged or stricter.
- ZAP's image is about 1.1 GB, and the consent prompt says so.
- The `zap` spider still follows every in-scope link with GET. A site whose links change data (a "delete" or "log out" link, for example) can be changed by the crawl. Staging is recommended for deployed scans (threat model T13).
- On deployed targets the egress proxy allows only GET and HEAD from plugins that are not destructive (owner decision, 2026-11-19), so a tool's default cannot submit data there. `TestReadOnly` checks that POST, PUT, DELETE, PATCH, OPTIONS and other methods are refused over HTTP and HTTPS.
- On deployed targets, ZAP checks only what the crawled responses show. Injection flaws on a deployed target are not tested until M2.10, which the report's "Not tested" list says.
- Requests go through the relay one connection at a time per ZAP thread. Measured in the container test: the spider and passive checks on the fixture took about 20 seconds, and the attack scan sent 773 requests in under 30 seconds.

## Alternatives considered

- **ZAP's packaged scan scripts:** they need a writable home directory, which the sandbox does not give.
- **Writing the plan into the output directory:** the sandbox requires that directory to be empty, and the tool could change the plan.
- **One ZAP plugin with mode-dependent jobs:** two plugins make it visible in every report which one ran and why the other did not.
