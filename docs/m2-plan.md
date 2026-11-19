# M2 plan: active web and API testing

Status: in progress (started 2026-11-19, after the M1 sign-off). This splits the [roadmap](roadmap.md) M2 scope into small pull requests. Each one keeps CI and the real-repository gate green and is merged when all checks pass. Security-critical parts come first, before any tool can send traffic.

| PR | Scope | Main design | Done when |
| --- | --- | --- | --- |
| M2.1 | URL targets and address rules: parse `scan URL`, resolve the host once, classify addresses (loopback, private, public, always blocked), local mode with typed confirmation for private addresses, append-only audit log. No traffic is sent yet. | ADR 0005 | Unit and negative tests for every address class, including IPv6, IPv4-mapped IPv6, decimal and octal IP spellings, and names that resolve to blocked addresses. |
| M2.2 | Deployed mode: a 128-bit token per host (kept between runs, checked at the start of every run), check at `/.well-known/siegekit-verify.txt` (no redirects) or DNS TXT `_siegekit-verify.<host>`, address pinning, typed host confirmation in a terminal (`--authorized-host` is not accepted in deployed mode), no bypass flag. | ADR 0005 | Negative tests: wrong host, subdomain, redirect, stale token, rebinding to a private address. |
| M2.2a | Support for AI coding assistants (owner request, 2026-11-19): `siegekit agents` prints a guide (`docs/agents.md`) with commands, flags, exit codes, the `report.json` fields and safety rules; `report.json` gets `schemaVersion`; findings carry the tool's `helpUri` (https only) in JSON, SARIF and HTML; refusals send the person to a terminal. The person still authorizes every target and download: deployed targets need the host name typed, and the guide tells assistants never to confirm for the person. | ADR 0005, 0016 | A test fails if a `report.json` field is missing from the guide; a real Trivy run shows `schemaVersion` and `helpUri`. |
| M2.3 | Egress proxy: `target-only` plugins run with no network except a relay container whose only way out is a SiegeKit proxy on the host (ADR 0019 replaced the internal network of ADR 0018) that allows the pinned addresses only, enforces the rate cap, sets the `SiegeKit/<version>` User-Agent where possible, and stops the run after repeated server errors. | ADR 0006, 0018, 0019 | Proxy tests that try metadata addresses, other hosts, DNS to other names and direct connections from the tool container. This PR completes the first half of the M2 gate. Done in two PRs: the proxy itself, then its sandbox wiring with container tests. Active tests run on Linux first; macOS stays refused until a CI job on GitHub's Intel macOS runners (Colima) passes and the owner agrees (decided 2026-11-19). |
| M2.4 | Vulnerable web fixture and the first active plugin: SiegeKit starts a pinned deliberately vulnerable app in a container (local mode) and runs ZAP against it. The relay image (ADR 0019) joins the dependency consent prompt here, with the first plugin that needs it. | ADR 0003, 0005 | Known fixture issues found by ZAP; findings imported through SARIF or ZAP's JSON. |
| M2.5 | Nuclei and ffuf (exposed files, misconfigurations), Schemathesis for OpenAPI targets. | ADR 0003 | Fixture issues found; destructive templates gated by `--allow-destructive`. |
| M2.6 | Login checks: login throttling with a test account and a random wrong password; default credentials (local mode only); secrets in served content. | ADR 0010 | Tests show limits are enforced (count, rate, deployed-mode gating). |
| M2.7 | App-logic checks: authorization differential, unauthenticated route check, rate-limit check, live backend-rules check. | ADR 0011 | Fixture issues found. |
| M2.8 | Passive tools moved from M1: OSV-Scanner, Syft (SBOM), Grype. | ADR 0003, 0014 | Planted issues found; real-repository gate still green. |
| M2.9 | Opengrep as the first pinned-binary plugin, with SiegeKit's own Apache-2.0 rules for JavaScript and TypeScript; opengrep-rules only downloaded after license acceptance. | ADR 0003, 0016 | Planted issues found on Linux and macOS, amd64 and arm64. |
| M2.10 | Optional sqlmap and Nikto; measure and set the default request rate; full M2 gate run. | ADR 0005 | M2 gate: all target-authorization negative tests pass and all known issues in the vulnerable web fixture are detected. Then the owner signs off. |

Added at the owner's request on 2026-11-19, outside the numbered PRs: a check for environment files. The `gitleaks-history` plugin scans every commit for secrets and committed `.env` files, and the built-in `dotenv-gitignore` check warns when `.gitignore` does not exclude them. Manifests gain `run.env` and `requiresGit` for this.

## Follow-ups from the re-check of 2026-11-19

The [re-check](recheck-2026-11-19.md) found items that earlier ADRs decided but no plan scheduled. The owner placed each one on 2026-11-19:

| Item | Decision |
| --- | --- |
| Pick checks by family (`--only secrets`) and `--profile` (ADR 0004) | M2, with M2.5. ADR 0022 changes ADR 0004 so that only URL scans ask before running; directory scans print the plan without asking. |
| Compare runs: "new" and "fixed" since the last scan (ADR 0007, 0013) | M2, a small PR. |
| OSV-Scanner and OpenSSF Scorecard in CI; image signature checks (ADR 0008) | On hold: the owner asked whether they are necessary. |
| Warning when the container engine is not rootless (ADR 0006) | No change until rootless engines are tested. |
| Restrict update containers to the publisher's hosts through the egress proxy (ADR 0014, threat model T19) | M2. |
| Container-image targets (secrets in images, base-image packages) | M3. |
| End-of-life runtime check | Declined: not a security issue in itself, and no data source has been confirmed. |
| Report the languages found in the target (ADR 0009) | M2, with M2.9. |
| Unit test coverage of 80% or more in every core package | M2, one test-only PR (deps, audit, registry and plugins are below 80%). |

Every PR that adds a command, flag or report field also updates `docs/agents.md`.

Every new dependency (tool image, binary, fixture image) goes through the ADR 0016 consent prompt and ADR 0008 pinning (digest, at least 7 days old).

Open questions are asked of the owner when a PR reaches them, not guessed.
