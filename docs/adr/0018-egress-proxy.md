# 0018. Egress proxy design

- Status: Accepted
- Date: 2026-11-19
- Amends: [0006](0006-sandbox.md)
- Amended by: [0019](0019-egress-relay.md) (relay container instead of an internal network; items 2 and 7), [0026](0026-nuclei.md) (the connection limit counts connections to the target; item 5)

## Context

ADR 0006 puts `network: target-only` plugins on an internal network whose only way out is a SiegeKit egress proxy. ADR 0005 requires that the proxy reach only the pinned target addresses, cap the request rate, and stop the run after repeated server errors. The proxy needs a concrete design for where it runs, what it accepts, and how it handles HTTPS.

What was checked on Linux with Docker 29.10.0 (2026-11-19):
- A container on an `--internal` network has no default route, and its embedded DNS answers SERVFAIL for outside names.
- That container can reach the host on the internal network's gateway address.

## Decision

1. **The proxy runs inside the SiegeKit process on the host.** No extra image or binary is needed. A loopback target such as `http://localhost:3000` is reached directly.
2. **One internal network per run.** The tool container joins a new `--internal` network. The proxy listens only on that network's gateway address, on a random port, and accepts connections only from that network's subnet. The tool gets the proxy through `HTTP_PROXY` and `HTTPS_PROXY`, or through its own proxy flag. A tool that ignores the proxy has no route anywhere. The network is removed after the run.
3. **Only the target origin.** The proxy accepts a request only for the target's exact host name (or IP literal), port and scheme. The `Host` header must name the target too. The proxy never resolves names itself: it connects only to the addresses pinned under ADR 0005, and checks them against the always-blocked ranges again. Everything else is refused with 403: other hosts, other ports, redirects to them, and a different `Host` header. A different `Host` header could send attack traffic to someone else's site on shared hosting or a CDN.
4. **HTTPS is inspected.** Without inspection the proxy sees only encrypted tunnels, so it could not count requests or see server errors. Each run creates a certificate authority in memory:
   - The private key is never written to disk.
   - Its name constraints allow only the target host, so the certificate is useless for any other site.
   - The tool container gets only the certificate, to trust.

   The proxy verifies the target's real certificate in deployed mode. In local mode it accepts self-signed certificates, which are common for development servers.
5. **Rate cap and stop.** Requests wait for a token bucket (the default is provisional until M2.10 measures it) and the number of open connections is limited. After a set number of server errors (5xx) in a row, the proxy refuses every further request and signals the runner to stop the run.
6. **Traffic is labeled.** The proxy appends `SiegeKit/<version>` to each request's `User-Agent`.
7. **macOS.** Docker Desktop and Podman on macOS run containers in a Linux VM, where the internal network's gateway is inside the VM, not on the Mac. Until this is checked on a real Mac, `target-only` plugins run only on Linux. On macOS they are refused with a message that says so.

## Consequences

- Every byte of active-test traffic passes through code SiegeKit controls, and that code is tested with Go unit tests and with container tests that try other hosts, metadata addresses, DNS and direct connections.
- Checks that need another `Host` header (virtual-host fuzzing, Host-header injection) cannot run. This is deliberate, and the report lists them as skipped once such plugins exist.
- Tools must accept a proxy and a custom certificate authority. A tool that does not is not added as a `target-only` plugin.
- Active tests on macOS wait for verification on a real Mac.

## Alternatives considered

- **Proxy in its own container:** needs a SiegeKit-built image for each CPU architecture and a release process for it, and cannot reach a target on the host's loopback.
- **Tunnel-only HTTPS (no inspection):** cannot enforce a request rate or see server errors on HTTPS targets, which ADR 0005 requires.
- **Relay container to a host proxy:** adds a container with a route out. It stays an option for macOS if the gateway approach does not work there.
