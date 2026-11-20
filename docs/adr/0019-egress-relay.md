# 0019. Egress through a relay with no network

- Status: Accepted
- Date: 2026-11-19
- Amends: [0018](0018-egress-proxy.md) (items 2 and 7)
- Amended by: [0021](0021-built-in-relay.md) (the relay is SiegeKit's own binary in the official Alpine image, not `alpine/socat`)

## Context

ADR 0018 put the tool container on an `--internal` network and had the proxy listen on that network's gateway address. Wiring it up (M2.3b) turned up two problems:

1. **Host exposure.** A container on an internal network reaches the host on the gateway address on every port, not only the proxy's. Any service on the host that listens on all addresses, such as a database or SSH, would be reachable from the tool container.
2. **Rootless engines.** With rootless Docker or Podman, the network lives in a separate namespace, so a process on the host cannot listen on the gateway address at all.

What was checked on Linux with Docker 29.10.0 (2026-11-19), using the relay image below:
- A container started with `--network container:<relay>`, where the relay has `--network none`, has only a loopback interface and no routes.
- From it, DNS, `1.1.1.1` and the host bridge address `172.17.0.1` all fail with "Network unreachable".
- A Unix socket bind-mounted read-only into the relay accepts connections from a non-root user.

## Decision

1. **No network for the tool.** Each `target-only` run starts a relay container with `--network none`. The tool container joins the relay's network namespace (`--network container:<relay>`), so it has only a loopback interface. The relay has the same hardening as tool containers: non-root, all capabilities dropped, read-only root filesystem, `no-new-privileges`, and memory and process limits.
2. **One way out.** The relay runs `socat`, listening on `127.0.0.1:8080` inside the shared namespace and forwarding each connection to a Unix socket. The socket is mounted read-only from a per-run host directory (mode 0711, socket 0666). The SiegeKit egress proxy from ADR 0018 listens on that socket on the host. The tool's proxy settings point at `http://127.0.0.1:8080`.
3. **SiegeKit sets the proxy environment.** `HTTP_PROXY`, `HTTPS_PROXY` (and lower-case forms) and an empty `NO_PROXY` are set by SiegeKit, never by a manifest. For an https target, the per-run CA certificate is mounted read-only at `/siegekit/ca.pem`, and `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS` point at it. Plugins whose tool needs another trust store (Java) add the certificate in their own arguments.
4. **The relay image** is `alpine/socat` 1.8.1.1 (Alpine 3.24 base, published 2026-06-20), pinned by index digest under ADR 0008. Like every other image, it is downloaded only after the user agrees (ADR 0016).
5. **The proxy stays on the host.** It reaches a loopback target such as `http://localhost:3000` directly, and it is not exposed on any network.
6. **macOS** stays refused, as in ADR 0018 item 7. Docker Desktop does not pass Unix sockets from the Mac into containers in general. A Linux-only check refuses `target-only` plugins elsewhere.

## Consequences

- The tool container cannot reach the host, other containers, DNS or the internet. It can reach only the proxy, which allows only the target.
- No `--internal` network is created, so no network is left behind if SiegeKit is killed. A relay container could be left behind, but it is started with `--rm` and has no network.
- It works with rootless Podman: CI's container tests, including `TestActiveRunOnlyReachesTarget`, run on rootless Podman 5.7.0 with cgroup v2 on GitHub's `ubuntu-latest` runners (found 2026-11-20; asserted by `TestDescribe` from PR #46, ADR 0038). Rootless Docker, and rootful Docker on cgroup v2, are unverified.
- One more small image (about 15 MB) is downloaded before the first active test.

## Alternatives considered

- **Internal network with the proxy on the gateway (ADR 0018):** exposes host services and fails on rootless engines.
- **Proxy in a container on two networks:** needs a SiegeKit-built Linux image and cannot reach a target on the host's loopback.
- **Host firewall rules:** would need root and would change the user's firewall.
