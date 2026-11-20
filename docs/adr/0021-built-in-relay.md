# 0021. The relay runs SiegeKit's own binary

- Status: Accepted
- Date: 2026-11-19
- Amends: [0019](0019-egress-relay.md) (items 2 and 4)
- Amended by: [0026](0026-nuclei.md) (at most 1,024 connections; item 1)

## Context

ADR 0019 picked `alpine/socat` as the relay image. A check on 2026-11-19 showed that the "alpine" organization on Docker Hub belongs to one person ("Bill Wang", per `https://hub.docker.com/v2/orgs/alpine/`). It is not the Alpine Linux project, and socat's authors publish no image. ADR 0008 asks for images from the publisher's official release. The relay had not been used by any plugin yet. The owner chose on 2026-11-19 to have SiegeKit do the relaying itself.

## Decision

1. The relay is a hidden SiegeKit command, `siegekit internal-relay 127.0.0.1:PORT SOCKET`. It accepts TCP connections on loopback and forwards each one to the proxy's Unix socket, with at most 64 at once (1,024 since ADR 0026).
2. For each active run, SiegeKit copies its own binary (`os.Executable`) into the per-run relay directory, with mode 0755. That directory is mounted read-only into the relay container, and the copy runs as the container's entrypoint. Every other rule of ADR 0019 stays: no network, non-root, all capabilities dropped, read-only root file system, memory and process limits.
3. The image only supplies a root file system. It is the Docker Official Image `alpine:3.24.4`, published 2026-11-08 and pinned by index digest (`sha256:f59abe65…`). It covers linux/amd64 and linux/arm64, among others.
4. The binary must be statically linked, so it runs in any image. SiegeKit checks this before it starts a relay. A dynamically linked build is refused with a message to build with `CGO_ENABLED=0`, which the README now says. Release builds are static (ADR 0002).

## Consequences

- No third-party relay image. The code that forwards active-test traffic is SiegeKit's own, reviewed and tested like the proxy.
- A local build with cgo cannot run active tests until it is rebuilt with `CGO_ENABLED=0`.
- The relay binary has the same version as the SiegeKit that started it.
- macOS stays refused (ADR 0018 item 7). A macOS SiegeKit binary is not a Linux executable, so this design would need a Linux build of SiegeKit for the relay there.
