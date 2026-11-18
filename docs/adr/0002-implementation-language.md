# 0002. Implementation language and platforms

- Status: Proposed
- Date: 2026-11-18

## Context

The orchestrator must run on Linux and macOS, start and supervise many external processes and containers, parse their output, and ship as something a non-expert can install. Many tools SiegeKit wraps (Trivy, Grype, Syft, OSV-Scanner, Gitleaks, Nuclei, gosec, ffuf) are written in Go.

## Decision

- Language: **Go**. Builds use the newest Go minor release that is still supported upstream (Go 1.27.x at the time of writing; the newest toolchain listed on proxy.golang.org on 2026-11-18 was 1.27.4). `go.mod` declares the oldest supported minor version so security fixes from either supported line can be used.
- Distribution: a single static binary per OS/architecture, plus a container image.
- Platforms for 1.0: Linux (amd64, arm64) and macOS (arm64, amd64). Windows is supported through WSL2, running the Linux build.
- Interface: command-line first, with a self-contained HTML report. A GUI is built only after the backend reaches release quality (after M4).
- External tools that are written in other languages (Python, Java) run inside their containers, so users never install those runtimes on the host.

## Consequences

- One static binary with no runtime dependency on the host besides a container engine.
- Go's memory safety removes a class of bugs from the code that parses untrusted tool output.
- Native Go fuzzing (`go test -fuzz`) is available for our own parsers.
- Native Windows support is deferred; Windows-specific paths and process handling are not tested before 1.0.

## Alternatives considered

- **Python:** fastest to prototype and many tools are Python, but distributing a reliable, self-contained Python application across OSes is harder, and dynamic typing makes the parsing layer riskier.
- **Rust:** strongest safety guarantees, but slower development, and little ecosystem overlap with the wrapped tools.
