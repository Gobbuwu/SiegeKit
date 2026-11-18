# 0006. Sandbox and network egress control

- Status: Proposed
- Date: 2026-11-18

## Context

SiegeKit runs third-party tools against untrusted input: source code that may contain hostile build scripts, fuzz harnesses that crash on purpose, and web apps that return attacker-controlled content. A compromised or buggy tool must not be able to read the user's files, reach arbitrary hosts, or persist on the machine.

## Decision

Every plugin runs in its own short-lived container:

- **Engine:** Docker or Podman, detected at start. Rootless mode is recommended and shown as a warning when not used. On macOS the engine's Linux VM is used.
- **Filesystem:** the target is mounted read-only; only a per-run output directory is writable. No home directory, SSH keys, cloud credentials or container-engine socket are mounted.
- **Privileges:** runs as a non-root user inside the container, all Linux capabilities dropped, `no-new-privileges` set, read-only root filesystem where the tool allows it.
- **Resources:** CPU, memory and process-count limits from the manifest; wall-clock timeout enforced by SiegeKit, which kills the container on expiry.
- **Network:**
  - `network: none` plugins get no network interface at all.
  - `network: target-only` plugins are attached to an internal network whose only route out is a SiegeKit egress proxy. The proxy allows only the target addresses approved under ADR 0005 and refuses everything else, including DNS to other names and the always-blocked ranges in ADR 0005 (for example cloud metadata at `169.254.169.254`).
- **GPU:** passed through only to plugins whose manifest declares `gpu: optional` or `required`, and only when the user enables GPU use.
- **Untrusted code never runs on the host.** Building or executing the user's code for fuzzing happens inside the container.

## Consequences

- A container engine is a hard requirement. SiegeKit will check for it and explain how to install it.
- GPU pass-through depends on the user's driver and container toolkit; the hashcat plugin will fall back to CPU when it is unavailable.
- The egress proxy is security-critical code and gets its own tests, including attempts to reach non-approved addresses.

## Alternatives considered

- **Running tools directly on the host:** simplest, but a hostile repository could execute code with the user's privileges. Rejected.
- **Full virtual machines per run:** stronger isolation, much slower and heavier. May be offered later as an option for binary fuzzing.
