# 0022. Ask before running only for URL targets

- Status: Accepted
- Date: 2026-11-19
- Amends: [0004](0004-plugin-manifest.md) (the last paragraph of its Decision)

## Context

ADR 0004 says: "Before anything runs, SiegeKit prints the resolved plan (plugins, versions, mode, target, limits) and asks for confirmation." The re-check of 2026-11-19 found that this was never built. Directory scans print the checks they run and start. Asking on every directory scan would block CI jobs and AI coding assistants, which run without a person at a terminal. URL targets already need a person's confirmation under ADR 0005 and ADR 0017. The owner approved this change on 2026-11-19.

## Decision

1. A scan of a directory prints its plan and does not ask. A directory scan only reads files and runs tools with no network.
2. A scan of a URL target keeps the confirmations of ADR 0005 and ADR 0017: a typed host name, `--authorized-host` for private addresses, and proof of control for deployed targets. Before any active test is sent, it prints the plan: target, mode, addresses, plugins and limits.
3. Downloads still need consent (ADR 0016).

## Consequences

- CI and AI assistants can scan directories without a terminal, as they do today.
- Every active test still has a person's confirmation of the target.
