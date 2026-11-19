# 0017. Target rule details

- Status: Accepted
- Date: 2026-11-19
- Amends: [0005](0005-target-authorization.md)

## Context

Implementing ADR 0005 (M2.1) raised cases it does not spell out: addresses that are internal in practice but not in its private list, IPv6 forms that carry an IPv4 address, host names that some tools read as IP addresses, and how a script or CI job gives the typed confirmation.

## Decision

1. **More internal ranges count as private**, so they need confirmation in local mode and are refused in deployed mode: shared address space used by carrier NAT and VPN overlays such as Tailscale (`100.64.0.0/10`), benchmarking (`198.18.0.0/15`), the IETF protocol block (`192.0.0.0/24`) and the reserved `240.0.0.0/4`.
2. **IPv6 addresses that carry an IPv4 address are judged by it**: IPv4-mapped (`::ffff:a.b.c.d`), NAT64 (`64:ff9b::/96`; the local-use `64:ff9b:1::/48` always counts as private), 6to4 (`2002::/16`) and IPv4-compatible (`::a.b.c.d`). A wrapped loopback address counts as private, because the wrapper is not this machine. IPv6 addresses with a zone (`fe80::1%eth0`) are refused.
3. **Ambiguous IP spellings are refused**: a host made only of numbers, dots and hex (`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`, `127.0.0.01`) must be a plain dotted-decimal IPv4 address, because tools disagree on how to read the other forms.
4. **A name must resolve only to allowed addresses.** If any address is not allowed in the chosen mode, the run is refused, even if others are allowed.
5. **Confirmation without a terminal** (chosen by the project owner on 2026-11-19): `--authorized-host HOST` must match the target host exactly (case and a trailing dot aside) and is recorded in the audit log as the verification method. Without it and without a terminal, a target that needs confirmation is refused. A standard input that is not a terminal (a pipe, `/dev/null`) never counts as one.
6. **Target URLs never keep credentials, queries or fragments.** A URL with a user name or password is refused; queries and fragments are dropped before the target is shown, logged or passed to a tool.

## Consequences

- Some home and corporate setups (Tailscale, carrier NAT) need `--authorized-host` or a typed confirmation where ADR 0005 alone would have treated the address as public and asked for deployed-mode proof.
- The audit log (`audit.log` in SiegeKit's data directory, JSON lines, mode 0600, append-only, at most 64 MiB) is written when an active run starts; M2.1 has no active plugin yet.
