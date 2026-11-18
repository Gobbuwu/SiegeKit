# 0005. Target modes and authorization

- Status: Proposed
- Date: 2026-11-18

## Context

Active tests (DAST, API fuzzing, injection simulation) send attack traffic. Sending it to systems the user does not control can be illegal and harmful. The project owner decided that users choose, per run, whether they are testing a **locally running app** or a **deployed app**. Both must be safe by default.

## Decision

### Passive and offline plugins

Run only on local paths (a repository, an image archive, a hash file) the user passes. No network access (enforced by ADR 0006).

### Always blocked

In every mode, the egress proxy refuses link-local addresses (`169.254.0.0/16`, `fe80::/10`, which include cloud metadata services such as `169.254.169.254`), unspecified and broadcast addresses (`0.0.0.0/8`, `255.255.255.255`, `::`), and multicast (`224.0.0.0/4`, `ff00::/8`).

### Local mode (default for active plugins)

Allowed targets:

1. Loopback addresses (`127.0.0.0/8`, `::1`).
2. Containers that SiegeKit itself started for this run (for example a test copy of the user's app).
3. Private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) only after a typed confirmation that the user is authorized to test that host, because a private address can belong to an employer or another person on the same network.

All plugin intensities are available, including destructive ones, after the run plan is confirmed.

### Deployed mode (`--deployed`)

For any target that is not covered by local mode:

1. **Proof of control, every run.** SiegeKit generates a random token (128 bits, tied to the exact host name) and the user publishes it either at `/.well-known/siegekit-verify.txt` on the target's own origin (same scheme, host and port as the target URL; redirects are not followed) or as a DNS TXT record at `_siegekit-verify.<host>`. SiegeKit checks it at the start of each run. A token for one host never authorizes another host, including subdomains.
2. **Address pinning.** The host name is resolved once at verification time. If any resolved address is loopback, private or in an always-blocked range, the run is refused, so a public name cannot be used to reach internal systems. The sandbox egress rules (ADR 0006) only allow those addresses for the rest of the run, which blocks DNS rebinding and tools that follow links to other hosts.
3. **Safe defaults.** Plugins with `destructive: true` are skipped unless the user names them with `--allow-destructive <plugin>` for that run. Request rate is capped (default to be set in M2 after measurement) and the run stops automatically after repeated server errors.
4. **Typed confirmation** of the host name before the run, plus a reminder to check the hosting provider's penetration-testing policy and to prefer a staging copy.
5. **No bypass.** There is no flag to skip verification in deployed mode.

### All active runs

An append-only local audit log records the time, target, resolved addresses, mode, verification method and plugins of every active run.

Every HTTP request sent by a plugin carries a `User-Agent` containing `SiegeKit/<version>` where the wrapped tool allows setting it, with no option to remove it, so target owners and defenders can identify the traffic.

### Limits of this control

SiegeKit is open source, so a fork can remove these checks. They prevent accidents and casual misuse by unmodified copies, not a determined attacker. The defense against a modified copy is that SiegeKit adds no capability beyond the public tools it wraps and deliberately omits mass scanning, denial of service, detection evasion and post-exploitation (see the threat model, "Misuse by a determined attacker").

## Consequences

- Users testing their own deployed app need a one-time setup step (token file or DNS record) per host.
- Someone who controls a host can still test it, which is the intended use; SiegeKit cannot detect a user lying about authorization on a private network, so local mode for private addresses relies on the confirmation and the audit log.
- A redirect to another host is blocked by the egress rules rather than followed.

## Alternatives considered

- **Only a confirmation checkbox:** too easy to misuse against third parties. Rejected for deployed mode.
- **Allow-list file of hosts without proof:** same weakness. Rejected.
- **Local mode only:** misses production-only problems (TLS, headers, exposed admin pages) that the owner wants covered.
