# 0014. Offline tool data and update containers

- Status: Accepted
- Date: 2026-11-19
- Amends: [0006](0006-sandbox.md) (adds one network mode for data updates)

## Context

Dependency scanners such as Trivy need a vulnerability database that changes every few hours, and rule-based scanners may need rule packs. Scans must keep running with no network (ADR 0006), and the target must never be mounted into a container that can reach the internet: that container could send the user's code anywhere.

## Decision

- A plugin manifest may declare a `data` section: the path where the data is mounted in the container (`mount`, under `/tmp` or `/data`), the arguments for an update run (`updateArgs`, placeholders `{data}` and `{threads}` only) and `maxAgeDays`.
- `siegekit update` (or `siegekit scan --update`) runs each such plugin's pinned image with `updateArgs` in a separate container:
  - the engine's default network (outbound access), because the data comes from the tool's publisher;
  - no target, no user files and no credentials mounted, only an empty, new data directory (read-write) and an empty output directory;
  - every other sandbox rule from ADR 0006 (non-root user, no capabilities, read-only root file system, memory, CPU, process and time limits).
- The sandbox refuses a networked run that mounts a target, and refuses writable data when a target is mounted.
- Data lives in `~/.local/share/siegekit/data/<plugin>/` (or `$XDG_DATA_HOME`). The data root is mode `0700`. New data is written to a new directory and swapped in only after the update succeeds, so a failed update keeps the previous data. An update that writes nothing, or more than 8 GiB, fails.
- SiegeKit, not the tool, records the update time in `<plugin>.updated` next to the data directory.
- Scans mount the data directory read-only, with `--network none`. If the data is missing, the check is reported as failed (the run is incomplete, exit code 4) with the instruction to run `siegekit update`. If it is older than `maxAgeDays`, the check runs and the report says how old the data is.
- Updates never run implicitly: scanning stays offline unless the user asks for an update.
- Only built-in plugins exist in M1. Third-party plugins with a `data` section must wait for the M2 egress proxy, which can restrict update containers to the publisher's hosts.

## Consequences

- A compromised tool image in update mode has network access. It cannot read the user's code or files, but it could reach the user's local network. Image pinning by digest, the 7-day adoption delay and review (ADR 0008) are the mitigation until the M2 egress proxy limits update traffic to declared hosts.
- Downloaded data is not pinned: it is fetched by the tool from its publisher (for Trivy, the `trivy-db` OCI artifact). Tampered data could hide or invent findings but runs only in the offline, read-only scan sandbox.
- Users who need an HTTP proxy, or whose network intercepts TLS, cannot update yet: the update container gets no proxy settings and does not trust the host's certificate authorities. Planned: options to pass a proxy and mount a CA bundle read-only.
- CI can cache the data directory between runs.

## Alternatives considered

- Downloading data inside the scan container: mixes network access with the user's code. Rejected.
- SiegeKit downloading the data itself: each tool has its own format, location and update protocol; reimplementing them is error-prone and breaks with tool upgrades.
- Bundling data in the release: the data is large (Trivy's database is about 1.7 GB unpacked) and goes stale within hours.
