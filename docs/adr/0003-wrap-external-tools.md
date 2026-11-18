# 0003. Wrap external tools as sandboxed processes

- Status: Proposed
- Date: 2026-11-18

## Context

Mature open-source scanners already exist for each test family (see [THIRD_PARTY.md](../../THIRD_PARTY.md)). Rewriting them would take years and would be less accurate. Several of them use copyleft licenses (GPL-2.0, GPL-3.0, AGPL-3.0) or restrictive terms (Commons Clause on Semgrep's community rules), which must not bind SiegeKit's own Apache-2.0 code.

## Decision

- SiegeKit builds only: the CLI, planner, scheduler, target authorization, sandbox runner, output normalizer, findings store and reports.
- Every scanner is an **external process run inside a container**. SiegeKit never links scanner code into its binary and never redistributes scanner binaries in its own release artifacts.
- Scanner images or binaries are fetched from the publisher's official release at a pinned version with a pinned SHA-256 (see ADR 0008).
- Tools with restrictive or non-open-source terms are either optional plugins the user enables explicitly, or excluded (CodeQL).

## Consequences

- Detection quality is that of the wrapped tools; SiegeKit's value is in selection, safety, consistency and reporting.
- Each plugin needs an output parser, which is the main code we write and must test heavily (golden files and fuzzing).
- Upstream breaking changes in tool output are caught by the golden-file tests when we bump a pinned version, never at runtime.

## Alternatives considered

- **Linking tools as Go libraries** (possible for some Go tools): couples our release to theirs, and some are AGPL. Rejected.
- **Writing our own scanners:** rejected for v1; may be revisited for gaps no existing tool covers.
