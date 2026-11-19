# 0013. Run storage as JSON files

- Status: Accepted
- Date: 2026-11-18
- Amends: [0007](0007-findings-format.md) (storage only)

## Context

ADR 0007 planned a local SQLite database for comparing runs. A SQLite driver for Go is either a cgo binding (which breaks the single static binary in ADR 0002) or a large pure-Go translation with many transitive dependencies (against the minimal-dependency rule in ADR 0008). M1 only needs to save runs and compare two of them.

## Decision

- Each run is saved as one JSON file, `<UTC timestamp>-<target slug>.json`, in the user's SiegeKit data directory, created with permissions `0700` (directory) and `0600` (files).
- Writes go to a temporary file that is renamed into place, so an interrupted run never leaves a partial file. Existing runs are never overwritten.
- Comparison ("new", "fixed", "still present") uses finding fingerprints. A finding counts as fixed only if the plugin that reported it ran to completion in the newer run; otherwise it stays listed, so a failed check cannot make problems look fixed.

## Consequences

- No database dependency. Comparing many runs is linear in file count, which is fine for a local tool.
- If querying across many runs is needed later, a new ADR can introduce an index without changing the files.
