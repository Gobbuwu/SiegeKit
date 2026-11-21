# 0045. gosec checks one package at a time

- Status: Accepted
- Date: 2026-11-21
- Amends: [0040](0040-tools-that-skip-work.md) (another way a tool drops results)

## Context

Since #47 the known-answer gate listed 4 of go-chi/chi's gosec findings as `unstable`: G705 `_examples/pathvalue/main.go:24` and G710 `middleware/profiler.go:27`, `:30` and `middleware/strip.go:62`. Four CI runs had reported 4, 4, 3 and 1 of them, while 52 local runs reported all 4 (full project check F3).

Measured on CI on 2026-11-21 (PR #54, a temporary workflow: GitHub `ubuntu-latest`, rootless Podman 5.7.0 and rootful Docker 29.4.2, both cgroup v2, Go 1.27.4, the pinned gosec 2.30.0 image with its 2-CPU, 2048 MiB limits; go-chi/chi at the answer's commit; gosec's stderr kept):

| gosec concurrency | Podman | Docker | Runs with all 4 |
|---|---|---|---|
| default (round 1) | 18 of 20 | 16 of 20 | 34 of 40 |
| default (round 2) | 17 of 20 | 19 of 20 | 36 of 40 |
| `-concurrency 1` | 20 of 20 | 20 of 20 | 40 of 40 |

- A run lost either the 3 G710 in `middleware` or the G705 in `_examples/pathvalue`. Each run's total was 70, 69 or 67, so the other 66 findings were reported every time (by count).
- In those runs gosec's stderr had extra lines like `Error building the SSA representation of the package middleware: package middleware has type errors, skipping SSA analysis`. In round 1 the count of these `middleware` lines matched the count of runs that lost `middleware`'s findings on each engine. The taint rules work on SSA, so they are skipped for that package. Neither package is among the 6 that gosec cannot load offline, and one at a time they were checked in every run.
- SiegeKit did not see it. In all 40 runs of round 2, `report.json` named the same 6 packages that could not be loaded (the modules missing offline), whether or not a run lost findings. gosec does not put these type errors in the JSON "Golang errors" that SiegeKit reads (ADR 0040). It exits as usual.
- One at a time was faster: 20 scans, including the first image download, took 6.9 minutes instead of 16.3 on Podman, and 5.2 instead of 12.3 on Docker.

Why gosec sees type errors that are not there when it checks packages at the same time is not known. gosec's default concurrency is `runtime.GOMAXPROCS(0)` (`cmd/gosec/main.go:150` at v2.30.0). That is 2 under the container's CPU limit if the image's gosec was built with Go 1.25 or later, and the runner's CPU count otherwise; the image's Go version is not recorded. Memory pressure inside the 2048 MiB limit is a guess (unverified).

This is the failure class of ADR 0040: a tool drops part of its results, exits as usual, and SiegeKit reports what remains.

## Decision

1. **gosec runs with `-concurrency 1`.** `TestBuiltin` requires it.
2. **go-chi's 4 G7xx findings are no longer `unstable`.** The gate requires all 4 on every run.

## Consequences

- Taint-rule findings on Go code no longer depend on timing in the measured case. Scans of large Go repositories may take longer. On go-chi they took less than half the time.
- Not fixed: SiegeKit cannot tell when gosec skips a package's SSA analysis for this reason, because gosec does not report it in its output. Detecting it from stderr (the lines name a package, not a directory) belongs to design part 3 ("checks that finish or say so"). It is recorded as a known gap in the M2 record.
- Not verified: other repositories at concurrency 1 beyond the Go fixtures in the gate (go-chi, gin, cobra, caddy, awesome-compose), which run on both engines with this change.

## Alternatives considered

- **Keep the 4 as `unstable`.** It hides dropped findings instead of keeping them. Rejected (ADR 0043 made the same choice for ZAP).
- **`-concurrency 2`, the container's CPU limit.** Not measured, and it may be the default already. One at a time is measured stable and was faster, so there was no reason to pick an unmeasured value.
