# 0040. A tool that skips part of its work makes the run incomplete

- Status: Accepted
- Date: 2026-11-21
- Amends: [0009](0009-honest-results.md) (a check that did part of its work is incomplete), [0039](0039-known-answers-and-engine-parity.md) (a known answer can be "failed")
- Amended by: [0043](0043-zap-reports-every-alert.md) (a tool can also drop results it found: ZAP's systemic alert limit), [0045](0045-gosec-one-package-at-a-time.md) (gosec skips taint rules when checking packages at the same time), [0067](0067-checks-finish-or-say-so.md) (file gaps are named without failing the check; run stops fail it)

## Context

The full project check of 2026-11-21 found that gosec skips every Go package it cannot load or type-check, exits 0, and writes nothing about it into its SARIF report (gosec 2.30.0). Scans run with no network, so the modules a repository imports, unless they are vendored, cannot be loaded. SiegeKit read only the exit code and the SARIF, and reported "ran".

Measured on 10 Go repositories (native gosec 2.30.0 built with Go 1.27.4, offline vs with modules, `gosec-offline-gap-measurement-2026-11-21.md` in the project files): every one had packages gosec could not load offline, and 9 of 10 lost findings (median 36%, 397 of 918 findings in all). On spf13/cobra gosec scanned 0 files. The gate's known answers for its Go fixtures were built from those runs, so they locked the gap in.

This is the same failure as ZAP's cut-short attack scan (ADR 0039): a tool does less than a complete run and says nothing SiegeKit reads.

## Decision

1. **A manifest can name what the tool did not do.** `output.stdout` (`file`, `parser`) saves the tool's standard output to a file in its output directory (`sandbox.Spec.StdoutFile`: created by SiegeKit before the tool starts, not followed if it is a link, counted against the output limit) and reads it with the parser. The only parser is `gosec-errors`.
2. **gosec writes its JSON report to standard output as well** (`-stdout -verbose json`). SARIF stays the source of findings, so finding keys do not change. `gosec-errors` reads the JSON's "Golang errors" list and turns it into package directories (`internal/gosec`, fuzzed).
3. **Any skipped package makes gosec "failed", with its findings kept**, as for files a root run cannot read (PR #21): the reason names up to 10 package directories and counts the rest, and says that vendoring the modules (`go mod vendor`) lets them be checked. Exit code 4 unless a finding gives 3. A missing or unreadable error list is also "failed": a run is not called complete without it.
4. **Known answers can be "failed"** with the reason the check gives and a why. The gate accepts exit 4 and a failed plugin only where the answer says so. Findings the fixture is known to have but the offline run misses are listed under `notMetYet`, with "Go module download (owner decision pending)" as what they need.
5. **gosec gets a writable module cache, and SiegeKit counts the files.** The first CI run found a second, silent way to skip: in the sandbox the image's `GOPATH` (`/go`) is not writable by the scan user, so Go cannot create its module cache, `go list` fails, and gosec drops every package that imports a module with no entry in "Golang errors" and exit 0 (gin: 4 of 54 files checked; reproduced natively as a non-root user without network, 2026-11-21; gosec skips a loaded package with no name, `analyzer.go`). The plugin sets `GOPATH=/tmp/go`, which gives the load errors of decision 3 instead. For any other cause, `internal/gosec` counts the Go files gosec should check (each directory with a `.go` file, `vendor` and `.git` left out as gosec's default `-exclude-dir` does; go/build for Linux on this architecture, no test files, no cgo files, regular files only) and the check is "failed" when gosec's own count (`Stats.files`) is lower and it named no error. On the 10 measured repositories the count was never higher than what gosec checked with the modules present (211 against 243 on caddy, 5 against 6 on kubernetes/examples, 93 against 94 on shiori, equal on the others), and it caught the silent skip on all 10 runs without a module cache.
6. **Getting the modules into the scan** is a separate decision for the owner: a consented download step like `siegekit update` (ADR 0014). Until then the report says what was not checked.

## Consequences

- Scans of most Go apps that do not vendor their modules now end incomplete (exit 4) and name the packages. That is true, and it is louder than before.
- Code that does not compile is also reported as not checked (2 of 10 repositories had such packages even with their modules).
- The pattern applies to any tool whose report format hides skipped work: add a stdout parser instead of trusting exit 0.
- The image's far lower finding counts in CI (caddy 2 against 74 natively offline, awesome-compose 1 against 6) were this missing module cache: native gosec without one gave the same numbers (caddy 2, awesome-compose 1).
- The file count is a lower bound: a file built only for a newer Go release than SiegeKit's, or only with cgo, is not counted, so a skip of such files alone is not seen.
- Not verified: the exact Go version inside the pinned gosec image (its release workflow builds it from `golang:1.27-alpine`).

## Alternatives considered

- **Read gosec's JSON instead of its SARIF.** It would change every finding's title, severity mapping and snippet, so the comparison with earlier runs and the known answers would change for reasons unrelated to the bug. Rejected.
- **Look for gosec's log lines on stderr.** Wording can change between versions, and stderr is kept only as its last 64 KiB. Rejected for the structured list.
- **Run gosec twice, once per format.** Doubles the time of the slowest repository check. Rejected.
