# 0040. A tool that skips part of its work makes the run incomplete

- Status: Accepted
- Date: 2026-11-21
- Amends: [0009](0009-honest-results.md) (a check that did part of its work is incomplete), [0039](0039-known-answers-and-engine-parity.md) (a known answer can be "failed")

## Context

The full project check of 2026-11-21 found that gosec skips every Go package it cannot load or type-check, exits 0, and writes nothing about it into its SARIF report (gosec 2.30.0). Scans run with no network, so the modules a repository imports, unless they are vendored, cannot be loaded. SiegeKit read only the exit code and the SARIF, and reported "ran".

Measured on 10 Go repositories (native gosec 2.30.0 built with Go 1.27.4, offline vs with modules, `gosec-offline-gap-measurement-2026-11-21.md` in the project files): every one had packages gosec could not load offline, and 9 of 10 lost findings (median 36%, 397 of 918 findings in all). On spf13/cobra gosec scanned 0 files. The gate's known answers for its Go fixtures were built from those runs, so they locked the gap in.

This is the same failure as ZAP's cut-short attack scan (ADR 0039): a tool does less than a complete run and says nothing SiegeKit reads.

## Decision

1. **A manifest can name what the tool did not do.** `output.stdout` (`file`, `parser`) saves the tool's standard output to a file in its output directory (`sandbox.Spec.StdoutFile`: created by SiegeKit before the tool starts, not followed if it is a link, counted against the output limit) and reads it with the parser. The only parser is `gosec-errors`.
2. **gosec writes its JSON report to standard output as well** (`-stdout -verbose json`). SARIF stays the source of findings, so finding keys do not change. `gosec-errors` reads the JSON's "Golang errors" list and turns it into package directories (`internal/gosec`, fuzzed).
3. **Any skipped package makes gosec "failed", with its findings kept**, as for files a root run cannot read (PR #21): the reason names up to 10 package directories and counts the rest, and says that vendoring the modules (`go mod vendor`) lets them be checked. Exit code 4 unless a finding gives 3. A missing or unreadable error list is also "failed": a run is not called complete without it.
4. **Known answers can be "failed"** with the reason the check gives and a why. The gate accepts exit 4 and a failed plugin only where the answer says so. Findings the fixture is known to have but the offline run misses are listed under `notMetYet`, with "Go module download (owner decision pending)" as what they need.
5. **Getting the modules into the scan** is a separate decision for the owner: a consented download step like `siegekit update` (ADR 0014). Until then the report says what was not checked.

## Consequences

- Scans of most Go apps that do not vendor their modules now end incomplete (exit 4) and name the packages. That is true, and it is louder than before.
- Code that does not compile is also reported as not checked (2 of 10 repositories had such packages even with their modules).
- The pattern applies to any tool whose report format hides skipped work: add a stdout parser instead of trusting exit 0.
- Not verified: the Go version inside the pinned gosec image, and whether it gives the same load errors as the native gosec measured here. The gate's runs on both engines will show the image's own numbers.

## Alternatives considered

- **Read gosec's JSON instead of its SARIF.** It would change every finding's title, severity mapping and snippet, so the comparison with earlier runs and the known answers would change for reasons unrelated to the bug. Rejected.
- **Look for gosec's log lines on stderr.** Wording can change between versions, and stderr is kept only as its last 64 KiB. Rejected for the structured list.
- **Run gosec twice, once per format.** Doubles the time of the slowest repository check. Rejected.
