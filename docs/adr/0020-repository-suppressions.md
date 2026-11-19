# 0020. Suppressions in the scanned repository

- Status: Accepted
- Date: 2026-11-19
- Amends: [0009](0009-honest-results.md)

## Context

The re-check of 2026-11-19 showed that the scanned repository can make the wrapped tools leave out findings without the report saying so. These were checked with real runs:
- gitleaks obeys `gitleaks:allow` comments, a `.gitleaksignore` file (in files and in git-history mode) and a `.gitleaks.toml` (files mode; the history plugin uses SiegeKit's own configuration).
- bandit obeys `# nosec` and a `.bandit` file at the top of the target.
- checkov obeys `checkov:skip=` comments and a `.checkov.yaml` file.
- gosec obeys `#nosec` comments.

The report then said that a check ran with 0 findings. People and AI assistants add such suppressions, sometimes to make a finding go away. The owner chose on 2026-11-19 to obey them but make them visible, over ignoring them (known false positives would come back on every scan) or only documenting them.

## Decision

1. Suppressions in the scanned repository keep working.
2. Each plugin result in `report.json`, the HTML report and the terminal summary says what the repository told the tool to ignore:
   - `suppressed`: findings the tool reports as suppressed. SARIF results with an accepted suppression are counted and left out; one under review or rejected stays a finding. gosec runs with `-track-suppressions` for this. Bandit's `nosec` and `skipped_tests` totals are used.
   - `repoSettings`: settings files the tool reads that are present at the target's top level, as listed in the plugin manifest (`repoIgnores.files`).
   - `ignoreMarkers`: lines with the tool's ignore comment (`repoIgnores.marker`), counted by SiegeKit with the built-in check limits (ADR 0015), for tools that do not report what they suppressed (gitleaks).
3. The AI assistant guide tells assistants not to add suppressions without the person's agreement, and to report these fields.

## Consequences

- Checkov results suppressed by `checkov:skip=` were reported as findings before and are now left out and counted.
- A settings file can hide findings without a count; the report can only say that it was used.
- `ignoreMarkers` counts lines in the current files, not in git history, and skips dependency directories.
