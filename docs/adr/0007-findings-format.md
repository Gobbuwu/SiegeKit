# 0007. Findings format and storage

- Status: Accepted
- Date: 2026-11-18

## Context

Each wrapped tool reports in its own format. Users need one ranked list of problems, comparable across runs, that other tools (code hosts, IDEs) can read.

## Decision

- Every finding is normalized to **SARIF 2.1.0** (the OASIS Static Analysis Results Interchange Format). Many wrapped tools emit SARIF already; the rest get a parser that converts their JSON/XML output.
- Severity is mapped to one scale: critical, high, medium, low, info. The mapping per tool is documented in the plugin's parser and tested.
- Findings are deduplicated by rule, location and a content fingerprint, so two tools reporting the same issue appear once with both sources listed.
- Results are stored locally in a SQLite database in the user's data directory, so runs can be compared ("new since last run", "fixed since last run").
- Reports: a self-contained HTML file (no external scripts or fonts), a merged SARIF file, and JSON. Secrets found by scanners are masked in every report by default.
- Nothing is uploaded anywhere. There is no telemetry.

## Consequences

- Parsers handle untrusted input and are fuzzed (Go native fuzzing) in CI.
- The HTML report must escape all tool output, since a scanned web app can put attacker-controlled text into findings.

## Alternatives considered

- **Each tool's native output only:** no unified view. Rejected.
- **A custom format:** no interoperability. Rejected; SARIF can carry extra fields in its property bags.
