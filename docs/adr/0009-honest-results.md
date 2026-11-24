# 0009. Honest results: coverage, not a "secure" verdict

- Status: Accepted
- Date: 2026-11-18
- Amended by: [0020](0020-repository-suppressions.md) (suppressions in the scanned repository are counted), [0040](0040-tools-that-skip-work.md) (a check that did part of its work is incomplete), [0067](0067-checks-finish-or-say-so.md) (complete, named gaps, or not proven complete)

## Context

Users, especially people shipping code they did not write line by line, will read a SiegeKit report as an answer to "is it safe to deploy?". Automated scanners cannot answer that. They are good at known patterns (vulnerable dependencies, leaked secrets, common injection sinks, misconfigurations, known CVEs) and weak or blind at:

- broken access control and authorization logic (one user reading another user's data);
- business-logic flaws (skipping a payment step, abusing a discount);
- authentication and session design flaws that need a human to understand intent;
- vulnerabilities in code paths the scanner never reached (pages behind login it could not use, API endpoints not in the spec, code not exercised by fuzzing);
- issues in components that were not scanned at all (infrastructure, cloud settings, third-party services).

A report that says "0 issues, passed" would give false confidence, which is worse than no report.

## Decision

1. **No pass/fail or "secure" wording.** Reports never say "secure", "safe", "passed" or show a green "all clear". The strongest summary is: "No issues found by the N checks that ran. This does not mean the application is secure."
2. **Coverage summary at the top of every report**, before any findings:
   - each test family: ran, skipped (and why), failed or timed out;
   - for DAST: whether authenticated scanning was configured, number of URLs/endpoints reached, and endpoints known but not reached;
   - for fuzzing: run time and, where the tool reports it, code coverage reached;
   - for SAST: languages detected versus languages with a configured analyzer.
3. **"Not tested by SiegeKit" section** in every report, listing the categories above that automated tools cannot cover, each linking to the [pre-deploy checklist](../pre-deploy-checklist.md).
4. **Exit codes** for CI use reflect findings above a user-chosen severity, and a separate non-zero code for incomplete runs (a plugin failed or timed out), so an incomplete run is never mistaken for a clean one.
5. **Every finding** shows which tool reported it, the rule, the evidence, and a confidence level where the tool provides one, so users can judge false positives.

## Consequences

- Reports are more honest and somewhat less satisfying to read.
- The coverage data must be collected from each plugin, which adds parser work in M1 and M2.
- Users get a concrete list of what still needs a human check.

## Alternatives considered

- **A single security score:** easy to read, but implies a precision the tools do not have. Rejected.
