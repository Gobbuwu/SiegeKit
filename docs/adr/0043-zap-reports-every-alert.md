# 0043. ZAP reports every alert instance

- Status: Accepted
- Date: 2026-11-21
- Amends: [0023](0023-active-web-scans.md) (ZAP's arguments), [0040](0040-tools-that-skip-work.md) (a tool can also drop results it found)

## Context

On PR #50 the Juice Shop gate failed 4 times in 8 PR runs. zap-active reported ZAP rule 10104 (User Agent Fuzzer) on only `/assets` or only `/assets/public`, never both. In each failing run the scan still sent its full 3,443 or 3,444 requests and reported exactly 3 findings. The 20 runs on `main` passed. #50 does not change ZAP.

Measured locally on 2026-11-21 (Docker 29.10.0 rootful, cgroup v1; the pinned ZAP 2.17.0 image with zap-active's plan, against the pinned Juice Shop v20.4.0; record: `zap-10104-systemic-limit-2026-11-21.md` in the project files):

- ZAP sent all 12 user agents to both paths in every run. A logging proxy recorded 6,145 and 6,070 requests, with the two paths interleaved because they are scanned by different threads.
- Each user agent's answer counted as different. ZAP follows the 301 redirect and compares the final 200 with the original 301 (`AbstractPlugin.sendAndReceive` follows redirects). Juice Shop answers every user agent the same, so here 10104 is a false positive.
- ZAP kept only 3 of those alerts, in 5 of 5 runs. 10104 is tagged "systemic", and ZAP 2.17.0 drops instances of a systemic alert type on a host once a limit is reached (`ExtensionAlert.isOverSystemicLimit`, new in 2.17.0, setting `alert.systemicLimit`). ZAP's log says nothing and exits 0. Which path fills the kept slots depends on thread timing. When one path takes all of them, the other is missing from the report.
- With `-config alert.systemicLimit=0`, 10104 was reported on both paths in 2 of 2 runs, with 22 and 24 instances.
- Through SiegeKit (`--only zap,zap-active`, 2 runs each, alternating): without the setting, zap-active reported 3 findings and one run lost `/assets/public` (the gate's failure, reproduced). With it, zap-active reported 24 findings and both paths in both runs. The passive `zap` check went from 14 findings (rules 10038, 10098 and 10109 on 4 or 5 pages each) to 33 (11 pages each). The requests were the same (94 and 3,443).

This is the failure class of ADR 0040: a tool drops part of its results, exits 0, and SiegeKit reports "ran".

## Decision

1. **Both ZAP plugins pass `-config alert.systemicLimit=0`**, so ZAP keeps every alert it raises. SiegeKit already merges alerts of one rule on one URL into one finding (`findings.Dedupe`), so the report grows only by URLs that were dropped before.
2. **`TestBuiltin` requires the setting** in every ZAP manifest.
3. **The known answers stay as they are.** The gate keeps requiring 10104 on both paths, which now holds every run. No answer is loosened.

## Consequences

- Reports list every page that shows a systemic alert (missing headers, for example), not just the first few per host. Reports from earlier versions under-reported these.
- The Juice Shop gate's zap-active answer becomes stable without changing it.
- The passive `zap` answer compares by rule because "a page's finding comes and goes" (ADR 0039). The limit is the likely cause: without it, each of its rules was reported on 11 pages in 2 of 2 local runs, against at most 5 before. The answer stays by rule here, and is re-measured on CI on both engines before it is made exact.
- Other tools may also cap or drop output on their own. That check belongs to design part 3 ("checks that finish or say so"), across all plugins.
- Not verified: why the race went the wrong way on #50's PR runs and never on `main`. Runner timing is the likely factor.

## Alternatives considered

- **Compare 10104 by rule in the gate.** It hides the dropped instances instead of keeping them, and leaves every ZAP report incomplete. Rejected.
- **Turn off rule 10104.** It would remove a rule the owner never chose to drop, and the limit would still drop instances of other systemic rules. Rejected.
