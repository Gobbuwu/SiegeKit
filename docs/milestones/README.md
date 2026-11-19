# Milestone records

One file per milestone records what was built, how it was checked and what is still open. The owner asked for this on 2026-11-19 so that a later check can cross-check these records instead of re-checking everything from scratch.

| Milestone | Status | Record |
| --- | --- | --- |
| M0 Design | Done, signed off | [M0.md](M0.md) |
| M1 Core and passive scans | Done, signed off 2026-11-19 | [M1.md](M1.md) |
| M2 Active web and API testing | In progress | [M2.md](M2.md) |

## Rules

- **Every pull request updates the record of its milestone, in the same pull request.** Add the PR's row to "Built", plus anything it decided, verified, left unverified or left open. A docs-only PR still gets a row.
- **"Verified" names the evidence:** a test name, a CI job, or a real run with what it showed. A claim with no evidence goes under "Unverified".
- **Owner decisions** are recorded with their date and where they are written down (ADR, plan or roadmap).
- **Remove a gap or an unverified item only with the PR that closes it,** and say which PR.
- **A CI job that GitHub never started is "not run", not "failed"** (owner, 2026-11-19). A pull request merges when every check that ran is green. "Never started" means the job ran no step and GitHub's annotation says it was not acquired by a runner; any other cancelled or failed job still blocks. The PR's row says which job did not run.
- **Each milestone ends with a milestone check** (owner, 2026-11-19): that milestone only, against its plan rows in `docs/m2-plan.md` (or the milestone's plan) and this record, not a full project check. The next milestone starts only when everything in the check works. Findings go into one report and one fix plan, not one small patch each.
- When a milestone's gate passes and the owner signs off, its record gets the date and the evidence for each gate item.

## How to cross-check a record

1. For each "Built" row, check that the PR is merged and the files it names exist on `main`.
2. For each "Verified" item, re-run the named test or look at the named CI job on the latest `main`.
3. Read "Unverified" and "Known gaps" as the list of what is not yet proven. Nothing in them may be reported as working.
4. A full re-check is needed only when a record and the code disagree, or when the owner asks for one. The full re-checks so far are [recheck-2026-11-19.md](../recheck-2026-11-19.md) and [recheck-2026-11-19-second.md](../recheck-2026-11-19-second.md).
