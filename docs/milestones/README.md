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
- **A result holds only where it was measured** (owner, 2026-11-20, [ADR 0038](../adr/0038-run-environment.md)). Every test run, measurement and CI result names its environment: the container engine and its version, rootless or rootful, and the cgroup version (and the OS when it is not Linux). A claim measured in one environment is written as verified there and unverified elsewhere. "In CI" means rootless Podman on GitHub's `ubuntu-latest` runners until the engine matrix adds others. A claim about an environment that no run has shown is an assumption: check it, or label it unverified.
- **Decide on evidence, not on confidence** (owner, 2026-11-20, replacing the earlier "at least 93% confident" rule). Decide only when each key claim is backed by a test, a measurement or a cited source. A self-scored confidence is not evidence. Anything else is labelled unverified, then measured or brought to the owner before a decision or a commit.
- **Owner decisions** are recorded with their date and where they are written down (ADR, plan or roadmap).
- **Remove a gap or an unverified item only with the PR that closes it,** and say which PR.
- **An unexplained difference between two runs is a finding, not an unverified item** (2026-11-20, ADR 0038). For example: the same scan sends 3,443 requests in one place and 944 in another. It goes under "Known gaps" with the milestone that must explain it, and that milestone's check cannot pass while it is open. Items from a re-check report are copied into the milestone record in the same pull request, so none is left only in the report.
- **A CI job that GitHub never started is "not run", not "failed"** (owner, 2026-11-19). A pull request merges when every check that ran is green. "Never started" means the job ran no step and GitHub's annotation says it was not acquired by a runner; any other cancelled or failed job still blocks. The PR's row says which job did not run.
- **Each milestone ends with a milestone check** (owner, 2026-11-19): that milestone only, against its plan rows in `docs/m2-plan.md` (or the milestone's plan) and this record, not a full project check. The next milestone starts only when everything in the check works. Findings go into one report and one fix plan, not one small patch each.
- **Every milestone check includes a hand triage of results** (owner, 2026-11-19), because the planted-issue tests only show that known issues are found. It starts with M2. The defaults below are a first version; change them only with the owner.
  1. Sample: from the latest run of the gate on `main`, up to 20 findings per check, picked at random across the scanned repositories (note the run and how they were picked), plus every critical and high finding up to 20 more per check. From the Juice Shop scan, every finding of medium severity or above.
  2. Label each finding as a true positive, a false positive or unclear, with one line of reason and its evidence (file and line, or URL and request).
  3. Misses: list the known issues in the gate's fixtures and in Juice Shop that fall in a category a check that ran claims to test, and say which no check reported.
  4. Record the counts per check (sampled, true, false, unclear, missed) under "Result quality" in the milestone record, with the labelled list in a file next to it. Each false positive or miss becomes a known gap or an item in the check's fix plan. No pass mark is set; the owner decides what blocks the milestone.
- **Every milestone check checks the evidence behind its design records** (owner, 2026-11-20). It starts with M2. For each ADR written in the milestone, every key claim must be backed by a test, a measurement or a cited source. Each claim with none is a finding in the check's report. Past milestones are covered by the full project check, not re-checked now.
- **The full project check also looks for wrong claims and work outside the plan** (owner, 2026-11-20). It lists every claim in code comments, docs and ADRs that no evidence backs (a guess or assumption written as fact, or one that turned out wrong), and every piece of work that is superfluous or has nothing to do with the plan. Each one is fixed, backed with evidence, moved under "Unverified", or removed.
- When a milestone's gate passes and the owner signs off, its record gets the date and the evidence for each gate item.

## How to cross-check a record

1. For each "Built" row, check that the PR is merged and the files it names exist on `main`.
2. For each "Verified" item, re-run the named test or look at the named CI job on the latest `main`, in the environment the item names.
3. Read "Unverified" and "Known gaps" as the list of what is not yet proven. Nothing in them may be reported as working.
4. A full re-check is needed only when a record and the code disagree, or when the owner asks for one. The full re-checks so far are [recheck-2026-11-19.md](../recheck-2026-11-19.md) and [recheck-2026-11-19-second.md](../recheck-2026-11-19-second.md).
