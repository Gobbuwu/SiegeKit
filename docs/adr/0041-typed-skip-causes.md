# 0041. Every skipped check has a typed cause

- Status: Accepted
- Date: 2026-11-21
- Amends: [0016](0016-dependency-consent.md) (what `--require-all` counts), [0039](0039-known-answers-and-engine-parity.md) (known answers compare the cause)

## Context

The full project check of 2026-11-21 (findings F4 and F5, root cause RC2) found that why a check was skipped was free text only, so code decided from its wording:

- `--require-all` counted every check in the run's skip list as "skipped for missing dependencies". That list also holds checks left out because the target is deployed, by `--profile quick`, for want of a login, URL, HAR file or backend URL, and because the person did not type `yes`. A deployed scan with `--require-all` therefore ended incomplete (exit 4) with every dependency installed whenever one of those checks was selected, as in the default selection. Logged while building M2.6a; reproduced by the new tests below, which fail on the old logic.
- CI's self-scan (`ci.yml`) and the gate (`gate.yml`) accepted a skip when `.reason | startswith("no files matching")`. Rewording a message would change what CI accepts, and an AI agent reading `report.json` had only the same wording to go by.

## Decision

1. **`report.json` gets `plugins[].cause`**, a fixed word, on every skipped check, and on a check that failed before it started where the cause is known. It is an added field, so `schemaVersion` stays 1. The causes are `missing-dependency`, `declined`, `no-files`, `deployed-or-local-only`, `profile`, `no-input`, `not-confirmed`, `platform` and `unsupported` (`report.Causes`; meanings in `docs/agents.md`, which a test keeps complete). `reason` stays, for people.
2. **The cause is set where the skip is decided** (`runner.Skip`, `runner.Fail`, the runner's own skip paths, `deps.Install`'s `notChosen`), never derived from the wording.
3. **A skip with no valid cause is a bug and is reported as `failed`** (`Run.CheckCauses`, before reports are written), so it can never pass as an acceptable skip. The command's tests make that a test failure, so every skip in every tested path has a cause.
4. **`--require-all` counts `missing-dependency` and `declined` only.** Checks left out by the mode, the profile, a missing input, a missing confirmation or the target's files do not make the run incomplete.
5. **CI decides on the cause**: the self-scan and the gate accept a skip only with `cause == "no-files"`. The Juice Shop gate also checks that Schemathesis is skipped with `no-input`.
6. **Known answers record a skipped check's cause** and compare it exactly; `Load` refuses a skipped answer with no valid cause, and a cause on any other status.

## Consequences

- Whether a skip is acceptable no longer depends on message wording, in SiegeKit, CI or an agent. The one remaining wording check in CI (Schemathesis's reason names `/openapi.json`) checks which spec paths were tried, on top of the cause.
- A new skip path must pick a cause, or its tests fail.
- `no-files` also covers `gitleaks-history` on a directory with no `.git` ("not a git repository"): the target has nothing that check reads. CI accepts it like a repository without Python code.
- A failed check (a tool error) usually has no cause; only failures before the check started (not Linux, an install that failed, no working engine) carry one.

## Alternatives considered

- **Keep the wording, fix only `--require-all`** by marking dependency skips with a flag in the `Unavailable` map: fixes F4 but not F5 or agents, and the next decision on wording repeats the bug class. Rejected (root cause, not instance).
- **A new status per cause** (`skipped-deployed`, ...): changes the meaning of `status`, which agents and the HTML report already read, and would need `schemaVersion` 2. Rejected.
