# 0039. Known-answer tests, and one sandbox on every engine

- Status: Accepted
- Date: 2026-11-20
- Amends: [0006](0006-sandbox.md) (the same filesystem on both engines, `SIEGEKIT_ENGINE`), [0038](0038-run-environment.md) (CI runs on both engines)
- Amended by: [0040](0040-tools-that-skip-work.md) (a known answer can be "failed"), [0041](0041-typed-skip-causes.md) (a skipped answer names its cause)

## Context

ADR 0038 found that CI ran on rootless Podman while local runs used Docker, and that the two sandboxes differed:

- Docker adds `noexec` to `--tmpfs`; Podman does not.
- Podman's `--read-only` also mounts writable `/run` and `/var/tmp` unless `--read-only-tmpfs=false` is given.

On Podman, ZAP's browser could start from `/tmp`, used up the 256-process limit, and `zap-active` stopped after about 944 of its 3,443 requests on Juice Shop in 11 of 15 CI runs. SiegeKit reported "ran". The gate only asserted that `zap-active` ran and sent more than 0 requests (`gate.yml`), so nothing failed.

The cause was not one engine flag. It was that no test said what a complete run of each check finds and how much work it does. The design [checks that finish or say so](https://claude.ai/artifact/Tzc1baUH4xz94CXnS3vnLB) calls this part 0 (known-answer tests) and part 1 (sandbox parity). The owner chose on 2026-11-20 at 23:05 UTC ("Required + listed gaps"): a known-answer miss fails CI; answers SiegeKit cannot meet yet are listed as "not met yet" with the part that fixes them, printed on every run; and CI fails when one starts passing without being moved into the answer.

## Decision

1. **One sandbox on every engine.** SiegeKit gives both engines the same filesystem:
   - `--tmpfs /tmp:rw,nosuid,nodev,noexec,size=…m`, with `noexec` written out instead of left to Docker's default;
   - an explicit `--tmpfs /dev/shm:rw,nosuid,nodev,noexec,size=64m`, because Podman's `/dev/shm` is read-only under `--read-only-tmpfs=false`;
   - on Podman, `--read-only-tmpfs=false` after `--read-only`, in tool containers and the relay.

   `TestSameSandboxOnEveryEngine` probes the result inside a container: the root, `/etc`, `/run`, `/var/tmp` and the target are not writable; the output directory, `/tmp` and `/dev/shm` are writable; nothing runs from `/tmp` or `/dev/shm`.
2. **`SIEGEKIT_ENGINE` picks the engine** (`podman` or `docker`). Without it, Podman is still preferred when both are installed. A `docker` command that is Podman is treated as Podman (`docker --version`).
3. **CI runs on both engines.** The test job and both gates run once with rootless Podman and once with rootful Docker on `ubuntu-latest`, and assert the engine they got (ADR 0038).
4. **Known answers.** `testdata/known-answers/` holds one file per gate fixture: the pinned commit and, for every check, what a complete run gives:
   - `status`, and `reason` for a skipped check (the reason must contain it);
   - `findings`, as `RULE path:line` for files and `RULE /path` for URLs, with `match` `exact` (nothing missing, nothing new) or `includes` (nothing missing; tools whose rules change with their data, such as trivy);
   - `count`, the number of findings, for exact checks;
   - `minRequests`, 90% of the fewest requests measured on complete runs, so a run cut short fails;
   - `byRule` when only the rule is stable (ZAP's passive crawl reaches different pages);
   - `unstable`, findings that come and go on identical runs, with `why`; they may be present or absent, and are printed on every run;
   - `byEngine`, a different answer on one engine, with `why`;
   - `notMetYet`, findings confirmed by hand that SiegeKit does not find yet, each with the part that will find it.

   The gates compare every scan against its answer (`go run ./internal/knownanswers/check`) and print the answer of the run, so an intended change is copied from the log. The container tests compare request counts on SiegeKit's test app the same way (`vulnAppMinRequests`). A tool whose request count depends on its random inputs runs there with a fixed seed, so the floor tells a cut-short run from an unlucky one: Schemathesis stops at the first failure it finds, and unseeded it sent 13 to 32 requests on the test app (amended 2026-11-21, PR #50). Scans stay unseeded.
5. **Answers come from CI runs on both engines.** The first answers come from four gate runs (two heads, two engines, 2026-11-20). A difference between runs is a finding (ADR 0038) and is either explained or listed as `unstable` with the evidence.

## Evidence

All CI runs are on GitHub's `ubuntu-latest` with Podman 5.7.0 rootless and Docker 29.4.2 rootful, both cgroup v2. Local runs are Docker 29.10.0 rootful and Podman 4.9.3 rootful, cgroup v1.

| Claim | Backed by |
|---|---|
| The two engines now give the same filesystem | `TestSameSandboxOnEveryEngine`: locally on Docker 29.10.0 and Podman 4.9.3; in CI on both engines. Its first CI run caught Podman's read-only `/dev/shm`, fixed in this PR. |
| The fix stops the cut-short attack scan | Gate runs 44834908813 and 44836476025: `zap-active` on Juice Shop sent at least 3,442 requests on all four runs (3,443 on both Podman runs) (before: about 944 in 11 of 15 Podman runs). |
| Both engines give the same answers | The same four runs: all 20 repositories and Juice Shop gave the same findings on both engines, except go-chi's gosec taint findings below, nuclei's two Swagger findings on Juice Shop (listed as `unstable`) and the pages ZAP's passive crawl reached (compared by rule). |
| go-chi's gosec G7xx findings vary | Four identical runs reported 4, 4, 3 and 1 of the same 4 findings. 20 local runs of gosec 2.30.0 reported all 4 every time. The cause is not found; it is listed as `unstable` and as an M2 known gap. |
| The checker catches each kind of shortfall | `TestCompareShortfalls` (cut short, a finding missed, a new finding, a wrong count, failed, a wrong skip reason, no answer, missing from the report, a "not met yet" finding now found), `TestCompareByRuleAndUnstable`, `TestCompareByEngine`, `TestLoadRejects`, `TestAnswerFromRoundTrip`, and `TestFixtureFiles`, which loads every answer file. |
| The three Juice Shop "not met yet" findings are real | Confirmed by hand on 2026-11-20 (see the M2 record, Verified). |

## Consequences

- A check that stops early, crashes inside its limits, or loses findings now fails CI even when the tool exits 0.
- Every container test and gate scan runs twice, once per engine, so CI uses about twice the runner time (not measured).
- Answers must be updated when a pin changes. The gate prints the new answer, and the person changing the pin reviews the difference.
- Rootless Docker, rootful Podman on cgroup v2 and macOS are still not tested.
- The answers cover the gate's fixtures only. They show that a check did its known work there, not that it finds everything elsewhere.
- Unstable findings weaken the answer for those findings: a run that drops them still passes. Each is listed with its evidence and reviewed in the M2 milestone check.

## Alternatives considered

- Assert only a request minimum for `zap-active`: not chosen. It would catch this failure and not the next one, for example a check that loses findings with the same number of requests.
- Pin CI to one engine: not chosen (ADR 0038).
- Compare only finding counts: not chosen. A count stays the same when one finding is lost and another appears.
- Make known-answer misses warnings: not chosen by the owner, because a warning on every run is ignored.
