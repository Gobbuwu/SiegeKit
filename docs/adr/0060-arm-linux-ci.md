# 0060. The CI test job on GitHub's ARM Linux runner

- Status: Accepted (1.0 item 15, owner decision of 2026-11-22: arm64 through GitHub's ARM Linux runners until an Apple-chip Mac is available)
- Date: 2026-11-23
- Amends: [0039](0039-known-answers-and-engine-parity.md) (item 3: where the test job runs)

## Context

SiegeKit supports `linux/arm64` and `darwin/arm64` (`manifest.Platforms`), and ffuf pins its own arm64 download (ADR 0027), but no CI job ran on arm64. The `macos-latest` job runs on an Apple-chip Mac but only runs the unit tests. Container tests are Linux-only, and that job was often never started (M2 record). So nothing checked that the pinned tool images have arm64 builds, that the engines pull them, or that the checks find their planted issues on arm64. `definition-of-done-1.0.md` item 15 asks for this: pull the pinned images and run the real scans on arm64, check that every pinned image has an arm64 build or list the gap, and find the planted issues as on amd64. Before this ADR, only the latest tags of five tools had been checked, not the pinned digests.

## Decision

1. **Two more test jobs** in `ci.yml`'s matrix: `ubuntu-24.04-arm` with rootless Podman and with rootful Docker (`expect: podman rootless` / `docker rootful`, as on `ubuntu-latest`). They run the same steps as the amd64 jobs: formatting, vet, `go test -race` with `SIEGEKIT_CONTAINER_TESTS=1` (every `...FindsPlantedIssues` container test, `TestDescribe`'s engine check) and the self-scan with `--fail-on info`.
2. **The self-scan checks the platform.** Each Linux job passes its `arch` (`amd64` or `arm64`) and the step requires the report's `environment.os == "linux"` and `environment.arch` to match. A runner label that quietly gives another architecture then fails the job instead of passing as arm64.
3. **Staticcheck, dead code and govulncheck** run on the Podman job of both architectures, because each checks the code built for its own GOARCH. **Fuzzing** stays on the amd64 Podman job only: the fuzzed parsers are plain Go with no per-architecture code (no `_arm64`/`_amd64` files or architecture build tags outside `vendor/`), and it takes about 17 minutes.
4. **The gates stay on amd64.** The real-repository gate, the Juice Shop jobs, and the writes, mail, pages and storage gates run on `ubuntu-latest` only. Item 15's evidence is the planted-issue tests and the self-scan. Real-repository known answers on arm64 are listed as not covered (M2 record, Known gaps).
5. **This is not Apple-chip Mac coverage.** macOS on Apple chips (Colima or another VM) stays untested until the owner has such a Mac (definition of done, M4 gate).

## Evidence

| Claim | Backed by |
|---|---|
| Every pinned tool image has a `linux/arm64` build at its pinned digest | Each image index fetched from Docker Hub or GHCR at the pinned digest on 2026-11-23. The SHA-256 of each index matches its digest, and each lists `linux/arm64`: ZAP stable, Nuclei, Trivy, Checkov, Gitleaks, Schemathesis, Bandit (GHCR), gosec (GHCR), Alpine 3.24.4 (relay and ffuf; `linux/arm64/v8`) and the test Alpine `d9e853e8…`. ffuf's arm64 archive was already pinned (ADR 0027). Gate-only images have arm64 builds too, though no arm64 job uses them yet: Juice Shop v20.4.0, Gitea 1.24.6, Mailpit, eclipse-temurin JRE, supabase/postgres 15.19.0.019 and supabase/storage-api v1.94.2. **No gap.** |
| The engines pull them and the checks find their planted issues on arm64 | CI run [45208531259](https://github.com/Gobbuwu/SiegeKit/actions/runs/45208531259) (head 29c3c78): Test (ubuntu-24.04-arm, podman) and (ubuntu-24.04-arm, docker) passed, with `internal/runner` (the container tests) taking 468 s on Podman. The container tests skip only without `SIEGEKIT_CONTAINER_TESTS=1`, which both jobs set, so they ran. |
| The jobs really ran on linux/arm64 with the expected engine | The same run's self-scan prints `Environment: linux/arm64, SiegeKit built with go1.27.4, podman 4.9.3 rootless, cgroup v2` and `docker 28.0.4 rootful, cgroup v2`. The new `environment.arch` check passed. `TestDescribe` asserted rootless Podman and rootful Docker. |
| The self-scan is clean on arm64 | Same run: all 9 checks ran on both arm64 jobs with 0 findings (bandit, checkov, gitleaks, gitleaks-history, gosec with 62 suppressed by comments as on amd64, trivy, backend-rules, dotenv-gitignore, weak-passwords). |
| The arm64 build passes the static checks | Same run, arm64 Podman job: staticcheck, deadcode and govulncheck ("No vulnerabilities found") passed. Locally, `GOARCH=arm64 go vet ./...` passed and `CGO_ENABLED=0 GOARCH=arm64 go build ./cmd/siegekit` gives a static ARM aarch64 ELF. |
| Nothing changed on amd64 | Same run: the two `ubuntu-latest` jobs and `macos-latest` passed. Fuzzing ran on the amd64 Podman job as before (17 min). |

The arm64 runner has older engines than `ubuntu-latest`: Podman 4.9.3 instead of 5.7.0, and Docker 28.0.4 instead of 29.4.2. Both are cgroup v2. A result holds for the engine it ran on (ADR 0038), so these versions are recorded with the result.

## Consequences

- Every pull request now also pulls the arm64 tool images and runs the container tests on arm64, so a pin moved to an amd64-only image fails CI. That adds two jobs of about 10 minutes each (15:44 to 15:54 in the run above), run in parallel with the others.
- Real-repository known answers, the Juice Shop jobs and the storage gates are not checked on arm64. If arm64 results ever need to match on real apps, those gates get an arm64 matrix entry. Their images have arm64 builds (above).
- Apple-chip macOS stays untested (item 5).

## Alternatives considered

- **Also run every gate on arm64**: 54 more gate jobs per pull request (40 for the 20-repository scan on two engines, 2 web, 4 writes, 2 mail, 2 pages, 4 storage). Item 15 asks for planted issues, not real-repository answers, so this was left out. It is listed as a gap the owner can ask for.
- **Emulating arm64 on amd64 (QEMU)**: slower, and it does not show that a real arm64 kernel and the runner's engines work. Rejected.
- **Fuzzing on both architectures**: about 17 more minutes on every pull request with no per-architecture parser code to find. Rejected.
