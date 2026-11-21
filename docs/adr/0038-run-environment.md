# 0038. Every run and result names its environment

- Status: Accepted
- Date: 2026-11-20
- Amends: [0006](0006-sandbox.md) (the engine is recorded), the evidence rules in [milestones/README.md](../milestones/README.md)
- Amended by: [0039](0039-known-answers-and-engine-parity.md) (CI runs on both engines)

## Context

The M1 record said "CI runs the container tests only with rootful Docker on Ubuntu" (2026-11-19). Nobody checked this, and it was wrong. SiegeKit prefers Podman when it is installed (`sandbox.Detect`, since M1.3). GitHub's `ubuntu-latest` runners have both engines, so CI has used Podman. On 2026-11-20 a scratch CI run (44825786215) showed Podman 5.7.0, rootless, cgroup v2. The development sandbox runs rootful Docker 29.10.0 with cgroup v1.

The two environments behave differently:

- Docker adds `noexec` to `--tmpfs /tmp` and Podman does not, measured on the same runner. Because of this, ZAP's browser starts only on Podman.
- On Podman the browser uses up the 256-process limit, and ZAP's attack scan on Juice Shop stops early: about 944 requests instead of 3,443, in 11 of 15 runs. SiegeKit reported "ran".
- The 2048 MiB ZAP limit was measured on Docker, where the browser cannot start.

The second re-check on 2026-11-19 noted "3,443 requests locally but 944 in CI" as unverified. That item was not carried into the M2 record, so nobody looked at it.

Several records repeated the assumption as fact: the M1 record, ADR 0019, the threat model, the M2 plan and the M2 record. The owner asked on 2026-11-20 for the cause to be fixed, not patched ("i'm okay if we go back a few steps to actually fix the issues"). The owner approved this as the first step of the design [checks that finish or say so](https://claude.ai/artifact/Tzc1baUH4xz94CXnS3vnLB) ("let's proceed with that then").

## Decision

1. **Every run names its environment.** These record the OS, the architecture, the Go release SiegeKit was built with, and the container engine (name, version, rootless or rootful, cgroup v1 or v2):
   - `report.json` (`environment`);
   - the HTML report header;
   - the terminal ("Environment: ...");
   - the audit log (`environment`).

   The Go release was added on 2026-11-21 (#53, full project check F11): local runs used Go 1.26.0 and CI 1.27.4, and the built-in checks and the relay are Go code, so a result holds only for the Go release it was measured with. Tools in images bring their own runtime; their versions are pinned in the manifests.

   SiegeKit asks the engine itself with `info --format`. It tries Podman's format first, so a `docker` command that is Podman is named as Podman. When the engine does not answer, the engine part is left out.
2. **CI asserts its engine.** `TestDescribe` fails when CI's engine is not rootless Podman (`SIEGEKIT_EXPECT_ENGINE`). Both gates fail when `report.json` names another engine. A change to GitHub's runners then shows up as a failure, not as a silent change of environment.
3. **A result holds only where it was measured.** The milestone rules now require every test run, measurement and CI result to name its environment. A claim measured in one environment is written as verified there and unverified elsewhere. "In CI" means rootless Podman until the engine matrix (design part 1) adds others.
4. **An unexplained difference between two runs is a finding.** It goes under "Known gaps" with the milestone that must explain it, and it is never left in a re-check report alone.
5. **The records were corrected** in the same pull request. The sweep, with every claim checked, is in [milestones/environment-sweep-2026-11-20.md](../milestones/environment-sweep-2026-11-20.md).

## Evidence

| Claim | Backed by |
|---|---|
| CI uses rootless Podman 5.7.0 with cgroup v2; Docker on the same runner is 29.4.2 | Scratch run 44825786215 (2026-11-20), both engines on `ubuntu-latest`. `TestDescribe` asserts it on every CI run from this PR on. |
| Docker adds `noexec` to `/tmp`, Podman does not | Same run: `grep ' /tmp ' /proc/mounts` in a container started with `--tmpfs /tmp:rw,nosuid,nodev`. Locally on Docker 29.10.0 too. |
| `info --format` gives version, cgroup and rootless for both engines | `TestParseInfo`, with answers shaped like those of Podman 5.7.0 and Docker 29.10.0. The rootless-Docker case follows Docker's `name=rootless` security option and is not measured. `TestDescribe` passes on Docker 29.10.0 locally and on Podman in CI. |
| The environment reaches the report | `TestEnvironment` (JSON fields, HTML header, no engine). `TestAgentsGuideListsEveryField` covers the new fields. |

## Consequences

- Results recorded before this PR name no environment unless the sweep added one. The sweep lists those it could not place as "environment not recorded".
- Rootless Podman is now known to be tested by CI's container tests. Rootless Docker, rootful Docker on cgroup v2, rootful Podman and macOS are not tested. The engine matrix (design part 1) adds Docker to CI.
- The rootless warning of ADR 0006 is still not built.
- Earlier CI runs printed no engine, so "CI used Podman from M1 on" is inferred from the code and the runner image, not shown by those runs.

## Alternatives considered

- Pin CI to Docker so it matches local runs: not chosen. It would hide every Podman difference from CI, and Podman users would get results no one measured.
- Correct only the records that turned out wrong: not chosen. Without the environment in every run, the next wrong assumption would go unseen in the same way.
