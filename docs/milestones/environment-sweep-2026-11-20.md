# Environment sweep, 2026-11-20

Why: the claim "CI runs the container tests with rootful Docker" was wrong (ADR 0038). This sweep reads every line in the ADRs, milestone records, plans, threat model, README and re-check reports that says something was verified, measured, tested or run "in CI", or that names an engine: 132 lines in 31 files (`grep -niE 'in CI|verified|measured|tested on|Docker 29|podman|rootless|rootful'`).

Environments: **CI** is rootless Podman 5.7.0, cgroup v2, on GitHub's `ubuntu-latest` runners (run 44825786215). **Local** is the development sandbox: rootful Docker 29.10.0, cgroup v1.

## Wrong, corrected

| Where | Claim | Correction |
| --- | --- | --- |
| `docs/milestones/M1.md` (Unverified) | CI runs the container tests only with rootful Docker on Ubuntu | CI runs them on rootless Podman; struck through and corrected |
| `docs/adr/0019-egress-relay.md` (Consequences) | Rootless Podman unverified until CI's container tests run on Podman | They do; rootless Podman verified for the relay, rootless Docker and cgroup-v2 Docker unverified |
| `docs/threat-model.md` (Open questions) | Rootless Podman not tested | Tested by CI's container tests, which write to the output directory |
| `docs/m2-plan.md` (follow-ups) | Rootless warning waits until rootless engines are tested | Rootless Podman was tested all along; the warning waits for the engine matrix |
| `docs/milestones/M2.md` (Unverified) | Rootless Podman unverified; "ZAP ... Podman" unverified | Moved: ZAP runs on rootless Podman, but its attack scan is cut short there (Known gaps) |
| `docs/milestones/M2.md` (Verified, gate) | `zap-active` sent 944 requests (as a verified result) | 944 is a cut-short scan; it verifies that ZAP runs on Podman, not that the scan completes |
| `docs/adr/0006-sandbox.md` | "Rootless mode ... shown as a warning when not used" | The warning was never built; now says so |
| `.github/workflows/ci.yml` comment | Container tests "need Docker" | Names Podman and the expected engine |
| `docs/recheck-2026-11-19-second.md` | Podman unverified; 3,443 vs 944 requests unexplained | Both answered, with a note that the second item was never carried into the M2 record |

## Environment added

| Where | Result | Environment |
| --- | --- | --- |
| `M2.md` Verified | Active-run container tests (PRs #22, #24) | Local and CI |
| `M2.md` Verified | `TestZAPFindsPlantedIssues` (PR #28) | Local and CI |
| `M2.md` Verified | ZAP peaked at 1.23 GiB on Juice Shop | Local; the browser cannot start there, so the peak does not hold where it does (2.76 GiB measured with it) |
| `adr/0023` Consequences | Attack scan sent 773 requests in under 30 s | Not recorded; most likely local |
| `adr/0026` Context | Nuclei facts measured 2026-11-19 | Not recorded except where the ADR says "CI" or "local" |
| `M1.md` Verified | Items "verified in CI" (bandit, gosec, planted issues, fuzzing) | CI, per the corrected line in M1's Unverified section |

## Checked, no environment needed

The other lines are one of these:

- results about the target app's own behaviour (Juice Shop, Gitea, Memos, Supabase, the Realtime Database emulator), which do not depend on the container engine: ADRs 0030, 0033, 0035, 0036, 0037;
- unit tests and fuzz targets, which do not use the engine: ADRs 0007, 0015, 0036, 0037;
- "verified target" in the sense of ownership proof: ADR 0011, threat model T3 and §2;
- plans, rules and future work: ADRs 0008, 0016, 0025, 0029, 0031, 0034, the roadmap, `m2-plan.md` row 29, `milestones/README.md`, README.

## Still open

- Container-test times and request counts recorded before today (ffuf 53 s, Nuclei 10,852 requests, Schemathesis 10 of 10 runs in M2's Verified list) name no environment. They hold for the run they came from. Part 0 of the design (known-answer tests on both engines) measures them again with the environment recorded.
- Whether every earlier CI run used Podman is inferred: those runs printed no engine.
