# Roadmap

Each milestone ends with a gate. The next milestone does not start until the gate passes and the project owner signs off.

| Milestone | Scope | Gate |
| --- | --- | --- |
| **M0 Design** | ADRs 0001 to 0011, coverage map, standards mapping, threat model, plugin manifest schema, pre-deploy checklist, repository and legal policies. | Owner signs off on the ADRs and threat model; ADRs move to Accepted. |
| **M1 Core and passive scans (alpha)** (done: gate passed and signed off by the owner on 2026-11-19) | CLI, planner, scheduler (checks run one at a time; parallel runs come in M5), sandbox runner, findings store, HTML/SARIF/JSON reports with coverage summary (ADR 0009), CI pipeline. Plugins: Bandit, gosec, Gitleaks, Checkov, Trivy (dependencies, offline database per ADR 0014); built-in static backend-rules check (ADR 0011, ADR 0015). Dependency consent (ADR 0016, added 2026-11-19): nothing is downloaded without the user's confirmation, installed dependencies are reported and not reinstalled, and declined ones skip and list their tests. Scope trimmed on 2026-11-19: OSV-Scanner, Syft and Grype moved to M2; multi-language code scanning moved to M2 as Opengrep (see M2). | Every planted issue in the fixture repositories is found; no crashes on 20 real open-source repositories; parser fuzzing runs in CI. |
| **M2 Active web and API testing (beta)** | Local and deployed target modes, ownership verification, egress proxy, rate limiting, login-throttling and default-credential checks, secrets in served content (ADR 0010); authorization differential test, unauthenticated route check, rate-limit check, live backend-rules check (ADR 0011). Plugins: ZAP, Nuclei, ffuf, Schemathesis; optional sqlmap and Nikto; OSV-Scanner, Syft (SBOM) and Grype moved from M1. Multi-language code scanning with [Opengrep](https://github.com/opengrep/opengrep) (LGPL-2.1 engine, chosen over Semgrep on 2026-11-19): needs pinned-binary plugins because Opengrep publishes binaries, not images; SiegeKit-written Apache-2.0 rules (JavaScript/TypeScript first) are built in, and the [opengrep-rules](https://github.com/opengrep/opengrep-rules) set (LGPL-2.1 with Commons Clause: no selling, including paid consulting) is downloaded by the user at a pinned commit only after they accept its license, never bundled. | All target-authorization negative tests pass; all known issues in the vulnerable web fixture are detected. |
| **M3 Fuzzing and hardware** | Go native fuzzing, Atheris, cargo-fuzz, optional AFL++; GPU detection; hashcat plugin with CPU fallback; AI feature checks with optional garak/promptfoo (ADR 0011). | Seeded crashes are found; GPU and CPU-fallback paths both tested. |
| **M4 1.0 release** | Documentation, signed reproducible builds for Linux and macOS, release process, one-week release-candidate soak. | No open high or critical issues. |
| **M5 Speed and optimization** | Added on 2026-11-19 at the owner's request: after 1.0 is tested and built, before any GUI work. Benchmark suite on the pinned real-repository set (wall time, peak memory, CPU use per check), recorded at 1.0 as the baseline. Parallel scheduler that runs independent checks at once within CPU and memory limits. Caching: reuse results for unchanged files and keep pulled images and tool data warm. Faster startup and file walking; profile the slowest checks and tune their arguments. | Speed targets are set from the 1.0 baseline before work starts and met in CI; every planted issue is still found and the real-repository findings do not change (no speed-up may drop a finding). |
| **After M5** | GUI on top of the stable backend, including a Dependencies tab (ADR 0016); native Windows; third-party plugin loading. | Separate plan. |

## Testing strategy (applies from M1)

- Unit tests for the core, target 80% or more line coverage on core packages.
- Golden-file tests for every parser, using recorded real output from the pinned tool version.
- Integration tests against deliberately vulnerable fixtures run in containers.
- Negative tests for target authorization and the egress proxy.
- Fuzzing of every parser with Go native fuzzing.
- SiegeKit scans its own repository in CI.
