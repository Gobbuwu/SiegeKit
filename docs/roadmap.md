# Roadmap

Each milestone ends with a gate. The next milestone does not start until the gate passes and the project owner signs off.

| Milestone | Scope | Gate |
| --- | --- | --- |
| **M0 Design** | ADRs 0001 to 0011, coverage map, standards mapping, threat model, plugin manifest schema, pre-deploy checklist, repository and legal policies. | Owner signs off on the ADRs and threat model; ADRs move to Accepted. |
| **M1 Core and passive scans (alpha)** | CLI, planner, scheduler, sandbox runner, findings store, HTML/SARIF/JSON reports with coverage summary (ADR 0009), CI pipeline. Plugins: Semgrep CE, Bandit, gosec, OSV-Scanner, Syft, Grype, Gitleaks, Checkov, Trivy; static backend-rules checks (ADR 0011). | Every planted issue in the fixture repositories is found; no crashes on 20 real open-source repositories; parser fuzzing runs in CI. |
| **M2 Active web and API testing (beta)** | Local and deployed target modes, ownership verification, egress proxy, rate limiting, login-throttling and default-credential checks, secrets in served content (ADR 0010); authorization differential test, unauthenticated route check, rate-limit check, live backend-rules check (ADR 0011). Plugins: ZAP, Nuclei, ffuf, Schemathesis; optional sqlmap and Nikto. | All target-authorization negative tests pass; all known issues in the vulnerable web fixture are detected. |
| **M3 Fuzzing and hardware** | Go native fuzzing, Atheris, cargo-fuzz, optional AFL++; GPU detection; hashcat plugin with CPU fallback; AI feature checks with optional garak/promptfoo (ADR 0011). | Seeded crashes are found; GPU and CPU-fallback paths both tested. |
| **M4 1.0 release** | Documentation, signed reproducible builds for Linux and macOS, release process, one-week release-candidate soak. | No open high or critical issues. |
| **After 1.0** | GUI on top of the stable backend; native Windows; third-party plugin loading. | Separate plan. |

## Testing strategy (applies from M1)

- Unit tests for the core, target 80% or more line coverage on core packages.
- Golden-file tests for every parser, using recorded real output from the pinned tool version.
- Integration tests against deliberately vulnerable fixtures run in containers.
- Negative tests for target authorization and the egress proxy.
- Fuzzing of every parser with Go native fuzzing.
- SiegeKit scans its own repository in CI.
