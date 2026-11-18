# Third-party tools

SiegeKit runs these tools as separate processes inside containers. It does not include their code in its own binary or release archives; each tool is downloaded from its publisher at a pinned version and checksum (see [ADR 0003](docs/adr/0003-wrap-external-tools.md) and [ADR 0008](docs/adr/0008-supply-chain.md)). Each tool keeps its own license.

Versions are the latest published versions checked on 2026-11-18 and are **not yet pinned**; pins and checksums are added with each plugin. Licenses were read from each project's LICENSE file on that date.

| Tool | Purpose | Latest version seen | License | Status |
| --- | --- | --- | --- | --- |
| [Semgrep CE](https://github.com/semgrep/semgrep) | SAST | 1.186.0 | LGPL-2.1 | Planned (M1) |
| [Semgrep community rules](https://github.com/semgrep/semgrep-rules) | SAST rules | n/a | LGPL-2.1 with Commons Clause | Not bundled; user opts in to download |
| [Bandit](https://github.com/PyCQA/bandit) | SAST, Python | 1.9.4 | Apache-2.0 | Planned (M1) |
| [gosec](https://github.com/securego/gosec) | SAST, Go | 2.30.0 | Apache-2.0 | Planned (M1) |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Dependency vulnerabilities | 2.7.1 | Apache-2.0 | Planned (M1) |
| [Syft](https://github.com/anchore/syft) | SBOM | 1.57.2 | Apache-2.0 | Planned (M1) |
| [Grype](https://github.com/anchore/grype) | Vulnerabilities, images | 0.122.1 | Apache-2.0 | Planned (M1) |
| [Trivy](https://github.com/aquasecurity/trivy) | Images, IaC, dependencies | 0.76.2 | Apache-2.0 | Planned (M1) |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets | 8.30.1 | MIT | Planned (M1) |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secrets with verification | 3.99.9 | AGPL-3.0 | Optional |
| [Checkov](https://github.com/bridgecrewio/checkov) | IaC | 3.4.5 | Apache-2.0 | Planned (M1) |
| [KICS](https://github.com/Checkmarx/kics) | IaC | not checked | Apache-2.0 | Later |
| [Hadolint](https://github.com/hadolint/hadolint) | Dockerfiles | not checked | GPL-3.0 | Optional |
| [ZAP](https://github.com/zaproxy/zaproxy) | DAST | 2.17.0 | Apache-2.0 | Planned (M2) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) and [templates](https://github.com/projectdiscovery/nuclei-templates) | DAST, known CVEs | 3.11.1 | MIT | Planned (M2) |
| [ffuf](https://github.com/ffuf/ffuf) | Content discovery | 2.3.0 | MIT | Planned (M2) |
| [Schemathesis](https://github.com/schemathesis/schemathesis) | API fuzzing | 4.33.4 | MIT | Planned (M2) |
| [sqlmap](https://github.com/sqlmapproject/sqlmap) | SQL injection | 1.10.11 | GPL-2.0 | Optional (M2) |
| [Nikto](https://github.com/sullo/nikto) | Web server checks | not checked | GPL-3.0 (code); database under separate terms | Optional (M2) |
| [Atheris](https://github.com/google/atheris) | Python fuzzing | 3.1.0 | Apache-2.0 | Planned (M3) |
| [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) | Rust fuzzing | 0.13.2 | not checked | Planned (M3) |
| [AFL++](https://github.com/AFLplusplus/AFLplusplus) | Native fuzzing | not checked | AGPL-3.0-or-later (afl-fuzz) | Optional (M3) |
| [garak](https://github.com/NVIDIA/garak) | LLM prompt-injection probing | 0.17.1 | Apache-2.0 | Optional (M3) |
| [promptfoo](https://github.com/promptfoo/promptfoo) | LLM prompt-injection probing | 0.126.0 | MIT | Optional (M3) |
| [hashcat](https://github.com/hashcat/hashcat) | Hash strength audit, GPU | 8.0.0 | MIT | Optional (M3) |
| [John the Ripper](https://github.com/openwall/john) | Hash strength audit, CPU | not checked | Mixed, per file | Optional (M3) |
| [Nmap](https://github.com/nmap/nmap) | Port and service discovery | not checked | Nmap Public Source License (not OSI-approved) | Not bundled; used only if the user installed it |
| [CodeQL CLI](https://github.com/github/codeql-cli-binaries) | SAST | not checked | GitHub CodeQL Terms and Conditions (not open source) | Excluded |
