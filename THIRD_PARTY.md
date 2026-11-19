# Third-party tools

SiegeKit runs these tools as separate processes inside containers. It does not include their code in its own binary or release archives; each tool is downloaded from its publisher at a pinned version and checksum (see [ADR 0003](docs/adr/0003-wrap-external-tools.md) and [ADR 0008](docs/adr/0008-supply-chain.md)). Each tool keeps its own license.

Versions are the latest published versions checked on 2026-11-18. Rows marked "Pinned" are used by a built-in plugin at exactly that version; the others are **not yet pinned**. Licenses were read from each project's LICENSE file on that date.

## Pinned images

These are the publishers' official images on Docker Hub or the GitHub Container Registry. Each tag was resolved to its multi-architecture index digest with `docker buildx imagetools inspect` on 2026-11-19 (linux/amd64 and linux/arm64), and the plugin manifest refers to the image only by that digest. Publisher image signatures are not verified yet. ADR 0008 asks for this where a publisher signs its images; it was planned for M1 but not done, and is now an open item (re-check of 2026-11-19).

| Plugin | Image | Tag resolved |
| --- | --- | --- |
| [gitleaks](plugins/gitleaks/plugin.json) | `docker.io/zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` | `v8.30.1` |
| [gitleaks-history](plugins/gitleaks-history/plugin.json) | Same image and digest as gitleaks | `v8.30.1` |
| [checkov](plugins/checkov/plugin.json) | `docker.io/bridgecrew/checkov@sha256:122602cf32cc72286155d39f1f234b7b594818f7b8d7fdf490701620e521368b` | `3.4.5` |
| [trivy](plugins/trivy/plugin.json) | `docker.io/aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb` | `0.76.2` (released 2026-11-05, after the [March 2026 compromise](https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know/) of Docker Hub tags 0.69.4 to 0.69.6) |
| [bandit](plugins/bandit/plugin.json) | `ghcr.io/pycqa/bandit/bandit@sha256:b405a808f5d50156aee921a77fb17c044d69d90ecef6499447a037678967c936` | `latest` (the publisher tags no versions; CI checks that the image reports 1.9.4) |
| [gosec](plugins/gosec/plugin.json) | `ghcr.io/securego/gosec@sha256:7bcf1edbab3e80d8006a28d53e7031a9c9775be8eec30679e4adc1f51d272121` | `2.30.0` (released 2026-10-23; the binary in this image reports version "dev", so the version rests on the tag the digest was resolved from) |
| relay for active tests ([ADR 0021](docs/adr/0021-built-in-relay.md)) | `docker.io/library/alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf` (Docker Official Image; used only as a root file system for SiegeKit's own relay binary; busybox GPL-2.0, musl MIT, other packages under their own licenses) | `3.24.4` (published 2026-11-08) |

The two GitHub Container Registry digests were resolved on 2026-11-19. Every pinned image's reported version is checked by `TestPinnedImageVersions` in CI.

Trivy's vulnerability database is not pinned: `siegekit update` lets Trivy download it from its publisher (ADR 0014).

## All tools

| Tool | Purpose | Latest version seen | License | Status |
| --- | --- | --- | --- | --- |
| [Semgrep CE](https://github.com/semgrep/semgrep) | SAST | 1.186.0 | LGPL-2.1 | Not planned; Opengrep chosen instead (its rules allow only internal business use) |
| [Semgrep community rules](https://github.com/semgrep/semgrep-rules) | SAST rules | n/a | [Semgrep Rules License v1.0](https://semgrep.dev/legal/rules-license): "only for your own internal business purposes", no distribution | Not bundled; needs a decision before any download |
| [Opengrep](https://github.com/opengrep/opengrep) and [opengrep-rules](https://github.com/opengrep/opengrep-rules) | SAST, many languages | 1.33.1 | Engine LGPL-2.1; rules LGPL-2.1 with Commons Clause | Planned (M2); rules downloaded by the user after accepting their license |
| [Bandit](https://github.com/PyCQA/bandit) | SAST, Python | 1.9.4 | Apache-2.0 | Pinned (M1) |
| [gosec](https://github.com/securego/gosec) | SAST, Go | 2.30.0 | Apache-2.0 | Pinned (M1) |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Dependency vulnerabilities | 2.7.1 | Apache-2.0 | Planned (M2; moved from M1 on 2026-11-19) |
| [Syft](https://github.com/anchore/syft) | SBOM | 1.57.2 | Apache-2.0 | Planned (M2; moved from M1 on 2026-11-19) |
| [Grype](https://github.com/anchore/grype) | Vulnerabilities, images | 0.122.1 | Apache-2.0 | Planned (M2; moved from M1 on 2026-11-19) |
| [Trivy](https://github.com/aquasecurity/trivy) | Images, IaC, dependencies | 0.76.2 | Apache-2.0 | Pinned (M1, dependencies) |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets | 8.30.1 | MIT | Pinned (M1) |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secrets with verification | 3.99.9 | AGPL-3.0 | Optional |
| [Checkov](https://github.com/bridgecrewio/checkov) | IaC | 3.4.5 | Apache-2.0 | Pinned (M1) |
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
| [Nmap](https://github.com/nmap/nmap) | Port and service discovery | not checked | Nmap Public Source License (not OSI-approved) | Not planned. SiegeKit never runs tools installed on the host (ADR 0016) |
| [CodeQL CLI](https://github.com/github/codeql-cli-binaries) | SAST | not checked | GitHub CodeQL Terms and Conditions (not open source) | Excluded |
