# Recorded tool output

Real reports from the pinned tool versions, used by `TestRecordedToolOutput`. They were recorded on 2026-11-19 from one small target with these files:

- `config.py`: a GitHub token assembled at run time (never stored in this repository)
- `Dockerfile`: `FROM ubuntu:latest`, `RUN apt-get update`, `USER root`
- `requirements.txt`: `django==2.2.0`
- `app.py`: `subprocess.call(cmd, shell=True)`
- `go.mod` and `main.go`: `md5.Sum` on a command-line argument

| File | Tool and version | How |
| --- | --- | --- |
| `gitleaks.sarif` | gitleaks 8.30.1, pinned image | the manifest's arguments |
| `gitleaks-history.sarif` | gitleaks 8.30.1, pinned image | the manifest's arguments and environment, on a separate git repository with three commits: a committed `.env` (later untracked and added to `.gitignore`), an `.env.example` (allowed), and a `conf.py` with a fake AWS key that a later commit deletes. Values are redacted by gitleaks. Recorded before ADR 0063 changed how the configuration is passed (`GITLEAKS_CONFIG` with the repository's rules and SiegeKit's); that changes which rules apply, not the shape of the report the parser reads. |
| `results_sarif.sarif` | checkov 3.4.5, pinned image | the manifest's arguments |
| `trivy.json` | trivy 0.76.2, pinned image (`sha256:8f6bb947…`) | recorded 2026-11-23 for ADR 0063 with the manifest's scan arguments (`--include-dev-deps --list-all-pkgs --format json`) and the vulnerability database of 2026-11-23, on the same target plus a `package.json` and `package-lock.json` with lodash 4.17.20 (production) and minimist 1.2.5 (development). It replaced `trivy.sarif`: the 43 django findings have the same fingerprints, titles, severities, locations and messages as before, and now carry CWE IDs. |
| `gosec.sarif` | gosec v2.30.0, built with `go install` (the pinned ghcr image could not be pulled from the recording machine) | the manifest's arguments, target at `/target`. Recorded again on 2026-11-19 after `-track-suppressions` was added: byte-for-byte the same, because the target has no `#nosec` comment. |
| `bandit.json` | bandit 1.9.4 from PyPI (same reason) | the manifest's arguments, target at `/target` |
| `zap/zap.json`, `zap-active/zap.json` | ZAP 2.17.0, pinned image (`zaproxy/zap-stable@sha256:9624669d…`) | recorded 2026-11-19 from `RunURL` with both built-in manifests against SiegeKit's own test fixture (`vulnapp_test.go`) served at `http://app.test:46199/`, behind the relay and egress proxy, the same path as `TestZAPFindsPlantedIssues`. The `/etc/passwd` text in the path-traversal evidence is the fixture's fake answer. |

In `gitleaks-history.sarif`, gitleaks' own `sourcegraph-access-token` rule matches two commit hashes of the recording repository. A `"siegekitNote": "gitleaks:allow"` property was added on those two lines (2026-11-19) so SiegeKit's self-scan does not report them; the parser ignores it.

Bandit repeats the token in its output. It was replaced with `PLACEHOLDER_NOT_A_REAL_TOKEN` before the file was committed.

After re-recording, run `go test ./internal/runner -run TestRecordedToolOutput -update` and review the golden diff.
