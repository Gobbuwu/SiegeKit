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
| `gitleaks-history.sarif` | gitleaks 8.30.1, pinned image | the manifest's arguments and environment, on a separate git repository with three commits: a committed `.env` (later untracked and added to `.gitignore`), an `.env.example` (allowed), and a `conf.py` with a fake AWS key that a later commit deletes. Values are redacted by gitleaks. |
| `results_sarif.sarif` | checkov 3.4.5, pinned image | the manifest's arguments |
| `trivy.sarif` | trivy 0.76.2, pinned image (`sha256:8f6bb947…`) | the manifest's scan arguments with the vulnerability database of 2026-11-19 |
| `gosec.sarif` | gosec v2.30.0, built with `go install` (the pinned ghcr image could not be pulled from the recording machine) | the manifest's arguments, target at `/target` |
| `bandit.json` | bandit 1.9.4 from PyPI (same reason) | the manifest's arguments, target at `/target` |

Bandit repeats the token in its output. It was replaced with `PLACEHOLDER_NOT_A_REAL_TOKEN` before the file was committed.

After re-recording, run `go test ./internal/runner -run TestRecordedToolOutput -update` and review the golden diff.
