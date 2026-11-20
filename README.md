# SiegeKit

SiegeKit is a free, local, open-source tool that runs security tests against software you own: static code analysis, dependency and secret scanning, infrastructure-as-code checks, dynamic web/API testing, fuzzing and password-hash audits. You choose which tests to run. Everything runs on your machine.

**Status:** milestone M1 (alpha) is complete; M2 (active web and API testing) is in progress. The alpha can scan a source directory for committed secrets, including in git history and committed `.env` files (gitleaks), `.env` files that `.gitignore` does not exclude, weak or default passwords written into config files and code (ADR 0034), insecure Dockerfile, Kubernetes, Terraform and CI settings (checkov), dependencies with known vulnerabilities (trivy) and common mistakes in Python and Go code (bandit, gosec). On Linux it can also test a running web app by URL: ZAP's crawl and passive checks, Nuclei's checks for known issues and exposed files, ffuf's guesses of common paths, and a Gitleaks scan of the scripts and other files the start page links on every target, and the attack tests (ZAP's attack scan, Nuclei's intrusive and default-login templates, and Schemathesis's API tests from your OpenAPI spec) only on your own local copy, as is the check of whether failed logins on a test account you give it are limited (ADR 0023, ADR 0026, ADR 0027, ADR 0028, ADR 0030, ADR 0032). Do not rely on it yet.

## Try the preview

You need Go 1.26 or later and Docker or Podman.

```sh
CGO_ENABLED=0 go build -o siegekit ./cmd/siegekit   # a static binary (needed for active tests)
./siegekit plugins list
./siegekit update                  # download vulnerability data (about 1.7 GB)
./siegekit scan path/to/your/repo
```

Nothing is downloaded without asking. Before a scan or update installs a missing tool image or tool data, SiegeKit lists it with its size and the tests that need it, says what is already installed, and asks which to install. Declined dependencies skip their tests, and the report lists them. Use `--yes` to install without asking (CI) or `--no-install` to install nothing. SiegeKit never installs Docker or Podman itself, and never uses a copy of a tool installed elsewhere on your machine (ADR 0016).

When you scan a directory, downloads are the only steps that use the network, and they run without access to your files. A URL target is resolved with DNS, and `--deployed` also fetches the proof-of-control file or DNS record. On local targets SiegeKit may also fetch the app's OpenAPI spec itself (`--openapi`, or one GET for each of 10 common paths) for Schemathesis, and with `--login-url` it sends the login throttling check's POST logins itself. On every URL target it fetches the start page and the files it links (GET only, at most 200 requests) for the served-secrets check, and with `--har` it replays the recording's GET and HEAD requests itself (at most 300 requests) for the access-control check. Run `siegekit update` at least weekly; reports say when the data is old.

The scan writes `report.html`, `report.json` and `report.sarif` to `./siegekit-report` and saves a copy of the run under `~/.local/share/siegekit/runs`. The next scan of the same target says what is new and what was fixed since then. Each tool runs in a container with no network and read-only access to your directory. Exit codes: 0 no findings at or above `--fail-on` (default high), 3 findings, 4 a check failed or timed out, 1 an error, 2 a usage error.

## Using SiegeKit with an AI coding assistant

If an AI assistant (Claude Code, Cursor, Copilot and others) works on your app, ask it to run `siegekit agents` first. That prints a guide to the commands, exit codes and `report.json`, and to a loop for fixing findings. The assistant can run scans and fix what they find. You stay in charge of what gets tested and downloaded: SiegeKit asks you before installing anything, and a deployed site needs you to type its host name in your own terminal.

## What a clean scan means

A SiegeKit run with no findings means the automated checks that ran found nothing. It does not mean your app is secure: scanners miss access-control, business-logic and design flaws. Every report shows what was and was not tested; use the [pre-deploy checklist](docs/pre-deploy-checklist.md) for the rest.

## Principles

- **Wrap proven tools, don't rewrite them.** SiegeKit orchestrates established open-source scanners and normalizes their results.
- **Only test what you own.** Active tests against a deployed host require proof of control of that host.
- **Sandboxed.** Every tool runs in its own container with limited access.
- **Local and private.** No account, no subscription, no telemetry.

## Authorized use only

Only test systems you own or have written permission to test. Testing systems without permission may be illegal where you live. SiegeKit checks ownership before active tests against deployed hosts, labels its traffic, and leaves out mass-scanning, denial-of-service and evasion features on purpose. Read the [disclaimer](DISCLAIMER.md) and [acceptable use policy](ACCEPTABLE_USE.md) before running active tests.

## Documentation

- [Roadmap](docs/roadmap.md)
- [Architecture decision records](docs/adr/)
- [Threat model](docs/threat-model.md)
- [What SiegeKit checks](docs/coverage.md)
- [Standards mapping (OWASP, CWE)](docs/standards-mapping.md)
- [Pre-deploy checklist](docs/pre-deploy-checklist.md)
- [Third-party tools and licenses](THIRD_PARTY.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Disclaimer and authorized use](DISCLAIMER.md)
- [Acceptable use policy](ACCEPTABLE_USE.md)

## License

Apache License 2.0. See [LICENSE](LICENSE). Third-party tools that SiegeKit runs keep their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
