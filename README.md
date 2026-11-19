# SiegeKit

SiegeKit is a free, local, open-source tool that runs security tests against software you own: static code analysis, dependency and secret scanning, infrastructure-as-code checks, dynamic web/API testing, fuzzing and password-hash audits. You choose which tests to run. Everything runs on your machine.

**Status:** milestone M1 in progress. An early developer preview can scan a source directory for committed secrets (gitleaks), insecure Dockerfile, Kubernetes, Terraform and CI settings (checkov) and dependencies with known vulnerabilities (trivy). Do not rely on it yet.

## Try the preview

You need Go 1.26 or later and Docker or Podman.

```sh
go build -o siegekit ./cmd/siegekit
./siegekit plugins list
./siegekit update                  # download vulnerability data (about 1.7 GB)
./siegekit scan path/to/your/repo
```

`siegekit update` is the only step that uses the network, and it runs without access to your files. Run it again at least weekly; reports say when the data is old.

The scan writes `report.html`, `report.json` and `report.sarif` to `./siegekit-report` and saves a copy of the run under `~/.local/share/siegekit/runs`. Each tool runs in a container with no network and read-only access to your directory. Exit codes: 0 no findings at or above `--fail-on` (default high), 3 findings, 4 a check failed or timed out, 1 an error, 2 a usage error.

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
