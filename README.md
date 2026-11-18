# SiegeKit

SiegeKit is a free, local, open-source tool that runs security tests against software you own: static code analysis, dependency and secret scanning, infrastructure-as-code checks, dynamic web/API testing, fuzzing and password-hash audits. You choose which tests to run. Everything runs on your machine.

**Status:** design phase (milestone M0). There is no runnable code yet.

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
- [Pre-deploy checklist](docs/pre-deploy-checklist.md)
- [Third-party tools and licenses](THIRD_PARTY.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Disclaimer and authorized use](DISCLAIMER.md)
- [Acceptable use policy](ACCEPTABLE_USE.md)

## License

Apache License 2.0. See [LICENSE](LICENSE). Third-party tools that SiegeKit runs keep their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
