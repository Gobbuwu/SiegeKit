# SiegeKit

SiegeKit is a free, local, open-source tool that runs security tests against software you own: static code analysis, dependency and secret scanning, infrastructure-as-code checks, dynamic web/API testing, fuzzing and password-hash audits. You choose which tests to run. Everything runs on your machine.

**Status:** design phase (milestone M0). There is no runnable code yet.

## Principles

- **Wrap proven tools, don't rewrite them.** SiegeKit orchestrates established open-source scanners and normalizes their results.
- **Only test what you own.** Active tests against a deployed host require proof of control of that host.
- **Sandboxed.** Every tool runs in its own container with limited access.
- **Local and private.** No account, no subscription, no telemetry.

## Documentation

- [Roadmap](docs/roadmap.md)
- [Architecture decision records](docs/adr/)
- [Threat model](docs/threat-model.md)
- [Third-party tools and licenses](THIRD_PARTY.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

Apache License 2.0. See [LICENSE](LICENSE). Third-party tools that SiegeKit runs keep their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
