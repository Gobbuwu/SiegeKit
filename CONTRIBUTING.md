# Contributing

## Process

1. **Design first.** A change to behavior covered by an [ADR](docs/adr/) needs a new or updated ADR before code. Security-relevant changes (target authorization, sandbox, egress, downloads, reports) also update the [threat model](docs/threat-model.md).
2. **Branch and pull request.** Work on a branch; open a pull request against `main`. Direct pushes to `main` are blocked.
3. **Tests with the change.** New code comes with unit tests; a new or changed parser comes with golden files; a new plugin comes with a fixture that proves it finds what it claims.
4. **Milestone record.** Every pull request updates the record of its milestone in [docs/milestones](docs/milestones/): what it built, the decisions it records, what was verified and how, and what is still unverified or open.
5. **Review.** At least one approving review and all checks green before merge.

## Adding or updating a wrapped tool

- Pin an exact version and the SHA-256 or image digest for every platform.
- Record in the pull request where the checksum came from (upstream checksum file, signature, or your own verified download).
- Confirm the upstream license and update [THIRD_PARTY.md](THIRD_PARTY.md).
- Re-run the parser golden tests against the new version's real output.

## Commits

- Small, focused commits with a clear message.
- Every commit carries a `Signed-off-by:` line (`git commit -s`), certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change or otherwise have the right to submit it under the project's license. The "DCO sign-off" CI check enforces this on every pull request.
- Sign your commits (SSH or GPG) once branch protection requires it.

## Features the project will not accept

Mass scanning, denial-of-service, detection evasion, post-exploitation and live password guessing. See the [acceptable use policy](ACCEPTABLE_USE.md) and the [threat model](docs/threat-model.md).

## Code of conduct

Everyone in project spaces follows the [Code of Conduct](CODE_OF_CONDUCT.md).
