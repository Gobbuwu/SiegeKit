# Contributing

## Process

1. **Design first.** A change to behavior covered by an [ADR](docs/adr/) needs a new or updated ADR before code. Security-relevant changes (target authorization, sandbox, egress, downloads, reports) also update the [threat model](docs/threat-model.md).
2. **Branch and pull request.** Work on a branch; open a pull request against `main`. Direct pushes to `main` are blocked.
3. **Tests with the change.** New code comes with unit tests; a new or changed parser comes with golden files; a new plugin comes with a fixture that proves it finds what it claims.
4. **Review.** At least one approving review and all checks green before merge.

## Adding or updating a wrapped tool

- Pin an exact version and the SHA-256 or image digest for every platform.
- Record in the pull request where the checksum came from (upstream checksum file, signature, or your own verified download).
- Confirm the upstream license and update [THIRD_PARTY.md](THIRD_PARTY.md).
- Re-run the parser golden tests against the new version's real output.

## Commits

- Small, focused commits with a clear message.
- Sign your commits (SSH or GPG) once branch protection requires it.

## Code of conduct

Be respectful and constructive. A formal code of conduct will be adopted before the first public release.
