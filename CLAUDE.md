# CLAUDE.md

Rules for AI coding assistants working on SiegeKit's own code. To run SiegeKit for a person instead, follow [docs/agents.md](docs/agents.md). Process details are in [CONTRIBUTING.md](CONTRIBUTING.md).

SiegeKit is a free, local security test runner (Go, Linux and macOS first, Windows via WSL2). It wraps pinned tools in containers and runs its own checks against code and apps the person owns.

## Top rules
1. Never guess or assume. Back each claim with a test, a measurement or a cited source, and label the rest "unverified". Self-rated confidence is not evidence.
2. Fix the root cause and the whole class of failure, not one instance. Trace any failure without a known cause until it is understood. Never re-run or patch "until it works".
3. Ask the maintainer before any step that can't be undone: merges, settings, releases, installs, messages outside the repo.

## Commands (what CI runs; Go 1.27.4)
```sh
test -z "$(gofmt -l .)"
go vet ./...
go test -race -count=1 -timeout 30m ./...   # container tests: SIEGEKIT_CONTAINER_TESTS=1 SIEGEKIT_ENGINE=podman|docker
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run golang.org/x/tools/cmd/deadcode@v0.52.0 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
go build -o /tmp/siegekit ./cmd/siegekit && /tmp/siegekit scan --fail-on info --no-save .   # self-scan: any finding fails CI
GOTOOLCHAIN=go1.27.4 go generate ./internal/waiterbin   # after changing internal/waiter or cmd/siegekit-waiter
```
Real-app tests run in `.github/workflows/gate.yml` (Juice Shop, Gitea and others). Its path filter must cover every path that changes scan behaviour.

## Decisions
- Measure every option on the real apps, through SiegeKit itself (a prototype run, not only curl or a direct tool run), on both engines (rootless Podman and Docker) and both chips (amd64 and arm64) where it matters. Recommend only the best measured option, with each option's cost and the coverage it gains or loses.
- A decision card says "all options measured through SiegeKit" or lists exactly what isn't. Keep it to the 2 to 4 options that matter.
- Record each decision with its evidence in `docs/adr/`. Security-relevant changes also update `docs/threat-model.md`.

## Pull requests and merges
- One PR per piece of work. Each PR updates its milestone record (`docs/milestones/Mx.md`): what was built, decisions, how it was verified, what is unverified, gaps.
- Before asking to merge: CI and gate green, the critical review sweep run on the full diff against main (project threads: `review-critical-checklist.md` in the project files), and everything labelled unverified verified. Report a weakened test or gate to the maintainer instead of fixing it quietly.
- Merge one PR at a time; update the next from main and re-run its checks.
- Sign off every commit (DCO) and never force-push.

## Testing
- Record the environment (OS, chip, engine, rootless or not, cgroup version, versions) with each result. A result holds only where it ran.
- Tools can drop work and exit 0: cross-check counts with an independent source. Trust known answers only from complete runs.
- Design tests the way real attackers work: recon, every route, chaining. GET is not always safe.

## Security and scope
- Test only throwaway apps and local copies, never systems you don't own. Report weaknesses privately through a security advisory, never in a public issue or PR.
- Reports never call an app "secure": they say which checks ran and which didn't (`docs/coverage.md`).
- Free and non-commercial. Use Opengrep, not Semgrep; licensed rule sets are downloaded by the user only.
- Never add mass scanning, denial of service, detection evasion, post-exploitation or live password guessing ([ACCEPTABLE_USE.md](ACCEPTABLE_USE.md)).
- The Porchlet repository is read-only for this project. Porchlet reports SiegeKit bugs as issues labelled `from-porchlet`; when a fix merges, comment on the issue so Porchlet retests.
