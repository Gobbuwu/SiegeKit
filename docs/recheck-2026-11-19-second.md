# SiegeKit re-check, 2026-11-19 (second, full)

Requested by the owner at 17:01 UTC: go through everything again, verify by running, no assumptions, one report and one fix plan before any fix.

**Scope.** The code on `main` (`46f29df`, includes #26 and #27) combined with the four open PRs: #28 (M2.4a ZAP), #29 (M2.4b Juice Shop gate), #30 (compare runs), #31 (DCO workflow). Merges of #28 to #31 were held until the owner decided.

**How.**
- Ran `go vet` and the full test suite with `-race` and container tests (Linux, Docker 29.10.0) on the combined code.
- Made real CLI runs: a planted repo, URL target refusals, a loopback attack scan in a pseudo-terminal, an unreachable target, `plugins list` and help, and a gitleaks scan of SiegeKit itself.
- Checked the plan rows, ADRs 0005, 0022 and 0023, and the M1/M2 milestone records against the code.
- For what cannot run here (ghcr.io images bandit and gosec, Trivy data, the 20-repo gate, fuzzing, the Juice Shop scan), the evidence is CI on the PR heads.

## Verified working

| Area | Evidence |
| --- | --- |
| Build, vet, format | `go vet ./...` clean, `gofmt -l .` empty (combined code) |
| Unit and container tests | All packages pass locally with `-race`, except 2 tests that need ghcr.io images; those 2 pass in CI on #28 head `72aeb6c` (internal/runner ok, 139 s) |
| Coverage | Every package at 80% or more (CI #28: lowest store 81.7%, audit 84.2%, runner 84.1%) |
| M1 gate: planted issues | `TestBuiltinPluginsFindPlantedIssues` passes in CI (#28). Locally on combined code: a planted repo scan found the committed and deleted `.env` in history, the unignored `.env`, the AWS key, the public Firestore rule and 4 Dockerfile issues (exit 3) |
| M1 gate: 20 real repositories | Gate green on #28 and #30 heads |
| M1 gate: fuzzing | Fuzz targets run in CI on #28 (manifest, SARIF, bandit, backend rules, dotenv, target) |
| M2.1 address rules | Tests cover IPv4-mapped IPv6, decimal, octal and hex IPs, zones, metadata names. Real runs refuse 169.254.169.254, a private address without a terminal, `--deployed` on loopback, and `--deployed --authorized-host` (all exit 1 with clear messages) |
| M2.2 deployed proof | Tests cover redirect, read limit, wrong certificate, parent/sibling TXT, parent's token on a subdomain, stale token, mistyped host |
| M2.3 egress | Proxy tests pass; the read-only rule (`TestReadOnly`) is mutation-checked |
| M2.4a ZAP | `TestZAPFindsPlantedIssues` passes (all 9 planted rules) locally and in CI |
| M2.4b Juice Shop | CI job passed on #29: both ZAP plugins ran (zap 94 requests, zap-active 944), rules 10038 and 10098 found |
| Compare runs (#30) | Unit and CLI tests pass; real runs showed new/fixed/still present correctly; same-second saves get a suffix |
| DCO (#31) | "DCO sign-off" now comes from `dco.yml` and passed |
| Milestone records | Every PR listed in M1.md and M2.md is merged, except #28 and #31 (open, part of this check) |

## Findings

All verified by reading the code and, where marked, a real run. None is a security hole in what is merged today.

| # | Finding | Evidence | Kind |
| --- | --- | --- | --- |
| F1 | No recorded-output golden test for ZAP's report. The testing strategy asks for one per parser | `golden_test.go` map has no zap | Plan gap |
| F2 | Fuzzing never uses the `sarif-zap` parser path (help links from ZAP references) | `sarif_test.go` FuzzSARIF uses a generic parser | Plan gap |
| F3 | HTML report does not show requests sent and refused per check. ADR 0023 says reports show them (terminal and JSON do) | `report.go` template | Plan gap |
| F4 | `docs/agents.md` says `refused` means another host, address or port, but the proxy now also refuses non-GET/HEAD on deployed targets; the GET/HEAD rule is not in the guide | agents.md:70 | Doc drift |
| F5 | On loopback targets, the destructive attack scan starts with no confirmation. ADR 0005 says destructive plugins run "after the run plan is confirmed"; ADR 0022 keeps only the existing confirmations, and loopback has none. The ADRs disagree | Real run in a terminal: no prompt | **Needs your decision** |
| F6 | `siegekit scan ftp://localhost/` is treated as a folder: "lstat …/ftp:: no such file or directory" | Real run | Bug (message) |
| F7 | `requests` counts a request before the target answers. With nothing listening, zap showed 4 "sent" and zap-active 102; none reached the target. The guide says "reached the target" | Real run; `egress.go:310` | Bug |
| F8 | An unreachable target is attacked until the 100-error stop (102 attempts). There is no reachability check before the first plugin | Real run | **Needs your decision** (new step) |
| F9 | Built-in checks call themselves version "1.0.0" ("built into SiegeKit 1.0.0") while SiegeKit is 0.0.0-dev, before 1.0 | `checks/dotenv.go:22`, `backendrules.go:28` | Bug (label) |
| F10 | `siegekit` with no arguments lists only `scan DIR`; URL scans are missing there | Real run | Doc drift |
| F11 | Every attack scan shows 1 to 12 "refused by SiegeKit" requests, but nothing records what was refused, so nobody can tell what ZAP tried to reach | Real runs, CI | Gap (cause unknown) |
| F12 | SiegeKit's own CI self-scan reports 4 gitleaks findings, all fake keys in test files, present since M1, never triaged in a record | Local gitleaks run on the repo | Record gap |
| F13 | CI accepts exit 3 from the self-scan, so a real secret committed to SiegeKit would not fail CI | `ci.yml` | **Needs your decision** |
| F14 | The new rule "milestone check covers that milestone only" is in memory but not yet in `docs/milestones/README.md` | — | Doc |

## Unverified (could not be checked here)

- HTTPS targets with ZAP; Podman; macOS (GitHub assigned no macOS runner since 12:54 UTC).
- Deployed mode end to end against a real public host (no public DNS here).
- Why Juice Shop's attack scan sent 3,443 requests locally but 944 in CI.
- ZAP memory on apps larger than Juice Shop.

## Fix plan: one PR, after #28 to #31 merge

**Plan-required (I'm at least 93% sure these are right, no decision needed):**
- F1: record a real ZAP SARIF report from the fixture run as a golden file and add zap to `TestRecordedToolOutput`.
- F2: add a `sarif-zap` fuzz target, or a seed with the zap parser.
- F3: show requests and refused per check in the HTML report.
- F4, F10, F14: docs (guide `refused` and the GET/HEAD rule; top-level usage; milestone-check scope).
- F6: refuse unsupported URL schemes with a clear message.
- F7: count a request only when the target answered; keep "sent no request = failed" on that count.
- F9: built-in checks report SiegeKit's own version.
- F11: record each refused destination (method, host:port) in `report.json` and the HTML report.
- F12: mark the 4 test keys with `gitleaks:allow` (counted in reports, per your earlier rule) and note the triage in the M1/M2 records.
- Milestone record row, re-run of the full suite and CI.

**Need your decision:**
- F5: ask before destructive checks on loopback targets (type "yes" in a terminal; `--yes` does not count), or change ADR 0005's wording to match today's behavior. I recommend asking.
- F8: one GET to the target before the first plugin, refusing the run with "target not reachable" if it fails. I recommend yes.
- F13: after F12, make CI fail when the self-scan reports any finding. I recommend yes.
- Order: merge #28 to #31 as they are (all checks that ran are green), then this one fix PR. I recommend this over folding fixes into #28, so each PR stays as reviewed.

## Owner decisions (2026-11-19, 17:12 to 17:14 UTC)

- F5: ask first. The attack scan on this machine runs only after the person types `yes` in a terminal or passes `--authorized-host` with the target's host; `--yes` does not count (ADR 0005 as written).
- F8: yes, one GET to the target before the first plugin.
- F13: yes, CI fails on any self-scan finding, after F12.
- Order: #28 to #31 merged as they were, then one fix PR for F1 to F14.

## Outcome

All fourteen findings are fixed in one pull request; see the M2 record. F11's new `refusedTo` field showed the cause of the attack scan's refused requests on the fixture: ZAP sends `CONNECT` for the target's host on an http target, which the proxy refuses.

