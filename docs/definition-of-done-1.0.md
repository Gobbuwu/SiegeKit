# Definition of done for 1.0

SiegeKit 1.0 ships when every line below is checked off with named evidence (a test, a CI run or a measurement), the self-audit gate passes on the release candidate, and the owner signs off. The owner approved this list on 2026-11-22 ([draft](https://claude.ai/artifact/6GDTCmwNL5QmSoA92VJD7P)). It turns the gates in [roadmap.md](roadmap.md) into checkable lines; where the two differ, this file records the later owner decision and the roadmap is changed in the same pull request.

Every milestone also follows the rules in [milestones/README.md](milestones/README.md): each PR updates its milestone record; every result names its engine, rootless or rootful and cgroup version; an unexplained difference between two runs blocks the milestone check; a milestone check includes hand triage and an evidence check of that milestone's ADRs; findings go into one report and one fix plan.

"Unverified" marks a claim that no test, measurement or cited source backs yet.

## Order

M2 work, then the M2 milestone check and bug fixing, then M3, then M4 with the self-audit gate on the release candidate, then the 1.0 tag. After 1.0: M5 speed and optimization, the full project check, the third-party AI agent test, then the GUI.

## 1. Rest of M2

| # | Item | Done when (evidence) | Status on 2026-11-22 |
| --- | --- | --- | --- |
| 1 | GET replay safety (ADR 0048) | Merged with every CI check that ran green. | Done, #58 |
| 2 | ARTEX item 2: replay of data-changing requests (ADR 0049, 0050) | Merged; the test app's planted write issue is found; local targets only (negative test). | Done, #59 and #60 |
| 3 | ARTEX item 3: rate-limit presets and a spray or per-IP lockout test | Merged; a planted fixture limit is found and a missing one is reported; the Juice Shop gate grows by no more than the measured cost (about 77 s, `artex-gaps-cost-2026-11-21.md` in the project files) plus noise the owner accepts. | Open |
| 4 | ARTEX item 5: storage write-then-delete | Merged; finds the planted open bucket on the Firebase emulator and on local Supabase; the object count after the run equals the count before on both. Real Firebase stays untested unless the owner creates a test project. | PR 1 (the check, ADR 0058) merged as #69; PR 2 (CI known answers, ADR 0059) merged as #70 |
| 5 | Outsider account C and route sweep (owner 2026-11-22, "Spec + server code (E2), with B") | PR 1, account C (ADR 0051): merged. PR 2, every object-naming route in the API spec sent as C with IDs from A's recording, reads first, local targets: the Rocket.Chat `chat.getDeletedMessages` leak (no room check, measured on 6.13.1 and 8.9.1) is found. PR 3, routes read from the person's server code, one extractor per framework: the same leak is found without a spec. | PR 1 done (#61); PR 2 building; PR 3 open |
| 6 | Consented Go module download (design, then build) | The owner approves the design; the 10-repository offline gosec measurement is rerun and every package either loads or is listed as failed. The target for findings regained is set with the design. | Design approved 2026-11-24 (ADR 0066, #72): target = every finding the same image finds with network on the 10 repositories, both engines; build in #78 |
| 7 | Design parts 3 to 5, "checks that finish or say so" | Every check compares what its tool was given with what it checked, including output caps, and flags any gap on every run (owner, 2026-11-22), or reports "not proven complete". Covers the open cases: gosec taint skips, Bandit's unparsable files, the Schemathesis request count. | Design approved 2026-11-24 (ADR 0067, #80, "All recommended (round 2)"): run stops fail with exit 4, file gaps named (`--require-complete` fails them), limits from measured program peaks, rules not run named, a shared URL list for both ZAP checks; build in five PRs |
| 8 | M2.8: OSV-Scanner, Syft (SBOM), Grype; OSV-Scanner and Scorecard in CI | Planted issues found; the 20-repository gate's findings are unchanged. | Open |
| 9 | M2.9: Opengrep with SiegeKit's JS/TS rules, opengrep-rules after license acceptance, detected languages, mobsfscan test | Planted issues found on Linux and macOS, amd64 and arm64; opengrep-rules never downloaded without acceptance (negative test); mobsfscan decision recorded (ADR 0033 item 4). | Open |
| 10 | M2.10: optional sqlmap and Nikto, default request rate, deployed-mode decisions | Default rate set from a measurement; each "local only until M2.10" item (ZAP attack scan, login throttling, rate-limit) has the owner's decision recorded in an ADR. | Open |
| 11 | Data-changing requests that are not in the recording, including writes taken from the API spec with A's read-back (owner 2026-11-21: build before 1.0) | Design approved; a planted unrecorded write endpoint in the test app is found; local targets only (negative test). | Open |
| 12 | Multi-step flows, for example checkout or password reset (owner 2026-11-21) | Design approved; a planted flow bug in the test app is found. | Open |
| 13 | GraphQL (owner 2026-11-21) | Design approved; planted GraphQL issues in a fixture are found. | Open |
| 14 | WebSockets, including socket and DDP method calls (owner 2026-11-21) | Design approved; a planted WebSocket issue in a fixture is found. | Open |
| 15 | ARM Linux CI job on `ubuntu-24.04-arm` (owner 2026-11-22), built after the current build thread | Pulls SiegeKit's pinned tool images and runs the real scans on arm64; every pinned image has an arm64 build or the gap is listed; planted issues found as on amd64. | Done: #71 (ADR 0060) merged 2026-11-23: every pinned digest has an arm64 build (no gap); planted-issue container tests, the self-scan and every gate job (the same known answers) pass on arm64 with rootless Podman 4.9.3 and Docker 28.0.4, cgroup v2 |
| 16 | Opt-in ZAP browser flag for DOM XSS, rule 40026 (owner 2026-11-22) | Merged; with the flag, the planted DOM XSS in the test app is found on both engines; without it, reports list DOM XSS as not tested; the looser sandbox settings (executable `/tmp`, more processes, 4 GiB) apply only with the flag (test). The 2026-11-20 costs (Juice Shop 3 to 7 min, 4 GiB) are measured again on current `main`. | Open |
| 17 | Approved follow-ups: image signature checks (after checking which publishers sign); update containers restricted to publisher hosts | Merged with tests. | Open |
| 18 | Outsider reads sent as POST (owner 2026-11-22, before 1.0): read-named method calls replayed as B, C and with no login, local targets only, under the write check's confirmation | Design approved; Rocket.Chat's `loadHistory`, `getRoomByTypeAndName` and `getRoomRoles` for a private room are refused for C in the measured setup, and a planted outsider POST-read leak in the test app is found. | Open |
| 19 | ID guessing as an outsider (owner 2026-11-22, before 1.0), for example predictable room IDs | Design approved with a measured request cap; a planted guessable-ID leak in the test app is found; local targets only (negative test). | Open |

Items 11 to 14, 18 and 19 are placed in M2, before its milestone check. Each gets a measured design for the owner first, then its own pull request.

## 2. M2 milestone check and bug fixing

- [ ] **Gate, part 1:** every target-authorization and egress negative test passes in CI on both engines (rootless Podman and Docker).
- [ ] **Gate, part 2:** every known issue in the vulnerable web fixture is detected. DOM XSS counts with the browser flag on (item 16).
- [ ] **Root causes first** (owner, 2026-11-22): every drop or flake seen so far is traced to its cause and fixed with a regression test, including the ZAP 40045 miss under Podman (traced and fixed with regression tests, ADR 0065) and the cause of each of the 3 relay-leftover CI failures (fixed by #52; cause per failure unverified).
- [ ] **Known false positives closed**, each with a regression test or the owner's written acceptance as a gap: ZAP 40045 on the Juice Shop login (closed by ADR 0065: made by SiegeKit's HAR, regression tests added), ZAP 10104 on Juice Shop, `rate-limit` reporting a mistyped URL on a single-page app as not limited, Gitea 40018, Rocket.Chat `roles.list`, `commands.list`, `users.info` and the tried `DELETE /avatar/room/<rid>`.
- [ ] **No open unexplained run-to-run difference** under M2's "Known gaps", including why 10104 lost a path only on #50's PR runs.
- [ ] **Hand triage** to the README's sampling rule; counts per check under "Result quality", with the labelled list beside it.
- [ ] **ADR evidence check:** every key claim in each ADR written in M2 is backed by a test, measurement or cited source, or is listed as a finding.
- [ ] **Every "Unverified" and "Known gaps" line re-read** against later PRs and corrected.
- [ ] **One report and one fix plan;** every fix merged; the gate run again on `main` afterwards, green on both engines.
- [ ] **Confirmation:** 10 green gate runs per engine after the fixes. They confirm, they do not prove: a flake that fails 1 run in 5 passes 10 runs about 11% of the time (0.8^10).
- [ ] The owner signs off; `M2.md` gets the date and the evidence for each gate item.

## 3. M3 Fuzzing and more targets

M3 has no design yet; these lines are the roadmap gate made checkable, and the M3 design adds detail.

- [ ] Go native fuzzing, Atheris and cargo-fuzz each find a seeded crash in a fixture, in CI. AFL++ only if the owner keeps it in.
- [ ] Container-image targets: a test image with a planted secret and an outdated OS package is scanned, and Trivy reports both.
- [ ] Mobile apps: MobSF static analysis finds planted issues in a test `.apk`, `.aab` and `.ipa`, offline in the sandbox; an encrypted App Store `.ipa` is refused (negative test); dynamic testing is decided in an ADR after one measured emulator run (ADR 0033).
- [ ] hashcat on the CPU cracks a known test hash. GPU detection and the GPU path move to M5 or later (owner, 2026-11-21), tested on the owner's own machine if needed.
- [ ] AI feature checks (garak or promptfoo, optional): a planted prompt-injection fixture is reported.
- [ ] The M3 milestone check passes under the same rules as M2, and the owner signs off.

## 4. M4 1.0 release

- [ ] Documentation: every shipped check appears in `docs/coverage.md` and the standards mapping with what it does not test; the `siegekit agents` guide matches `report.json` (existing test).
- [ ] Signed reproducible builds for Linux and macOS: two independent builds of the release commit are byte-identical and the signatures verify.
- [ ] Release process written and dry-run once end to end on a test tag.
- [ ] Lawyer review, once the 1.0 scope is fully defined (owner, 2026-11-21): a qualified lawyer reviews `DISCLAIMER.md`, `ACCEPTABLE_USE.md`, `THIRD_PARTY.md` and the Opengrep and opengrep-rules license handling; the template banners come off only after their written sign-off, recorded with its date.
- [ ] One-week release-candidate soak (owner, 2026-11-22): the full gate runs daily on the candidate for 7 days and the owner uses the candidate on a project of their own; no new high or critical issue and no unexplained difference.
- [ ] No open high or critical issue (GitHub issues and milestone records).
- [ ] The self-audit gate passes on that candidate.

## 5. Self-audit gate

Runs on the 1.0 release candidate; passes only with no open high or critical issue in SiegeKit, and any new one restarts it. These are the seven parts in the roadmap.

- [ ] **Self-scan:** SiegeKit scans its own repository and release binaries with every check it ships.
- [ ] **Fuzzing:** every fuzz target runs at least one hour; parsers get new seed corpora from real tool output.
- [ ] **Trust-boundary review:** line-by-line review of the sandbox, egress proxy, target rules and address pinning, ownership verification, dependency consent and downloads, parsers, report rendering and audit log; every threat-model row has a test or a written review note.
- [ ] **Supply chain:** every pinned image, binary and rule set re-verified (digest, signature where published, at least 7 days old, license); `govulncheck` clean on SiegeKit and its Go toolchain; SiegeKit's SBOM published; reproducible-build check passes.
- [ ] **End to end** with Docker and rootless Podman: the real-repository gate, the vulnerable fixture in local mode, deployed mode against a staging host the owner controls (the owner provides it), and every target-authorization and egress negative test. Platforms (owner, 2026-11-22): Linux amd64; arm64 through the ARM Linux CI job (item 15); macOS through GitHub's Intel Mac runners with Colima. Apple-chip Macs are tested once the owner has one, and are listed as untested if 1.0 ships first.
- [ ] **Claude Security deep scan** of the release-candidate commit (owner, 2026-11-21); every finding verified, then fixed with a regression test or closed with a written reason.
- [ ] **Write-up:** `docs/self-audit.md` lists every issue found and its fix PR; the owner signs off.

## 6. The release

- [ ] `v1.0.0` is tagged from the exact candidate commit that passed the self-audit gate and the soak.
- [ ] Signed binaries, checksums and SiegeKit's SBOM are published with the release, and verified from a clean machine.
- [ ] Installing from the release and running `--profile quick` works on each platform in the self-audit matrix.
- [ ] The release notes list what 1.0 tests and what it does not (from `docs/coverage.md`), and never say "secure".

## After 1.0 (recorded here so it is not lost)

- M5 speed and optimization, including GPU detection and the GPU path for hashcat (owner, 2026-11-21).
- Full project check.
- Third-party AI agent test (owner, 2026-11-20, kept after 1.0 on 2026-11-21): SiegeKit driven by a non-Claude agent, which must not be able to confirm targets itself.
- GUI. It listens on the user's own machine only (loopback) by default, and a test proves it: Unit 42 found hundreds of ARTEX consoles open on the internet (`artex-vs-siegekit-2026-11-21.md` in the project files, lesson 6). Its own plan adds the rest.
