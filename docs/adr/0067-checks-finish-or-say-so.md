# 0067. Every check compares what it was given with what it checked: run stops, named gaps, measured limits, rules not run, a shared URL list

- Status: Accepted (owner, 2026-11-24 20:05 UTC: "All recommended (round 2)" on the design's decision card, after every option was measured; to be built in five PRs)
- Date: 2026-11-24
- Amends: [0009](0009-honest-results.md) (a check can be complete, have named gaps, or be not proven complete), [0040](0040-tools-that-skip-work.md) (file gaps are named without failing the check; run stops fail it), [0043](0043-zap-reports-every-alert.md) (the passive scan's alerts-a-rule cap is removed)
- Related: [0038](0038-run-environment.md) (the design "checks that finish or say so", parts 0 to 2 in #46 and #47), [0047](0047-recorded-requests-to-zap.md) (part 5 seeds GET URLs when no recording is given), [0048](0048-get-replay-skips-actions.md) (the action-word skip), 1.0 item 7

## Context

1.0 item 7 asks that every check compares what its tool was given with what it checked, including output caps, and flags any gap on every run, or says "not proven complete". The design "checks that finish or say so" (owner, 2026-11-20) left three parts: limits set from measurement (part 3), rules not run shown as not tested (part 4), and a shared URL list (part 5).

The design document is "SiegeKit: checks that finish or say so, parts 3 to 5 (design)"; the full record with scripts and numbers is `completeness-parts-3-5-2026-11-24.md` in the project files. The temporary measuring workflow and scripts ran in this PR (`.github/workflows/zz-measure-completeness.yml`, `.github/zz-measure/`) and are removed before merge. After the first set of recommendations the owner asked whether every pick was validated (2026-11-24 19:15 UTC); every option was then measured, through SiegeKit where it can be, and four picks changed (Q1, Q3, Q5, Q7).

What the measurements found:

1. **Six tools (seven checks) drop work with exit 0 and no word in the report.** ZAP's passive scan keeps 10 alerts a rule (Juice Shop 33 findings instead of 235); a cut-short ZAP attack scan started 50 of 54 rules and said nothing; Checkov drops Kubernetes YAML it cannot parse with no trace; Bandit puts unparsable files in `errors`; Trivy dropped a broken `package-lock.json` and `poetry.lock`; Gitleaks history at 96 MiB scanned 2,503 of 21,840 commits; Nuclei against a target that stopped answering finished at 73% with 5 and 9 findings instead of 19; 262 Nuclei templates fail at runtime on every run.
2. **SiegeKit's own checks hit 14 kinds of caps in silence**, among them 2 MiB answers counted as "did not answer" by `access-control`, the served-secrets fetch cap inherited by `public-maps`, `backend-live` and `storage-write`, and `dotenv-gitignore` reporting "ran" on a folder with no `.git` (inventory in the record).
3. **Only a process inside the container sees every refused process and memory kill.** A small static program started as the container's first process (the waiter) gave counters or exit 137 in every run, on rootless Podman and Docker, amd64 and arm64, cgroup v1 and v2. Polling from the host every 2 s caught 0 of 18 events; the engine's `inspect` missed a memory kill with exit 0 on Podman 4.9.3 and never sees refused processes. Rootless Podman gives the tool an OOM score of 500, so the waiter raises the tool's to 1000 to be killed after it.
4. **File-level gaps are common; run stops were not.** On the 18 gate repositories, tools could not read some files in 6: Bandit syntax errors in Juice Shop (2 of 3 files), the FastAPI template (1 of 43) and Black (18 of 447); Checkov parse errors in kubernetes/examples (1), awesome-compose (2) and firebase (5). No memory kill and no refused process in any of the 18 repository scans or the 4 Juice Shop scans.
5. **The kernel's memory peak counts file cache.** Trivy's database download sat at its 2 GiB limit in every run while the program used 36 MB.
6. **Gitleaks 8.30.1 skips files at its default log level without a word.** A planted token was found only in a plain-text file: it was missed in a zip and a `.gz` file (archive depth 0 by default), in a binary file and behind a symlink. `.tgz` is never extracted at any depth.
7. **SiegeKit's script reader drops template literals that hold `${…}`** (`internal/coderoutes/jsroutes.go` stores them as an empty token), so it misses Juice Shop's search route, `${this.hostServer}/rest/products/search?q=${t}`, the one route where ZAP finds the SQL injection without a recording.

## Decision

1. **Two kinds of gap (Q1 A).** A run cut short (memory kill, refused process, a time cap reached, the target stopped answering, ZAP or Nuclei below 100%) fails the check with exit 4, findings kept, with a typed reason. Files or rules a tool could not read are named in `report.json` (`gaps`, each with a typed cause) and in the summary, and the exit code is unchanged; `--require-complete` turns them into exit 4. A check whose tool leaves no signal to compare is `ran` with a completeness field saying "not proven complete", on every run. gosec's skipped packages stay `failed` as decided in ADR 0040 and 0066, and so do files a root run cannot read (PR #21).
2. **The kernel counters are read by the waiter (Q2 A).** It runs the tool, raises the tool's OOM score to 1000, samples program memory (`anon` in `memory.stat`) every 0.2 s, and reads the refused-process and memory-kill counters (cgroup v1 and v2) after the tool exits. When the waiter itself is killed the report says exit 137 without naming memory.
3. **Gitleaks opens archives and names what it skips (Q3 A).** `--max-archive-depth 2` and debug log level; the debug lines name every binary, symlink, empty and allowlisted file skipped, and hold fingerprints only, never secrets. Skipped binaries are named as not checked; `.tgz` files are named as binary. Trace level is never used (its lines hold secrets in clear).
4. **ZAP's passive cap of 10 alerts a rule is removed (Q4 A)** (`maxAlertsPerRule` in `plugins/zap/plugin.json`). ZAP's other caps stay; reaching one is a run cut short (decision 1).
5. **Limits come from measured program peaks (Q5 A).** The waiter records each check's program-memory and process peaks. A gate fails when a check passes 80% of its limit. Each limit is 1.5 times its highest gate peak; with today's peaks Nuclei moves from 2.0 to 2.2 GiB and nothing else changes. The 80% and 1.5 are policy, not measurements.
6. **Rules not run are named where the tool can (Q6 A).** ZAP's statistics name each rule skipped or never started; Schemathesis gives skipped operations with reasons; Nuclei gives a count only. The "Not tested by SiegeKit" list moves into `report.json` as well as the HTML.
7. **One shared URL list for both ZAP checks (Q7 A).** The script reader keeps each piece of a template literal; the list keeps GET paths and leaves out those ADR 0048's action-word rule skips (`authz.ActionReason`). Both `zap` and `zap-active` get it when no recording is given. Juice Shop's search route is its known answer.
8. **Each check's signal** is as in the design's table: Bandit's metrics and errors; Checkov's `parsing_errors` from a second JSON output; a Trivy signal to be measured against the broken-lockfile test (a lockfile with no result is not one, see Unverified); the Gitleaks history commit count as a backstop; Nuclei's `-stats -sj` final line and its unresponsive-target line; Schemathesis's operation counts; ffuf's request count against the wordlist; ZAP's statistics; and every cap in SiegeKit's own checks, typed.

## Build plan

Five PRs, in order:

1. The waiter (counters and program-memory peaks) on both engines; typed run stops (exit 4); named file gaps and `--require-complete`; the output-limit reason shown; the 14 kinds of caps in SiegeKit's own checks reported. Also checks the waiter's counters inside the ZAP, Checkov, Schemathesis and ffuf images.
2. Tool signals (decision 8), Gitleaks archive depth and debug-log skips, the passive cap removed.
3. Limits from peaks (decision 5).
4. Rules not run (decision 6) and "Not tested by SiegeKit" in `report.json`.
5. The script reader fix and the shared URL list (decision 7).

## Evidence

CI run 45469559561 (round 2: SiegeKit scanning the 18 gate repositories and Juice Shop on rootless Podman and Docker, `ubuntu-latest` and `ubuntu-24.04-arm`, cgroup v2); local runs on Docker 29.9.3 rootful, cgroup v1, ZAP 2.17.0, Juice Shop v20.4.0. Every number is in the record.

| Claim | Backed by |
|---|---|
| File gaps on 6 of 18 repositories, no run stops | Round 2 CI: Bandit `errors` and metrics against `.py` files on disk, Checkov `parsing_errors`, `memory.events` and `pids.events` for every scan |
| The waiter sees every refused process and memory kill | Round 1 CI: counters or exit 137 in every run, both engines, both CPU types, cgroup v1 and v2; host poll 0 of 18; `inspect` missed a kill on Podman 4.9.3 |
| The waiter starts the other tools | Round 2 CI: ZAP, Checkov, Schemathesis and ffuf images, exit 0 on both engines and CPU types |
| Gitleaks skips archives, binaries and symlinks; depth 2 opens zip and `.gz` | Local fixture with a planted token in each; Juice Shop's source 11.2 s against 11.9 s, 75 findings both; no token in info or debug logs (4 runs); Gitleaks 8.30.1 source |
| Removing the passive cap | Through SiegeKit, 2 runs each: Juice Shop 33 to 235 findings, 94 requests both, 38 to 40 s, `report.json` 53 KB to 306 KB; Gitea 66 to 82 findings, 43 requests, 42 s |
| Program peaks (anon) | Podman amd64 and Docker arm64: Nuclei 1.44 GB of 2 GiB (70%), gosec 1.30 GB (63%), zap-active 1.26 GB (61%), Checkov 542 MB (102 of 256 processes), Schemathesis 385 MB of 1 GiB, Bandit 126 MB, Trivy 105 MB, Gitleaks 91 MB, ffuf 11 MB, relay 17 MB of 64 MB |
| Nuclei names no failing template | `-tl`, `-validate`, `-v`, `-debug` list 11,032 templates and name none, both engines and CPU types |
| The shared list finds Juice Shop's SQL injection | Prototype reader: Juice Shop 107 paths, 15 skipped by the action-word rule (including `/rest/user/change-password?current=` and `/rest/saveLoginIp`), 92 kept; Gitea 63 to 49. Through SiegeKit's sandbox (`zap-active`): Juice Shop 3,443 requests in 179 s with no 40018, against 21,095 in 565 s with 40018 on `/rest/products/search?q=`; Gitea 8,714 in 129 s against 15,224 in 201 s |

## Consequences

- Every run cut short now fails, on every check, including SiegeKit's own caps. CI stays green when a few files could not be parsed unless `--require-complete` is set; those files are named on every run.
- Reports get larger: Juice Shop's passive findings grow sevenfold.
- Scans without a recording take longer: about 6.4 minutes on Juice Shop and 72 s on Gitea. On Gitea the list is mostly paths with no attack finding.
- Gitleaks takes about 0.7 s more on Juice Shop's source.
- `report.json` gains `gaps`, a completeness field and the "Not tested" list. These are new fields, so `schemaVersion` stays 1.

## Unverified

- Peaks were read from Podman amd64 and Docker arm64 only; the other two setups ran green, but their logs were not read.
- The waiter's counters inside the ZAP, Checkov, Schemathesis and ffuf images: only that the tool starts is verified. Build PR 1 checks them.
- The kernel's memory `max` event stayed 0 even while Trivy sat at its limit. The cause is unknown, so the design does not use that counter.
- A precise Trivy signal. All 5 lockfiles with no result on the gate repositories had no pinned packages, so "no result" is not a drop. Build PR 2 measures one against the broken-lockfile test.
- Gitleaks archive scanning in history mode (its source applies the same setting) and `.tgz` files, which are never opened.
- The URL list on other frameworks; Memos was not run again.
- Counters on macOS (Colima) and on a real Apple-chip Mac: measured on Linux only.
- The Gitleaks history count on Juice Shop is 0.1% below the nearest count from git, so it is a backstop only.
- A Kubernetes YAML file Checkov cannot parse leaves no trace, so YAML-based frameworks stay "not proven complete".

## Build PR 1 (#85)

Where the build differs from the decision above, or settles what it left open, and why:

- **The waiter is embedded, not SiegeKit's own binary.** SiegeKit's own binary cannot be the waiter on macOS (a Mach-O program does not run in a Linux container) or when it is built with cgo (today's default `go build`, measured: dynamically linked), so the waiter is a separate static program (`cmd/siegekit-waiter`, 2.8 MB for amd64, 2.7 MB for arm64) embedded in SiegeKit (`internal/waiterbin`). `TestEmbeddedMatchesSource` builds it again from source with Go 1.27.4 in every CI job, macOS included, and fails if a byte differs; two builds from different folders and caches gave the same bytes. The owner's card on this choice is pending; the PR goes ahead with the recommended option.
- **The tool's OOM score is raised before the tool starts.** The waiter starts itself again as a shim that writes 1000 to its own `oom_score_adj` and then becomes the tool, so no process of the tool is ever created with the engine's score.
- **The waiter checks it reads its own cgroup.** It reads the counters of the cgroup whose `cgroup.procs` lists it (cgroup v2: the path in `/proc/self/cgroup`; v1: the `memory` and `pids` mounts), so a parent or host cgroup is never read.
- **The status file is created before the tool starts**, and rewritten through the waiter's handle after the tool exits, so a tool cannot put one there first (a container test writes a forged one; its values are replaced). SiegeKit reads it without following links, at most 64 KiB, as strict JSON with nothing after it (fuzzed); any missing, unreadable or incomplete counter fails the check as `counters-unread`.
- **Process counts include threads.** The kernel's process limit counts threads, so `usage.processPeak` does too. The waiter runs Go on one processor; with it, a container running `sh` and `sleep` peaked at 10.
- **A stop is the sandbox's last output line**, so every caller that shows the last line (data updates, the module download) now says why, including the output limit that was hidden before (record item 14).
- **Run stops typed in this PR:** `time-limit`, `memory-kill`, `process-limit`, `killed`, `output-limit`, `counters-unread`, `target-stopped` (SiegeKit's proxy) and `file-limit` (SiegeKit's own checks over 200,000 entries). The tools' own caps (ZAP, Nuclei) are typed in build PR 2.
- **SiegeKit's own repository checks name their gaps:** text files over 1 MiB (`too-large`) and folders deeper than 40 levels (`too-deep`) for `backend-rules`, `weak-passwords`, `dotenv-gitignore` (including an ignore file too large to read) and the `--source` reader. A large file whose first 8,000 bytes hold a NUL byte (git's test for binary files) is not named: these checks look for text, and naming every large image would hide the files that matter. Dependency and version-control folders (`.git`, `node_modules`, `vendor`, `.venv`, `venv`, `__pycache__`) are left out by design and named in "Not tested by SiegeKit" instead of as gaps, so `--require-complete` stays usable on any JavaScript or Go repository. These checks are `complete` when they name no gap.
- **`dotenv-gitignore` on a folder with no `.git` is skipped** (`no-files`), not reported as ran with nothing found.
- **The root-only list of unreadable files** (PR #21) no longer drops its 200,000-entry cap silently: past it every check the list affects fails, as when the list cannot be made. The count of ignore comments past the cap is a gap.
- **The caps of SiegeKit's URL checks get their own PR** right after this one (served-secrets, public-maps, backend-live, storage-write, access-control's 2 MiB answers, rate-limit, zap-active's recordings over 100; coordinator, 2026-11-24, as recommended), after its order with the Porchlet fix plan's PR C, which changes served-secrets, is agreed. Until then they are counted in each check's `result` as today, not typed.

## Alternatives considered

- **Q1 B, every gap fails with exit 4.** It fails 6 of the 18 gate repositories and every URL scan (Nuclei's 262 templates) on every run. Rejected.
- **Q1 C, a new status `incomplete`.** It gives the same coverage as A or B but needs schemaVersion 2 for every report reader. Rejected.
- **Q1 D, gaps as info findings with exit 0.** Cut-short scans would stay green. Rejected.
- **Q2 B, the waiter plus keeping the container until `inspect` is read.** It adds "killed for memory" on Docker and Podman 5.7, but not on Podman 4.9.3, and leaves containers behind if SiegeKit is killed. Rejected.
- **Q2 C, polling from the host, or Q2 D, `inspect` alone.** These missed events (see Context, point 3). Rejected.
- **Q3 B, "not proven complete".** Archive secrets would stay missed in silence. Rejected.
- **Q3 C, counting files from the trace log.** It is exact, but its lines hold secrets in clear. Rejected.
- **Q4 B, keep the cap and name each rule at it as a gap.** Three rules on Juice Shop hit it on every run. Rejected.
- **Q5 B, hand-set limits.** Reaching one is a run cut short, with no warning before people hit it. Rejected. The kernel's peak (`memory.peak`) is also rejected as the measure, because it counts file cache.
- **Q6 B, counts only.** Rejected.
- **Q7 B, spider only.** It finds no attack finding on Juice Shop without a recording. Rejected.
