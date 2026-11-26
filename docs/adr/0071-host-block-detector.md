# 0071. Stop a check when the host stops serving the app (host-blocked)

- Status: Accepted (owner, 2026-11-25 05:14Z: "D1+D3 with F2" on the decision card in "Plan fixes for Porchlet R1p bugs")
- Date: 2026-11-25
- Amends: [0067](0067-checks-finish-or-say-so.md) decision 1 (a new run stop, `host-blocked`), [0018](0018-egress-proxy.md) (the proxy also stops on it), [0007](0007-findings-format.md) (findings carry the answers they were read from, unsaved)
- Related: issue [#86](https://github.com/Gobbuwu/SiegeKit/issues/86) (`from-porchlet`), ADR [0070](0070-extra-headers.md), threat model T32

## Context

On Porchlet's R1p run (2026-11-25) Vercel's Security Checkpoint started answering every request with one 403 page of about 25 KB partway through the scan. ffuf and Nuclei reported "ran", ffuf with every guessed path as a finding and Nuclei with the page's Astro markup as `tech: astro`. Reproduced through SiegeKit on a stand-in and on Juice Shop behind a block switch, on rootless Podman and Docker, amd64 and arm64 (CI runs 45529252929, 45537954705, 45544252358; record `siegekit/porchlet-r1p-fix-plan-2026-11-25/` in the project files): without a fix, ffuf "ran" with 3,779 block-page findings and exit 0, and access-control "ran" and silently lost a finding.

Root cause: the egress proxy's only "the target is unhealthy" signal was 5xx or no connection, so a 403, a 429 or a 200 challenge page counted as healthy, and nothing compared the target's answers during a run with its answers at the start. ADR 0067 named "the target stopped answering" as a run stop, not "the target kept answering with something other than the app". Fixing it per tool (ffuf's calibration, Nuclei's templates) would leave ZAP, Schemathesis and SiegeKit's own checks open, so the fix is one detector that sees every request of every URL check.

Options, all measured through SiegeKit on the four Linux setups (macOS Intel with Colima runs no URL check, ADR 0018, so the block cannot happen there):

| | Blocked answers before the stop | Extra requests per full scan | False stops (Juice Shop, Gitea, Next.js-like, full scans) |
|---|---|---|---|
| D1 start page before and after each check | after the check (misses a block that ends inside it) | 1 per check | 0 |
| D2 start page every 50 requests | 13 to 35 | 323 (2%) | 0 |
| D3 start page when 10 answers in a row share a shape | 9 to 19 (misses a block in a check's last answers) | 2 to 5 | 0 |
| D4 50 answers of 403 or 429 in a row | 50 to 129; never stops ZAP | 0 | 0 |

Findings reported before the stop: F1 keep all (ADR 0067's rule) left block-page findings on Podman, where ffuf writes its report when stopped; F3 drop all lost real findings (1 to 7 per case); F2 drop the findings read from answers like the block page kept every real finding and dropped every block-page finding in every case where the finding showed its answer.

## Decision

1. **One watch per run, on the target's start page** (`egress.Watch`). Each check is a unit (`Watch.Begin`, `Unit.End`): every plugin, and SiegeKit's own spec probe, start-page fetch (served-secrets, backend-live, storage, public-maps), access-control and access-control-write. The proxy and `egress.Send` show the unit every answer.
2. **D1:** the start page is fetched when a check begins and, unless the check already stopped, when it ends. The run's first fetch is the reference. A check whose start page has another status than the reference, or cannot be fetched, is not run (before) or is stopped (after).
3. **D3:** when 10 answers in a row have one shape (status, media type, length within 5%), the start page is fetched once for that shape; if it now has the same shape and the reference did not, the check stops. The proxy stops forwarding (the tool's container is stopped as for the 5xx rule) and `Send` returns `egress.BlockedError` without sending.
4. **The stop is typed `host-blocked`**, failing the check (exit 4 unless findings decide the exit, ADR 0009), with what was seen in the reason: "the host stopped serving the app: 10 answers in a row and the start page were the same page, 403 (text/html, 24983 bytes); at the run's first check the start page answered 200".
5. **F2:** of a stopped check's findings, those read from any answer with the block page's status and a length within 5% of it are dropped and counted in the reason; the rest are kept. Findings carry the answers they were read from (`findings.Finding.Answers`, not saved): ffuf gives its result's status and length, access-control and access-control-write give the answers they compared, and served-secrets gives the file's answer (200 and its length).

### Build decisions (this PR)

- **The reference is the run's first start page, not each check's own.** In the measured full scans the detector ran in shadow mode, and with a per-check reference a check that starts while the block goes on takes the block page as its reference: in B6 Nuclei then "ran" with the block page's `metatag-cms`. With the run's reference, every check after a stop that still finds the block sends nothing, and one that finds the app again runs (gate job `block`, cases A and B).
- **The throttle checks** (login-throttle, login-spray, rate-limit, reset, sign-up and code pages) get only the fetch before them. They stop at the first changed answer and report it as the limit, so a host's block during them is their result (a sprayer from one address is stopped by it too), and an app-wide limit would otherwise fail a check that measured it correctly. Started while the host blocks, they would read the block page as every answer and report "no limit", so they are not run then.
- **Access-control's findings carry their answers.** The first local run of the gate's case C kept a finding the block made: `/rest/memories/`'s request with no login got the block page, so the read looked refused and the no-login secret became a cross-account read. With the answers attached, F2 drops it and keeps the 4 reads found before the block (the web job's known 4).
- **Answers are measured as they stream to the tool**, not buffered: the prototype read up to 2 MiB of every answer before forwarding it, which would hold back a streamed answer (a test streams one).
- **backend-live and storage are not run** when the host blocked while the app's start page and scripts were fetched: their input (the scripts' backend URL and key) may be the host's page, and the storage test writes data.
- **SiegeKit's own checks end at the refusal.** The spec probe, the start-page fetch, access-control and access-control-write stop at the first `BlockedError` and keep what they read before it; the watch's `End` then reports the block. Found by the owner's review: they went on through every remaining request, each refused after its paced wait (on a deployed target at 10 requests a second, up to about 200 s of waiting in access-control). Tests in authz, served, publicmaps and the CLI fail without this.
- **Tools' requests go to the host without `Accept-Encoding`.** The proxy measures an answer as it streams, compressed if the host compressed it, while the start-page fetch reads it uncompressed, so a compressed block page never matched and D3 never fired (a test with a gzipping host and Go's client, which asks for gzip by itself as ffuf and Nuclei do, failed before this). Two options were measured through SiegeKit on the gate's `block` job (Juice Shop behind a host that gzips, rootless Podman and Docker, amd64 and arm64, Go 1.27.4, 2026-11-26; runs [45719371632](https://github.com/Gobbuwu/SiegeKit/actions/runs/45719371632) and [45725310823](https://github.com/Gobbuwu/SiegeKit/actions/runs/45725310823)):
  - *Strip* (chosen): the proxy removes `Accept-Encoding`, so answers come uncompressed to both. A block from ffuf's 1,000th request stops ffuf after exactly 10 block pages with 4 start-page fetches, and F2 drops every block-page finding (0 kept; on Podman, which writes ffuf's report on a stop, ffuf kept 7 real findings). Cost: about 164 MB on the wire for ffuf, Nuclei and ZAP on Juice Shop with no block, 232 to 250 s.
  - *Match*: keep the tools' `Accept-Encoding` and fetch the start page in the encoding of the answers it is compared with. It stops ffuf at the same point, but F2 then compares the compressed length the proxy recorded with the decompressed length ffuf reports (the cause read from the code, not traced in a run), so on Podman 10 block-page findings were kept (17 findings, 10 from the block page). It costs about 58 MB on the wire (2.8 times fewer bytes) and was 10 to 15% faster (201 to 232 s).
  - Both: no false stop on any of the 120 (match) and 124 (strip) gate jobs; the same requests (ffuf 4,758, Nuclei about 11,410 to 11,430, ZAP 94), 9 to 10 start-page fetches, and the same findings (ffuf 20, Nuclei 12, ZAP 33; once ZAP 34 under match on Podman arm64, rule 10038 counted 12 times instead of 11, not traced). Strip keeps F2 correct for every tool that decompresses; match would need a second length per answer to do that. The tools see the same content either way.
- **The start-page fetch** carries `SIEGEKIT_EXTRA_HEADERS` (ADR 0070), so a preview behind its host's login is not taken for a block, and its User-Agent ends in "(start page check)". Start-page fetches are not counted in a check's requests.

## Measured (this PR, through SiegeKit)

- Locally, Docker 29.9.3 rootful, cgroup v1, linux/amd64, Go 1.27.4, Juice Shop v20.4.0 behind `.github/gate/block`, 2026-11-25:
  - Block from ffuf's 1,000th request, `--only ffuf,public-maps,zap`: ffuf failed `host-blocked` after 10 block pages, no finding kept (Docker writes no ffuf report on a stop); ZAP not run ("before this check"); public-maps ran with its finding; 8 start-page fetches in all; exit 4.
  - The same block, ending after ffuf's stop: ffuf failed `host-blocked`; ZAP ran on the app (94 requests, 33 findings, none from the block page).
  - Block from SiegeKit's 55th own request (access-control's last answers): access-control failed `host-blocked` by D1, 45 requests, 3 got the block page, F2 dropped 1 and kept 4 cross-account reads (without a block: 5 findings, the 4 plus `no-login-secret`).
- Gate job `block` runs these three cases on rootless Podman and Docker, amd64 and arm64, with Nuclei in place of ZAP. Every other gate job scans with the detector on and must meet its known answers: the false-stop check on Juice Shop, Gitea, the Next.js login app, Mailpit and the storage backends. Results on head 55f1fe5: CI run 45648414828 and gate run 45648414966 green, job `block` on all four setups; on rootless Podman ffuf writes its report when stopped, and F2 dropped its 10 block-page findings and kept 7 real ones.
- On Vercel (owner, Porchlet's protected preview with the bypass header, WSL Docker rootful, cgroup v2, amd64, 2026-11-25): two scans of about 10.7k requests with no block had no false stop. With Vercel's Attack Challenge Mode switched on while Nuclei ran, Nuclei stopped `host-blocked` after 1,980 requests on "403 (text/html, 25144 bytes)", with no finding from the challenge page, exit 4. During the mode a request with the bypass header got Vercel's 429 challenge page, so the header does not get past it.
- Unit tests: shapes and the 5% margin; D1 before, after and on an unreachable start page; D3 on `Send` (stops at exactly 10 block pages, sends nothing after) and on the proxy (forwards exactly 10, refuses the rest, 3 start-page fetches); 40 not-found pages cost one fetch and no stop; a block that ends lets the next check run; a streamed answer is not held back; the start-page fetch carries the extra headers; RunURL for a proxy stop, a D1 stop and a D1 stop after a time limit (F2 drops 2 of 4 ffuf findings, the next plugin is not run); SiegeKit's own checks through the CLI (start-page fetch, spec probe, rate-limit before, access-control after); F2 on access-control's answers.

## Consequences

- A scan that hits a block page ends with the checks it affected failed, `stop: host-blocked`, and only findings read from the app.
- Each check costs one or two start-page fetches, plus one per new repeated answer shape (2 to 5 per full scan, measured).
- Gaps:
  - A block or login wall from the first request: the reference is already the block page, so nothing changes (recorded for its own fix; in deployed mode the proof-of-control check usually refuses first).
  - Nuclei's and ZAP's findings carry no answer. When D1 stops them after they finished (a block in their last 9 answers), F2 cannot tell their block-page findings apart, and they are kept; the check is still failed.
  - A block that starts and ends inside one check in fewer than 10 answers is not seen.
  - A real answer with the block page's status and a length within 5% of it is dropped from a stopped check.
  - An app-wide limit that a throttle check triggers fails every later check while it lasts, with the start page's answer in the reason.
  - Verified on Vercel's Attack Challenge Mode page, not on the Security Checkpoint starting on its own (it did not start in two runs of about 10.7k requests); both were a 403 of about 25 KB to SiegeKit.

## Alternatives considered

- D2 (every 50 requests): stops as fast as D3 but costs about 2% more requests on every scan.
- D4 (403/429 rule): never stopped ZAP, and needs 50 or more block pages.
- D1 or D3 alone: D3 misses a block in a check's last answers (access-control, measured), D1 alone misses one that ends before the check does.
- F1, F3: F1 keeps block-page findings on Podman only (engine-dependent false findings); F3 drops real ones.
- A per-check reference, as in the prototype: later checks take the block page for the app (see Build decisions).
- Measuring answers by buffering them: holds back streamed answers.
