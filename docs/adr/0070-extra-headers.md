# 0070. Extra request headers for previews behind their host's login (SIEGEKIT_EXTRA_HEADERS)

- Status: Accepted (owner, 2026-11-25 05:14Z: H1 on the decision card in "Plan fixes for Porchlet R1p bugs")
- Date: 2026-11-25
- Amends: [0005](0005-target-authorization.md) (the proof-of-control fetch sends the headers), [0018](0018-egress-proxy.md) (the egress proxy adds them)
- Related: issue [#87](https://github.com/Gobbuwu/SiegeKit/issues/87) (`from-porchlet`), [#86](https://github.com/Gobbuwu/SiegeKit/issues/86), ADR [0035](0035-access-control-replay.md), threat model T31

## Context

Vercel puts preview deployments behind Vercel Authentication by default: every request without a Vercel login gets a 302 to `vercel.com/sso-api`. Vercel's way through for automation is the "Protection Bypass for Automation" secret, sent as the `x-vercel-protection-bypass` header ([Vercel docs](https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/protection-bypass-automation): "available on all plans"). SiegeKit had no way to send it: the proxy set only `User-Agent`, `egress.SendHeader` took headers only from SiegeKit's own checks, and the proof fetch (`internal/verify`) built its own request. So `--deployed` could not even prove control (the well-known file answered 302), and Porchlet's R1p run had to switch the login off for every preview for about 30 minutes.

Options (measured through SiegeKit, CI runs 45529252929, 45537954705 and 45544252358, rootless Podman and Docker, amd64 and arm64, plus macOS Intel for the proof fetch; and on Porchlet's real protected Hobby preview, 2026-11-25; record in the project files, `siegekit/porchlet-r1p-fix-plan-2026-11-25/`):

- **H1**, generic headers from `SIEGEKIT_EXTRA_HEADERS`, one `Name: value` per line, as issue #87 suggested.
- **H2**, a Vercel-only variable holding just the secret.
- **H3**, Vercel's query-parameter form: not built, because the secret would be in every URL, report and tool log.

H1 and H2 behaved the same everywhere (proof fetch passed, every request carried the header, the secret in no report or log, identical check tables on the real preview). H1 also takes any other provider's bypass header (only Vercel's was tested). The real test found two things the prototype lacked: an empty paste sent no header silently, and the steps had no proof-file step.

## Decision

1. **`SIEGEKIT_EXTRA_HEADERS`**, read before any DNS lookup or request (`egress.ParseExtraHeaders`, `extraHeaders` in `cmd/siegekit`). Refused loudly, without quoting the text: a variable with no header, a line without `Name: value`, an invalid name, an empty value, a value under 8 characters (item 4), a control character, a name given twice; `Host`, `User-Agent`, `Content-Type`, `Content-Length`, `Accept-Encoding`, the hop-by-hop headers and every `Proxy-` header; `Cookie`, `Authorization` and the other headers the access-control check treats as a login (`authz.IsSessionHeader`: its list plus every header in `SIEGEKIT_SESSION_B` and `SIEGEKIT_SESSION_C`), because its requests with no login would be signed in and hide real findings; and plain `http://` with `--deployed`, where the value would cross the internet unencrypted.
2. **Sent on every request to the target's origin, never to another host.** `egress.Config.Header` is added by `Reachable`, `Send`/`SendHeader` (SiegeKit's own checks) and the host-side proxy (every tool, so the value never enters a tool container), and `verify.Checker.Check` takes it for the well-known-file fetch. It replaces a header of the same name set by a tool or a check. `--backend-url`, `--storage-url` and `--mail-catcher` are other hosts and never get it, even on the same origin.
3. **Never printed or logged.** The plan names the headers only; the audit entry gets `extraHeaders` with the names only.
4. **Hidden in every report.** An app that echoes request headers puts the value in tool output, so before the reports are written `report.Run.Hide` replaces every value in every exported string of the run (findings, snippets, reasons, results, gaps) with `[hidden: SIEGEKIT_EXTRA_HEADERS value]`; the JSON, SARIF and HTML reports, the terminal summary and the saved run all come from it. Because every value is hidden, a value under 8 characters is refused rather than hiding ordinary text everywhere.

## Measured (this PR, through SiegeKit)

- New gate job `headers`: the web job's Juice Shop v20.4.0 scan, every URL check that job runs (12 with requests), behind a stand-in for Vercel Authentication (`.github/gate/headers`: 302 without the header, the app with it), on rootless Podman and Docker, amd64 and arm64. It must meet the web job's known answers (`juice-shop-url.json`), no request may reach the stand-in without the header, and the secret (new each run) must be in no output, report, saved run or audit log. Results: in the PR and `docs/milestones/M2.md`.
- Unit tests: every refusal, with no value quoted; the header on the proxy, `Reachable`, `Send` and `SendHeader` paths (each one removed in turn makes the test fail) and replacing a tool's header; the proof fetch refused with a 302 without it and passing with it; `Run.Hide` over the three report formats; a CLI scan whose tool output echoes the secret: every check's config, the proof fetch, the plan line and the audit entry, and the value in no file of the report directory or the data directory and not in the terminal output.
- Local, Docker 29.9.3, linux/amd64: `public-maps` through the stand-in, 13 requests without the header (all 302) and 13 with it (all reached the app); the secret in no file.

## Consequences

- Porchlet's next round (R2) can scan a preview with Vercel Authentication on.
- The bypass header does not get past Vercel's Security Checkpoint (measured on Porchlet's preview), so a long deployed scan can still be cut short there: #86's detector is still needed.
- Gaps: a custom app-login header with another name is not detected; a value quoted by a tool in an encoded form is not hidden; a backend or storage on the target's own origin gets no header; only Vercel's bypass was tested.

## Alternatives considered

- H2 (Vercel-only variable): same results as H1 on every setup, but only one provider.
- H3 (query parameter and cookie): the secret would be in URLs, reports and tool logs.
- Adding the headers inside the tool containers: the value would enter every container and its logs; the host-side proxy adds it instead.
- Sending the headers to every host SiegeKit contacts (the prototype read them in the proxy package for any target): the bypass secret would go to Supabase backends and mail catchers.
