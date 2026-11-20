# 0026. Running Nuclei

- Status: Accepted
- Date: 2026-11-19
- Amends: [0004](0004-plugin-manifest.md) (placeholder `{target-base}`, parser `nuclei-jsonl`), [0018](0018-egress-proxy.md) and [0023](0023-active-web-scans.md) (what the connection limit counts), [0021](0021-built-in-relay.md) (relay connection limit), [0025](0025-m2-5-web-tools.md) (which templates each Nuclei plugin runs)
- Amended by: [0031](0031-default-logins.md) (default-login templates run in `nuclei-default-login`)

## Context

ADR 0025 placed Nuclei in two plugins. Building them (M2.5b) showed facts that ADR 0025 did not cover. All of them were measured on 2026-11-19 with the pinned image and templates against SiegeKit's test app and a counting test server.

- **Templates.** nuclei-templates publishes no release files, only its git tags, so the pin is GitHub's generated archive of tag `v10.5.2`: 10,105,056 bytes, SHA-256 `016b7abb…c574`. It was downloaded twice on a GitHub Actions runner with identical bytes (this development sandbox cannot download GitHub's generated archives). The archive holds regular files only.
- **Skip list.** Nuclei skips some templates by default through the file `.nuclei-ignore`, but it reads that file only from its own configuration folder, not from a template folder given with `-t`. In a container it is therefore not applied.
- **Size of a run.** The non-intrusive HTTP templates are about 9,600. One run sends about 10,500 to 10,900 requests: 2 to 4 minutes at the local rate of 100 per second, about 18 minutes at the deployed rate of 10 per second. Nuclei's tech-detection mode (`-as`) sent about 2,200 requests but found none of the 10 header issues the full set found.
- **Double slashes.** Nuclei appends paths to the target as given, so `http://host/` becomes `http://host//.env`. Servers that redirect such paths (Go's, for example) are never asked for `/.env`: the `.env` exposure was missed until the trailing slash was removed.
- **Results.** Nuclei's SARIF export gives every matcher of a template the same message (the ten missing security headers read alike) and no URL. Its JSON Lines output has the matcher, severity, CWE, URL and template link.
- **Memory.** `nuclei-intrusive` was killed at 1 GiB; with 2 GiB, Nuclei used at most about 900 MiB.
- **Exit code.** Nuclei exits 0 and writes an empty report even when the target cannot be reached. SiegeKit already fails a plugin that sent no request (ADR 0023).
- **Lost requests.** The first CI run missed the planted `.env` (template `laravel-env`) while `codeigniter-env`, which asks for the same path, found it; a later local run missed `codeigniter-env` instead. Cause, measured with a counter in the egress proxy: the proxy held one of its 16 connection slots for every open connection from the tool, idle keep-alive connections included, until its 60-second idle timeout. Nuclei opens more connections than that, so 779 new connections waited for a slot in one run, 16 of them over a second and the longest 27 seconds, past Nuclei's 10-second request timeout. Nuclei drops such a request without a warning (its output shows none). With the proxy no longer counting idle connections, the relay's limit of 64 open connections was hit next (it closes connections beyond it) and another template was missed; with the relay limit lifted for a measurement, Nuclei had at most 299 connections open, found every planted issue, and its run took 150 instead of about 250 seconds.
- **Template warnings.** Nuclei reports "262 templates with runtime error" with the pinned set; they are skipped. It also logs that it found no `.nuclei-ignore` (see the skip list above).

## Decision

1. **Every target gets the full non-intrusive set.** The owner chose this on 2026-11-19 after seeing the request counts above, over tech detection or local-only. Deployed targets still get only GET and HEAD requests through the proxy, at 10 per second, stopped after 10 server errors in a row.
2. **`nuclei`** runs `-pt http` templates, with out-of-band callbacks off (`-ni`) and no update checks (`-duc`), excluding the tags `intrusive`, `dos`, `fuzz`, `dast`, `local`, `bruteforce`, `txt-service` and `default-login`, and the six HTTP files on the publisher's skip list.
3. **`nuclei-intrusive`** runs the templates tagged `intrusive`, with the same exclusions otherwise. It is destructive and local-only (ADR 0023, 0025). Denial-of-service templates stay out because they can crash the app. Fuzzing and `dast` templates stay out because they need crawled URLs with parameters, which Nuclei does not get here. Default-login templates stay out until M2.6, which adds limits on login attempts (ADR 0010).
4. **Arguments.**
   - The target is passed as `{target-base}`, a new placeholder for URL plugins: the target URL without its trailing slash.
   - The relay is the proxy, with `-proxy` as well as the environment.
   - The request rate is `{ratelimit}`.
   - At most 8 templates run at once (`-c 8`).
5. **Results** are read from JSON Lines by a new parser, `nuclei-jsonl`. Results of one template at one URL become one finding that names each matcher. When `matched-at` is only `host:port`, the request URL is used instead. Extracted values are never copied into findings, because they can be secrets.
6. **Connection limit (amends ADR 0018 item 5, ADR 0021 item 1 and ADR 0023 item 5).** The limit of 16 (local) or 8 (deployed) connections now counts connections from the proxy to the target, which is what protects the target: at most that many requests are in flight. Idle connections from the tool no longer hold a slot. The relay's bound on the tool's open connections rises from 64 to 1,024, about three times the measured peak, and still protects SiegeKit's own process. The rate cap and the stop after server errors are unchanged.
7. **Resources:** 2 CPUs and 2 GiB. The timeout is 45 minutes for `nuclei` (the deployed run takes about 18) and 15 minutes for `nuclei-intrusive`.

## Consequences

Not tested, and stated in every report's "Not tested" list:
- Nuclei's TCP, DNS, SSL and JavaScript templates (about 490): they cannot pass the HTTP-only egress proxy. TLS settings are not checked.
- Templates that need out-of-band callbacks (blind SSRF and similar).
- 340 default-login templates (until M2.6), and the denial-of-service, fuzzing and brute-force templates. (ADR 0031: 338 HTTP template files carry the tag, and the M2.6b plugin `nuclei-default-login` runs 337 of them, as counted by Nuclei's own template list.)

Also:
- A deployed scan now takes about 18 minutes longer and sends about 10,500 more requests.
- The tech-detection template `waf-detect` reports "apachegeneric" for any app that sends an Apache `Server` header. It is an informational finding; the M2 result-quality triage counts such cases.
- Nuclei tries to look up the machine's public address (`checkip.amazonaws.com`). The proxy refuses it, and the report lists it under refused requests.

## Alternatives considered

- Tech detection (`-as`) on deployed targets: about 4 minutes, but it misses generic checks. The owner chose the full set.
- Reading Nuclei's SARIF export: it loses which header or cookie is affected and gives no URL.
- Copying `.nuclei-ignore` into Nuclei's configuration folder: that would need a shell in the container. The two short lists in the manifest do the same and are visible in review.
