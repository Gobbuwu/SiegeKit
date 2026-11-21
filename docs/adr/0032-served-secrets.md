# 0032. Secrets in served files

- Status: Accepted
- Date: 2026-11-20
- Amended by: [0046](0046-public-api-maps.md) (`<file>.map` is also tried for scripts and styles that name no source map)
- Amends: [0010](0010-login-checks.md) (how the served files are obtained)

## Context

ADR 0010 says that files fetched during the crawl are scanned with Gitleaks, using the same rules as the repository scan. ZAP's SARIF report lists only the URLs where an alert fired, not everything it crawled, and ZAP's spider misses pages that single-page apps build in JavaScript (M2.4). On 2026-11-20 the owner chose answer 5a of the M2.6 design ([design](https://claude.ai/artifact/62fVx5n5HBpLwfWXEwQ2mB)): "SiegeKit fetches the files itself: the start page, plus the same-origin scripts, styles, JSON and source maps it links, one level deep. That is at most 200 files of at most 10 MiB each, GET only, through the proxy. Gitleaks then reads them in its pinned image [...]. This works on deployed targets too, because it uses GET only."

Checked on 2026-11-20:

- **Gitleaks reads every file name.** The pinned Gitleaks 8.30.1 image found the same 2 planted keys in files named `.html`, `.js`, `.min.js`, `.js.map`, `.map`, `.css` and `.json`, so the names SiegeKit gives the fetched files do not hide any.
- **Juice Shop v20.4.0** (the CI gate's image): its start page links 1 stylesheet (twice), 4 `modulepreload` scripts and 3 scripts. The check fetched those 9 files with 9 requests in about 2 seconds, and Gitleaks reported nothing. None of the scripts names a source map. Scripts that `main.js` loads later are not linked from the page, so they were not fetched.

## Decision

1. **`served-secrets`** is SiegeKit's own check, in the `secrets` family, for URL targets. It runs on every target, `--deployed` included, and with `--profile quick`, because it sends only GET requests. Like the other URL checks, it runs only on Linux for now (ADR 0018).
2. **What is fetched.** SiegeKit sends a GET for the target URL (the start page) and reads it as HTML. It then fetches what the page links:
   - `<script src>`;
   - `<link href>` with `rel` `stylesheet`, `modulepreload` or `manifest`;
   - `<link href>` with `rel` `preload` or `prefetch` and `as` `script`, `style` or `fetch`.
   For each script and style it fetched, it also fetches the source map that the file names, in a `SourceMap` or `X-SourceMap` header or a `sourceMappingURL` comment. This is my reading of "source maps it links": pages rarely link source maps directly, so a script's map counts as part of the script. Only links on the target's origin are fetched (ADR 0005); others are counted. Links are not followed further.
3. **Limits.**
   - At most 200 requests are sent, counting redirects, and each answer can be at most 10 MiB.
   - Requests are sent one at a time, no faster than the mode's rate (100 per second on local targets, 10 on deployed ones).
   - A redirect is followed only on the same origin, at most 5 times.
   - A file whose answer is not 200 is counted and left out.
   - SiegeKit sends the requests itself, to the pinned addresses with the proxy's transport (`egress.Send`, as for the spec lookup of ADR 0028), on a read-only configuration.
   - The check fails, with the reason, only when the start page does not answer 200.
4. **How it is read.**
   - The files are written to a private temporary directory, which is removed after the run.
   - The `gitleaks` plugin runs over that directory exactly as in a directory scan: same pinned image, same arguments, no network.
   - Ignore notes inside the served files (`gitleaks:allow`) are obeyed and counted, as ADR 0020 does for repositories.
   - The Gitleaks image goes through the dependency consent of ADR 0016. If it is missing or declined, the check is skipped with the reason.
5. **Results.**
   - Each finding is placed at the URL of the file it was found in, without the query string. Its source names `served-secrets`, and its severity is high, as for every Gitleaks finding.
   - The message says which kind of file it was and that anyone who opens the site can read it.
   - The report's plugin entry names Gitleaks and its version. It also gives:
     - `input`: the start page;
     - `result`: for example `scanned 9 file(s): 1 page, 7 scripts, 1 style`, plus what was left out;
     - `requests`: the requests the target answered.
6. **Test app.** The test app's start page links `/static/app.js`, which holds a GitHub token and names `app.js.map`, which holds an AWS key. Both keys are built at run time, so the repository holds no real-looking secret. The container test must find both keys at their URLs. The CI gate expects `served-secrets` to run on Juice Shop and send requests.

## Consequences

- Keys in the scripts, styles and source maps a site serves are checked on every URL target, deployed ones included. This covers single-page apps, whose bundles ZAP's spider often misses.
- **Not covered:**
  - scripts loaded later by other scripts (lazy chunks, `import()`), and other pages;
  - files on other origins, such as CDNs;
  - inline `data:` source maps;
  - files larger than 10 MiB, and anything past 200 requests;
  - files that are only served after a login.
  The report's "Not tested" list says so.
- Only Gitleaks' rules are used, which look for random-looking keys. Weak passwords are not reported here.
- A URL scan sends up to 200 more GET requests. That took about 2 seconds on Juice Shop.

## Alternatives considered

- Using what ZAP crawled, if ZAP could export its crawl: not chosen (answer 5b). It also loses single-page-app files ZAP's spider misses.
- No check of served files: not chosen (answer 5c). Exposed files such as `/.env` would stay covered by Nuclei and ffuf, but keys inside served scripts would not be checked.
- Following script imports to more levels: not chosen. The owner's answer says one level deep, at most 200 files.
