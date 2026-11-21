# Using SiegeKit from an AI coding assistant

This guide is for AI coding assistants (Claude Code, Cursor, Copilot and others) that run SiegeKit for a person, and for that person. Print it at any time with `siegekit agents`.

SiegeKit runs security checks on code and apps the person owns. The person stays in charge. An assistant runs the scans, reads the results and fixes the code. Only the person can authorize a target or a download.

## Rules for assistants

1. **Only scan what the person owns or is authorized to test.** Scan their own project directory, or a URL they gave you for their own app. Never pick a target on your own.
2. **Ask before downloading.** Missing tool images, tool files and data can take gigabytes. Run without `--yes` first: with no terminal, nothing is installed, and the affected checks are reported as skipped. Tell the person what is missing and how big it is. Pass `--yes` only after they say yes, or use `--no-install`.
3. **Never confirm a target for the person.**
   - A private network address (for example `192.168.x.x` or `nas.lan`) needs the host name typed in a terminal. In a terminal you cannot answer, `--authorized-host HOST` does the same, but use it only when the person told you, in this conversation, to scan that exact host.
   - A deployed (public) target with `--deployed` always needs the person to type the host name in their own terminal. SiegeKit refuses `--authorized-host` and runs without a terminal for deployed targets. Ask the person to run that command themselves.
   - Never answer a question SiegeKit asks a person: never pipe or type answers into it, and never run it inside `script`, `expect`, `unbuffer` or any other program that gives it a terminal. That is confirming for the person, even though SiegeKit cannot tell.
4. **Proof of control is the person's step.** For `--deployed`, SiegeKit prints a token to publish on the site or in DNS. Help publish it only when the person asks you to, and only for a host they told you they control. Never publish it on a host they did not name.
5. **Do not edit SiegeKit's own data.** Leave `~/.local/share/siegekit` (tokens, the audit log, saved runs, tool data and downloaded tool files) alone.
6. **Never say the app is "secure".** No findings means the checks that ran found nothing. Tell the person which checks ran and which were skipped. Also point them to the "Not tested" list in `report.html` and the pre-deploy checklist (`docs/pre-deploy-checklist.md` in the SiegeKit repository).

## Commands

```sh
siegekit scan DIR                  # passive checks of a source directory (no network)
siegekit scan --only gitleaks DIR  # selected checks or families (--only secrets,dast); --skip a,b leaves some out
siegekit scan --profile quick URL  # no attack tests (zap-active, nuclei-intrusive, nuclei-default-login, schemathesis, login-throttle, rate-limit); full is the default
siegekit scan http://localhost:3000   # a running app: target rules first, then ZAP web tests
siegekit update                    # refresh vulnerability data (network; asks first)
siegekit plugins list              # checks and pinned tool versions
siegekit agents                    # this guide
```

Useful scan flags:
- `--report-dir DIR`: where reports go; the default is `./siegekit-report`.
- `--fail-on LEVEL`: the lowest severity that gives exit code 3; the default is `high`.
- `--no-save`: do not keep a copy of the run.
- `--no-install`: install nothing.
- `--yes`: install missing dependencies without asking, only after the person agrees.
- `--require-all`: treat checks skipped for a missing or declined dependency (`cause` `missing-dependency` or `declined`) as an incomplete run. Checks left out by the mode, the profile, a missing input or the target's files do not count.
- `--login-url URL`, `--login-user NAME`, `--login-body TEMPLATE`: a login for the login throttling check, all three together. Use only a test account the person gave you for this; the check can lock it.
- `--login-attempts N`: how many wrong-password logins it sends, from 2 to 50 (default 20).

`siegekit scan -h` lists them all.

A URL scan sends real requests to the app. It first prints the plan (target, mode, addresses, checks and limits), records the run in SiegeKit's audit log, and sends one GET to check that the app answers. If it does not, nothing else is sent and the exit code is 1. These checks run:
- `zap` crawls the app and reports what ZAP's passive rules see, such as missing security headers and cookie flags.
- `nuclei` runs Nuclei's templates for known vulnerabilities, exposed files (such as `/.git/config` and `/.env`), admin panels and misconfigurations: about 10,000 requests, on every target.
- `ffuf` asks for common paths that should not be public (backups, `.git`, `.env`, admin pages) with GET requests and reports each one the app answers: about 4,760 requests on local targets, about 215 on every other target.
- `zap-active` sends attack payloads (SQL injection, cross-site scripting, path traversal) that can change data. It runs only on local targets: this machine, or a private address the person confirmed. On `--deployed` targets it is skipped. On this machine it runs only after the person types `yes` in a terminal, or with `--authorized-host HOST` (the target's host); `--yes` does not count. Without either, it is reported as skipped. Pass `--authorized-host` only when the person told you, in this conversation, to run the attack scan on that app. ZAP's crawler never sends XML or JSON bodies, so zap-active also attacks the requests in the person's `--har` recording (every GET, HEAD, POST, PUT, PATCH and DELETE to the target, at most 100): that is how XML external entities (XXE) and flaws in recorded writes such as a JSON login are tested. ZAP attacks them with that recording's session, so they are sent only after the person types `test accounts` (see `access-control`); `plugins[].input` says how many it got.
- `nuclei-intrusive` runs Nuclei's intrusive templates, such as uploading a file with PUT. It follows the same rules as `zap-active`.
- `nuclei-default-login` tries the factory logins that vendors document for their products, such as `tomcat:tomcat` on a Tomcat manager page, each once (PeopleSoft's on each of 20 paths): 337 templates, about 950 requests. A login can lock an account, so it follows the same rules as `zap-active`.
- `schemathesis` sends requests generated from the API's OpenAPI or Swagger 2.0 spec, including invalid input and POST, PUT and DELETE requests, and reports server errors and answers that differ from the spec. It follows the same rules as `zap-active`. It needs a spec: pass `--openapi FILE` (or a URL on the target's own origin, without a query), or SiegeKit uses the first valid spec at 11 common paths, such as `/openapi.json` and swagger-ui-express's `/api-docs/swagger-ui-init.js` (the paths `public-maps` tries). Without a spec it is skipped; `plugins[].input` in `report.json` names the spec it used.
- `login-throttle` is SiegeKit's own check of whether the app limits failed logins. It needs a test account the person owns and its login: `--login-url http://localhost:3000/rest/user/login --login-user test@example.com --login-body '{"email":"{user}","password":"{password}"}'`. The body is JSON if it starts with `{`, otherwise a form such as `username={user}&password={password}`. SiegeKit sends 20 POST logins (or `--login-attempts N`, at most 50), one per second, each with a new random wrong password, and stops at the first sign of a limit (a 429, 423 or 503, a `Retry-After` header, a changed status, a lockout or CAPTCHA message, or a much slower answer). No limit is a medium finding, `login-not-limited`. It sends these requests itself from this machine to the target's address, not through the proxy, and follows the same rules as `zap-active`, because it can lock the account. Without the three flags it is skipped. `plugins[].result` says what it saw. Never use a real person's account, and never put a real password in the body: SiegeKit fills in `{password}` itself.
- `rate-limit` is SiegeKit's own check of whether the app limits requests to one URL the person names, such as a search, a report or an AI call: `--rate-limit-url 'http://localhost:3000/rest/products/search?q=apple'` (a query is allowed). The URL must answer without a login. It is a GET, or a POST with `--rate-limit-body BODY` (JSON if it starts with `{` or `[`, otherwise a form). SiegeKit sends 20 requests (or `--rate-limit-requests N`, at most 50), one per second, and stops at the first sign of a limit: a 429 or 503, a `Retry-After` header, or a `RateLimit`, `RateLimit-*` or `X-RateLimit-*` header, even on the first answer. No limit is a low finding, `rate-not-limited`. Local targets only, left out by `--profile quick`; a POST follows the same rules as `zap-active` (confirmation on loopback), a GET needs none. Without `--rate-limit-url` it is skipped. A first answer of 401 or 403 (login needed), 404, 405 or a server error makes the check fail with the reason. Check that the URL is the one the person meant: an app that answers every page with 200 also shows no limit at a mistyped URL.
- `served-secrets` is SiegeKit's own check for keys in what the site serves. It sends GET requests for the start page and the same-origin scripts, styles, JSON files and source maps the page links, plus `<file>.map` for scripts and styles that name no source map (at most 200 requests, 10 MiB each), then runs Gitleaks over them. Findings are located at the file's URL. It runs on every target, `--deployed` and `--profile quick` included, because it only reads. `plugins[].result` says how many files it scanned and how many it left out.
- `public-maps` is SiegeKit's own check for "attack maps" anyone can download: an OpenAPI or Swagger spec, and source maps. It sends one GET to each of 11 common spec paths (including the spec inside a Swagger UI page at `/api-docs/`), and checks the source maps of the scripts and styles the start page links, including `<file>.map` when a file names none (shared with `served-secrets`). Each one served is a low finding, `public-api-spec` or `public-source-map`. A public API may publish its spec on purpose: ask the person. It runs on every target, `--deployed` and `--profile quick` included, because it only reads.
- `access-control` is SiegeKit's own check of whether one account can read another's data. It needs two test accounts the person owns. The person records a HAR file in their browser while using the app as account A (browser developer tools, Network tab, "Save all as HAR"), and gives account B's session headers in the environment variable `SIEGEKIT_SESSION_B`, one `Name: value` per line, such as `Authorization: Bearer ...` and `Cookie: ...` (every header the app uses for its session). Then `--har a.har`, and `--har-user A_LOGIN_NAME` to also report A's data readable with no login. SiegeKit replays the HAR's GET and HEAD requests (at most 100, static files left out), plus OpenAPI GET routes without path parameters, as A, as B and with no login: at most 300 requests, GET and HEAD only, on every target, `--deployed` and `--profile quick` included. B getting A's exact answer, with data, while no login is refused is `cross-account-read`: high when the URL holds an ID or the answer holds A's login name, otherwise medium. No login getting A's answer with A's login name is `no-login-read` (medium: public pages name their authors by design). A no-login JSON answer with a field named like a password, hash, secret, key or token that holds a value is `no-login-secret` (high). Medium findings were mostly false alarms when measured: tell the person to check each one by hand before acting on it. Before replaying anything, SiegeKit asks the person to type `test accounts` in a terminal to confirm both accounts are test accounts they own; no flag skips this, so ask the person to run the command themselves, and never type it for them. Without that, it is skipped (`cause` `not-confirmed`). Without `--har` it is skipped; without `SIEGEKIT_SESSION_B` only no login is tested. A HAR file holds A's session: never ask for a real person's recording, and tell the person to delete the file afterwards. `plugins[].result` says how many requests were replayed and why others were not.
- `access-control-write` is SiegeKit's own check of whether one account can change or delete another's data. It is off unless the person asks for it with `--replay-writes` (with `--har`, and `SIEGEKIT_SESSION_B` for account B), runs only on local targets and is left out of `--profile quick`. It replays the recording's POST, PUT, PATCH and DELETE requests (at most 50) as account B and with no login, each on a fresh copy of A's object that A creates again first and deletes afterwards, and also tries the PUT, PATCH and DELETE requests the recording did not make on objects A read or made (at most 50); before a POST on an object A prepared with earlier writes (a checkout after adding basket items), A sends those writes again. It tests only what the recording did: ask the person to record every kind of change the app has (create, edit and delete each kind of object, send each form, finish a purchase); login, logout, sign-up, password, second-factor, token, key and session writes and account deletes are never replayed, nor are GraphQL queries (only mutations). It changes data in the app for real: tell the person to use a throwaway database or a snapshot. After `test accounts`, SiegeKit lists every write and asks the person to type `change test data`; no flag skips this, so ask the person to run the command themselves and never type it for them; otherwise it is skipped (`cause` `not-confirmed`). `cross-account-write` (B) and `no-login-write` are high when A's own read of the same URL changed after a PUT, PATCH or DELETE, otherwise medium: tell the person to check medium findings by hand. `plugins[].result` lists every accepted write, the copies made and deleted, and the writes not replayed, so the person knows what to reset.
- `backend-live` is SiegeKit's own check of whether the app's Supabase tables or Firebase Realtime Database paths can be read by anyone who loads the app. Pass `--backend-url https://PROJECT.supabase.co` (or `https://DB.firebaseio.com`, or a local stack such as `http://127.0.0.1:54321`). It reads table names from `.from('...')` calls and paths from `ref('...')` in the scripts the start page links, plus, with `--source DIR` (the app's repository, read locally), tables created in `supabase/` migrations and paths in `database.rules.json`; `--source` also gives Schemathesis an OpenAPI file when the app serves none. It sends one GET per name (at most 200), asking for at most one row, with the app's own public key (Supabase anon or publishable key; never a service-role key) or no login (Firebase). A table that returns a row, or a path that returns data, is a high finding (`supabase-table-readable`, `firebase-rtdb-readable`) that names the columns or counts the keys, never values. A backend that is not on this machine must appear in the app's scripts, and the person must type its host name in their own terminal: no flag skips this, so ask the person to run the command. It only reads, so it runs on every target. Without `--backend-url` it is skipped. A table meant to be public, such as a product list, is also reported: ask the person whether it should be.

Every request from the tools goes through SiegeKit's egress proxy, which allows only the target's own address and labels the traffic `SiegeKit/<version>`. SiegeKit's own requests (the first GET, the spec lookup, `login-throttle`, `rate-limit`, `served-secrets`, `public-maps` and `access-control`) go straight to the same pinned address with the same label; `backend-live` goes to the backend's own pinned addresses, after the confirmation above. On `--deployed` targets it also allows only GET and HEAD requests, so no check can change data there. Web tests run only on Linux for now; elsewhere the run is reported as incomplete. Scan a URL only when the person asked for that app to be tested, and prefer a local or staging copy.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on` |
| 3 | Findings at or above `--fail-on` |
| 4 | Incomplete: a check failed or timed out, or did only part of its work, such as gosec skipping Go packages whose modules are not in the repository (their findings are kept; the check's `reason` names what was left out). With `--require-all`, also a check skipped for a missing dependency |
| 1 | Error, or the target was refused |
| 2 | Usage error |

Exit code 3 wins over 4, so always read `report.json` too.

## Reading the results

Each scan writes `report.json`, `report.sarif` (SARIF 2.1.0) and `report.html` to the report directory. Read `report.json`. Its format version is `schemaVersion`, currently 1. New fields can appear without a version change, and a field is removed or changes meaning only with a new version.

Top level:
- `schemaVersion`, `siegekitVersion`, `target`, `mode`, `started`, `finished`.
- `environment`: where the run happened: `os`, `arch`, `go` (the Go release SiegeKit was built with; tools in images bring their own), and `engine` (`name` docker or podman, `version`, `rootless`, `cgroup` v1 or v2), absent when no engine answered. Results from one engine or cgroup version do not carry over to another (ADR 0038); say which one a result came from when you report it. `SIEGEKIT_ENGINE=docker` or `podman` picks the engine when both are installed (Podman otherwise); never change it to make a check pass.
- `plugins`: one entry per check, with `id`, `family`, `tool`, `version`, `status` (`ran`, `skipped`, `failed` or `timed-out`), `reason` (why it was skipped or failed, for people; its wording can change), `cause` and `findings` (a count). When the scanned repository told the tool to ignore something, three more fields say so, and are left out when there is nothing to report:
  - `suppressed`: how many findings the tool left out because of comments in the code, such as `# nosec` or `checkov:skip=`, where the tool reports this.
  - `repoSettings`: the repository's own settings files that the tool obeyed, such as `.gitleaksignore`, `.gitleaks.toml`, `.bandit` or `.checkov.yaml`. They can hide findings without a count.
  - `ignoreMarkers`: how many lines carry the tool's ignore comment (`gitleaks:allow`), counted by SiegeKit outside dependency directories, for tools that do not report what they suppressed.
  - `cause`: why a check did not run, as a fixed word to decide on instead of the wording of `reason` (ADR 0041). Every `skipped` check has one, and a `failed` check that never started can have one:
    - `missing-dependency`: the container engine, an image, a file or data is not installed (`--no-install`, or no terminal to ask in), or could not be installed. Ask the person whether to install it.
    - `declined`: the person said no to installing it.
    - `no-files`: the target has nothing the check reads, such as gosec on a repository without Go code, or no git history for `gitleaks-history`. Nothing to do.
    - `deployed-or-local-only`: the check does not run in this mode, such as `zap-active` on a `--deployed` target.
    - `profile`: `--profile quick` leaves it out.
    - `no-input`: it needs something that was not given or not found: a login, a URL, a HAR file, a backend URL or an OpenAPI spec. `reason` names the flag.
    - `not-confirmed`: it needs a person's confirmation, which was not given. Never confirm it yourself; ask the person to run the command in their terminal.
    - `platform`: it does not run on this operating system or architecture.
    - `unsupported`: the check's kind does not fit this target; a SiegeKit bug, please report it.
  `--require-all` counts only `missing-dependency` and `declined`. A skipped check with no valid cause is reported as `failed` (a SiegeKit bug).

  URL scans add these, also left out when zero or empty:
  - `requests`: how many requests the target answered through the egress proxy. A check with none is reported as `failed`, because it tested nothing.
  - `refused`: how many requests and connections the proxy blocked: those to another host, address or port, and on `--deployed` targets any method other than GET and HEAD.
  - `refusedTo`: what was blocked, such as `CONNECT other.example:443` or `POST app.example (only GET and HEAD)`, each once, at most 20.
  - `input`: what the check tested from besides the target, such as `OpenAPI spec http://localhost:3000/openapi.json` for `schemathesis`, `POST http://localhost:3000/rest/user/login as "test@example.com"` for `login-throttle`, or `the start page http://localhost:3000/ and the files it links` for `served-secrets`. Absent for other checks.
  - `result`: what a check saw when that is not a finding, such as `limited after 6 of 20 attempts: answered 429` for `login-throttle`, or `scanned 9 file(s): 1 page, 7 scripts, 1 style` for `served-secrets`. Absent for other checks.
- `findings`: the deduplicated findings, most severe first.
- `comparison`: present when a saved run of the same `target` exists (runs are saved unless `--no-save` is given). It compares this run with the most recent one:
  - `previousRun`, `previousStarted`, `previousVersion`: that run's ID, start time and SiegeKit version. If the version differs, some changes may come from the upgrade.
  - `new`: the `fingerprint` of each finding in this run that the previous run did not report.
  - `fixed`: findings the previous run reported that are gone, and whose check ran to completion in this run.
  - `notRechecked`: findings the previous run reported that are gone, but whose check did not complete in this run. Do not treat these as fixed.
  - `stillPresent`: how many findings both runs reported.

Each finding:
- `ruleId`, `title`, `message`.
- `severity`: `critical`, `high`, `medium`, `low` or `info`.
- `cwes`: for example `CWE-89`.
- `location`: `uri`, the file path relative to the scanned directory, and `startLine`. For URL scans, `uri` is the page's URL.
- `snippet`: the code at that line. Secrets are masked.
- `family`: `secrets`, `sast`, `sca`, `iac` or `dast` (web tests).
- `sources`: which `plugin` and `ruleId` reported it. One finding can come from several tools.
- `confidence`: when the tool gives one.
- `helpUri`: the tool's page about the rule, when it has one. It explains the issue and the fix.
- `fingerprint`: a stable ID for the same issue across runs. Use it to check that a fix removed the finding.

## A fix loop that works

1. Run `siegekit scan DIR --no-save`.
2. Check `plugins`. Report any check that was skipped or failed, with its `reason`, instead of treating the run as clean.
3. Fix the findings, most severe first. Read `helpUri` when it is set. Make the smallest change that removes the cause, and keep the app working.
4. Scan again and compare fingerprints. A finding that is gone was fixed. A new one may come from your change.
5. Tell the person what you changed, what is still open, and what SiegeKit does not test.

Do not silence a finding by deleting the check, adding a suppression comment or ignore file, or moving the code out of the scanned directory, unless the person agrees that it is a false positive. SiegeKit obeys such suppressions but counts them in `report.json`, so tell the person about any `suppressed`, `repoSettings` or `ignoreMarkers` you see.
