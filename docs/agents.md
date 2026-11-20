# Using SiegeKit from an AI coding assistant

This guide is for AI coding assistants (Claude Code, Cursor, Copilot and others) that run SiegeKit for a person, and for that person. Print it at any time with `siegekit agents`.

SiegeKit runs security checks on code and apps the person owns. The person stays in charge. An assistant runs the scans, reads the results and fixes the code. Only the person can authorize a target or a download.

## Rules for assistants

1. **Only scan what the person owns or is authorized to test.** Scan their own project directory, or a URL they gave you for their own app. Never pick a target on your own.
2. **Ask before downloading.** Missing tool images, tool files and data can take gigabytes. Run without `--yes` first: with no terminal, nothing is installed, and the affected checks are reported as skipped. Tell the person what is missing and how big it is. Pass `--yes` only after they say yes, or use `--no-install`.
3. **Never confirm a target for the person.**
   - A private network address (for example `192.168.x.x` or `nas.lan`) needs the host name typed in a terminal. In a terminal you cannot answer, `--authorized-host HOST` does the same, but use it only when the person told you, in this conversation, to scan that exact host.
   - A deployed (public) target with `--deployed` always needs the person to type the host name in their own terminal. SiegeKit refuses `--authorized-host` and runs without a terminal for deployed targets. Ask the person to run that command themselves.
4. **Proof of control is the person's step.** For `--deployed`, SiegeKit prints a token to publish on the site or in DNS. Help publish it only when the person asks you to, and only for a host they told you they control. Never publish it on a host they did not name.
5. **Do not edit SiegeKit's own data.** Leave `~/.local/share/siegekit` (tokens, the audit log, saved runs, tool data and downloaded tool files) alone.
6. **Never say the app is "secure".** No findings means the checks that ran found nothing. Tell the person which checks ran and which were skipped. Also point them to the "Not tested" list in `report.html` and the pre-deploy checklist (`docs/pre-deploy-checklist.md` in the SiegeKit repository).

## Commands

```sh
siegekit scan DIR                  # passive checks of a source directory (no network)
siegekit scan --only gitleaks DIR  # selected checks; --skip a,b leaves some out
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
- `--require-all`: treat checks skipped for a missing dependency as an incomplete run.

`siegekit scan -h` lists them all.

A URL scan sends real requests to the app. It first prints the plan (target, mode, addresses, checks and limits), records the run in SiegeKit's audit log, and sends one GET to check that the app answers. If it does not, nothing else is sent and the exit code is 1. These checks run:
- `zap` crawls the app and reports what ZAP's passive rules see, such as missing security headers and cookie flags.
- `nuclei` runs Nuclei's templates for known vulnerabilities, exposed files (such as `/.git/config` and `/.env`), admin panels and misconfigurations: about 10,000 requests, on every target.
- `ffuf` asks for common paths that should not be public (backups, `.git`, `.env`, admin pages) with GET requests and reports each one the app answers: about 4,760 requests on local targets, about 215 on every other target.
- `zap-active` sends attack payloads (SQL injection, cross-site scripting, path traversal) that can change data. It runs only on local targets: this machine, or a private address the person confirmed. On `--deployed` targets it is skipped. On this machine it runs only after the person types `yes` in a terminal, or with `--authorized-host HOST` (the target's host); `--yes` does not count. Without either, it is reported as skipped. Pass `--authorized-host` only when the person told you, in this conversation, to run the attack scan on that app.
- `nuclei-intrusive` runs Nuclei's intrusive templates, such as uploading a file with PUT. It follows the same rules as `zap-active`.

Every request goes through SiegeKit's egress proxy, which allows only the target's own address and labels the traffic `SiegeKit/<version>`. On `--deployed` targets it also allows only GET and HEAD requests, so no check can change data there. Web tests run only on Linux for now; elsewhere the run is reported as incomplete. Scan a URL only when the person asked for that app to be tested, and prefer a local or staging copy.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on` |
| 3 | Findings at or above `--fail-on` |
| 4 | Incomplete: a check failed or timed out (or, with `--require-all`, was skipped for a missing dependency) |
| 1 | Error, or the target was refused |
| 2 | Usage error |

Exit code 3 wins over 4, so always read `report.json` too.

## Reading the results

Each scan writes `report.json`, `report.sarif` (SARIF 2.1.0) and `report.html` to the report directory. Read `report.json`. Its format version is `schemaVersion`, currently 1. New fields can appear without a version change, and a field is removed or changes meaning only with a new version.

Top level:
- `schemaVersion`, `siegekitVersion`, `target`, `mode`, `started`, `finished`.
- `plugins`: one entry per check, with `id`, `family`, `tool`, `version`, `status` (`ran`, `skipped`, `failed` or `timed-out`), `reason` (why it was skipped or failed) and `findings` (a count). When the scanned repository told the tool to ignore something, three more fields say so, and are left out when there is nothing to report:
  - `suppressed`: how many findings the tool left out because of comments in the code, such as `# nosec` or `checkov:skip=`, where the tool reports this.
  - `repoSettings`: the repository's own settings files that the tool obeyed, such as `.gitleaksignore`, `.gitleaks.toml`, `.bandit` or `.checkov.yaml`. They can hide findings without a count.
  - `ignoreMarkers`: how many lines carry the tool's ignore comment (`gitleaks:allow`), counted by SiegeKit outside dependency directories, for tools that do not report what they suppressed.

  URL scans add two counts, also left out when zero:
  - `requests`: how many requests the target answered through the egress proxy. A check with none is reported as `failed`, because it tested nothing.
  - `refused`: how many requests and connections the proxy blocked: those to another host, address or port, and on `--deployed` targets any method other than GET and HEAD.
  - `refusedTo`: what was blocked, such as `CONNECT other.example:443` or `POST app.example (only GET and HEAD)`, each once, at most 20.
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
