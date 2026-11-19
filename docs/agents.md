# Using SiegeKit from an AI coding assistant

This guide is for AI coding assistants (Claude Code, Cursor, Copilot and others) that run SiegeKit for a person, and for that person. Print it at any time with `siegekit agents`.

SiegeKit runs security checks on code and apps the person owns. The person stays in charge. An assistant runs the scans, reads the results and fixes the code. Only the person can authorize a target or a download.

## Rules for assistants

1. **Only scan what the person owns or is authorized to test.** Scan their own project directory, or a URL they gave you for their own app. Never pick a target on your own.
2. **Ask before downloading.** Missing tool images and data can take gigabytes. Run without `--yes` first: with no terminal, nothing is installed, and the affected checks are reported as skipped. Tell the person what is missing and how big it is. Pass `--yes` only after they say yes, or use `--no-install`.
3. **Never confirm a target for the person.**
   - A private network address (for example `192.168.x.x` or `nas.lan`) needs the host name typed in a terminal. In a terminal you cannot answer, `--authorized-host HOST` does the same, but use it only when the person told you, in this conversation, to scan that exact host.
   - A deployed (public) target with `--deployed` always needs the person to type the host name in their own terminal. SiegeKit refuses `--authorized-host` and runs without a terminal for deployed targets. Ask the person to run that command themselves.
4. **Proof of control is the person's step.** For `--deployed`, SiegeKit prints a token to publish on the site or in DNS. Help publish it only when the person asks you to, and only for a host they told you they control. Never publish it on a host they did not name.
5. **Do not edit SiegeKit's own data.** Leave `~/.local/share/siegekit` (tokens, the audit log, saved runs and tool data) alone.
6. **Never say the app is "secure".** No findings means the checks that ran found nothing. Tell the person which checks ran and which were skipped. Also point them to the "Not tested" list in `report.html` and the pre-deploy checklist (`docs/pre-deploy-checklist.md` in the SiegeKit repository).

## Commands

```sh
siegekit scan DIR                  # passive checks of a source directory (no network)
siegekit scan --only gitleaks DIR  # selected checks; --skip a,b leaves some out
siegekit scan http://localhost:3000   # a URL target: checked against the target rules
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
- `findings`: the deduplicated findings, most severe first.

Each finding:
- `ruleId`, `title`, `message`.
- `severity`: `critical`, `high`, `medium`, `low` or `info`.
- `cwes`: for example `CWE-89`.
- `location`: `uri`, the file path relative to the scanned directory, and `startLine`.
- `snippet`: the code at that line. Secrets are masked.
- `family`: `secrets`, `sast`, `sca` or `iac`.
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
