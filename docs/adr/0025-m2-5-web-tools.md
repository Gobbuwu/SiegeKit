# 0025. Nuclei, ffuf and Schemathesis (M2.5)

- Status: Accepted
- Date: 2026-11-19
- Amends: [0023](0023-active-web-scans.md) (destructive plugins on deployed targets: no opt-in before M2.10)
- Amended by: [0026](0026-nuclei.md) (which templates each Nuclei plugin runs, measured request counts), [0028](0028-schemathesis.md) (how the OpenAPI spec is fetched and checked)

## Context

M2.5 adds three web tools behind the egress proxy and relay that ZAP uses (ADR 0019, 0023). The owner answered six design questions on 2026-11-19 ([design document](https://claude.ai/artifact/84fk3Qjt2mZhbDdBu9fxAg)): questions 1 to 5 as recommended, and option (b) for question 6. Questions 1 and 2 (pinned downloads, ffuf in the pinned Alpine image) are recorded in ADR 0024.

Facts checked on 2026-11-19, all MIT-licensed and at least 7 days old (ADR 0008): Nuclei 3.11.1 has an official image (`projectdiscovery/nuclei`) without templates, and fetches the latest templates itself unless given a folder; nuclei-templates v10.5.2 is a GitHub release; ffuf 2.3.0 has release binaries but no official image; Schemathesis 4.33.4 has an official image (`schemathesis/schemathesis`).

## Decision

1. **Nuclei, two plugins, like ZAP.**
   - `nuclei` runs on every target. It uses the pinned templates (ADR 0024), never fetches templates or update checks itself, excludes templates tagged `intrusive`, `dos`, `fuzz` or `dast`, and has out-of-band callbacks (OAST) off. On deployed targets the proxy allows it GET and HEAD only (ADR 0023).
   - `nuclei-intrusive` runs the excluded templates on local targets only, after the same confirmation as `zap-active`.
2. **ffuf wordlists.** Local targets get SecLists `Discovery/Web-Content/common.txt`, pinned to a commit (about 4,700 paths; its license is confirmed before pinning). Deployed targets get a list of about 200 paths that SiegeKit writes itself (backups, `.git`, `.env`, admin panels): at the deployed rate of 10 requests per second the long list would take about 8 minutes, the short one about 20 seconds.
3. **Deployed targets stay read-only until M2.10.** No `--allow-destructive` flag yet: destructive plugins run only on local targets, after confirmation. ADR 0023 said the flag would arrive with M2.5; it waits until M2.10 has measured request limits. The flag of ADR 0005 item 3 is unchanged in design, only later.
4. **Schemathesis and the OpenAPI spec.** Schemathesis sends POST, PUT and DELETE requests, so it is destructive and local only. A new flag `--openapi FILE_OR_URL` names the spec and always wins. Without it, SiegeKit sends one GET to each of a fixed list of default spec paths on the local target (such as `/openapi.json`, `/swagger.json`, `/v3/api-docs`) and uses the first valid spec. The report names the spec used, or the paths tried.

## Consequences

What these choices leave untested; each item goes into the report's "Not tested" list when it applies:

- Deployed targets get the short wordlist, so exposed files with other names are missed there.
- Nuclei templates that find blind flaws through an out-of-band callback (for example blind SSRF) cannot report. The egress proxy blocks such callbacks by design.
- Deployed targets get no attack tests from any M2.5 tool until M2.10.
- APIs with no spec given and none at the default paths are not tested by Schemathesis.

## Alternatives considered

- Letting Nuclei download the latest templates: not pinned (ADR 0008). Rejected.
- One long wordlist everywhere: about 8 minutes of requests against a deployed app. Rejected.
- `--allow-destructive` now: a second rule for deployed targets before request limits are measured. Rejected for now.
- `--openapi` only, no default paths: APIs whose user does not pass the flag would go untested even when the spec is at a standard address. Rejected.
