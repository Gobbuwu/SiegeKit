# 0029. Choosing checks by family and profile

- Status: Accepted
- Date: 2026-11-20
- Amends: [0004](0004-plugin-manifest.md) (selection on the command line)

## Context

ADR 0004 showed `--only sast,secrets` and `--profile full` but did not define them; until now `--only` and `--skip` took plugin IDs only. The owner approved both for M2.5 (re-check follow-up 1, 2026-11-19) and chose the profile names on 2026-11-20: `quick` and `full`, with `full` the default. Measured costs of the URL checks that `quick` leaves out: ZAP's attack scan is limited to 30 minutes (`maxScanDurationInMins`), Nuclei's intrusive run sent about 1,000 requests on the test app, and Schemathesis has a 15-minute timeout (ADR 0028).

## Decision

1. **Families.** `--only` and `--skip` take plugin and check IDs and family names (`sast`, `sca`, `secrets`, `iac`, `dast`, and the families reserved for later milestones). A family stands for every plugin and built-in check of that family. A name that is neither, or a family with nothing for the target (such as `--only secrets` on a URL), is an error, so a typo never drops a check silently. No plugin or check may be named like a family (a test checks the built-ins).
2. **Profiles.** `--profile full` (the default) runs every selected check. `--profile quick` leaves out the destructive plugins, which today are the URL attack tests `zap-active`, `nuclei-intrusive` and `schemathesis`. They are reported as skipped with the reason, so the report shows what was not tested. Directory scans have no destructive plugins, so `quick` changes nothing there. `--only` naming a plugin that the profile leaves out is an error.

## Consequences

- `--profile quick` on a local URL loses ZAP's injection, cross-site scripting and path traversal tests, Nuclei's intrusive templates (such as PUT uploads) and Schemathesis's API tests, in exchange for up to about 45 minutes less run time (30 for ZAP's attack scan and 15 for Schemathesis, at their limits). It also asks no confirmation, since nothing that can change data runs.
- Deployed targets already skip the destructive plugins (ADR 0025), so `quick` and `full` behave the same there.

## Alternatives considered

- Only `--only` by family now, profiles in M5 once check times are measured: offered to the owner, not chosen.
- `full` as the only profile: offered, not chosen; it would add nothing over the default.
