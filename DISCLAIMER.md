# Disclaimer and authorized use

> This document is a template prepared without legal review. It is not legal advice. Have a qualified lawyer review it before the 1.0 release.

## Authorized use only

SiegeKit sends real attack traffic in its active tests. Use it only against systems that you own, or that you have explicit written permission from the owner to test. Unauthorized testing of computer systems is illegal in many countries (for example under computer-misuse or unauthorized-access laws) and can also breach hosting providers' terms of service.

You are solely responsible for:

- making sure you have authorization for every target you test;
- complying with the laws that apply to you and to the target's location;
- complying with your hosting or cloud provider's penetration-testing policy;
- any damage, data loss, downtime or cost that your tests cause, including to your own systems.

SiegeKit's ownership check (see [ADR 0005](docs/adr/0005-target-authorization.md)) is a safety aid against mistakes. Passing it is not legal permission, and failing to trigger it does not make a test lawful.

## Testing deployed systems

Active tests can change or delete data, fill logs, trigger alerts, lock accounts or slow a service down, even with SiegeKit's safe defaults. Prefer a staging copy. Back up data before testing production, and tell anyone who operates or monitors the system before you start.

## No warranty

SiegeKit is provided "as is", without warranties or conditions of any kind, as stated in sections 7 ("Disclaimer of Warranty") and 8 ("Limitation of Liability") of the [Apache License 2.0](LICENSE), which governs your use of SiegeKit's code. This document does not change or add to that license.

A scan that reports no findings does not mean the target is secure. Security tools miss vulnerabilities, report false positives, and only test what they are configured to test.

## Third-party tools

SiegeKit downloads and runs third-party tools under their own licenses ([THIRD_PARTY.md](THIRD_PARTY.md)). Your use of each tool is also governed by its license.

## Privacy

SiegeKit collects no telemetry. Findings, logs and reports stay on your machine unless you share them. Reports may contain sensitive information about your systems; store and share them with care.
