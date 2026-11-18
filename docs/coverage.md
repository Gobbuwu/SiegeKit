# What SiegeKit checks

Each row is a common security concern, the plugins planned to check it, and the milestone that delivers it. "Manual" rows are not automated; see the [pre-deploy checklist](pre-deploy-checklist.md). Tools are listed in [THIRD_PARTY.md](../THIRD_PARTY.md).

| Concern | Checked by | Milestone |
| --- | --- | --- |
| API keys, tokens, private keys in source code and **git history** | Gitleaks; TruffleHog (optional) | M1 |
| Secrets inside container images | Trivy | M1 |
| Secrets exposed by a running site (JS bundles, public `.env`, `.git/`, backups) | Gitleaks on crawled content; Nuclei exposure templates; ffuf | M2 ([ADR 0010](adr/0010-login-checks.md)) |
| Outdated libraries with known vulnerabilities | OSV-Scanner, Grype, Trivy | M1 |
| Outdated container base images and OS packages | Trivy, Grype | M1 |
| Software inventory (what versions you ship) | Syft (SBOM) | M1 |
| Old or forgotten endpoints, backup and leftover files, directory listings | ffuf, Nuclei, Nikto (optional) | M2 |
| Exposed admin pages and dashboards | Nuclei panel templates, ffuf, ZAP spider | M2 |
| Default vendor logins left enabled | Nuclei default-login templates, local mode only | M2 ([ADR 0010](adr/0010-login-checks.md)) |
| No limit on failed login attempts | Login throttling check on your own test account | M2 ([ADR 0010](adr/0010-login-checks.md)) |
| Session cookie flags, security headers, TLS settings | ZAP, Nuclei | M2 |
| Injection (SQL, command, template), XSS, SSRF patterns | Semgrep, Bandit, gosec (code); ZAP, Nuclei, sqlmap (running app) | M1 code, M2 running app |
| Known CVEs in deployed software | Nuclei CVE templates | M2 |
| API endpoints that crash or leak errors on bad input | Schemathesis | M2 |
| Misconfigured Dockerfiles, Kubernetes, Terraform | Checkov, Trivy, Hadolint (optional) | M1 |
| Crashes and memory bugs on malformed input | Go fuzzing, Atheris, cargo-fuzz, AFL++ (optional) | M3 |
| Weak password hashes in data you supply | hashcat (GPU), John the Ripper (CPU), offline only | M3 |
| One user reading or changing another user's data | Manual | n/a |
| Business-logic flaws (skipping steps, price tampering) | Manual | n/a |
| Cloud account settings (buckets, IAM, firewalls) | Manual (not in scope for 1.0) | n/a |
| Password guessing against live logins | Not provided, by design | n/a |

Not yet decided: whether to flag runtimes and frameworks that are past end-of-life even without a known vulnerability. To be evaluated in M1, including the license of any end-of-life dataset used.
