# What SiegeKit checks

Each row is a common security concern, the plugins planned to check it, and the milestone that delivers it. Rows were checked against the code on 2026-11-19; M1 rows are what the current version runs. "Manual" rows are not automated; see the [pre-deploy checklist](pre-deploy-checklist.md). Tools are listed in [THIRD_PARTY.md](../THIRD_PARTY.md). For coverage against the OWASP and CWE lists, see [standards mapping](standards-mapping.md).

| Concern | Checked by | Milestone |
| --- | --- | --- |
| API keys, tokens, private keys in source code and **git history** | Gitleaks (files, M1); gitleaks-history (every commit on every branch, including secrets deleted later; added in M2 on 2026-11-19, because M1 scanned only the files); TruffleHog (optional) | M1, M2 |
| Environment files (`.env`, `.env.local` and similar) committed to git, or not excluded by `.gitignore` | gitleaks-history (committed in any commit); built-in `dotenv-gitignore` (not excluded, so `git add .` would commit it). Templates such as `.env.example` are allowed. Added at the owner's request on 2026-11-19. | M2 |
| Secrets inside container images | Trivy (needs container-image targets, which SiegeKit does not support yet) | Not scheduled |
| Secrets exposed by a running site (JS bundles, public `.env`, `.git/`, backups) | Gitleaks on crawled content; Nuclei exposure templates; ffuf | M2 ([ADR 0010](adr/0010-login-checks.md)) |
| Outdated libraries with known vulnerabilities | Trivy, from lock and manifest files (M1); OSV-Scanner, Grype (M2) | M1, M2 |
| Outdated container base images and OS packages | Trivy, Grype (needs container-image targets) | Not scheduled |
| Software inventory (what versions you ship) | Syft (SBOM) | M2 |
| Old or forgotten endpoints, backup and leftover files, directory listings | ffuf, Nuclei, Nikto (optional) | M2 |
| Exposed admin pages and dashboards | Nuclei panel templates, ffuf, ZAP spider | M2 |
| Default vendor logins left enabled | Nuclei default-login templates, local mode only | M2 ([ADR 0010](adr/0010-login-checks.md)) |
| No limit on failed login attempts | Login throttling check on your own test account | M2 ([ADR 0010](adr/0010-login-checks.md)) |
| Session cookie flags, security headers, TLS settings | ZAP, Nuclei | M2 |
| Injection (SQL, command, template), XSS, SSRF patterns | Bandit (Python) and gosec (Go) code, M1; Opengrep for other languages, M2; ZAP, Nuclei, sqlmap on the running app, M2 | M1, M2 |
| Known CVEs in deployed software | Nuclei CVE templates | M2 |
| API endpoints that crash or leak errors on bad input | Schemathesis | M2 |
| Misconfigured Dockerfiles, Kubernetes, Terraform | Checkov (M1); Hadolint (optional, not scheduled). Trivy runs only its dependency scanner. | M1 |
| Crashes and memory bugs on malformed input | Go fuzzing, Atheris, cargo-fuzz, AFL++ (optional) | M3 |
| Weak password hashes in data you supply | hashcat (GPU), John the Ripper (CPU), offline only | M3 |
| One user reading or changing another user's data (IDOR/BOLA), admin functions open to normal users | Authorization differential test with two test accounts; partial, heuristic | M2 ([ADR 0011](adr/0011-app-logic-and-ai-checks.md)) |
| API routes with no login required | Unauthenticated request to every discovered route | M2 (ADR 0011) |
| Supabase tables without row-level security, open Firebase rules | Static rules (M1); read-only live check with the app's public key (M2) | M1, M2 (ADR 0011) |
| Missing rate limits on expensive or AI endpoints | Capped rate-limit check | M2 (ADR 0011) |
| CORS misconfiguration, open redirects, CSRF, file-upload flaws, path traversal, SSRF | Bandit and gosec where they have rules (M1); Opengrep (M2); ZAP, Nuclei on the running app (M2) | M1, M2 |
| AI provider keys (OpenAI, Anthropic and others) in code or bundles | Gitleaks | M1, M2 |
| AI model output reaching eval, shell, SQL or HTML unescaped | Static rules | M3 (ADR 0011) |
| Prompt injection and system-prompt leakage in the app's AI features | garak or promptfoo, optional | M3 (ADR 0011) |
| Mass assignment, excessive AI agency, logging gaps | Manual | n/a |
| Business-logic flaws (skipping steps, price tampering) | Manual | n/a |
| Cloud account settings (buckets, IAM, firewalls) | Manual (not in scope for 1.0) | n/a |
| Password guessing against live logins | Not provided, by design | n/a |

Not yet decided: whether to flag runtimes and frameworks that are past end-of-life even without a known vulnerability. It was planned for evaluation in M1 but was not evaluated, and is still open (found in the re-check of 2026-11-19).
