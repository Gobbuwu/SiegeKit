# Standards mapping

How SiegeKit's planned checks map to four widely used lists. "Auto" means a planned plugin targets it; "Partial" means automated checks find some cases but a human review is still needed; "Manual" means not automated (see the [pre-deploy checklist](pre-deploy-checklist.md)). Checked 2026-11-18 against the sources listed at the end. On 2026-11-19 Semgrep was replaced by Opengrep (M2) in the plans, and this page was updated to match.

## OWASP Top 10 (2025)

| Item | Coverage | How |
| --- | --- | --- |
| A01 Broken Access Control | Partial | `access-control`: a browser recording replayed as a second account and with no login (M2.7a, [ADR 0035](adr/0035-access-control-replay.md)); `access-control-write`: its writes replayed the same way on local targets ([ADR 0049](adr/0049-write-replay.md)); `backend-live`: Supabase tables and Realtime Database paths readable with the project's public key (M2.7c, [ADR 0037](adr/0037-backend-live-check.md)); `storage-write`: Firebase and Supabase Storage buckets anyone can upload to, on local targets ([ADR 0058](adr/0058-storage-write-test.md)); see [coverage](coverage.md) for what it misses |
| A02 Security Misconfiguration | Auto | Checkov (IaC); ZAP, Nuclei (headers, CORS, exposed files); backend-rules checks (ADR 0011) |
| A03 Software Supply Chain Failures | Auto | OSV-Scanner (whether it flags known malicious packages is to be confirmed in M2, where it was moved), Grype, Trivy, Syft SBOM |
| A04 Cryptographic Failures | Partial | Opengrep weak-crypto rules; ZAP and Nuclei TLS and cookie checks; offline hash audit (M3) |
| A05 Injection | Auto | Opengrep, Bandit, gosec; ZAP, Nuclei, sqlmap |
| A06 Insecure Design | Manual | Threat modelling and design review |
| A07 Authentication Failures | Partial | Login throttling, password spraying past a per-account lockout and second-factor code limits ([ADR 0055](adr/0055-rate-limit-pages.md)), default credentials ([ADR 0010](adr/0010-login-checks.md)); ZAP session checks |
| A08 Software or Data Integrity Failures | Partial | Opengrep (unsafe deserialization); SCA |
| A09 Security Logging and Alerting Failures | Manual | Checklist item 7 |
| A10 Mishandling of Exceptional Conditions | Auto | Schemathesis (error leakage, crashes); fuzzers (M3) |

## OWASP API Security Top 10 (2023)

| Item | Coverage | How |
| --- | --- | --- |
| API1 Broken Object Level Authorization | Partial | `access-control`, recorded requests replayed as a second account (ADR 0035); `access-control-write`, recorded writes, local targets (ADR 0049) |
| API2 Broken Authentication | Partial | `access-control` and `access-control-write` with no login (ADR 0035, 0049), login throttling (ADR 0030), spraying and code limits (ADR 0055) |
| API3 Broken Object Property Level Authorization | Partial | Differential test compares returned fields; mass-assignment remains manual |
| API4 Unrestricted Resource Consumption | Partial | `rate-limit`: capped burst to one URL the user names, local targets (ADR 0011, 0036); no load testing by design |
| API5 Broken Function Level Authorization | Partial | `access-control` with two accounts of different roles (ADR 0035; GET and HEAD only; writes with `access-control-write` on local targets, ADR 0049) |
| API6 Unrestricted Access to Sensitive Business Workflows | Manual | Business logic |
| API7 Server Side Request Forgery | Auto | Opengrep; ZAP, Nuclei |
| API8 Security Misconfiguration | Auto | As A02 |
| API9 Improper Inventory Management | Partial | ffuf and Nuclei find undocumented and old endpoints; compared with the OpenAPI spec |
| API10 Unsafe Consumption of APIs | Partial | Opengrep rules on how third-party API responses are used |

## CWE Top 25 (2025)

| CWEs | Coverage | How |
| --- | --- | --- |
| 79 XSS, 89 SQL injection, 78/77 command injection, 94 code injection, 22 path traversal, 918 SSRF, 502 deserialization, 20 input validation | Auto | SAST (Opengrep, Bandit, gosec) and DAST (ZAP, Nuclei, sqlmap) |
| 352 CSRF | Auto | ZAP |
| 434 Unrestricted file upload | Partial | Opengrep rules; ZAP upload checks where forms are found |
| 862, 863, 284, 639 authorization; 306 missing authentication | Partial | Authorization differential test and unauthenticated route check (ADR 0011); `backend-live` for Supabase tables and Realtime Database paths (ADR 0037); `storage-write` for storage buckets anyone can upload to (ADR 0058) |
| 200 Sensitive information exposure | Auto | Secrets scanning in code and git history (M1) and served content (M2); container images not scheduled; ZAP |
| 770 No resource limits | Partial | `rate-limit` (`rate-not-limited`, ADR 0011, 0036) |
| 799 Improper control of interaction frequency | Partial | `reset-limit` (`reset-not-limited`), `signup-limit` (`signup-not-limited`), local targets (ADR 0055) |
| 787, 416, 125, 120, 476, 121, 122 memory-safety bugs | Auto (fuzzing) | AFL++, libFuzzer-based fuzzers, Go fuzzing (M3); only for code with a harness |

## OWASP Top 10 for LLM Applications (2025)

| Item | Coverage | How |
| --- | --- | --- |
| LLM01 Prompt Injection | Partial | garak or promptfoo probes (ADR 0011, optional, M3) |
| LLM02 Sensitive Information Disclosure | Partial | Probes; AI keys found by Gitleaks |
| LLM03 Supply Chain | Partial | SCA on AI libraries; model files not scanned |
| LLM04 Data and Model Poisoning | Manual | Not in scope |
| LLM05 Improper Output Handling | Auto | Static rules for model output reaching eval, shell, SQL or HTML |
| LLM06 Excessive Agency | Manual | Design review of what tools the model can call |
| LLM07 System Prompt Leakage | Partial | Probes |
| LLM08 Vector and Embedding Weaknesses | Manual | Not in scope |
| LLM09 Misinformation | Manual | Not in scope |
| LLM10 Unbounded Consumption | Partial | `rate-limit` on an AI endpoint the user names, if it answers without a login (ADR 0036) |

## Sources

- OWASP Top 10 2025 names: [Qualys summary](https://blog.qualys.com/qualys-insights/2026/06/15/what-changed-in-owasp-top-10-2025-and-recommendations-for-each-category) (official list at owasp.org/Top10/2025/ not fetched)
- [CWE Top 25 (2025), MITRE](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- OWASP API Security Top 10 2023 names: [Veracode summary](https://www.veracode.com/blog/breaking-down-owasp-top-10-api-security-risks-2023-what-changed-2019/); no newer edition found
- OWASP Top 10 for LLM Applications 2025 names: [HackerOne summary](https://www.hackerone.com/blog/owasp-top-10-llms-2025-how-genai-risks-are-evolving)
