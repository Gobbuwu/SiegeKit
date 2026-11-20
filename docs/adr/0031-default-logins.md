# 0031. Default credentials with Nuclei

- Status: Accepted
- Date: 2026-11-20
- Amends: [0010](0010-login-checks.md) (which templates run; one exception to one attempt per credential), [0026](0026-nuclei.md) (default-login templates now run, in their own plugin), [0029](0029-check-selection.md) (what `--profile quick` leaves out)

## Context

ADR 0010 adds a check for vendor default credentials with Nuclei's default-login templates, on local targets only, with one attempt per credential. ADR 0026 kept those templates out of both Nuclei plugins until M2.6. On 2026-11-20 the owner chose to run all HTTP default-login templates in a new destructive, local-only plugin ([design](https://claude.ai/artifact/62fVx5n5HBpLwfWXEwQ2mB), answer 4a).

Facts checked on 2026-11-20 with the pinned Nuclei 3.11.1 image and nuclei-templates v10.5.2 (ADR 0026):

- **Templates.** 338 HTTP template files carry the tag `default-login`. ADR 0026 says 340; that count is not reproduced here. 2 of the 338 are also tagged `fuzz`, which the publisher's `.nuclei-ignore` skips by default:
  - `http/fuzzing/wordpress-weak-credentials.yaml` tries 11 user names against 23 passwords from word lists. That is password guessing, which ADR 0010 rules out.
  - `http/default-logins/oracle/peoplesoft-default-login.yaml` tries 10 PeopleSoft factory logins on each of 20 paths.
- **Template list.** With `-tags default-login -etags dos,fuzz,dast,local,bruteforce,txt-service`, Nuclei's own template list (`-tl`) loads 336 templates. Adding `-it` for the PeopleSoft file loads 337, and WordPress stays out.
- **Requests.** Each template's `max-request` metadata adds up to about 950 requests for the 337 templates. Against the test app, the plugin sent 631 requests with 336 templates and 831 with 337, in about 16 seconds. The proxy refused one request, a `CONNECT` for the target's own host on an http target (seen before, M2 record F11).
- **Retries.** Nuclei retries a failed request once by default (`-retries`, default 1). A failed request is one with no answer.

## Decision

1. **`nuclei-default-login`** runs the pinned Nuclei image and templates with `-tags default-login`, excluding `dos`, `fuzz`, `dast`, `local`, `bruteforce` and `txt-service`. It also excludes the publisher's skip list (ADR 0026), and adds back only the PeopleSoft template with `-it`. That gives 337 templates. The PeopleSoft template is added back by the owner's decision of 2026-11-20 ("we never know who's gonna be using siegekit"). The WordPress template stays out.
2. **One attempt per credential.** `-retries 0`, so no login is sent twice. Each template lists each credential once. **The exception** is the PeopleSoft template: it sends each of its 10 credentials to each of 20 paths, so one PeopleSoft server can see up to 20 attempts per account. The owner accepted this.
3. **Where it runs.** It is destructive, because a login can lock an account: local targets only, after the confirmation ADR 0023 asks for (a typed `yes` or `--authorized-host` on loopback). `--profile quick` leaves it out. It is never run on deployed targets. Only HTTP templates run (`-pt http`, as in ADR 0026), so the 13 non-HTTP default-login templates (SSH, databases and similar) stay out.
4. **Results** come from the `nuclei-jsonl` parser, with Nuclei's own severities, as for the other Nuclei plugins. A finding names the template (its rule ID, such as `tomcat-default-login`) and the URL; the template file lists the credentials it tries. The parser reads no payload or extracted values, so the working credential itself is never written to a report.
5. **Test app** gets a Tomcat manager page at `/manager/html` that accepts `tomcat:tomcat`. `tomcat-default-login` must report it. The Juice Shop gate runs the plugin and checks that it sent requests.

## Consequences

- Vendor factory logins for the HTTP products Nuclei knows are tested on local targets. Deployed targets, non-HTTP services and the WordPress password-list template are not tested.
- About 950 extra requests per local URL scan by the publisher's count; 831 were sent to the test app, in about 16 seconds.
- A login that the app counts as a failure can lock an account. PeopleSoft accounts can see up to 20 attempts.
- When the templates pin is upgraded, the template count and the `-it` path must be checked again; `TestBuiltin` checks the path and that the WordPress template is never named.

## Alternatives considered

- All 338 templates, WordPress included: the WordPress template is password guessing (ADR 0010).
- 336 templates, PeopleSoft left out too, following the publisher's default: offered first, not chosen by the owner.
- Running only templates for products found by Nuclei's technology detection: offered (answer 4b), not chosen.
