# 0010. Login protection and secret-exposure checks

- Status: Accepted
- Date: 2026-11-18
- Amended by: [0030](0030-login-throttling.md) (the login throttling check: flags, what counts as a limit, local targets only until M2.10), [0031](0031-default-logins.md) (the default-credentials check: which templates, one attempt per credential)

## Context

The project owner asked whether SiegeKit checks login weaknesses, password-attempt limits, leaked keys and exposed admin pages. Leaked keys in code and admin-page discovery were already planned (see [coverage](../coverage.md)). Two gaps remained:

1. Whether the app **limits failed login attempts**. The threat model rules out "credential attacks against live login services", which was meant to exclude password guessing against real accounts, but it also excluded this defensive check.
2. **Secrets exposed by a running site** (keys inside JavaScript bundles, a public `.env` or config file), as opposed to secrets in the source repository.

## Decision

### Login throttling check (new, M2)

- The user supplies a **test account they own** (username only) and the login endpoint.
- SiegeKit sends a small, fixed number of logins with a **deliberately wrong, randomly generated password** (default 20, hard maximum 50, at most 1 per second) and reports whether the app slows down, blocks, shows a CAPTCHA or locks the account. It never tries real passwords and never uses a password list.
- Local mode: available after the run plan is confirmed.
- Deployed mode: off unless named with `--allow-destructive login-throttle`, because it can lock the test account.

### Default credentials check (new, M2, local mode only)

- Tries the small set of vendor default credentials published for software detected on the target (for example an admin panel's documented factory login), using Nuclei's default-login templates, capped at one attempt per credential.
- Not available in deployed mode.

### Secrets in served content (new, M2)

- JavaScript, HTML and config files fetched during the web crawl are scanned with the same secret rules as the repository scan (Gitleaks), and common exposed files (`.env`, `.git/`, backups) are checked through Nuclei exposure templates and ffuf.

### What stays ruled out

Guessing or brute-forcing passwords of any account through a live login (dictionary, credential stuffing, spraying) remains out of scope in every mode. Password strength is only audited **offline**, on hash files the user supplies (M3).

## Consequences

- The "features we will not build" list in the threat model is clarified rather than weakened: the throttling check uses one known account and a known-wrong password, so it cannot discover anyone's password.
- The test account may be locked; the plan screen warns about this.

## Alternatives considered

- **No login checks:** leaves a very common weakness (no rate limit on login) untested.
- **Small password-list attack:** would discover weak passwords but is exactly the capability the misuse policy excludes. Rejected.
